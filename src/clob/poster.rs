//! The hot write path: a hyper-based poster with pinned DNS, isolated
//! connection pools, and hand-rolled L2 signing over the exact bytes sent.
//!
//! Everything here is latency-motivated:
//!
//! - **Pinned DNS**: one lookup at construction, then a fixed `SocketAddr` —
//!   no per-request resolution.
//! - **Two isolated pools**: order POSTs and cancels each get their own
//!   hyper pool, so a placement burst can never push a latency-critical
//!   cancel onto a cold connection.
//! - **Warm tiers**: [`FastPoster::warm_up`] pings a small hot set every few
//!   seconds; [`FastPoster::warm_reserve`] holds a larger fleet of completed
//!   TLS handshakes on a slower cadence for multi-leg bursts.
//! - **Sign-what-you-send**: the L2 HMAC covers the exact serialized bytes
//!   that go on the wire, built in one buffer.
//!
//! All order writes should come through here; the reqwest-based
//! `ClobClient` covers reads and admin calls.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use alloy::primitives::U256;
use alloy::signers::SignerSync;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;
use futures::future::join_all;
use hmac::{Hmac, Mac as _};
use http_body_util::Full;
use hyper::header::HeaderValue;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use rust_decimal::Decimal;
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use sha2::Sha256;

use crate::clob::ClobClient;
use crate::clob::signing::{
    OrderSigner, build_signable_order, build_signable_order_side, generate_salt, to_fixed_usdc,
};
use crate::clob::tick::{FIXED_SIZE, TickEntry};
use crate::clob::types::{
    CancelOrdersResponse, OrderStatus, OrderType, PostOrderResponse, Side, SignedOrder,
};
use crate::error::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Max order ids per `DELETE /orders` payload.
///
/// The CLOB cancel API rejects any payload over 1000 ids with a 400 ("Too
/// many orders in payload, max allowed: 1000") — larger chunks fail the
/// whole pass once a key holds >1000 resting orders.
pub const CANCEL_BATCH_SIZE: usize = 1000;

/// Order-pool connections pinged every [`FastPoster::warm_up`] pass, sized
/// for a burst of concurrent place POSTs.
const WARM_CONNECTIONS: usize = 4;
/// Cancel-pool warm connections: cancels are low-volume but latency-critical
/// (the stale-quote pickoff window), so a few stay hot and isolated.
const CANCEL_WARM_CONNECTIONS: usize = 4;

/// Which CLOB endpoint urgent cancels ([`FastPoster::cancel_for_reprice`])
/// use. Bulk lifecycle cancels always use the batched `DELETE /orders`
/// regardless.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CancelEndpoint {
    /// Batched `DELETE /orders` — one request carrying every order id.
    #[default]
    Orders,
    /// Singular `DELETE /order` — one request per id, fired concurrently.
    /// The two endpoints carry separate venue rate limits.
    Order,
}

impl CancelEndpoint {
    /// The *other* endpoint — useful when a cancel-path 429 makes a caller
    /// flip to the alternate `DELETE` path. An involution.
    #[must_use]
    pub const fn flipped(self) -> Self {
        match self {
            Self::Orders => Self::Order,
            Self::Order => Self::Orders,
        }
    }

    /// The lowercase token matching the serde encoding, for config
    /// round-trips.
    #[must_use]
    pub const fn as_config_str(self) -> &'static str {
        match self {
            Self::Orders => "orders",
            Self::Order => "order",
        }
    }
}

/// Which CLOB endpoint [`FastPoster::post_one`] places through. Batch
/// placement ([`post_signed`]) always uses `POST /orders` regardless.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderEndpoint {
    /// Batched `POST /orders` — one request carrying a chunk of orders.
    #[default]
    Orders,
    /// Singular `POST /order` — one request per order.
    Order,
}

/// Which CLOB call path tripped the rate-limit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitEndpoint {
    /// `POST /order(s)` — order placement.
    PlaceOrder = 0,
    /// `DELETE /order(s)` — order cancellation.
    Cancel = 1,
}

impl RateLimitEndpoint {
    /// Human label; reads naturally as "on the {…} endpoint".
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PlaceOrder => "place order",
            Self::Cancel => "cancel",
        }
    }
}

/// Rate-limit breaker handle shared between the poster and a supervising
/// loop: a `Notify` the loop awaits plus the endpoint of the most recent 429,
/// so the wake-up can name which call path was throttled.
#[derive(Default)]
pub struct RateLimitSignal {
    notify: tokio::sync::Notify,
    /// [`RateLimitEndpoint`] of the latest 429, stored before the wake.
    endpoint: AtomicU8,
}

impl RateLimitSignal {
    /// Resolves when a 429 has tripped the breaker. Pair with
    /// [`Self::endpoint`] to read which call path was throttled.
    pub async fn notified(&self) {
        self.notify.notified().await;
    }

    /// The endpoint that tripped the most recent 429.
    pub fn endpoint(&self) -> RateLimitEndpoint {
        if self.endpoint.load(Ordering::Acquire) == RateLimitEndpoint::Cancel as u8 {
            RateLimitEndpoint::Cancel
        } else {
            RateLimitEndpoint::PlaceOrder
        }
    }

    /// Record the throttled endpoint and wake the supervisor. The store is
    /// released before the wake so the `Acquire` load observes it.
    fn signal(&self, endpoint: RateLimitEndpoint) {
        self.endpoint.store(endpoint as u8, Ordering::Release);
        self.notify.notify_one();
    }
}

/// Session-total counts of place/cancel HTTP requests actually sent.
///
/// Incremented once per request as it goes on the wire — including failures
/// and timeouts, which still count against the venue's rate limits. Cancels
/// split by endpoint: singular `DELETE /order` and batched `DELETE /orders`
/// carry separate venue rate limits. Warm-up pings are excluded. Share one
/// `Arc` between the poster and whatever reads the rates.
#[derive(Default)]
pub struct ApiCallCounters {
    place: AtomicU64,
    cancel_order: AtomicU64,
    cancel_orders: AtomicU64,
}

impl ApiCallCounters {
    pub fn place_total(&self) -> u64 {
        self.place.load(Ordering::Relaxed)
    }

    pub fn cancel_order_total(&self) -> u64 {
        self.cancel_order.load(Ordering::Relaxed)
    }

    pub fn cancel_orders_total(&self) -> u64 {
        self.cancel_orders.load(Ordering::Relaxed)
    }

    fn record_place(&self) {
        self.place.fetch_add(1, Ordering::Relaxed);
    }

    fn record_cancel(&self, batched: bool) {
        let counter = if batched {
            &self.cancel_orders
        } else {
            &self.cancel_order
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Timings for one place round, for callers that watch their send latency.
#[derive(Debug, Default)]
pub struct PostTimings {
    /// JSON serialization + HMAC of the request body, ms.
    pub serialize_ms: f64,
    /// Round trip of the slowest chunk, ms.
    pub network_ms: f64,
    /// Whole [`post_signed`] round, ms.
    pub post_ms: f64,
    /// `POST /orders` chunks the round was split into.
    pub chunk_count: usize,
}

/// Outcome of one posted order: the venue's response plus the POST's round
/// trip.
#[derive(Debug)]
pub struct LegPost {
    pub response: PostOrderResponse,
    pub rtt_ms: f64,
}

#[derive(Clone)]
struct PinnedResolver(SocketAddr);

impl tower_service::Service<hyper_util::client::legacy::connect::dns::Name> for PinnedResolver {
    type Response = std::iter::Once<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _name: hyper_util::client::legacy::connect::dns::Name) -> Self::Future {
        std::future::ready(Ok(std::iter::once(self.0)))
    }
}

type HttpsConnector = hyper_rustls::HttpsConnector<
    hyper_util::client::legacy::connect::HttpConnector<PinnedResolver>,
>;
type PostClient = HyperClient<HttpsConnector, Full<bytes::Bytes>>;

/// Build a hyper client with its own connection pool, DNS pinned to `addr`,
/// TCP nodelay, HTTP/1.1, keep-alive (5-min idle). Each call yields an
/// isolated pool — orders and cancels use separate ones so a POST burst can't
/// occupy a connection a cancel needs.
fn build_client(addr: SocketAddr) -> PostClient {
    let resolver = PinnedResolver(addr);
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new_with_resolver(resolver);
    http.enforce_http(false);
    http.set_nodelay(true);

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .wrap_connector(http);

    HyperClient::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(300))
        .build(connector)
}

/// The hot order-write client. Build from an authenticated
/// [`ClobClient`] via [`ClobClient::poster`] (async: it pins DNS once).
pub struct FastPoster {
    client: PostClient,
    /// Dedicated pool for cancels, isolated from order POSTs.
    cancel_client: PostClient,
    /// Fired on any CLOB 429 so a supervising loop can trip a breaker.
    rate_limit: Option<Arc<RateLimitSignal>>,
    /// Per-request place/cancel tallies for rate telemetry.
    call_counters: Option<Arc<ApiCallCounters>>,
    /// Endpoint [`Self::cancel_for_reprice`] uses; every other cancel path
    /// always batches `DELETE /orders`.
    cancel_endpoint: CancelEndpoint,
    /// Endpoint [`Self::post_one`] uses; [`post_signed`] always batches.
    order_endpoint: OrderEndpoint,
    /// Batched URL (`{host}orders`).
    url: hyper::Uri,
    /// Singular URL (`{host}order`).
    order_url: hyper::Uri,
    hmac_template: Hmac<Sha256>,
    address_header: HeaderValue,
    api_key_header: HeaderValue,
    passphrase_header: HeaderValue,
    warm_connections: usize,
    cancel_warm_connections: usize,
    /// TOTAL order-pool connections held open by the slower
    /// [`Self::warm_reserve`] cadence. `0` (default) disables the tier.
    warm_reserve_connections: usize,
}

impl FastPoster {
    /// Builds the poster from an authenticated client: decodes the HMAC
    /// secret, precomputes headers, resolves and pins the CLOB host's DNS,
    /// and opens the two pools.
    pub async fn new(clob: &ClobClient) -> Result<Self, Error> {
        let creds = clob.credentials();
        let hmac_key = URL_SAFE
            .decode(creds.secret().expose_secret())
            .map_err(|e| Error::InvalidData(format!("invalid HMAC secret: {e}")))?;
        let hmac_template = Hmac::<Sha256>::new_from_slice(&hmac_key)
            .map_err(|e| Error::InvalidData(format!("HMAC init failed: {e}")))?;

        let url: hyper::Uri = format!("{}orders", clob.host())
            .parse()
            .map_err(|e| Error::InvalidData(format!("invalid URL: {e}")))?;
        let order_url: hyper::Uri = format!("{}order", clob.host())
            .parse()
            .map_err(|e| Error::InvalidData(format!("invalid order URL: {e}")))?;
        let host = url
            .host()
            .ok_or_else(|| Error::InvalidData("CLOB URL has no host".into()))?;
        let port = url.port_u16().unwrap_or(443);
        let addr = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| Error::InvalidData(format!("DNS lookup failed for {host}: {e}")))?
            .next()
            .ok_or_else(|| Error::InvalidData(format!("DNS returned no addresses for {host}")))?;
        tracing::info!(%host, %addr, "CLOB DNS pinned");

        let client = build_client(addr);
        let cancel_client = build_client(addr);

        let parse_header = |s: &str| {
            HeaderValue::from_str(s)
                .map_err(|e| Error::InvalidData(format!("invalid header value: {e}")))
        };

        Ok(Self {
            client,
            cancel_client,
            rate_limit: None,
            call_counters: None,
            cancel_endpoint: CancelEndpoint::Orders,
            order_endpoint: OrderEndpoint::Orders,
            url,
            order_url,
            hmac_template,
            address_header: parse_header(&clob.address().to_checksum(None))?,
            api_key_header: parse_header(&creds.key().to_string())?,
            passphrase_header: parse_header(creds.passphrase().expose_secret())?,
            warm_connections: WARM_CONNECTIONS,
            cancel_warm_connections: CANCEL_WARM_CONNECTIONS,
            warm_reserve_connections: 0,
        })
    }

    /// Size the warm-connection tiers: `hot` order-pool and `cancel`
    /// cancel-pool connections are pinged on every [`Self::warm_up`] pass;
    /// `reserve` is the total order-pool fleet held open by the slower
    /// [`Self::warm_reserve`] cadence (`0` disables it). Set once at startup
    /// before the poster is shared across tasks.
    pub const fn set_warm_sizes(&mut self, hot: usize, cancel: usize, reserve: usize) {
        self.warm_connections = hot;
        self.cancel_warm_connections = cancel;
        self.warm_reserve_connections = reserve;
    }

    /// Wire a signal fired on any CLOB 429 so a supervising loop can trip a
    /// rate-limit breaker. Set once at startup before sharing the poster.
    pub fn set_rate_limit_signal(&mut self, signal: Arc<RateLimitSignal>) {
        self.rate_limit = Some(signal);
    }

    /// Wire shared place/cancel request tallies. Set once at startup; left
    /// unwired, nothing is counted.
    pub fn set_call_counters(&mut self, counters: Arc<ApiCallCounters>) {
        self.call_counters = Some(counters);
    }

    /// Select the endpoint [`Self::cancel_for_reprice`] uses. Set once at
    /// startup. Every other cancel path stays on the batched `/orders`.
    pub const fn set_cancel_endpoint(&mut self, endpoint: CancelEndpoint) {
        self.cancel_endpoint = endpoint;
    }

    /// Select the endpoint [`Self::post_one`] uses. Set once at startup.
    /// Batch placement always uses `/orders`.
    pub const fn set_order_endpoint(&mut self, endpoint: OrderEndpoint) {
        self.order_endpoint = endpoint;
    }

    fn signal_rate_limit(&self, endpoint: RateLimitEndpoint) {
        if let Some(signal) = &self.rate_limit {
            signal.signal(endpoint);
        }
    }

    /// Pings each warm connection on both pools concurrently and returns the
    /// per-ping latency in ms. A ping near the others is a reused (warm)
    /// connection; a spike is a fresh TLS handshake — how warmth is observed,
    /// since hyper has no pool-introspection API.
    pub async fn warm_up(&self) -> Vec<f64> {
        let mut futs = Vec::with_capacity(self.warm_connections + self.cancel_warm_connections);
        for _ in 0..self.warm_connections {
            futs.push(self.warm_single(&self.client));
        }
        for _ in 0..self.cancel_warm_connections {
            futs.push(self.warm_single(&self.cancel_client));
        }
        join_all(futs).await
    }

    /// Pings `warm_reserve_connections` order-pool connections concurrently —
    /// concurrent in-flight requests are what force hyper to open and retain
    /// that many distinct pooled connections. Run on a slower cadence than
    /// [`Self::warm_up`]. No-op when sized 0.
    pub async fn warm_reserve(&self) -> Vec<f64> {
        if self.warm_reserve_connections == 0 {
            return Vec::new();
        }
        let futs: Vec<_> = (0..self.warm_reserve_connections)
            .map(|_| self.warm_single(&self.client))
            .collect();
        join_all(futs).await
    }

    async fn warm_single(&self, client: &PostClient) -> f64 {
        let t = Instant::now();
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(self.url.clone())
            .header("Content-Type", "application/json")
            .header("Connection", "keep-alive")
            .body(Full::new(bytes::Bytes::from_static(b"[]")));

        let req = match req {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("CLOB warm-up request build failed (non-fatal): {e}");
                return t.elapsed().as_secs_f64() * 1000.0;
            }
        };

        match client.request(req).await {
            Ok(resp) => {
                let status = resp.status();
                let _ = http_body_util::BodyExt::collect(resp.into_body()).await;
                tracing::debug!(http_status = %status, "CLOB path kept warm");
            }
            Err(e) => tracing::warn!("CLOB warm-up failed (non-fatal): {e}"),
        }
        t.elapsed().as_secs_f64() * 1000.0
    }

    /// POST a batch of signed orders to `POST /orders`. The L2 HMAC covers
    /// the exact serialized bytes sent. `api_ts` is the L2 timestamp (Unix
    /// seconds).
    pub async fn post_orders(
        &self,
        orders: &[SignedOrder],
        timings: &mut PostTimings,
        api_ts: i64,
    ) -> Result<Vec<LegPost>, Error> {
        let t0 = Instant::now();

        let mut ts_buf = itoa::Buffer::new();
        let ts_str = ts_buf.format(api_ts);

        let mut msg_buf: Vec<u8> = Vec::with_capacity(orders.len() * 640);
        msg_buf.extend_from_slice(ts_str.as_bytes());
        msg_buf.extend_from_slice(b"POST/orders");
        let body_start = msg_buf.len();
        serde_json::to_writer(&mut msg_buf, orders)
            .map_err(|e| Error::InvalidData(format!("JSON serialization failed: {e}")))?;

        let mut mac = self.hmac_template.clone();
        mac.update(&msg_buf);
        let mut sig_buf = [0_u8; 44];
        let sig_len = URL_SAFE
            .encode_slice(mac.finalize().into_bytes(), &mut sig_buf)
            .map_err(|e| Error::InvalidData(format!("base64 encode failed: {e}")))?;

        timings.serialize_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let body = bytes::Bytes::from(msg_buf).slice(body_start..);

        let req = self.build_post(&self.url, &sig_buf[..sig_len], ts_str, body)?;

        if let Some(c) = &self.call_counters {
            c.record_place();
        }
        let t1 = Instant::now();

        let (status, body) = self.round_trip(&self.client, req, "POST").await?;

        let rtt_ms = t1.elapsed().as_secs_f64() * 1000.0;
        timings.network_ms = rtt_ms;

        if status == hyper::StatusCode::TOO_MANY_REQUESTS {
            self.signal_rate_limit(RateLimitEndpoint::PlaceOrder);
            return Err(Error::RateLimit { retry_after: None });
        }
        if !status.is_success() {
            let text = String::from_utf8_lossy(&body);
            return Err(Error::InvalidData(format!("CLOB API {status}: {text}")));
        }

        let resps: Vec<PostOrderResponse> = serde_json::from_slice(&body)
            .map_err(|e| Error::InvalidData(format!("response parse failed: {e}")))?;

        if resps.len() != orders.len() {
            return Err(Error::InvalidData(format!(
                "expected {} responses, got {}",
                orders.len(),
                resps.len()
            )));
        }

        Ok(resps
            .into_iter()
            .map(|response| LegPost { response, rtt_ms })
            .collect())
    }

    /// POST a **single** order to the singular `POST /order` endpoint: the
    /// body is a JSON object (not a 1-element array) and the sign path is
    /// `POST/order`. 429 handling, timeout, and headers are identical to
    /// [`Self::post_orders`].
    async fn post_order_single(
        &self,
        order: &SignedOrder,
        timings: &mut PostTimings,
        api_ts: i64,
    ) -> Result<LegPost, Error> {
        let t0 = Instant::now();

        let mut ts_buf = itoa::Buffer::new();
        let ts_str = ts_buf.format(api_ts);

        let mut msg_buf: Vec<u8> = Vec::with_capacity(640);
        msg_buf.extend_from_slice(ts_str.as_bytes());
        msg_buf.extend_from_slice(b"POST/order");
        let body_start = msg_buf.len();
        serde_json::to_writer(&mut msg_buf, order)
            .map_err(|e| Error::InvalidData(format!("JSON serialization failed: {e}")))?;

        let mut mac = self.hmac_template.clone();
        mac.update(&msg_buf);
        let mut sig_buf = [0_u8; 44];
        let sig_len = URL_SAFE
            .encode_slice(mac.finalize().into_bytes(), &mut sig_buf)
            .map_err(|e| Error::InvalidData(format!("base64 encode failed: {e}")))?;

        timings.serialize_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let body = bytes::Bytes::from(msg_buf).slice(body_start..);

        let req = self.build_post(&self.order_url, &sig_buf[..sig_len], ts_str, body)?;

        if let Some(c) = &self.call_counters {
            c.record_place();
        }
        let t1 = Instant::now();

        let (status, body) = self.round_trip(&self.client, req, "POST").await?;

        let rtt_ms = t1.elapsed().as_secs_f64() * 1000.0;
        timings.network_ms = rtt_ms;

        if status == hyper::StatusCode::TOO_MANY_REQUESTS {
            self.signal_rate_limit(RateLimitEndpoint::PlaceOrder);
            return Err(Error::RateLimit { retry_after: None });
        }
        if !status.is_success() {
            let text = String::from_utf8_lossy(&body);
            return Err(Error::InvalidData(format!("CLOB API {status}: {text}")));
        }

        let response: PostOrderResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::InvalidData(format!("response parse failed: {e}")))?;

        Ok(LegPost { response, rtt_ms })
    }

    /// Place one order, honoring [`Self::set_order_endpoint`]:
    /// [`OrderEndpoint::Order`] sends a singular `POST /order`,
    /// [`OrderEndpoint::Orders`] (default) a 1-element batched `POST /orders`.
    /// The caller owns any concurrency.
    pub async fn post_one(
        &self,
        order: &SignedOrder,
        timings: &mut PostTimings,
        api_ts: i64,
    ) -> Result<LegPost, Error> {
        match self.order_endpoint {
            OrderEndpoint::Order => self.post_order_single(order, timings, api_ts).await,
            OrderEndpoint::Orders => self
                .post_orders(std::slice::from_ref(order), timings, api_ts)
                .await?
                .pop()
                .ok_or_else(|| Error::InvalidData("empty response".into())),
        }
    }

    fn build_post(
        &self,
        uri: &hyper::Uri,
        signature: &[u8],
        ts_str: &str,
        body: bytes::Bytes,
    ) -> Result<hyper::Request<Full<bytes::Bytes>>, Error> {
        hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(uri.clone())
            .header("Content-Type", "application/json")
            .header("Connection", "keep-alive")
            .header("POLY_ADDRESS", &self.address_header)
            .header("POLY_API_KEY", &self.api_key_header)
            .header("POLY_PASSPHRASE", &self.passphrase_header)
            .header(
                "POLY_SIGNATURE",
                HeaderValue::from_bytes(signature)
                    .map_err(|e| Error::InvalidData(format!("signature header: {e}")))?,
            )
            .header(
                "POLY_TIMESTAMP",
                HeaderValue::from_str(ts_str)
                    .map_err(|e| Error::InvalidData(format!("timestamp header: {e}")))?,
            )
            .body(Full::new(body))
            .map_err(|e| Error::InvalidData(format!("request build failed: {e}")))
    }

    async fn round_trip(
        &self,
        client: &PostClient,
        req: hyper::Request<Full<bytes::Bytes>>,
        verb: &str,
    ) -> Result<(hyper::StatusCode, bytes::Bytes), Error> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let response = client
                .request(req)
                .await
                .map_err(|e| Error::InvalidData(format!("{verb} failed: {e}")))?;
            let status = response.status();
            let body = http_body_util::BodyExt::collect(response.into_body())
                .await
                .map_err(|e| Error::InvalidData(format!("body read failed: {e}")))?
                .to_bytes();
            Ok::<_, Error>((status, body))
        })
        .await
        .map_err(|_| Error::InvalidData(format!("{verb} timed out")))?
    }

    /// Sign (L2 HMAC over `{ts}{sign_path}{body}`) and send a `DELETE` to
    /// `uri` carrying `body`. A 429 trips the rate-limit breaker.
    async fn send_delete(
        &self,
        uri: &hyper::Uri,
        sign_path: &[u8],
        body: bytes::Bytes,
    ) -> Result<CancelOrdersResponse, Error> {
        let timestamp = chrono::Utc::now().timestamp();
        let mut ts_buf = itoa::Buffer::new();
        let ts_str = ts_buf.format(timestamp);

        let mut msg_buf: Vec<u8> = Vec::with_capacity(64 + body.len());
        msg_buf.extend_from_slice(ts_str.as_bytes());
        msg_buf.extend_from_slice(sign_path);
        msg_buf.extend_from_slice(&body);

        let mut mac = self.hmac_template.clone();
        mac.update(&msg_buf);
        let mut sig_buf = [0_u8; 44];
        let sig_len = URL_SAFE
            .encode_slice(mac.finalize().into_bytes(), &mut sig_buf)
            .map_err(|e| Error::InvalidData(format!("base64 encode failed: {e}")))?;

        let req = hyper::Request::builder()
            .method(hyper::Method::DELETE)
            .uri(uri.clone())
            .header("Content-Type", "application/json")
            .header("Connection", "keep-alive")
            .header("POLY_ADDRESS", &self.address_header)
            .header("POLY_API_KEY", &self.api_key_header)
            .header("POLY_PASSPHRASE", &self.passphrase_header)
            .header(
                "POLY_SIGNATURE",
                HeaderValue::from_bytes(&sig_buf[..sig_len])
                    .map_err(|e| Error::InvalidData(format!("signature header: {e}")))?,
            )
            .header(
                "POLY_TIMESTAMP",
                HeaderValue::from_str(ts_str)
                    .map_err(|e| Error::InvalidData(format!("timestamp header: {e}")))?,
            )
            .body(Full::new(body))
            .map_err(|e| Error::InvalidData(format!("request build failed: {e}")))?;

        if let Some(c) = &self.call_counters {
            // `sign_path` is exactly one of `DELETE/orders` (batched) or
            // `DELETE/order` (singular).
            c.record_cancel(sign_path == b"DELETE/orders".as_slice());
        }

        let (status, resp_body) = self.round_trip(&self.cancel_client, req, "DELETE").await?;

        if status == hyper::StatusCode::TOO_MANY_REQUESTS {
            self.signal_rate_limit(RateLimitEndpoint::Cancel);
            return Err(Error::RateLimit { retry_after: None });
        }
        if !status.is_success() {
            let text = String::from_utf8_lossy(&resp_body);
            return Err(Error::InvalidData(format!(
                "CLOB cancel API {status}: {text}"
            )));
        }

        serde_json::from_slice(&resp_body)
            .map_err(|e| Error::InvalidData(format!("cancel response parse failed: {e}")))
    }

    /// Cancel a specific set of orders by id (batched `DELETE /orders`).
    pub async fn cancel_orders(&self, order_ids: &[&str]) -> Result<CancelOrdersResponse, Error> {
        let body_json = serde_json::to_vec(order_ids)
            .map_err(|e| Error::InvalidData(format!("cancel JSON failed: {e}")))?;
        self.send_delete(&self.url, b"DELETE/orders", bytes::Bytes::from(body_json))
            .await
    }

    /// Cancel a single order by id (singular `DELETE /order`, body
    /// `{"orderID":"<id>"}`).
    async fn cancel_single(&self, order_id: &str) -> Result<CancelOrdersResponse, Error> {
        let body = cancel_order_body(order_id)?;
        self.send_delete(&self.order_url, b"DELETE/order", bytes::Bytes::from(body))
            .await
    }

    /// Cancel resting orders for an *urgent* pull (reprice/fill), honoring
    /// [`Self::set_cancel_endpoint`]: [`CancelEndpoint::Orders`] (default)
    /// sends one batched `DELETE /orders`; [`CancelEndpoint::Order`] fans out
    /// via [`Self::cancel_singly`].
    pub async fn cancel_for_reprice(
        &self,
        order_ids: &[&str],
    ) -> Result<CancelOrdersResponse, Error> {
        if self.cancel_endpoint == CancelEndpoint::Orders || order_ids.is_empty() {
            return self.cancel_orders(order_ids).await;
        }
        self.cancel_singly(order_ids).await
    }

    /// Cancel a set of orders as one concurrent singular `DELETE /order`
    /// apiece, merging the responses. A per-id transport error is folded into
    /// `not_canceled` (the order stayed resting — a "miss"), so the caller's
    /// accounting is unchanged; a 429 still trips the breaker. Only every id
    /// failing surfaces as `Err`.
    pub async fn cancel_singly(&self, order_ids: &[&str]) -> Result<CancelOrdersResponse, Error> {
        if order_ids.is_empty() {
            return Ok(CancelOrdersResponse::default());
        }

        let results = join_all(order_ids.iter().map(|id| self.cancel_single(id))).await;

        let mut merged = CancelOrdersResponse::default();
        let mut first_err: Option<Error> = None;
        let mut ok_count = 0_usize;
        for (id, result) in order_ids.iter().zip(results) {
            match result {
                Ok(resp) => {
                    ok_count += 1;
                    merged.canceled.extend(resp.canceled);
                    merged.not_canceled.extend(resp.not_canceled);
                }
                Err(e) => {
                    merged.not_canceled.insert((*id).to_string(), e.to_string());
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        // Non-empty input with zero successes means every request errored:
        // surface the first as a failure rather than a silent all-miss.
        if ok_count == 0 {
            return Err(first_err
                .unwrap_or_else(|| Error::InvalidData("all singular cancels failed".into())));
        }
        Ok(merged)
    }
}

/// Build the singular `DELETE /order` request body: `{"orderID":"<id>"}`.
///
/// Kept pure and separate so the exact bytes signed are the exact bytes sent
/// (the HMAC covers the body).
fn cancel_order_body(order_id: &str) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&serde_json::json!({ "orderID": order_id }))
        .map_err(|e| Error::InvalidData(format!("cancel order JSON failed: {e}")))
}

/// Does a CLOB `not_canceled` reason mean the order no longer exists, so
/// retrying the cancel is pointless?
///
/// `true` for terminal states — already filled, matched, executed, completed,
/// expired, already canceled, or simply not on the book anymore. **`false`
/// for anything unrecognized**: an unknown reason is treated as a transient
/// miss so the order is *retried*, never silently abandoned — a still-live
/// order must never be dropped from tracking. Match is lowercased +
/// substring to tolerate the venue's (undocumented) wording drift.
///
/// Caveat: the singular `/order` fan-out folds per-id *transport* errors into
/// the same `not_canceled` map, so a transport error string containing one of
/// these substrings would be misread as terminal. The default endpoint is the
/// batched `/orders`, whose `not_canceled` only carries genuine CLOB reasons.
#[must_use]
pub fn cancel_reason_is_terminal(reason: &str) -> bool {
    /// Substrings that each unambiguously mean "the order is gone".
    const TERMINAL: &[&str] = &[
        "filled",         // "order already filled"
        "not found",      // "order not found" (off-book: filled / canceled / expired)
        "matched",        // "order already matched"
        "executed",       // "order already executed"
        "complete",       // "order complete" / "completed"
        "already cancel", // "order already canceled" / "...cancelled"
        "expired",        // "order expired"
    ];
    let reason = reason.to_ascii_lowercase();
    TERMINAL.iter().any(|t| reason.contains(t))
}

/// A cancel target: `(group index, item index, order_id)` — a convenient
/// shape for multi-leg engines feeding [`partition_cancels`].
pub type CancelLeg = (usize, usize, String);

/// Partition a flushed cancel batch into `(done, retry)` items.
///
/// Generic over the batch element; `get_id` extracts the order id. `done`
/// items are confirmed gone — drop them from tracking; `retry` items are
/// requeued for another attempt.
///
/// On a whole-POST transport error every item is presumed still resting and
/// retried. On success an item is `done` if the venue canceled it *or*
/// reported a terminal `not_canceled` reason (see
/// [`cancel_reason_is_terminal`]); anything else — a non-terminal/unknown
/// reason, or an id the venue omitted from both lists — is retried, so a
/// still-live order is never dropped from tracking on a transient failure.
#[must_use]
pub fn partition_cancels<T>(
    batch: Vec<T>,
    result: &Result<CancelOrdersResponse, Error>,
    get_id: impl Fn(&T) -> &str,
) -> (Vec<T>, Vec<T>) {
    let Ok(resp) = result else {
        return (Vec::new(), batch); // transport failure: retry everything
    };
    let mut done = Vec::new();
    let mut retry = Vec::new();
    for item in batch {
        let id = get_id(&item);
        let gone = resp.canceled.iter().any(|c| c.as_str() == id)
            || resp
                .not_canceled
                .get(id)
                .is_some_and(|reason| cancel_reason_is_terminal(reason));
        if gone {
            done.push(item);
        } else {
            retry.push(item);
        }
    }
    (done, retry)
}

/// Cancel a set of order ids in [`CANCEL_BATCH_SIZE`] chunks, merging the
/// responses.
pub async fn cancel_in_batches(
    poster: &FastPoster,
    ids: &[&str],
) -> Result<CancelOrdersResponse, Error> {
    let mut merged = CancelOrdersResponse::default();
    for chunk in ids.chunks(CANCEL_BATCH_SIZE) {
        let resp = poster.cancel_orders(chunk).await?;
        merged.canceled.extend(resp.canceled);
        merged.not_canceled.extend(resp.not_canceled);
    }
    Ok(merged)
}

/// Page the key's open orders and collect the ids resting on `side`.
pub async fn fetch_order_ids_by_side(clob: &ClobClient, side: Side) -> Result<Vec<String>, Error> {
    let orders = clob
        .all_open_orders(&crate::clob::OpenOrdersRequest::default())
        .await?;
    Ok(orders
        .into_iter()
        .filter(|order| order.side == side)
        .map(|order| order.id)
        .collect())
}

/// Cancel every open order on the key resting on `side`.
///
/// Lets two systems share one API key without stepping on each other's book
/// (e.g. a maker that only rests BUYs beside a seller that only rests
/// SELLs).
pub async fn cancel_orders_by_side(
    clob: &ClobClient,
    poster: &FastPoster,
    side: Side,
) -> Result<CancelOrdersResponse, Error> {
    let ids = fetch_order_ids_by_side(clob, side).await?;
    if ids.is_empty() {
        return Ok(CancelOrdersResponse::default());
    }

    tracing::info!(count = ids.len(), %side, "cancelling orders by side");

    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    cancel_in_batches(poster, &refs).await
}

/// Cancel every resting BUY order on the key.
pub async fn cancel_buy_orders(
    clob: &ClobClient,
    poster: &FastPoster,
) -> Result<CancelOrdersResponse, Error> {
    cancel_orders_by_side(clob, poster, Side::Buy).await
}

/// Cancel every resting SELL order on the key.
pub async fn cancel_sell_orders(
    clob: &ClobClient,
    poster: &FastPoster,
) -> Result<CancelOrdersResponse, Error> {
    cancel_orders_by_side(clob, poster, Side::Sell).await
}

/// Page the open orders and collect every resting SELL id — the fetch half of
/// [`cancel_sell_orders`], for callers that loop "fetch → cancel → re-fetch"
/// until empty.
pub async fn fetch_sell_order_ids(clob: &ClobClient) -> Result<Vec<String>, Error> {
    fetch_order_ids_by_side(clob, Side::Sell).await
}

/// POST pre-signed orders in `max_orders_per_post`-sized chunks (always the
/// batched `POST /orders`), chunks in flight concurrently.
pub async fn post_signed(
    signed_orders: &[SignedOrder],
    poster: &FastPoster,
    timings: &mut PostTimings,
    max_orders_per_post: usize,
    api_ts: i64,
) -> Result<Vec<LegPost>, Error> {
    let t = Instant::now();

    let chunk_size = max_orders_per_post.max(1);
    let futs = signed_orders.chunks(chunk_size).map(|chunk| async move {
        let mut ct = PostTimings::default();
        let posts = poster.post_orders(chunk, &mut ct, api_ts).await?;
        Ok::<_, Error>((posts, ct))
    });
    let results = futures::future::try_join_all(futs).await?;

    timings.post_ms = t.elapsed().as_secs_f64() * 1000.0;
    timings.chunk_count = signed_orders.len().div_ceil(chunk_size);

    let mut leg_posts = Vec::with_capacity(signed_orders.len());
    for (posts, ct) in results {
        timings.serialize_ms = timings.serialize_ms.max(ct.serialize_ms);
        timings.network_ms = timings.network_ms.max(ct.network_ms);
        leg_posts.extend(posts);
    }

    Ok(leg_posts)
}

/// One resting order to place.
///
/// Carries the token's tick data (which holds the token id), the price to
/// rest at, and the size in shares.
#[derive(Debug, Clone, Copy)]
pub struct RestingPlacement {
    pub tick: TickEntry,
    pub price: Decimal,
    pub size: Decimal,
    /// Displayed size resting AHEAD at `price` the instant of placement —
    /// the queue position. `0` means the order joined an empty level (front
    /// of queue). Carried through for callers that track fill likelihood;
    /// ignore it otherwise.
    pub queue_ahead: Decimal,
}

fn now_ms() -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Sign and POST a batch of resting BUY orders as `GTC` + post-only.
///
/// Post-only makes them rest as maker liquidity (rejected rather than
/// crossing the spread). Returns one [`LegPost`] per placement, in order; the
/// caller records each `order_id` and owns the cancel/replace lifecycle.
pub async fn place_resting<S: SignerSync + Sync>(
    placements: &[RestingPlacement],
    poster: &FastPoster,
    signer: &S,
    order_signer: &OrderSigner,
    max_orders_per_post: usize,
) -> Result<Vec<LegPost>, Error> {
    if placements.is_empty() {
        return Ok(Vec::new());
    }

    let ts = now_ms();
    let mut signed_orders = Vec::with_capacity(placements.len());
    for p in placements {
        let maker_amount = U256::from(to_fixed_usdc(p.size * p.price)?);
        let taker_amount = U256::from(to_fixed_usdc(p.size)?);
        let order = build_signable_order(
            p.tick.token_id_u256,
            maker_amount,
            taker_amount,
            order_signer.identity(),
            ts,
            OrderType::GTC,
            generate_salt(),
            true,
        );
        signed_orders.push(order_signer.sign_order(order, signer)?);
    }

    let mut timings = PostTimings::default();
    let api_ts = chrono::Utc::now().timestamp();
    post_signed(
        &signed_orders,
        poster,
        &mut timings,
        max_orders_per_post,
        api_ts,
    )
    .await
}

/// Sign and POST a batch of resting SELL orders as `GTC` + post-only.
///
/// For a SELL the maker gives `size` shares and receives `size × price`
/// USDC, so the maker/taker amounts are the swap of [`place_resting`]'s, and
/// each placement carries the *sold* token's tick.
pub async fn place_resting_sell<S: SignerSync + Sync>(
    placements: &[RestingPlacement],
    poster: &FastPoster,
    signer: &S,
    order_signer: &OrderSigner,
    max_orders_per_post: usize,
) -> Result<Vec<LegPost>, Error> {
    place_sell_orders(
        placements,
        poster,
        signer,
        order_signer,
        max_orders_per_post,
        OrderType::GTC,
        true,
    )
    .await
}

/// Shared body behind [`place_resting_sell`] (GTC post-only maker) and
/// [`place_marketable_sell`] (FAK taker): the two differ only in
/// `order_type` + `post_only`, so both ride one tested signing path.
async fn place_sell_orders<S: SignerSync + Sync>(
    placements: &[RestingPlacement],
    poster: &FastPoster,
    signer: &S,
    order_signer: &OrderSigner,
    max_orders_per_post: usize,
    order_type: OrderType,
    post_only: bool,
) -> Result<Vec<LegPost>, Error> {
    if placements.is_empty() {
        return Ok(Vec::new());
    }

    let ts = now_ms();
    let mut signed_orders = Vec::with_capacity(placements.len());
    for p in placements {
        // SELL: give `size` shares, receive `size × price` USDC — the swap
        // of the BUY amounts in `place_resting`.
        let maker_amount = U256::from(to_fixed_usdc(p.size)?);
        let taker_amount = U256::from(to_fixed_usdc(p.size * p.price)?);
        let order = build_signable_order_side(
            p.tick.token_id_u256,
            maker_amount,
            taker_amount,
            order_signer.identity(),
            ts,
            order_type.clone(),
            generate_salt(),
            post_only,
            Side::Sell,
        );
        signed_orders.push(order_signer.sign_order(order, signer)?);
    }

    let mut timings = PostTimings::default();
    let api_ts = chrono::Utc::now().timestamp();
    post_signed(
        &signed_orders,
        poster,
        &mut timings,
        max_orders_per_post,
        api_ts,
    )
    .await
}

/// Place a single **marketable** (taker) SELL — an [`OrderType::FAK`] order
/// with `post_only` off, so it crosses an existing bid instead of resting.
///
/// `placement.price` is the FAK **limit** — for a SELL the *minimum*
/// acceptable price, so the order fills only against bids at or above it and
/// kills the rest (its own safety floor: a book that moved down yields a
/// no-fill rather than a worse-than-shown sale). FAK leaves no resting
/// residue. The caller credits the fill from the response's
/// `making_amount`/`taking_amount` — a taker fill is not echoed on the
/// user-WS maker channel.
pub async fn place_marketable_sell<S: SignerSync + Sync>(
    placement: &RestingPlacement,
    poster: &FastPoster,
    signer: &S,
    order_signer: &OrderSigner,
) -> Result<LegPost, Error> {
    place_sell_orders(
        std::slice::from_ref(placement),
        poster,
        signer,
        order_signer,
        1,
        OrderType::FAK,
        false,
    )
    .await?
    .pop()
    .ok_or_else(|| Error::InvalidData("empty marketable sell response".into()))
}

fn build_warmup_orders<S: SignerSync>(
    entries: &[&TickEntry],
    order_signer: &OrderSigner,
    signer: &S,
) -> Vec<SignedOrder> {
    let ts = now_ms();
    entries
        .iter()
        .filter_map(|tick| {
            let maker_amount = U256::from(to_fixed_usdc(FIXED_SIZE * tick.min_price).ok()?);
            let taker_amount = U256::from(to_fixed_usdc(FIXED_SIZE).ok()?);
            let order = build_signable_order(
                tick.token_id_u256,
                maker_amount,
                taker_amount,
                order_signer.identity(),
                ts,
                OrderType::FOK,
                generate_salt(),
                false,
            );
            order_signer.sign_order(order, signer).ok()
        })
        .collect()
}

/// Warm the whole sign→POST path with minimum-size FOK orders priced at each
/// token's tick floor.
///
/// These are real requests that exercise TLS, HMAC, and the venue pipeline
/// end to end. An FOK at the price floor cannot rest and essentially cannot
/// fill; a fill would be logged as an unexpected bargain. Returns the
/// per-post RTTs (empty on failure — warm-up is always non-fatal).
pub async fn deep_warm_up<S: SignerSync + Sync>(
    entries: &[&TickEntry],
    order_signer: &OrderSigner,
    signer: &S,
    poster: &FastPoster,
    max_per_post: usize,
) -> Vec<f64> {
    if entries.is_empty() {
        return Vec::new();
    }

    let warmup_orders = build_warmup_orders(entries, order_signer, signer);
    if warmup_orders.is_empty() {
        return Vec::new();
    }

    let mut timings = PostTimings::default();
    let api_ts = chrono::Utc::now().timestamp();
    match post_signed(&warmup_orders, poster, &mut timings, max_per_post, api_ts).await {
        Ok(leg_posts) => {
            let mut rtts = Vec::with_capacity(leg_posts.len());
            for lp in &leg_posts {
                if lp.response.status == OrderStatus::Matched {
                    tracing::warn!(
                        order_id = %lp.response.order_id,
                        "warmup FOK FILLED — unexpected bargain",
                    );
                }
                rtts.push(lp.rtt_ms);
            }
            tracing::debug!(
                count = leg_posts.len(),
                net_ms = timings.network_ms,
                "deep warmup complete"
            );
            rtts
        }
        Err(e) => {
            tracing::debug!(%e, "deep warmup failed (non-fatal)");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_order_body_is_exact_json() {
        // The HMAC signs these exact bytes, so the serialization must be
        // byte-stable.
        let body = cancel_order_body("0xabc").expect("serialize cancel body");
        assert_eq!(body, br#"{"orderID":"0xabc"}"#);
    }

    #[test]
    fn terminal_cancel_reasons_are_recognized() {
        // The venue's wording for "the order is gone".
        for r in [
            "Order already filled",
            "order is filled",
            "Order not found",
            "ORDER ALREADY MATCHED",
            "order already executed",
            "order complete",
            "order already canceled",
            "order already cancelled",
            "order expired",
        ] {
            assert!(cancel_reason_is_terminal(r), "should be terminal: {r:?}");
        }
    }

    #[test]
    fn transient_cancel_reasons_are_retried() {
        // Anything not recognized as terminal is retried, never dropped — a
        // still-live order must never be abandoned.
        for r in [
            "",
            "rate limited",
            "too many requests",
            "service unavailable",
            "request timeout",
            "connection reset",
            "internal error",
        ] {
            assert!(!cancel_reason_is_terminal(r), "should be retried: {r:?}");
        }
    }

    #[test]
    fn partition_cancels_splits_done_from_retry() {
        // Venue confirmed "a" canceled; "b" is gone (terminal reason →
        // done); "c" hit a non-terminal reason and "d" was omitted entirely
        // → both retried, never dropped.
        let batch: Vec<CancelLeg> = vec![
            (0, 0, "a".to_owned()),
            (0, 1, "b".to_owned()),
            (0, 2, "c".to_owned()),
            (0, 3, "d".to_owned()),
        ];
        let resp: CancelOrdersResponse = serde_json::from_str(
            r#"{"canceled":["a"],"notCanceled":{"b":"Order already filled","c":"rate limited"}}"#,
        )
        .expect("parse cancel response");
        let (done, retry) = partition_cancels(batch, &Ok(resp), |(_, _, id)| id.as_str());
        assert_eq!(
            done,
            vec![(0, 0, "a".to_owned()), (0, 1, "b".to_owned())],
            "canceled + terminal-reason legs are done"
        );
        assert_eq!(
            retry,
            vec![(0, 2, "c".to_owned()), (0, 3, "d".to_owned())],
            "non-terminal + omitted legs are retried"
        );
    }

    #[test]
    fn partition_cancels_retries_everything_on_transport_error() {
        // A whole-POST failure has no per-id verdicts: every leg is presumed
        // still resting.
        let batch: Vec<CancelLeg> = vec![(0, 0, "a".to_owned()), (0, 1, "b".to_owned())];
        let err: Result<CancelOrdersResponse, Error> = Err(Error::InvalidData("boom".into()));
        let (done, retry) = partition_cancels(batch.clone(), &err, |(_, _, id)| id.as_str());
        assert!(done.is_empty());
        assert_eq!(retry, batch);
    }

    #[test]
    fn cancel_endpoint_serde_and_flip() {
        assert_eq!(
            serde_json::from_str::<CancelEndpoint>(r#""orders""#).unwrap(),
            CancelEndpoint::Orders
        );
        assert_eq!(
            serde_json::from_str::<CancelEndpoint>(r#""order""#).unwrap(),
            CancelEndpoint::Order
        );
        assert_eq!(CancelEndpoint::default(), CancelEndpoint::Orders);

        for ep in [CancelEndpoint::Orders, CancelEndpoint::Order] {
            assert_eq!(ep.flipped().flipped(), ep);
            // The config token must parse back to the same variant, or a
            // flip would silently reset on a config round-trip.
            assert_eq!(
                serde_json::from_str::<CancelEndpoint>(&format!("\"{}\"", ep.as_config_str()))
                    .unwrap(),
                ep
            );
        }
    }

    #[test]
    fn order_endpoint_serde() {
        assert_eq!(
            serde_json::from_str::<OrderEndpoint>(r#""orders""#).unwrap(),
            OrderEndpoint::Orders
        );
        assert_eq!(
            serde_json::from_str::<OrderEndpoint>(r#""order""#).unwrap(),
            OrderEndpoint::Order
        );
        assert_eq!(OrderEndpoint::default(), OrderEndpoint::Orders);
    }
}
