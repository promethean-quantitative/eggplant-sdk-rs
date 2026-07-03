//! Polymarket CLOB: order types, EIP-712 signing, venue size rules, and the
//! HTTP client surfaces.
//!
//! [`ClobClient`] is the read/admin surface (reqwest): authentication,
//! market/tick metadata, order books, open-order listing, trades, cancel-all.
//! Latency-critical order placement and cancellation live on the dedicated
//! hyper-based [`poster::FastPoster`], built from a client via
//! [`ClobClient::poster`].

pub mod books;
pub mod poster;
pub mod signing;
pub mod tick;
pub mod types;

use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::signers::Signer;
use chrono::Utc;
use reqwest::Method;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::auth::{self, Credentials};
use crate::chain::{CLOB_HOST, POLYGON};
use crate::clob::books::BookSummary;
use crate::clob::signing::{ExchangeDomain, OrderIdentity, OrderSigner};
use crate::clob::types::{
    CancelOrdersResponse, ClobMarket, ClobTrade, OpenOrder, Page, SignatureType,
};
use crate::error::Error;

/// The cursor value marking the final page of a cursor-paginated listing.
pub const TERMINAL_CURSOR: &str = "LTE=";

/// Filters for the open-orders and trades listings. Empty filters list
/// everything owned by the API key.
#[derive(Clone, Debug, Default)]
pub struct OpenOrdersRequest {
    /// A specific order id.
    pub id: Option<String>,
    /// A market condition id.
    pub market: Option<String>,
    /// A token id (decimal string).
    pub asset_id: Option<String>,
}

impl OpenOrdersRequest {
    fn query(&self, cursor: Option<&str>) -> String {
        let mut q = String::new();
        for (key, value) in [
            ("id", self.id.as_deref()),
            ("market", self.market.as_deref()),
            ("asset_id", self.asset_id.as_deref()),
            ("next_cursor", cursor),
        ] {
            if let Some(value) = value {
                q.push(if q.is_empty() { '?' } else { '&' });
                q.push_str(key);
                q.push('=');
                q.push_str(value);
            }
        }
        q
    }
}

/// Builder for [`ClobClient`]: host, chain, and the signature-type/funder
/// pair, finished by either a network handshake ([`Self::authenticate`]) or
/// saved credentials ([`Self::with_credentials`]).
#[derive(Clone, Debug)]
pub struct ClobClientBuilder {
    host: String,
    chain_id: u64,
    signature_type: SignatureType,
    funder: Option<Address>,
    nonce: Option<u32>,
    use_server_time: bool,
}

impl Default for ClobClientBuilder {
    fn default() -> Self {
        Self {
            host: CLOB_HOST.to_owned(),
            chain_id: POLYGON,
            signature_type: SignatureType::Eoa,
            funder: None,
            nonce: None,
            use_server_time: false,
        }
    }
}

impl ClobClientBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// CLOB REST host. Default [`CLOB_HOST`].
    #[must_use]
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// Chain id for L1 auth and order signing. Default [`POLYGON`]. Taken
    /// from the builder, never from the signer — a missing signer chain id
    /// must not silently change what gets signed.
    #[must_use]
    pub const fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// The signature type orders will carry. Default [`SignatureType::Eoa`].
    #[must_use]
    pub const fn signature_type(mut self, signature_type: SignatureType) -> Self {
        self.signature_type = signature_type;
        self
    }

    /// The funding wallet, required for signature types 1/2/3 (proxy, Safe,
    /// deposit wallet). Derive proxy/Safe addresses with
    /// [`crate::chain::derive_proxy_wallet`] / [`crate::chain::derive_safe_wallet`].
    #[must_use]
    pub const fn funder(mut self, funder: Address) -> Self {
        self.funder = Some(funder);
        self
    }

    /// L1 auth nonce. Each nonce maps to one API key per wallet; default `0`.
    #[must_use]
    pub const fn nonce(mut self, nonce: u32) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sign L1 timestamps with the venue's clock (`GET /time`) instead of the
    /// local one. Default off.
    #[must_use]
    pub const fn use_server_time(mut self, use_server_time: bool) -> Self {
        self.use_server_time = use_server_time;
        self
    }

    /// Creates a fresh API key via the L1 handshake (`POST /auth/api-key`).
    pub async fn create_api_key<S: Signer + Sync>(&self, signer: &S) -> Result<Credentials, Error> {
        self.api_key_request(signer, Method::POST, "auth/api-key")
            .await
    }

    /// Re-derives the wallet's existing API key (`GET /auth/derive-api-key`).
    pub async fn derive_api_key<S: Signer + Sync>(&self, signer: &S) -> Result<Credentials, Error> {
        self.api_key_request(signer, Method::GET, "auth/derive-api-key")
            .await
    }

    /// The full handshake: try create, and fall back to derive only when the
    /// venue answered with an HTTP error (e.g. the key already exists).
    /// Network and rate-limit failures propagate instead of falling through.
    pub async fn authenticate<S: Signer + Sync>(self, signer: &S) -> Result<ClobClient, Error> {
        let credentials = match self.create_api_key(signer).await {
            Ok(credentials) => credentials,
            Err(Error::Api { .. }) => self.derive_api_key(signer).await?,
            Err(e) => return Err(e),
        };
        self.with_credentials(signer.address(), credentials)
    }

    /// Hot start from saved [`Credentials`] — no network round trip.
    /// `signer_address` is the EOA the credentials were derived for.
    pub fn with_credentials(
        self,
        signer_address: Address,
        credentials: Credentials,
    ) -> Result<ClobClient, Error> {
        let identity = self.resolve_identity(signer_address)?;
        Ok(ClobClient {
            http: default_http()?,
            host: normalize_host(self.host),
            chain_id: self.chain_id,
            address: signer_address,
            identity,
            credentials,
        })
    }

    /// Encodes the venue's signature-type/funder table (see
    /// [`OrderIdentity`]) with build-time validation.
    fn resolve_identity(&self, signer_address: Address) -> Result<OrderIdentity, Error> {
        match self.signature_type {
            SignatureType::Eoa => {
                if self.funder.is_some_and(|funder| funder != signer_address) {
                    return Err(Error::InvalidData(
                        "signature type 0 (EOA) takes no separate funder — the EOA itself is the maker".into(),
                    ));
                }
                Ok(OrderIdentity::eoa(signer_address))
            }
            SignatureType::Proxy => self.funder.map(|f| OrderIdentity::proxy(signer_address, f)).ok_or_else(|| {
                Error::InvalidData(
                    "signature type 1 (proxy) requires .funder(proxy_wallet); derive it with chain::derive_proxy_wallet".into(),
                )
            }),
            SignatureType::GnosisSafe => self
                .funder
                .map(|f| OrderIdentity::gnosis_safe(signer_address, f))
                .ok_or_else(|| {
                    Error::InvalidData(
                        "signature type 2 (Safe) requires .funder(safe_wallet); derive it with chain::derive_safe_wallet".into(),
                    )
                }),
            SignatureType::Poly1271 => self.funder.map(OrderIdentity::poly1271).ok_or_else(|| {
                Error::InvalidData(
                    "signature type 3 (Poly1271) requires .funder(deposit_wallet)".into(),
                )
            }),
        }
    }

    async fn api_key_request<S: Signer + Sync>(
        &self,
        signer: &S,
        method: Method,
        endpoint: &str,
    ) -> Result<Credentials, Error> {
        let http = default_http()?;
        let host = normalize_host(self.host.clone());

        let timestamp = if self.use_server_time {
            fetch_server_time(&http, &host).await?
        } else {
            Utc::now().timestamp()
        };

        let headers = auth::l1_headers(signer, self.chain_id, timestamp, self.nonce).await?;
        let response = http
            .request(method, format!("{host}{endpoint}"))
            .headers(headers)
            .send()
            .await?;
        parse_response(response).await
    }
}

/// Authenticated CLOB client: credentials, identity, and the read/admin REST
/// surface. Order placement goes through [`ClobClient::poster`].
pub struct ClobClient {
    http: reqwest::Client,
    /// Host with a trailing slash (`https://clob.polymarket.com/`).
    host: String,
    chain_id: u64,
    /// The signer EOA the credentials belong to (L2 `POLY_ADDRESS`).
    address: Address,
    identity: OrderIdentity,
    credentials: Credentials,
}

impl ClobClient {
    #[must_use]
    pub fn builder() -> ClobClientBuilder {
        ClobClientBuilder::new()
    }

    /// The REST host, trailing-slash normalized.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The signer EOA address.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    #[must_use]
    pub const fn identity(&self) -> OrderIdentity {
        self.identity
    }

    #[must_use]
    pub const fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// An [`OrderSigner`] for this client's identity against `domain`.
    #[must_use]
    pub fn order_signer(&self, domain: &ExchangeDomain) -> OrderSigner {
        OrderSigner::new(self.chain_id, domain, self.identity, self.credentials.key())
    }

    /// Builds the hot write-path poster (async: it resolves and pins the
    /// host's DNS once).
    pub async fn poster(&self) -> Result<poster::FastPoster, Error> {
        poster::FastPoster::new(self).await
    }

    /// Venue clock, Unix seconds (`GET /time`, public).
    pub async fn server_time(&self) -> Result<i64, Error> {
        fetch_server_time(&self.http, &self.host).await
    }

    /// A token's current minimum tick (`GET /tick-size`, public). Plain
    /// [`Decimal`] — any venue grid parses.
    pub async fn tick_size(&self, token_id: &str) -> Result<Decimal, Error> {
        #[derive(Deserialize)]
        struct TickSizeResponse {
            minimum_tick_size: Decimal,
        }
        let response: TickSizeResponse = self
            .get_public(&format!("tick-size?token_id={token_id}"))
            .await?;
        Ok(response.minimum_tick_size)
    }

    /// Whether a token trades on the negRisk exchange (`GET /neg-risk`,
    /// public) — this decides the signing domain
    /// ([`ExchangeDomain::ctf_v2`]).
    pub async fn neg_risk(&self, token_id: &str) -> Result<bool, Error> {
        #[derive(Deserialize)]
        struct NegRiskResponse {
            neg_risk: bool,
        }
        let response: NegRiskResponse = self
            .get_public(&format!("neg-risk?token_id={token_id}"))
            .await?;
        Ok(response.neg_risk)
    }

    /// One market by condition id (`GET /markets/{condition_id}`, public).
    pub async fn market(&self, condition_id: &str) -> Result<ClobMarket, Error> {
        self.get_public(&format!("markets/{condition_id}")).await
    }

    /// One page of open orders (`GET /data/orders`, L2-authenticated).
    pub async fn open_orders(
        &self,
        request: &OpenOrdersRequest,
        cursor: Option<&str>,
    ) -> Result<Page<OpenOrder>, Error> {
        self.get_l2("data/orders", &request.query(cursor)).await
    }

    /// Every open order matching `request`, paging until the terminal
    /// cursor.
    pub async fn all_open_orders(
        &self,
        request: &OpenOrdersRequest,
    ) -> Result<Vec<OpenOrder>, Error> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self.open_orders(request, cursor.as_deref()).await?;
            out.extend(page.data);
            let next = page.next_cursor;
            if next.is_empty() || next == TERMINAL_CURSOR || Some(&next) == cursor.as_ref() {
                break;
            }
            cursor = Some(next);
        }
        Ok(out)
    }

    /// One page of the key's trades (`GET /data/trades`, L2-authenticated).
    pub async fn trades(
        &self,
        request: &OpenOrdersRequest,
        cursor: Option<&str>,
    ) -> Result<Page<ClobTrade>, Error> {
        self.get_l2("data/trades", &request.query(cursor)).await
    }

    /// Cancels every open order owned by the API key
    /// (`DELETE /cancel-all`, L2-authenticated).
    pub async fn cancel_all(&self) -> Result<CancelOrdersResponse, Error> {
        let timestamp = Utc::now().timestamp();
        let headers = auth::l2_headers(
            self.address,
            &self.credentials,
            timestamp,
            "DELETE",
            "/cancel-all",
            "",
        )?;
        let response = self
            .http
            .delete(format!("{}cancel-all", self.host))
            .headers(headers)
            .send()
            .await?;
        parse_response(response).await
    }

    /// Book summaries for up to [`books::MAX_BATCH_SIZE`] tokens
    /// (`POST /books`, public, leniently parsed).
    pub async fn order_books(&self, token_ids: &[&str]) -> Result<Vec<BookSummary>, Error> {
        books::fetch_books_at(&self.http, &format!("{}books", self.host), token_ids).await
    }

    /// Book summaries for arbitrarily many tokens, chunked and fetched
    /// concurrently, keyed by asset id.
    pub async fn order_book_map(
        &self,
        token_ids: &[&str],
    ) -> Result<std::collections::HashMap<U256, BookSummary>, Error> {
        books::fetch_book_map_at(&self.http, &format!("{}books", self.host), token_ids).await
    }

    async fn get_public<T: DeserializeOwned>(&self, endpoint_and_query: &str) -> Result<T, Error> {
        let response = self
            .http
            .get(format!("{}{}", self.host, endpoint_and_query))
            .send()
            .await?;
        parse_response(response).await
    }

    async fn get_l2<T: DeserializeOwned>(&self, endpoint: &str, query: &str) -> Result<T, Error> {
        let timestamp = Utc::now().timestamp();
        // The L2 message covers the path only — query strings are excluded.
        let headers = auth::l2_headers(
            self.address,
            &self.credentials,
            timestamp,
            "GET",
            &format!("/{endpoint}"),
            "",
        )?;
        let response = self
            .http
            .get(format!("{}{}{}", self.host, endpoint, query))
            .headers(headers)
            .send()
            .await?;
        parse_response(response).await
    }
}

fn normalize_host(mut host: String) -> String {
    if !host.ends_with('/') {
        host.push('/');
    }
    host
}

fn default_http() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(Error::from)
}

async fn fetch_server_time(http: &reqwest::Client, host: &str) -> Result<i64, Error> {
    let response = http.get(format!("{host}time")).send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(Error::Api {
            status: status.as_u16(),
            body: text.chars().take(300).collect(),
        });
    }
    text.trim()
        .trim_matches('"')
        .parse()
        .map_err(|_| Error::InvalidData(format!("unparseable server time: {text}")))
}

/// Shared response handling: 429 → [`Error::RateLimit`], other non-2xx →
/// [`Error::Api`], else deserialize.
async fn parse_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    let status = response.status();
    if status.as_u16() == 429 {
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        return Err(Error::RateLimit { retry_after });
    }
    let text = response.text().await?;
    if !status.is_success() {
        return Err(Error::Api {
            status: status.as_u16(),
            body: text.chars().take(300).collect(),
        });
    }
    serde_json::from_str(&text).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_normalized_with_trailing_slash() {
        assert_eq!(
            normalize_host("https://clob.polymarket.com".into()),
            "https://clob.polymarket.com/"
        );
        assert_eq!(
            normalize_host("https://clob.polymarket.com/".into()),
            "https://clob.polymarket.com/"
        );
    }

    #[test]
    fn open_orders_request_query() {
        let empty = OpenOrdersRequest::default();
        assert_eq!(empty.query(None), "");
        assert_eq!(empty.query(Some("abc=")), "?next_cursor=abc=");

        let filtered = OpenOrdersRequest {
            asset_id: Some("777".into()),
            ..Default::default()
        };
        assert_eq!(
            filtered.query(Some("MTA=")),
            "?asset_id=777&next_cursor=MTA="
        );
    }

    #[test]
    fn identity_resolution_enforces_funder_table() {
        let eoa: Address = "0x00000000000000000000000000000000000000AB"
            .parse()
            .unwrap();
        let wallet: Address = "0x00000000000000000000000000000000000000CD"
            .parse()
            .unwrap();

        // EOA: no funder needed; a matching funder is tolerated, a foreign one is not.
        assert!(ClobClientBuilder::new().resolve_identity(eoa).is_ok());
        assert!(
            ClobClientBuilder::new()
                .funder(eoa)
                .resolve_identity(eoa)
                .is_ok()
        );
        assert!(
            ClobClientBuilder::new()
                .funder(wallet)
                .resolve_identity(eoa)
                .is_err()
        );

        // Types 1/2/3 demand a funder.
        for signature_type in [
            SignatureType::Proxy,
            SignatureType::GnosisSafe,
            SignatureType::Poly1271,
        ] {
            assert!(
                ClobClientBuilder::new()
                    .signature_type(signature_type)
                    .resolve_identity(eoa)
                    .is_err(),
                "{signature_type:?} without funder must fail"
            );
            let identity = ClobClientBuilder::new()
                .signature_type(signature_type)
                .funder(wallet)
                .resolve_identity(eoa)
                .unwrap();
            assert_eq!(identity.maker, wallet);
            assert_eq!(identity.signature_type, signature_type);
        }

        // Poly1271: the deposit wallet signs for itself; 1/2: the EOA signs.
        let p1271 = ClobClientBuilder::new()
            .signature_type(SignatureType::Poly1271)
            .funder(wallet)
            .resolve_identity(eoa)
            .unwrap();
        assert_eq!(p1271.signer, wallet);
        let proxy = ClobClientBuilder::new()
            .signature_type(SignatureType::Proxy)
            .funder(wallet)
            .resolve_identity(eoa)
            .unwrap();
        assert_eq!(proxy.signer, eoa);
    }
}
