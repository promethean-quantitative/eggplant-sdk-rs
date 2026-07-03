//! User-channel messages (own trades and order lifecycle) and a
//! single-connection stream.
//!
//! The schema is adapted from the MIT-licensed `polymarket_client_sdk_v2`
//! (see `ATTRIBUTION.md`) with one deliberate change: the top-level
//! [`UserMessage`] carries an `Unknown` tail so a new venue event kind
//! degrades instead of failing the frame.
//!
//! Operational notes proven in production:
//!
//! - The channel delivers **maker** fills; your own taker fills are *not*
//!   echoed here — credit them from the POST response's
//!   `making_amount`/`taking_amount`.
//! - Every fill on the API key is delivered, so processes sharing a key must
//!   filter by side ([`crate::ws::util::our_maker_side`]) and dedup by trade
//!   id across redundant connections ([`crate::ws::util::SeenIds`]).
//! - A trade's `maker_orders` lists *every* maker the sweep hit — filter to
//!   entries whose `owner` is your API key before crediting.

use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer};

use crate::auth::{ApiKey, Credentials};
use crate::chain::WS_USER_URL;
use crate::clob::types::{OrderStatus, Side};
use crate::error::Error;
use crate::ws::frames;
use crate::ws::market::LiveSocket;

/// One user-channel message.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "event_type")]
pub enum UserMessage {
    /// A trade the key participated in (as maker or taker).
    #[serde(rename = "trade")]
    Trade(TradeMessage),
    /// An order lifecycle event (placement / update / cancellation).
    #[serde(rename = "order")]
    Order(OrderMessage),
    /// A venue event kind this crate doesn't know yet.
    #[serde(other)]
    Unknown,
}

/// Parse one user-channel text frame.
pub fn parse_user_message(text: &str) -> Result<UserMessage, serde_json::Error> {
    serde_json::from_str(text)
}

/// Trade settlement status.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum TradeStatus {
    #[serde(alias = "matched", alias = "MATCHED")]
    Matched,
    #[serde(alias = "mined", alias = "MINED")]
    Mined,
    #[serde(alias = "confirmed", alias = "CONFIRMED")]
    Confirmed,
    #[serde(alias = "retrying", alias = "RETRYING")]
    Retrying,
    #[serde(alias = "failed", alias = "FAILED")]
    Failed,
    #[serde(untagged)]
    Unknown(String),
}

impl TradeStatus {
    /// Whether this status is final (`CONFIRMED` / `FAILED`).
    ///
    /// Gate final-status handling *before* trade-id dedup: a `RETRYING`
    /// first sighting must not swallow the later confirmation.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Confirmed | Self::Failed)
    }
}

/// One maker order matched within a trade.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct MakerOrder {
    /// Token id (decimal string).
    #[serde(default)]
    pub asset_id: String,
    pub matched_amount: Decimal,
    pub order_id: String,
    /// Outcome (`"Yes"` / `"No"`).
    #[serde(default)]
    pub outcome: String,
    /// API key that owns the maker order — filter to yours.
    pub owner: ApiKey,
    pub price: Decimal,
}

/// Venue timestamps arrive as decimal strings (sometimes numbers); an
/// unparseable one degrades to `None`.
fn lenient_i64<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Num(i64),
        Str(String),
    }
    Ok(match Option::<Raw>::deserialize(deserializer)? {
        None => None,
        Some(Raw::Num(n)) => Some(n),
        Some(Raw::Str(s)) => s.trim().parse().ok(),
    })
}

/// A trade the key participated in (authenticated channel).
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct TradeMessage {
    /// Trade id — the dedup key across redundant connections.
    pub id: String,
    /// Market condition id (hex).
    #[serde(default)]
    pub market: String,
    /// Token id of the *taker* side (decimal string).
    #[serde(default)]
    pub asset_id: String,
    /// The **taker's** side. Derive your own maker side from this plus the
    /// outcomes via [`crate::ws::util::our_maker_side`].
    pub side: Side,
    pub size: Decimal,
    pub price: Decimal,
    pub status: TradeStatus,
    /// The taker's outcome (`"Yes"` / `"No"`).
    #[serde(default)]
    pub outcome: Option<String>,
    /// API key of the event's owner (the key this delivery is for).
    #[serde(default)]
    pub owner: Option<ApiKey>,
    #[serde(default)]
    pub trade_owner: Option<ApiKey>,
    #[serde(default)]
    pub taker_order_id: Option<String>,
    /// Every maker order the sweep matched — includes other participants'.
    #[serde(default)]
    pub maker_orders: Vec<MakerOrder>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub last_update: Option<i64>,
    #[serde(default, alias = "match_time", deserialize_with = "lenient_i64")]
    pub matchtime: Option<i64>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub timestamp: Option<i64>,
    #[serde(default)]
    pub fee_rate_bps: Option<Decimal>,
    #[serde(default)]
    pub transaction_hash: String,
    /// `"MAKER"` / `"TAKER"`.
    #[serde(default)]
    pub trader_side: String,
}

/// Order lifecycle kind.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum OrderEventType {
    #[serde(alias = "placement", alias = "PLACEMENT")]
    Placement,
    #[serde(alias = "update", alias = "UPDATE")]
    Update,
    #[serde(alias = "cancellation", alias = "CANCELLATION")]
    Cancellation,
    #[serde(untagged)]
    Unknown(String),
}

/// An order lifecycle event on the key (authenticated channel).
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct OrderMessage {
    /// Order id.
    pub id: String,
    /// Market condition id (hex).
    #[serde(default)]
    pub market: String,
    /// Token id (decimal string).
    #[serde(default)]
    pub asset_id: String,
    pub side: Side,
    pub price: Decimal,
    #[serde(rename = "type", default)]
    pub msg_type: Option<OrderEventType>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub owner: Option<ApiKey>,
    #[serde(default)]
    pub order_owner: Option<ApiKey>,
    #[serde(default)]
    pub original_size: Option<Decimal>,
    #[serde(default)]
    pub size_matched: Option<Decimal>,
    #[serde(default, deserialize_with = "lenient_i64")]
    pub timestamp: Option<i64>,
    #[serde(default)]
    pub associate_trades: Option<Vec<String>>,
    #[serde(default)]
    pub status: Option<OrderStatus>,
}

/// Configuration for one user-channel connection.
#[derive(Clone)]
pub struct UserStreamConfig {
    /// Defaults to [`WS_USER_URL`].
    pub url: String,
    pub credentials: Credentials,
    /// Condition ids to filter to; empty subscribes to every fill on the
    /// key. No historical replay — only live events from connect onward.
    pub markets: Vec<String>,
}

impl UserStreamConfig {
    #[must_use]
    pub fn new(credentials: Credentials) -> Self {
        Self {
            url: WS_USER_URL.to_owned(),
            credentials,
            markets: Vec::new(),
        }
    }
}

/// One authenticated user-channel connection with the liveness protocol
/// handled.
///
/// For redundancy, run several identically-subscribed streams and dedup by
/// trade id ([`crate::ws::util::SeenIds`]) — first delivery wins.
pub struct UserStream {
    inner: LiveSocket,
}

impl UserStream {
    /// Connect and authenticate-subscribe.
    pub async fn connect(config: &UserStreamConfig) -> Result<Self, Error> {
        let frame = frames::user_subscribe_frame(&config.credentials, &config.markets);
        Ok(Self {
            inner: LiveSocket::connect(&config.url, frame).await?,
        })
    }

    /// The next raw data frame; `Ok(None)` means the server closed cleanly,
    /// `Err` means transport failure or PONG-deadline breach (reconnect).
    pub async fn next_text(&mut self) -> Result<Option<String>, Error> {
        self.inner.next_text().await
    }

    /// The next parsed message. Unknown event kinds surface as
    /// [`UserMessage::Unknown`] rather than erroring.
    pub async fn next_message(&mut self) -> Result<Option<UserMessage>, Error> {
        self.next_text().await?.map_or(Ok(None), |text| {
            parse_user_message(&text)
                .map(Some)
                .map_err(|e| Error::InvalidData(format!("user frame parse: {e}")))
        })
    }

    /// Politely close (e.g. for a scheduled recycle).
    pub async fn close(&mut self) {
        self.inner.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Venue-shaped trade frame (the venue's published sample payload).
    const SAMPLE_TRADE: &str = r#"{
        "asset_id": "52114319501245915516055106046884209969926127482827954674443846427813813222426",
        "event_type": "trade",
        "id": "28c4d2eb-bbea-40e7-a9f0-b2fdb56b2c2e",
        "last_update": "1672290701",
        "maker_orders": [
            {
                "asset_id": "52114319501245915516055106046884209969926127482827954674443846427813813222426",
                "matched_amount": "10",
                "order_id": "0xff354cd7ca7539dfa9c28d90943ab5779a4eac34b9b37a757d7b32bdfb11790b",
                "outcome": "YES",
                "owner": "9180014b-33c8-9240-a14b-bdca11c0a465",
                "price": "0.57"
            }
        ],
        "market": "0xbd31dc8a20211944f6b70f31557f1001557b59905b7738480ca09bd4532f84af",
        "matchtime": "1672290701",
        "outcome": "YES",
        "owner": "9180014b-33c8-9240-a14b-bdca11c0a465",
        "price": "0.57",
        "side": "BUY",
        "size": "10",
        "status": "MATCHED",
        "taker_order_id": "0x06bc63e346ed4ceddce9efd6b3af37c8f8f440c92fe7da6b2d0f9e4ccbc50c42",
        "timestamp": "1672290701",
        "trade_owner": "9180014b-33c8-9240-a14b-bdca11c0a465",
        "type": "TRADE"
    }"#;

    #[test]
    fn parses_sample_trade_event() {
        let msg = parse_user_message(SAMPLE_TRADE).expect("sample trade should parse");
        let UserMessage::Trade(t) = msg else {
            panic!("expected a Trade variant");
        };
        assert_eq!(t.id, "28c4d2eb-bbea-40e7-a9f0-b2fdb56b2c2e");
        assert_eq!(t.side, Side::Buy);
        assert_eq!(t.price.to_string(), "0.57");
        assert_eq!(t.size.to_string(), "10");
        assert_eq!(t.status, TradeStatus::Matched);
        assert_eq!(t.matchtime, Some(1_672_290_701));
        assert_eq!(t.maker_orders.len(), 1);
        assert_eq!(t.maker_orders[0].outcome, "YES");
        assert_eq!(
            t.maker_orders[0].owner.to_string(),
            "9180014b-33c8-9240-a14b-bdca11c0a465"
        );
    }

    #[test]
    fn parses_order_event() {
        let json = r#"{
            "event_type": "order",
            "id": "0xff354cd7",
            "market": "0xbd31dc8a",
            "asset_id": "521143195",
            "side": "SELL",
            "price": "0.57",
            "type": "PLACEMENT",
            "outcome": "YES",
            "original_size": "100",
            "size_matched": "0",
            "timestamp": "1672290701",
            "status": "LIVE"
        }"#;
        let UserMessage::Order(o) = parse_user_message(json).unwrap() else {
            panic!("expected an Order variant");
        };
        assert_eq!(o.msg_type, Some(OrderEventType::Placement));
        assert_eq!(o.side, Side::Sell);
        assert_eq!(o.status, Some(OrderStatus::Live));
        assert_eq!(o.original_size, Some("100".parse().unwrap()));
    }

    #[test]
    fn unknown_event_kind_and_statuses_degrade() {
        assert!(matches!(
            parse_user_message(r#"{"event_type": "brand_new", "x": 1}"#).unwrap(),
            UserMessage::Unknown
        ));

        let status: TradeStatus = serde_json::from_str(r#""SOME_NEW_STATUS""#).unwrap();
        assert_eq!(status, TradeStatus::Unknown("SOME_NEW_STATUS".to_owned()));
        assert!(!status.is_final());
        assert!(TradeStatus::Confirmed.is_final());
        assert!(TradeStatus::Failed.is_final());
        assert!(!TradeStatus::Retrying.is_final());
    }
}
