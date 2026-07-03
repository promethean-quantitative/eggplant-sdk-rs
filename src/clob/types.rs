//! CLOB order types and their venue wire serialization.
//!
//! The EIP-712 `Order` struct layouts (V1/V2) and the signed-order JSON shape
//! are adapted from the MIT-licensed `polymarket_client_sdk_v2` (see
//! `ATTRIBUTION.md`). They mirror the deployed CTF Exchange contracts and the
//! CLOB's expected request bodies exactly — field order and type strings are
//! load-bearing for the EIP-712 typehash, and the JSON layout is what the
//! venue's HMAC-signed POST bodies carry.
//!
//! Enums deliberately keep lenient `Unknown` tails: the venue adds statuses
//! and order types without notice, and a strict parse fails the whole
//! response (a closed tick-size enum meeting a new venue tick can take a
//! client down at startup).

use std::fmt;

use alloy::primitives::{Address, B256, Signature, U256};
use rust_decimal::Decimal;
use serde::ser::{Error as _, SerializeStruct as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::auth::ApiKey;
use crate::error::Error;

/// Order side. `Unknown` (255) absorbs venue drift on deserialization; it is
/// never valid to *send*.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[repr(u8)]
pub enum Side {
    #[serde(alias = "buy")]
    Buy = 0,
    #[serde(alias = "sell")]
    Sell = 1,
    #[serde(other)]
    Unknown = 255,
}

impl fmt::Display for Side {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Buy => "BUY",
            Self::Sell => "SELL",
            Self::Unknown => "UNKNOWN",
        })
    }
}

impl TryFrom<u8> for Side {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Buy),
            1 => Ok(Self::Sell),
            other => Err(Error::InvalidData(format!(
                "unable to create Side from {other}"
            ))),
        }
    }
}

/// Venue order types.
#[non_exhaustive]
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum OrderType {
    /// Good 'til Cancelled: rests on the book until explicitly cancelled.
    #[serde(alias = "gtc")]
    GTC,
    /// Fill or Kill: fills in full immediately or cancels entirely.
    #[default]
    #[serde(alias = "fok")]
    FOK,
    /// Good 'til Date: rests until the payload's `expiration`.
    #[serde(alias = "gtd")]
    GTD,
    /// Fill and Kill: fills what it can immediately, cancels the remainder.
    #[serde(alias = "fak")]
    FAK,
    /// Unknown order type from the API (raw value retained for debugging).
    #[serde(untagged)]
    Unknown(String),
}

impl fmt::Display for OrderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GTC => f.write_str("GTC"),
            Self::FOK => f.write_str("FOK"),
            Self::GTD => f.write_str("GTD"),
            Self::FAK => f.write_str("FAK"),
            Self::Unknown(raw) => f.write_str(raw),
        }
    }
}

/// How the venue validates the order signature, and which wallet is the
/// order's `maker`.
///
/// | type | maker            | signer | wallet kind                          |
/// |------|------------------|--------|--------------------------------------|
/// | 0    | EOA              | EOA    | plain externally-owned account       |
/// | 1    | proxy wallet     | EOA    | Magic/email proxy ([`crate::chain::derive_proxy_wallet`]) |
/// | 2    | Safe wallet      | EOA    | browser-wallet Gnosis Safe ([`crate::chain::derive_safe_wallet`]) |
/// | 3    | deposit wallet   | deposit wallet | ERC-1271 deposit wallet (wrapped signature) |
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum SignatureType {
    /// Plain EOA ECDSA (signature type 0).
    #[default]
    Eoa = 0,
    /// Polymarket proxy wallet (Magic/email login), signed by the owning EOA.
    Proxy = 1,
    /// 1-of-1 Gnosis Safe (browser wallet), signed by the owning EOA.
    GnosisSafe = 2,
    /// EIP-1271 deposit wallet: the wrapped Solady `TypedDataSign` scheme.
    /// V2 orders only.
    Poly1271 = 3,
}

impl Serialize for SignatureType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for SignatureType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = u8::deserialize(deserializer)?;
        Self::try_from(raw).map_err(de::Error::custom)
    }
}

impl TryFrom<u8> for SignatureType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Eoa),
            1 => Ok(Self::Proxy),
            2 => Ok(Self::GnosisSafe),
            3 => Ok(Self::Poly1271),
            other => Err(Error::InvalidData(format!(
                "unable to create SignatureType from {other}"
            ))),
        }
    }
}

// Each version is defined inside its own module so that `sol!` emits the
// Solidity type name `Order` for both — that is what the on-chain CTF Exchange
// contracts hash into their EIP-712 typehashes. Renaming the Rust struct would
// change the typehash and invalidate every signature.
mod v1 {
    use alloy::sol;

    sol! {
        /// EIP-712 order struct for the legacy Polymarket CTF Exchange (V1).
        ///
        /// `expiration` is part of the signed struct. Field order mirrors the
        /// on-chain contract's typehash and must not change.
        #[derive(Debug, Default, PartialEq, Eq)]
        struct Order {
            uint256 salt;
            address maker;
            address signer;
            address taker;
            uint256 tokenId;
            uint256 makerAmount;
            uint256 takerAmount;
            uint256 expiration;
            uint256 nonce;
            uint256 feeRateBps;
            uint8   side;
            uint8   signatureType;
        }
    }
}

mod v2 {
    use alloy::sol;

    sol! {
        /// EIP-712 order struct for the Polymarket CTF Exchange V2.
        ///
        /// `expiration` is NOT part of the signed struct; it travels on the
        /// outer JSON payload. Field order mirrors the on-chain contract's
        /// typehash and must not change.
        #[derive(Debug, Default, PartialEq, Eq)]
        struct Order {
            uint256 salt;
            address maker;
            address signer;
            uint256 tokenId;
            uint256 makerAmount;
            uint256 takerAmount;
            uint8   side;
            uint8   signatureType;
            uint256 timestamp;
            bytes32 metadata;
            bytes32 builder;
        }
    }
}

pub use v1::Order as OrderV1;
pub use v2::Order as OrderV2;

/// V2 order payload: the signed struct plus the out-of-struct `expiration`.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OrderPayloadV2 {
    pub order: OrderV2,
    pub expiration: U256,
}

/// V1 order payload. `expiration` lives inside the signed struct.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OrderPayloadV1 {
    pub order: OrderV1,
}

/// The order payload, version-tagged.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum OrderPayload {
    V1(OrderPayloadV1),
    V2(OrderPayloadV2),
}

impl Default for OrderPayload {
    fn default() -> Self {
        Self::V2(OrderPayloadV2::default())
    }
}

impl OrderPayload {
    /// Construct a V2 payload — the current order flow.
    #[must_use]
    pub const fn new(order: OrderV2, expiration: U256) -> Self {
        Self::V2(OrderPayloadV2 { order, expiration })
    }

    /// Construct a V1 payload (legacy exchange).
    #[must_use]
    pub const fn new_v1(order: OrderV1) -> Self {
        Self::V1(OrderPayloadV1 { order })
    }

    /// The protocol version this payload targets (1 or 2).
    #[must_use]
    pub const fn version(&self) -> u32 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
        }
    }

    /// The V2 order reference, or `None` for V1 payloads.
    #[must_use]
    pub const fn as_v2(&self) -> Option<&OrderV2> {
        match self {
            Self::V2(p) => Some(&p.order),
            Self::V1(_) => None,
        }
    }

    /// The V1 order reference, or `None` for V2 payloads.
    #[must_use]
    pub const fn as_v1(&self) -> Option<&OrderV1> {
        match self {
            Self::V1(p) => Some(&p.order),
            Self::V2(_) => None,
        }
    }
}

/// An order ready to sign: payload plus the venue-level flags that ride the
/// outer JSON body.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignableOrder {
    pub payload: OrderPayload,
    pub order_type: OrderType,
    /// Only emit when set: the venue rejects `postOnly` on non-GTC/GTD order
    /// types, so taker orders must omit the field entirely.
    pub post_only: Option<bool>,
    pub defer_exec: Option<bool>,
}

impl SignableOrder {
    /// A plain signable order with no `postOnly`/`deferExec` flags.
    #[must_use]
    pub const fn new(payload: OrderPayload, order_type: OrderType) -> Self {
        Self {
            payload,
            order_type,
            post_only: None,
            defer_exec: None,
        }
    }

    /// Sets `postOnly`. Only meaningful for GTC/GTD orders.
    #[must_use]
    pub const fn with_post_only(mut self, post_only: bool) -> Self {
        self.post_only = Some(post_only);
        self
    }

    /// Sets `deferExec`.
    #[must_use]
    pub const fn with_defer_exec(mut self, defer_exec: bool) -> Self {
        self.defer_exec = Some(defer_exec);
        self
    }

    /// Returns the V2 order struct.
    ///
    /// # Panics
    ///
    /// Panics if this is a V1 order. Callers that may encounter either
    /// version should inspect [`SignableOrder::payload`] directly.
    #[must_use]
    pub fn order(&self) -> &OrderV2 {
        &self.v2().order
    }

    /// Returns the V2 payload.
    ///
    /// # Panics
    ///
    /// Panics if this is a V1 order.
    #[must_use]
    pub fn v2(&self) -> &OrderPayloadV2 {
        match &self.payload {
            OrderPayload::V2(p) => p,
            OrderPayload::V1(_) => panic!("SignableOrder is V1; match on .payload directly"),
        }
    }
}

/// A signed order in the exact shape the venue accepts. Serialize it and POST
/// the bytes — the JSON layout here is what the venue-side HMAC covers.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub struct SignedOrder {
    pub payload: OrderPayload,
    pub signature: OrderSignature,
    pub order_type: OrderType,
    /// The API key that owns the order (rides as `owner`).
    pub owner: ApiKey,
    pub post_only: Option<bool>,
    pub defer_exec: Option<bool>,
}

impl SignedOrder {
    /// Assemble a signed order. Prefer signing through
    /// [`OrderSigner::sign_order`](crate::clob::signing::OrderSigner::sign_order);
    /// this constructor exists for callers bringing their own signing scheme.
    #[must_use]
    pub fn new(
        payload: OrderPayload,
        signature: impl Into<OrderSignature>,
        order_type: OrderType,
        owner: ApiKey,
    ) -> Self {
        Self {
            payload,
            signature: signature.into(),
            order_type,
            owner,
            post_only: None,
            defer_exec: None,
        }
    }

    /// Sets `postOnly`. Only meaningful for GTC/GTD orders.
    #[must_use]
    pub const fn with_post_only(mut self, post_only: bool) -> Self {
        self.post_only = Some(post_only);
        self
    }

    /// Sets `deferExec`.
    #[must_use]
    pub const fn with_defer_exec(mut self, defer_exec: bool) -> Self {
        self.defer_exec = Some(defer_exec);
        self
    }

    /// Returns the V2 order struct.
    ///
    /// # Panics
    ///
    /// Panics if this is a V1 order. Callers that may encounter either
    /// version should inspect [`SignedOrder::payload`] directly.
    #[must_use]
    pub fn order(&self) -> &OrderV2 {
        &self.v2().order
    }

    /// Returns the V2 payload.
    ///
    /// # Panics
    ///
    /// Panics if this is a V1 order.
    #[must_use]
    pub fn v2(&self) -> &OrderPayloadV2 {
        match &self.payload {
            OrderPayload::V2(p) => p,
            OrderPayload::V1(_) => panic!("SignedOrder is V1; match on .payload directly"),
        }
    }
}

/// Signature material attached to a signed order.
///
/// Types 0/1/2 carry a normal 65-byte ECDSA signature. Deposit-wallet orders
/// ([`SignatureType::Poly1271`]) carry the longer wrapped signature the wallet
/// validates through EIP-1271.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub enum OrderSignature {
    Ecdsa(Signature),
    Wrapped(String),
}

impl From<Signature> for OrderSignature {
    fn from(signature: Signature) -> Self {
        Self::Ecdsa(signature)
    }
}

impl From<String> for OrderSignature {
    fn from(signature: String) -> Self {
        Self::Wrapped(signature)
    }
}

impl From<&str> for OrderSignature {
    fn from(signature: &str) -> Self {
        Self::Wrapped(signature.to_owned())
    }
}

impl fmt::Display for OrderSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // 65 bytes r ‖ s ‖ v with v ∈ {27, 28} — the venue's expected
            // ECDSA wire form (py-clob-client emits the same).
            Self::Ecdsa(sig) => {
                f.write_str("0x")?;
                for byte in sig.as_bytes() {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Wrapped(sig) => f.write_str(sig),
        }
    }
}

// CLOB expects salt as a JSON number. A u64-generated salt (see
// `signing::generate_salt`) always fits; anything larger is a caller bug we
// surface instead of silently truncating.
fn ser_salt<S: Serializer>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> {
    let v: u64 = (*value)
        .try_into()
        .map_err(|e| S::Error::custom(format!("salt does not fit into u64: {e}")))?;
    serializer.serialize_u64(v)
}

// tokenId / amounts / timestamps ride as decimal strings.
#[allow(clippy::trivially_copy_pass_by_ref)] // serde serialize_with signature
fn ser_u256_dec<S: Serializer>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

/// V2 `order` body with the signature folded in.
#[derive(Serialize)]
struct OrderV2WithSignature {
    #[serde(serialize_with = "ser_salt")]
    salt: U256,
    maker: Address,
    signer: Address,
    #[serde(rename = "tokenId", serialize_with = "ser_u256_dec")]
    token_id: U256,
    #[serde(rename = "makerAmount", serialize_with = "ser_u256_dec")]
    maker_amount: U256,
    #[serde(rename = "takerAmount", serialize_with = "ser_u256_dec")]
    taker_amount: U256,
    side: Side,
    #[serde(serialize_with = "ser_u256_dec")]
    expiration: U256,
    #[serde(rename = "signatureType")]
    signature_type: u8,
    #[serde(serialize_with = "ser_u256_dec")]
    timestamp: U256,
    metadata: B256,
    builder: B256,
    signature: String,
}

/// V1 `order` body with the signature folded in.
#[derive(Serialize)]
struct OrderV1WithSignature {
    #[serde(serialize_with = "ser_salt")]
    salt: U256,
    maker: Address,
    signer: Address,
    taker: Address,
    #[serde(rename = "tokenId", serialize_with = "ser_u256_dec")]
    token_id: U256,
    #[serde(rename = "makerAmount", serialize_with = "ser_u256_dec")]
    maker_amount: U256,
    #[serde(rename = "takerAmount", serialize_with = "ser_u256_dec")]
    taker_amount: U256,
    side: Side,
    #[serde(serialize_with = "ser_u256_dec")]
    expiration: U256,
    #[serde(serialize_with = "ser_u256_dec")]
    nonce: U256,
    #[serde(rename = "feeRateBps", serialize_with = "ser_u256_dec")]
    fee_rate_bps: U256,
    #[serde(rename = "signatureType")]
    signature_type: u8,
    signature: String,
}

// The CLOB expects the signature folded into the inner `order` object. Shape
// differs between V1 and V2; the outer wrapper (order / orderType / owner /
// postOnly / deferExec) is identical.
impl Serialize for SignedOrder {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut field_count = 3;
        if self.post_only.is_some() {
            field_count += 1;
        }
        if self.defer_exec.is_some() {
            field_count += 1;
        }
        let mut st = serializer.serialize_struct("SignedOrder", field_count)?;

        match &self.payload {
            OrderPayload::V2(payload) => {
                let order = &payload.order;
                let side = Side::try_from(order.side).map_err(S::Error::custom)?;
                let body = OrderV2WithSignature {
                    salt: order.salt,
                    maker: order.maker,
                    signer: order.signer,
                    token_id: order.tokenId,
                    maker_amount: order.makerAmount,
                    taker_amount: order.takerAmount,
                    side,
                    expiration: payload.expiration,
                    signature_type: order.signatureType,
                    timestamp: order.timestamp,
                    metadata: order.metadata,
                    builder: order.builder,
                    signature: self.signature.to_string(),
                };
                st.serialize_field("order", &body)?;
            }
            OrderPayload::V1(payload) => {
                let order = &payload.order;
                let side = Side::try_from(order.side).map_err(S::Error::custom)?;
                let body = OrderV1WithSignature {
                    salt: order.salt,
                    maker: order.maker,
                    signer: order.signer,
                    taker: order.taker,
                    token_id: order.tokenId,
                    maker_amount: order.makerAmount,
                    taker_amount: order.takerAmount,
                    side,
                    expiration: order.expiration,
                    nonce: order.nonce,
                    fee_rate_bps: order.feeRateBps,
                    signature_type: order.signatureType,
                    signature: self.signature.to_string(),
                };
                st.serialize_field("order", &body)?;
            }
        }

        st.serialize_field("orderType", &self.order_type)?;
        st.serialize_field("owner", &self.owner)?;
        if let Some(post_only) = self.post_only {
            st.serialize_field("postOnly", &post_only)?;
        }
        if let Some(defer_exec) = self.defer_exec {
            st.serialize_field("deferExec", &defer_exec)?;
        }

        st.end()
    }
}

// ---------------------------------------------------------------------------
// REST response types (lenient by design)
// ---------------------------------------------------------------------------

/// Venue order status. Lenient: unknown statuses land in `Unknown` instead of
/// failing the response.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum OrderStatus {
    #[serde(alias = "live")]
    Live,
    #[serde(alias = "matched")]
    Matched,
    #[serde(alias = "canceled")]
    Canceled,
    #[serde(alias = "delayed")]
    Delayed,
    #[serde(alias = "unmatched")]
    Unmatched,
    /// Unknown order status from the API (raw value retained for debugging).
    #[serde(untagged)]
    Unknown(String),
}

impl Default for OrderStatus {
    fn default() -> Self {
        Self::Unknown(String::new())
    }
}

/// Accepts a decimal as string or number; empty/missing/null mean zero. The
/// venue sends `""` for the untouched side of a fill.
fn empty_string_as_zero<'de, D>(deserializer: D) -> Result<Decimal, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Dec(Decimal),
        Str(String),
    }
    match Option::<Raw>::deserialize(deserializer)? {
        None => Ok(Decimal::ZERO),
        Some(Raw::Dec(d)) => Ok(d),
        Some(Raw::Str(s)) if s.trim().is_empty() => Ok(Decimal::ZERO),
        Some(Raw::Str(s)) => s.trim().parse().map_err(de::Error::custom),
    }
}

/// `null` collapses to the type's default (the venue sends `null`, not `[]`
/// or `{}`, for empty collections).
fn null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Response to `POST /order(s)` — one per submitted order.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostOrderResponse {
    #[serde(default)]
    pub error_msg: Option<String>,
    /// Filled amount on the maker side of this order (shares for SELL, USDC
    /// for BUY), zero when the order rested.
    #[serde(default, deserialize_with = "empty_string_as_zero")]
    pub making_amount: Decimal,
    /// Filled amount on the taker side of this order.
    #[serde(default, deserialize_with = "empty_string_as_zero")]
    pub taking_amount: Decimal,
    #[serde(default, rename = "orderID")]
    pub order_id: String,
    #[serde(default)]
    pub status: OrderStatus,
    pub success: bool,
    #[serde(
        default,
        deserialize_with = "null_to_default",
        alias = "transactionsHashes"
    )]
    pub transaction_hashes: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub trade_ids: Vec<String>,
}

impl PostOrderResponse {
    /// Venue accepted the order: HTTP-level success and no error message.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.success && self.error_msg.as_deref().unwrap_or("").is_empty()
    }
}

/// Response to `DELETE /order(s)` and `DELETE /cancel-all`.
#[non_exhaustive]
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelOrdersResponse {
    #[serde(default, deserialize_with = "null_to_default")]
    pub canceled: Vec<String>,
    /// `order id -> reason` for every order the venue declined to cancel.
    #[serde(default, deserialize_with = "null_to_default", alias = "not_canceled")]
    pub not_canceled: std::collections::HashMap<String, String>,
}

/// One page of a cursor-paginated listing. `next_cursor == "LTE="` marks the
/// end (see [`crate::clob::TERMINAL_CURSOR`]).
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct Page<T> {
    #[serde(default = "Vec::new")]
    pub data: Vec<T>,
    #[serde(default)]
    pub next_cursor: String,
    #[serde(default)]
    pub limit: u64,
    #[serde(default)]
    pub count: u64,
}

/// One open order from `GET /data/orders`.
///
/// Deliberately lenient: every non-essential field defaults instead of
/// failing the page — a strict parse of this listing is a startup-outage
/// vector.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct OpenOrder {
    pub id: String,
    #[serde(default)]
    pub status: OrderStatus,
    #[serde(default)]
    pub owner: String,
    /// The market condition id.
    #[serde(default)]
    pub market: String,
    /// Token id (decimal string).
    #[serde(default)]
    pub asset_id: String,
    #[serde(default = "side_unknown")]
    pub side: Side,
    #[serde(default)]
    pub original_size: Decimal,
    #[serde(default)]
    pub size_matched: Decimal,
    #[serde(default)]
    pub price: Decimal,
    #[serde(default)]
    pub outcome: String,
    /// Unix seconds.
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub order_type: Option<OrderType>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub associate_trades: Vec<String>,
}

const fn side_unknown() -> Side {
    Side::Unknown
}

/// One trade from `GET /data/trades`, reduced to the load-bearing fields.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct ClobTrade {
    pub id: String,
    #[serde(default)]
    pub taker_order_id: String,
    #[serde(default)]
    pub market: String,
    #[serde(default)]
    pub asset_id: String,
    #[serde(default = "side_unknown")]
    pub side: Side,
    #[serde(default, deserialize_with = "empty_string_as_zero")]
    pub size: Decimal,
    #[serde(default, deserialize_with = "empty_string_as_zero")]
    pub price: Decimal,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub trader_side: String,
    #[serde(default)]
    pub match_time: String,
}

/// One market from `GET /markets/{condition_id}`, reduced and lenient.
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
#[allow(clippy::struct_excessive_bools)] // mirrors the API's field set
pub struct ClobMarket {
    #[serde(default)]
    pub condition_id: String,
    #[serde(default)]
    pub question_id: String,
    #[serde(default)]
    pub question: String,
    #[serde(default)]
    pub market_slug: String,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub closed: bool,
    #[serde(default)]
    pub accepting_orders: bool,
    #[serde(default)]
    pub minimum_order_size: Decimal,
    /// The market's price grid — a plain [`Decimal`], never a closed enum.
    #[serde(default)]
    pub minimum_tick_size: Decimal,
    #[serde(default)]
    pub neg_risk: bool,
    #[serde(default)]
    pub end_date_iso: Option<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    pub tokens: Vec<ClobToken>,
}

/// One outcome token of a [`ClobMarket`].
#[non_exhaustive]
#[derive(Debug, Clone, Deserialize)]
pub struct ClobToken {
    /// Token id (decimal string).
    #[serde(default)]
    pub token_id: String,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub price: Decimal,
    #[serde(default)]
    pub winner: bool,
}

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolStruct as _;
    use serde_json::{json, to_value};

    use super::*;

    // The exact typehash inputs the deployed exchanges verify against. If a
    // sol! field is renamed or reordered these break before any money moves.
    #[test]
    fn order_v2_eip712_type_string() {
        assert_eq!(
            OrderV2::eip712_root_type(),
            crate::clob::signing::ORDER_TYPE_STRING,
        );
    }

    #[test]
    fn order_v1_eip712_type_string() {
        assert_eq!(
            OrderV1::eip712_root_type(),
            "Order(uint256 salt,address maker,address signer,address taker,uint256 tokenId,uint256 makerAmount,uint256 takerAmount,uint256 expiration,uint256 nonce,uint256 feeRateBps,uint8 side,uint8 signatureType)"
        );
    }

    #[test]
    fn side_wire_strings() {
        assert_eq!(Side::Buy.to_string(), "BUY");
        assert_eq!(Side::Sell.to_string(), "SELL");
        assert_eq!(serde_json::to_value(Side::Buy).unwrap(), json!("BUY"));
        assert_eq!(
            serde_json::from_str::<Side>(r#""sell""#).unwrap(),
            Side::Sell
        );
        // Unknown side strings degrade instead of failing the response.
        assert_eq!(
            serde_json::from_str::<Side>(r#""SHORT""#).unwrap(),
            Side::Unknown
        );
    }

    #[test]
    fn order_type_lenient_deserialize() {
        assert_eq!(
            serde_json::from_str::<OrderType>(r#""gtc""#).unwrap(),
            OrderType::GTC
        );
        assert_eq!(
            serde_json::from_str::<OrderType>(r#""NEW_ORDER_TYPE""#).unwrap(),
            OrderType::Unknown("NEW_ORDER_TYPE".to_owned())
        );
    }

    #[test]
    fn signature_type_wire_values() {
        assert_eq!(serde_json::to_value(SignatureType::Eoa).unwrap(), json!(0));
        assert_eq!(
            serde_json::to_value(SignatureType::Proxy).unwrap(),
            json!(1)
        );
        assert_eq!(
            serde_json::to_value(SignatureType::GnosisSafe).unwrap(),
            json!(2)
        );
        assert_eq!(
            serde_json::to_value(SignatureType::Poly1271).unwrap(),
            json!(3)
        );
        assert_eq!(
            serde_json::from_str::<SignatureType>("2").unwrap(),
            SignatureType::GnosisSafe
        );
        assert!(serde_json::from_str::<SignatureType>("9").is_err());
    }

    #[test]
    fn signed_order_serialization_omits_post_only_when_none() {
        let signed_order = SignedOrder::new(
            OrderPayload::default(),
            Signature::new(U256::ZERO, U256::ZERO, false),
            OrderType::GTC,
            ApiKey::nil(),
        );

        let value = to_value(&signed_order).expect("serialize SignedOrder");
        let object = value.as_object().expect("object");

        assert!(!object.contains_key("postOnly"));
        assert!(!object.contains_key("deferExec"));
    }

    #[test]
    fn signed_order_serialization_includes_v2_fields_only() {
        let signed_order = SignedOrder::new(
            OrderPayload::default(),
            Signature::new(U256::ZERO, U256::ZERO, false),
            OrderType::GTC,
            ApiKey::nil(),
        )
        .with_defer_exec(false);

        let value = to_value(&signed_order).expect("serialize SignedOrder");
        let object = value.as_object().expect("object");

        let order_obj = object["order"].as_object().unwrap();
        assert!(order_obj.contains_key("timestamp"));
        assert!(order_obj.contains_key("metadata"));
        assert!(order_obj.contains_key("builder"));
        assert!(order_obj.contains_key("expiration"));
        assert!(!order_obj.contains_key("taker"));
        assert!(!order_obj.contains_key("nonce"));
        assert!(!order_obj.contains_key("feeRateBps"));
        assert!(object.contains_key("deferExec"));
    }

    #[test]
    fn signed_order_serialization_uses_wrapped_signature() {
        let signed_order = SignedOrder::new(
            OrderPayload::default(),
            "0xwrapped",
            OrderType::GTC,
            ApiKey::nil(),
        );

        let value = to_value(&signed_order).expect("serialize SignedOrder");
        assert_eq!(value["order"]["signature"], "0xwrapped");
    }

    #[test]
    fn signed_order_wire_shape_golden() {
        let order = OrderV2 {
            salt: U256::from(12_345_u64),
            maker: Address::repeat_byte(0x11),
            signer: Address::repeat_byte(0x11),
            tokenId: U256::from(777_u64),
            makerAmount: U256::from(4_850_000_u64),
            takerAmount: U256::from(5_000_000_u64),
            side: Side::Buy as u8,
            signatureType: SignatureType::Poly1271 as u8,
            timestamp: U256::from(1_700_000_000_000_u64),
            metadata: B256::ZERO,
            builder: B256::ZERO,
        };

        let signed = SignedOrder::new(
            OrderPayload::new(order, U256::ZERO),
            "0xdeadbeef",
            OrderType::GTC,
            ApiKey::nil(),
        )
        .with_post_only(true);

        let value = to_value(&signed).expect("serialize");
        // Salt is a JSON *number*; ids/amounts/timestamps are decimal strings;
        // side is the UPPERCASE string; signatureType is a number.
        assert_eq!(value["order"]["salt"], json!(12_345));
        assert_eq!(value["order"]["tokenId"], json!("777"));
        assert_eq!(value["order"]["makerAmount"], json!("4850000"));
        assert_eq!(value["order"]["takerAmount"], json!("5000000"));
        assert_eq!(value["order"]["side"], json!("BUY"));
        assert_eq!(value["order"]["signatureType"], json!(3));
        assert_eq!(value["order"]["timestamp"], json!("1700000000000"));
        assert_eq!(value["order"]["expiration"], json!("0"));
        assert_eq!(value["orderType"], json!("GTC"));
        assert_eq!(value["postOnly"], json!(true));
        assert_eq!(
            value["owner"],
            json!("00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn post_order_response_venue_shape() {
        // The exact shape the venue answers with (string decimals, orderID).
        let response: PostOrderResponse = serde_json::from_value(json!({
            "errorMsg": "",
            "makingAmount": "1.0",
            "takingAmount": "2.0",
            "orderID": "0xabc",
            "status": "live",
            "success": true,
        }))
        .unwrap();
        assert!(response.is_accepted());
        assert_eq!(response.making_amount, Decimal::ONE);
        assert_eq!(response.order_id, "0xabc");
        assert_eq!(response.status, OrderStatus::Live);

        // Rejection with an unknown status string still parses.
        let rejected: PostOrderResponse = serde_json::from_value(json!({
            "errorMsg": "not enough balance",
            "makingAmount": "",
            "takingAmount": "",
            "orderID": "",
            "status": "SOME_NEW_STATUS",
            "success": false,
        }))
        .unwrap();
        assert!(!rejected.is_accepted());
        assert_eq!(rejected.making_amount, Decimal::ZERO);
        assert_eq!(
            rejected.status,
            OrderStatus::Unknown("SOME_NEW_STATUS".to_owned())
        );
    }

    #[test]
    fn cancel_orders_response_venue_shape() {
        let response: CancelOrdersResponse = serde_json::from_str(
            r#"{"canceled":["a"],"notCanceled":{"b":"Order already filled"}}"#,
        )
        .unwrap();
        assert_eq!(response.canceled, vec!["a"]);
        assert_eq!(
            response.not_canceled.get("b").map(String::as_str),
            Some("Order already filled")
        );

        // Nulls collapse to empty collections.
        let nulls: CancelOrdersResponse =
            serde_json::from_str(r#"{"canceled":null,"notCanceled":null}"#).unwrap();
        assert!(nulls.canceled.is_empty() && nulls.not_canceled.is_empty());
    }

    #[test]
    fn open_order_is_lenient() {
        // Only `id` is required; everything else degrades to defaults.
        let order: OpenOrder = serde_json::from_str(r#"{"id":"0xdead"}"#).unwrap();
        assert_eq!(order.id, "0xdead");
        assert_eq!(order.side, Side::Unknown);
        assert_eq!(order.status, OrderStatus::Unknown(String::new()));

        let full: OpenOrder = serde_json::from_value(json!({
            "id": "0xbeef",
            "status": "LIVE",
            "side": "BUY",
            "asset_id": "777",
            "price": "0.42",
            "original_size": "100",
            "size_matched": "1.5",
            "created_at": 1_700_000_000,
        }))
        .unwrap();
        assert_eq!(full.side, Side::Buy);
        assert_eq!(full.price, "0.42".parse().unwrap());
        assert_eq!(full.created_at, Some(1_700_000_000));
    }

    #[test]
    fn ecdsa_signature_display_is_65_byte_hex() {
        let sig = Signature::new(U256::from(1_u64), U256::from(2_u64), true);
        let rendered = OrderSignature::from(sig).to_string();
        assert!(rendered.starts_with("0x"));
        // 65 bytes → 130 hex chars.
        assert_eq!(rendered.len(), 2 + 130);
        // v rides as 27/28 in the last byte.
        let v = u8::from_str_radix(&rendered[rendered.len() - 2..], 16).unwrap();
        assert!(v == 27 || v == 28, "v was {v}");
    }
}
