//! Crate-wide error type.

use thiserror::Error;

/// Relayer `/submit` response substring shown when another action is already in
/// flight for the wallet. Matched as a string because the relayer returns it in
/// the HTTP error body, which we surface as [`Error::InvalidData`].
const WALLET_BUSY_MARKER: &str = "wallet busy: active action exists";

/// Unified error type for all SDK operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Non-2xx response from a Polymarket HTTP API (CLOB, Gamma, Data, relayer).
    #[error("API error ({status}): {body}")]
    Api { status: u16, body: String },

    /// HTTP 429. `retry_after` carries the raw `Retry-After` header when the
    /// venue sent one; it is advisory only.
    #[error("rate limited")]
    RateLimit { retry_after: Option<String> },

    /// A response or input that could not be interpreted. The relayer's
    /// "wallet busy" condition also surfaces here — see [`Error::is_wallet_busy`].
    #[error("{0}")]
    InvalidData(String),

    /// The relayer rejected a submission because the API key's quota is spent.
    /// `resets_in_secs` is scraped from the response body and is known to be
    /// unreliable (the real reset is usually much sooner) — treat it as
    /// logging-only and retry on your own fixed cadence.
    #[error("relayer quota exhausted, resets in {resets_in_secs}s")]
    RelayerQuotaExhausted { resets_in_secs: u64 },

    /// WebSocket transport failure or liveness (PONG deadline) breach.
    #[cfg(feature = "ws")]
    #[error("websocket error: {0}")]
    Ws(String),
}

impl Error {
    /// True when this is the transient relayer "wallet busy" condition. It
    /// clears once the in-flight action settles, so callers can wait and retry.
    #[must_use]
    pub fn is_wallet_busy(&self) -> bool {
        matches!(self, Self::InvalidData(msg) if msg.contains(WALLET_BUSY_MARKER))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_busy_detection() {
        let busy = Error::InvalidData(
            "relayer error 400: {\"error\":\"wallet busy: active action exists\"}".into(),
        );
        assert!(busy.is_wallet_busy());

        let other = Error::InvalidData("some other error".into());
        assert!(!other.is_wallet_busy());

        let quota = Error::RelayerQuotaExhausted { resets_in_secs: 60 };
        assert!(!quota.is_wallet_busy());
    }
}
