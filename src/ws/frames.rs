//! Subscribe frames and the liveness protocol for Polymarket's WS channels.
//!
//! Liveness is text-frame based, not WebSocket ping opcodes: send the literal
//! text [`PING`] every [`PING_INTERVAL`]; the venue answers with the literal
//! text [`PONG`]. A socket that hasn't ponged within [`PONG_TIMEOUT`] is
//! half-open (NAT drop, server stall) and must be reconnected — waiting for a
//! TCP-level failure can take minutes.

use std::time::Duration;

use secrecy::ExposeSecret as _;

use crate::auth::Credentials;

/// Liveness ping text frame.
pub const PING: &str = "PING";
/// Expected liveness answer.
pub const PONG: &str = "PONG";

/// Cadence of [`PING`] frames.
pub const PING_INTERVAL: Duration = Duration::from_secs(10);

/// No [`PONG`] for this long ⇒ treat the socket as half-open and reconnect.
/// Three ping intervals tolerates the odd dropped frame.
pub const PONG_TIMEOUT: Duration = Duration::from_secs(30);

/// The market-channel subscribe frame: `{"assets_ids": […], "type":
/// "market"}`. `custom_features` additionally requests the
/// `best_bid_ask`/`new_market`/`market_resolved` event kinds.
#[must_use]
pub fn market_subscribe_frame(token_ids: &[String], custom_features: bool) -> String {
    let frame = if custom_features {
        serde_json::json!({
            "assets_ids": token_ids,
            "type": "market",
            "custom_feature_enabled": true,
        })
    } else {
        serde_json::json!({
            "assets_ids": token_ids,
            "type": "market",
        })
    };
    frame.to_string()
}

/// The user-channel subscribe frame. Carries the raw credentials in-band —
/// that is the venue's protocol — so send it only over the TLS socket.
///
/// Empty `markets` subscribes to every fill on the authenticated account.
#[must_use]
pub fn user_subscribe_frame(credentials: &Credentials, markets: &[String]) -> String {
    serde_json::json!({
        "type": "user",
        "markets": markets,
        "auth": {
            "apiKey": credentials.key().to_string(),
            "secret": credentials.secret().expose_secret(),
            "passphrase": credentials.passphrase().expose_secret(),
        },
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::ApiKey;

    #[test]
    fn market_frame_shape() {
        let frame = market_subscribe_frame(&["111".to_owned(), "222".to_owned()], true);
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "market");
        assert_eq!(v["assets_ids"], serde_json::json!(["111", "222"]));
        assert_eq!(v["custom_feature_enabled"], true);

        let plain = market_subscribe_frame(&[], false);
        let v: serde_json::Value = serde_json::from_str(&plain).unwrap();
        assert!(v.get("custom_feature_enabled").is_none());
    }

    #[test]
    fn user_frame_shape() {
        let creds = Credentials::new(ApiKey::nil(), "c2VjcmV0".into(), "pass".into());
        let frame = user_subscribe_frame(&creds, &[]);
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["type"], "user");
        assert_eq!(v["markets"], serde_json::json!([]));
        assert_eq!(v["auth"]["apiKey"], ApiKey::nil().to_string());
        assert_eq!(v["auth"]["secret"], "c2VjcmV0");
        assert_eq!(v["auth"]["passphrase"], "pass");
    }

    #[test]
    fn pong_timeout_is_three_ping_intervals() {
        assert_eq!(PONG_TIMEOUT, PING_INTERVAL * 3);
    }
}
