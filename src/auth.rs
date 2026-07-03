//! Authentication: API credentials, L1 (EIP-712 `ClobAuth`) key derivation,
//! and L2 (HMAC) request signing.
//!
//! Two layers, per the venue's model:
//!
//! - **L1** proves control of a wallet by signing the `ClobAuth` EIP-712
//!   struct; the venue answers with [`Credentials`] (create) or re-derives
//!   the existing ones (derive). See
//!   [`ClobClientBuilder`](crate::clob::ClobClientBuilder).
//! - **L2** signs every authenticated REST request:
//!   `HMAC-SHA256(base64_url_decode(secret), "{ts}{METHOD}{path}{body}")`,
//!   sent as the `POLY_*` header set.
//!
//! Header names, message layout, and the golden test vectors are adapted
//! from the MIT-licensed `polymarket_client_sdk_v2` (see `ATTRIBUTION.md`).

use alloy::primitives::{Address, U256};
use alloy::signers::Signer;
use alloy::sol_types::{Eip712Domain, SolStruct as _, eip712_domain};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;
use hmac::{Hmac, Mac as _};
use reqwest::header::HeaderMap;
use secrecy::ExposeSecret as _;
pub use secrecy::SecretString;
use serde::Deserialize;
use sha2::Sha256;

use crate::error::Error;

/// CLOB API key identifier. The venue issues keys as UUIDs; the key rides on
/// every L2-authenticated request (`POLY_API_KEY`) and as the `owner` of
/// posted orders.
pub type ApiKey = uuid::Uuid;

/// L1/L2 header names. HTTP header lookup is case-insensitive; these render
/// lowercase on the wire.
pub const POLY_ADDRESS: &str = "POLY_ADDRESS";
pub const POLY_API_KEY: &str = "POLY_API_KEY";
pub const POLY_NONCE: &str = "POLY_NONCE";
pub const POLY_PASSPHRASE: &str = "POLY_PASSPHRASE";
pub const POLY_SIGNATURE: &str = "POLY_SIGNATURE";
pub const POLY_TIMESTAMP: &str = "POLY_TIMESTAMP";

/// API credentials issued by the venue's L1 handshake.
///
/// `secret` and `passphrase` are [`SecretString`]s: they redact in `Debug`
/// output and zeroize on drop. Deserializes directly from the venue's
/// `{"apiKey": …, "secret": …, "passphrase": …}` response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Credentials {
    #[serde(alias = "apiKey")]
    key: ApiKey,
    secret: SecretString,
    passphrase: SecretString,
}

impl Credentials {
    #[must_use]
    pub fn new(key: ApiKey, secret: String, passphrase: String) -> Self {
        Self {
            key,
            secret: SecretString::from(secret),
            passphrase: SecretString::from(passphrase),
        }
    }

    /// The API key (order `owner`, `POLY_API_KEY` header).
    #[must_use]
    pub const fn key(&self) -> ApiKey {
        self.key
    }

    /// The base64-URL-encoded HMAC secret.
    #[must_use]
    pub const fn secret(&self) -> &SecretString {
        &self.secret
    }

    /// The passphrase (`POLY_PASSPHRASE` header).
    #[must_use]
    pub const fn passphrase(&self) -> &SecretString {
        &self.passphrase
    }
}

mod clob_auth {
    use alloy::sol;

    sol! {
        /// The L1 attestation struct. Field order is load-bearing for the
        /// EIP-712 typehash.
        struct ClobAuth {
            address address;
            string  timestamp;
            uint256 nonce;
            string  message;
        }
    }
}

const CLOB_AUTH_MESSAGE: &str = "This message attests that I control the given wallet";

const fn clob_auth_domain(chain_id: u64) -> Eip712Domain {
    eip712_domain! {
        name: "ClobAuthDomain",
        version: "1",
        chain_id: chain_id,
    }
}

/// Builds the L1 headers (`POLY_ADDRESS`/`POLY_NONCE`/`POLY_SIGNATURE`/
/// `POLY_TIMESTAMP`) that authorize API-key creation and derivation.
///
/// `timestamp` is Unix seconds; `nonce` defaults to `0` (each nonce maps to
/// one API key — pass a different nonce to mint additional keys for the same
/// wallet).
pub async fn l1_headers<S: Signer + Sync>(
    signer: &S,
    chain_id: u64,
    timestamp: i64,
    nonce: Option<u32>,
) -> Result<HeaderMap, Error> {
    let naive_nonce = nonce.unwrap_or(0);

    let auth = clob_auth::ClobAuth {
        address: signer.address(),
        timestamp: timestamp.to_string(),
        nonce: U256::from(naive_nonce),
        message: CLOB_AUTH_MESSAGE.to_owned(),
    };

    let hash = auth.eip712_signing_hash(&clob_auth_domain(chain_id));
    let signature = signer
        .sign_hash(&hash)
        .await
        .map_err(|e| Error::InvalidData(format!("L1 signing failed: {e}")))?;

    let mut map = HeaderMap::new();
    let address = format!("{:#x}", signer.address());
    insert_header(&mut map, POLY_ADDRESS, &address)?;
    insert_header(&mut map, POLY_NONCE, &naive_nonce.to_string())?;
    insert_header(&mut map, POLY_SIGNATURE, &signature.to_string())?;
    insert_header(&mut map, POLY_TIMESTAMP, &timestamp.to_string())?;

    Ok(map)
}

/// The exact byte string L2 signs: `{timestamp}{METHOD}{path}{body}`.
///
/// `path` is the URL path only — query strings are *not* part of the signed
/// message. `body` is the exact bytes that will be sent (empty for GET).
#[must_use]
pub fn l2_message(timestamp: i64, method: &str, path: &str, body: &str) -> String {
    format!("{timestamp}{method}{path}{body}")
}

/// HMAC-SHA256 of `message` under the base64-URL-decoded `secret`, re-encoded
/// base64-URL — the `POLY_SIGNATURE` value.
pub fn l2_hmac(secret: &SecretString, message: &str) -> Result<String, Error> {
    let decoded_secret = URL_SAFE
        .decode(secret.expose_secret())
        .map_err(|e| Error::InvalidData(format!("credentials secret is not base64: {e}")))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&decoded_secret)
        .map_err(|e| Error::InvalidData(format!("HMAC init failed: {e}")))?;
    mac.update(message.as_bytes());

    let result = mac.finalize().into_bytes();
    Ok(URL_SAFE.encode(result))
}

/// Builds the full L2 header set for one request. `address` is the signer's
/// EOA (sent checksummed); `path`/`body` per [`l2_message`].
pub fn l2_headers(
    address: Address,
    credentials: &Credentials,
    timestamp: i64,
    method: &str,
    path: &str,
    body: &str,
) -> Result<HeaderMap, Error> {
    let signature = l2_hmac(
        &credentials.secret,
        &l2_message(timestamp, method, path, body),
    )?;

    let mut map = HeaderMap::new();
    insert_header(&mut map, POLY_ADDRESS, &address.to_checksum(None))?;
    insert_header(&mut map, POLY_API_KEY, &credentials.key.to_string())?;
    insert_header(
        &mut map,
        POLY_PASSPHRASE,
        credentials.passphrase.expose_secret(),
    )?;
    insert_header(&mut map, POLY_SIGNATURE, &signature)?;
    insert_header(&mut map, POLY_TIMESTAMP, &timestamp.to_string())?;

    Ok(map)
}

fn insert_header(map: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), Error> {
    let value = value
        .parse()
        .map_err(|_| Error::InvalidData(format!("invalid header value for {name}")))?;
    map.insert(name, value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use alloy::signers::local::PrivateKeySigner;

    use super::*;
    use crate::chain::AMOY;

    // Publicly known throwaway key (the anvil dev key).
    const PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    // Golden vectors adapted from the MIT-licensed polymarket_client_sdk_v2
    // test suite (see ATTRIBUTION.md).
    #[tokio::test]
    async fn l1_headers_match_golden_vector() {
        let signer = PrivateKeySigner::from_str(PRIVATE_KEY).unwrap();

        let headers = l1_headers(&signer, AMOY, 10_000_000, Some(23))
            .await
            .unwrap();

        assert_eq!(
            headers[POLY_ADDRESS],
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert_eq!(headers[POLY_NONCE], "23");
        assert_eq!(
            headers[POLY_SIGNATURE],
            "0xf62319a987514da40e57e2f4d7529f7bac38f0355bd88bb5adbb3768d80de6c1682518e0af677d5260366425f4361e7b70c25ae232aff0ab2331e2b164a1aedc1b"
        );
        assert_eq!(headers[POLY_TIMESTAMP], "10000000");
    }

    #[test]
    fn l2_headers_match_golden_vector() {
        let signer = PrivateKeySigner::from_str(PRIVATE_KEY).unwrap();
        let credentials = Credentials::new(
            ApiKey::nil(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        );

        let headers = l2_headers(signer.address(), &credentials, 1, "GET", "/", "").unwrap();

        assert_eq!(
            headers[POLY_ADDRESS],
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        );
        assert_eq!(
            headers[POLY_PASSPHRASE],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(headers[POLY_API_KEY], ApiKey::nil().to_string());
        assert_eq!(
            headers[POLY_SIGNATURE],
            "eHaylCwqRSOa2LFD77Nt_SaTpbsxzN8eTEI3LryhEj4="
        );
        assert_eq!(headers[POLY_TIMESTAMP], "1");
    }

    #[test]
    fn l2_message_layout() {
        assert_eq!(
            l2_message(1, "POST", "/path", r#"{"foo":"bar"}"#),
            r#"1POST/path{"foo":"bar"}"#
        );
    }

    #[test]
    fn l2_hmac_matches_golden_vector() {
        let message = l2_message(1_000_000, "test-sign", "/orders", r#"{"hash":"0x123"}"#);
        assert_eq!(message, r#"1000000test-sign/orders{"hash":"0x123"}"#);

        let signature = l2_hmac(
            &SecretString::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()),
            &message,
        )
        .unwrap();
        assert_eq!(signature, "4gJVbox-R6XlDK4nlaicig0_ANVL1qdcahiL8CXfXLM=");
    }

    #[test]
    fn debug_does_not_expose_secrets() {
        let secret_value = "my_super_secret_value_12345";
        let passphrase_value = "my_super_secret_passphrase_67890";
        let credentials = Credentials::new(
            ApiKey::nil(),
            secret_value.to_owned(),
            passphrase_value.to_owned(),
        );

        let debug_output = format!("{credentials:?}");
        assert!(!debug_output.contains(secret_value));
        assert!(!debug_output.contains(passphrase_value));
    }

    #[test]
    fn credentials_deserialize_from_venue_shape() {
        let creds: Credentials = serde_json::from_str(
            r#"{"apiKey":"019097a4-cb4e-79d8-bb5f-b4f8b1d800f5","secret":"c2VjcmV0","passphrase":"pass"}"#,
        )
        .unwrap();
        assert_eq!(
            creds.key().to_string(),
            "019097a4-cb4e-79d8-bb5f-b4f8b1d800f5"
        );
        assert_eq!(creds.secret().expose_secret(), "c2VjcmV0");
        assert_eq!(creds.passphrase().expose_secret(), "pass");
    }
}
