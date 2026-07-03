//! Polymarket relayer-v2 client: gasless transaction submission for Safe
//! wallets and ERC-1271 deposit wallets.
//!
//! Three submission paths, all `POST {host}/submit`:
//!
//! - [`RelayerClient::submit`] — a Gnosis `SafeTx` (type `SAFE`), signed with
//!   the Safe `eth_sign` convention (`v = parity + 31`, EIP-191 re-hash).
//!   Used for approvals and arbitrary calls from a Safe wallet.
//! - [`RelayerClient::deploy`] — Safe wallet creation (type `SAFE-CREATE`).
//! - [`RelayerClient::submit_deposit_wallet_batch`] — the `DepositWallet`
//!   batch EIP-712 (type `WALLET`): N calls executed atomically from a
//!   deposit wallet. The merge/convert/redeem/split engine rides this path.
//!
//! This relayer protocol does not exist in the official SDK; the EIP-712
//! layouts here are pinned by typehash tests and a golden vector
//! cross-checked against Polymarket's Python relayer client. Requires relayer
//! API credentials (Polymarket builder program).

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, U256, b256, keccak256};
use alloy::signers::Signer;
use serde::{Deserialize, Serialize};

use crate::chain::{DEPOSIT_WALLET_FACTORY, POLYGON, RELAYER_HOST};
use crate::error::Error;

// keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
const DOMAIN_SEPARATOR_TYPEHASH: B256 =
    b256!("47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218");

// keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
const SAFE_TX_TYPEHASH: B256 =
    b256!("bb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8");

// keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)")
const CREATE_DOMAIN_TYPEHASH: B256 =
    b256!("8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a866");

// keccak256("Polymarket Contract Proxy Factory")
const SAFE_FACTORY_NAME_HASH: B256 =
    b256!("0e50835e49a5f2de690010a802604667466241e3a0473df3748c77850723de32");

// keccak256("CreateProxy(address paymentToken,uint256 payment,address paymentReceiver)")
const CREATE_PROXY_TYPEHASH: B256 =
    b256!("dee5f5588156b735c3bff14a54c9acefc845807cec91b7fd0809fa3deccab363");

const ZERO_ADDRESS_STR: &str = "0x0000000000000000000000000000000000000000";

/// Relayer client. Requires a relayer API key pair (builder program).
pub struct RelayerClient {
    http: reqwest::Client,
    host: String,
    chain_id: u64,
    api_key: String,
    api_key_address: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SubmitRequest {
    from: String,
    to: String,
    proxy_wallet: String,
    data: String,
    nonce: String,
    signature: String,
    signature_params: SignatureParams,
    #[serde(rename = "type")]
    type_: &'static str,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignatureParams {
    gas_price: &'static str,
    operation: &'static str,
    safe_txn_gas: &'static str,
    base_gas: &'static str,
    gas_token: &'static str,
    refund_receiver: &'static str,
}

const ZERO_PARAMS: SignatureParams = SignatureParams {
    gas_price: "0",
    operation: "0",
    safe_txn_gas: "0",
    base_gas: "0",
    gas_token: ZERO_ADDRESS_STR,
    refund_receiver: ZERO_ADDRESS_STR,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeployRequest {
    from: String,
    to: String,
    proxy_wallet: String,
    data: &'static str,
    signature: String,
    signature_params: DeploySignatureParams,
    #[serde(rename = "type")]
    type_: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeploySignatureParams {
    payment_token: &'static str,
    payment: &'static str,
    payment_receiver: &'static str,
}

/// Relayer acknowledgement of a submission.
#[derive(Debug, Deserialize)]
pub struct SubmitResponse {
    #[serde(rename = "transactionID")]
    pub transaction_id: String,
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<String>,
}

impl RelayerClient {
    /// A client against the production relayer ([`RELAYER_HOST`]) on Polygon.
    #[must_use]
    pub fn new(api_key: String, api_key_address: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            host: RELAYER_HOST.to_owned(),
            chain_id: POLYGON,
            api_key,
            api_key_address,
        }
    }

    /// Override the relayer host (no trailing slash).
    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// Override the chain id used for [`Self::submit`]'s `SafeTx` domain.
    #[must_use]
    pub const fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Submit one call from a Safe wallet (type `SAFE`): sign the `SafeTx`
    /// EIP-712 hash with the Safe `eth_sign` convention and relay it.
    pub async fn submit<S: Signer + Sync>(
        &self,
        signer: &S,
        safe: Address,
        to: Address,
        data: &[u8],
        nonce: u64,
    ) -> Result<SubmitResponse, Error> {
        let tx_hash = compute_safe_tx_hash(safe, self.chain_id, to, data, nonce);

        let sig = signer
            .sign_message(tx_hash.as_ref())
            .await
            .map_err(|e| Error::InvalidData(format!("signing failed: {e}")))?;

        // Safe eth_sign: v = parity + 31 (tells the Safe to verify with the
        // EIP-191 prefix).
        let sig_raw = pack_signature(&sig, 31);

        let request = SubmitRequest {
            from: signer.address().to_string(),
            to: to.to_string(),
            proxy_wallet: safe.to_string(),
            data: to_hex(data),
            nonce: nonce.to_string(),
            signature: to_hex(&sig_raw),
            signature_params: ZERO_PARAMS,
            type_: "SAFE",
        };

        self.post_submit(&request).await
    }

    /// Deploy the signer's Safe wallet (type `SAFE-CREATE`).
    pub async fn deploy<S: Signer + Sync>(
        &self,
        signer: &S,
        safe_factory: Address,
        safe_address: Address,
        chain_id: u64,
    ) -> Result<SubmitResponse, Error> {
        tracing::info!(%safe_address, %safe_factory, "deploying Safe wallet via relayer");

        let eip712_hash = compute_create_proxy_hash(safe_factory, chain_id);

        let sig = signer
            .sign_hash(&eip712_hash)
            .await
            .map_err(|e| Error::InvalidData(format!("signing failed: {e}")))?;

        let sig_raw = pack_signature(&sig, 27);

        let request = DeployRequest {
            from: signer.address().to_string(),
            to: safe_factory.to_string(),
            proxy_wallet: safe_address.to_string(),
            data: "0x",
            signature: to_hex(&sig_raw),
            signature_params: DeploySignatureParams {
                payment_token: ZERO_ADDRESS_STR,
                payment: "0",
                payment_receiver: ZERO_ADDRESS_STR,
            },
            type_: "SAFE-CREATE",
        };

        let resp = self
            .http
            .post(format!("{}/submit", self.host))
            .header("RELAYER_API_KEY", &self.api_key)
            .header("RELAYER_API_KEY_ADDRESS", &self.api_key_address)
            .json(&request)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::InvalidData(format!(
                "relayer deploy error ({status}): {body}"
            )));
        }

        let result: SubmitResponse = resp.json().await?;
        tracing::info!(tx_id = %result.transaction_id, "Safe deploy submitted");
        Ok(result)
    }

    async fn post_submit<R: Serialize + Sync>(&self, request: &R) -> Result<SubmitResponse, Error> {
        let resp = self
            .http
            .post(format!("{}/submit", self.host))
            .header("RELAYER_API_KEY", &self.api_key)
            .header("RELAYER_API_KEY_ADDRESS", &self.api_key_address)
            .json(request)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            // Quota exhaustion isn't always a clean 429 — match the body too,
            // so a non-429 "quota exceeded" isn't misrouted to `InvalidData`
            // (where a retry cycle would burn its rebuild attempts hammering
            // the same dead quota). `resets_in_secs` is for the log only; pick
            // your own retry cadence, the relayer's hint is unreliable (it
            // reports ~3600s while the quota actually frees in well under a
            // minute).
            if is_quota_response(status.as_u16(), &body) {
                let resets_in_secs = parse_quota_reset(&body).unwrap_or(3600);
                return Err(Error::RelayerQuotaExhausted { resets_in_secs });
            }
            return Err(Error::InvalidData(format!(
                "relayer error ({status}): {body}"
            )));
        }

        resp.json().await.map_err(Error::from)
    }
}

/// Classify a failed relayer response as quota exhaustion. It usually arrives
/// as HTTP 429, but not always — a non-429 body that mentions "quota" is
/// treated the same so it routes to the caller's retry path instead of being
/// misread as a hard error.
fn is_quota_response(status: u16, body: &str) -> bool {
    status == 429 || body.to_ascii_lowercase().contains("quota")
}

fn parse_quota_reset(body: &str) -> Option<u64> {
    let idx = body.find("resets in ")?;
    let rest = &body[idx + 10..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Pack an alloy signature into the 65-byte `r ‖ s ‖ v` form with
/// `v = parity + v_base` (27 for raw EIP-712, 31 for Safe `eth_sign`).
fn pack_signature(sig: &alloy::primitives::Signature, v_base: u8) -> [u8; 65] {
    let v = u8::from(sig.v()) + v_base;
    let mut sig_raw = [0_u8; 65];
    sig_raw[..32].copy_from_slice(&sig.r().to_be_bytes::<32>());
    sig_raw[32..64].copy_from_slice(&sig.s().to_be_bytes::<32>());
    sig_raw[64] = v;
    sig_raw
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── Deposit wallet (signature type 3) ───────────────────────────────

// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
const DW_DOMAIN_TYPEHASH: B256 =
    b256!("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");

// keccak256("DepositWallet")
const DW_NAME_HASH: B256 =
    b256!("d682b529a17cda19aa275f3a050608f9e9401fadd1b0d233d81519972295828b");

// keccak256("1")
const DW_VERSION_HASH: B256 =
    b256!("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6");

// keccak256("Call(address target,uint256 value,bytes data)")
const CALL_TYPEHASH: B256 =
    b256!("84fa2cf05cd88e992eae77e851af68a4ee278dcff6ef504e487a55b3baadfbe5");

// keccak256("Batch(address wallet,uint256 nonce,uint256 deadline,Call[] calls)Call(address target,uint256 value,bytes data)")
const BATCH_TYPEHASH: B256 =
    b256!("712ef66e8362c387e862cabf0923c209db0fa24cfc97d25eccba7c86f3ee1dd3");

const DEPOSIT_WALLET_DEADLINE_SECS: u64 = 600;

/// One call of a `DepositWallet` batch (`value` is always zero on this path).
#[derive(Debug)]
pub struct DepositWalletCall {
    pub target: Address,
    pub data: Vec<u8>,
}

#[derive(Serialize)]
struct DepositWalletBatchRequest {
    #[serde(rename = "type")]
    type_: &'static str,
    from: String,
    to: String,
    nonce: String,
    signature: String,
    #[serde(rename = "depositWalletParams")]
    deposit_wallet_params: DepositWalletParams,
}

#[derive(Serialize)]
struct DepositWalletParams {
    #[serde(rename = "depositWallet")]
    deposit_wallet: String,
    deadline: String,
    calls: Vec<DepositWalletCallJson>,
}

#[derive(Serialize)]
struct DepositWalletCallJson {
    target: String,
    value: String,
    data: String,
}

impl RelayerClient {
    /// The EOA's next `WALLET`-type nonce (`GET /nonce`). Tolerates the
    /// relayer answering with a number or a numeric string.
    pub async fn get_wallet_nonce(&self, eoa: Address) -> Result<u64, Error> {
        let resp = self
            .http
            .get(format!("{}/nonce?address={eoa}&type=WALLET", self.host))
            .header("RELAYER_API_KEY", &self.api_key)
            .header("RELAYER_API_KEY_ADDRESS", &self.api_key_address)
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::InvalidData(format!("nonce request failed: {body}")));
        }

        let body: serde_json::Value = resp.json().await?;
        tracing::debug!(nonce_response = %body, "relayer nonce response");
        body["nonce"]
            .as_u64()
            .or_else(|| body["nonce"].as_str()?.parse().ok())
            .ok_or_else(|| Error::InvalidData(format!("no nonce in response: {body}")))
    }

    /// Submit an atomic batch of calls from an ERC-1271 deposit wallet (type
    /// `WALLET`): fetch the EOA's nonce, sign the `Batch` EIP-712 hash, and
    /// relay against the deposit-wallet factory with a 10-minute deadline.
    pub async fn submit_deposit_wallet_batch<S: Signer + Sync>(
        &self,
        signer: &S,
        wallet: Address,
        chain_id: u64,
        calls: &[DepositWalletCall],
    ) -> Result<SubmitResponse, Error> {
        let nonce = self.get_wallet_nonce(signer.address()).await?;
        let deadline = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::InvalidData(format!("clock error: {e}")))?
            .as_secs()
            + DEPOSIT_WALLET_DEADLINE_SECS;

        let hash = compute_deposit_wallet_batch_hash(wallet, chain_id, nonce, deadline, calls);

        let sig = signer
            .sign_hash(&hash)
            .await
            .map_err(|e| Error::InvalidData(format!("signing failed: {e}")))?;

        let sig_raw = pack_signature(&sig, 27);

        let request = DepositWalletBatchRequest {
            type_: "WALLET",
            from: signer.address().to_string(),
            to: DEPOSIT_WALLET_FACTORY.to_string(),
            nonce: nonce.to_string(),
            signature: to_hex(&sig_raw),
            deposit_wallet_params: DepositWalletParams {
                deposit_wallet: wallet.to_string(),
                deadline: deadline.to_string(),
                calls: calls
                    .iter()
                    .map(|c| DepositWalletCallJson {
                        target: c.target.to_string(),
                        value: "0".into(),
                        data: to_hex(&c.data),
                    })
                    .collect(),
            },
        };

        self.post_submit(&request).await
    }
}

/// The EIP-712 hash a `WALLET`-type batch submission signs.
#[must_use]
pub fn compute_deposit_wallet_batch_hash(
    wallet: Address,
    chain_id: u64,
    nonce: u64,
    deadline: u64,
    calls: &[DepositWalletCall],
) -> B256 {
    // Domain separator
    let mut domain_buf = [0_u8; 160];
    domain_buf[..32].copy_from_slice(DW_DOMAIN_TYPEHASH.as_ref());
    domain_buf[32..64].copy_from_slice(DW_NAME_HASH.as_ref());
    domain_buf[64..96].copy_from_slice(DW_VERSION_HASH.as_ref());
    domain_buf[96..128].copy_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    domain_buf[128..160].copy_from_slice(wallet.into_word().as_ref());
    let domain_separator = keccak256(domain_buf);

    // Hash each call: keccak256(CALL_TYPEHASH || target || value || keccak256(data))
    let mut calls_concat = Vec::with_capacity(calls.len() * 32);
    for call in calls {
        let data_hash = keccak256(&call.data);
        let mut call_buf = [0_u8; 128];
        call_buf[..32].copy_from_slice(CALL_TYPEHASH.as_ref());
        call_buf[32..64].copy_from_slice(call.target.into_word().as_ref());
        // value slot (64..96) is zero
        call_buf[96..128].copy_from_slice(data_hash.as_ref());
        calls_concat.extend_from_slice(keccak256(call_buf).as_ref());
    }
    let calls_hash = keccak256(&calls_concat);

    // Batch struct hash
    let mut batch_buf = [0_u8; 160];
    batch_buf[..32].copy_from_slice(BATCH_TYPEHASH.as_ref());
    batch_buf[32..64].copy_from_slice(wallet.into_word().as_ref());
    batch_buf[64..96].copy_from_slice(&U256::from(nonce).to_be_bytes::<32>());
    batch_buf[96..128].copy_from_slice(&U256::from(deadline).to_be_bytes::<32>());
    batch_buf[128..160].copy_from_slice(calls_hash.as_ref());
    let struct_hash = keccak256(batch_buf);

    // EIP-712 final hash
    let mut final_buf = [0_u8; 66];
    final_buf[0] = 0x19;
    final_buf[1] = 0x01;
    final_buf[2..34].copy_from_slice(domain_separator.as_ref());
    final_buf[34..66].copy_from_slice(struct_hash.as_ref());
    keccak256(final_buf)
}

/// The EIP-712 hash a `SAFE-CREATE` deploy signs.
#[must_use]
pub fn compute_create_proxy_hash(safe_factory: Address, chain_id: u64) -> B256 {
    // Domain: EIP712Domain(string name, uint256 chainId, address verifyingContract)
    let mut domain_buf = [0_u8; 128];
    domain_buf[..32].copy_from_slice(CREATE_DOMAIN_TYPEHASH.as_ref());
    domain_buf[32..64].copy_from_slice(SAFE_FACTORY_NAME_HASH.as_ref());
    domain_buf[64..96].copy_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    domain_buf[96..128].copy_from_slice(safe_factory.into_word().as_ref());
    let domain_separator = keccak256(domain_buf);

    // Struct: CreateProxy(address paymentToken, uint256 payment, address paymentReceiver)
    // All values are zero.
    let mut struct_buf = [0_u8; 128];
    struct_buf[..32].copy_from_slice(CREATE_PROXY_TYPEHASH.as_ref());
    // paymentToken, payment, paymentReceiver are all zero — buffer is already zeroed
    let struct_hash = keccak256(struct_buf);

    let mut final_buf = [0_u8; 66];
    final_buf[0] = 0x19;
    final_buf[1] = 0x01;
    final_buf[2..34].copy_from_slice(domain_separator.as_ref());
    final_buf[34..66].copy_from_slice(struct_hash.as_ref());
    keccak256(final_buf)
}

/// The `SafeTx` EIP-712 hash a `SAFE`-type submission signs (all gas params
/// zero).
#[must_use]
pub fn compute_safe_tx_hash(
    safe: Address,
    chain_id: u64,
    to: Address,
    data: &[u8],
    nonce: u64,
) -> B256 {
    // Domain separator: abi.encode(typehash, chainId, verifyingContract)
    let mut domain_buf = [0_u8; 96];
    domain_buf[..32].copy_from_slice(DOMAIN_SEPARATOR_TYPEHASH.as_ref());
    domain_buf[32..64].copy_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    domain_buf[64..96].copy_from_slice(safe.into_word().as_ref());
    let domain_separator = keccak256(domain_buf);

    // Struct hash: 11 words (typehash + to + value + dataHash + operation..nonce)
    // All gas params are zero; only to, dataHash, and nonce are non-zero.
    let data_hash = keccak256(data);
    let mut tx_buf = [0_u8; 352];
    tx_buf[..32].copy_from_slice(SAFE_TX_TYPEHASH.as_ref());
    tx_buf[32..64].copy_from_slice(to.into_word().as_ref());
    tx_buf[96..128].copy_from_slice(data_hash.as_ref());
    tx_buf[320..352].copy_from_slice(&U256::from(nonce).to_be_bytes::<32>());
    let struct_hash = keccak256(tx_buf);

    let mut final_buf = [0_u8; 66];
    final_buf[0] = 0x19;
    final_buf[1] = 0x01;
    final_buf[2..34].copy_from_slice(domain_separator.as_ref());
    final_buf[34..66].copy_from_slice(struct_hash.as_ref());
    keccak256(final_buf)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;

    use super::*;

    #[test]
    fn quota_response_matches_429_or_body() {
        // The clean signal.
        assert!(is_quota_response(429, ""));
        assert!(is_quota_response(429, "whatever"));
        // Non-429 statuses that name the quota still route to the retry path
        // (case-insensitive) — otherwise a retry cycle burns its rebuild
        // attempts hammering the same exhausted quota before failing.
        assert!(is_quota_response(403, "API quota exceeded"));
        assert!(is_quota_response(400, "Monthly QUOTA reached"));
        // Genuine non-quota failures stay hard errors.
        assert!(!is_quota_response(400, "bad request"));
        assert!(!is_quota_response(500, "internal error"));
    }

    #[test]
    fn quota_reset_parses_from_body() {
        assert_eq!(
            parse_quota_reset("quota exceeded, resets in 3600 seconds"),
            Some(3600)
        );
        assert_eq!(parse_quota_reset("no hint here"), None);
    }

    #[test]
    fn domain_separator_typehash_matches() {
        assert_eq!(
            keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)"),
            DOMAIN_SEPARATOR_TYPEHASH,
        );
    }

    #[test]
    fn safe_tx_typehash_matches() {
        assert_eq!(
            keccak256(b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"),
            SAFE_TX_TYPEHASH,
        );
    }

    #[test]
    fn create_domain_typehash_matches() {
        assert_eq!(
            keccak256(b"EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            CREATE_DOMAIN_TYPEHASH,
        );
    }

    #[test]
    fn safe_factory_name_hash_matches() {
        assert_eq!(
            keccak256(b"Polymarket Contract Proxy Factory"),
            SAFE_FACTORY_NAME_HASH,
        );
    }

    #[test]
    fn create_proxy_typehash_matches() {
        assert_eq!(
            keccak256(b"CreateProxy(address paymentToken,uint256 payment,address paymentReceiver)"),
            CREATE_PROXY_TYPEHASH,
        );
    }

    #[test]
    fn create_proxy_hash_matches_python_sdk() {
        let factory = address!("0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b");
        let hash = compute_create_proxy_hash(factory, 137);
        assert_eq!(
            hash,
            b256!("563ac315294c5be01ab1f3b04a5abdfa39e8317a9d90679d4e63caf760b126a4"),
        );

        let h2 = compute_create_proxy_hash(factory, 80002);
        assert_ne!(hash, h2);
    }

    #[test]
    fn hash_deterministic_and_nonce_sensitive() {
        let safe = address!("0xd93b25Cb943D14d0d34FBAf01fc93a0F8b5f6e47");
        let to = address!("0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB");
        let data = &[0x09, 0x5e, 0xa7, 0xb3];

        let h1 = compute_safe_tx_hash(safe, 137, to, data, 0);
        let h2 = compute_safe_tx_hash(safe, 137, to, data, 0);
        assert_eq!(h1, h2);

        let h3 = compute_safe_tx_hash(safe, 137, to, data, 1);
        assert_ne!(h1, h3);
    }

    #[test]
    fn dw_domain_typehash_matches() {
        assert_eq!(
            keccak256(
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
            ),
            DW_DOMAIN_TYPEHASH,
        );
    }

    #[test]
    fn dw_name_hash_matches() {
        assert_eq!(keccak256(b"DepositWallet"), DW_NAME_HASH);
    }

    #[test]
    fn dw_version_hash_matches() {
        assert_eq!(keccak256(b"1"), DW_VERSION_HASH);
    }

    #[test]
    fn call_typehash_matches() {
        assert_eq!(
            keccak256(b"Call(address target,uint256 value,bytes data)"),
            CALL_TYPEHASH,
        );
    }

    #[test]
    fn batch_typehash_matches() {
        assert_eq!(
            keccak256(
                b"Batch(address wallet,uint256 nonce,uint256 deadline,Call[] calls)Call(address target,uint256 value,bytes data)"
            ),
            BATCH_TYPEHASH,
        );
    }

    #[test]
    fn batch_hash_deterministic_and_input_sensitive() {
        let wallet = address!("0xd93b25Cb943D14d0d34FBAf01fc93a0F8b5f6e47");
        let calls = [DepositWalletCall {
            target: address!("0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296"),
            data: vec![0xde, 0xad],
        }];
        let h1 = compute_deposit_wallet_batch_hash(wallet, 137, 5, 1_000, &calls);
        let h2 = compute_deposit_wallet_batch_hash(wallet, 137, 5, 1_000, &calls);
        assert_eq!(h1, h2);
        assert_ne!(
            h1,
            compute_deposit_wallet_batch_hash(wallet, 137, 6, 1_000, &calls)
        );
        assert_ne!(
            h1,
            compute_deposit_wallet_batch_hash(wallet, 137, 5, 1_001, &calls)
        );
    }

    #[test]
    fn to_hex_encodes_correctly() {
        assert_eq!(to_hex(&[0xab, 0xcd, 0x01]), "0xabcd01");
        assert_eq!(to_hex(&[]), "0x");
    }
}
