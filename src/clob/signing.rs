//! High-performance EIP-712 order signing for every Polymarket signature type.
//!
//! [`OrderSigner`] precomputes the exchange domain separator (and, for
//! deposit wallets, the Solady `TypedDataSign` template) once at construction;
//! per-order work is one struct hash, one or two keccaks, and one ECDSA
//! signature.
//!
//! Signature-type dispatch:
//!
//! - **Types 0/1/2** (EOA, proxy, Safe): the plain EIP-712 digest
//!   `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(order))`, signed by the
//!   EOA. The venue validates proxy/Safe orders against the owning EOA.
//! - **Type 3** (`Poly1271` deposit wallet): the digest is re-wrapped through
//!   the wallet's own `DepositWallet` (version "1") domain via Solady's
//!   `TypedDataSign`, and the wire signature is the wrapped hex envelope
//!   `sig ‖ exchangeDomainSeparator ‖ contentsHash ‖ contentsType ‖ len`.
//!
//! **Real money.** Every constant here is verified against the deployed
//! exchanges; the differential tests prove the precomputed fast path equals
//! alloy's generic EIP-712 implementation.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::signers::SignerSync;
use alloy::sol_types::SolStruct as _;
use rust_decimal::Decimal;

use crate::auth::ApiKey;
use crate::chain::{EXCHANGE_V2, EXCHANGE_V3, NEG_RISK_EXCHANGE_V2};
use crate::clob::types::{
    OrderPayload, OrderSignature, OrderType, OrderV2, Side, SignableOrder, SignatureType,
    SignedOrder,
};
use crate::error::Error;

/// USDC / conditional-token raw decimals (1 share = 10^6 raw units).
pub const USDC_DECIMALS: u32 = 6;

/// Largest integer JavaScript can hold exactly (2^53 − 1). Salts are masked
/// to this so the venue's JS-side tooling round-trips them losslessly.
pub const JS_MAX_SAFE_INT: u64 = (1_u64 << 53) - 1;

const DOMAIN_TYPE_STRING: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// EIP-712 domain name shared by every Polymarket exchange deployment.
pub const ORDER_DOMAIN_NAME: &str = "Polymarket CTF Exchange";

/// The V2 `Order` EIP-712 type string. Must match the sol! struct in
/// [`crate::clob::types`] — a unit test pins the equality.
pub const ORDER_TYPE_STRING: &str = concat!(
    "Order(uint256 salt,address maker,address signer,uint256 tokenId,",
    "uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,",
    "uint256 timestamp,bytes32 metadata,bytes32 builder)"
);

const SOLADY_TYPE_STRING: &str = concat!(
    "TypedDataSign(Order contents,string name,string version,uint256 chainId,",
    "address verifyingContract,bytes32 salt)",
    "Order(uint256 salt,address maker,address signer,uint256 tokenId,",
    "uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,",
    "uint256 timestamp,bytes32 metadata,bytes32 builder)"
);
const DEPOSIT_WALLET_NAME: &str = "DepositWallet";
const DEPOSIT_WALLET_VERSION: &str = "1";

fn push_hex(out: &mut String, bytes: &[u8]) {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    out.reserve(bytes.len() * 2);
    for byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
}

/// The EIP-712 domain of one exchange deployment: which contract verifies the
/// order and under which protocol version string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeDomain {
    /// Domain `name` — [`ORDER_DOMAIN_NAME`] on every known deployment.
    pub name: &'static str,
    /// Domain `version`: `"2"` for the CTF Exchange V2 family, `"3"` for the
    /// combos exchange, `"1"` for the legacy V1 exchange.
    pub version: &'static str,
    pub verifying_contract: Address,
}

impl ExchangeDomain {
    /// The CTF Exchange V2 domain — the current order flow. `neg_risk`
    /// selects between the negRisk and regular exchange deployments.
    #[must_use]
    pub const fn ctf_v2(neg_risk: bool) -> Self {
        Self {
            name: ORDER_DOMAIN_NAME,
            version: "2",
            verifying_contract: if neg_risk {
                NEG_RISK_EXCHANGE_V2
            } else {
                EXCHANGE_V2
            },
        }
    }

    /// The combos (parlay/RFQ) exchange V3 domain.
    #[must_use]
    pub const fn combos_v3() -> Self {
        Self {
            name: ORDER_DOMAIN_NAME,
            version: "3",
            verifying_contract: EXCHANGE_V3,
        }
    }

    /// Escape hatch for a deployment this crate doesn't know about yet.
    #[must_use]
    pub const fn custom(version: &'static str, verifying_contract: Address) -> Self {
        Self {
            name: ORDER_DOMAIN_NAME,
            version,
            verifying_contract,
        }
    }
}

/// Which addresses an order carries as `maker`/`signer`, and how the venue
/// validates its signature.
///
/// Build via the per-type constructors — they encode the venue's maker/signer
/// table so callers can't mis-wire it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderIdentity {
    /// The wallet whose funds move (`maker` field, and the funder the venue
    /// debits).
    pub maker: Address,
    /// The address the signature is validated against.
    pub signer: Address,
    pub signature_type: SignatureType,
}

impl OrderIdentity {
    /// Signature type 0: a plain EOA is both maker and signer.
    #[must_use]
    pub const fn eoa(address: Address) -> Self {
        Self {
            maker: address,
            signer: address,
            signature_type: SignatureType::Eoa,
        }
    }

    /// Signature type 1: a Polymarket proxy wallet (Magic/email login) holds
    /// the funds; the owning EOA signs. Derive the proxy address with
    /// [`crate::chain::derive_proxy_wallet`].
    #[must_use]
    pub const fn proxy(eoa: Address, proxy_wallet: Address) -> Self {
        Self {
            maker: proxy_wallet,
            signer: eoa,
            signature_type: SignatureType::Proxy,
        }
    }

    /// Signature type 2: a 1-of-1 Gnosis Safe (browser wallet) holds the
    /// funds; the owning EOA signs. Derive the Safe address with
    /// [`crate::chain::derive_safe_wallet`].
    #[must_use]
    pub const fn gnosis_safe(eoa: Address, safe_wallet: Address) -> Self {
        Self {
            maker: safe_wallet,
            signer: eoa,
            signature_type: SignatureType::GnosisSafe,
        }
    }

    /// Signature type 3: an ERC-1271 deposit wallet is both maker and signer;
    /// the wallet-owning EOA produces the wrapped signature.
    #[must_use]
    pub const fn poly1271(deposit_wallet: Address) -> Self {
        Self {
            maker: deposit_wallet,
            signer: deposit_wallet,
            signature_type: SignatureType::Poly1271,
        }
    }
}

/// Precomputed EIP-712 order signer for one (exchange domain, identity) pair.
///
/// Construction hashes the domain once; [`OrderSigner::sign_order`] then does
/// the minimum per-order work. Cheap to clone (one `String` pair + fixed
/// buffers).
#[derive(Clone)]
pub struct OrderSigner {
    domain_separator: B256,
    identity: OrderIdentity,
    /// Solady `TypedDataSign` buffer with everything but the per-order
    /// contents hash prefilled (Poly1271 only; unused for other types).
    typed_data_template: [u8; 224],
    domain_separator_hex: String,
    order_type_suffix: String,
    owner: ApiKey,
}

impl OrderSigner {
    #[must_use]
    pub fn new(
        chain_id: u64,
        domain: &ExchangeDomain,
        identity: OrderIdentity,
        owner: ApiKey,
    ) -> Self {
        let mut domain_buf = [0_u8; 160];
        domain_buf[0..32].copy_from_slice(keccak256(DOMAIN_TYPE_STRING.as_bytes()).as_slice());
        domain_buf[32..64].copy_from_slice(keccak256(domain.name.as_bytes()).as_slice());
        domain_buf[64..96].copy_from_slice(keccak256(domain.version.as_bytes()).as_slice());
        domain_buf[96..128].copy_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
        domain_buf[140..160].copy_from_slice(domain.verifying_contract.as_slice());
        let domain_separator = keccak256(domain_buf);

        let solady_type_hash = keccak256(SOLADY_TYPE_STRING.as_bytes());
        let wallet_name_hash = keccak256(DEPOSIT_WALLET_NAME.as_bytes());
        let wallet_version_hash = keccak256(DEPOSIT_WALLET_VERSION.as_bytes());

        // The TypedDataSign wrapper hashes over the *deposit wallet's* own
        // domain: name "DepositWallet", version "1", this chain, and the
        // wallet address (= the order's signer for Poly1271) as verifying
        // contract, salt zero.
        let mut typed_data_template = [0_u8; 224];
        typed_data_template[0..32].copy_from_slice(solady_type_hash.as_slice());
        // slot 1 (contents_hash) filled per-order
        typed_data_template[64..96].copy_from_slice(wallet_name_hash.as_slice());
        typed_data_template[96..128].copy_from_slice(wallet_version_hash.as_slice());
        typed_data_template[128..160].copy_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
        typed_data_template[172..192].copy_from_slice(identity.signer.as_slice());
        // slot 6 (B256::ZERO salt) already zeroed

        let mut domain_separator_hex = String::with_capacity(64);
        push_hex(&mut domain_separator_hex, domain_separator.as_slice());

        let mut order_type_suffix = String::with_capacity(ORDER_TYPE_STRING.len() * 2 + 4);
        push_hex(&mut order_type_suffix, ORDER_TYPE_STRING.as_bytes());
        #[allow(clippy::cast_possible_truncation)]
        let len = ORDER_TYPE_STRING.len() as u16;
        push_hex(&mut order_type_suffix, &len.to_be_bytes());

        Self {
            domain_separator,
            identity,
            typed_data_template,
            domain_separator_hex,
            order_type_suffix,
            owner,
        }
    }

    /// The identity orders signed here carry.
    #[must_use]
    pub const fn identity(&self) -> OrderIdentity {
        self.identity
    }

    /// The exchange domain separator (useful for debugging signatures).
    #[must_use]
    pub const fn domain_separator(&self) -> B256 {
        self.domain_separator
    }

    /// Signs a V2 order. `signer` must be the EOA key matching
    /// [`OrderIdentity::signer`] (for Poly1271: the EOA that owns the deposit
    /// wallet).
    ///
    /// ECDSA over a fixed digest is deterministic (RFC 6979), so signing the
    /// same signable twice yields byte-identical output — callers may
    /// duplicate a signed order freely.
    pub fn sign_order<S: SignerSync>(
        &self,
        order: SignableOrder,
        signer: &S,
    ) -> Result<SignedOrder, Error> {
        let SignableOrder {
            payload,
            order_type,
            post_only,
            defer_exec,
        } = order;

        let v2 = match &payload {
            OrderPayload::V2(p) => &p.order,
            OrderPayload::V1(_) => {
                return Err(Error::InvalidData("expected V2 order".into()));
            }
        };

        debug_assert_eq!(
            v2.maker, self.identity.maker,
            "order maker must match the signer's identity"
        );
        debug_assert_eq!(
            v2.signatureType, self.identity.signature_type as u8,
            "order signatureType must match the signer's identity"
        );

        let contents_hash = v2.eip712_hash_struct();

        let struct_hash = match self.identity.signature_type {
            // Types 0/1/2: sign the exchange digest directly; the venue
            // recovers the EOA from the plain 65-byte signature.
            SignatureType::Eoa | SignatureType::Proxy | SignatureType::GnosisSafe => contents_hash,
            // Poly1271: splice the contents hash into the precomputed Solady
            // TypedDataSign buffer and sign the wrapped digest.
            SignatureType::Poly1271 => {
                let mut tdb = self.typed_data_template;
                tdb[32..64].copy_from_slice(contents_hash.as_slice());
                keccak256(tdb)
            }
        };

        let mut digest_input = [0_u8; 66];
        digest_input[0] = 0x19;
        digest_input[1] = 0x01;
        digest_input[2..34].copy_from_slice(self.domain_separator.as_slice());
        digest_input[34..66].copy_from_slice(struct_hash.as_slice());
        let digest = keccak256(digest_input);

        let sig = signer
            .sign_hash_sync(&digest)
            .map_err(|e| Error::InvalidData(format!("signing failed: {e}")))?;

        let signature = match self.identity.signature_type {
            SignatureType::Eoa | SignatureType::Proxy | SignatureType::GnosisSafe => {
                OrderSignature::Ecdsa(sig)
            }
            SignatureType::Poly1271 => {
                let sig_bytes = sig.as_bytes();
                let mut wrapped =
                    String::with_capacity(2 + 130 + 64 + 64 + self.order_type_suffix.len());
                wrapped.push_str("0x");
                push_hex(&mut wrapped, &sig_bytes);
                wrapped.push_str(&self.domain_separator_hex);
                push_hex(&mut wrapped, contents_hash.as_slice());
                wrapped.push_str(&self.order_type_suffix);
                OrderSignature::Wrapped(wrapped)
            }
        };

        let mut signed_order = SignedOrder::new(payload, signature, order_type, self.owner);
        signed_order.post_only = post_only;
        signed_order.defer_exec = defer_exec;
        Ok(signed_order)
    }
}

/// A time-derived salt masked to [`JS_MAX_SAFE_INT`].
///
/// # Panics
///
/// Panics if the system clock reads before the Unix epoch — a degenerate
/// salt must never be signed silently.
#[must_use]
pub fn generate_salt() -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    let salt = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after epoch")
        .as_nanos() as u64
        & JS_MAX_SAFE_INT;
    salt
}

/// Converts a non-negative decimal amount to raw 6-decimal units.
///
/// Truncates past the 6th decimal. Errors on negative amounts or values too
/// large for `u128` — order amounts from user input must never wrap.
pub fn to_fixed_usdc(d: Decimal) -> Result<u128, Error> {
    u128::try_from(d.normalize().trunc_with_scale(USDC_DECIMALS).mantissa())
        .map_err(|_| Error::InvalidData(format!("amount out of range for order: {d}")))
}

/// Builds a signable V2 order for either side.
///
/// Amounts are raw 6-decimal units (see [`to_fixed_usdc`]). For a BUY the
/// maker pays `size × price` USDC (`maker_amount`) for `size` shares
/// (`taker_amount`); a SELL swaps them: the maker gives `size` shares for
/// `size × price` USDC. `timestamp` is free-form on the wire (production use
/// passes the triggering event's milliseconds); `expiration` is always zero
/// here — GTC/FOK/FAK orders don't expire, and GTD callers can set
/// `payload.expiration` on the result.
///
/// `post_only` is only emitted when `true`: the venue rejects `postOnly` on
/// non-GTC/GTD order types, and taker orders must stay able to take.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_signable_order_side(
    token_id: U256,
    maker_amount: U256,
    taker_amount: U256,
    identity: OrderIdentity,
    timestamp: u64,
    order_type: OrderType,
    salt: u64,
    post_only: bool,
    side: Side,
) -> SignableOrder {
    let order = OrderV2 {
        salt: U256::from(salt),
        maker: identity.maker,
        signer: identity.signer,
        tokenId: token_id,
        makerAmount: maker_amount,
        takerAmount: taker_amount,
        side: side as u8,
        signatureType: identity.signature_type as u8,
        timestamp: U256::from(timestamp),
        metadata: B256::ZERO,
        builder: B256::ZERO,
    };

    let payload = OrderPayload::new(order, U256::ZERO);

    let mut signable = SignableOrder::new(payload, order_type);
    if post_only {
        signable = signable.with_post_only(true);
    }
    signable
}

/// BUY convenience wrapper over [`build_signable_order_side`].
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn build_signable_order(
    token_id: U256,
    maker_amount: U256,
    taker_amount: U256,
    identity: OrderIdentity,
    timestamp: u64,
    order_type: OrderType,
    salt: u64,
    post_only: bool,
) -> SignableOrder {
    build_signable_order_side(
        token_id,
        maker_amount,
        taker_amount,
        identity,
        timestamp,
        order_type,
        salt,
        post_only,
        Side::Buy,
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol_types::eip712_domain;

    use super::*;
    use crate::chain::POLYGON;

    fn d(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    fn test_funder() -> Address {
        "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap()
    }

    // Fixed throwaway key (the well-known anvil dev key) → hermetic tests.
    fn test_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_str(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        )
        .unwrap()
    }

    fn poly1271_signer() -> OrderSigner {
        OrderSigner::new(
            POLYGON,
            &ExchangeDomain::ctf_v2(true),
            OrderIdentity::poly1271(test_funder()),
            ApiKey::nil(),
        )
    }

    fn signable(identity: OrderIdentity, salt: u64) -> SignableOrder {
        build_signable_order(
            U256::from(111_u64),
            U256::from(4_850_000_u64),
            U256::from(5_000_000_u64),
            identity,
            1_700_000_000_000,
            OrderType::GTC,
            salt,
            false,
        )
    }

    #[test]
    fn build_signable_order_sets_amounts() {
        let token_id = U256::from(111_u64);
        // 5 shares at 0.97 = 4.85 USDC.
        let maker_amount = U256::from(4_850_000_u64);
        let taker_amount = U256::from(5_000_000_u64);
        let identity = OrderIdentity::poly1271(test_funder());
        let order = build_signable_order(
            token_id,
            maker_amount,
            taker_amount,
            identity,
            1_700_000_000_000,
            OrderType::GTC,
            generate_salt(),
            false,
        );
        let v2 = order.order();

        assert_eq!(v2.makerAmount, maker_amount);
        assert_eq!(v2.takerAmount, taker_amount);
        assert_eq!(v2.tokenId, token_id);
        assert_eq!(v2.side, Side::Buy as u8);
        assert_eq!(v2.signatureType, SignatureType::Poly1271 as u8);
        assert_eq!(v2.maker, test_funder());
        assert_eq!(v2.signer, test_funder());
    }

    /// The venue's maker/signer table, per signature type.
    #[test]
    fn identity_maker_signer_table() {
        let eoa = test_signer().address();
        let wallet = Address::repeat_byte(0x22);

        let id = OrderIdentity::eoa(eoa);
        assert_eq!((id.maker, id.signer), (eoa, eoa));
        assert_eq!(id.signature_type as u8, 0);

        let id = OrderIdentity::proxy(eoa, wallet);
        assert_eq!((id.maker, id.signer), (wallet, eoa));
        assert_eq!(id.signature_type as u8, 1);

        let id = OrderIdentity::gnosis_safe(eoa, wallet);
        assert_eq!((id.maker, id.signer), (wallet, eoa));
        assert_eq!(id.signature_type as u8, 2);

        let id = OrderIdentity::poly1271(wallet);
        assert_eq!((id.maker, id.signer), (wallet, wallet));
        assert_eq!(id.signature_type as u8, 3);

        // And the order builder threads the identity through the struct.
        let order = signable(OrderIdentity::proxy(eoa, wallet), 7);
        assert_eq!(order.order().maker, wallet);
        assert_eq!(order.order().signer, eoa);
        assert_eq!(order.order().signatureType, 1);
    }

    /// Pins the premise behind sign-once-per-leg fan-out: copies of a leg are
    /// byte-identical (same salt and signable), and ECDSA over the same digest
    /// is deterministic (RFC 6979), so one signature serves every copy.
    #[test]
    fn sign_order_is_deterministic_for_identical_input() {
        let signer = test_signer();
        let fast = poly1271_signer();
        let identity = OrderIdentity::poly1271(test_funder());
        let a = fast.sign_order(signable(identity, 7), &signer).unwrap();
        let b = fast.sign_order(signable(identity, 7), &signer).unwrap();
        assert_eq!(a, b);
    }

    /// The precomputed domain separator must equal alloy's generic EIP-712
    /// implementation for every deployment we know.
    #[test]
    fn domain_separator_matches_alloy_for_all_deployments() {
        for (domain, ident) in [
            (ExchangeDomain::ctf_v2(true), "negRisk v2"),
            (ExchangeDomain::ctf_v2(false), "regular v2"),
            (ExchangeDomain::combos_v3(), "combos v3"),
        ] {
            let ours = OrderSigner::new(
                POLYGON,
                &domain,
                OrderIdentity::eoa(test_funder()),
                ApiKey::nil(),
            )
            .domain_separator();

            let alloy_domain = eip712_domain! {
                name: domain.name,
                version: domain.version,
                chain_id: POLYGON,
                verifying_contract: domain.verifying_contract,
            };
            assert_eq!(ours, alloy_domain.separator(), "{ident}");
        }
    }

    /// For plain-ECDSA types the digest we sign must equal alloy's
    /// `eip712_signing_hash` — proving the whole fast path (not just the
    /// domain) is equivalent to the generic implementation.
    #[test]
    fn eoa_digest_matches_alloy_signing_hash() {
        let signer = test_signer();
        let eoa = signer.address();
        let domain = ExchangeDomain::ctf_v2(true);
        let order_signer =
            OrderSigner::new(POLYGON, &domain, OrderIdentity::eoa(eoa), ApiKey::nil());

        let order = signable(OrderIdentity::eoa(eoa), 7);
        let v2 = order.order().clone();

        let alloy_domain = eip712_domain! {
            name: domain.name,
            version: domain.version,
            chain_id: POLYGON,
            verifying_contract: domain.verifying_contract,
        };
        let expected_digest = v2.eip712_signing_hash(&alloy_domain);
        let expected_sig = signer.sign_hash_sync(&expected_digest).unwrap();

        let signed_order = order_signer.sign_order(order, &signer).unwrap();
        match signed_order.signature {
            OrderSignature::Ecdsa(sig) => assert_eq!(sig, expected_sig),
            OrderSignature::Wrapped(_) => panic!("EOA orders must carry plain ECDSA signatures"),
        }
    }

    /// ECDSA signatures for types 0/1/2 render as 0x + 65-byte hex with
    /// v ∈ {27, 28} — the venue's expected format.
    #[test]
    fn ecdsa_signature_wire_format() {
        let signer = test_signer();
        let eoa = signer.address();
        for identity in [
            OrderIdentity::eoa(eoa),
            OrderIdentity::proxy(eoa, Address::repeat_byte(0x22)),
            OrderIdentity::gnosis_safe(eoa, Address::repeat_byte(0x33)),
        ] {
            let order_signer = OrderSigner::new(
                POLYGON,
                &ExchangeDomain::ctf_v2(true),
                identity,
                ApiKey::nil(),
            );
            let signed_order = order_signer
                .sign_order(signable(identity, 7), &signer)
                .unwrap();
            let rendered = signed_order.signature.to_string();
            assert_eq!(rendered.len(), 2 + 130, "{identity:?}");
            let v = u8::from_str_radix(&rendered[rendered.len() - 2..], 16).unwrap();
            assert!(v == 27 || v == 28, "{identity:?}: v was {v}");
        }
    }

    /// The Poly1271 wrapped envelope: sig ‖ domain separator ‖ contents hash
    /// ‖ hex(type string) ‖ big-endian length.
    #[test]
    fn poly1271_wrapped_envelope_shape() {
        let signer = test_signer();
        let fast = poly1271_signer();
        let identity = OrderIdentity::poly1271(test_funder());
        let signed_order = fast.sign_order(signable(identity, 7), &signer).unwrap();

        let OrderSignature::Wrapped(wrapped) = &signed_order.signature else {
            panic!("Poly1271 orders must carry wrapped signatures");
        };
        assert!(wrapped.starts_with("0x"));
        let type_suffix_len = ORDER_TYPE_STRING.len() * 2 + 4;
        assert_eq!(wrapped.len(), 2 + 130 + 64 + 64 + type_suffix_len);
        // The domain separator rides right after the 65-byte signature.
        let sep_hex = &wrapped[2 + 130..2 + 130 + 64];
        let mut expected = String::new();
        push_hex(&mut expected, fast.domain_separator().as_slice());
        assert_eq!(sep_hex, expected);
        // The suffix ends with the big-endian u16 length of the type string.
        let len_hex = &wrapped[wrapped.len() - 4..];
        let len = u16::from_str_radix(len_hex, 16).unwrap();
        assert_eq!(usize::from(len), ORDER_TYPE_STRING.len());
    }

    #[test]
    fn signing_a_v1_payload_is_an_error() {
        let fast = poly1271_signer();
        let signable = SignableOrder::new(
            OrderPayload::new_v1(crate::clob::types::OrderV1::default()),
            OrderType::GTC,
        );
        assert!(fast.sign_order(signable, &test_signer()).is_err());
    }

    #[test]
    fn build_signable_order_is_gtc_with_zero_expiration() {
        let order = signable(OrderIdentity::poly1271(test_funder()), 7);
        assert_eq!(order.order_type, OrderType::GTC);
        assert_eq!(order.v2().expiration, U256::ZERO);
    }

    #[test]
    fn build_signable_order_salt_is_js_safe() {
        let order = build_signable_order(
            U256::from(111_u64),
            U256::from(4_850_000_u64),
            U256::from(5_000_000_u64),
            OrderIdentity::poly1271(test_funder()),
            1_700_000_000_000,
            OrderType::GTC,
            generate_salt(),
            false,
        );
        let salt: u64 = order.order().salt.to::<u64>();
        assert!(salt <= JS_MAX_SAFE_INT);
        assert!(salt > 0);
    }

    #[test]
    fn marketable_sell_builds_fak_taker_no_post_only() {
        // A marketable SELL is a FAK taker with `post_only` off — the builder
        // emits no `postOnly` when off (the venue rejects post-only on FAK).
        // Amounts are the SELL swap: maker = `size` shares, taker = `size ×
        // price` USDC.
        let size = d("50");
        let price = d("0.002");
        let order = build_signable_order_side(
            U256::from(333_u64),
            U256::from(to_fixed_usdc(size).unwrap()),
            U256::from(to_fixed_usdc(size * price).unwrap()),
            OrderIdentity::poly1271(test_funder()),
            1_700_000_000_000,
            OrderType::FAK,
            generate_salt(),
            false,
            Side::Sell,
        );
        assert_eq!(order.order_type, OrderType::FAK);
        assert_eq!(order.post_only, None, "FAK must not carry post_only");
    }

    #[test]
    fn to_fixed_usdc_truncates_to_six_decimals() {
        assert_eq!(to_fixed_usdc(d("4.85")).unwrap(), 4_850_000);
        assert_eq!(to_fixed_usdc(d("0.0000019")).unwrap(), 1);
        assert_eq!(to_fixed_usdc(Decimal::ZERO).unwrap(), 0);
        assert!(to_fixed_usdc(d("-1")).is_err());
    }
}
