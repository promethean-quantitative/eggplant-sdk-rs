//! Chain-level constants: deployed contract addresses, wallet factories,
//! CREATE2 wallet derivations, and default service hosts.
//!
//! Everything here is a public on-chain or venue constant. The wallet-factory
//! constants and CREATE2 derivation rules are adapted from the MIT-licensed
//! `polymarket_client_sdk_v2` (see `ATTRIBUTION.md`).
//!
//! # Collateral: pUSD vs USDC.e
//!
//! The current venue's exchange collateral ([`ContractConfig::collateral`]) is
//! **pUSD** (`0xC011…2DFB`), *not* USDC.e. Bridged USDC.e ([`USDC_E`]) is
//! wrapped into pUSD via the [`COLLATERAL_ONRAMP`]. Approving or funding the
//! wrong token is a fund-loss-adjacent mistake — double-check which one an
//! operation needs.

use alloy::primitives::{Address, B256, address, b256, keccak256};

/// Chain id for Polygon mainnet.
pub const POLYGON: u64 = 137;

/// Chain id for the Polygon Amoy testnet.
pub const AMOY: u64 = 80002;

// ---------------------------------------------------------------------------
// Default service hosts
// ---------------------------------------------------------------------------

/// CLOB REST API.
pub const CLOB_HOST: &str = "https://clob.polymarket.com";
/// Gamma API (event/market metadata).
pub const GAMMA_HOST: &str = "https://gamma-api.polymarket.com";
/// Data API (wallet positions).
pub const DATA_API_HOST: &str = "https://data-api.polymarket.com";
/// Relayer v2 (gasless Safe / deposit-wallet transaction submission).
pub const RELAYER_HOST: &str = "https://relayer-v2.polymarket.com";
/// Market-data WebSocket channel (order books, price changes).
pub const WS_MARKET_URL: &str = "wss://ws-subscriptions-clob.polymarket.com/ws/market";
/// User WebSocket channel (own trades and order lifecycle events).
pub const WS_USER_URL: &str = "wss://ws-subscriptions-clob.polymarket.com/ws/user";

// ---------------------------------------------------------------------------
// Polygon contract addresses
// ---------------------------------------------------------------------------

/// Conditional Tokens Framework (ERC-1155 outcome tokens).
pub const CTF: Address = address!("0x4D97DCd97eC945f40cF65F87097ACe5EA0476045");

/// Exchange collateral: pUSD, the token current markets are denominated and
/// paid out in.
///
/// Bridged USDC.e ([`USDC_E`]) is wrapped into it via the [`COLLATERAL_ONRAMP`];
/// it is also the `collateralToken` argument the pUSD collateral adapter's
/// CTF-mirror merge / redeem / split calls take.
pub const COLLATERAL: Address = address!("0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB");

/// Legacy negRisk adapter (USDC.e-native).
///
/// Still on-chain and still the intermediary the exchange settles negRisk
/// trades through (so trading approvals target it — see [`ContractConfig::neg_risk_adapter`]),
/// and the pUSD collateral adapter delegates its convert / merge / redeem to
/// it internally. But since the pUSD (V2) migration the gasless relayer's
/// target allowlist **no longer permits direct calls to it** — a relayed
/// convert / merge / redeem here is rejected with `call blocked: … are not
/// permitted`. Position operations must go through
/// [`NEG_RISK_COLLATERAL_ADAPTER`] instead.
pub const NEG_RISK_ADAPTER: Address = address!("0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296");

/// pUSD-native negRisk **collateral adapter** (the "V2" contract) — the
/// relayer-allowlisted entry point for convert / merge / redeem / split since
/// the pUSD migration.
///
/// It wraps (delegates to) the legacy [`NEG_RISK_ADAPTER`] internally and
/// returns proceeds as pUSD. Verified against a live UI convert (tx
/// `0xc5d332ab…`). Entry points differ per op:
/// - **convert**: `convertPositions(bytes32,uint256,uint256)` — same calldata
///   as the legacy adapter.
/// - **merge**: the CTF-mirror `mergePositions(address,bytes32,bytes32,uint256[],uint256)`
///   with pUSD collateral and the `[1, 2]` partition. The legacy-style
///   `mergePositions(bytes32,uint256)` overload exists in its bytecode but
///   REVERTS.
/// - **redeem**: the CTF-mirror `redeemPositions(address,bytes32,bytes32,uint256[])`
///   with pUSD and per-holding index sets. Legacy-style reverts likewise.
///
/// The wallet must have approved it as a CTF operator (`setApprovalForAll`);
/// a wallet that has ever converted through the Polymarket UI already is.
pub const NEG_RISK_COLLATERAL_ADAPTER: Address =
    address!("0xadA2005600Dec949baf300f4C6120000bDB6eAab");

/// negRisk CTF Exchange V2 — the EIP-712 verifying contract for negRisk order
/// signing (domain version "2").
pub const NEG_RISK_EXCHANGE_V2: Address = address!("0xe2222d279d744050d28e00520010520000310F59");

/// CTF Exchange V2 for non-negRisk (regular binary) markets.
pub const EXCHANGE_V2: Address = address!("0xE111180000d2663C0091e4f400237545B87B996B");

/// Combos exchange V3 (parlay / RFQ orders, domain version "3").
pub const EXCHANGE_V3: Address = address!("0xe3333700cA9d93003F00f0F71f8515005F6c00Aa");

/// Bridged USDC.e — the *input* to the collateral onramp, not the exchange
/// collateral itself (see the module docs on pUSD vs USDC.e).
pub const USDC_E: Address = address!("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174");

/// Collateral onramp: wraps USDC.e into pUSD, the exchange collateral.
pub const COLLATERAL_ONRAMP: Address = address!("0x93070a847efEf7F70739046A929D47a521F5B8ee");

/// `DepositWallet` factory — the `to` target for relayer `WALLET` batch
/// submissions (ERC-1271 deposit wallets, signature type `Poly1271`).
pub const DEPOSIT_WALLET_FACTORY: Address = address!("0x00000000000Fb5C9ADea0298D729A0CB3823Cc07");

// ---------------------------------------------------------------------------
// Per-chain configs
// ---------------------------------------------------------------------------

/// Deployed exchange-side contract addresses for one (chain, negRisk?) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContractConfig {
    /// Legacy CTF Exchange (V1 orders).
    pub exchange: Address,
    /// CTF Exchange V2 (V2 orders — the current order flow).
    pub exchange_v2: Option<Address>,
    /// Exchange collateral token. On the current venue this is **pUSD**, not
    /// USDC.e — see the module docs.
    pub collateral: Address,
    /// Conditional Tokens Framework.
    pub conditional_tokens: Address,
    /// negRisk adapter; present only in negRisk configs. Must be approved for
    /// token transfers to trade negRisk markets.
    pub neg_risk_adapter: Option<Address>,
}

/// Wallet factory addresses for CREATE2 address derivation on one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WalletConfig {
    /// Factory for Polymarket proxy wallets (Magic/email users,
    /// signature type 1). Not deployed on every chain.
    pub proxy_factory: Option<Address>,
    /// Factory for 1-of-1 Gnosis Safe wallets (browser-wallet users,
    /// signature type 2).
    pub safe_factory: Address,
}

/// Returns the [`ContractConfig`] for a chain, for either the regular or the
/// negRisk exchange family. `None` for unsupported chains.
#[must_use]
pub const fn contract_config(chain_id: u64, is_neg_risk: bool) -> Option<ContractConfig> {
    match (chain_id, is_neg_risk) {
        (POLYGON, false) => Some(ContractConfig {
            exchange: address!("0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"),
            exchange_v2: Some(EXCHANGE_V2),
            collateral: COLLATERAL,
            conditional_tokens: CTF,
            neg_risk_adapter: None,
        }),
        (POLYGON, true) => Some(ContractConfig {
            exchange: address!("0xC5d563A36AE78145C45a50134d48A1215220f80a"),
            exchange_v2: Some(NEG_RISK_EXCHANGE_V2),
            collateral: COLLATERAL,
            conditional_tokens: CTF,
            neg_risk_adapter: Some(NEG_RISK_ADAPTER),
        }),
        (AMOY, false) => Some(ContractConfig {
            exchange: address!("0xdFE02Eb6733538f8Ea35D585af8DE5958AD99E40"),
            exchange_v2: Some(EXCHANGE_V2),
            collateral: COLLATERAL,
            conditional_tokens: address!("0x69308FB512518e39F9b16112fA8d994F4e2Bf8bB"),
            neg_risk_adapter: None,
        }),
        (AMOY, true) => Some(ContractConfig {
            exchange: address!("0xC5d563A36AE78145C45a50134d48A1215220f80a"),
            exchange_v2: Some(NEG_RISK_EXCHANGE_V2),
            collateral: COLLATERAL,
            conditional_tokens: address!("0x69308FB512518e39F9b16112fA8d994F4e2Bf8bB"),
            neg_risk_adapter: Some(NEG_RISK_ADAPTER),
        }),
        _ => None,
    }
}

/// Returns the [`WalletConfig`] for a chain. `None` for unsupported chains.
#[must_use]
pub const fn wallet_config(chain_id: u64) -> Option<WalletConfig> {
    match chain_id {
        POLYGON => Some(WalletConfig {
            proxy_factory: Some(address!("0xaB45c5A4B0c941a2F231C04C3f49182e1A254052")),
            safe_factory: address!("0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b"),
        }),
        // Proxy factory unsupported on Amoy.
        AMOY => Some(WalletConfig {
            proxy_factory: None,
            safe_factory: address!("0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b"),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CREATE2 wallet derivation
// ---------------------------------------------------------------------------

/// Init code hash for Polymarket proxy wallets (EIP-1167 minimal proxy).
pub const PROXY_INIT_CODE_HASH: B256 =
    b256!("0xd21df8dc65880a8606f09fe0ce3df9b8869287ab0b058be05aa9e8af6330a00b");

/// Init code hash for Polymarket-deployed Gnosis Safe wallets.
pub const SAFE_INIT_CODE_HASH: B256 =
    b256!("0x2bce2127ff07fb632d16c8347c4ebf501f4841168bed00d9e6ef715ddb6fcecf");

/// Derives the Polymarket proxy wallet address (signature type 1 funder) for
/// an EOA via CREATE2. Salt is `keccak256` of the packed 20-byte address.
///
/// `None` when the chain has no proxy factory.
#[must_use]
pub fn derive_proxy_wallet(eoa: Address, chain_id: u64) -> Option<Address> {
    let factory = wallet_config(chain_id)?.proxy_factory?;
    Some(factory.create2(keccak256(eoa), PROXY_INIT_CODE_HASH))
}

/// Derives the 1-of-1 Gnosis Safe wallet address (signature type 2 funder)
/// for an EOA via CREATE2. Salt is `keccak256` of the address ABI-padded to
/// 32 bytes.
///
/// `None` when the chain is unsupported.
#[must_use]
pub fn derive_safe_wallet(eoa: Address, chain_id: u64) -> Option<Address> {
    let factory = wallet_config(chain_id)?.safe_factory;
    let mut padded = [0_u8; 32];
    padded[12..].copy_from_slice(eoa.as_slice());
    Some(factory.create2(keccak256(padded), SAFE_INIT_CODE_HASH))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Well-known Foundry/Anvil test EOA.
    const TEST_EOA: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    #[test]
    fn polygon_neg_risk_config() {
        let cfg = contract_config(POLYGON, true).expect("polygon negRisk config");
        assert_eq!(cfg.exchange_v2, Some(NEG_RISK_EXCHANGE_V2));
        assert_eq!(cfg.neg_risk_adapter, Some(NEG_RISK_ADAPTER));
        assert_eq!(cfg.conditional_tokens, CTF);
        assert_eq!(cfg.collateral, COLLATERAL);
        assert_eq!(
            cfg.exchange,
            address!("0xC5d563A36AE78145C45a50134d48A1215220f80a")
        );
    }

    #[test]
    fn fund_critical_addresses_pinned() {
        // A typo in either of these silently sends convert/merge/redeem/split
        // to the wrong contract, so pin the literal checksummed values.
        assert_eq!(
            NEG_RISK_COLLATERAL_ADAPTER,
            address!("0xadA2005600Dec949baf300f4C6120000bDB6eAab")
        );
        assert_eq!(
            COLLATERAL,
            address!("0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB")
        );
        // The collateral adapter is the pUSD-native V2 successor, distinct from
        // the de-allowlisted legacy adapter.
        assert_ne!(NEG_RISK_COLLATERAL_ADAPTER, NEG_RISK_ADAPTER);
    }

    #[test]
    fn polygon_regular_config() {
        let cfg = contract_config(POLYGON, false).expect("polygon config");
        assert_eq!(cfg.exchange_v2, Some(EXCHANGE_V2));
        assert_eq!(cfg.neg_risk_adapter, None);
        assert_eq!(
            cfg.exchange,
            address!("0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E")
        );
        // Collateral is pUSD, deliberately distinct from USDC.e.
        assert_ne!(cfg.collateral, USDC_E);
    }

    #[test]
    fn unsupported_chain_is_none() {
        assert!(contract_config(1, false).is_none());
        assert!(contract_config(1, true).is_none());
        assert!(wallet_config(1).is_none());
    }

    // CREATE2 vectors adapted from the MIT-licensed polymarket_client_sdk_v2
    // test suite (see ATTRIBUTION.md).
    #[test]
    fn derive_proxy_wallet_polygon_vector() {
        let proxy = derive_proxy_wallet(TEST_EOA, POLYGON).expect("derivation");
        assert_eq!(
            proxy,
            address!("0x365f0cA36ae1F641E02Fe3b7743673DA42A13a70")
        );
    }

    #[test]
    fn derive_safe_wallet_polygon_vector() {
        let safe = derive_safe_wallet(TEST_EOA, POLYGON).expect("derivation");
        assert_eq!(safe, address!("0xd93b25Cb943D14d0d34FBAf01fc93a0F8b5f6e47"));
    }

    #[test]
    fn derive_proxy_wallet_amoy_unsupported() {
        assert!(derive_proxy_wallet(TEST_EOA, AMOY).is_none());
    }

    #[test]
    fn derive_safe_wallet_amoy_matches_polygon() {
        // Same Safe factory on both networks ⇒ same derived address.
        assert_eq!(
            derive_safe_wallet(TEST_EOA, AMOY),
            derive_safe_wallet(TEST_EOA, POLYGON)
        );
    }

    #[test]
    fn derive_unsupported_chain() {
        assert!(derive_proxy_wallet(TEST_EOA, 1).is_none());
        assert!(derive_safe_wallet(TEST_EOA, 1).is_none());
    }
}
