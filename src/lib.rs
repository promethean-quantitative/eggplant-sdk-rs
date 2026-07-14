//! # eggplant-sdk
//!
//! A highly performant Rust SDK for Polymarket.
//!
//! What's here:
//!
//! - **CLOB trading** — client initialization with every signature type
//!   (EOA, proxy, Gnosis Safe, and ERC-1271 deposit wallets), order signing
//!   with precomputed EIP-712 domains, and a pinned-DNS hyper posting path
//!   for latency-critical order placement and cancellation.
//! - **Relayer operations** — gasless merge / split / convert / redeem for
//!   negRisk positions through Polymarket's relayer, including the
//!   `DepositWallet` batch path, plus a [`sweep`] safety net that settles
//!   every held position in one pass.
//! - **Market data** — lenient order-book fetching, Gamma API events, Data
//!   API positions, and WebSocket streams for both the market and user
//!   channels (zero-copy parsing available on the hot path).
//!
//! Financial math uses [`rust_decimal::Decimal`] on every order-affecting
//! path. Wire types are deliberately lenient: unknown enum values and missing
//! fields degrade gracefully instead of failing the whole response, because
//! the venue adds fields and tick sizes without notice.
//!
//! Real money moves through this code. Read the docs of each module you use,
//! and prefer the venue's smallest sizes while validating an integration.

#[cfg(feature = "rpc")]
pub mod approval;
pub mod auth;
pub mod book;
pub mod chain;
pub mod clob;
pub mod convert;
pub mod data;
pub mod error;
pub mod fee;
pub mod gamma;
pub mod redeem;
pub mod relayer;
pub mod sweep;
#[cfg(feature = "ws")]
pub mod ws;

pub use auth::Credentials;
pub use chain::{AMOY, POLYGON};
pub use clob::{ClobClient, ClobClientBuilder};
pub use error::Error;

/// Convenience alias for fallible SDK operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Environment variable conventionally holding the signer's private key.
/// Nothing in the SDK reads it implicitly; it is a shared convention for
/// examples and downstream binaries.
pub const PRIVATE_KEY_VAR: &str = "POLYMARKET_PRIVATE_KEY";
