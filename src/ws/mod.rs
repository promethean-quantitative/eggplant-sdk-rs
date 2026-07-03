//! WebSocket streams: the market channel (order books, price changes) and
//! the authenticated user channel (own trades and order lifecycle events).
//!
//! Layered so hot paths can stay allocation-light:
//!
//! - [`frames`] — subscribe-frame builders and the text `PING`/`PONG`
//!   liveness protocol constants.
//! - [`market`] / [`user`] — typed messages plus thin single-connection
//!   streams ([`market::MarketStream`], [`user::UserStream`]) that own the
//!   liveness protocol and hand back raw frames; the market types come in a
//!   zero-copy borrowed form for hot consumers.
//! - [`util`] — multi-connection plumbing proven in production: staggered
//!   recycle phasing, maker-side classification, bounded dedup.
//!
//! Connection *policy* (how many connections, sharding, redundancy, backoff)
//! deliberately stays with the caller; these pieces are the mechanism.

pub mod frames;
pub mod market;
pub mod user;
pub mod util;
