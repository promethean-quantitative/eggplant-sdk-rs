# 🍆 eggplant-sdk-rs 🦀

A highly performant rust sdk for Polymarket.

[![CI](https://github.com/promethean-quantitative/eggplant-sdk-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/promethean-quantitative/eggplant-sdk-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A complete, standalone Polymarket client — signing, posting, cancels,
relayer operations, and streaming — built for correctness and latency, with
zero dependency on the official SDK.

## Why

- **Resilient by design.** Tick sizes are plain `Decimal`s (a closed enum
  breaks the day the venue adds a grid), wire types degrade leniently
  instead of failing whole responses, order books parse per-element, cancel
  bookkeeping distinguishes terminal from transient misses, and the Data
  API's offset-cap recycling and the relayer's non-429 quota responses are
  handled.
- **Performant.** Pinned-DNS hyper pools (isolated order/cancel pools, warm
  tiers), precomputed EIP-712 domains with one-buffer signing, HMAC over the
  exact bytes sent, zero-copy WebSocket parsing on the market channel.
- **Complete for real trading.** All four signature types, gasless
  merge/split/convert/redeem through the relayer, order books, positions,
  Gamma metadata, and both WS channels with the liveness protocol that keeps
  half-open sockets from silently eating your fills.
- **Financially strict.** `rust_decimal` on every order-affecting path — no
  floats where money moves. `#![forbid(unsafe_code)]`.

## Feature matrix

| Capability                                                      | eggplant-sdk             | official `polymarket_client_sdk_v2`    |
| --------------------------------------------------------------- | ------------------------ | -------------------------------------- |
| L1 auth (create/derive API key)                                 | ✓ (golden-vector pinned) | ✓                                      |
| Signature types 0 / 1 / 2 / Poly1271                            | ✓ all four, one signer   | ✓                                      |
| Hot posting path (pinned DNS, isolated pools, warm tiers)       | ✓                        | —                                      |
| Batch + singular place/cancel endpoint switching                | ✓                        | —                                      |
| Cancel bookkeeping (`partition_cancels`, terminal reasons)      | ✓                        | —                                      |
| Relayer v2: SAFE / SAFE-CREATE / DepositWallet batches          | ✓                        | —                                      |
| negRisk merge / **split** / convert / redeem + planning engine  | ✓                        | split/merge/redeem as raw on-chain txs |
| Lenient order books (`tick_size: Decimal`, per-book parse)      | ✓                        | closed tick enum (breaks on new grids) |
| Market WS: zero-copy events, text PING/PONG liveness            | ✓                        | owned types                            |
| User WS: fills/orders + maker-side derivation + dedup           | ✓                        | types only                             |
| Gamma / Data API clients                                        | ✓                        | ✓                                      |
| Wallet CREATE2 derivation (proxy + Safe)                        | ✓                        | ✓                                      |

## Install

```toml
[dependencies]
eggplant-sdk = "0.1"
alloy = { version = "1.6", default-features = false, features = ["signers", "signer-local"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

`alloy` supplies the wallet signer types; every price/size the SDK takes or
returns on order paths is a `rust_decimal::Decimal`.

## Usage

### 1. Authenticate

One builder covers all four venue signature types. The chain id always comes
from the builder (default Polygon, 137) — never silently from the signer.

```rust
use alloy::signers::local::PrivateKeySigner;
use eggplant_sdk::chain::{derive_proxy_wallet, derive_safe_wallet, POLYGON};
use eggplant_sdk::clob::types::SignatureType;
use eggplant_sdk::ClobClient;

let signer: PrivateKeySigner = std::env::var("POLYMARKET_PRIVATE_KEY")?.parse()?;

// Type 0 (EOA holds the funds) — the default:
let client = ClobClient::builder().authenticate(&signer).await?;

// Type 1 (Magic/email proxy wallet) or 2 (browser Gnosis Safe): the wallet
// address is deterministic from your EOA —
let proxy = derive_proxy_wallet(signer.address(), POLYGON).unwrap();
let client = ClobClient::builder()
    .signature_type(SignatureType::Proxy) // or GnosisSafe + derive_safe_wallet
    .funder(proxy)
    .authenticate(&signer)
    .await?;

// Type 3 (ERC-1271 deposit wallet):
let client = ClobClient::builder()
    .signature_type(SignatureType::Poly1271)
    .funder("0xYourDepositWallet".parse()?)
    .authenticate(&signer)
    .await?;
```

| type                          | who holds funds (`maker`) | who signs                |
| ----------------------------- | ------------------------- | ------------------------ |
| 0 `Eoa`                       | the EOA itself            | EOA                      |
| 1 `Proxy` (Magic/email)       | proxy wallet              | EOA                      |
| 2 `GnosisSafe` (browser)      | 1-of-1 Safe               | EOA                      |
| 3 `Poly1271` (deposit wallet) | deposit wallet            | deposit wallet (wrapped) |

`authenticate` runs the L1 handshake: it signs the `ClobAuth` attestation,
tries `POST /auth/api-key`, and falls back to deriving the existing key. The
pieces are also exposed directly, which is what a hot restart wants — persist
the credentials once and skip the network round trip forever after:

```rust
let creds = ClobClient::builder().derive_api_key(&signer).await?; // or create_api_key
let client = ClobClient::builder()
    .signature_type(SignatureType::Poly1271)
    .funder(deposit_wallet)
    .with_credentials(signer.address(), creds)?; // no network
```

`Credentials`' secret and passphrase are `secrecy::SecretString`s — they
redact in `Debug` output and zeroize on drop.

### 2. Read market data

```rust
// CLOB metadata (public endpoints):
let venue_time = client.server_time().await?;
let tick = client.tick_size(token_id).await?;      // plain Decimal — any grid parses
let neg_risk = client.neg_risk(token_id).await?;   // picks the signing domain below
let market = client.market(condition_id).await?;   // tokens, tick, accepting_orders, …

// Order books — POST /books, parsed leniently (a malformed book is skipped,
// never poisons the batch). Chunked + concurrent past 500 ids:
let books = client.order_books(&[token_id]).await?;
let by_id = client.order_book_map(&thousands_of_ids).await?;

// Your open orders and trades (L2-authenticated, cursor-paged):
use eggplant_sdk::clob::OpenOrdersRequest;
let open = client.all_open_orders(&OpenOrdersRequest::default()).await?;
let trades = client.trades(&OpenOrdersRequest::default(), None).await?;
```

Event metadata and wallet holdings ride their own hosts, no credentials
needed:

```rust
use eggplant_sdk::data::DataApiClient;
use eggplant_sdk::gamma::GammaClient;

// Page the open-event universe, or resolve one event by slug:
let gamma = GammaClient::new();
let page = gamma.fetch_keyset_page(None, 50, None).await?; // feed back page.next_cursor
let event = gamma.fetch_events_by_slug("some-event-slug").await?;

// A wallet's positions (and what's redeemable):
let data = DataApiClient::new();
let positions = data.all_positions("0xWallet…", 1.0).await?;
let (redeemable, hit_cap) = data.all_redeemable_positions("0xWallet…").await?;
```

### 3. Place and cancel orders

Three steps: build a signer for the market's exchange domain, sign, POST
through the hot poster. Amounts are raw 6-decimal units; for a **BUY** the
maker amount is USDC (`size × price`) and the taker amount is shares
(`size`); a **SELL** swaps them.

```rust
use eggplant_sdk::clob::signing::{
    build_signable_order_side, generate_salt, to_fixed_usdc, ExchangeDomain,
};
use eggplant_sdk::clob::poster::PostTimings;
use eggplant_sdk::clob::types::{OrderType, Side};
use alloy::primitives::U256;
use rust_decimal::Decimal;

// Once per market family: negRisk and regular markets verify against
// different exchange contracts.
let order_signer = client.order_signer(&ExchangeDomain::ctf_v2(neg_risk));

// Once per process: the poster pins the venue's DNS and opens its pools.
let poster = client.poster().await?;

// A resting BUY: 10 shares at 0.45, GTC + post-only (rests as maker
// liquidity; rejected rather than crossing).
let (size, price) = (Decimal::from(10), "0.45".parse::<Decimal>()?);
let signable = build_signable_order_side(
    token_id.parse::<U256>()?,
    U256::from(to_fixed_usdc(size * price)?), // maker: USDC in
    U256::from(to_fixed_usdc(size)?),         // taker: shares out
    client.identity(),
    u64::try_from(chrono::Utc::now().timestamp_millis())?,
    OrderType::GTC,
    generate_salt(),
    true, // post_only — only ever emitted for GTC/GTD
    Side::Buy,
);
let signed = order_signer.sign_order(signable, &signer)?;

let mut timings = PostTimings::default();
let posts = poster
    .post_orders(&[signed], &mut timings, chrono::Utc::now().timestamp())
    .await?;
let response = &posts[0].response;
assert!(response.is_accepted(), "{:?}", response.error_msg);

// Cancel by id (batched DELETE /orders; ≤1000 ids per request — use
// cancel_in_batches for more):
poster.cancel_orders(&[response.order_id.as_str()]).await?;
```

Taker orders are the same call with `OrderType::FOK`/`FAK` and `post_only:
false`. **A taker fill is credited from the POST response**
(`making_amount`/`taking_amount`) — it is _not_ echoed on the user channel,
which only carries maker fills.

Batch helpers for maker flows: `place_resting` / `place_resting_sell` sign
and POST whole ladders of GTC post-only orders, `place_marketable_sell`
fires a FAK whose limit is its own safety floor, and `deep_warm_up` keeps
the sign→POST pipeline hot with unfillable FOKs. `cancel_orders_by_side`
clears one side of the book without touching the other — how two processes
share one API key safely.

When a cancel response comes back, don't guess — partition it:

```rust
use eggplant_sdk::clob::poster::{partition_cancels, CancelLeg};

let batch: Vec<CancelLeg> = vec![(0, 0, order_id)];
let result = poster.cancel_orders(&ids).await;
let (done, retry) = partition_cancels(batch, &result, |(_, _, id)| id.as_str());
// `done`: confirmed cancelled OR terminally gone (already filled/expired/…).
// `retry`: transient misses — a still-live order is never silently dropped.
```

### 4. Keep a live order book

Seed over REST, then apply the market channel. Reconnect on any `Err` — the
resubscribe replays a fresh snapshot, so no state is lost beyond the gap.

```rust
use eggplant_sdk::book::Book;
use eggplant_sdk::ws::market::{MarketEventOwned, MarketStream, MarketStreamConfig};

let mut book = Book::default();
let mut stream = MarketStream::connect(&MarketStreamConfig::new(vec![token_id.into()])).await?;

while let Some(event) = stream.next_event().await? {
    match event {
        MarketEventOwned::Book { bids, asks, .. } => book.apply_snapshot(
            bids.into_iter().map(|l| (l.price, l.size)),
            asks.into_iter().map(|l| (l.price, l.size)),
        ),
        MarketEventOwned::PriceChange { price_changes, .. } => {
            for entry in price_changes {
                if let Some(side) = entry.book_side() {
                    // Idempotent: duplicate deliveries are no-ops.
                    book.apply_delta(side, entry.price, entry.size);
                }
            }
        }
        MarketEventOwned::TickSizeChange { new_tick_size, .. } => { /* re-grid quotes */ }
        _ => {}
    }
    let best_ask = book.asks.first_key_value();
}
```

Latency-sensitive consumers should take `next_text()` instead and
borrow-parse with `parse_market_event` — the zero-copy `MarketEvent<'_>`
handles thousands of updates per second without allocating. The stream owns
the venue's text `PING`/`PONG` liveness protocol internally; a half-open
socket surfaces as an `Err` within ~30s instead of hanging for minutes. For
redundant fan-outs, `ws::util` has the staggered recycle phasing that keeps
long-lived connections fresh without two peers ever refreshing at once.

### 5. Watch your fills

The user channel delivers **every** maker fill on the API key, on every
connection you open, with statuses that evolve (`MATCHED` → … →
`CONFIRMED`/`FAILED`). Handle them in this order: gate on a final status
**before** deduping (a `RETRYING` first sighting must not swallow the
confirmation), dedup by trade id, filter `maker_orders` to your own key, and
derive your side — the trade's top-level `side` describes the _taker_.

```rust
use eggplant_sdk::ws::user::{UserMessage, UserStream, UserStreamConfig};
use eggplant_sdk::ws::util::{our_maker_side, SeenIds};

let our_key = client.credentials().key();
let mut stream =
    UserStream::connect(&UserStreamConfig::new(client.credentials().clone())).await?;
let mut seen = SeenIds::new(1024);

while let Some(message) = stream.next_message().await? {
    let UserMessage::Trade(trade) = message else { continue };
    if !trade.status.is_final() || !seen.insert(trade.id.clone()) {
        continue;
    }
    for maker in trade.maker_orders.iter().filter(|m| m.owner == our_key) {
        let side = our_maker_side(trade.side, trade.outcome.as_deref(), &maker.outcome);
        println!("filled {side:?} {} @ {}", maker.matched_amount, maker.price);
    }
}
```

For redundancy, open several identically-subscribed `UserStream`s behind one
shared `SeenIds` — first delivery wins.

### 6. Merge / split / convert / redeem (relayer)

Gasless position operations ride Polymarket's relayer as `DepositWallet`
batches (requires relayer API credentials from the builder program). The
negRisk math in one line each: **merge** burns YES+NO on a leg for $1;
**convert** burns NO across `k` legs of one event and frees `(k−1)·amount`;
**split** is merge's inverse; **redeem** collects a resolved market.

The engine turns live balances into the minimal submission plan — merges
before converts, tier decomposition, gas-budget chunking, wallet-busy
retries, and a final wrap of the freed USDC.e into pUSD:

```rust
use eggplant_sdk::convert::{convert_legs, plan_jobs, process_job, ConvertDelays, ConvertJob};
use eggplant_sdk::gamma::{GammaClient, GammaMarket};
use eggplant_sdk::relayer::RelayerClient;

// Legs come straight off Gamma:
let event = &GammaClient::new().fetch_events_by_slug(slug).await?[0];
let legs = convert_legs(
    event.markets.as_deref().unwrap_or_default().iter().filter_map(GammaMarket::market_ids),
);

let job = ConvertJob {
    slug: slug.into(), legs,
    amount_raw: alloy::primitives::U256::ZERO,
    attempts: 0, queued_at: std::time::Instant::now(),
};

// Read-only dry run — one RPC balance snapshot, no submissions:
let (plans, _wrap) = plan_jobs(&[&job], rpc_url, wallet, ConvertDelays::default().single_leg_min_qty_raw).await?;
println!("would free {} USDC.e", eggplant_sdk::convert::fmt_usdc(plans[0].proceeds));

// The full cycle (plan → submit chunks → settle → wrap):
let relayer = RelayerClient::new(relayer_api_key, relayer_api_key_address);
let detail = process_job(&job, &signer, &relayer, rpc_url, wallet, ConvertDelays::default()).await?;
```

For a long-running process, spawn `convert_worker` with an mpsc channel and
queue `ConvertJob`s as fills land — bursts coalesce into one shared cycle.
Standalone builders (`build_merge_calldata`, `build_split_calldata`,
`redeem_calls`, `split_calls`, …) are available without the `rpc` feature
and feed `RelayerClient::submit_deposit_wallet_batch` directly.

> ⚠ `splitPosition` is the least-exercised call in this crate. Its 2-arg
> form mirrors the merge exactly, but verify against the deployed adapter
> (or split a dust amount first) before trusting it with size.

Error semantics worth handling: `Error::RelayerQuotaExhausted` means retry
on **your own** fixed backoff (the relayer's `resets in` hint claims ~an
hour; the quota actually frees in well under a minute), and
`err.is_wallet_busy()` means a prior action is still settling and _nothing
was submitted_ — waiting and retrying is always safe.

### 7. One-time approvals

A fresh wallet must approve the exchange contracts before it can trade.
For the Safe path (type 2), `approval::ensure_approvals(&signer, &relayer,
rpc_url)` deploys the Safe if missing and grants pUSD + CTF approvals,
idempotently. Deposit wallets (type 3) batch the same `approve` /
`setApprovalForAll` calldata through `submit_deposit_wallet_batch` instead.

### 8. Handle errors

One `Error` enum end to end. The variants that should change your control
flow:

- `RateLimit { retry_after }` — HTTP 429 anywhere. The poster can also fan
  a `RateLimitSignal` into a supervising task (`set_rate_limit_signal`) so a
  breaker can pull quotes instead of hammering.
- `RelayerQuotaExhausted { resets_in_secs }` / `is_wallet_busy()` — see §6.
- `Api { status, body }` — non-2xx from a read endpoint, body attached.
- `InvalidData` — unparseable input/response, and the poster's transport
  failures (timeout included). On a failed _place_, reconcile against
  `all_open_orders` before assuming nothing rested — a lost ACK is not a
  lost order.

Wire types themselves rarely error: unknown enum values land in `Unknown`
tails and optional fields default, because a strict parse of a drifting
venue is an outage waiting to happen.

## Venue notes

Rules and defaults the crate encodes:

- **Venue minimums**: an order needs ≥ 5 shares (`tick::MIN_SIZE`) _or_ $1
  notional (`tick::MIN_NOTIONAL`); share sizes max 2 decimals
  (`SIZE_DECIMALS`, helpers `floor_to_size_step` / `compute_order_size`);
  prices live on `[tick, 1 − tick]` (`TickEntry`).
- **Salts are masked to 2^53 − 1** (`generate_salt`) so the venue's JS
  tooling round-trips them; the wire serializes salt as a JSON _number_.
- **Reuse one `FastPoster`**; call `warm_up()` on a few-second cadence (and
  size `set_warm_sizes` / `warm_reserve` to your burst) so a hot order never
  waits on a TLS handshake. Cancels ride their own pool by design.
- **Data API offsets cap at 10,000** and then _recycle_ the same page —
  `all_positions` stops there on purpose. Redeem to shrink a huge wallet.
- **Order books can exceed 500 ids per request** only via chunking —
  `order_book_map` does it concurrently for you.
- **WS liveness is text `"PING"`/`"PONG"`**, not WebSocket ping opcodes; the
  streams enforce the 3-missed-pings deadline for you.

## Examples

Runnable walkthroughs in [`examples/`](examples/) — venue writes are gated
behind `EGGPLANT_LIVE_TRADE=1`, everything else is read-only:

| example              | shows                                                                           |
| -------------------- | ------------------------------------------------------------------------------- |
| `quickstart`         | authenticate (any signature type) → read grid → sign → optionally place+cancel |
| `stream_order_books` | REST seed + market channel + `Book` maintenance (no credentials)                |
| `stream_user_fills`  | user channel with dedup, final-status gating, own-maker filtering               |
| `positions`          | Data API holdings + redeemable listing                                          |
| `convert_merge_split`| Gamma → legs → read-only plan → optional relayer cycle; split builders          |
| `approvals_bootstrap`| Safe-path approvals bootstrap                                                   |

```sh
POLYMARKET_PRIVATE_KEY=0x… cargo run --example quickstart
TOKEN_IDS=<id> cargo run --example stream_order_books
```

## Modules

| module                         | contents                                                                                                                                                                                                           |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `clob`                         | `ClobClient` (auth, market/tick metadata, open orders, trades, cancel-all), `signing` (all-type `OrderSigner`), `poster` (`FastPoster` hot writes), `books` (lenient `/books`), `tick` (venue size rules), `types` |
| `relayer`                      | `RelayerClient`: SAFE / SAFE-CREATE / DepositWallet batch submission + EIP-712 hash builders                                                                                                                       |
| `convert`                      | merge/split/convert/redeem calldata, the tier planner, and (with `rpc`) the balance-read → plan → submit → wrap engine                                                                                             |
| `approval`                     | (`rpc`) Safe-path approvals bootstrap                                                                                                                                                                              |
| `ws`                           | market + user streams, zero-copy events, liveness, recycle phasing, `our_maker_side`, `SeenIds`                                                                                                                    |
| `gamma`, `data`                | event metadata and wallet positions                                                                                                                                                                                |
| `book`, `fee`, `chain`, `auth` | order-book state, fee math, contracts/hosts/CREATE2, L1/L2 primitives                                                                                                                                              |

## Feature flags

- `ws` _(default)_ — WebSocket streams (tokio-tungstenite).
- `rpc` _(default)_ — on-chain reads via alloy providers: the convert engine
  and approvals bootstrap. Calldata builders and the relayer client work
  without it.

## Verification

- Golden vectors: L1/L2 auth signatures, CREATE2 wallet addresses, relayer
  EIP-712 typehashes and a create-proxy hash cross-checked against
  Polymarket's Python client.
- Differential tests: the precomputed signing fast path equals alloy's
  generic `eip712_signing_hash` for every known exchange domain.
- `EGGPLANT_LIVE=1 cargo test --test live -- --ignored` runs read-only
  smoke tests against the production venue.

Poly1271 is the most heavily exercised signing path. Types 0/1/2 are
verified against golden vectors and the differential tests — validate with
small sizes first.

## Notes

- MSRV 1.88, edition 2024.
- Relayer operations require API credentials from Polymarket's builder
  program.
- Portions adapted from the MIT-licensed `polymarket_client_sdk_v2` — see
  [ATTRIBUTION.md](ATTRIBUTION.md).

## Disclaimer

This software places real orders and moves real funds. It is provided as-is,
without warranty of any kind; nothing here is financial advice. Validate
every integration with minimum sizes first.
