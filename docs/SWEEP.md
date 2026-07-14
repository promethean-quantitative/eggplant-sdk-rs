# Sweep — the merge/convert safety net

`sweep` systematically settles **every** negRisk position a wallet holds:
merging YES+NO pairs back into collateral and converting leftover NO into
freed USDC. Unlike the convert worker (which converts one event right after a
fill), sweep discovers your *actual* holdings and works through all of them —
so it mops up orphans a normal flow can strand: a convert that errored or was
quota-throttled, a partial fill, a crash mid-cycle.

It is **purely additive and idempotent** — safe to run by hand or on a cron. A
re-run simply finds less to do.

> 💰 **Real money.** Sweep submits gasless relayer transactions that move funds.
> Always start with the read-only dry run, and validate on a wallet with small
> positions first.

---

## 1. Prerequisites

- **Rust** and this crate. From your project: `eggplant-sdk = { version = "…" }`
  with the default features (`rpc` is required for sweep; it is on by default).
  To run the bundled example, clone this repo.
- **A funder wallet** — the address that holds the positions (a Polymarket
  proxy, Safe, or ERC-1271 deposit wallet). Sweep never uses your EOA balance.
- **Relayer API credentials** from Polymarket's builder program
  (`RELAYER_API_KEY` + `RELAYER_API_KEY_ADDRESS`) — the gasless relayer path
  needs them.
- **Approvals in place.** The pUSD collateral adapter must be an ERC-1155
  operator on the wallet (and pUSD-approved). A wallet that has ever converted
  through the Polymarket UI already is. Otherwise bootstrap once:
  - Safe wallets: `approval::ensure_approvals(&signer, &relayer, rpc_url)`
    (see the `approvals_bootstrap` example) — it now covers the collateral
    adapter.
  - Deposit wallets: batch the `setApprovalForAll(collateral_adapter, true)`
    calldata through `RelayerClient::submit_deposit_wallet_batch`.

## 2. Environment variables

| variable                   | needed for       | notes                                             |
| -------------------------- | ---------------- | ------------------------------------------------- |
| `WALLET`                   | always           | the funder address holding the positions          |
| `POLYGON_RPC_URL`          | execute          | a Polygon RPC endpoint (defaults to a public one) |
| `POLYMARKET_PRIVATE_KEY`   | execute          | signer key for the funder wallet                  |
| `RELAYER_API_KEY`          | execute          | Polymarket relayer credential                     |
| `RELAYER_API_KEY_ADDRESS`  | execute          | address paired with the relayer key               |
| `EGGPLANT_LIVE_TRADE=1`    | execute          | required flag to actually submit (else dry run)   |
| `SLUG`                     | optional         | restrict the sweep to a single event slug         |
| `MIN_SHARES`               | optional         | Data API size floor for discovery (default 0)     |

The example loads a `.env` file if present (via `dotenvy`).

## 3. Quick start (the bundled example)

Dry run — discovers holdings and reports the work, **submits nothing**:

```sh
WALLET=0xYourFunder cargo run --example sweep
```

Execute — settle everything (needs the relayer keys + the live flag):

```sh
WALLET=0xYourFunder \
POLYMARKET_PRIVATE_KEY=0x… \
RELAYER_API_KEY=… RELAYER_API_KEY_ADDRESS=0x… \
EGGPLANT_LIVE_TRADE=1 \
cargo run --example sweep
```

Narrow to one event, or skip dust:

```sh
WALLET=0xYourFunder SLUG=some-event-slug MIN_SHARES=1 cargo run --example sweep
```

## 4. Using it from your own code

Two entry points, mirroring the rest of the crate — a read-only planner and an
executor:

```rust
use eggplant_sdk::data::DataApiClient;
use eggplant_sdk::gamma::GammaClient;
use eggplant_sdk::relayer::RelayerClient;
use eggplant_sdk::sweep::{plan_sweep, sweep_all, SweepOptions};

let data = DataApiClient::new();
let gamma = GammaClient::new();
let opts = SweepOptions::default();

// Read-only: which held events have merge/convert work (submits nothing).
for r in plan_sweep(&data, &gamma, wallet, &opts).await? {
    if r.class.actionable() {
        println!("[{}] {} — merge {} / convert {}",
            r.slug, r.title, r.class.merge_pairs, r.class.convert_legs);
    }
}

// Execute: settle every actionable event, one at a time.
let relayer = RelayerClient::new(relayer_api_key, relayer_api_key_address);
let summary = sweep_all(&signer, &relayer, &data, &gamma, rpc_url, wallet, &opts).await?;
println!("{} settled, {} failed", summary.executed, summary.failed);
```

`SweepOptions` fields: `min_shares` (Data API floor), `only_slug`, `delays`
(a `convert::ConvertDelays` — settle waits, gas budget, single-leg dust floor),
and `gamma_concurrency`.

The pure classification layer (`sweep::leg_sizes`, `sweep::classify_event`) is
available without the network if you bring your own positions and legs.

## 5. How it works

1. **Discover** — `DataApiClient::all_positions` lists the wallet's open
   positions.
2. **Resolve** — each distinct negRisk event is resolved to its full leg set
   from Gamma (`fetch_events_by_slug`). Gamma is needed because convert requires
   each leg's `question_id`, which the Data API doesn't carry. A slug Gamma
   can't resolve is skipped (best-effort), never fatal.
3. **Classify** — from the Data API sizes alone (no on-chain reads): a leg
   holding YES+NO is mergeable; leftover NO is convertible (a lone NO leg only
   past the single-leg dust floor, since converting it alone frees 0 USDC).
4. **Execute** — each actionable event runs the shared `convert::process_job`
   cycle **sequentially** (the wallet runs one relayer action at a time).

The scan's amounts are approximate (the API's `size` is a float); the
**authoritative** merge/convert amounts come from on-chain balances that
`process_job` re-reads at execute time. So the API scan only decides *which*
events to touch, never how much — a mis-sized scan can't move the wrong amount.

## 6. Operational notes

- **Idempotent / resumable.** Interrupt it and re-run; it picks up what's left.
- **Sequential by design.** A second in-flight relayer action on the same wallet
  is rejected as "wallet busy"; sweep serializes and retries.
- **Cron-friendly.** Run it on a schedule as a safety net behind your main flow.
- **Failures are per-event.** One event failing (quota, transient) is counted and
  skipped; the rest still settle. Quota exhaustion frees in well under a minute
  despite the relayer's `resets in` hint — just run again.
