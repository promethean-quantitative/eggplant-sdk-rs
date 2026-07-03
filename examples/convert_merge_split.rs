//! Plan (and optionally execute) a negRisk merge/convert cycle for one held
//! event, and show the split builders.
//!
//! ```sh
//! SLUG=<event-slug> WALLET=0x… cargo run --example convert_merge_split
//! ```
//!
//! Planning is read-only (one RPC balance read). Submission additionally
//! needs `POLYMARKET_PRIVATE_KEY`, `RELAYER_API_KEY`,
//! `RELAYER_API_KEY_ADDRESS`, and `EGGPLANT_LIVE_TRADE=1`.

use std::time::Instant;

use alloy::primitives::U256;
use eggplant_sdk::convert::{
    ConvertDelays, ConvertJob, convert_legs, fmt_usdc, plan_jobs, process_job, split_calls,
};
use eggplant_sdk::gamma::{GammaClient, GammaMarket};
use eggplant_sdk::relayer::RelayerClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let slug = std::env::var("SLUG").map_err(|_| "set SLUG=<event slug>")?;
    let wallet: alloy::primitives::Address = std::env::var("WALLET")
        .map_err(|_| "set WALLET=<funder address>")?
        .parse()?;
    let rpc_url =
        std::env::var("POLYGON_RPC_URL").unwrap_or_else(|_| "https://polygon-rpc.com".to_owned());

    // --- 1. Resolve the event's legs from Gamma. ---
    let gamma = GammaClient::new();
    let events = gamma.fetch_events_by_slug(&slug).await?;
    let event = events.first().ok_or("no event for that slug")?;
    let markets = event.markets.as_deref().unwrap_or_default();
    let legs = convert_legs(markets.iter().filter_map(GammaMarket::market_ids));
    println!("{slug}: {} plannable legs", legs.len());

    // --- 2. Plan from a live balance snapshot (read-only). ---
    let job = ConvertJob {
        slug: slug.clone(),
        legs,
        amount_raw: U256::ZERO,
        attempts: 0,
        queued_at: Instant::now(),
    };
    let delays = ConvertDelays::default();
    let (plans, snapshot) =
        plan_jobs(&[&job], &rpc_url, wallet, delays.single_leg_min_qty_raw).await?;
    let plan = &plans[0];
    println!(
        "plan: {} merges, {} convert tiers, frees {} USDC.e (wallet already holds {} unwrapped)",
        plan.merges.len(),
        plan.tiers.len(),
        fmt_usdc(plan.proceeds),
        fmt_usdc(snapshot.balance),
    );
    for tier in &plan.tiers {
        println!(
            "  convert {} across {} legs (+{} post-merges)",
            fmt_usdc(tier.amount),
            tier.question_ids.len(),
            tier.post_merges.len(),
        );
    }

    // --- 3. Split is merge's inverse; the builders are symmetric. Shown
    //        here without submitting (see build_split_calldata's caveat). ---
    if let Some((cid, _)) = plan.merges.first() {
        let calls = split_calls(&[(*cid, U256::from(1_000_000_u64))]);
        println!(
            "\nsplit example: 1.000000 collateral → YES+NO on {cid} ({} bytes calldata)",
            calls[0].data.len(),
        );
    }

    // --- 4. Execute only when explicitly asked. ---
    if std::env::var("EGGPLANT_LIVE_TRADE").as_deref() != Ok("1") {
        println!("\nEGGPLANT_LIVE_TRADE=1 (plus relayer keys) to submit the cycle");
        return Ok(());
    }
    let signer: alloy::signers::local::PrivateKeySigner =
        std::env::var(eggplant_sdk::PRIVATE_KEY_VAR)?.parse()?;
    let relayer = RelayerClient::new(
        std::env::var("RELAYER_API_KEY")?,
        std::env::var("RELAYER_API_KEY_ADDRESS")?,
    );
    let detail = process_job(&job, &signer, &relayer, &rpc_url, wallet, delays).await?;
    println!("cycle complete: {detail}");
    Ok(())
}
