//! Systematically merge/convert every negRisk position a wallet holds.
//!
//! ```sh
//! WALLET=0x… cargo run --example sweep                        # dry run
//! WALLET=0x… EGGPLANT_LIVE_TRADE=1 cargo run --example sweep  # submit
//! ```
//!
//! The dry run discovers holdings (Data API + Gamma) and reports the
//! merge/convert work each held event has, submitting nothing. Submission
//! additionally needs `POLYMARKET_PRIVATE_KEY`, `RELAYER_API_KEY`,
//! `RELAYER_API_KEY_ADDRESS`, and the wallet's approvals already bootstrapped
//! (see the `approvals_bootstrap` example). `SLUG=<slug>` narrows the sweep to
//! one event; `MIN_SHARES=<n>` sets the Data API size floor.

use alloy::primitives::Address;
use eggplant_sdk::data::DataApiClient;
use eggplant_sdk::gamma::GammaClient;
use eggplant_sdk::relayer::RelayerClient;
use eggplant_sdk::sweep::{SweepOptions, plan_sweep, sweep_all};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let wallet: Address = std::env::var("WALLET")
        .map_err(|_| "set WALLET=<funder address>")?
        .parse()?;
    let rpc_url =
        std::env::var("POLYGON_RPC_URL").unwrap_or_else(|_| "https://polygon-rpc.com".to_owned());

    let opts = SweepOptions {
        only_slug: std::env::var("SLUG").ok(),
        min_shares: std::env::var("MIN_SHARES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0.0),
        ..SweepOptions::default()
    };

    let data = DataApiClient::new();
    let gamma = GammaClient::new();

    // Dry run: what each held negRisk event would merge/convert.
    let reports = plan_sweep(&data, &gamma, wallet, &opts).await?;
    let actionable = reports.iter().filter(|r| r.class.actionable()).count();
    println!(
        "{} held negRisk event(s), {actionable} actionable:",
        reports.len()
    );
    for r in reports.iter().filter(|r| r.class.actionable()) {
        print!("  [{}] {}", r.slug, r.title);
        if r.class.mergeable {
            print!("  merge {} pair(s)", r.class.merge_pairs);
        }
        if r.class.convertible {
            print!("  convert {} leg(s)", r.class.convert_legs);
        }
        println!();
    }

    if std::env::var("EGGPLANT_LIVE_TRADE").as_deref() != Ok("1") {
        println!("\nEGGPLANT_LIVE_TRADE=1 (plus relayer keys) to settle everything");
        return Ok(());
    }

    let signer: alloy::signers::local::PrivateKeySigner =
        std::env::var(eggplant_sdk::PRIVATE_KEY_VAR)?.parse()?;
    let relayer = RelayerClient::new(
        std::env::var("RELAYER_API_KEY")?,
        std::env::var("RELAYER_API_KEY_ADDRESS")?,
    );
    let summary = sweep_all(&signer, &relayer, &data, &gamma, &rpc_url, wallet, &opts).await?;
    println!(
        "done — {} held, {} actionable, {} settled, {} failed",
        summary.held_events, summary.actionable, summary.executed, summary.failed,
    );
    Ok(())
}
