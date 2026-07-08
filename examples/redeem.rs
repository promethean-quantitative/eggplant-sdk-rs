//! Redeem every resolved position a wallet holds.
//!
//! ```sh
//! WALLET=0x… cargo run --example redeem                        # dry run
//! WALLET=0x… EGGPLANT_LIVE_TRADE=1 cargo run --example redeem  # submit
//! ```
//!
//! The dry run is read-only (Data API + one RPC balance read per pass) and
//! reports what the first page-set would redeem. Submission additionally needs
//! `POLYMARKET_PRIVATE_KEY`, `RELAYER_API_KEY`, `RELAYER_API_KEY_ADDRESS`, and
//! the wallet's approvals already bootstrapped.

use alloy::primitives::{Address, U256};
use eggplant_sdk::convert::fmt_usdc;
use eggplant_sdk::data::DataApiClient;
use eggplant_sdk::redeem::{RedeemOptions, plan_redeem, redeem_all};
use eggplant_sdk::relayer::RelayerClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let wallet: Address = std::env::var("WALLET")
        .map_err(|_| "set WALLET=<funder address>")?
        .parse()?;
    let rpc_url =
        std::env::var("POLYGON_RPC_URL").unwrap_or_else(|_| "https://polygon-rpc.com".to_owned());

    let data = DataApiClient::new();

    // Dry run: what the first page-set would redeem (submits nothing).
    let (redemptions, hit_cap) = plan_redeem(&data, &rpc_url, wallet, U256::ZERO).await?;
    println!(
        "{} redeemable condition(s) in this page-set{}",
        redemptions.len(),
        if hit_cap {
            " (more remain beyond the offset cap)"
        } else {
            ""
        },
    );
    for r in redemptions.iter().take(10) {
        println!(
            "  {}  yes={} no={}",
            r.condition_id,
            fmt_usdc(r.yes_amount),
            fmt_usdc(r.no_amount),
        );
    }

    if std::env::var("EGGPLANT_LIVE_TRADE").as_deref() != Ok("1") {
        println!("\nEGGPLANT_LIVE_TRADE=1 (plus relayer keys) to redeem everything");
        return Ok(());
    }

    let signer: alloy::signers::local::PrivateKeySigner =
        std::env::var(eggplant_sdk::PRIVATE_KEY_VAR)?.parse()?;
    let relayer = RelayerClient::new(
        std::env::var("RELAYER_API_KEY")?,
        std::env::var("RELAYER_API_KEY_ADDRESS")?,
    );
    let summary = redeem_all(
        &signer,
        &relayer,
        &data,
        &rpc_url,
        wallet,
        &RedeemOptions::default(),
    )
    .await?;
    println!(
        "done — {} redeemed, {} failed across {} pass(es)",
        summary.redeemed, summary.failed, summary.passes,
    );
    Ok(())
}
