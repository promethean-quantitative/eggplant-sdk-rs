//! List a wallet's open and redeemable positions (no credentials needed).
//!
//! ```sh
//! WALLET=0x… cargo run --example positions
//! ```

use eggplant_sdk::data::DataApiClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let wallet = std::env::var("WALLET").map_err(|_| "set WALLET=<funder address>")?;
    let data = DataApiClient::new();

    let positions = data.all_positions(&wallet, 1.0).await?;
    println!("{} positions ≥ 1 share:", positions.len());
    for p in positions.iter().take(20) {
        println!(
            "  {:>12.2}  {:<4} {} ({})",
            p.size,
            p.outcome,
            p.title,
            if p.negative_risk { "negRisk" } else { "binary" },
        );
    }
    if positions.len() > 20 {
        println!("  … and {} more", positions.len() - 20);
    }

    let (redeemable, hit_cap) = data.all_redeemable_positions(&wallet).await?;
    println!(
        "\n{} redeemable position(s){}",
        redeemable.len(),
        if hit_cap {
            " (offset cap hit — a tail may remain; redeem and re-fetch)"
        } else {
            ""
        },
    );
    Ok(())
}
