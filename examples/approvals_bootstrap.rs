//! One-time approvals bootstrap for the Safe-wallet (signature type 2) path:
//! deploys the Safe if missing, then approves collateral + CTF for the
//! negRisk exchange contracts. Idempotent — re-running skips what's granted.
//!
//! ```sh
//! POLYMARKET_PRIVATE_KEY=0x… \
//! RELAYER_API_KEY=… RELAYER_API_KEY_ADDRESS=… \
//! cargo run --example approvals_bootstrap
//! ```

use alloy::signers::local::PrivateKeySigner;
use eggplant_sdk::approval::ensure_approvals;
use eggplant_sdk::chain::{POLYGON, derive_safe_wallet};
use eggplant_sdk::relayer::RelayerClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init(); // ensure_approvals reports via tracing

    let signer: PrivateKeySigner = std::env::var(eggplant_sdk::PRIVATE_KEY_VAR)?.parse()?;
    let safe = derive_safe_wallet(signer.address(), POLYGON).ok_or("no Safe factory")?;
    println!("EOA {} → Safe {safe}", signer.address());

    let (Ok(api_key), Ok(api_key_address)) = (
        std::env::var("RELAYER_API_KEY"),
        std::env::var("RELAYER_API_KEY_ADDRESS"),
    ) else {
        println!("set RELAYER_API_KEY / RELAYER_API_KEY_ADDRESS (builder program) to proceed");
        return Ok(());
    };

    let relayer = RelayerClient::new(api_key, api_key_address);
    let rpc_url =
        std::env::var("POLYGON_RPC_URL").unwrap_or_else(|_| "https://polygon-rpc.com".to_owned());
    ensure_approvals(&signer, &relayer, &rpc_url).await?;
    println!("approvals verified");
    Ok(())
}
