//! Authenticate, inspect a market, sign an order — and only place it when
//! explicitly asked to.
//!
//! ```sh
//! POLYMARKET_PRIVATE_KEY=0x… cargo run --example quickstart
//! ```
//!
//! Environment:
//! - `POLYMARKET_PRIVATE_KEY` (required) — the signing EOA.
//! - `SIGNATURE_TYPE` — `eoa` (default), `proxy`, `safe`, or `poly1271`.
//! - `FUNDER` — the funding wallet, required for `proxy`/`safe`/`poly1271`
//!   (for `proxy`/`safe` it can be derived; see `chain::derive_*_wallet`).
//! - `TOKEN_ID` — a token to quote; without it the example stops after
//!   authentication.
//! - `EGGPLANT_LIVE_TRADE=1` — actually POST the order (then cancel it).
//!   Off by default: the example prints the signed wire body instead.

use alloy::signers::local::PrivateKeySigner;
use eggplant_sdk::PRIVATE_KEY_VAR;
use eggplant_sdk::clob::signing::{ExchangeDomain, build_signable_order};
use eggplant_sdk::clob::tick::{MIN_SIZE, TickEntry};
use eggplant_sdk::clob::types::{OrderType, SignatureType};
use eggplant_sdk::clob::{ClobClient, poster};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let signer: PrivateKeySigner = std::env::var(PRIVATE_KEY_VAR)?.parse()?;

    // --- 1. Build + authenticate the client (create-or-derive an API key). ---
    let mut builder = ClobClient::builder();
    match std::env::var("SIGNATURE_TYPE").as_deref() {
        Ok("proxy") => builder = builder.signature_type(SignatureType::Proxy),
        Ok("safe") => builder = builder.signature_type(SignatureType::GnosisSafe),
        Ok("poly1271") => builder = builder.signature_type(SignatureType::Poly1271),
        _ => {} // default: EOA
    }
    if let Ok(funder) = std::env::var("FUNDER") {
        builder = builder.funder(funder.parse()?);
    }
    let client = builder.authenticate(&signer).await?;
    println!("authenticated: api key {}", client.credentials().key());
    println!("maker/funder:  {}", client.identity().maker);
    println!("venue time:    {}", client.server_time().await?);

    let Ok(token_id) = std::env::var("TOKEN_ID") else {
        println!("\nset TOKEN_ID=<decimal token id> to quote a market");
        return Ok(());
    };

    // --- 2. Read the market's grid and pick the signing domain. ---
    let tick = client.tick_size(&token_id).await?;
    let neg_risk = client.neg_risk(&token_id).await?;
    println!("token {token_id}: tick {tick}, negRisk {neg_risk}");

    let order_signer = client.order_signer(&ExchangeDomain::ctf_v2(neg_risk));

    // --- 3. Sign a minimum-size BUY resting at the price floor (post-only
    //        GTC): essentially unfillable, ideal for validating a pipeline. ---
    let entry = TickEntry::new(tick, token_id.parse()?);
    let size = MIN_SIZE;
    let price = entry.min_price;
    let signable = build_signable_order(
        entry.token_id_u256,
        alloy::primitives::U256::from(eggplant_sdk::clob::signing::to_fixed_usdc(size * price)?),
        alloy::primitives::U256::from(eggplant_sdk::clob::signing::to_fixed_usdc(size)?),
        client.identity(),
        u64::try_from(chrono::Utc::now().timestamp_millis())?,
        OrderType::GTC,
        eggplant_sdk::clob::signing::generate_salt(),
        true, // post-only
    );
    let signed_order = order_signer.sign_order(signable, &signer)?;
    println!(
        "\nsigned {size} @ {price} (BUY, GTC, post-only):\n{}",
        serde_json::to_string_pretty(&signed_order)?
    );

    // --- 4. Only touch the venue when explicitly asked. ---
    if std::env::var("EGGPLANT_LIVE_TRADE").as_deref() != Ok("1") {
        println!("\nEGGPLANT_LIVE_TRADE=1 to place (and immediately cancel) it");
        return Ok(());
    }

    let fast = client.poster().await?;
    let mut timings = poster::PostTimings::default();
    let posts = fast
        .post_orders(
            &[signed_order],
            &mut timings,
            chrono::Utc::now().timestamp(),
        )
        .await?;
    let response = &posts[0].response;
    println!(
        "placed: accepted={} id={} status={:?} ({:.1}ms)",
        response.is_accepted(),
        response.order_id,
        response.status,
        posts[0].rtt_ms,
    );

    if !response.order_id.is_empty() {
        let cancelled = fast.cancel_orders(&[response.order_id.as_str()]).await?;
        println!("cancelled: {:?}", cancelled.canceled);
    }
    Ok(())
}
