//! Watch your own fills on the authenticated user channel, with the
//! production filtering discipline: trade-id dedup across deliveries, final
//! status handling, own-maker-order filtering, and maker-side derivation.
//!
//! ```sh
//! POLYMARKET_PRIVATE_KEY=0x… cargo run --example stream_user_fills
//! ```

use alloy::signers::local::PrivateKeySigner;
use eggplant_sdk::PRIVATE_KEY_VAR;
use eggplant_sdk::clob::ClobClient;
use eggplant_sdk::ws::user::{UserMessage, UserStream, UserStreamConfig};
use eggplant_sdk::ws::util::{SeenIds, our_maker_side};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let signer: PrivateKeySigner = std::env::var(PRIVATE_KEY_VAR)?.parse()?;

    // Re-derive the wallet's API key (no key is created).
    let credentials = ClobClient::builder().derive_api_key(&signer).await?;
    let our_key = credentials.key();
    println!(
        "streaming fills for api key {our_key} ({})",
        signer.address()
    );

    let config = UserStreamConfig::new(credentials);
    let mut seen = SeenIds::new(1024);

    loop {
        let mut stream = UserStream::connect(&config).await?;
        println!("subscribed to user channel");
        loop {
            match stream.next_message().await {
                Ok(Some(UserMessage::Trade(trade))) => {
                    // Wait for a final status before acting; gate BEFORE the
                    // dedup so a RETRYING first sighting can't swallow the
                    // later confirmation.
                    if !trade.status.is_final() {
                        continue;
                    }
                    if !seen.insert(trade.id.clone()) {
                        continue; // duplicate delivery
                    }
                    // A sweep lists every counterparty's maker orders — only
                    // ours matter, and the trade's top-level side is the
                    // *taker's*.
                    for maker in trade.maker_orders.iter().filter(|m| m.owner == our_key) {
                        let side =
                            our_maker_side(trade.side, trade.outcome.as_deref(), &maker.outcome);
                        println!(
                            "fill {:?} {} {} @ {} ({} | trade {})",
                            side,
                            maker.matched_amount,
                            maker.outcome,
                            maker.price,
                            maker.asset_id,
                            trade.id,
                        );
                    }
                }
                Ok(Some(UserMessage::Order(order))) => {
                    println!(
                        "order {:?} {} {:?} @ {} (matched {:?})",
                        order.msg_type, order.id, order.side, order.price, order.size_matched,
                    );
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    println!("server closed; reconnecting");
                    break;
                }
                Err(e) => {
                    println!("stream error ({e}); reconnecting");
                    break;
                }
            }
        }
    }
}
