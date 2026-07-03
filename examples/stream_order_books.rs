//! Maintain live order books: REST seed + market-channel stream. No
//! credentials needed.
//!
//! ```sh
//! TOKEN_IDS=<id>[,<id>…] cargo run --example stream_order_books
//! ```

use std::collections::HashMap;

use alloy::primitives::U256;
use eggplant_sdk::book::Book;
use eggplant_sdk::chain::CLOB_HOST;
use eggplant_sdk::clob::books;
use eggplant_sdk::ws::market::{MarketEventOwned, MarketStream, MarketStreamConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token_ids: Vec<String> = std::env::var("TOKEN_IDS")
        .map_err(|_| "set TOKEN_IDS=<decimal token id>[,<id>…]")?
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();

    // --- 1. Seed the books over REST (lenient /books). ---
    let refs: Vec<&str> = token_ids.iter().map(String::as_str).collect();
    let http = reqwest::Client::new();
    let seeded = books::fetch_book_map_at(&http, &format!("{CLOB_HOST}/books"), &refs).await?;

    let mut book_by_token: HashMap<String, Book> = HashMap::new();
    for id in &token_ids {
        let mut book = Book::default();
        if let Some(summary) = id.parse::<U256>().ok().and_then(|u| seeded.get(&u)) {
            book.apply_snapshot(
                summary.bids.iter().map(|l| (l.price, l.size)),
                summary.asks.iter().map(|l| (l.price, l.size)),
            );
        }
        print_top(id, &book);
        book_by_token.insert(id.clone(), book);
    }

    // --- 2. Keep them live off the market channel. On Err, reconnect: the
    //        resubscribe replays a fresh snapshot, so nothing is lost. ---
    loop {
        let mut stream = MarketStream::connect(&MarketStreamConfig::new(token_ids.clone())).await?;
        println!("subscribed to {} tokens", token_ids.len());
        loop {
            match stream.next_event().await {
                Ok(Some(MarketEventOwned::Book {
                    asset_id,
                    bids,
                    asks,
                    ..
                })) => {
                    if let Some(book) = book_by_token.get_mut(&asset_id) {
                        book.apply_snapshot(
                            bids.into_iter().map(|l| (l.price, l.size)),
                            asks.into_iter().map(|l| (l.price, l.size)),
                        );
                        print_top(&asset_id, book);
                    }
                }
                Ok(Some(MarketEventOwned::PriceChange { price_changes, .. })) => {
                    for entry in price_changes {
                        let Some(side) = entry.book_side() else {
                            continue;
                        };
                        if let Some(book) = book_by_token.get_mut(&entry.asset_id)
                            && book.apply_delta(side, entry.price, entry.size)
                        {
                            print_top(&entry.asset_id, book);
                        }
                    }
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

fn print_top(token_id: &str, book: &Book) {
    let best_bid = book.bids.last_key_value().map(|(p, s)| (*p, *s));
    let best_ask = book.asks.first_key_value().map(|(p, s)| (*p, *s));
    let short = &token_id[..token_id.len().min(12)];
    println!("{short}…  bid {best_bid:?}  ask {best_ask:?}");
}
