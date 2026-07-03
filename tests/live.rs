//! Live smoke tests against production Polymarket. Read-only.
//!
//! Deliberately `#[ignore]`d AND gated on `EGGPLANT_LIVE=1` so neither `cargo
//! test` nor a bare `--ignored` run touches the network by accident:
//!
//! ```sh
//! EGGPLANT_LIVE=1 cargo test --test live -- --ignored --nocapture
//! ```
//!
//! `derive_key_and_read_clob` additionally needs `POLYMARKET_PRIVATE_KEY`;
//! `wallet_positions` needs `WALLET` (a funder address). Both skip silently
//! when their variable is absent.

use eggplant_sdk::clob::ClobClient;
use eggplant_sdk::data::DataApiClient;
use eggplant_sdk::gamma::GammaClient;

fn live() -> bool {
    std::env::var("EGGPLANT_LIVE").is_ok_and(|v| v == "1")
}

#[tokio::test]
#[ignore = "live venue: EGGPLANT_LIVE=1 cargo test --test live -- --ignored"]
async fn gamma_universe_and_books() {
    if !live() {
        return;
    }

    // One keyset page of open events…
    let gamma = GammaClient::new();
    let page = gamma
        .fetch_keyset_page(None, 10, None)
        .await
        .expect("gamma keyset page");
    assert!(
        !page.events.is_empty(),
        "open-event universe is never empty"
    );

    // …then seed order books for the first tokens found (public POST /books).
    let token_ids: Vec<String> = page
        .events
        .iter()
        .filter_map(|e| e.markets.as_ref())
        .flatten()
        .filter_map(|m| m.yes_token_id().map(str::to_owned))
        .take(5)
        .collect();
    assert!(!token_ids.is_empty(), "events carry clobTokenIds");

    let refs: Vec<&str> = token_ids.iter().map(String::as_str).collect();
    let http = reqwest::Client::new();
    let url = format!("{}/books", eggplant_sdk::chain::CLOB_HOST);
    let books = eggplant_sdk::clob::books::fetch_books_at(&http, &url, &refs)
        .await
        .expect("books fetch");
    println!("fetched {} books for {} tokens", books.len(), refs.len());
    for book in &books {
        assert!(book.tick_size > rust_decimal::Decimal::ZERO);
    }
}

#[tokio::test]
#[ignore = "live venue: EGGPLANT_LIVE=1 cargo test --test live -- --ignored"]
async fn derive_key_and_read_clob() {
    if !live() {
        return;
    }
    dotenvy::dotenv().ok();
    let Ok(pk) = std::env::var(eggplant_sdk::PRIVATE_KEY_VAR) else {
        eprintln!("skipping: {} not set", eggplant_sdk::PRIVATE_KEY_VAR);
        return;
    };
    let signer: alloy::signers::local::PrivateKeySigner = pk.parse().expect("private key parses");

    // The L1 handshake end to end (derive only — never mints a key here).
    let builder = ClobClient::builder();
    let credentials = builder
        .derive_api_key(&signer)
        .await
        .expect("derive-api-key");
    println!("derived api key {}", credentials.key());

    let client = ClobClient::builder()
        .with_credentials(alloy::signers::Signer::address(&signer), credentials)
        .expect("client builds");

    let server_time = client.server_time().await.expect("server time");
    let now = chrono::Utc::now().timestamp();
    assert!(
        (server_time - now).abs() < 300,
        "venue clock within 5 minutes of local"
    );

    // L2-authenticated read: one open-orders page.
    let page = client
        .open_orders(&eggplant_sdk::clob::OpenOrdersRequest::default(), None)
        .await
        .expect("open orders page");
    println!(
        "open orders: {} on the first page (cursor {})",
        page.data.len(),
        page.next_cursor
    );
}

#[tokio::test]
#[ignore = "live venue: EGGPLANT_LIVE=1 cargo test --test live -- --ignored"]
async fn wallet_positions() {
    if !live() {
        return;
    }
    dotenvy::dotenv().ok();
    let Ok(wallet) = std::env::var("WALLET") else {
        eprintln!("skipping: WALLET not set");
        return;
    };

    let data = DataApiClient::new();
    let positions = data.all_positions(&wallet, 1.0).await.expect("positions");
    println!("{wallet} holds {} positions ≥ 1 share", positions.len());

    let (redeemable, hit_cap) = data
        .all_redeemable_positions(&wallet)
        .await
        .expect("redeemable positions");
    println!("{} redeemable (hit_cap: {hit_cap})", redeemable.len());
}
