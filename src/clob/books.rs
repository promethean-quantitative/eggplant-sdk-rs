//! Batch order-book summary fetch (`POST /books`), parsed into lenient owned
//! types.
//!
//! `tick_size` is a plain [`Decimal`] — deliberately not an enum. The venue
//! launches new price grids without notice (the 0.0025 quarter-cent tick,
//! 2026-07), and a closed tick enum makes the *whole* batch response fail to
//! deserialize — at startup, that can keep a client from booting at all.
//! Here any grid parses, and each book is parsed independently, so one
//! malformed element is skipped and logged instead of poisoning its batch.

use std::collections::HashMap;
use std::str::FromStr as _;
use std::time::Instant;

use alloy::primitives::U256;
use futures::future::try_join_all;
use rust_decimal::Decimal;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::Error;

/// One price level of a book summary. The venue sends decimal strings; any
/// price parses (no grid assumption).
#[derive(Debug, Clone, Deserialize)]
pub struct BookLevel {
    pub price: Decimal,
    pub size: Decimal,
}

/// One order-book summary from `POST /books`, reduced to the load-bearing
/// fields.
///
/// `tick_size` is a plain [`Decimal`] so every venue grid parses — including
/// ticks outside the historical {0.1, 0.01, 0.001, 0.0001} set.
#[derive(Debug, Clone, Deserialize)]
pub struct BookSummary {
    /// Token id (arrives as a decimal string).
    #[serde(deserialize_with = "u256_from_dec_str")]
    pub asset_id: U256,
    #[serde(default, deserialize_with = "null_to_empty")]
    pub bids: Vec<BookLevel>,
    #[serde(default, deserialize_with = "null_to_empty")]
    pub asks: Vec<BookLevel>,
    /// The market's current price grid (minimum tick).
    pub tick_size: Decimal,
}

fn u256_from_dec_str<'de, D>(de: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    U256::from_str(s).map_err(serde::de::Error::custom)
}

/// A missing or `null` side is an empty ladder (the venue sends `null`, not
/// `[]`).
fn null_to_empty<'de, D>(de: D) -> Result<Vec<BookLevel>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<BookLevel>>::deserialize(de)?.unwrap_or_default())
}

/// `POST /books` request entry. Only `token_id`; omitting `side` returns both.
#[derive(Serialize)]
struct BookRequest<'a> {
    token_id: &'a str,
}

/// Validate every id parses as a `U256` and borrow the originals into the
/// POST body.
fn build_requests<'a>(token_ids: &[&'a str]) -> Result<Vec<BookRequest<'a>>, Error> {
    token_ids
        .iter()
        .map(|id| {
            U256::from_str(id)
                .map_err(|e| Error::InvalidData(format!("invalid token ID {id}: {e}")))?;
            Ok(BookRequest { token_id: id })
        })
        .collect()
}

/// Best-effort id extraction for diagnostics on a book that failed to parse.
#[derive(Deserialize)]
struct AssetIdOnly {
    #[serde(default)]
    asset_id: String,
}

/// Parse a `/books` response body leniently: the top level must be a JSON
/// array, but each element parses independently — a malformed book is skipped
/// with a warning instead of failing the batch. This is the property a strict
/// typed parse lacks: one unexpected value (e.g. a new tick size) poisons
/// every book in the response.
fn parse_books(text: &str) -> Result<Vec<BookSummary>, Error> {
    let raw: Vec<&serde_json::value::RawValue> = serde_json::from_str(text)?;
    let mut books = Vec::with_capacity(raw.len());
    let mut skipped = 0_usize;
    for rv in raw {
        match serde_json::from_str::<BookSummary>(rv.get()) {
            Ok(b) => books.push(b),
            Err(e) => {
                skipped += 1;
                // Failure path only: re-parse just the id so the log names the token.
                let asset_id = serde_json::from_str::<AssetIdOnly>(rv.get())
                    .map(|a| a.asset_id)
                    .unwrap_or_default();
                tracing::warn!(%asset_id, error = %e, "skipping unparseable book summary");
            }
        }
    }
    if skipped > 0 {
        tracing::warn!(
            skipped,
            parsed = books.len(),
            "books response had unparseable entries"
        );
    }
    Ok(books)
}

/// One raw `POST /books` round trip for `token_ids`, leniently parsed.
/// `url` is the full endpoint (`{host}/books`).
pub async fn fetch_books_at(
    http: &reqwest::Client,
    url: &str,
    token_ids: &[&str],
) -> Result<Vec<BookSummary>, Error> {
    let requests = build_requests(token_ids)?;
    let response = http.post(url).json(&requests).send().await?;
    let status = response.status();
    if status.as_u16() == 429 {
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        return Err(Error::RateLimit { retry_after });
    }
    let text = response.text().await?;
    if !status.is_success() {
        return Err(Error::Api {
            status: status.as_u16(),
            body: text.chars().take(300).collect(),
        });
    }
    parse_books(&text)
}

/// Max token ids per `/books` POST.
pub const MAX_BATCH_SIZE: usize = 500;

/// Fetches books for arbitrarily many ids, chunked at [`MAX_BATCH_SIZE`] with
/// the chunks in flight concurrently, keyed by asset id.
pub async fn fetch_book_map_at(
    http: &reqwest::Client,
    url: &str,
    token_ids: &[&str],
) -> Result<HashMap<U256, BookSummary>, Error> {
    let total_start = Instant::now();
    let chunks: Vec<_> = token_ids.chunks(MAX_BATCH_SIZE).collect();
    let num_chunks = chunks.len();

    let results = try_join_all(chunks.iter().enumerate().map(|(i, chunk)| async move {
        let start = Instant::now();
        let books = fetch_books_at(http, url, chunk).await?;
        tracing::debug!(
            chunk = i + 1,
            of = num_chunks,
            requested = chunk.len(),
            returned = books.len(),
            elapsed_ms = start.elapsed().as_millis(),
            "order book chunk"
        );
        Ok::<_, Error>(books)
    }))
    .await?;

    let mut map = HashMap::with_capacity(token_ids.len());
    for books in results {
        map.extend(books.into_iter().map(|b| (b.asset_id, b)));
    }

    tracing::debug!(
        total_tokens = token_ids.len(),
        books = map.len(),
        chunks = num_chunks,
        elapsed_ms = total_start.elapsed().as_millis(),
        "order book fetch complete"
    );

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    // Venue-shaped payload: string prices, a null side, extra fields, and the
    // quarter-cent tick a closed enum rejects wholesale.
    const QUARTER_CENT_BOOK: &str = r#"[{
        "market": "0xabc",
        "asset_id": "71321045679252212594626385532706912750332728571942532289631379312455583992563",
        "timestamp": "1751300000000",
        "hash": "h",
        "bids": [{"price": "0.4975", "size": "120.5"}],
        "asks": null,
        "min_order_size": "5",
        "tick_size": "0.0025",
        "neg_risk": true
    }]"#;

    #[test]
    fn parses_quarter_cent_tick() {
        let books = parse_books(QUARTER_CENT_BOOK).unwrap();
        assert_eq!(books.len(), 1);
        let b = &books[0];
        assert_eq!(b.tick_size, d("0.0025"));
        assert_eq!(b.bids.len(), 1);
        assert_eq!(b.bids[0].price, d("0.4975"));
        assert_eq!(b.bids[0].size, d("120.5"));
        // `null` side → empty ladder.
        assert!(b.asks.is_empty());
        let id = "71321045679252212594626385532706912750332728571942532289631379312455583992563";
        assert_eq!(b.asset_id, U256::from_str(id).unwrap());
    }

    #[test]
    fn malformed_book_is_skipped_not_fatal() {
        // The middle element has no tick_size: it alone is dropped.
        let json = r#"[
            {"asset_id": "11", "bids": [], "asks": [], "tick_size": "0.01"},
            {"asset_id": "22", "bids": [], "asks": []},
            {"asset_id": "33", "bids": [], "asks": [], "tick_size": "0.0025"}
        ]"#;
        let books = parse_books(json).unwrap();
        assert_eq!(books.len(), 2);
        assert_eq!(books[0].tick_size, d("0.01"));
        assert_eq!(books[1].tick_size, d("0.0025"));
    }

    #[test]
    fn missing_sides_default_empty() {
        let json = r#"[{"asset_id": "11", "tick_size": "0.001"}]"#;
        let books = parse_books(json).unwrap();
        assert!(books[0].bids.is_empty() && books[0].asks.is_empty());
    }

    #[test]
    fn non_array_body_is_an_error() {
        assert!(parse_books(r#"{"error": "not ok"}"#).is_err());
    }

    #[test]
    fn numeric_tick_also_parses() {
        // Defensive: rust_decimal's deserializer accepts bare numbers too, so
        // a venue switch away from strings wouldn't break the fetch.
        let json = r#"[{"asset_id": "11", "tick_size": 0.0025}]"#;
        assert_eq!(parse_books(json).unwrap()[0].tick_size, d("0.0025"));
    }

    #[test]
    fn build_requests_rejects_garbage_id() {
        assert!(build_requests(&["not-a-number"]).is_err());
        assert!(build_requests(&["123"]).is_ok());
    }
}
