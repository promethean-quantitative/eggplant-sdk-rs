//! Market-channel messages (zero-copy first) and a single-connection stream.
//!
//! [`MarketEvent`] borrows every string field straight out of the frame —
//! built to parse thousands of book updates per second without allocating.
//! Convert to [`MarketEventOwned`] (typed `Decimal`/`i64`) off the hot path
//! via [`MarketEvent::to_owned_event`].
//!
//! [`MarketStream`] is deliberately thin: connect, subscribe, and yield raw
//! text frames with the PING/PONG liveness protocol handled internally.
//! Multi-connection fan-out, sharding, and reconnect policy stay with the
//! caller (see [`crate::ws::util`] for the proven phasing helpers).

use std::time::Instant;

use futures::{SinkExt as _, StreamExt as _};
use rust_decimal::Decimal;
use serde::Deserialize;
use tokio_tungstenite::tungstenite::Message;

use crate::book::BookSide;
use crate::chain::WS_MARKET_URL;
use crate::error::Error;
use crate::ws::frames::{self, PING_INTERVAL, PONG_TIMEOUT};

/// One price level, borrowed from the frame (decimal strings).
#[derive(Debug, Deserialize)]
pub struct BookLevel<'a> {
    pub price: &'a str,
    pub size: &'a str,
}

/// One entry of a `price_change` batch, borrowed from the frame.
#[derive(Debug, Deserialize)]
pub struct PriceChangeEntry<'a> {
    #[serde(borrow)]
    pub asset_id: &'a str,
    pub price: &'a str,
    /// New absolute size at `price` (`"0"` removes the level).
    pub size: &'a str,
    /// `"BUY"` (bid ladder) or `"SELL"` (ask ladder).
    pub side: &'a str,
    pub best_bid: &'a str,
    pub best_ask: &'a str,
}

impl PriceChangeEntry<'_> {
    /// Which book ladder this delta touches, or `None` for an unknown side.
    #[must_use]
    pub fn book_side(&self) -> Option<BookSide> {
        side_to_book(self.side)
    }
}

fn side_to_book(side: &str) -> Option<BookSide> {
    if side.eq_ignore_ascii_case("BUY") {
        Some(BookSide::Bid)
    } else if side.eq_ignore_ascii_case("SELL") {
        Some(BookSide::Ask)
    } else {
        None
    }
}

/// One market-channel event, zero-copy.
///
/// Unrecognized `event_type`s land in `Unknown` instead of failing the frame
/// — the venue adds event kinds without notice.
#[derive(Debug, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum MarketEvent<'a> {
    /// Full book snapshot (sent on subscribe and after trades).
    Book {
        #[serde(borrow)]
        asset_id: &'a str,
        #[serde(default)]
        bids: Vec<BookLevel<'a>>,
        #[serde(default)]
        asks: Vec<BookLevel<'a>>,
        /// Venue milliseconds, as a string.
        #[serde(default)]
        timestamp: Option<&'a str>,
    },
    /// Incremental level changes.
    PriceChange {
        #[serde(borrow)]
        price_changes: Vec<PriceChangeEntry<'a>>,
        #[serde(default)]
        timestamp: Option<&'a str>,
    },
    TickSizeChange {
        #[serde(borrow)]
        asset_id: &'a str,
        new_tick_size: &'a str,
    },
    /// A trade print. Every field beyond `asset_id`/`price` is
    /// venue-optional so a shape drift degrades to a less-informative record
    /// instead of a parse drop.
    LastTradePrice {
        #[serde(borrow)]
        asset_id: &'a str,
        price: &'a str,
        #[serde(default)]
        size: Option<&'a str>,
        #[serde(default)]
        side: Option<&'a str>,
        #[serde(default)]
        timestamp: Option<&'a str>,
    },
    #[serde(other)]
    Unknown,
}

/// Parse one market-channel text frame, borrowing from it.
pub fn parse_market_event(text: &str) -> Result<MarketEvent<'_>, serde_json::Error> {
    serde_json::from_str(text)
}

/// Owned, numerically-typed price level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookLevelOwned {
    pub price: Decimal,
    pub size: Decimal,
}

/// Owned, numerically-typed `price_change` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceChangeEntryOwned {
    pub asset_id: String,
    pub price: Decimal,
    pub size: Decimal,
    pub side: String,
    pub best_bid: Option<Decimal>,
    pub best_ask: Option<Decimal>,
}

impl PriceChangeEntryOwned {
    /// Which book ladder this delta touches, or `None` for an unknown side.
    #[must_use]
    pub fn book_side(&self) -> Option<BookSide> {
        side_to_book(&self.side)
    }
}

/// Owned mirror of [`MarketEvent`] with numeric fields parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketEventOwned {
    Book {
        asset_id: String,
        bids: Vec<BookLevelOwned>,
        asks: Vec<BookLevelOwned>,
        /// Venue milliseconds.
        timestamp: Option<i64>,
    },
    PriceChange {
        price_changes: Vec<PriceChangeEntryOwned>,
        timestamp: Option<i64>,
    },
    TickSizeChange {
        asset_id: String,
        new_tick_size: Decimal,
    },
    LastTradePrice {
        asset_id: String,
        price: Decimal,
        size: Option<Decimal>,
        side: Option<String>,
        timestamp: Option<i64>,
    },
    Unknown,
}

fn dec(raw: &str, field: &str) -> Result<Decimal, Error> {
    raw.parse()
        .map_err(|_| Error::InvalidData(format!("unparseable {field}: {raw}")))
}

fn opt_dec(raw: Option<&str>, field: &str) -> Result<Option<Decimal>, Error> {
    raw.map(|r| dec(r, field)).transpose()
}

/// Empty-string best bid/ask means "no level" — tolerate rather than error.
fn lenient_dec(raw: &str) -> Option<Decimal> {
    raw.parse().ok()
}

fn opt_ms(raw: Option<&str>) -> Option<i64> {
    raw.and_then(|r| r.parse().ok())
}

impl MarketEvent<'_> {
    /// Convert into the owned mirror, parsing prices and sizes to
    /// [`Decimal`]. Errors on an unparseable load-bearing number
    /// (`best_bid`/`best_ask` and timestamps degrade to `None` instead).
    pub fn to_owned_event(&self) -> Result<MarketEventOwned, Error> {
        Ok(match self {
            Self::Book {
                asset_id,
                bids,
                asks,
                timestamp,
            } => {
                let convert = |levels: &[BookLevel<'_>]| -> Result<Vec<BookLevelOwned>, Error> {
                    levels
                        .iter()
                        .map(|l| {
                            Ok(BookLevelOwned {
                                price: dec(l.price, "book price")?,
                                size: dec(l.size, "book size")?,
                            })
                        })
                        .collect()
                };
                MarketEventOwned::Book {
                    asset_id: (*asset_id).to_owned(),
                    bids: convert(bids)?,
                    asks: convert(asks)?,
                    timestamp: opt_ms(*timestamp),
                }
            }
            Self::PriceChange {
                price_changes,
                timestamp,
            } => MarketEventOwned::PriceChange {
                price_changes: price_changes
                    .iter()
                    .map(|entry| {
                        Ok(PriceChangeEntryOwned {
                            asset_id: entry.asset_id.to_owned(),
                            price: dec(entry.price, "price_change price")?,
                            size: dec(entry.size, "price_change size")?,
                            side: entry.side.to_owned(),
                            best_bid: lenient_dec(entry.best_bid),
                            best_ask: lenient_dec(entry.best_ask),
                        })
                    })
                    .collect::<Result<_, Error>>()?,
                timestamp: opt_ms(*timestamp),
            },
            Self::TickSizeChange {
                asset_id,
                new_tick_size,
            } => MarketEventOwned::TickSizeChange {
                asset_id: (*asset_id).to_owned(),
                new_tick_size: dec(new_tick_size, "new_tick_size")?,
            },
            Self::LastTradePrice {
                asset_id,
                price,
                size,
                side,
                timestamp,
            } => MarketEventOwned::LastTradePrice {
                asset_id: (*asset_id).to_owned(),
                price: dec(price, "last_trade_price price")?,
                size: opt_dec(*size, "last_trade_price size")?,
                side: side.map(str::to_owned),
                timestamp: opt_ms(*timestamp),
            },
            Self::Unknown => MarketEventOwned::Unknown,
        })
    }
}

/// Configuration for one market-channel connection.
#[derive(Debug, Clone)]
pub struct MarketStreamConfig {
    /// Defaults to [`WS_MARKET_URL`].
    pub url: String,
    /// Token ids to subscribe (the venue accepts ~500 per connection before
    /// delivery degrades; shard beyond that).
    pub token_ids: Vec<String>,
    /// Request the extended event kinds (`best_bid_ask`, `new_market`,
    /// `market_resolved`).
    pub custom_features: bool,
}

impl MarketStreamConfig {
    #[must_use]
    pub fn new(token_ids: Vec<String>) -> Self {
        Self {
            url: WS_MARKET_URL.to_owned(),
            token_ids,
            custom_features: true,
        }
    }
}

pub(crate) type WsSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Shared connect + subscribe + liveness loop for both channels.
pub(crate) struct LiveSocket {
    socket: WsSocket,
    ping: tokio::time::Interval,
    last_pong: Instant,
}

impl LiveSocket {
    pub(crate) async fn connect(url: &str, subscribe_frame: String) -> Result<Self, Error> {
        let (mut socket, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| Error::Ws(format!("connect failed: {e}")))?;
        socket
            .send(Message::Text(subscribe_frame.into()))
            .await
            .map_err(|e| Error::Ws(format!("subscribe failed: {e}")))?;
        Ok(Self {
            socket,
            ping: tokio::time::interval(PING_INTERVAL),
            last_pong: Instant::now(),
        })
    }

    /// The next data frame: `Ok(Some(text))` for a data frame, `Ok(None)` on
    /// a clean close, `Err` on transport failure or a PONG-deadline breach.
    /// PING/PONG frames are handled internally and never surface.
    pub(crate) async fn next_text(&mut self) -> Result<Option<String>, Error> {
        loop {
            tokio::select! {
                _ = self.ping.tick() => {
                    // No PONG within the deadline ⇒ half-open socket; bail to
                    // the caller's reconnect path rather than waiting minutes
                    // for a TCP-level failure.
                    if self.last_pong.elapsed() > PONG_TIMEOUT {
                        return Err(Error::Ws("PONG timeout (half-open socket)".into()));
                    }
                    self.socket
                        .send(Message::Text(frames::PING.into()))
                        .await
                        .map_err(|e| Error::Ws(format!("ping failed: {e}")))?;
                }
                msg = self.socket.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if text.as_str() == frames::PONG {
                                self.last_pong = Instant::now();
                            } else {
                                return Ok(Some(text.as_str().to_owned()));
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => return Ok(None),
                        Some(Ok(_)) => {} // binary/ping/pong opcodes: ignored
                        Some(Err(e)) => return Err(Error::Ws(format!("read failed: {e}"))),
                    }
                }
            }
        }
    }

    /// Politely close (e.g. for a scheduled recycle).
    pub(crate) async fn close(&mut self) {
        let _ = self.socket.send(Message::Close(None)).await;
    }
}

/// One market-channel connection with the liveness protocol handled.
///
/// Yields raw text frames so hot consumers can borrow-parse with
/// [`parse_market_event`]; [`MarketStream::next_event`] layers the owned
/// parse on top. On `Err`, drop and reconnect — resubscribing replays a
/// fresh book snapshot, so no state is lost beyond the gap.
pub struct MarketStream {
    inner: LiveSocket,
}

impl MarketStream {
    /// Connect and subscribe.
    pub async fn connect(config: &MarketStreamConfig) -> Result<Self, Error> {
        let frame = frames::market_subscribe_frame(&config.token_ids, config.custom_features);
        Ok(Self {
            inner: LiveSocket::connect(&config.url, frame).await?,
        })
    }

    /// The next raw data frame: `Ok(Some(text))` for a data frame,
    /// `Ok(None)` on a clean server close, `Err` on transport failure or a
    /// PONG-deadline breach (reconnect). PING/PONG never surfaces.
    pub async fn next_text(&mut self) -> Result<Option<String>, Error> {
        self.inner.next_text().await
    }

    /// The next event, owned-parsed. Unknown event kinds surface as
    /// [`MarketEventOwned::Unknown`] rather than erroring.
    pub async fn next_event(&mut self) -> Result<Option<MarketEventOwned>, Error> {
        match self.next_text().await? {
            None => Ok(None),
            Some(text) => {
                let event = parse_market_event(&text)
                    .map_err(|e| Error::InvalidData(format!("market frame parse: {e}")))?;
                event.to_owned_event().map(Some)
            }
        }
    }

    /// Politely close (e.g. for a scheduled recycle).
    pub async fn close(&mut self) {
        self.inner.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    #[test]
    fn parses_book_snapshot() {
        let text = r#"{
            "event_type": "book",
            "asset_id": "111",
            "market": "0xabc",
            "bids": [{"price": "0.48", "size": "30"}],
            "asks": [{"price": "0.52", "size": "10.5"}],
            "timestamp": "1751300000123",
            "hash": "deadbeef"
        }"#;
        let event = parse_market_event(text).unwrap();
        let MarketEvent::Book {
            asset_id,
            bids,
            asks,
            timestamp,
        } = &event
        else {
            panic!("expected Book");
        };
        assert_eq!(*asset_id, "111");
        assert_eq!(bids.len(), 1);
        assert_eq!(asks[0].price, "0.52");
        assert_eq!(*timestamp, Some("1751300000123"));

        let owned = event.to_owned_event().unwrap();
        let MarketEventOwned::Book {
            bids, timestamp, ..
        } = owned
        else {
            panic!("expected owned Book");
        };
        assert_eq!(bids[0].price, d("0.48"));
        assert_eq!(timestamp, Some(1_751_300_000_123));
    }

    #[test]
    fn parses_price_change_batch_and_maps_sides() {
        let text = r#"{
            "event_type": "price_change",
            "market": "0xabc",
            "price_changes": [
                {"asset_id": "111", "price": "0.49", "size": "25", "side": "BUY",
                 "best_bid": "0.49", "best_ask": "0.52"},
                {"asset_id": "111", "price": "0.53", "size": "0", "side": "SELL",
                 "best_bid": "0.49", "best_ask": ""}
            ],
            "timestamp": "1751300000123"
        }"#;
        let event = parse_market_event(text).unwrap();
        let MarketEvent::PriceChange { price_changes, .. } = &event else {
            panic!("expected PriceChange");
        };
        assert_eq!(price_changes.len(), 2);
        assert_eq!(price_changes[0].book_side(), Some(BookSide::Bid));
        assert_eq!(price_changes[1].book_side(), Some(BookSide::Ask));

        let owned = event.to_owned_event().unwrap();
        let MarketEventOwned::PriceChange { price_changes, .. } = owned else {
            panic!("expected owned PriceChange");
        };
        // A "0" size delta means level removal; empty best_ask degrades to None.
        assert_eq!(price_changes[1].size, Decimal::ZERO);
        assert_eq!(price_changes[1].best_ask, None);
        assert_eq!(price_changes[0].best_bid, Some(d("0.49")));
    }

    #[test]
    fn parses_quarter_cent_tick_change() {
        let text = r#"{"event_type": "tick_size_change", "asset_id": "111",
                       "old_tick_size": "0.01", "new_tick_size": "0.0025"}"#;
        let owned = parse_market_event(text).unwrap().to_owned_event().unwrap();
        assert_eq!(
            owned,
            MarketEventOwned::TickSizeChange {
                asset_id: "111".to_owned(),
                new_tick_size: d("0.0025"),
            }
        );
    }

    #[test]
    fn parses_last_trade_price_with_optional_fields_missing() {
        let text = r#"{"event_type": "last_trade_price", "asset_id": "111", "price": "0.57"}"#;
        let owned = parse_market_event(text).unwrap().to_owned_event().unwrap();
        let MarketEventOwned::LastTradePrice {
            price, size, side, ..
        } = owned
        else {
            panic!("expected LastTradePrice");
        };
        assert_eq!(price, d("0.57"));
        assert!(size.is_none() && side.is_none());
    }

    #[test]
    fn unknown_event_kind_degrades_not_fails() {
        let text = r#"{"event_type": "brand_new_thing", "payload": {"x": 1}}"#;
        assert!(matches!(
            parse_market_event(text).unwrap(),
            MarketEvent::Unknown
        ));
    }

    #[test]
    fn book_events_feed_the_book_state() {
        // End-to-end shape check: WS frames drive crate::book::Book.
        let mut book = crate::book::Book::default();
        let snapshot = r#"{
            "event_type": "book", "asset_id": "111",
            "bids": [{"price": "0.48", "size": "30"}],
            "asks": [{"price": "0.52", "size": "10"}]
        }"#;
        if let MarketEventOwned::Book { bids, asks, .. } = parse_market_event(snapshot)
            .unwrap()
            .to_owned_event()
            .unwrap()
        {
            book.apply_snapshot(
                bids.into_iter().map(|l| (l.price, l.size)),
                asks.into_iter().map(|l| (l.price, l.size)),
            );
        }
        assert_eq!(book.asks.len(), 1);

        let delta = r#"{
            "event_type": "price_change", "market": "0xabc",
            "price_changes": [{"asset_id": "111", "price": "0.52", "size": "0",
                               "side": "SELL", "best_bid": "0.48", "best_ask": ""}]
        }"#;
        if let MarketEventOwned::PriceChange { price_changes, .. } =
            parse_market_event(delta).unwrap().to_owned_event().unwrap()
        {
            for entry in price_changes {
                let side = entry.book_side().unwrap();
                book.apply_delta(side, entry.price, entry.size);
            }
        }
        assert!(book.asks.is_empty(), "the SELL delta removed the ask level");
    }
}
