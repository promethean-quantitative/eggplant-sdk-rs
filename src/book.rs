//! Order-book depth state.
//!
//! [`Book`] reconstructs one token's full ladder from a snapshot (a `book`
//! WS event or a REST seed) and keeps it live under incremental
//! `price_change` deltas. The snapshot/delta application — and its
//! idempotency across an N-way WS connection fan-out — lives here, in one
//! tested place.

use std::collections::BTreeMap;

use rust_decimal::Decimal;

/// Which side of the book a `price_change` delta touches: a `BUY` tick
/// updates the bid ladder, a `SELL` tick the ask ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BookSide {
    Bid,
    Ask,
}

/// Full order book for one token: every live price level on each side,
/// `price -> size`.
///
/// `BTreeMap` keeps levels price-sorted, so the best ask is the first
/// (lowest) key and the best bid is the last (highest) key.
#[derive(Default)]
pub struct Book {
    pub bids: BTreeMap<Decimal, Decimal>,
    pub asks: BTreeMap<Decimal, Decimal>,
}

impl Book {
    /// Replace both ladders from a full snapshot (a `book` event or REST
    /// seed). Zero-size levels are dropped — a level only exists while it has
    /// resting size.
    pub fn apply_snapshot(
        &mut self,
        bids: impl IntoIterator<Item = (Decimal, Decimal)>,
        asks: impl IntoIterator<Item = (Decimal, Decimal)>,
    ) {
        self.bids.clear();
        self.asks.clear();
        for (price, size) in bids {
            if !size.is_zero() {
                self.bids.insert(price, size);
            }
        }
        for (price, size) in asks {
            if !size.is_zero() {
                self.asks.insert(price, size);
            }
        }
    }

    /// Apply one incremental level change from a `price_change`. `size` is
    /// the new absolute size at `price`; `size == 0` removes the level.
    /// Idempotent: replaying the same delta (e.g. the same tick arriving on
    /// another fan-out connection) is a no-op, so the reconstructed book
    /// converges regardless of duplication.
    ///
    /// Returns `true` if the ladder actually changed (so an idempotent
    /// re-delivery returns `false`), letting callers drive work off a genuine
    /// depth change.
    #[allow(clippy::similar_names)] // `side` / `size` are the domain field names
    pub fn apply_delta(&mut self, side: BookSide, price: Decimal, size: Decimal) -> bool {
        let levels = match side {
            BookSide::Bid => &mut self.bids,
            BookSide::Ask => &mut self.asks,
        };
        if size.is_zero() {
            levels.remove(&price).is_some()
        } else {
            levels.insert(price, size) != Some(size)
        }
    }

    /// The ask price at which cumulative ladder depth first covers `need`
    /// shares — the marginal level a taker BUY of that size must reach.
    /// Limit-pricing a large order off the touch alone underprices it (the
    /// touch may hold a fraction of the size); pricing off this level lets
    /// the whole order cross. When the ladder holds less than `need` in
    /// total, returns the deepest level (the best truth the book offers);
    /// `None` only on an empty ladder.
    pub fn ask_price_for_size(&self, need: Decimal) -> Option<Decimal> {
        let mut cum = Decimal::ZERO;
        let mut last = None;
        for (&price, &size) in &self.asks {
            cum += size;
            last = Some(price);
            if cum >= need {
                break;
            }
        }
        last
    }

    /// Cumulative ask depth at every level priced at or below `max_price` —
    /// the size a taker BUY fills without paying past `max_price`. The
    /// inverse companion to [`Self::ask_price_for_size`] (size for a price
    /// ceiling, vs. price for a size), summing the same best-ask-first ladder
    /// so the two stay consistent. `0` when the touch already sits above
    /// `max_price` (nothing fillable that cheap) or the ladder is empty.
    #[must_use]
    pub fn ask_depth_up_to(&self, max_price: Decimal) -> Decimal {
        self.asks.range(..=max_price).map(|(_, &size)| size).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Decimal {
        s.parse().expect("test literal")
    }

    fn ladder(levels: &[(&str, &str)]) -> Book {
        let mut book = Book::default();
        book.apply_snapshot(
            std::iter::empty(),
            levels.iter().map(|&(p, s)| (d(p), d(s))),
        );
        book
    }

    #[test]
    fn ask_price_for_size_walks_to_covering_level() {
        // 30 at the touch, 50 behind, 100 deep: a 100-share taker must reach 0.13.
        let book = ladder(&[("0.11", "30"), ("0.12", "50"), ("0.13", "100")]);
        assert_eq!(book.ask_price_for_size(d("100")), Some(d("0.13")));
        // The touch alone covers a small order.
        assert_eq!(book.ask_price_for_size(d("30")), Some(d("0.11")));
        // Boundary: exactly the first two levels.
        assert_eq!(book.ask_price_for_size(d("80")), Some(d("0.12")));
    }

    #[test]
    fn ask_price_for_size_exhausted_ladder_returns_deepest() {
        let book = ladder(&[("0.11", "30"), ("0.12", "50")]);
        assert_eq!(book.ask_price_for_size(d("500")), Some(d("0.12")));
    }

    #[test]
    fn ask_price_for_size_empty_ladder_is_none() {
        let book = Book::default();
        assert_eq!(book.ask_price_for_size(d("10")), None);
    }

    #[test]
    fn ask_depth_up_to_sums_levels_within_ceiling() {
        let book = ladder(&[("0.11", "30"), ("0.12", "50"), ("0.13", "100")]);
        // Touch only.
        assert_eq!(book.ask_depth_up_to(d("0.11")), d("30"));
        // First two levels (inclusive boundary).
        assert_eq!(book.ask_depth_up_to(d("0.12")), d("80"));
        // A ceiling between levels takes everything at or below it, nothing above.
        assert_eq!(book.ask_depth_up_to(d("0.125")), d("80"));
        // Whole ladder.
        assert_eq!(book.ask_depth_up_to(d("0.13")), d("180"));
        // Below the touch: nothing fillable that cheap.
        assert_eq!(book.ask_depth_up_to(d("0.10")), Decimal::ZERO);
        // Empty ladder.
        assert_eq!(Book::default().ask_depth_up_to(d("0.50")), Decimal::ZERO);
    }

    #[test]
    fn apply_delta_is_idempotent_and_reports_change() {
        let mut book = Book::default();
        assert!(book.apply_delta(BookSide::Ask, d("0.11"), d("30")));
        // Same delta again (fan-out re-delivery): no change.
        assert!(!book.apply_delta(BookSide::Ask, d("0.11"), d("30")));
        // Size change at the level: change.
        assert!(book.apply_delta(BookSide::Ask, d("0.11"), d("40")));
        // Zero size removes; removing again is a no-op.
        assert!(book.apply_delta(BookSide::Ask, d("0.11"), Decimal::ZERO));
        assert!(!book.apply_delta(BookSide::Ask, d("0.11"), Decimal::ZERO));
        assert!(book.asks.is_empty());
    }

    #[test]
    fn snapshot_drops_zero_size_levels() {
        let mut book = Book::default();
        book.apply_snapshot(
            [(d("0.5"), d("10")), (d("0.4"), Decimal::ZERO)],
            [(d("0.6"), Decimal::ZERO), (d("0.7"), d("5"))],
        );
        assert_eq!(book.bids.len(), 1);
        assert_eq!(book.asks.len(), 1);
    }
}
