//! Multi-connection reader plumbing, proven in production: staggered recycle
//! phasing, maker-side classification, and bounded first-delivery dedup.
//!
//! A recycle is a *scheduled* clean close + immediate reconnect. Half-open
//! sockets (NAT drops, server stalls) are caught separately by each reader's
//! PONG liveness deadline; recycling bounds the age of every connection so
//! subtler degradation (silent subscription loss, a stale LB path) can't
//! accumulate. Offsets are phased so that redundant peers never refresh
//! together — one always stays subscribed to cover the brief gap, which is
//! why recycling disables itself without a peer.

use std::collections::{HashSet, VecDeque};
use std::time::Duration;

use crate::clob::types::Side;

/// How a single connection's read loop ended.
///
/// A scheduled [`Recycle`](Self::Recycle) reconnects immediately (a staggered
/// peer covers the brief gap); a clean [`Disconnected`](Self::Disconnected)
/// backs off like the error path.
pub enum ReaderExit {
    Disconnected,
    Recycle,
}

/// Phase offset for connection `conn_id`'s recycle timer, or `None` when
/// recycling is off.
///
/// Off means `interval_secs == 0`, or fewer than two connections — a lone
/// connection has no peer to cover the refresh gap and relies on the
/// reader's PONG liveness deadline instead.
///
/// The N connections recycle at phases `1/N, 2/N, … N/N` of the period, so
/// they are evenly spread and none fires at boot (phase `0`).
#[must_use]
pub fn recycle_offset(conn_id: u8, connections: u8, interval_secs: u64) -> Option<Duration> {
    if interval_secs == 0 || connections < 2 {
        return None;
    }
    let period = Duration::from_secs(interval_secs);
    Some(period * (u32::from(conn_id) + 1) / u32::from(connections))
}

/// Phase offset for the recycle timer of shard `shard_id`'s redundant copy
/// `copy`, or `None` when recycling is off.
///
/// Mirrors [`recycle_offset`], but phases by a slot ordered *copy-major,
/// shard-minor* (`copy * num_shards + shard_id`) over all
/// `num_shards * redundancy` connections: every connection lands on a
/// distinct, evenly spread phase, and a shard's redundant copies sit exactly
/// `period / redundancy` apart, so one is always fully reconnected before
/// its peer recycles. `redundancy < 2` ⇒ `None` (a lone copy has no
/// same-shard peer to cover the refresh gap); `interval_secs == 0` ⇒ `None`
/// too. Fan-outs beyond `u8::MAX` total connections also disable recycling.
#[must_use]
pub fn market_recycle_offset(
    shard_id: usize,
    copy: usize,
    num_shards: usize,
    redundancy: usize,
    interval_secs: u64,
) -> Option<Duration> {
    if redundancy < 2 {
        return None;
    }
    let total = u8::try_from(num_shards * redundancy).ok()?;
    let slot = u8::try_from(copy * num_shards + shard_id).ok()?;
    recycle_offset(slot, total, interval_secs)
}

/// Build a connection's recycle timer: first tick at `offset`, then every
/// `period_secs`.
///
/// Build it once per connection (not per reconnect attempt) so the staggered
/// phase stays anchored across reconnects; `Skip` keeps the phase grid after
/// a tick is missed during a backoff instead of bursting a catch-up recycle
/// onto the fresh connection.
#[must_use]
pub fn recycle_interval(offset: Duration, period_secs: u64) -> tokio::time::Interval {
    let mut iv = tokio::time::interval_at(
        tokio::time::Instant::now() + offset,
        Duration::from_secs(period_secs),
    );
    iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    iv
}

/// Flip a known side; pass other variants (e.g. `Unknown`) through untouched.
const fn opposite(side: Side) -> Side {
    match side {
        Side::Buy => Side::Sell,
        Side::Sell => Side::Buy,
        other => other,
    }
}

/// Our side as the *maker* of a user-channel trade, derived from the taker
/// side and the two outcomes.
///
/// The trade's top-level `side`/`outcome` describe the taker; a maker order
/// carries its own `outcome` but no side. Because YES+NO prices sum to 1
/// ("buy YES" == "sell NO"): a *matching* outcome means we took the opposite
/// side of the same token; a *differing* outcome means we are on the taker's
/// side in the complementary token. Returns `None` when the side or outcome
/// is unknown.
///
/// This is how two processes sharing one API key stay out of each other's
/// way: the user channel delivers every fill on the key to both, and each
/// filters by its own side (a buyer drops provable `Sell`s, a seller drops
/// provable `Buy`s).
#[must_use]
pub fn our_maker_side(
    taker_side: Side,
    taker_outcome: Option<&str>,
    maker_outcome: &str,
) -> Option<Side> {
    let taker_outcome = taker_outcome?;
    match taker_side {
        Side::Buy | Side::Sell => {
            let same = maker_outcome.eq_ignore_ascii_case(taker_outcome);
            Some(if same {
                opposite(taker_side)
            } else {
                taker_side
            })
        }
        _ => None,
    }
}

/// Bounded FIFO set of ids already handled.
///
/// Share one across redundant user-channel connections so the first to
/// deliver a given trade wins and the rest drop it; keep it for the process
/// lifetime so reconnects don't replay old fills.
pub struct SeenIds {
    set: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl SeenIds {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            set: HashSet::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }

    /// Record `id`. Returns `true` if it was newly seen (handle it), `false`
    /// if already present (duplicate — drop it). At capacity the oldest id
    /// is evicted FIFO.
    pub fn insert(&mut self, id: String) -> bool {
        if !self.set.insert(id.clone()) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.cap
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }

    /// Whether `id` has been seen (without recording it).
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        SeenIds, Side, market_recycle_offset, our_maker_side, recycle_interval, recycle_offset,
    };

    #[test]
    fn recycle_off_when_disabled_or_single_connection() {
        // interval 0 ⇒ off.
        assert_eq!(recycle_offset(0, 2, 0), None);
        // a lone connection has no peer to cover the gap ⇒ off (relies on PONG).
        assert_eq!(recycle_offset(0, 1, 300), None);
    }

    #[test]
    fn recycle_offsets_evenly_phased_and_never_at_boot() {
        // Four connections over a 300s period recycle at 75/150/225/300s:
        // evenly spaced by period/N, all in (0, period], so two never refresh
        // at once and none fires at startup (phase 0).
        let offsets: Vec<Duration> = (0_u8..4)
            .map(|k| recycle_offset(k, 4, 300).expect("enabled"))
            .collect();
        assert_eq!(
            offsets,
            vec![
                Duration::from_secs(75),
                Duration::from_secs(150),
                Duration::from_secs(225),
                Duration::from_secs(300),
            ]
        );
        assert!(offsets.iter().all(|o| *o > Duration::ZERO));
        for w in offsets.windows(2) {
            assert_eq!(w[1], w[0] + Duration::from_secs(75));
        }
    }

    #[test]
    fn market_recycle_off_without_same_shard_peer() {
        // A shard with a single copy has no peer to cover the refresh gap ⇒ off.
        assert_eq!(market_recycle_offset(0, 0, 4, 1, 300), None);
        // interval 0 ⇒ off too (delegated to `recycle_offset`).
        assert_eq!(market_recycle_offset(0, 0, 4, 2, 0), None);
    }

    #[test]
    fn market_recycle_copies_of_a_shard_are_period_over_redundancy_apart() {
        // 3 shards × 2 copies over 300s: a shard's two copies must sit
        // period/redundancy = 150s apart so one is fully reconnected before
        // its peer recycles.
        for shard in 0..3_usize {
            let c0 = market_recycle_offset(shard, 0, 3, 2, 300).expect("enabled");
            let c1 = market_recycle_offset(shard, 1, 3, 2, 300).expect("enabled");
            assert_eq!(c1.checked_sub(c0).unwrap(), Duration::from_secs(150));
        }
    }

    #[test]
    fn market_recycle_phases_distinct_and_evenly_spread() {
        // Every connection lands on a distinct phase in (0, period], evenly
        // spaced by period/total, so no two recycle together and none fires
        // at boot.
        let (num_shards, redundancy, period) = (3_usize, 2_usize, 300_u64);
        let total = num_shards * redundancy;
        let mut offsets: Vec<Duration> = Vec::new();
        for copy in 0..redundancy {
            for shard in 0..num_shards {
                offsets.push(
                    market_recycle_offset(shard, copy, num_shards, redundancy, period)
                        .expect("enabled"),
                );
            }
        }
        offsets.sort_unstable();
        let mut distinct = offsets.clone();
        distinct.dedup();
        assert_eq!(distinct.len(), total, "all phases distinct");
        assert!(
            offsets.iter().all(|o| *o > Duration::ZERO),
            "none fires at boot",
        );
        let step = Duration::from_secs(period) / u32::try_from(total).unwrap();
        let mut expected = step;
        for o in &offsets {
            assert_eq!(*o, expected, "evenly spaced by period/total");
            expected += step;
        }
    }

    #[tokio::test]
    async fn recycle_interval_anchors_period_and_skips_missed_ticks() {
        let iv = recycle_interval(Duration::from_secs(7), 300);
        assert_eq!(iv.period(), Duration::from_secs(300));
        assert_eq!(
            iv.missed_tick_behavior(),
            tokio::time::MissedTickBehavior::Skip
        );
    }

    #[test]
    fn our_maker_side_truth_table() {
        // Resting BUY NO — both taker fill mechanics (mint / direct) ⇒ Buy.
        assert_eq!(
            our_maker_side(Side::Buy, Some("YES"), "NO"),
            Some(Side::Buy)
        );
        assert_eq!(
            our_maker_side(Side::Sell, Some("NO"), "NO"),
            Some(Side::Buy)
        );

        // Resting SELL NO ⇒ Sell, in both complementary representations.
        assert_eq!(
            our_maker_side(Side::Sell, Some("YES"), "NO"),
            Some(Side::Sell)
        );
        assert_eq!(
            our_maker_side(Side::Buy, Some("NO"), "NO"),
            Some(Side::Sell)
        );

        // Resting SELL YES ⇒ Sell, in both complementary representations.
        assert_eq!(
            our_maker_side(Side::Buy, Some("YES"), "YES"),
            Some(Side::Sell)
        );
        assert_eq!(
            our_maker_side(Side::Sell, Some("NO"), "YES"),
            Some(Side::Sell)
        );

        // Indeterminate ⇒ None (callers decide their conservative default).
        assert_eq!(our_maker_side(Side::Unknown, Some("YES"), "NO"), None);
        assert_eq!(our_maker_side(Side::Buy, None, "NO"), None);

        // Outcome comparison is case-insensitive (guards an inversion hazard).
        assert_eq!(
            our_maker_side(Side::Buy, Some("No"), "no"),
            Some(Side::Sell)
        );
        assert_eq!(
            our_maker_side(Side::Buy, Some("Yes"), "No"),
            Some(Side::Buy)
        );
    }

    #[test]
    fn dedup_drops_repeats_and_evicts_oldest() {
        let mut seen = SeenIds::new(2);
        assert!(seen.insert("a".to_owned()), "first sighting is new");
        assert!(!seen.insert("a".to_owned()), "repeat is a duplicate");
        assert!(seen.insert("b".to_owned()));
        // Inserting a third distinct id evicts the oldest ("a").
        assert!(seen.insert("c".to_owned()));
        assert!(!seen.contains("a"));
        assert!(
            seen.insert("a".to_owned()),
            "evicted id is treated as new again"
        );
    }
}
