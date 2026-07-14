//! Merge/convert **safety net**: systematically settle every negRisk position
//! a wallet holds, not just the one event a caller just traded.
//!
//! Where the [`convert`](crate::convert) worker converts a single event right
//! after a fill, `sweep` discovers the wallet's *actual* holdings and runs the
//! same cycle over all of them — mopping up orphans a normal flow can leave
//! behind: a convert that errored or was quota-throttled, a partial fill, a
//! crash mid-cycle. It is purely additive and idempotent: safe to run by hand
//! or on a cron.
//!
//! How it discovers work (no persisted event file needed):
//!
//! 1. [`DataApiClient::all_positions`](crate::data::DataApiClient::all_positions)
//!    lists the wallet's open positions.
//! 2. Each distinct **negRisk** event those positions belong to is resolved to
//!    its full leg set from Gamma
//!    ([`GammaClient::fetch_events_by_slug`](crate::gamma::GammaClient::fetch_events_by_slug)).
//!    Gamma is needed because convert requires each leg's `question_id`, which
//!    the Data API doesn't carry. A slug Gamma can't resolve is skipped
//!    (best-effort), not fatal.
//! 3. Each event is classified **from the Data API sizes alone** — no on-chain
//!    reads in the scan: a leg holding YES+NO is mergeable; leftover NO is
//!    convertible (a lone NO leg only past the single-leg dust floor, since
//!    converting it alone frees 0 USDC).
//!
//! The scan's amounts are approximate (the API's `size` is a float); the
//! **authoritative** merge/convert amounts come from on-chain balances at
//! execute time, which [`process_job`](crate::convert::process_job) re-reads.
//!
//! Layers mirror [`crate::convert`]: the pure classification
//! ([`leg_sizes`], [`classify_event`]) is always available; the discovery +
//! execution engine ([`plan_sweep`], [`sweep_all`]) needs the `rpc` feature.

use std::collections::HashMap;

use alloy::primitives::U256;

use crate::convert::ConvertLeg;
use crate::data::Position;

/// Merge/convert classification for one event, derived from Data API sizes.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct EventClassification {
    /// Legs holding both YES and NO (and a condition id) — mergeable pairs.
    pub merge_pairs: usize,
    /// Total shares recoverable by merging those pairs (`Σ min(yes, no)`).
    pub merge_shares: f64,
    /// Legs holding leftover NO after netting out any merge — convert inputs.
    pub convert_legs: usize,
    /// Smallest leftover-NO across the convert legs (`0.0` when none).
    pub convert_min_no: f64,
    /// Any mergeable pair present.
    pub mergeable: bool,
    /// A convert frees USDC: ≥ 2 leftover-NO legs, or a lone one above the
    /// single-leg dust floor.
    pub convertible: bool,
}

impl EventClassification {
    /// Whether this event has any merge or convert work worth submitting.
    #[must_use]
    pub const fn actionable(&self) -> bool {
        self.mergeable || self.convertible
    }
}

/// Sum the wallet's per-leg `(no_shares, yes_shares)` for an event's legs from
/// Data API positions.
///
/// Maps each position's token id back to its leg and side. Legs the wallet
/// doesn't hold read as `(0.0, 0.0)`; the result is always `legs.len()` long,
/// in leg order.
#[must_use]
pub fn leg_sizes(legs: &[ConvertLeg], positions: &[Position]) -> Vec<(f64, f64)> {
    // token id -> (leg index, is_no)
    let mut by_token: HashMap<U256, (usize, bool)> = HashMap::with_capacity(legs.len() * 2);
    for (i, leg) in legs.iter().enumerate() {
        by_token.insert(leg.no_token_id, (i, true));
        if let Some(y) = leg.yes_token_id {
            by_token.insert(y, (i, false));
        }
    }

    let mut sizes = vec![(0.0_f64, 0.0_f64); legs.len()];
    for p in positions {
        let Ok(tid) = p.asset.parse::<U256>() else {
            continue;
        };
        if let Some(&(i, is_no)) = by_token.get(&tid) {
            if is_no {
                sizes[i].0 += p.size;
            } else {
                sizes[i].1 += p.size;
            }
        }
    }
    sizes
}

/// Classify one event's held sizes into merge/convert work.
///
/// `sizes[i]` is leg `i`'s `(no_shares, yes_shares)` (see [`leg_sizes`]);
/// `single_leg_min_qty` is the leftover-NO floor (in shares) below which a
/// *lone* convertible leg is left alone (converting it alone frees 0 USDC, so
/// it isn't worth the gas). Multi-leg converts ignore the floor.
#[must_use]
pub fn classify_event(
    legs: &[ConvertLeg],
    sizes: &[(f64, f64)],
    single_leg_min_qty: f64,
) -> EventClassification {
    let mut merge_pairs = 0_usize;
    let mut merge_shares = 0.0_f64;
    let mut convert_legs = 0_usize;
    let mut min_no = f64::INFINITY;

    for (leg, &(no, yes)) in legs.iter().zip(sizes) {
        if no > 0.0 && yes > 0.0 && leg.condition_id.is_some() {
            merge_pairs += 1;
            merge_shares += no.min(yes);
        }
        let remaining_no = no - no.min(yes);
        if remaining_no > 0.0 {
            convert_legs += 1;
            min_no = min_no.min(remaining_no);
        }
    }

    let mergeable = merge_pairs > 0;
    let convertible =
        convert_legs > 1 || (convert_legs == 1 && min_no >= single_leg_min_qty);

    EventClassification {
        merge_pairs,
        merge_shares,
        convert_legs,
        convert_min_no: if min_no.is_finite() { min_no } else { 0.0 },
        mergeable,
        convertible,
    }
}

// ---------------------------------------------------------------------------
// Discovery + execution engine (`rpc` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "rpc")]
pub use engine::{HeldEvent, SweepOptions, SweepReport, SweepSummary, plan_sweep, sweep_all};

#[cfg(feature = "rpc")]
mod engine {
    use std::time::Instant;

    use alloy::primitives::Address;
    use alloy::signers::Signer;
    use futures::stream::StreamExt as _;

    use super::{EventClassification, classify_event, leg_sizes};
    use crate::convert::{ConvertDelays, ConvertJob, ConvertLeg, convert_legs, process_job};
    use crate::data::{DataApiClient, Position};
    use crate::gamma::{GammaClient, GammaMarket};
    use crate::error::Error;
    use crate::relayer::RelayerClient;

    /// A held negRisk event resolved to its full leg set (from Gamma).
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct HeldEvent {
        pub slug: String,
        pub title: String,
        pub legs: Vec<ConvertLeg>,
    }

    /// One held event's classification, tagged with its slug and title for
    /// reporting.
    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct SweepReport {
        pub slug: String,
        pub title: String,
        pub class: EventClassification,
    }

    /// Knobs for [`sweep_all`] / [`plan_sweep`]. [`Default`] is a workable
    /// starting point; build with `SweepOptions { ..Default::default() }`.
    #[derive(Debug, Clone)]
    pub struct SweepOptions {
        /// Data API size floor for discovery (shares; `0.0` = everything).
        pub min_shares: f64,
        /// Restrict the sweep to a single event slug (`None` = every held
        /// negRisk event).
        pub only_slug: Option<String>,
        /// Merge/convert cycle tuning — settle waits, gas budget, and the
        /// single-leg dust floor (whose raw form is the authoritative guard
        /// inside [`process_job`](crate::convert::process_job)).
        pub delays: ConvertDelays,
        /// Max concurrent Gamma event resolutions during discovery.
        pub gamma_concurrency: usize,
    }

    impl Default for SweepOptions {
        fn default() -> Self {
            Self {
                min_shares: 0.0,
                only_slug: None,
                delays: ConvertDelays::default(),
                gamma_concurrency: 8,
            }
        }
    }

    /// What [`sweep_all`] did.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    #[non_exhaustive]
    pub struct SweepSummary {
        /// Distinct held negRisk events discovered.
        pub held_events: usize,
        /// Events with actionable merge/convert work.
        pub actionable: usize,
        /// Events whose cycle submitted successfully.
        pub executed: usize,
        /// Events whose cycle failed.
        pub failed: usize,
    }

    /// The single-leg dust floor in shares (f64), from the raw 6-dp form the
    /// authoritative on-chain guard uses.
    #[allow(
        clippy::cast_precision_loss,
        reason = "a dust floor in shares; f64 rounding at that magnitude is immaterial"
    )]
    fn single_leg_min_qty(delays: &ConvertDelays) -> f64 {
        let raw = u128::try_from(delays.single_leg_min_qty_raw).unwrap_or(u128::MAX);
        raw as f64 / 1_000_000.0
    }

    /// Resolve one held event slug to its full leg set via Gamma.
    ///
    /// Best-effort: a Gamma error (rate-limit, transient) or an event that is
    /// non-negRisk / single-leg yields `None` and is skipped, never fatal.
    async fn resolve_event(gamma: &GammaClient, slug: &str) -> Option<HeldEvent> {
        let events = match gamma.fetch_events_by_slug(slug).await {
            Ok(events) => events,
            Err(e) => {
                tracing::warn!(%slug, error = %e, "sweep: Gamma resolve failed, skipping event");
                return None;
            }
        };
        let event = events
            .iter()
            .find(|e| e.slug == slug)
            .or_else(|| events.first())?;
        if !event.neg_risk {
            return None;
        }
        let markets = event.markets.as_deref().unwrap_or_default();
        let legs = convert_legs(markets.iter().filter_map(GammaMarket::market_ids));
        // negRisk convert/merge needs 2+ legs (the same gate the bot uses).
        if legs.len() < 2 {
            return None;
        }
        Some(HeldEvent {
            slug: event.slug.clone(),
            title: event.title.clone(),
            legs,
        })
    }

    /// Fetch positions and resolve the distinct held negRisk events to their
    /// full leg sets (bounded-concurrency Gamma lookups, order preserved).
    async fn discover(
        data: &DataApiClient,
        gamma: &GammaClient,
        wallet: Address,
        opts: &SweepOptions,
    ) -> Result<(Vec<Position>, Vec<HeldEvent>), Error> {
        let positions = data
            .all_positions(&wallet.to_string(), opts.min_shares)
            .await?;

        // Distinct negRisk event slugs, first-seen order preserved.
        let mut seen = std::collections::HashSet::new();
        let slugs: Vec<String> = positions
            .iter()
            .filter(|p| p.negative_risk && !p.event_slug.is_empty())
            .filter(|p| opts.only_slug.as_ref().is_none_or(|s| s == &p.event_slug))
            .filter(|p| seen.insert(p.event_slug.clone()))
            .map(|p| p.event_slug.clone())
            .collect();

        let events: Vec<HeldEvent> = futures::stream::iter(slugs)
            .map(|slug| async move { resolve_event(gamma, &slug).await })
            .buffered(opts.gamma_concurrency.max(1))
            .filter_map(|maybe| async move { maybe })
            .collect()
            .await;

        Ok((positions, events))
    }

    /// Classify every held event from the discovered positions.
    fn classify(
        events: &[HeldEvent],
        positions: &[Position],
        delays: &ConvertDelays,
    ) -> Vec<SweepReport> {
        let floor = single_leg_min_qty(delays);
        events
            .iter()
            .map(|he| {
                let sizes = leg_sizes(&he.legs, positions);
                SweepReport {
                    slug: he.slug.clone(),
                    title: he.title.clone(),
                    class: classify_event(&he.legs, &sizes, floor),
                }
            })
            .collect()
    }

    /// Discover the wallet's held negRisk events and report the merge/convert
    /// work each has — **submits nothing** (a dry run).
    ///
    /// Classification is from Data API sizes, so amounts are approximate; the
    /// authoritative amounts come from on-chain balances at [`sweep_all`] time.
    pub async fn plan_sweep(
        data: &DataApiClient,
        gamma: &GammaClient,
        wallet: Address,
        opts: &SweepOptions,
    ) -> Result<Vec<SweepReport>, Error> {
        let (positions, events) = discover(data, gamma, wallet, opts).await?;
        Ok(classify(&events, &positions, &opts.delays))
    }

    /// Settle every actionable held negRisk event: merge YES+NO pairs and
    /// convert leftover NO, one event at a time.
    ///
    /// Discovers holdings, classifies them, and runs
    /// [`process_job`](crate::convert::process_job) over each actionable event
    /// **sequentially** — the wallet runs one relayer action at a time, and
    /// `process_job` re-reads on-chain balances at action time (so the API-size
    /// scan only decides *which* events to touch, never the amounts).
    /// Idempotent and resumable: a re-run simply finds less to do.
    ///
    /// Assumes the wallet's approvals are already in place — the collateral
    /// adapter must be an ERC-1155 operator for it (see [`crate::approval`]).
    pub async fn sweep_all<S: Signer + Sync>(
        signer: &S,
        relayer: &RelayerClient,
        data: &DataApiClient,
        gamma: &GammaClient,
        rpc_url: &str,
        wallet: Address,
        opts: &SweepOptions,
    ) -> Result<SweepSummary, Error> {
        let (positions, events) = discover(data, gamma, wallet, opts).await?;
        let reports = classify(&events, &positions, &opts.delays);

        let mut summary = SweepSummary {
            held_events: events.len(),
            ..SweepSummary::default()
        };

        for (he, report) in events.into_iter().zip(&reports) {
            if !report.class.actionable() {
                continue;
            }
            summary.actionable += 1;
            let job = ConvertJob {
                slug: he.slug,
                legs: he.legs,
                amount_raw: alloy::primitives::U256::ZERO,
                attempts: 0,
                queued_at: Instant::now(),
            };
            match process_job(&job, signer, relayer, rpc_url, wallet, opts.delays).await {
                Ok(detail) => {
                    tracing::info!(slug = %job.slug, %detail, "sweep event settled");
                    summary.executed += 1;
                }
                Err(e) => {
                    tracing::warn!(slug = %job.slug, error = %e, "sweep event failed");
                    summary.failed += 1;
                }
            }
        }

        Ok(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;

    /// Test leg: NO token id `2000 + n`, YES token id `1000 + n` when `yes`,
    /// condition id tagged with `n` when `cond`.
    fn leg(n: u8, yes: bool, cond: bool) -> ConvertLeg {
        let mut qid = [0_u8; 32];
        qid[0] = n;
        let mut cid = [0_u8; 32];
        cid[1] = n;
        ConvertLeg {
            question_id: B256::from(qid),
            condition_id: cond.then(|| B256::from(cid)),
            yes_token_id: yes.then(|| U256::from(1000_u64 + u64::from(n))),
            no_token_id: U256::from(2000_u64 + u64::from(n)),
        }
    }

    fn pos(token: u64, size: f64) -> Position {
        Position {
            asset: token.to_string(),
            size,
            condition_id: String::new(),
            event_slug: String::new(),
            title: String::new(),
            outcome: String::new(),
            negative_risk: true,
            redeemable: false,
        }
    }

    #[test]
    #[allow(clippy::float_cmp, reason = "sizes are exact small literals")]
    fn leg_sizes_maps_tokens_to_legs_and_sides() {
        let legs = [leg(1, true, true), leg(2, false, true)];
        // leg1: NO=2001 (held 10), YES=1001 (held 4); leg2: NO=2002 (held 7).
        let positions = [pos(2001, 10.0), pos(1001, 4.0), pos(2002, 7.0), pos(9999, 5.0)];
        let sizes = leg_sizes(&legs, &positions);
        assert_eq!(sizes, vec![(10.0, 4.0), (7.0, 0.0)]);
    }

    #[test]
    fn classify_flags_merge_and_convert() {
        let legs = [leg(1, true, true), leg(2, false, true)];
        // leg1 holds YES+NO (mergeable, min=4); both legs have leftover NO.
        let sizes = [(10.0, 4.0), (7.0, 0.0)];
        let c = classify_event(&legs, &sizes, 0.1);
        assert_eq!(c.merge_pairs, 1);
        assert!((c.merge_shares - 4.0).abs() < 1e-9);
        // leftover NO: leg1 = 10-4 = 6, leg2 = 7 → 2 convert legs.
        assert_eq!(c.convert_legs, 2);
        assert!(c.mergeable && c.convertible && c.actionable());
    }

    #[test]
    fn lone_convert_leg_below_floor_is_not_convertible() {
        let legs = [leg(1, false, true), leg(2, false, true)];
        // Only leg1 holds NO (0.05 shares) → lone convert leg below the floor.
        let sizes = [(0.05, 0.0), (0.0, 0.0)];
        let c = classify_event(&legs, &sizes, 0.1);
        assert_eq!(c.convert_legs, 1);
        assert!(!c.convertible);
        assert!(!c.actionable());
        // The same lone leg above the floor is convertible.
        let c2 = classify_event(&legs, &[(5.0, 0.0), (0.0, 0.0)], 0.1);
        assert!(c2.convertible && c2.actionable());
    }

    #[test]
    fn merge_needs_a_condition_id() {
        // Holds YES+NO but no condition id ⇒ can't merge; the YES offsets NO,
        // leaving nothing convertible either.
        let legs = [leg(1, true, false)];
        let sizes = [(5.0, 5.0)];
        let c = classify_event(&legs, &sizes, 0.1);
        assert_eq!(c.merge_pairs, 0);
        assert_eq!(c.convert_legs, 0);
        assert!(!c.actionable());
    }
}
