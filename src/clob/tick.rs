//! Venue size rules and live tick-size state.
//!
//! Tick sizes are plain [`Decimal`]s throughout — deliberately **not** a
//! closed enum. The venue has added new grids without notice (0.0025
//! quarter-cent ticks landed mid-2026), and a closed enum turns that into a
//! parse failure on every book fetch. Price rails always derive as
//! `[tick, 1 − tick]`.

use std::collections::HashMap;
use std::str::FromStr as _;

use alloy::primitives::U256;
use rust_decimal::Decimal;

/// Order size used by connection warm-up pings (the venue minimum).
pub const FIXED_SIZE: Decimal = Decimal::from_parts(5, 0, 0, false, 0);

/// The venue's minimum order size in shares.
pub const MIN_SIZE: Decimal = Decimal::from_parts(5, 0, 0, false, 0);

/// The venue's minimum order notional in USDC. The venue accepts an order
/// that clears *either* [`MIN_SIZE`] or this notional.
pub const MIN_NOTIONAL: Decimal = Decimal::ONE;

/// Max decimal places the CLOB accepts in a BUY order's *taker* amount
/// (shares).
///
/// Order sizes must be truncated to this precision or the API rejects them
/// with "invalid amounts ... taker amount a max of 2 decimals". Sizes stepped
/// in [`SIZE_STEP`] (0.1) increments are already within it; only fractional
/// fills (e.g. a partial maker fill being hedged) need truncating down to
/// this scale.
pub const SIZE_DECIMALS: u32 = 2;

/// Granularity order sizes are floored to.
///
/// Finer than a whole share (so a thin book's odd-lot depth past the integer
/// isn't left on the table) yet coarser than [`SIZE_DECIMALS`], so every
/// quoted size stays within the CLOB's 2-decimal taker-amount limit.
pub const SIZE_STEP: Decimal = Decimal::from_parts(1, 0, 0, false, 1);

/// Floors a share size down to the nearest [`SIZE_STEP`] increment. Exact for
/// the terminating decimals these sizes are.
#[must_use]
pub fn floor_to_size_step(size: Decimal) -> Decimal {
    (size / SIZE_STEP).floor() * SIZE_STEP
}

/// Largest order size that:
/// - is a multiple of [`SIZE_STEP`] (floored toward zero) and at least
///   [`MIN_SIZE`],
/// - can be fully filled against the thinnest leg (`min_ask_size`),
/// - does not exceed `max_size`,
/// - does not deploy more than `max_cash_deploy` of summed leg cost, where
///   `cost_per_unit` is the per-unit summed best-ask cost (Σ ask).
///
/// `max_cash_deploy <= 0` disables the cash cap. Returns `None` when no
/// qualifying size reaches [`MIN_SIZE`].
pub fn compute_order_size(
    min_ask_size: Decimal,
    max_size: Decimal,
    max_cash_deploy: Decimal,
    cost_per_unit: Decimal,
) -> Option<Decimal> {
    let mut cap = min_ask_size.min(max_size);
    if max_cash_deploy > Decimal::ZERO && cost_per_unit > Decimal::ZERO {
        cap = cap.min(max_cash_deploy / cost_per_unit);
    }
    let stepped = floor_to_size_step(cap);
    (stepped >= MIN_SIZE).then_some(stepped)
}

/// One token's tick-derived price rails plus its id pre-parsed to [`U256`]
/// (so the signing path needs no per-order string parse).
#[derive(Debug, Clone, Copy)]
pub struct TickEntry {
    pub max_price: Decimal,
    pub min_price: Decimal,
    pub token_id_u256: U256,
}

impl TickEntry {
    #[must_use]
    pub fn new(tick_size: Decimal, token_id_u256: U256) -> Self {
        let max_price = Decimal::ONE - tick_size;
        Self {
            max_price,
            min_price: tick_size,
            token_id_u256,
        }
    }

    /// Re-grid to `new_tick`, preserving `token_id_u256`. Returns `None` when
    /// the tick is unchanged (idempotent re-delivery / no-op), mirroring
    /// [`TickSizeCache::update_tick`].
    #[must_use]
    pub fn retick(&self, new_tick: Decimal) -> Option<Self> {
        (self.min_price != new_tick).then(|| Self::new(new_tick, self.token_id_u256))
    }
}

/// Live tick-size state per token id, kept current under `tick_size_change`
/// WS events.
pub struct TickSizeCache {
    entries: HashMap<String, TickEntry>,
}

impl Default for TickSizeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TickSizeCache {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn insert(&mut self, token_id: String, tick_size: Decimal) {
        let u256 = U256::from_str(&token_id).unwrap_or(U256::ZERO);
        self.entries
            .insert(token_id, TickEntry::new(tick_size, u256));
    }

    /// Apply a live `tick_size_change`. Returns `Some((old_tick, new_tick))`
    /// when an existing entry actually changed, else `None` (unknown token,
    /// or idempotent re-delivery from a multi-connection fan-out). Preserves
    /// `token_id_u256`.
    pub fn update_tick(&mut self, token_id: &str, new_tick: Decimal) -> Option<(Decimal, Decimal)> {
        let entry = self.entries.get_mut(token_id)?;
        let old = entry.min_price;
        if old == new_tick {
            return None;
        }
        entry.min_price = new_tick;
        entry.max_price = Decimal::ONE - new_tick;
        Some((old, new_tick))
    }

    #[must_use]
    pub fn get(&self, token_id: &str) -> Option<&TickEntry> {
        self.entries.get(token_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clob::signing::to_fixed_usdc;

    fn d(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    #[test]
    fn tick_entry_prices_001() {
        let entry = TickEntry::new(d("0.01"), U256::from(111_u64));
        assert_eq!(entry.max_price, d("0.99"));
        assert_eq!(entry.min_price, d("0.01"));
    }

    #[test]
    fn tick_entry_prices_0001() {
        let entry = TickEntry::new(d("0.001"), U256::from(222_u64));
        assert_eq!(entry.max_price, d("0.999"));
        assert_eq!(entry.min_price, d("0.001"));
    }

    #[test]
    fn tick_entry_prices_quarter_cent() {
        // The 0.0025 grid (2026-07 venue addition): rails derive as
        // [tick, 1 − tick] — no enumeration of known ticks anywhere.
        let entry = TickEntry::new(d("0.0025"), U256::from(333_u64));
        assert_eq!(entry.max_price, d("0.9975"));
        assert_eq!(entry.min_price, d("0.0025"));
    }

    #[test]
    fn update_tick_onto_quarter_cent_grid() {
        let mut cache = TickSizeCache::new();
        cache.insert("111".into(), d("0.01"));
        assert_eq!(
            cache.update_tick("111", d("0.0025")),
            Some((d("0.01"), d("0.0025")))
        );
        let entry = cache.get("111").unwrap();
        assert_eq!(entry.min_price, d("0.0025"));
        assert_eq!(entry.max_price, d("0.9975"));
    }

    #[test]
    fn retick_recomputes_bounds_and_preserves_u256() {
        let entry = TickEntry::new(d("0.01"), U256::from(123_u64));
        let regridded = entry
            .retick(d("0.001"))
            .expect("a changed tick yields Some");
        assert_eq!(regridded.min_price, d("0.001"));
        assert_eq!(regridded.max_price, d("0.999"));
        assert_eq!(regridded.token_id_u256, U256::from(123_u64));
    }

    #[test]
    fn retick_same_value_is_none() {
        let entry = TickEntry::new(d("0.01"), U256::from(123_u64));
        assert!(entry.retick(d("0.01")).is_none());
    }

    #[test]
    fn update_tick_refine_recomputes_bounds_and_preserves_u256() {
        let mut cache = TickSizeCache::new();
        cache.insert("111".into(), d("0.01"));
        let u256 = cache.get("111").unwrap().token_id_u256;

        assert_eq!(
            cache.update_tick("111", d("0.001")),
            Some((d("0.01"), d("0.001")))
        );
        let entry = cache.get("111").unwrap();
        assert_eq!(entry.min_price, d("0.001"));
        assert_eq!(entry.max_price, d("0.999"));
        assert_eq!(entry.token_id_u256, u256);
    }

    #[test]
    fn update_tick_coarsen_lowers_max_price() {
        let mut cache = TickSizeCache::new();
        cache.insert("111".into(), d("0.001"));

        assert_eq!(
            cache.update_tick("111", d("0.01")),
            Some((d("0.001"), d("0.01")))
        );
        assert_eq!(cache.get("111").unwrap().max_price, d("0.99"));
    }

    #[test]
    fn update_tick_same_value_is_noop() {
        let mut cache = TickSizeCache::new();
        cache.insert("111".into(), d("0.01"));

        assert_eq!(cache.update_tick("111", d("0.01")), None);
        assert_eq!(cache.get("111").unwrap().max_price, d("0.99"));
    }

    #[test]
    fn update_tick_unknown_token_does_not_insert() {
        let mut cache = TickSizeCache::new();

        assert_eq!(cache.update_tick("999", d("0.01")), None);
        assert!(cache.get("999").is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn compute_order_size_floors_to_size_step() {
        // Cash cap disabled (max_cash_deploy = 0); cost_per_unit is unused.
        let max = d("20");
        assert_eq!(
            compute_order_size(d("5"), max, d("0"), d("1")),
            Some(d("5"))
        );
        // Fractional caps floor to the nearest 0.1; never round up past the cap.
        assert_eq!(
            compute_order_size(d("5.9"), max, d("0"), d("1")),
            Some(d("5.9"))
        );
        // Sub-step remainder is dropped, not rounded up.
        assert_eq!(
            compute_order_size(d("5.05"), max, d("0"), d("1")),
            Some(d("5"))
        );
        assert_eq!(
            compute_order_size(d("9"), max, d("0"), d("1")),
            Some(d("9"))
        );
        assert_eq!(
            compute_order_size(d("10"), max, d("0"), d("1")),
            Some(d("10"))
        );
        assert_eq!(
            compute_order_size(d("14.99"), max, d("0"), d("1")),
            Some(d("14.9"))
        );
        assert_eq!(
            compute_order_size(d("20"), max, d("0"), d("1")),
            Some(d("20"))
        );
        // max_size (20) binds below min_ask_size.
        assert_eq!(
            compute_order_size(d("25"), max, d("0"), d("1")),
            Some(d("20"))
        );
        assert_eq!(
            compute_order_size(d("100"), max, d("0"), d("1")),
            Some(d("20"))
        );
        // Below MIN_SIZE after the floor -> skip (4.99 floors to 4.9).
        assert_eq!(compute_order_size(d("4.99"), max, d("0"), d("1")), None);
        assert_eq!(compute_order_size(d("0"), max, d("0"), d("1")), None);
    }

    #[test]
    fn compute_order_size_caps_by_cash() {
        // cost_per_unit = Σ ask; size is capped so size * cost_per_unit <= budget.
        // 30 / 2 = 15 binds below max_size (20).
        assert_eq!(
            compute_order_size(d("100"), d("20"), d("30"), d("2")),
            Some(d("15"))
        );
        // 100 / 3 = 33.33... floors to 33.3 (post-cap, nearest 0.1).
        assert_eq!(
            compute_order_size(d("100"), d("100"), d("100"), d("3")),
            Some(d("33.3"))
        );
        // 8 / 2 = 4 < MIN_SIZE -> skip the opportunity.
        assert_eq!(compute_order_size(d("100"), d("20"), d("8"), d("2")), None);
        // Budget of 0 disables the cap.
        assert_eq!(
            compute_order_size(d("100"), d("20"), d("0"), d("3")),
            Some(d("20"))
        );
    }

    #[test]
    fn warmup_maker_amount_tick_001() {
        let tick = TickEntry::new(d("0.01"), U256::from(111_u64));
        assert_eq!(tick.min_price, d("0.01"));
        let maker = to_fixed_usdc(FIXED_SIZE * tick.min_price).unwrap();
        assert_eq!(maker, 50_000);
    }

    #[test]
    fn warmup_maker_amount_tick_0001() {
        let tick = TickEntry::new(d("0.001"), U256::from(222_u64));
        assert_eq!(tick.min_price, d("0.001"));
        let maker = to_fixed_usdc(FIXED_SIZE * tick.min_price).unwrap();
        assert_eq!(maker, 5_000);
    }
}
