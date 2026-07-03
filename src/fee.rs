//! Polymarket V2 platform-fee math.
//!
//! The venue charges takers `shares × rate × (price × (1 − price))^exponent`.
//! With exponent `1` (no builder code) the formula collapses to
//! `shares × rate × price × (1 − price)` — pure [`Decimal`], no floating
//! point.
//!
//! `rate` is the raw, gross fee rate from the market's fee schedule. Referral
//! kickbacks are *rebates* applied by callers, never folded in here, so the
//! value returned is always the gross fee the venue charges at fill time.
//! Maker fills incur no taker fee, so price only the taker legs.

use rust_decimal::Decimal;

/// Gross taker platform fee for `shares` filled at `price` under fee `rate`.
///
/// `shares × rate × price × (1 − price)`. The `price × (1 − price)` base is
/// the V2 exponent-1 form; it is symmetric in YES/NO and zero at the `0`/`1`
/// bounds (no fee on a leg that fills at a degenerate price). Returns gross —
/// apply any referral kickback at the call site if a net figure is wanted.
#[must_use]
pub fn platform_fee(shares: Decimal, price: Decimal, rate: Decimal) -> Decimal {
    shares * rate * price * (Decimal::ONE - price)
}

#[cfg(test)]
mod tests {
    use rust_decimal::Decimal;

    use super::platform_fee;

    fn d(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    #[test]
    fn matches_venue_formula_at_a_known_point() {
        // 6.52 shares @ 0.83 NO, rate 0.05: 6.52 × 0.05 × 0.83 × 0.17 = 0.0459986.
        let fee = platform_fee(d("6.52"), d("0.83"), d("0.05"));
        assert_eq!(fee, d("0.0459986"));
        assert_eq!(fee.round_dp(3), d("0.046"));
    }

    #[test]
    fn zero_at_price_bounds() {
        assert_eq!(
            platform_fee(d("10"), Decimal::ZERO, d("0.05")),
            Decimal::ZERO
        );
        assert_eq!(
            platform_fee(d("10"), Decimal::ONE, d("0.05")),
            Decimal::ZERO
        );
    }

    #[test]
    fn linear_in_shares() {
        let one = platform_fee(Decimal::ONE, d("0.69"), d("0.05"));
        let many = platform_fee(d("6.52"), d("0.69"), d("0.05"));
        assert_eq!(many, one * d("6.52"));
    }

    #[test]
    fn symmetric_in_yes_no_price() {
        // price×(1−price) is symmetric, so a NO fill at 0.69 and a YES fill
        // at 0.31 carry the same per-share fee.
        assert_eq!(
            platform_fee(Decimal::ONE, d("0.69"), d("0.05")),
            platform_fee(Decimal::ONE, d("0.31"), d("0.05")),
        );
    }
}
