//! Quadratic pricing with a baseline floor for ant-node (Phase 1 recalibration).
//!
//! Formula: `price_per_chunk_ANT(n) = BASELINE + K × (n / D)²`
//!
//! This recalibration introduces a non-zero `BASELINE` so that empty nodes
//! charge a meaningful spam-barrier price, and re-anchors `K` so per-GB USD
//! pricing matches real-world targets at the current ~$0.10/ANT token price.
//! The legacy formula produced ~$25/GB at the lower stable boundary and ~$0/GB
//! when nodes were empty — both unreasonable.
//!
//! ## Parameters
//!
//! | Constant  | Value         | Role                                            |
//! |-----------|---------------|-------------------------------------------------|
//! | BASELINE  | 0.00390625 ANT| Price at empty (bootstrap-phase spam barrier)   |
//! | K         | 0.03515625 ANT| Quadratic coefficient                           |
//! | D         | 6000          | Lower stable boundary (records stored)          |
//!
//! ## Design Rationale
//!
//! - **Empty / lightly loaded nodes** charge the `BASELINE` floor, preventing
//!   free storage and acting as a bootstrap-phase spam barrier.
//! - **Moderately loaded nodes** add a small quadratic contribution on top.
//! - **Heavily loaded nodes** charge quadratically more, pushing clients
//!   toward less-loaded nodes elsewhere in the network.

use evmlib::common::Amount;

/// Lower stable boundary of the quadratic curve, in records stored.
const PRICING_DIVISOR: u128 = 6000;

/// `PRICING_DIVISOR²`, precomputed to avoid repeated multiplication.
const DIVISOR_SQUARED: u128 = PRICING_DIVISOR * PRICING_DIVISOR;

/// Baseline price at empty / bootstrap-phase spam barrier.
///
/// `0.00390625 ANT × 10¹⁸ wei/ANT = 3_906_250_000_000_000 wei`.
const PRICE_BASELINE_WEI: u128 = 3_906_250_000_000_000;

/// Quadratic coefficient `K`.
///
/// `0.03515625 ANT × 10¹⁸ wei/ANT = 35_156_250_000_000_000 wei`.
const PRICE_COEFFICIENT_WEI: u128 = 35_156_250_000_000_000;

/// Calculate storage price in wei from the number of close records stored.
///
/// Formula: `price_wei = BASELINE + n² × K / D²`
///
/// where `BASELINE = 0.00390625 ANT`, `K = 0.03515625 ANT`, and `D = 6000`.
/// U256 arithmetic prevents overflow for large record counts.
#[must_use]
pub fn calculate_price(close_records_stored: usize) -> Amount {
    let n = Amount::from(close_records_stored);
    let n_squared = n.saturating_mul(n);
    let quadratic_wei = n_squared.saturating_mul(Amount::from(PRICE_COEFFICIENT_WEI))
        / Amount::from(DIVISOR_SQUARED);
    Amount::from(PRICE_BASELINE_WEI).saturating_add(quadratic_wei)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 1 token = 10¹⁸ wei (used for test sanity-checks).
    const WEI_PER_TOKEN: u128 = 1_000_000_000_000_000_000;

    /// Helper: expected price matching the formula `BASELINE + n² × K / D²`.
    fn expected_price(n: u64) -> Amount {
        let n_amt = Amount::from(n);
        let quad =
            n_amt * n_amt * Amount::from(PRICE_COEFFICIENT_WEI) / Amount::from(DIVISOR_SQUARED);
        Amount::from(PRICE_BASELINE_WEI) + quad
    }

    #[test]
    fn test_zero_records_gets_baseline() {
        // At n = 0 the quadratic term vanishes, leaving the baseline floor.
        let price = calculate_price(0);
        assert_eq!(price, Amount::from(PRICE_BASELINE_WEI));
    }

    #[test]
    fn test_baseline_is_nonzero_spam_barrier() {
        // The baseline ensures even empty nodes charge a meaningful price,
        // making the legacy MIN_PRICE_WEI = 1 sentinel redundant.
        assert!(calculate_price(0) > Amount::ZERO);
        assert!(calculate_price(1) > calculate_price(0));
    }

    #[test]
    fn test_one_record_above_baseline() {
        let price = calculate_price(1);
        assert_eq!(price, expected_price(1));
        assert!(price > Amount::from(PRICE_BASELINE_WEI));
    }

    #[test]
    fn test_at_divisor_is_baseline_plus_k() {
        // At n = D the quadratic contribution equals K × 1² = K.
        // price = BASELINE + K = 0.00390625 + 0.03515625 = 0.0390625 ANT
        let price = calculate_price(6000);
        let expected = Amount::from(PRICE_BASELINE_WEI + PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_double_divisor_is_baseline_plus_four_k() {
        // At n = 2D the quadratic contribution is 4K.
        let price = calculate_price(12000);
        let expected = Amount::from(PRICE_BASELINE_WEI + 4 * PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_triple_divisor_is_baseline_plus_nine_k() {
        // At n = 3D the quadratic contribution is 9K.
        let price = calculate_price(18000);
        let expected = Amount::from(PRICE_BASELINE_WEI + 9 * PRICE_COEFFICIENT_WEI);
        assert_eq!(price, expected);
    }

    #[test]
    fn test_smooth_pricing_no_staircase() {
        // 11999 should give a strictly higher price than 6000 (no integer-division plateau).
        let price_6k = calculate_price(6000);
        let price_11k = calculate_price(11999);
        assert!(
            price_11k > price_6k,
            "11999 records ({price_11k}) should cost more than 6000 ({price_6k})"
        );
    }

    #[test]
    fn test_price_increases_with_records() {
        let price_low = calculate_price(6000);
        let price_mid = calculate_price(12000);
        let price_high = calculate_price(18000);
        assert!(price_mid > price_low);
        assert!(price_high > price_mid);
    }

    #[test]
    fn test_price_increases_monotonically() {
        let mut prev_price = Amount::ZERO;
        for records in (0..60000).step_by(100) {
            let price = calculate_price(records);
            assert!(
                price >= prev_price,
                "Price at {records} records ({price}) should be >= previous ({prev_price})"
            );
            prev_price = price;
        }
    }

    #[test]
    fn test_large_value_no_overflow() {
        let price = calculate_price(usize::MAX);
        assert!(price > Amount::ZERO);
    }

    #[test]
    fn test_price_deterministic() {
        let price1 = calculate_price(12000);
        let price2 = calculate_price(12000);
        assert_eq!(price1, price2);
    }

    #[test]
    fn test_quadratic_growth_excluding_baseline() {
        // Subtracting the baseline, quadratic contribution should scale with n².
        // At 2× records the quadratic portion is 4×; at 4× records it is 16×.
        let base = Amount::from(PRICE_BASELINE_WEI);
        let quad_6k = calculate_price(6000) - base;
        let quad_12k = calculate_price(12000) - base;
        let quad_24k = calculate_price(24000) - base;
        assert_eq!(quad_12k, quad_6k * Amount::from(4u64));
        assert_eq!(quad_24k, quad_6k * Amount::from(16u64));
    }

    #[test]
    fn test_small_record_counts_near_baseline() {
        // At small n, price is dominated by the baseline — quadratic term is tiny.
        let price = calculate_price(100);
        assert_eq!(price, expected_price(100));
        assert!(price < Amount::from(WEI_PER_TOKEN)); // well below 1 ANT
        assert!(price > Amount::from(PRICE_BASELINE_WEI)); // strictly above baseline
    }
}
