//! Simple quadratic pricing algorithm for ant-node.
//!
//! Uses the formula `(close_records_stored / 6000)^2` to calculate storage price.
//! Integer division means nodes with fewer than 6000 records get a ratio of 0,
//! but a minimum floor of 1 prevents free storage.
//!
//! ## Design Rationale
//!
//! The quadratic curve creates natural load balancing:
//! - **Lightly loaded nodes** (< 6000 records) charge the minimum floor price
//! - **Moderately loaded nodes** charge proportionally more as records grow
//! - **Heavily loaded nodes** charge quadratically more, pushing clients elsewhere

use evmlib::common::Amount;

/// Divisor for the pricing formula.
const PRICING_DIVISOR: u64 = 6000;

/// PRICING_DIVISOR², precomputed to avoid repeated multiplication.
const DIVISOR_SQUARED: u64 = PRICING_DIVISOR * PRICING_DIVISOR;

/// 1 token = 10^18 wei.
const WEI_PER_TOKEN: u128 = 1_000_000_000_000_000_000;

/// Minimum price in wei (1 wei) to prevent free storage.
const MIN_PRICE_WEI: u128 = 1;

/// Calculate storage price in wei from the number of close records stored.
///
/// Formula: `price_wei = n² × 10¹⁸ / 6000²`
///
/// This is equivalent to `(n / 6000)²` in tokens, converted to wei, but
/// preserves sub-token precision by scaling before dividing. U256 arithmetic
/// prevents overflow for large record counts.
#[must_use]
pub fn calculate_price(close_records_stored: usize) -> Amount {
    let n = Amount::from(close_records_stored);
    let n_squared = n.saturating_mul(n);
    let price_wei =
        n_squared.saturating_mul(Amount::from(WEI_PER_TOKEN)) / Amount::from(DIVISOR_SQUARED);
    if price_wei.is_zero() {
        Amount::from(MIN_PRICE_WEI)
    } else {
        price_wei
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const WEI: u128 = WEI_PER_TOKEN;

    /// Helper: expected price for n records = n² * 10^18 / 6000²
    fn expected_price(n: u64) -> Amount {
        let n = Amount::from(n);
        n * n * Amount::from(WEI) / Amount::from(DIVISOR_SQUARED)
    }

    #[test]
    fn test_zero_records_gets_min_price() {
        let price = calculate_price(0);
        assert_eq!(price, Amount::from(MIN_PRICE_WEI));
    }

    #[test]
    fn test_one_record_nonzero() {
        // 1² * 1e18 / 36e6 = 1e18 / 36e6 ≈ 27_777_777_777
        let price = calculate_price(1);
        assert_eq!(price, expected_price(1));
        assert!(price > Amount::ZERO);
    }

    #[test]
    fn test_at_divisor_gets_one_token() {
        // 6000² * 1e18 / 6000² = 1e18
        let price = calculate_price(6000);
        assert_eq!(price, Amount::from(WEI));
    }

    #[test]
    fn test_double_divisor_gets_four_tokens() {
        // 12000² * 1e18 / 6000² = 4e18
        let price = calculate_price(12000);
        assert_eq!(price, Amount::from(4 * WEI));
    }

    #[test]
    fn test_triple_divisor_gets_nine_tokens() {
        // 18000² * 1e18 / 6000² = 9e18
        let price = calculate_price(18000);
        assert_eq!(price, Amount::from(9 * WEI));
    }

    #[test]
    fn test_smooth_pricing_no_staircase() {
        // With the old integer-division approach, 6000 and 11999 gave the same price.
        // Now 11999 should give a higher price than 6000.
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
    fn test_quadratic_growth() {
        // price at 4x records should be 16x price at 1x
        let price_1x = calculate_price(6000);
        let price_4x = calculate_price(24000);
        assert_eq!(price_1x, Amount::from(WEI));
        assert_eq!(price_4x, Amount::from(16 * WEI));
    }

    #[test]
    fn test_small_record_counts_are_cheap() {
        // 100 records: 100² * 1e18 / 36e6 ≈ 277_777_777_777_777 wei ≈ 0.000278 tokens
        let price = calculate_price(100);
        assert_eq!(price, expected_price(100));
        assert!(price < Amount::from(WEI)); // well below 1 token
    }
}
