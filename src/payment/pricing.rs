//! Local fullness-based pricing algorithm for saorsa-node.
//!
//! Mirrors the logarithmic pricing curve from autonomi's `MerklePaymentVault` contract:
//! - Empty node → price ≈ `MIN_PRICE` (floor)
//! - Filling up → price increases logarithmically
//! - Nearly full → price spikes (ln(x) as x→0)
//! - At capacity → returns `u64::MAX` (effectively refuses new data)
//!
//! ## Design Rationale: Capacity-Based Pricing
//!
//! Pricing is based on node **fullness** (percentage of storage capacity used),
//! not on a fixed cost-per-byte. This design mirrors the autonomi
//! `MerklePaymentVault` on-chain contract and creates natural load balancing:
//!
//! - **Empty nodes** charge the minimum floor price, attracting new data
//! - **Nearly full nodes** charge exponentially more via the logarithmic curve
//! - **This pushes clients toward emptier nodes**, distributing data across the network
//!
//! A flat cost-per-byte model would not incentivize distribution — all nodes would
//! charge the same regardless of remaining capacity. The logarithmic curve ensures
//! the network self-balances as nodes fill up.

use ant_evm::{Amount, QuotingMetrics};

/// Minimum price floor (matches contract's `minPrice = 3`).
const MIN_PRICE: u64 = 3;

/// Scaling factor for the logarithmic pricing curve.
/// In the contract this is 1e18; we normalize to 1.0 for f64 arithmetic.
const SCALING_FACTOR: f64 = 1.0;

/// ANT price constant (normalized to 1.0, matching contract's 1e18/1e18 ratio).
const ANT_PRICE: f64 = 1.0;

/// Calculate a local price estimate from node quoting metrics.
///
/// Implements the autonomi pricing formula:
/// ```text
/// price = (-s/ANT) * (ln|rUpper - 1| - ln|rLower - 1|) + pMin*(rUpper - rLower) - (rUpper - rLower)/ANT
/// ```
///
/// where:
/// - `rLower = total_cost_units / max_cost_units` (current fullness ratio)
/// - `rUpper = (total_cost_units + cost_unit) / max_cost_units` (fullness after storing)
/// - `s` = scaling factor, `ANT` = ANT price, `pMin` = minimum price
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#[must_use]
pub fn calculate_price(metrics: &QuotingMetrics) -> Amount {
    let min_price = Amount::from(MIN_PRICE);

    // Edge case: zero or very small capacity
    if metrics.max_records == 0 {
        return min_price;
    }

    // Use close_records_stored as the authoritative record count for pricing.
    let total_records = metrics.close_records_stored as u64;

    let max_records = metrics.max_records as f64;

    // Normalize to [0, 1) range (matching contract's _getBound)
    let r_lower = total_records as f64 / max_records;
    // Adding one record (cost_unit = 1 normalized)
    let r_upper = (total_records + 1) as f64 / max_records;

    // At capacity: return maximum price to effectively refuse new data
    if r_lower >= 1.0 || r_upper >= 1.0 {
        return Amount::from(u64::MAX);
    }
    if (r_upper - r_lower).abs() < f64::EPSILON {
        return min_price;
    }

    // Calculate |r - 1| for logarithm inputs
    let upper_diff = (r_upper - 1.0).abs();
    let lower_diff = (r_lower - 1.0).abs();

    // Avoid log(0)
    if upper_diff < f64::EPSILON || lower_diff < f64::EPSILON {
        return min_price;
    }

    let log_upper = upper_diff.ln();
    let log_lower = lower_diff.ln();
    let log_diff = log_upper - log_lower;

    let linear_part = r_upper - r_lower;

    // Formula: price = (-s/ANT) * logDiff + pMin * linearPart - linearPart/ANT
    let part_one = (-SCALING_FACTOR / ANT_PRICE) * log_diff;
    let part_two = MIN_PRICE as f64 * linear_part;
    let part_three = linear_part / ANT_PRICE;

    let price = part_one + part_two - part_three;

    if price <= 0.0 || !price.is_finite() {
        return min_price;
    }

    // Scale by data_size (larger data costs proportionally more)
    let data_size_factor = metrics.data_size.max(1) as f64;
    let scaled_price = price * data_size_factor;

    if !scaled_price.is_finite() {
        return min_price;
    }

    // Convert to Amount (U256), floor at MIN_PRICE
    let price_u64 = if scaled_price > u64::MAX as f64 {
        u64::MAX
    } else {
        (scaled_price as u64).max(MIN_PRICE)
    };

    Amount::from(price_u64)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn make_metrics(
        records_stored: usize,
        max_records: usize,
        data_size: usize,
        data_type: u32,
    ) -> QuotingMetrics {
        let records_per_type = if records_stored > 0 {
            vec![(data_type, u32::try_from(records_stored).unwrap_or(u32::MAX))]
        } else {
            vec![]
        };
        QuotingMetrics {
            data_type,
            data_size,
            close_records_stored: records_stored,
            records_per_type,
            max_records,
            received_payment_count: 0,
            live_time: 0,
            network_density: None,
            network_size: Some(500),
        }
    }

    #[test]
    fn test_empty_node_gets_min_price() {
        let metrics = make_metrics(0, 1000, 1, 0);
        let price = calculate_price(&metrics);
        // Empty node should return approximately MIN_PRICE
        assert_eq!(price, Amount::from(MIN_PRICE));
    }

    #[test]
    fn test_half_full_node_costs_more() {
        let empty = make_metrics(0, 1000, 1024, 0);
        let half = make_metrics(500, 1000, 1024, 0);
        let price_empty = calculate_price(&empty);
        let price_half = calculate_price(&half);
        assert!(
            price_half > price_empty,
            "Half-full price ({price_half}) should exceed empty price ({price_empty})"
        );
    }

    #[test]
    fn test_nearly_full_node_costs_much_more() {
        let half = make_metrics(500, 1000, 1024, 0);
        let nearly_full = make_metrics(900, 1000, 1024, 0);
        let price_half = calculate_price(&half);
        let price_nearly_full = calculate_price(&nearly_full);
        assert!(
            price_nearly_full > price_half,
            "Nearly-full price ({price_nearly_full}) should far exceed half-full price ({price_half})"
        );
    }

    #[test]
    fn test_full_node_returns_max_price() {
        // At capacity (r_lower >= 1.0), effectively refuse new data with max price
        let metrics = make_metrics(1000, 1000, 1024, 0);
        let price = calculate_price(&metrics);
        assert_eq!(price, Amount::from(u64::MAX));
    }

    #[test]
    fn test_price_increases_monotonically() {
        let max_records = 1000;
        let data_size = 1024;
        let mut prev_price = Amount::ZERO;

        // Check from 0% to 99% full
        for pct in 0..100 {
            let records = pct * max_records / 100;
            let metrics = make_metrics(records, max_records, data_size, 0);
            let price = calculate_price(&metrics);
            assert!(
                price >= prev_price,
                "Price at {pct}% ({price}) should be >= price at previous step ({prev_price})"
            );
            prev_price = price;
        }
    }

    #[test]
    fn test_zero_max_records_returns_min_price() {
        let metrics = make_metrics(0, 0, 1024, 0);
        let price = calculate_price(&metrics);
        assert_eq!(price, Amount::from(MIN_PRICE));
    }

    #[test]
    fn test_different_data_sizes_same_fullness() {
        let small = make_metrics(500, 1000, 100, 0);
        let large = make_metrics(500, 1000, 10000, 0);
        let price_small = calculate_price(&small);
        let price_large = calculate_price(&large);
        assert!(
            price_large > price_small,
            "Larger data ({price_large}) should cost more than smaller data ({price_small})"
        );
    }

    #[test]
    fn test_price_with_multiple_record_types() {
        // 300 type-0 records + 200 type-1 records = 500 total out of 1000
        let metrics = QuotingMetrics {
            data_type: 0,
            data_size: 1024,
            close_records_stored: 500,
            records_per_type: vec![(0, 300), (1, 200)],
            max_records: 1000,
            received_payment_count: 0,
            live_time: 0,
            network_density: None,
            network_size: Some(500),
        };
        let price_multi = calculate_price(&metrics);

        // Compare with single-type equivalent (500 of type 0)
        let metrics_single = make_metrics(500, 1000, 1024, 0);
        let price_single = calculate_price(&metrics_single);

        // Same total records → same price
        assert_eq!(price_multi, price_single);
    }

    #[test]
    fn test_price_at_95_percent() {
        let metrics = make_metrics(950, 1000, 1024, 0);
        let price = calculate_price(&metrics);
        let min = Amount::from(MIN_PRICE);
        assert!(
            price > min,
            "Price at 95% should be above minimum, got {price}"
        );
    }

    #[test]
    fn test_price_at_99_percent() {
        let metrics = make_metrics(990, 1000, 1024, 0);
        let price = calculate_price(&metrics);
        let price_95 = calculate_price(&make_metrics(950, 1000, 1024, 0));
        assert!(
            price > price_95,
            "Price at 99% ({price}) should exceed price at 95% ({price_95})"
        );
    }

    #[test]
    fn test_over_capacity_returns_max_price() {
        // 1100 records stored but max is 1000 — over capacity
        let metrics = make_metrics(1100, 1000, 1024, 0);
        let price = calculate_price(&metrics);
        assert_eq!(
            price,
            Amount::from(u64::MAX),
            "Over-capacity should return max price"
        );
    }

    #[test]
    fn test_price_deterministic() {
        let metrics = make_metrics(500, 1000, 1024, 0);
        let price1 = calculate_price(&metrics);
        let price2 = calculate_price(&metrics);
        let price3 = calculate_price(&metrics);
        assert_eq!(price1, price2);
        assert_eq!(price2, price3);
    }
}
