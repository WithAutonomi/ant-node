//! `SingleNode` payment mode implementation for saorsa-node.
//!
//! This module implements the `SingleNode` payment strategy from autonomi:
//! - Client gets 5 quotes from network (`CLOSE_GROUP_SIZE`)
//! - Sort by price and select median (index 2)
//! - Pay ONLY the median-priced node with 3x the quoted amount
//! - Other 4 nodes get `Amount::ZERO`
//! - All 5 are submitted for payment and verification
//!
//! Total cost is the same as Standard mode (3x), but with one actual payment.
//! This saves gas fees while maintaining the same total payment amount.

use crate::error::{Error, Result};
use ant_evm::{Amount, PaymentQuote, QuoteHash, QuotingMetrics, RewardsAddress};
use evmlib::contract::payment_vault;
use evmlib::wallet::Wallet;
use evmlib::Network as EvmNetwork;
use tracing::info;

/// Required number of quotes for `SingleNode` payment (matches `CLOSE_GROUP_SIZE`)
pub const REQUIRED_QUOTES: usize = 5;

/// Create zero-valued `QuotingMetrics` for payment verification.
///
/// The contract doesn't validate metric values, so we use zeroes.
fn zero_quoting_metrics() -> QuotingMetrics {
    QuotingMetrics {
        data_size: 0,
        data_type: 0,
        close_records_stored: 0,
        records_per_type: vec![],
        max_records: 0,
        received_payment_count: 0,
        live_time: 0,
        network_density: None,
        network_size: None,
    }
}

/// Index of the median-priced node after sorting
const MEDIAN_INDEX: usize = 2;

/// Single node payment structure for a chunk.
///
/// Contains exactly 5 quotes where only the median-priced one receives payment (3x),
/// and the other 4 have `Amount::ZERO`.
///
/// The fixed-size array ensures compile-time enforcement of the 5-quote requirement,
/// making the median index (2) always valid.
#[derive(Debug, Clone)]
pub struct SingleNodePayment {
    /// All 5 quotes (sorted by price) - fixed size ensures median index is always valid
    pub quotes: [QuotePaymentInfo; REQUIRED_QUOTES],
}

/// Information about a single quote payment
#[derive(Debug, Clone)]
pub struct QuotePaymentInfo {
    /// The quote hash
    pub quote_hash: QuoteHash,
    /// The rewards address
    pub rewards_address: RewardsAddress,
    /// The amount to pay (3x for median, 0 for others)
    pub amount: Amount,
    /// The quoting metrics
    pub quoting_metrics: QuotingMetrics,
}

impl SingleNodePayment {
    /// Create a `SingleNode` payment from 5 quotes and their prices.
    ///
    /// The quotes are automatically sorted by price (cheapest first).
    /// The median (index 2) gets 3x its quote price.
    /// The other 4 get `Amount::ZERO`.
    ///
    /// # Arguments
    ///
    /// * `quotes_with_prices` - Vec of (`PaymentQuote`, Amount) tuples (will be sorted internally)
    ///
    /// # Errors
    ///
    /// Returns error if not exactly 5 quotes are provided.
    pub fn from_quotes(mut quotes_with_prices: Vec<(PaymentQuote, Amount)>) -> Result<Self> {
        let len = quotes_with_prices.len();
        if len != REQUIRED_QUOTES {
            return Err(Error::Payment(format!(
                "SingleNode payment requires exactly {REQUIRED_QUOTES} quotes, got {len}"
            )));
        }

        // Sort by price (cheapest first) to ensure correct median selection
        quotes_with_prices.sort_by_key(|(_, price)| *price);

        // Get median price and calculate 3x
        let median_price = quotes_with_prices
            .get(MEDIAN_INDEX)
            .ok_or_else(|| {
                Error::Payment(format!(
                    "Missing median quote at index {MEDIAN_INDEX}: expected {REQUIRED_QUOTES} quotes but get() failed"
                ))
            })?
            .1;
        let enhanced_price = median_price
            .checked_mul(Amount::from(3u64))
            .ok_or_else(|| {
                Error::Payment("Price overflow when calculating 3x median".to_string())
            })?;

        // Build quote payment info for all 5 quotes
        // Use try_from to convert Vec to fixed-size array
        let quotes_vec: Vec<QuotePaymentInfo> = quotes_with_prices
            .into_iter()
            .enumerate()
            .map(|(idx, (quote, _))| QuotePaymentInfo {
                quote_hash: quote.hash(),
                rewards_address: quote.rewards_address,
                amount: if idx == MEDIAN_INDEX {
                    enhanced_price
                } else {
                    Amount::ZERO
                },
                quoting_metrics: quote.quoting_metrics,
            })
            .collect();

        // Convert Vec to array - we already validated length is REQUIRED_QUOTES
        let quotes: [QuotePaymentInfo; REQUIRED_QUOTES] = quotes_vec
            .try_into()
            .map_err(|_| Error::Payment("Failed to convert quotes to fixed array".to_string()))?;

        Ok(Self { quotes })
    }

    /// Get the total payment amount (should be 3x median price)
    #[must_use]
    pub fn total_amount(&self) -> Amount {
        self.quotes.iter().map(|q| q.amount).sum()
    }

    /// Get the median quote that receives payment.
    ///
    /// Returns `None` only if the internal array is somehow shorter than `MEDIAN_INDEX`,
    /// which should never happen since the array is fixed-size `[_; REQUIRED_QUOTES]`.
    #[must_use]
    pub fn paid_quote(&self) -> Option<&QuotePaymentInfo> {
        self.quotes.get(MEDIAN_INDEX)
    }

    /// Pay for all quotes on-chain using the wallet.
    ///
    /// Pays 3x to the median quote and 0 to the other 4.
    ///
    /// # Errors
    ///
    /// Returns an error if the payment transaction fails.
    pub async fn pay(&self, wallet: &Wallet) -> Result<Vec<evmlib::common::TxHash>> {
        // Build quote payments: (QuoteHash, RewardsAddress, Amount)
        let quote_payments: Vec<_> = self
            .quotes
            .iter()
            .map(|q| (q.quote_hash, q.rewards_address, q.amount))
            .collect();

        info!(
            "Paying for {} quotes: 1 real ({} atto) + {} with 0 atto",
            REQUIRED_QUOTES,
            self.total_amount(),
            REQUIRED_QUOTES - 1
        );

        let (tx_hashes, _gas_info) = wallet.pay_for_quotes(quote_payments).await.map_err(
            |evmlib::wallet::PayForQuotesError(err, _)| {
                Error::Payment(format!("Failed to pay for quotes: {err}"))
            },
        )?;

        // Collect transaction hashes only for non-zero amount quotes
        // Zero-amount quotes don't generate on-chain transactions
        let mut result_hashes = Vec::new();
        for quote_info in &self.quotes {
            if quote_info.amount > Amount::ZERO {
                let tx_hash = tx_hashes.get(&quote_info.quote_hash).ok_or_else(|| {
                    Error::Payment(format!(
                        "Missing transaction hash for non-zero quote {}",
                        quote_info.quote_hash
                    ))
                })?;
                result_hashes.push(*tx_hash);
            }
        }

        info!(
            "Payment successful: {} on-chain transactions",
            result_hashes.len()
        );

        Ok(result_hashes)
    }

    /// Verify all payments on-chain.
    ///
    /// This checks that all 5 payments were recorded on the blockchain.
    /// The contract requires exactly 5 payment verifications.
    ///
    /// # Arguments
    ///
    /// * `network` - The EVM network to verify on
    /// * `owned_quote_hash` - Optional quote hash that this node owns (expects to receive payment)
    ///
    /// # Returns
    ///
    /// The total verified payment amount received by owned quotes.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails or payment is invalid.
    pub async fn verify(
        &self,
        network: &EvmNetwork,
        owned_quote_hash: Option<QuoteHash>,
    ) -> Result<Amount> {
        // Build payment digest for all 5 quotes
        // Each quote needs an owned QuotingMetrics (tuple requires ownership)
        let payment_digest: Vec<_> = self
            .quotes
            .iter()
            .map(|q| (q.quote_hash, zero_quoting_metrics(), q.rewards_address))
            .collect();

        // Mark owned quotes
        let owned_quote_hashes = owned_quote_hash.map_or_else(Vec::new, |hash| vec![hash]);

        info!(
            "Verifying {} payments (owned: {})",
            payment_digest.len(),
            owned_quote_hashes.len()
        );

        let verified_amount =
            payment_vault::verify_data_payment(network, owned_quote_hashes.clone(), payment_digest)
                .await
                .map_err(|e| Error::Payment(format!("Payment verification failed: {e}")))?;

        if owned_quote_hashes.is_empty() {
            info!("Payment verified as valid on-chain");
        } else {
            // If we own a quote, verify the amount matches
            let expected = self
                .quotes
                .iter()
                .find(|q| Some(q.quote_hash) == owned_quote_hash)
                .ok_or_else(|| Error::Payment("Owned quote hash not found in payment".to_string()))?
                .amount;

            if verified_amount != expected {
                return Err(Error::Payment(format!(
                    "Payment amount mismatch: expected {expected}, verified {verified_amount}"
                )));
            }

            info!("Payment verified: {verified_amount} atto received");
        }

        Ok(verified_amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::node_bindings::{Anvil, AnvilInstance};
    use evmlib::contract::payment_vault::interface;
    use evmlib::quoting_metrics::QuotingMetrics;
    use evmlib::testnet::{deploy_data_payments_contract, deploy_network_token_contract, Testnet};
    use evmlib::transaction_config::TransactionConfig;
    use evmlib::utils::{dummy_address, dummy_hash};
    use evmlib::wallet::Wallet;
    use reqwest::Url;
    use serial_test::serial;
    use std::time::SystemTime;
    use xor_name::XorName;

    fn make_test_quote(rewards_addr_seed: u8) -> PaymentQuote {
        PaymentQuote {
            content: XorName::random(&mut rand::thread_rng()),
            timestamp: SystemTime::now(),
            quoting_metrics: QuotingMetrics {
                data_size: 1024,
                data_type: 0,
                close_records_stored: 0,
                records_per_type: vec![],
                max_records: 1000,
                received_payment_count: 0,
                live_time: 0,
                network_density: None,
                network_size: None,
            },
            rewards_address: RewardsAddress::new([rewards_addr_seed; 20]),
            pub_key: vec![],
            signature: vec![],
        }
    }

    /// Start an Anvil node with increased timeout for CI environments.
    ///
    /// The default timeout is 10 seconds which can be insufficient in CI.
    /// This helper uses a 60-second timeout and random port assignment
    /// to handle slower CI environments and parallel test execution.
    #[allow(clippy::expect_used, clippy::panic)]
    fn start_node_with_timeout() -> (AnvilInstance, Url) {
        const ANVIL_TIMEOUT_MS: u64 = 60_000; // 60 seconds for CI

        let host = std::env::var("ANVIL_IP_ADDR").unwrap_or_else(|_| "localhost".to_string());

        // Use port 0 to let the OS assign a random available port.
        // This prevents port conflicts when running tests in parallel.
        let anvil = Anvil::new()
            .timeout(ANVIL_TIMEOUT_MS)
            .try_spawn()
            .unwrap_or_else(|_| panic!("Could not spawn Anvil node after {ANVIL_TIMEOUT_MS}ms"));

        let url = Url::parse(&format!("http://{host}:{}", anvil.port()))
            .expect("Failed to parse Anvil URL");

        (anvil, url)
    }

    /// Test: Standard 5-quote payment verification (autonomi baseline)
    #[tokio::test]
    #[serial]
    #[allow(clippy::expect_used)]
    async fn test_standard_five_quote_payment() {
        // Use autonomi's setup pattern with increased timeout for CI
        let (node, rpc_url) = start_node_with_timeout();
        let network_token = deploy_network_token_contract(&rpc_url, &node).await;
        let mut payment_vault =
            deploy_data_payments_contract(&rpc_url, &node, *network_token.contract.address()).await;

        let transaction_config = TransactionConfig::default();

        // Create 5 random quote payments (autonomi pattern)
        let mut quote_payments = vec![];
        for _ in 0..5 {
            let quote_hash = dummy_hash();
            let reward_address = dummy_address();
            let amount = Amount::from(1u64);
            quote_payments.push((quote_hash, reward_address, amount));
        }

        // Approve tokens
        network_token
            .approve(
                *payment_vault.contract.address(),
                evmlib::common::U256::MAX,
                &transaction_config,
            )
            .await
            .expect("Failed to approve");

        println!("✓ Approved tokens");

        // CRITICAL: Set provider to same as network token
        payment_vault.set_provider(network_token.contract.provider().clone());

        // Pay for quotes
        let result = payment_vault
            .pay_for_quotes(quote_payments.clone(), &transaction_config)
            .await;

        assert!(result.is_ok(), "Payment failed: {:?}", result.err());
        println!("✓ Paid for {} quotes", quote_payments.len());

        // Verify payments using handler directly
        let payment_verifications: Vec<_> = quote_payments
            .into_iter()
            .map(|v| interface::IPaymentVault::PaymentVerification {
                metrics: zero_quoting_metrics().into(),
                rewardsAddress: v.1,
                quoteHash: v.0,
            })
            .collect();

        let results = payment_vault
            .verify_payment(payment_verifications)
            .await
            .expect("Verify payment failed");

        for result in results {
            assert!(result.isValid, "Payment verification should be valid");
        }

        println!("✓ All 5 payments verified successfully");
        println!("\n✅ Standard 5-quote payment works!");
    }

    /// Test: `SingleNode` payment strategy (1 real + 4 dummy payments)
    #[tokio::test]
    #[serial]
    #[allow(clippy::expect_used)]
    async fn test_single_node_payment_strategy() {
        let (node, rpc_url) = start_node_with_timeout();
        let network_token = deploy_network_token_contract(&rpc_url, &node).await;
        let mut payment_vault =
            deploy_data_payments_contract(&rpc_url, &node, *network_token.contract.address()).await;

        let transaction_config = TransactionConfig::default();

        // CHANGE: Create 5 payments: 1 real (3x) + 4 dummy (0x)
        let real_quote_hash = dummy_hash();
        let real_reward_address = dummy_address();
        let real_amount = Amount::from(3u64); // 3x amount

        let mut quote_payments = vec![(real_quote_hash, real_reward_address, real_amount)];

        // Add 4 dummy payments with 0 amount
        for _ in 0..4 {
            let dummy_quote_hash = dummy_hash();
            let dummy_reward_address = dummy_address();
            let dummy_amount = Amount::from(0u64); // 0 amount
            quote_payments.push((dummy_quote_hash, dummy_reward_address, dummy_amount));
        }

        // Approve tokens
        network_token
            .approve(
                *payment_vault.contract.address(),
                evmlib::common::U256::MAX,
                &transaction_config,
            )
            .await
            .expect("Failed to approve");

        println!("✓ Approved tokens");

        // Set provider
        payment_vault.set_provider(network_token.contract.provider().clone());

        // Pay (1 real payment of 3 atto + 4 dummy payments of 0 atto)
        let result = payment_vault
            .pay_for_quotes(quote_payments.clone(), &transaction_config)
            .await;

        assert!(result.is_ok(), "Payment failed: {:?}", result.err());
        println!("✓ Paid: 1 real (3 atto) + 4 dummy (0 atto)");

        // Verify all 5 payments
        let payment_verifications: Vec<_> = quote_payments
            .into_iter()
            .map(|v| interface::IPaymentVault::PaymentVerification {
                metrics: zero_quoting_metrics().into(),
                rewardsAddress: v.1,
                quoteHash: v.0,
            })
            .collect();

        let results = payment_vault
            .verify_payment(payment_verifications)
            .await
            .expect("Verify payment failed");

        // Check that real payment is valid
        assert!(
            results.first().is_some_and(|r| r.isValid),
            "Real payment should be valid"
        );
        println!("✓ Real payment verified (3 atto)");

        // Check dummy payments
        for (i, result) in results.iter().skip(1).enumerate() {
            println!("  Dummy payment {}: valid={}", i + 1, result.isValid);
        }

        println!("\n✅ SingleNode payment strategy works!");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_from_quotes_median_selection() {
        let prices: Vec<u64> = vec![50, 30, 10, 40, 20];
        let mut quotes_with_prices = Vec::new();

        for price in &prices {
            let quote = PaymentQuote {
                content: XorName::random(&mut rand::thread_rng()),
                timestamp: SystemTime::now(),
                quoting_metrics: QuotingMetrics {
                    data_size: 1024,
                    data_type: 0,
                    close_records_stored: 0,
                    records_per_type: vec![(0, 10)],
                    max_records: 1000,
                    received_payment_count: 5,
                    live_time: 3600,
                    network_density: None,
                    network_size: Some(100),
                },
                rewards_address: RewardsAddress::new([1u8; 20]),
                pub_key: vec![],
                signature: vec![],
            };
            quotes_with_prices.push((quote, Amount::from(*price)));
        }

        let payment = SingleNodePayment::from_quotes(quotes_with_prices).unwrap();

        // After sorting by price: 10, 20, 30, 40, 50
        // Median (index 2) = 30, paid amount = 3 * 30 = 90
        let median_quote = payment.quotes.get(MEDIAN_INDEX).unwrap();
        assert_eq!(median_quote.amount, Amount::from(90u64));

        // Other 4 quotes should have Amount::ZERO
        for (i, q) in payment.quotes.iter().enumerate() {
            if i != MEDIAN_INDEX {
                assert_eq!(q.amount, Amount::ZERO);
            }
        }

        // Total should be 3 * median price = 90
        assert_eq!(payment.total_amount(), Amount::from(90u64));
    }

    #[test]
    fn test_from_quotes_wrong_count() {
        let quotes: Vec<_> = (0..3)
            .map(|_| (make_test_quote(1), Amount::from(10u64)))
            .collect();
        let result = SingleNodePayment::from_quotes(quotes);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_from_quotes_zero_quotes() {
        let result = SingleNodePayment::from_quotes(vec![]);
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(err_msg.contains("exactly 5"));
    }

    #[test]
    fn test_from_quotes_one_quote() {
        let result =
            SingleNodePayment::from_quotes(vec![(make_test_quote(1), Amount::from(10u64))]);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_from_quotes_six_quotes() {
        let quotes: Vec<_> = (0..6)
            .map(|_| (make_test_quote(1), Amount::from(10u64)))
            .collect();
        let result = SingleNodePayment::from_quotes(quotes);
        assert!(result.is_err());
        let err_msg = format!("{}", result.expect_err("should fail"));
        assert!(err_msg.contains("exactly 5"));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_paid_quote_returns_median() {
        let quotes: Vec<_> = (0..5u8)
            .map(|i| (make_test_quote(i + 1), Amount::from(u64::from(i + 1) * 10)))
            .collect();

        let payment = SingleNodePayment::from_quotes(quotes).unwrap();
        let paid = payment.paid_quote().unwrap();

        // The paid quote should have a non-zero amount
        assert!(paid.amount > Amount::ZERO);

        // Total amount should equal the paid quote's amount
        assert_eq!(payment.total_amount(), paid.amount);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_all_quotes_have_distinct_addresses() {
        let quotes: Vec<_> = (0..5u8)
            .map(|i| (make_test_quote(i + 1), Amount::from(u64::from(i + 1) * 10)))
            .collect();

        let payment = SingleNodePayment::from_quotes(quotes).unwrap();

        // Verify all 5 quotes are present (sorting doesn't lose data)
        let mut addresses: Vec<_> = payment.quotes.iter().map(|q| q.rewards_address).collect();
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len(), 5);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_total_amount_equals_3x_median() {
        let prices = [100u64, 200, 300, 400, 500];
        let quotes: Vec<_> = prices
            .iter()
            .map(|price| (make_test_quote(1), Amount::from(*price)))
            .collect();

        let payment = SingleNodePayment::from_quotes(quotes).unwrap();
        // Sorted: 100, 200, 300, 400, 500 — median = 300, total = 3 * 300 = 900
        assert_eq!(payment.total_amount(), Amount::from(900u64));
    }

    /// Test: Complete `SingleNode` flow with real contract prices
    #[tokio::test]
    #[serial]
    async fn test_single_node_with_real_prices() -> Result<()> {
        // Setup testnet
        let testnet = Testnet::new().await;
        let network = testnet.to_network();
        let wallet =
            Wallet::new_from_private_key(network.clone(), &testnet.default_wallet_private_key())
                .map_err(|e| Error::Payment(format!("Failed to create wallet: {e}")))?;

        println!("✓ Started Anvil testnet");

        // Approve tokens
        wallet
            .approve_to_spend_tokens(*network.data_payments_address(), evmlib::common::U256::MAX)
            .await
            .map_err(|e| Error::Payment(format!("Failed to approve tokens: {e}")))?;

        println!("✓ Approved tokens");

        // Create 5 quotes with real prices from contract
        let chunk_xor = XorName::random(&mut rand::thread_rng());
        let chunk_size = 1024usize;

        let mut quotes_with_prices = Vec::new();
        for i in 0..REQUIRED_QUOTES {
            let quoting_metrics = QuotingMetrics {
                data_size: chunk_size,
                data_type: 0,
                close_records_stored: 10 + i,
                records_per_type: vec![(
                    0,
                    u32::try_from(10 + i)
                        .map_err(|e| Error::Payment(format!("Invalid record count: {e}")))?,
                )],
                max_records: 1000,
                received_payment_count: 5,
                live_time: 3600,
                network_density: None,
                network_size: Some(100),
            };

            // Get market price for this quote
            // PERF-004: Clone required - payment_vault::get_market_price (external API from evmlib)
            // takes ownership of Vec<QuotingMetrics>. We need quoting_metrics again below for
            // PaymentQuote construction, so the clone is unavoidable.
            let prices = payment_vault::get_market_price(&network, vec![quoting_metrics.clone()])
                .await
                .map_err(|e| Error::Payment(format!("Failed to get market price: {e}")))?;

            let price = prices.first().ok_or_else(|| {
                Error::Payment(format!(
                    "Empty price list from get_market_price for quote {}: expected at least 1 price but got {} elements",
                    i,
                    prices.len()
                ))
            })?;

            let quote = PaymentQuote {
                content: chunk_xor,
                timestamp: SystemTime::now(),
                quoting_metrics,
                rewards_address: wallet.address(),
                pub_key: vec![],
                signature: vec![],
            };

            quotes_with_prices.push((quote, *price));
        }

        println!("✓ Got 5 real quotes from contract");

        // Create SingleNode payment (will sort internally and select median)
        let payment = SingleNodePayment::from_quotes(quotes_with_prices)?;

        let median_price = payment
            .paid_quote()
            .ok_or_else(|| Error::Payment("Missing paid quote at median index".to_string()))?
            .amount
            .checked_div(Amount::from(3u64))
            .ok_or_else(|| Error::Payment("Failed to calculate median price".to_string()))?;
        println!("✓ Sorted and selected median price: {median_price} atto");

        assert_eq!(payment.quotes.len(), REQUIRED_QUOTES);
        let median_amount = payment
            .quotes
            .get(MEDIAN_INDEX)
            .ok_or_else(|| {
                Error::Payment(format!(
                    "Index out of bounds: tried to access median index {} but quotes array has {} elements",
                    MEDIAN_INDEX,
                    payment.quotes.len()
                ))
            })?
            .amount;
        assert_eq!(
            payment.total_amount(),
            median_amount,
            "Only median should have non-zero amount"
        );

        println!(
            "✓ Created SingleNode payment: {} atto total (3x median)",
            payment.total_amount()
        );

        // Pay on-chain
        let tx_hashes = payment.pay(&wallet).await?;
        println!("✓ Payment successful: {} transactions", tx_hashes.len());

        // Verify payment (as owner of median quote)
        let median_quote = payment
            .quotes
            .get(MEDIAN_INDEX)
            .ok_or_else(|| {
                Error::Payment(format!(
                    "Index out of bounds: tried to access median index {} but quotes array has {} elements",
                    MEDIAN_INDEX,
                    payment.quotes.len()
                ))
            })?;
        let median_quote_hash = median_quote.quote_hash;
        let verified_amount = payment.verify(&network, Some(median_quote_hash)).await?;

        assert_eq!(
            verified_amount, median_quote.amount,
            "Verified amount should match median payment"
        );

        println!("✓ Payment verified: {verified_amount} atto");
        println!("\n✅ Complete SingleNode flow with real prices works!");

        Ok(())
    }
}
