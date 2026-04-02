//! `SingleNode` payment mode implementation for ant-node.
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

use crate::ant_protocol::CLOSE_GROUP_SIZE;
use crate::error::{Error, Result};
use evmlib::common::{Amount, QuoteHash};
use evmlib::wallet::Wallet;
use evmlib::Network as EvmNetwork;
use evmlib::PaymentQuote;
use evmlib::RewardsAddress;
use tracing::info;

/// Index of the median-priced node after sorting, derived from `CLOSE_GROUP_SIZE`.
const MEDIAN_INDEX: usize = CLOSE_GROUP_SIZE / 2;

/// Single node payment structure for a chunk.
///
/// Contains exactly `CLOSE_GROUP_SIZE` quotes where only the median-priced one
/// receives payment (3x), and the remaining quotes have `Amount::ZERO`.
///
/// The fixed-size array ensures compile-time enforcement of the quote count,
/// making the median index always valid.
#[derive(Debug, Clone)]
pub struct SingleNodePayment {
    /// All quotes (sorted by price) - fixed size ensures median index is always valid
    pub quotes: [QuotePaymentInfo; CLOSE_GROUP_SIZE],
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
        if len != CLOSE_GROUP_SIZE {
            return Err(Error::Payment(format!(
                "SingleNode payment requires exactly {CLOSE_GROUP_SIZE} quotes, got {len}"
            )));
        }

        // Sort by price (cheapest first) to ensure correct median selection
        quotes_with_prices.sort_by_key(|(_, price)| *price);

        // Get median price and calculate 3x
        let median_price = quotes_with_prices
            .get(MEDIAN_INDEX)
            .ok_or_else(|| {
                Error::Payment(format!(
                    "Missing median quote at index {MEDIAN_INDEX}: expected {CLOSE_GROUP_SIZE} quotes but get() failed"
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
            })
            .collect();

        // Convert Vec to array - we already validated length is CLOSE_GROUP_SIZE
        let quotes: [QuotePaymentInfo; CLOSE_GROUP_SIZE] = quotes_vec
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
    /// which should never happen since the array is fixed-size `[_; CLOSE_GROUP_SIZE]`.
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
            CLOSE_GROUP_SIZE,
            self.total_amount(),
            CLOSE_GROUP_SIZE - 1
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

    /// Verify that the median quote was paid at least 3× its price on-chain.
    ///
    /// Every node in the close group runs this same check: look up the median
    /// quote's on-chain payment amount and confirm it meets the 3× threshold.
    /// This ensures all 5 nodes can independently detect underpayment, not
    /// just the median node.
    ///
    /// # Returns
    ///
    /// The on-chain payment amount for the median quote.
    ///
    /// # Errors
    ///
    /// Returns an error if the on-chain lookup fails or the median quote
    /// was paid less than 3× its price.
    pub async fn verify(&self, network: &EvmNetwork) -> Result<Amount> {
        let median = &self.quotes[MEDIAN_INDEX];
        let expected_amount = median.amount;

        info!("Verifying median quote payment: expected at least {expected_amount} atto");

        let provider = evmlib::utils::http_provider(network.rpc_url().clone());
        let vault_address = *network.payment_vault_address();
        let contract =
            evmlib::contract::payment_vault::interface::IPaymentVault::new(vault_address, provider);

        let result = contract
            .completedPayments(median.quote_hash)
            .call()
            .await
            .map_err(|e| Error::Payment(format!("completedPayments lookup failed: {e}")))?;

        let on_chain_amount = Amount::from(result.amount);

        if on_chain_amount < expected_amount {
            return Err(Error::Payment(format!(
                "Median quote underpaid: on-chain {on_chain_amount}, expected at least {expected_amount}"
            )));
        }

        info!("Payment verified: {on_chain_amount} atto paid for median quote");
        Ok(on_chain_amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::node_bindings::{Anvil, AnvilInstance};
    use evmlib::testnet::{deploy_network_token_contract, deploy_payment_vault_contract, Testnet};
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
            price: Amount::from(1u64),
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
        let network_token = deploy_network_token_contract(&rpc_url, &node)
            .await
            .expect("deploy network token");
        let mut payment_vault =
            deploy_payment_vault_contract(&rpc_url, &node, *network_token.contract.address())
                .await
                .expect("deploy data payments");

        let transaction_config = TransactionConfig::default();

        // Create CLOSE_GROUP_SIZE random quote payments (autonomi pattern)
        let mut quote_payments = vec![];
        for _ in 0..CLOSE_GROUP_SIZE {
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

        // Verify payments via completedPayments mapping
        for (quote_hash, _reward_address, amount) in &quote_payments {
            let result = payment_vault
                .contract
                .completedPayments(*quote_hash)
                .call()
                .await
                .expect("completedPayments lookup failed");

            let on_chain_amount = result.amount;
            assert!(
                on_chain_amount >= u128::try_from(*amount).expect("amount fits u128"),
                "On-chain amount should be >= paid amount"
            );
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
        let network_token = deploy_network_token_contract(&rpc_url, &node)
            .await
            .expect("deploy network token");
        let mut payment_vault =
            deploy_payment_vault_contract(&rpc_url, &node, *network_token.contract.address())
                .await
                .expect("deploy data payments");

        let transaction_config = TransactionConfig::default();

        // CHANGE: Create 5 payments: 1 real (3x) + 4 dummy (0x)
        let real_quote_hash = dummy_hash();
        let real_reward_address = dummy_address();
        let real_amount = Amount::from(3u64); // 3x amount

        let mut quote_payments = vec![(real_quote_hash, real_reward_address, real_amount)];

        // Add dummy payments with 0 amount for remaining close group members
        for _ in 0..CLOSE_GROUP_SIZE - 1 {
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

        // Verify via completedPayments mapping

        // Check that real payment is recorded on-chain
        let real_result = payment_vault
            .contract
            .completedPayments(real_quote_hash)
            .call()
            .await
            .expect("completedPayments lookup failed");

        assert!(
            real_result.amount > 0,
            "Real payment should have non-zero amount on-chain"
        );
        println!("✓ Real payment verified (3 atto)");

        // Check dummy payments (should have 0 amount)
        for (i, (hash, _, _)) in quote_payments.iter().skip(1).enumerate() {
            let result = payment_vault
                .contract
                .completedPayments(*hash)
                .call()
                .await
                .expect("completedPayments lookup failed");

            println!("  Dummy payment {}: amount={}", i + 1, result.amount);
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
                price: Amount::from(*price),
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
        let quotes: Vec<_> = (1u8..)
            .take(CLOSE_GROUP_SIZE)
            .map(|i| (make_test_quote(i), Amount::from(u64::from(i) * 10)))
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
        let quotes: Vec<_> = (1u8..)
            .take(CLOSE_GROUP_SIZE)
            .map(|i| (make_test_quote(i), Amount::from(u64::from(i) * 10)))
            .collect();

        let payment = SingleNodePayment::from_quotes(quotes).unwrap();

        // Verify all quotes are present (sorting doesn't lose data)
        let mut addresses: Vec<_> = payment.quotes.iter().map(|q| q.rewards_address).collect();
        addresses.sort();
        addresses.dedup();
        assert_eq!(addresses.len(), CLOSE_GROUP_SIZE);
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
        let testnet = Testnet::new()
            .await
            .map_err(|e| Error::Payment(format!("Failed to start testnet: {e}")))?;
        let network = testnet.to_network();
        let wallet_key = testnet
            .default_wallet_private_key()
            .map_err(|e| Error::Payment(format!("Failed to get wallet key: {e}")))?;
        let wallet = Wallet::new_from_private_key(network.clone(), &wallet_key)
            .map_err(|e| Error::Payment(format!("Failed to create wallet: {e}")))?;

        println!("✓ Started Anvil testnet");

        // Approve tokens
        wallet
            .approve_to_spend_tokens(*network.payment_vault_address(), evmlib::common::U256::MAX)
            .await
            .map_err(|e| Error::Payment(format!("Failed to approve tokens: {e}")))?;

        println!("✓ Approved tokens");

        // Create 5 quotes with prices calculated from record counts
        let chunk_xor = XorName::random(&mut rand::thread_rng());

        let mut quotes_with_prices = Vec::new();
        for i in 0..CLOSE_GROUP_SIZE {
            let records_stored = 10 + i;
            let price = crate::payment::pricing::calculate_price(records_stored);

            let quote = PaymentQuote {
                content: chunk_xor,
                timestamp: SystemTime::now(),
                price,
                rewards_address: wallet.address(),
                pub_key: vec![],
                signature: vec![],
            };

            quotes_with_prices.push((quote, price));
        }

        println!("✓ Got 5 quotes with calculated prices");

        // Create SingleNode payment (will sort internally and select median)
        let payment = SingleNodePayment::from_quotes(quotes_with_prices)?;

        let median_price = payment
            .paid_quote()
            .ok_or_else(|| Error::Payment("Missing paid quote at median index".to_string()))?
            .amount
            .checked_div(Amount::from(3u64))
            .ok_or_else(|| Error::Payment("Failed to calculate median price".to_string()))?;
        println!("✓ Sorted and selected median price: {median_price} atto");

        assert_eq!(payment.quotes.len(), CLOSE_GROUP_SIZE);
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

        // Verify median quote payment — all nodes run this same check
        let verified_amount = payment.verify(&network).await?;
        let expected_median_amount = payment.quotes[MEDIAN_INDEX].amount;

        assert_eq!(
            verified_amount, expected_median_amount,
            "Verified amount should match median payment"
        );

        println!("✓ Payment verified: {verified_amount} atto");
        println!("\n✅ Complete SingleNode flow with real prices works!");

        Ok(())
    }
}
