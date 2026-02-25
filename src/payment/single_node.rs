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
        if quotes_with_prices.len() != REQUIRED_QUOTES {
            return Err(Error::Payment(format!(
                "SingleNode payment requires exactly {} quotes, got {}",
                REQUIRED_QUOTES,
                quotes_with_prices.len()
            )));
        }

        // Sort by price (cheapest first) to ensure correct median selection
        quotes_with_prices.sort_by_key(|(_, price)| *price);

        // Get median price and calculate 3x
        let median_price = quotes_with_prices
            .get(MEDIAN_INDEX)
            .ok_or_else(|| Error::Payment("Missing median quote".to_string()))?
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
    /// This always returns a valid reference since the array is fixed-size
    /// and `MEDIAN_INDEX` is guaranteed to be in bounds.
    #[must_use]
    pub fn paid_quote(&self) -> &QuotePaymentInfo {
        &self.quotes[MEDIAN_INDEX]
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

        // Collect transaction hashes for all quotes
        // Note: wallet may not return tx_hash for zero-amount payments
        let result_hashes: Vec<_> = self
            .quotes
            .iter()
            .filter_map(|quote_info| {
                if let Some(&tx_hash) = tx_hashes.get(&quote_info.quote_hash) {
                    Some(Ok(tx_hash))
                } else if quote_info.amount != Amount::ZERO {
                    // Non-zero amount should have a transaction hash
                    Some(Err(Error::Payment(format!(
                        "Missing transaction hash for non-zero quote {} (amount: {})",
                        quote_info.quote_hash, quote_info.amount
                    ))))
                } else {
                    // Zero-amount payments may not get a transaction
                    None
                }
            })
            .collect::<Result<Vec<_>>>()?;

        info!(
            "Payment successful: {} transactions (expected 1-5)",
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
        // Use zero metrics for verification (contract doesn't validate them)
        let zero_metrics = QuotingMetrics {
            data_size: 0,
            data_type: 0,
            close_records_stored: 0,
            records_per_type: vec![],
            max_records: 0,
            received_payment_count: 0,
            live_time: 0,
            network_density: None,
            network_size: None,
        };

        // Build payment digest for all 5 quotes
        let payment_digest: Vec<_> = self
            .quotes
            .iter()
            .map(|q| (q.quote_hash, zero_metrics.clone(), q.rewards_address))
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
    use evmlib::testnet::{deploy_data_payments_contract, deploy_network_token_contract};
    use evmlib::transaction_config::TransactionConfig;
    use evmlib::utils::{dummy_address, dummy_hash};
    use reqwest::Url;

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

    /// Step 1: Exact copy of autonomi's `test_verify_payment_on_local`
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn test_exact_copy_of_autonomi_verify_payment() {
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
                metrics: QuotingMetrics {
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
                .into(),
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

        println!("✓ All {} payments verified successfully", 5);
        println!("\n✅ Exact autonomi pattern works!");
    }

    /// Step 3: Pay 3x for ONE quote and 0 for the other 4 (`SingleNode` mode)
    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn test_step3_single_node_payment_pattern() {
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
                metrics: QuotingMetrics {
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
                .into(),
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

        println!("\n✅ Step 3: SingleNode pattern (1 real + 4 dummy) works!");
    }

    /// Step 4: Complete `SingleNode` payment flow with real quotes
    #[tokio::test]
    async fn test_step4_complete_single_node_payment_flow() -> Result<()> {
        use evmlib::testnet::Testnet;
        use evmlib::wallet::Wallet;
        use std::time::SystemTime;
        use xor_name::XorName;

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
            let prices = payment_vault::get_market_price(&network, vec![quoting_metrics.clone()])
                .await
                .map_err(|e| Error::Payment(format!("Failed to get market price: {e}")))?;

            let price = prices.first().ok_or_else(|| {
                Error::Payment("Empty price list from get_market_price".to_string())
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
            .amount
            .checked_div(Amount::from(3u64))
            .ok_or_else(|| Error::Payment("Failed to calculate median price".to_string()))?;
        println!("✓ Sorted and selected median price: {median_price} atto");

        assert_eq!(payment.quotes.len(), REQUIRED_QUOTES);
        let median_amount = payment
            .quotes
            .get(MEDIAN_INDEX)
            .ok_or_else(|| Error::Payment("Missing median quote".to_string()))?
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
            .ok_or_else(|| Error::Payment("Missing median quote".to_string()))?;
        let median_quote_hash = median_quote.quote_hash;
        let verified_amount = payment.verify(&network, Some(median_quote_hash)).await?;

        assert_eq!(
            verified_amount, median_quote.amount,
            "Verified amount should match median payment"
        );

        println!("✓ Payment verified: {verified_amount} atto");
        println!("\n✅ Step 4: Complete SingleNode flow with real quotes works!");

        Ok(())
    }
}
