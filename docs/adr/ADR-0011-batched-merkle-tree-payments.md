# ADR-0011: Batched Merkle Tree Payments (payForMerkleTrees)

- **Status:** Proposed
- **Date:** 2026-08-17
- **Decision owners:** Nic Dorman
- **Reviewers:** <pending>
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ADR-0008 (storage economics and payment protocol), Linear V2-949 (design), V2-989 (contract + evmlib), V2-990 (ant-core), V2-991 (ant-ui), V2-992 (deployment), [WithAutonomi/evmlib#15](https://github.com/WithAutonomi/evmlib/pull/15) (payForMerkleTrees)

## Context

External-signer uploads (ant-ui via WalletConnect/MetaMask, mobile SDKs) pay
per merkle tree: each ≤256-chunk (~1 GiB) tree is one `payForMerkleTree`
transaction, so a large upload costs one allowance approval plus **N wallet
confirmations**. Field experience with ant-ui 0.9.7 confirmed the N-approval
flow is painful (7 GB ≈ 7 confirmations).

Two facts shape the solution space:

- **Nodes are payment-tx-agnostic.** ant-node verifies merkle payments via the
  `getCompletedMerklePayment(winnerPoolHash)` state getter plus cryptographic
  checks against the pool; it never inspects the paying transaction, its
  calldata, or its events. All node caches are pool-hash/XorName-keyed.
  Batching N payments into one transaction therefore requires **zero node
  changes**.
- **The deployed vaults cannot be upgraded in place.** Both production vaults
  (Arbitrum One, Arbitrum Sepolia) are plain contracts — no proxy slots, no
  DELEGATECALL (verified on-chain 2026-08-17). A new entry point ships via
  redeployment and an evmlib address bump, with a node-first rollout
  (tracked in V2-992).

## Decision Drivers

- One wallet confirmation per ~4 GiB instead of one per ~1 GiB slice.
- Released clients (ant-ui 0.9.7, mobile SDK 0.0.7) must keep working
  unchanged against both old and new vaults.
- Arbitrum sequencer `TxMaxDataSize` (95,000 bytes) caps calldata per
  transaction; a depth-8 tree is ≈17 KiB of ABI-encoded calldata.
- Replay protection (`completedMerklePayments[winnerPoolHash]`) and the
  economic formula (`median16(prices) × 2^depth`, per-node transfers) must be
  preserved exactly.

## Considered Options

1. **Contract-level batch entry point `payForMerkleTrees(trees[])`** — one
   transaction, atomic, works with every wallet.
2. **EIP-5792 `wallet_sendCalls`** — batches at the wallet layer; availability
   and atomicity vary per wallet, no contract guarantee; unusable as the
   primary mechanism (remains a future additive lever).
3. **Multicall-style aggregator contract** — breaks the `msg.sender`-seeded
   winner selection and the allowance model (the aggregator would become the
   payer).
4. **Status quo with UX polish** — keeps N confirmations; rejected by field
   feedback.

## Decision

We will add an **additive** entry point to PaymentVaultV2 (option 1) and
redeploy:

```solidity
struct MerkleTreePayment {
    uint8 depth;
    uint64 merklePaymentTimestamp;
    PoolCommitment[] poolCommitments;
}

function payForMerkleTrees(MerkleTreePayment[] calldata trees)
    external returns (bytes32[] memory winnerPoolHashes, uint256 totalAmount);
```

- **All-or-nothing:** trees are processed in input order; any failing tree
  (depth, pool count, duplicate winner pool, transfer failure) reverts the
  whole transaction.
- **Events unchanged:** one `MerklePaymentMade` per tree, emitted in input
  order; clients attribute event → tree by log order. `winnerPoolHashes` is
  returned aligned to input order.
- **On-chain bound:** `MAX_TREES_PER_PAYMENT = 16`; the public constant getter
  doubles as the client feature probe against old deployments (revert/absent →
  legacy per-tree path).
- **Seed fix:** the winner-pool seed gains the tree index —
  `keccak(prevrandao, block.timestamp, msg.sender, ts, treeIndex)` — so trees
  paid in one transaction select winners independently. The legacy entry point
  passes index 0. Selection is computed and stored in the same transaction, so
  the formula change has no cross-transaction compatibility impact.
- **Economics unchanged:** per-node `safeTransferFrom` is retained; a batch
  costs exactly the sum of the per-tree costs, so summed-allowance semantics
  carry over.
- **Client-side cap:** evmlib exports `MERKLE_TREES_PER_PAYMENT = 4` as the
  recommended trees-per-transaction cap (≈4 GiB per confirmation) derived from
  the calldata sizing above; consumers chunk by this constant instead of
  hardcoding it. The on-chain 16 leaves headroom.
- **Back-compat:** `payForMerkleTree` is kept forever. The repo contract is
  also aligned with the deployed production source (`Ownable` +
  `setBatchLimit`), which the previous repo copy lacked.

evmlib grows the matching surface: `Wallet::pay_for_merkle_trees`,
`external_signer::pay_for_merkle_trees_calldata` (one calldata blob + approve
info), and a handler that decodes **all** `MerklePaymentMade` events of the
transaction in log order (the previous implementation decoded only the first).
Deterministic reverts surfaced at gas-estimation time now retain their revert
data, so contract errors like `PaymentAlreadyExists` reach callers as typed
errors instead of opaque strings after pointless retries.

## Consequences

### Positive

- One confirmation per ≤4 trees: a 7 GB upload drops from 7 confirmations
  to 2.
- Zero node changes; released clients unaffected; old vault keeps serving
  during the transition.
- Same-transaction winner-selection correlation is fixed by the seed change.
- Typed contract errors from estimation-time reverts improve every payment
  path (no more 3×-retry of deterministic reverts).

### Negative / Trade-offs

- Requires redeployment and a node-first rollout (fresh vault state; nodes
  verify against the vault address in their own config) — V2-992.
- All-or-nothing means one already-paid tree poisons its batch; clients must
  submit only unpaid trees (upload re-preparation already skips stored
  chunks, and `PaymentAlreadyExists` is now reliably surfaced).
- Uploads beyond the calldata cap still need multiple confirmations (7 GB =
  2); further levers (packed calldata, deeper trees, EIP-5792) are separate
  decisions.

### Neutral / Operational

- The seed formula changes for both entry points at the redeploy boundary;
  winner selection remains on-chain-only, so nothing off-chain recomputes it.
- New-vault ownership (EOA vs Safe) and deploy tooling are decided in V2-992.

## Validation

- **Foundry suite** (evmlib `test/PaymentVaultV2.t.sol`, 15 tests): event
  ordering + attribution, revert atomicity (wrong pool count mid-batch,
  depth-too-large, depth-0 panic, allowance short by one), duplicate winner
  within a batch and replay across entry points, seed decorrelation of
  identical trees, empty/oversized batch bounds, max-batch acceptance, legacy
  entry-point regression, `setBatchLimit` onlyOwner.
- **Anvil integration** (Rust): batched round trip via handler and via
  `Wallet`, duplicate rejection surfacing typed `PaymentAlreadyExists`,
  external-signer raw-calldata end-to-end (approve → submit calldata → verify
  one stored payment per tree).
- Before freezing the client cap at 4: real-wallet Arbitrum Sepolia test
  pushing a ~70–85 KiB batched payload through the WalletConnect relay
  (V2-991), plus a LAN devnet rerun of the full upload path (V2-990/991).
- Review trigger: any change to tree depth economics (depth > 8) or to
  Arbitrum's `TxMaxDataSize` revisits `MERKLE_TREES_PER_PAYMENT`.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without
human review**. Accepted ADRs are immutable: create a new superseding ADR
rather than editing an Accepted ADR.
