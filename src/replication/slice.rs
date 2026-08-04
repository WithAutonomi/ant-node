//! BLAKE3 verified-slice possession proofs for the storage-commitment audit
//! (ADR-0002 round 2, V2-685).
//!
//! The audit's round 2 used to make a challenged peer return the **complete
//! original bytes** of the sampled chunks (up to two 4 MiB chunks per response),
//! at 5.8 to 6.2 MB per response measured in production. What that cost the
//! fleet per day moved with the audit *rate*, not the response size, so
//! frequency caps could move the daily total but never the cost of an
//! individual audit. This module replaces the response shape instead: one
//! opened 1 KiB block is a few KB rather than a full chunk, about 427x smaller,
//! and that holds whatever the rate does.
//!
//! Two axes move in opposite directions, and it is worth separating them. The
//! *freshness* construction gets strictly stronger: the nonce now enters every
//! block leaf, closing a preprocessing gap in the old flat `nonced_hash`. The
//! *coverage* gets weaker: round 2 samples blocks instead of checking every
//! byte. See "What a pass does and does not prove" below — that trade is the
//! whole design, not a footnote to it.
//!
//! ## Why two chains
//!
//! A chunk's address is `BLAKE3(content)` (its content hash), and BLAKE3 is
//! internally a Merkle tree over 1 KiB blocks, so a **Bao verified slice** proves
//! that a given block is the real content at a given offset *against the address
//! the auditor already knows* — content authenticity, for free, no full chunk.
//! But authenticity alone is checkable from purely public data (the address is
//! public), so a node that stores nothing could pass it by fetching the block on
//! demand from an honest holder. To bind **possession at commitment time** the
//! responder also commits, per leaf in round 1, a fresh **nonced block tree**:
//! a Merkle root over the same 1 KiB blocks whose leaves are **keyed** BLAKE3
//! hashes, `keyed_BLAKE3(key=f(nonce ‖ peer ‖ key), block_index ‖ len ‖ block)`.
//!
//! The nonce is fed as the BLAKE3 **key**, not a message prefix, so it mixes
//! into every chunk compression of every block leaf: there is no
//! nonce-independent chaining value a responder can precompute across audits.
//! (A plain `BLAKE3(nonce ‖ … ‖ block)` prefix would leave the block's tail in a
//! second, nonce-free BLAKE3 chunk whose CV is precomputable, letting a node
//! store ~10.7% less than each block and still reconstruct the leaf for any
//! fresh nonce — a smaller version of the old flat-`nonced_hash` gap.) Building
//! the *correct* `nonced_root` therefore requires all of a chunk's bytes at
//! round-1 commit time, and the auditor picks which block to open with fresh
//! randomness *after* the roots are committed (cut-and-choose): a responder
//! cannot connect a real, after-the-fact-fetched block to a garbage committed
//! root without a preimage break.
//!
//! In round 2 the auditor verifies both chains over the **same** block bytes:
//! the Bao chain against the address (authenticity) and the nonced chain against
//! the round-1 `nonced_root` (possession). Either failing is a confirmed cheat.
//!
//! ## What a pass does and does not prove
//!
//! This is a **sampling** check, and the strength claim should be read as such.
//! The auditor holds none of the audited bytes, so it cannot tell a correct
//! `nonced_root` from a responder-chosen one. A peer holding a fraction `p` of a
//! chunk's blocks can commit a root built from real leaves for the blocks it
//! kept and arbitrary leaves for the rest, and it passes whenever every fresh
//! draw lands on a kept block. Per audit that is roughly `p^leaves` over the
//! 3..=5 sampled leaves; the mandatory final-block opening pins the claimed
//! length but adds no detection, since a partial holder simply keeps the final
//! block.
//!
//! So a pass means "held the sampled blocks at commit time", and repeated audits
//! drive the probability of sustained under-storage down geometrically rather
//! than catching it outright on the first try. The full-byte round 2 this
//! replaces caught any missing byte of a sampled chunk with certainty — that is
//! the difference, and it is inherent: verifying every byte means moving every
//! byte.
//!
//! For `p^leaves` to describe *detection* rather than merely a pass, declining
//! to answer must not be cheaper than answering. The responder sees the drawn
//! blocks before it replies, so an unanswered round 2 following a valid round-1
//! proof revokes the holder credit for the commitment under audit (see
//! `storage_commitment_audit::round2_revokes_pinned_credit`). It stays in the
//! graced timeout lane and costs no trust, so an honest dropped reply is
//! harmless; what it removes is the option of holding credit while never
//! completing a possession check.
//!
//! Be precise about the comparison, in both directions:
//!
//! - Against a node under-storing **in bulk** — the realistic case, a node
//!   dropping data to save disk — detection is close to what the full-byte
//!   audit gave, at roughly 1/430 of the egress (measured about 427x on a
//!   same-network control cohort: 14.49 KB against 6.19 MB). A 990-node run
//!   caught a 256 MB in-place corruption on the first audit that reached the
//!   node.
//! - Against a **fine-grained** partial deleter, one shaving a little off every
//!   chunk, this is strictly weaker per audit than serving every byte. The
//!   compensating lever is audit *frequency*, which is exactly what the cost
//!   reduction buys: the old shape made frequent auditing unaffordable.
//!
//! If a threat model ever needs sharper per-audit detection, the knob is
//! openings per leaf, at linear egress cost.

use std::io::{Cursor, Read};

use crate::ant_protocol::XorName;

/// Block size for slice audits: one BLAKE3 chunk (1 KiB). A block is the unit
/// both the Bao authenticity proof and the nonced possession tree open on.
///
/// Matching BLAKE3's internal 1 KiB chunk means a single opened block maps to a
/// single BLAKE3 leaf, so the Bao proof for one block is minimal.
pub const AUDIT_BLOCK_SIZE: u64 = 1024;

/// Domain tag for a nonced block-tree leaf. Distinct from every other hash in
/// the protocol so a leaf can never be reinterpreted as a node or a commitment.
const DOMAIN_BLOCK_LEAF: &[u8] = b"autonomi.ant.audit.slice.block-leaf.v1";

/// Domain tag for a nonced block-tree internal node.
const DOMAIN_BLOCK_NODE: &[u8] = b"autonomi.ant.audit.slice.block-node.v1";

/// Domain-separation context for deriving the per-audit BLAKE3 key of the
/// nonced block tree.
///
/// Versioned alongside the subtree-audit protocol id and distinct from every
/// other BLAKE3 use in the replication subsystem.
const BLOCK_KEY_CONTEXT: &str = "autonomi.ant.audit.slice.block-key.v1";

/// Per-audit keying material for the nonced block tree, derived from the fresh
/// nonce, the challenged peer and the chunk key. Constant across a chunk's blocks.
///
/// Uses BLAKE3's `derive_key` mode. `derive_key` separates domains at the mode
/// level (its own flag bits), so this key cannot collide with a plain or keyed
/// hash of the same bytes; a plain hash over a domain prefix would separate only
/// by convention.
///
/// The result is then used as a BLAKE3 **key**, not a message prefix. That is
/// what forces every BLAKE3 chunk of a block leaf to depend on the nonce: keyed
/// BLAKE3 mixes the key into the initial state of every chunk compression, so
/// there is no nonce-independent chaining value. Prefixing the nonce instead
/// leaves the block's tail in a second, nonce-free BLAKE3 chunk whose chaining
/// value is precomputable (leaf input is `domain ‖ nonce ‖ … ‖ block`, ~1166
/// bytes, so the last ~142 block bytes fall in chunk 1 with no nonce), letting a
/// node store ~10.7% less than each block and still reconstruct the leaf for any
/// fresh nonce.
///
#[must_use]
fn nonced_block_key(nonce: &[u8; 32], peer: &[u8; 32], key: &XorName) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(BLOCK_KEY_CONTEXT);
    h.update(nonce);
    h.update(peer);
    h.update(key);
    *h.finalize().as_bytes()
}

/// Number of 1 KiB blocks covering `content_len` bytes.
///
/// Always at least 1 (an empty chunk is one empty block) so every committed key
/// opens at least one block, and the block index the auditor draws is always in
/// range.
#[must_use]
pub fn block_count(content_len: u64) -> u32 {
    if content_len == 0 {
        return 1;
    }
    u32::try_from(content_len.div_ceil(AUDIT_BLOCK_SIZE)).unwrap_or(u32::MAX)
}

/// Byte range `[start, end)` of block `index` within `content_len` bytes.
///
/// The final block may be short; an out-of-range index clamps to an empty range
/// at `content_len` (callers never pass one — the auditor draws indices in
/// `0..block_count`).
#[must_use]
pub fn block_range(content_len: u64, index: u32) -> (u64, u64) {
    let start = u64::from(index)
        .saturating_mul(AUDIT_BLOCK_SIZE)
        .min(content_len);
    let end = start.saturating_add(AUDIT_BLOCK_SIZE).min(content_len);
    (start, end)
}

/// Slice a block's bytes out of a full chunk. Returns an empty slice for an
/// out-of-range index (never happens for auditor-drawn indices).
#[must_use]
fn block_bytes(content: &[u8], index: u32) -> &[u8] {
    let (start, end) = block_range(content.len() as u64, index);
    let start = usize::try_from(start).unwrap_or(usize::MAX);
    let end = usize::try_from(end).unwrap_or(usize::MAX);
    content.get(start..end).unwrap_or(&[])
}

/// Nonced block-leaf hash: keyed by the per-audit key (nonce/peer/key) so every
/// BLAKE3 chunk of the leaf depends on the nonce, binding the block index, block
/// length and block bytes with no nonce-independent state to precompute.
///
/// See [`nonced_block_key`] for why the nonce is a key, not a prefix.
#[must_use]
fn nonced_block_leaf(
    nonce: &[u8; 32],
    peer: &[u8; 32],
    key: &XorName,
    index: u32,
    block: &[u8],
) -> [u8; 32] {
    let audit_key = nonced_block_key(nonce, peer, key);
    let mut h = blake3::Hasher::new_keyed(&audit_key);
    h.update(DOMAIN_BLOCK_LEAF);
    h.update(&index.to_le_bytes());
    let block_len = u32::try_from(block.len()).unwrap_or(u32::MAX);
    h.update(&block_len.to_le_bytes());
    h.update(block);
    *h.finalize().as_bytes()
}

/// Combine two child hashes into a nonced block-tree internal node.
#[must_use]
fn nonced_block_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_BLOCK_NODE);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Fold one level of a left-packed Merkle tree, self-pairing an unpaired last
/// node (`node(x, x)`) exactly like the commitment tree.
#[must_use]
fn fold_level(level: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        let left = level.get(i).copied().unwrap_or([0u8; 32]);
        // Self-pair the last node when the level has an odd length.
        let right = level.get(i + 1).copied().unwrap_or(left);
        next.push(nonced_block_node(&left, &right));
        i += 2;
    }
    next
}

/// The nonced block-tree leaves for a chunk's `content`, in block order.
#[must_use]
fn nonced_leaves(
    nonce: &[u8; 32],
    peer: &[u8; 32],
    key: &XorName,
    content: &[u8],
) -> Vec<[u8; 32]> {
    let count = block_count(content.len() as u64);
    (0..count)
        .map(|i| nonced_block_leaf(nonce, peer, key, i, block_bytes(content, i)))
        .collect()
}

/// Compute the nonced block-tree root over a chunk's `content` (responder, round
/// 1). Requires every byte of the chunk, under the fresh nonce.
#[must_use]
pub fn nonced_block_root(
    nonce: &[u8; 32],
    peer: &[u8; 32],
    key: &XorName,
    content: &[u8],
) -> [u8; 32] {
    let mut level = nonced_leaves(nonce, peer, key, content);
    // A single leaf is its own root (matches the commitment tree's convention).
    while level.len() > 1 {
        level = fold_level(&level);
    }
    level.first().copied().unwrap_or([0u8; 32])
}

/// Sibling hashes on the path from block `index` up to the nonced root,
/// bottom-up (leaf level first). `None` if `index` is out of range for the tree.
///
/// The verifier folds the recomputed leaf with these siblings using node-index
/// parity, so the sibling ordering is positional, not left/right-tagged.
#[must_use]
pub fn nonced_block_siblings(
    nonce: &[u8; 32],
    peer: &[u8; 32],
    key: &XorName,
    content: &[u8],
    index: u32,
) -> Option<Vec<[u8; 32]>> {
    siblings_from_leaves(&nonced_leaves(nonce, peer, key, content), index)
}

/// Sibling chain for `index` from prebuilt nonced leaves (no per-leaf rehash).
///
/// Folding 32-byte CVs is cheap; the cost is computing the leaves, so callers
/// that open several blocks of one chunk build the leaves once and fold here per
/// block. `None` if `index` is out of range.
#[must_use]
fn siblings_from_leaves(leaves: &[[u8; 32]], index: u32) -> Option<Vec<[u8; 32]>> {
    if usize::try_from(index).ok()? >= leaves.len() {
        return None;
    }
    let mut level = leaves.to_vec();
    let mut node_index = index as usize;
    let mut siblings = Vec::new();
    while level.len() > 1 {
        // Sibling is the other child of this node's parent; the last node of an
        // odd level self-pairs, so its sibling is itself.
        let sibling_index = node_index ^ 1;
        let sibling = level
            .get(sibling_index)
            .or_else(|| level.get(node_index))
            .copied()
            .unwrap_or([0u8; 32]);
        siblings.push(sibling);
        node_index /= 2;
        level = fold_level(&level);
    }
    Some(siblings)
}

/// Verify a nonced block opening (auditor, round 2): recompute the block leaf
/// from the served bytes and fold it with `siblings` to the committed
/// `nonced_root`.
///
/// `block` must be the Bao-verified block bytes for `index`, so this proves the
/// responder committed a nonced root over the *real* content at round-1 time.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_nonced_block(
    nonce: &[u8; 32],
    peer: &[u8; 32],
    key: &XorName,
    index: u32,
    block: &[u8],
    siblings: &[[u8; 32]],
    nonced_root: &[u8; 32],
    block_count: u32,
) -> bool {
    // Enforce the canonical tree geometry: the sibling chain MUST be exactly the
    // depth of a `block_count`-leaf tree. `nonced_root` is responder-chosen in
    // round 1, so without this a partial holder could set `nonced_root` to a
    // single block's leaf and pass with zero siblings whenever the fresh draw
    // happens to land on that block. Pinning the depth binds the claimed
    // left-packed geometry and rejects such degraded proofs.
    if siblings.len() != nonced_tree_depth(block_count) {
        return false;
    }
    // An index past the last block names no leaf of the committed tree, so there
    // is nothing it could legitimately open. Production requests are always in
    // range; rejecting here makes a malformed or forged one fail deterministically
    // and cheaply, rather than folding a hash chain to reach the same answer.
    if index >= block_count {
        return false;
    }
    let mut node_index = index as usize;
    let mut cur = nonced_block_leaf(nonce, peer, key, index, block);
    for sibling in siblings {
        cur = if node_index % 2 == 0 {
            nonced_block_node(&cur, sibling)
        } else {
            nonced_block_node(sibling, &cur)
        };
        node_index /= 2;
    }
    &cur == nonced_root
}

/// Canonical sibling-chain length for a `block_count`-leaf nonced tree.
///
/// The number of `div_ceil(2)` folds from the leaf level down to a single root
/// (0 for a single-block chunk). Matches [`nonced_block_siblings`]'s output.
#[must_use]
pub fn nonced_tree_depth(block_count: u32) -> usize {
    let mut n = block_count.max(1) as usize;
    let mut depth = 0;
    while n > 1 {
        n = n.div_ceil(2);
        depth += 1;
    }
    depth
}

/// Extract a Bao verified slice for block `index` of `content` (responder, round
/// 2). The slice carries the block bytes plus the O(log n) BLAKE3 parent hashes
/// that verify it against the chunk address.
///
/// # Errors
///
/// Returns the underlying IO error only if the in-memory Bao extraction fails,
/// which cannot happen for a well-formed in-memory chunk; surfaced as a
/// `Result` rather than a panic so the responder degrades to a rejection.
pub fn extract_block_slice(content: &[u8], index: u32) -> std::io::Result<Vec<u8>> {
    // The outboard carries the BLAKE3 tree hashes separately from the content, so
    // the extractor reads the real chunk bytes plus just the parent hashes on the
    // block's path — no need to materialise a full Bao encoding of the chunk.
    let (outboard, _hash) = bao::encode::outboard(content);
    extract_block_slice_with_outboard(content, &outboard, index)
}

/// Extract a Bao verified slice for block `index` reusing a prebuilt `outboard`.
///
/// Building the outboard hashes the whole chunk, so when several blocks of the
/// same chunk are opened in one challenge (round + final, plus any dedup), the
/// caller builds the outboard once (see [`ChunkOpener`]) and calls this per
/// block instead of re-hashing. Borrows `content` directly (no copy).
///
/// # Errors
///
/// Surfaces an in-memory Bao extraction error as a `Result` rather than a panic;
/// it cannot happen for a well-formed in-memory chunk and outboard.
pub fn extract_block_slice_with_outboard(
    content: &[u8],
    outboard: &[u8],
    index: u32,
) -> std::io::Result<Vec<u8>> {
    let (start, end) = block_range(content.len() as u64, index);
    let len = end - start;
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        Cursor::new(content),
        Cursor::new(outboard),
        start,
        len,
    );
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;
    Ok(slice)
}

/// Reusable per-chunk responder state for building round-2 openings.
///
/// Building the Bao outboard and the nonced block-tree leaves each hash the full
/// chunk. When one challenge opens several blocks of the same chunk (the normal
/// random + final pair, plus any duplicates), doing that work once and serving
/// every opening from it keeps a multi-opening challenge to a single hashing pass
/// over the bytes instead of one per opening (V2-685 round-2 amplification fix).
pub struct ChunkOpener<'a> {
    content: &'a [u8],
    outboard: Vec<u8>,
    leaves: Vec<[u8; 32]>,
}

impl<'a> ChunkOpener<'a> {
    /// Build the chunk's reusable opening state once: its Bao outboard and its
    /// nonced block-leaves (two hash passes over the resident chunk). Repeated
    /// openings of the same chunk reuse this state instead of rehashing per opening.
    #[must_use]
    pub fn new(nonce: &[u8; 32], peer: &[u8; 32], key: &XorName, content: &'a [u8]) -> Self {
        let (outboard, _hash) = bao::encode::outboard(content);
        let leaves = nonced_leaves(nonce, peer, key, content);
        Self {
            content,
            outboard,
            leaves,
        }
    }

    /// Number of 1 KiB blocks in the chunk (always ≥ 1).
    #[must_use]
    pub fn block_count(&self) -> u32 {
        u32::try_from(self.leaves.len()).unwrap_or(u32::MAX)
    }

    /// Bao verified slice for `index`, reusing the prebuilt outboard.
    ///
    /// # Errors
    /// Surfaces an in-memory Bao extraction error as a `Result` rather than a panic.
    pub fn bao_slice(&self, index: u32) -> std::io::Result<Vec<u8>> {
        extract_block_slice_with_outboard(self.content, &self.outboard, index)
    }

    /// Nonced-tree sibling chain for `index`, reusing the prebuilt leaves.
    #[must_use]
    pub fn nonced_siblings(&self, index: u32) -> Option<Vec<[u8; 32]>> {
        siblings_from_leaves(&self.leaves, index)
    }
}

/// Size of the Bao slice's leading length header (a little-endian `u64` giving
/// the encoded content's total length, in bytes). This is the first field of
/// every Bao slice; the decoder authenticates it against the tree root, so it
/// cannot be forged to disagree with the `address` the slice verifies against.
const BAO_LENGTH_HEADER_SIZE: usize = 8;

/// Verify a Bao slice for block `index` against the chunk `address`
/// (`BLAKE3(content)`), returning the verified block bytes (auditor, round 2).
///
/// `content_len` is the responder's round-1 claim. It is NOT bound by the signed
/// commitment (the Merkle leaf hashes only `key ‖ bytes_hash`), so a malicious
/// responder can claim any length. Left unchecked, a **deflation** lie forges
/// possession: claiming `content_len = 1024` for a 4 MiB chunk collapses
/// `block_count` to 1, so the auditor can only ever open block 0, and a Bao
/// slice for the prefix range `[0, 1024)` verifies fine against the true
/// full-content address — a node storing ~1 KiB passes an audit for the whole
/// chunk. To close this, the slice's own authenticated length header (which the
/// decoder validates against `address`, so it equals the *true* content length)
/// must match the claimed `content_len`. A responder that lies about the length
/// then either fails the header check (claim ≠ true length) or is forced to
/// report the true length — in which case the block index is drawn from the full
/// range and possession of all blocks is required.
#[must_use]
pub fn verify_block_slice(
    slice: &[u8],
    address: &[u8; 32],
    content_len: u64,
    index: u32,
) -> Option<Vec<u8>> {
    // Authenticate the claimed length against the slice's own header before
    // trusting `content_len` for the block range. The header is the first 8
    // bytes of every Bao slice and is validated against `address` by the decode
    // below (a forged header changes the tree shape and fails the root check),
    // so requiring it to equal `content_len` forces the claim to be the true
    // content length — defeating the deflation forgery described above.
    let header = slice.get(..BAO_LENGTH_HEADER_SIZE)?;
    let declared_len = u64::from_le_bytes(header.try_into().ok()?);
    if declared_len != content_len {
        return None;
    }

    // Reject an out-of-range index outright. `block_range` clamps one to the
    // empty range `[content_len, content_len)`, which would decode to an empty
    // block and return `Some(vec![])` — a malformed request reading as a
    // partially valid answer. Nothing legitimate opens a block that does not
    // exist.
    if index >= block_count(content_len) {
        return None;
    }

    let (start, end) = block_range(content_len, index);
    let len = end - start;
    let hash = blake3::Hash::from_bytes(*address);
    let mut decoder = bao::decode::SliceDecoder::new(Cursor::new(slice), &hash, start, len);
    let mut verified = Vec::new();
    decoder.read_to_end(&mut verified).ok()?;
    if verified.len() as u64 != len {
        return None;
    }
    Some(verified)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    const NONCE: [u8; 32] = [0x11; 32];
    const PEER: [u8; 32] = [0x22; 32];
    const KEY: XorName = [0x33; 32];

    /// Deterministic pseudo-content of a given length (avoids RNG in tests).
    fn content_of(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 + 7) as u8).collect()
    }

    // -- block geometry -----------------------------------------------------

    #[test]
    fn block_count_is_ceil_with_empty_floor() {
        assert_eq!(block_count(0), 1);
        assert_eq!(block_count(1), 1);
        assert_eq!(block_count(1024), 1);
        assert_eq!(block_count(1025), 2);
        assert_eq!(block_count(4096), 4);
        assert_eq!(block_count(4 * 1024 * 1024), 4096);
        assert_eq!(block_count(4 * 1024 * 1024 - 1), 4096);
    }

    #[test]
    fn block_range_covers_content_without_gaps_or_overlap() {
        let len = 1024 * 3 + 500;
        let count = block_count(len);
        let mut expected_start = 0u64;
        for i in 0..count {
            let (s, e) = block_range(len, i);
            assert_eq!(s, expected_start);
            assert!(e <= len);
            assert!(e > s || len == 0);
            expected_start = e;
        }
        assert_eq!(expected_start, len);
    }

    // -- bao slice == blake3 address ---------------------------------------

    #[test]
    fn bao_root_equals_blake3_address_across_lengths() {
        // The whole design rests on Bao's root being the chunk's BLAKE3 address.
        for len in [0usize, 1, 1023, 1024, 1025, 2048, 4096, 10_000, 1 << 20] {
            let content = content_of(len);
            let (_outboard, bao_hash) = bao::encode::outboard(&content);
            let blake = blake3::hash(&content);
            assert_eq!(
                bao_hash.as_bytes(),
                blake.as_bytes(),
                "bao root must equal blake3(content) at len {len}"
            );
        }
    }

    // Both verifiers reject a block index past the end of the chunk. Nothing the
    // auditor generates is ever out of range, so this is about failing cleanly:
    // `block_range` clamps an over-large index to an empty range, which without
    // the check reads back as a successfully verified empty block rather than as
    // the malformed request it is.
    #[test]
    fn verifiers_reject_a_block_index_past_the_end() {
        let len = 4096usize;
        let content = content_of(len);
        let address = *blake3::hash(&content).as_bytes();
        let count = block_count(len as u64);

        // A real slice for the last block does not become a valid opening for a
        // block that does not exist.
        let slice = extract_block_slice(&content, count - 1).expect("extract");
        assert!(
            verify_block_slice(&slice, &address, len as u64, count).is_none(),
            "the first index past the end must be rejected, not read as empty"
        );
        assert!(verify_block_slice(&slice, &address, len as u64, u32::MAX).is_none());

        // Same on the possession chain, with a genuine sibling path.
        let siblings =
            nonced_block_siblings(&NONCE, &PEER, &KEY, &content, count - 1).expect("siblings");
        let root = nonced_block_root(&NONCE, &PEER, &KEY, &content);
        let (s, e) = block_range(len as u64, count - 1);
        let block = &content[s as usize..e as usize];
        assert!(
            !verify_nonced_block(&NONCE, &PEER, &KEY, count, block, &siblings, &root, count),
            "an index past the last leaf names nothing in the committed tree"
        );
    }

    #[test]
    fn slice_roundtrip_verifies_every_block() {
        for len in [1usize, 1024, 1025, 4096, 5000, 1 << 16] {
            let content = content_of(len);
            let address = *blake3::hash(&content).as_bytes();
            let count = block_count(len as u64);
            for i in 0..count {
                let slice = extract_block_slice(&content, i).expect("extract");
                let verified =
                    verify_block_slice(&slice, &address, len as u64, i).expect("verify slice");
                let (s, e) = block_range(len as u64, i);
                assert_eq!(verified.as_slice(), &content[s as usize..e as usize]);
            }
        }
    }

    // Regression: content_len deflation must NOT forge possession.
    //
    // `content_len` is not bound by the signed round-1 commitment (the Merkle
    // leaf hashes only key+bytes_hash), so a malicious responder can claim
    // content_len=1024 for a 1 MiB chunk. That would collapse block_count to 1,
    // let the auditor only ever open block 0, and — before the fix — pass a Bao
    // slice for the prefix [0,1024) against the true full-content address while
    // storing ~1 KiB. verify_block_slice now authenticates the slice's own length
    // header against the claim, so the deflation is rejected at chain 1.
    #[test]
    fn content_len_deflation_is_rejected() {
        let full = content_of(1 << 20); // 1 MiB chunk, truly 1024 blocks.
        let address = *blake3::hash(&full).as_bytes();

        // Attacker keeps only the first block's Bao slice (extracted honestly for
        // range [0,1024) of the real content), discarding the rest of the 1 MiB.
        let stored_slice = extract_block_slice(&full, 0).expect("extract block 0");

        // Round 1: attacker claims content_len = 1024 (one block).
        let claimed_len = 1024u64;
        assert_eq!(block_count(claimed_len), 1, "deflated claim = one block");

        // Round 2: only block 0 could be drawn. Chain 1 must reject because the
        // slice's authenticated length header (1 MiB) disagrees with the claim.
        assert!(
            verify_block_slice(&stored_slice, &address, claimed_len, 0).is_none(),
            "deflated content_len must fail the slice length-header check"
        );

        // An honest responder reporting the true length still verifies block 0.
        let honest = verify_block_slice(&stored_slice, &address, (1 << 20) as u64, 0);
        assert_eq!(
            honest.expect("honest full-length slice must verify").len(),
            1024
        );
    }

    /// Rewrite a Bao slice's 8-byte little-endian length header in place.
    fn rewrite_slice_len(slice: &mut [u8], forged_len: u64) {
        slice[..BAO_LENGTH_HEADER_SIZE].copy_from_slice(&forged_len.to_le_bytes());
    }

    // Regression for the header-rewrite length forgery (the residual attack the
    // plain header==content_len check does NOT catch on its own).
    //
    // Bao does not cryptographically bind the length header for a PREFIX slice
    // that never touches EOF: the unopened right subtree is an opaque hash. So an
    // attacker can claim `content_len` just past a subtree boundary (e.g. 2 KiB+1
    // for a 4 KiB / 4-block chunk), REWRITE each slice header to that forged
    // length, supply the true right-subtree CV as the opaque root sibling, and
    // pass any opening in the retained left half — storing only that half. The
    // header check passes because header == forged content_len.
    //
    // The defence is to ALSO open the CLAIMED FINAL block: that decode reaches
    // EOF, where Bao authenticates the encoded length against the address, so a
    // forged-short length fails. This test shows both halves: a left-half opening
    // slips past the header check, but the final-block opening rejects the forgery.
    #[test]
    fn header_rewrite_length_forgery_is_caught_at_the_final_block() {
        // True chunk: 4 blocks. Root = parent(parent(b0,b1), parent(b2,b3)).
        let full = content_of(4096);
        let address = *blake3::hash(&full).as_bytes();

        // Forged length: 2049 bytes → block_count 3 (b0, b1 full, b2' one byte).
        // The claimed final block is index 2; blocks 0..2 are the retained half.
        let forged_len = 2049u64;
        assert_eq!(block_count(forged_len), 3);
        let forged_final = block_count(forged_len) - 1;

        // Left-half opening (block 0): the attacker rewrites an honest block-0
        // slice's header to the forged length. The retained slice already carries
        // the true right-subtree CV as the opaque root sibling, so it verifies
        // against the real address AND passes the header==content_len check.
        let mut left = extract_block_slice(&full, 0).expect("extract block 0");
        rewrite_slice_len(&mut left, forged_len);
        assert!(
            verify_block_slice(&left, &address, forged_len, 0).is_some(),
            "header rewrite lets a left-half opening slip past the header check — \
             this is exactly why the final block must also be opened"
        );

        // Final-block opening (block 2 under the forged length): no slice the
        // attacker can offer verifies, because reaching the forged EOF forces Bao
        // to authenticate the length against the true address. The best attempt —
        // an honest block-2 slice of the true content with a rewritten header —
        // is rejected.
        let mut fake_final = extract_block_slice(&full, 2).expect("extract block 2");
        rewrite_slice_len(&mut fake_final, forged_len);
        assert!(
            verify_block_slice(&fake_final, &address, forged_len, forged_final).is_none(),
            "final-block opening under a forged short length must fail (EOF length auth)"
        );
    }

    #[test]
    fn slice_against_wrong_address_fails() {
        let content = content_of(4096);
        let mut wrong = *blake3::hash(&content).as_bytes();
        wrong[0] ^= 0x01;
        let slice = extract_block_slice(&content, 2).expect("extract");
        assert!(verify_block_slice(&slice, &wrong, 4096, 2).is_none());
    }

    #[test]
    fn tampered_slice_bytes_fail_verification() {
        let content = content_of(4096);
        let address = *blake3::hash(&content).as_bytes();
        let mut slice = extract_block_slice(&content, 1).expect("extract");
        // Corrupt the payload bytes near the end of the slice (a data byte).
        if let Some(b) = slice.last_mut() {
            *b ^= 0xFF;
        }
        assert!(verify_block_slice(&slice, &address, 4096, 1).is_none());
    }

    #[test]
    fn slice_for_one_block_cannot_serve_a_different_block() {
        let content = content_of(4096);
        let address = *blake3::hash(&content).as_bytes();
        let slice = extract_block_slice(&content, 0).expect("extract");
        // A slice built for block 0 must not verify as block 2.
        assert!(verify_block_slice(&slice, &address, 4096, 2).is_none());
    }

    // -- nonced block tree --------------------------------------------------

    #[test]
    fn nonced_openings_roundtrip_every_block() {
        for len in [1usize, 1024, 1025, 3000, 4096, 9001] {
            let content = content_of(len);
            let root = nonced_block_root(&NONCE, &PEER, &KEY, &content);
            let count = block_count(len as u64);
            for i in 0..count {
                let siblings =
                    nonced_block_siblings(&NONCE, &PEER, &KEY, &content, i).expect("siblings");
                let block = block_bytes(&content, i);
                assert!(
                    verify_nonced_block(&NONCE, &PEER, &KEY, i, block, &siblings, &root, count),
                    "len {len} block {i} must verify"
                );
            }
        }
    }

    #[test]
    fn nonced_opening_rejects_wrong_block_bytes() {
        let content = content_of(4096);
        let root = nonced_block_root(&NONCE, &PEER, &KEY, &content);
        let siblings = nonced_block_siblings(&NONCE, &PEER, &KEY, &content, 1).expect("siblings");
        let mut wrong = block_bytes(&content, 1).to_vec();
        wrong[0] ^= 0x01;
        let bc = block_count(content.len() as u64);
        assert!(!verify_nonced_block(
            &NONCE, &PEER, &KEY, 1, &wrong, &siblings, &root, bc
        ));
    }

    #[test]
    fn nonced_opening_binds_nonce_peer_and_key() {
        let content = content_of(4096);
        let root = nonced_block_root(&NONCE, &PEER, &KEY, &content);
        let siblings = nonced_block_siblings(&NONCE, &PEER, &KEY, &content, 2).expect("siblings");
        let block = block_bytes(&content, 2);
        let bc = block_count(content.len() as u64);
        // Correct binding verifies.
        assert!(verify_nonced_block(
            &NONCE, &PEER, &KEY, 2, block, &siblings, &root, bc
        ));
        // A different nonce, peer, or key must not verify against the same root.
        let other = [0xAB; 32];
        assert!(!verify_nonced_block(
            &other, &PEER, &KEY, 2, block, &siblings, &root, bc
        ));
        assert!(!verify_nonced_block(
            &NONCE, &other, &KEY, 2, block, &siblings, &root, bc
        ));
        assert!(!verify_nonced_block(
            &NONCE, &PEER, &other, 2, block, &siblings, &root, bc
        ));
    }

    // Regression: the nonce must KEY every BLAKE3 chunk of a block
    // leaf, not merely prefix the message. A prefixed leaf (`BLAKE3(nonce ‖ … ‖
    // block)`, ~1166 bytes) leaves the block's tail in a second, nonce-free
    // BLAKE3 chunk whose chaining value is precomputable, letting a node store
    // ~10.7% less than each block and rebuild the leaf for any fresh nonce. Lock
    // in the keyed construction and prove it differs from the vulnerable one.
    #[test]
    fn leaf_is_keyed_by_the_nonce_not_prefixed() {
        let block = content_of(1024);
        let index = 3u32;
        let block_len = block.len() as u32;
        let got = nonced_block_leaf(&NONCE, &PEER, &KEY, index, &block);

        // Required construction: keyed BLAKE3, nonce in the key.
        let audit_key = nonced_block_key(&NONCE, &PEER, &KEY);
        let mut keyed = blake3::Hasher::new_keyed(&audit_key);
        keyed.update(DOMAIN_BLOCK_LEAF);
        keyed.update(&index.to_le_bytes());
        keyed.update(&block_len.to_le_bytes());
        keyed.update(&block);
        assert_eq!(
            got,
            *keyed.finalize().as_bytes(),
            "leaf must be keyed BLAKE3 with the nonce-derived key"
        );

        // The old, vulnerable prefixed construction must NOT match.
        let mut prefixed = blake3::Hasher::new();
        prefixed.update(DOMAIN_BLOCK_LEAF);
        prefixed.update(&NONCE);
        prefixed.update(&PEER);
        prefixed.update(&KEY);
        prefixed.update(&index.to_le_bytes());
        prefixed.update(&block_len.to_le_bytes());
        prefixed.update(&block);
        assert_ne!(
            got,
            *prefixed.finalize().as_bytes(),
            "leaf must not use the precomputable prefixed-nonce construction"
        );
    }

    // The documented strength claim, made executable: a partial holder CAN pass,
    // and what stops it is sampling, not the hash construction.
    //
    // A peer keeping blocks 0..k of a chunk commits a root whose kept-block
    // leaves are genuine and whose dropped-block leaves are garbage. Every
    // opening on a kept block verifies against that root; every opening on a
    // dropped block fails. This is the whole basis for describing round 2 as a
    // sampling check rather than a proof of complete possession.
    #[test]
    fn partial_holder_passes_on_kept_blocks_and_fails_on_dropped_ones() {
        let content = content_of(8 * 1024); // 8 blocks
        let count = block_count(content.len() as u64);
        assert_eq!(count, 8);
        let kept = 5u32; // blocks 0..5 retained, 5..8 dropped

        // Build the tree a partial holder would commit: real leaves for kept
        // blocks, arbitrary (wrong) leaves for the dropped ones.
        let leaves: Vec<[u8; 32]> = (0..count)
            .map(|i| {
                if i < kept {
                    nonced_block_leaf(&NONCE, &PEER, &KEY, i, block_bytes(&content, i))
                } else {
                    // No bytes for this block — anything at all goes here.
                    nonced_block_leaf(&NONCE, &PEER, &KEY, i, b"dropped")
                }
            })
            .collect();
        let mut level = leaves.clone();
        while level.len() > 1 {
            level = fold_level(&level);
        }
        let forged_root = level.first().copied().expect("non-empty tree");

        // An opening on a KEPT block verifies against the forged root: the peer
        // passes this draw despite not holding the whole chunk.
        for i in 0..kept {
            let siblings = siblings_from_leaves(&leaves, i).expect("in range");
            assert!(
                verify_nonced_block(
                    &NONCE,
                    &PEER,
                    &KEY,
                    i,
                    block_bytes(&content, i),
                    &siblings,
                    &forged_root,
                    count,
                ),
                "a kept block must verify — this is the false-pass path the docs describe"
            );
        }

        // An opening on a DROPPED block cannot be answered: the peer has no
        // bytes whose leaf folds to the committed root at that index.
        for i in kept..count {
            let siblings = siblings_from_leaves(&leaves, i).expect("in range");
            assert!(
                !verify_nonced_block(
                    &NONCE,
                    &PEER,
                    &KEY,
                    i,
                    block_bytes(&content, i),
                    &siblings,
                    &forged_root,
                    count,
                ),
                "a dropped block must fail — sampling is what catches the partial holder"
            );
        }
    }

    // The slice proof uses BLAKE3 `derive_key` mode over
    // `nonce ‖ peer ‖ key` under a subtree-specific context string.
    #[test]
    fn block_key_uses_the_subtree_domain_separated_derivation() {
        let mut expected = blake3::Hasher::new_derive_key(BLOCK_KEY_CONTEXT);
        expected.update(&NONCE);
        expected.update(&PEER);
        expected.update(&KEY);
        assert_eq!(
            nonced_block_key(&NONCE, &PEER, &KEY),
            *expected.finalize().as_bytes(),
            "block key must use derive_key mode"
        );

        // Mode separation is the point: the same material under a plain hash,
        // or under keyed mode, must land somewhere else entirely.
        let mut plain = blake3::Hasher::new();
        plain.update(BLOCK_KEY_CONTEXT.as_bytes());
        plain.update(&NONCE);
        plain.update(&PEER);
        plain.update(&KEY);
        assert_ne!(
            nonced_block_key(&NONCE, &PEER, &KEY),
            *plain.finalize().as_bytes(),
            "derive_key mode must not coincide with a plain domain-prefixed hash"
        );
    }

    #[test]
    fn nonced_root_changes_with_any_block_edit() {
        let content = content_of(5000);
        let root = nonced_block_root(&NONCE, &PEER, &KEY, &content);
        let mut edited = content;
        // Flip a byte in the LAST block; the root must change (all blocks covered).
        if let Some(b) = edited.last_mut() {
            *b ^= 0x01;
        }
        let root2 = nonced_block_root(&NONCE, &PEER, &KEY, &edited);
        assert_ne!(root, root2);
    }

    #[test]
    fn nonced_siblings_out_of_range_is_none() {
        let content = content_of(2048);
        let count = block_count(content.len() as u64);
        assert!(nonced_block_siblings(&NONCE, &PEER, &KEY, &content, count).is_none());
    }

    // -- the combined possession property ----------------------------------

    #[test]
    fn relay_cannot_open_against_a_foreign_committed_root() {
        // A responder that did NOT hold the bytes at round 1 commits a root over
        // garbage (or a guess). Even if it later fetches the real block, folding
        // the real leaf to that committed root would be a preimage break: model
        // this by taking a root from DIFFERENT content and checking that the real
        // block + honest siblings never fold to it.
        let real = content_of(4096);
        let garbage = content_of(4097); // different content => different tree
        let foreign_root = nonced_block_root(&NONCE, &PEER, &KEY, &garbage);
        let siblings = nonced_block_siblings(&NONCE, &PEER, &KEY, &real, 0).expect("siblings");
        let block = block_bytes(&real, 0);
        assert!(!verify_nonced_block(
            &NONCE,
            &PEER,
            &KEY,
            0,
            block,
            &siblings,
            &foreign_root,
            block_count(real.len() as u64)
        ));
    }

    // Canonical-depth regression: `nonced_root` is responder-chosen in round 1,
    // so a partial holder could set it to a single block's leaf and pass with
    // zero siblings whenever the fresh draw lands on that block. Pinning the
    // sibling-chain length to the tree depth rejects that (and any wrong-depth
    // chain) even when it would fold to the supplied root.
    #[test]
    fn canonical_depth_rejects_wrong_sibling_count() {
        let content = content_of(4096); // 4 blocks → canonical depth 2
        let bc = block_count(content.len() as u64);
        assert_eq!(nonced_tree_depth(bc), 2);
        let block0 = block_bytes(&content, 0);

        // Degraded escape: claim root = block 0's own leaf, supply zero siblings.
        // Folds to that root, but depth 0 != 2, so rejected.
        let leaf0 = nonced_block_leaf(&NONCE, &PEER, &KEY, 0, block0);
        assert!(!verify_nonced_block(
            &NONCE,
            &PEER,
            &KEY,
            0,
            block0,
            &[],
            &leaf0,
            bc
        ));

        // The honest, correct-depth opening still verifies.
        let root = nonced_block_root(&NONCE, &PEER, &KEY, &content);
        let siblings = nonced_block_siblings(&NONCE, &PEER, &KEY, &content, 0).expect("siblings");
        assert_eq!(siblings.len(), 2);
        assert!(verify_nonced_block(
            &NONCE, &PEER, &KEY, 0, block0, &siblings, &root, bc
        ));

        // A too-long chain (extra sibling) is rejected on depth alone.
        let mut too_long = siblings;
        too_long.push([0u8; 32]);
        assert!(!verify_nonced_block(
            &NONCE, &PEER, &KEY, 0, block0, &too_long, &root, bc
        ));
    }
}
