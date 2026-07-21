//! BLAKE3 verified-slice possession proofs for the storage-commitment audit
//! (ADR-0002 round 2, V2-685).
//!
//! The audit's round 2 used to make a challenged peer return the **complete
//! original bytes** of the sampled chunks (up to two 4 MiB chunks per response),
//! which turned proof-of-storage into the fleet's second-largest bandwidth cost
//! (~7.5 TB/day). This module replaces that with a two-chain verified slice: the
//! response for one opened 1 KiB block is a few KB instead of a full chunk, a
//! ~1000× reduction, while proving *more* than the old flat check.
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
//! a Merkle root over the same 1 KiB blocks whose leaves are
//! `BLAKE3(nonce ‖ peer ‖ key ‖ block_index ‖ block_len ‖ block_bytes)`.
//!
//! Because the fresh per-audit nonce enters **every** block leaf, there is no
//! nonce-independent state a responder can precompute across audits (this closes
//! the BLAKE3-chaining-value preprocessing gap the old flat `nonced_hash` left
//! open, where only the first BLAKE3 chunk saw the nonce). Building the correct
//! `nonced_root` therefore requires *all* of a chunk's bytes at round-1 commit
//! time, and the auditor picks which block to open with fresh randomness *after*
//! the roots are committed (cut-and-choose): a responder cannot connect a real,
//! after-the-fact-fetched block to a garbage committed root without a preimage
//! break, and cannot commit a correct root without holding the bytes.
//!
//! In round 2 the auditor verifies both chains over the **same** block bytes:
//! the Bao chain against the address (authenticity) and the nonced chain against
//! the round-1 `nonced_root` (possession). Either failing is a confirmed cheat.

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

/// Nonced block-leaf hash: binds the fresh nonce, challenged peer, key, block
/// index, block length and block bytes.
///
/// The nonce enters here, at every block, which is the whole point: no part of
/// the tree can be precomputed before the audit's nonce is known.
#[must_use]
fn nonced_block_leaf(
    nonce: &[u8; 32],
    peer: &[u8; 32],
    key: &XorName,
    index: u32,
    block: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(DOMAIN_BLOCK_LEAF);
    h.update(nonce);
    h.update(peer);
    h.update(key);
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
    let mut level = nonced_leaves(nonce, peer, key, content);
    if usize::try_from(index).ok()? >= level.len() {
        return None;
    }
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
pub fn verify_nonced_block(
    nonce: &[u8; 32],
    peer: &[u8; 32],
    key: &XorName,
    index: u32,
    block: &[u8],
    siblings: &[[u8; 32]],
    nonced_root: &[u8; 32],
) -> bool {
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
    let (start, end) = block_range(content.len() as u64, index);
    let len = end - start;
    // The outboard carries the BLAKE3 tree hashes separately from the content, so
    // the extractor reads the real chunk bytes plus just the parent hashes on the
    // block's path — no need to materialise a full Bao encoding of the chunk.
    let (outboard, _hash) = bao::encode::outboard(content);
    let mut extractor = bao::encode::SliceExtractor::new_outboard(
        Cursor::new(content.to_vec()),
        Cursor::new(outboard),
        start,
        len,
    );
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;
    Ok(slice)
}

/// Verify a Bao slice for block `index` against the chunk `address`
/// (`BLAKE3(content)`), returning the verified block bytes (auditor, round 2).
///
/// `content_len` is the responder's round-1 claim; a lie there makes the block
/// range disagree with the address-committed tree shape, so the decode fails —
/// a lying responder can only fail its own audit, never forge a pass.
#[must_use]
pub fn verify_block_slice(
    slice: &[u8],
    address: &[u8; 32],
    content_len: u64,
    index: u32,
) -> Option<Vec<u8>> {
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
                    verify_nonced_block(&NONCE, &PEER, &KEY, i, block, &siblings, &root),
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
        assert!(!verify_nonced_block(
            &NONCE, &PEER, &KEY, 1, &wrong, &siblings, &root
        ));
    }

    #[test]
    fn nonced_opening_binds_nonce_peer_and_key() {
        let content = content_of(4096);
        let root = nonced_block_root(&NONCE, &PEER, &KEY, &content);
        let siblings = nonced_block_siblings(&NONCE, &PEER, &KEY, &content, 2).expect("siblings");
        let block = block_bytes(&content, 2);
        // Correct binding verifies.
        assert!(verify_nonced_block(
            &NONCE, &PEER, &KEY, 2, block, &siblings, &root
        ));
        // A different nonce, peer, or key must not verify against the same root.
        let other = [0xAB; 32];
        assert!(!verify_nonced_block(
            &other, &PEER, &KEY, 2, block, &siblings, &root
        ));
        assert!(!verify_nonced_block(
            &NONCE, &other, &KEY, 2, block, &siblings, &root
        ));
        assert!(!verify_nonced_block(
            &NONCE, &PEER, &other, 2, block, &siblings, &root
        ));
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
            &foreign_root
        ));
    }
}
