//! Close groups worked out once per key range, instead of once per key.
//!
//! The peers closest to a key change only at a few points in the key space. Of two
//! peers, the one closer to a key is decided by the first bit where the two peers
//! differ: the one matching the key's bit there is closer, whatever the lower bits.
//! So walking down a key's bits from the top, the peers still competing for its
//! group split at each bit into a closer side and a farther side:
//!
//! - if the closer side can fill the group, the farther side is out;
//! - if not, the whole closer side is in, and the rest of the group comes from the
//!   farther side.
//!
//! The walk stops once every key under a prefix has the same group, or once the
//! peers still competing don't differ at the next bit. Those few are then compared
//! for each key. A routing table of a few hundred peers gives tens to a few hundred
//! ranges.
//!
//! Each key's group is the one sorting every candidate by distance to it would
//! give: the map applies the same order, once per range. Hint builds use it to read
//! only the ranges where a peer they build for can be in the group.

use std::collections::HashSet;
use std::ops::Range;

use saorsa_core::identity::PeerId;

use crate::ant_protocol::{XorName, XORNAME_LEN};
use crate::client::xor_distance;

#[cfg(test)]
use rand::{rngs::StdRng, Rng, SeedableRng};

/// Bits in one byte of a key.
const BITS_PER_BYTE: usize = 8;

/// Bits in a key.
const KEY_BITS: usize = XORNAME_LEN * BITS_PER_BYTE;

/// A byte's highest bit, which comes first in a key's bit order.
const HIGHEST_BIT_IN_BYTE: u8 = 0x80;

/// Keys from `low` to `high` whose close groups hold the same settled candidates,
/// plus the closest `need` of the open ones, picked for each key.
#[derive(Debug, Clone)]
pub struct GroupRange {
    low: XorName,
    high: XorName,
    /// Candidates in the group of every key in the range, as indices.
    settled: Vec<usize>,
    /// Candidates still competing, as a run of indices.
    open: Range<usize>,
    /// How many of the open candidates each key's group takes.
    need: usize,
}

impl GroupRange {
    /// The range's first and last key.
    pub fn bounds(&self) -> (XorName, XorName) {
        (self.low, self.high)
    }
}

/// The close group of every key, for one set of candidates and one group size.
#[derive(Debug)]
pub struct CloseGroupMap {
    /// Every candidate, sorted by ID.
    candidates: Vec<PeerId>,
    /// Ranges in key order, covering every key once.
    ranges: Vec<GroupRange>,
}

impl CloseGroupMap {
    /// Map each key's closest `group_size` of `candidates`.
    pub fn new(candidates: impl IntoIterator<Item = PeerId>, group_size: usize) -> Self {
        let mut candidates: Vec<PeerId> = candidates.into_iter().collect();
        candidates.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        candidates.dedup();
        let mut walk = Walk {
            candidates: &candidates,
            settled: Vec::new(),
            ranges: Vec::new(),
        };
        walk.split(
            [0; XORNAME_LEN],
            0,
            0..candidates.len(),
            group_size.min(candidates.len()),
        );
        let ranges = walk.ranges;
        Self { candidates, ranges }
    }

    /// Every range, in key order.
    pub fn ranges(&self) -> &[GroupRange] {
        &self.ranges
    }

    /// Whether any of `peers` is in the group of some key in `range`.
    pub fn may_include_any(&self, range: &GroupRange, peers: &HashSet<PeerId>) -> bool {
        let open = if range.need == 0 {
            &[][..]
        } else {
            self.candidates.get(range.open.clone()).unwrap_or(&[])
        };
        range
            .settled
            .iter()
            .filter_map(|&index| self.candidates.get(index))
            .chain(open)
            .any(|peer| peers.contains(peer))
    }

    /// The close group of `key`, which must lie in `range`.
    pub fn group_in(&self, range: &GroupRange, key: &XorName) -> Vec<PeerId> {
        let mut group: Vec<PeerId> = range
            .settled
            .iter()
            .filter_map(|&index| self.candidates.get(index))
            .copied()
            .collect();
        if range.need == 0 {
            return group;
        }
        let mut open: Vec<(XorName, PeerId)> = self
            .candidates
            .get(range.open.clone())
            .unwrap_or(&[])
            .iter()
            .map(|peer| (xor_distance(key, peer.as_bytes()), *peer))
            .collect();
        if range.need < open.len() {
            open.select_nth_unstable_by_key(range.need - 1, |(distance, _)| *distance);
            open.truncate(range.need);
        }
        group.extend(open.into_iter().map(|(_, peer)| peer));
        group
    }

    /// The close group of any key.
    #[cfg(test)]
    pub fn group_of(&self, key: &XorName) -> Vec<PeerId> {
        let index = self.ranges.partition_point(|range| range.high < *key);
        self.ranges
            .get(index)
            .map_or_else(Vec::new, |range| self.group_in(range, key))
    }
}

/// The state of one map's walk down the key bits.
struct Walk<'a> {
    candidates: &'a [PeerId],
    /// Candidates in the group of every key under the current prefix.
    settled: Vec<usize>,
    ranges: Vec<GroupRange>,
}

impl Walk<'_> {
    /// Map the keys sharing the first `depth` bits of `prefix`, whose groups hold
    /// the settled candidates and the closest `need` of `open`. Every candidate in
    /// `open` shares those bits with the others.
    fn split(&mut self, prefix: XorName, depth: usize, open: Range<usize>, need: usize) {
        if need == 0 || open.len() == need {
            let mut settled = self.settled.clone();
            if need > 0 {
                settled.extend(open);
            }
            self.push(prefix, depth, settled, 0..0, 0);
            return;
        }
        // Sorted by ID and sharing every bit above this one, the open candidates
        // run from those with this bit clear to those with it set.
        let run = self.candidates.get(open.clone()).unwrap_or(&[]);
        let set_from = open.start + run.partition_point(|peer| !bit(peer.as_bytes(), depth));
        if depth >= KEY_BITS || set_from == open.start || set_from == open.end {
            // No open candidate differs from another at this bit, so a key's bit
            // here can't change which of them are closer: each key decides.
            let settled = self.settled.clone();
            self.push(prefix, depth, settled, open, need);
            return;
        }
        for key_bit in [false, true] {
            let (closer, farther) = if key_bit {
                (set_from..open.end, open.start..set_from)
            } else {
                (open.start..set_from, set_from..open.end)
            };
            let child = with_bit(prefix, depth, key_bit);
            if closer.len() >= need {
                self.split(child, depth + 1, closer, need);
            } else {
                let mark = self.settled.len();
                let taken = closer.len();
                self.settled.extend(closer);
                self.split(child, depth + 1, farther, need - taken);
                self.settled.truncate(mark);
            }
        }
    }

    fn push(
        &mut self,
        prefix: XorName,
        depth: usize,
        settled: Vec<usize>,
        open: Range<usize>,
        need: usize,
    ) {
        let mut high = prefix;
        for free in depth..KEY_BITS {
            high = with_bit(high, free, true);
        }
        self.ranges.push(GroupRange {
            low: prefix,
            high,
            settled,
            open,
            need,
        });
    }
}

/// Bit `depth` of `id`, counting from its highest bit.
fn bit(id: &XorName, depth: usize) -> bool {
    id.get(depth / BITS_PER_BYTE)
        .is_some_and(|byte| byte & (HIGHEST_BIT_IN_BYTE >> (depth % BITS_PER_BYTE)) != 0)
}

/// `id` with bit `depth`, counting from its highest bit, set to `value`.
fn with_bit(mut id: XorName, depth: usize, value: bool) -> XorName {
    let mask = HIGHEST_BIT_IN_BYTE >> (depth % BITS_PER_BYTE);
    if let Some(byte) = id.get_mut(depth / BITS_PER_BYTE) {
        if value {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    id
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SEED: u64 = 0x5EED_C105;
    const KEYS_PER_CASE: usize = 400;
    const RECORD_GROUP: usize = 7;
    const PAID_GROUP: usize = 20;
    const GROUP_SIZES: [usize; 4] = [1, 2, RECORD_GROUP, PAID_GROUP];
    const MEDIUM_TABLE: usize = 60;
    const LARGE_TABLE: usize = 250;
    /// Around and at the group sizes, where the edge cases are.
    const TABLE_SIZES: [usize; 8] = [
        0,
        1,
        2,
        RECORD_GROUP,
        PAID_GROUP,
        PAID_GROUP + 1,
        MEDIUM_TABLE,
        LARGE_TABLE,
    ];
    const EXAMPLE_GROUP: usize = 2;
    /// Bytes a clustered ID shares with the candidate it sits beside.
    const CLUSTERED_SHARED_BYTES: usize = 3;
    const CLUSTERED_IDS: usize = 40;

    fn peer(bytes: XorName) -> PeerId {
        PeerId::from_bytes(bytes)
    }

    /// A key whose first byte is `first` and the rest zero.
    fn key_starting(first: u8) -> XorName {
        let mut key = [0u8; XORNAME_LEN];
        key[0] = first;
        key
    }

    /// The closest `group_size` candidates to `key`, by sorting them all.
    fn brute_force(candidates: &[PeerId], key: &XorName, group_size: usize) -> Vec<PeerId> {
        let mut sorted = candidates.to_vec();
        sorted.sort_by_key(|peer| xor_distance(key, peer.as_bytes()));
        sorted.truncate(group_size);
        sorted
    }

    fn sorted(mut peers: Vec<PeerId>) -> Vec<PeerId> {
        peers.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        peers
    }

    /// Keys that test the edges: the ends of the key space, each candidate's own
    /// ID and its neighbours one bit away, then random keys.
    fn probe_keys(candidates: &[PeerId], rng: &mut StdRng) -> Vec<XorName> {
        let mut keys = vec![[0u8; XORNAME_LEN], [0xFF; XORNAME_LEN]];
        for candidate in candidates {
            let id = *candidate.as_bytes();
            keys.push(id);
            keys.push(with_bit(id, KEY_BITS - 1, !bit(&id, KEY_BITS - 1)));
            keys.push(with_bit(id, 0, !bit(&id, 0)));
        }
        keys.extend((0..KEYS_PER_CASE).map(|_| rng.gen::<XorName>()));
        keys
    }

    fn assert_matches_brute_force(candidates: &[PeerId], group_size: usize, rng: &mut StdRng) {
        let map = CloseGroupMap::new(candidates.iter().copied(), group_size);
        for key in probe_keys(candidates, rng) {
            assert_eq!(
                sorted(map.group_of(&key)),
                sorted(brute_force(candidates, &key, group_size)),
                "{} candidates, group {group_size}, key {}",
                candidates.len(),
                hex::encode(key)
            );
        }
    }

    #[test]
    fn every_group_matches_sorting_every_candidate_by_distance() {
        let mut rng = StdRng::seed_from_u64(SEED);
        for table in TABLE_SIZES {
            let candidates: Vec<PeerId> = (0..table).map(|_| peer(rng.gen())).collect();
            for group_size in GROUP_SIZES {
                assert_matches_brute_force(&candidates, group_size, &mut rng);
            }
        }
    }

    #[test]
    fn groups_match_with_ids_clustered_beside_one_candidate() {
        let mut rng = StdRng::seed_from_u64(SEED);
        let mut candidates: Vec<PeerId> = (0..MEDIUM_TABLE).map(|_| peer(rng.gen())).collect();
        let beside = *candidates[0].as_bytes();
        for _ in 0..CLUSTERED_IDS {
            let mut id: XorName = rng.gen();
            id[..CLUSTERED_SHARED_BYTES].copy_from_slice(&beside[..CLUSTERED_SHARED_BYTES]);
            candidates.push(peer(id));
        }
        for group_size in GROUP_SIZES {
            assert_matches_brute_force(&candidates, group_size, &mut rng);
        }
    }

    #[test]
    fn groups_match_when_every_candidate_shares_its_top_bits() {
        let mut rng = StdRng::seed_from_u64(SEED);
        let candidates: Vec<PeerId> = (0..MEDIUM_TABLE)
            .map(|_| {
                let mut id: XorName = rng.gen();
                id[0] = 0;
                peer(id)
            })
            .collect();
        for group_size in GROUP_SIZES {
            assert_matches_brute_force(&candidates, group_size, &mut rng);
        }
    }

    #[test]
    fn ranges_cover_every_key_once_in_order() {
        let mut rng = StdRng::seed_from_u64(SEED);
        let candidates: Vec<PeerId> = (0..LARGE_TABLE).map(|_| peer(rng.gen())).collect();
        for group_size in GROUP_SIZES {
            let map = CloseGroupMap::new(candidates.iter().copied(), group_size);
            let bounds: Vec<(XorName, XorName)> =
                map.ranges().iter().map(GroupRange::bounds).collect();
            assert_eq!(bounds.first().map(|b| b.0), Some([0u8; XORNAME_LEN]));
            assert_eq!(bounds.last().map(|b| b.1), Some([0xFF; XORNAME_LEN]));
            for pair in bounds.windows(2) {
                let (_, high) = pair[0];
                let (low, _) = pair[1];
                assert!(high < low, "ranges overlap or are out of order");
                let mut next = high;
                for byte in next.iter_mut().rev() {
                    let (sum, carried) = byte.overflowing_add(1);
                    *byte = sum;
                    if !carried {
                        break;
                    }
                }
                assert_eq!(next, low, "a gap between ranges");
            }
        }
    }

    #[test]
    fn the_worked_example_splits_into_three_ranges() {
        // Peers 0000, 0001, 0101, 1000 and 1110 in the top four bits, a group of two.
        // For keys starting 01, peer 0101 is in, and 0000 and 0001 differ only in
        // their last bit, so each key picks one of them.
        let ids = [
            0b0000_0000,
            0b0001_0000,
            0b0101_0000,
            0b1000_0000,
            0b1110_0000,
        ];
        let candidates: Vec<PeerId> = ids.iter().map(|first| peer(key_starting(*first))).collect();
        let map = CloseGroupMap::new(candidates.iter().copied(), EXAMPLE_GROUP);
        let starts: Vec<u8> = map.ranges().iter().map(|range| range.low[0]).collect();
        assert_eq!(starts, vec![0b0000_0000, 0b0100_0000, 0b1000_0000]);

        let settled = |range: &GroupRange| -> Vec<PeerId> {
            sorted(range.settled.iter().map(|&i| map.candidates[i]).collect())
        };
        let ranges = map.ranges();
        assert_eq!(
            settled(&ranges[0]),
            sorted(vec![candidates[0], candidates[1]])
        );
        assert_eq!(settled(&ranges[1]), vec![candidates[2]]);
        assert_eq!(ranges[1].need, 1, "0000 and 0001 are compared for each key");
        assert_eq!(
            map.group_of(&key_starting(0b0100_0000)),
            vec![candidates[2], candidates[0]]
        );
        assert_eq!(
            map.group_of(&key_starting(0b0101_0000)),
            vec![candidates[2], candidates[1]]
        );
        assert_eq!(
            settled(&ranges[2]),
            sorted(vec![candidates[3], candidates[4]])
        );

        let neighbour = HashSet::from([candidates[1]]);
        let read: Vec<bool> = ranges
            .iter()
            .map(|range| map.may_include_any(range, &neighbour))
            .collect();
        assert_eq!(
            read,
            vec![true, true, false],
            "keys from 1000 on are never read"
        );
    }

    #[test]
    fn with_no_more_candidates_than_the_group_every_key_gets_them_all() {
        let mut rng = StdRng::seed_from_u64(SEED);
        let candidates: Vec<PeerId> = (0..RECORD_GROUP).map(|_| peer(rng.gen())).collect();
        let map = CloseGroupMap::new(candidates.iter().copied(), PAID_GROUP);
        assert_eq!(map.ranges().len(), 1);
        assert_eq!(sorted(map.group_of(&rng.gen())), sorted(candidates));

        let empty = CloseGroupMap::new(Vec::new(), PAID_GROUP);
        assert_eq!(empty.ranges().len(), 1);
        assert!(empty.group_of(&rng.gen()).is_empty());
    }
}
