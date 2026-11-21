//! Exact fixed-depth search over the grouped 192-bit CDF.
use crate::ct::{ct_eq_limbs, ct_lt_limbs_be, opaque_mask};
use zeroize::Zeroizing;
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel33_ct_tree_four_state\n.p2align 2\n_pretzel33_ct_tree_four_state:\n",
        include_str!("../../pretzel-4-4/core/src/ct_tree_four.S")
    ),
    options(raw)
);
// SAFETY: contract of the assembly routine defined just above (`ct_tree_four.S` of rank four, under
// this crate's symbol name). It writes 256 bytes at `out` (`[[u64; 4]; 8]`), reads 96 bytes at
// `draws` (four draws of three `u64`) and reads `depth` descriptors of two words at `levels`;
// `depth` must be at least 1. Each descriptor is a table address and a block count of at least 1,
// and the routine reads 448 bytes per block of that table, front to back. It uses NEON only, saves
// and restores d8 to d15 in a 160-byte frame, keeps no pointer and has no global state.
unsafe extern "C" {
    fn pretzel33_ct_tree_four_state(
        out: *mut u64,
        levels: *const [usize; 2],
        depth: usize,
        draws: *const u64,
    );
}

#[cfg(test)]
const MAX: [u64; 3] = [u64::MAX; 3];
type Block = [[u32; 16]; 7];
pub(crate) struct Tree {
    // `levels` owns the allocations that the descriptors below point into;
    // Rust code reads it only in tests.
    #[allow(dead_code)]
    levels: Vec<Vec<Block>>,
    // Explicit array layout for native access. Exposed addresses point into
    // the immutable owning levels above, whose allocations survive all moves
    // of this Tree. These descriptors are never exported or mutated.
    descriptors: Vec<[usize; 2]>,
}
impl Tree {
    pub(crate) fn new(groups: &[[u64; 4]]) -> Self {
        assert!(!groups.is_empty() && groups.len() < 1 << 15);
        assert!(groups.windows(2).all(|w| w[0][..3] < w[1][..3]));
        let depth = (usize::BITS - groups.len().leading_zeros()) as usize;
        let mut levels = Vec::with_capacity(depth);
        for d in 0..depth {
            let nodes = 1usize << d;
            let stride = 1usize << (depth - d - 1);
            let mut blocks = vec![[[0u32; 16]; 7]; nodes.div_ceil(16)];
            for i in 0..nodes {
                let origin = (2 * i + 1) * stride - 1;
                if origin < groups.len() {
                    let row = groups[origin];
                    assert!(row[3] < 1 << 31);
                    for k in 0..3 {
                        blocks[i / 16][2 * k][i % 16] = row[k] as u32;
                        blocks[i / 16][2 * k + 1][i % 16] = (row[k] >> 32) as u32;
                    }
                    blocks[i / 16][6][i % 16] = row[3] as u32 | (1 << 31);
                }
            }
            {
                // These are immutable public CDF blocks. Omitted trailing
                // blocks contain only virtual invalid zero nodes; the
                // gather returns exactly zero for unmatched indices.
                while blocks.len() > 1
                    && blocks
                        .last()
                        .is_some_and(|block| block.iter().flatten().all(|&word| word == 0))
                {
                    blocks.pop();
                }
            }
            levels.push(blocks);
        }
        let descriptors = levels
            .iter()
            .map(|level| [level.as_ptr() as usize, level.len()])
            .collect();
        Self {
            levels,
            descriptors,
        }
    }
    #[inline(never)]
    fn four(&self, draws: &[[u64; 3]; 4], out: &mut [[u64; 2]; 4], z: &[u64; 3]) {
        {
            assert!(!self.descriptors.is_empty()); // Immutable public shape.
            let mut state = Zeroizing::new([[0u64; 4]; 8]);
            // SAFETY: `state` is a local `[[u64; 4]; 8]` and `draws` a `[[u64; 3]; 4]`.
            // `self.descriptors` is nonempty (asserted above) and private; `new` builds one entry
            // per level from the address and length of a `Vec<Block>` that holds at least one
            // 448-byte block and is owned, unchanged, by `self.levels`, so every table extent the
            // routine reads is live. NEON is in the baseline of every target this crate builds for.
            unsafe {
                pretzel33_ct_tree_four_state(
                    state.as_mut_ptr().cast(),
                    self.descriptors.as_ptr(),
                    self.descriptors.len(),
                    draws.as_ptr().cast(),
                );
            }
            for lane in 0..4 {
                let lo = Zeroizing::new(core::array::from_fn(|k| state[k][lane]));
                let hi = Zeroizing::new(core::array::from_fn(|k| state[3 + k][lane]));
                let metadata = state[6][lane];
                let seen = state[7][lane];
                let mid = Zeroizing::new(crate::ct_grouped_cdf::midpoint(
                    *lo,
                    *hi,
                    (metadata >> 16) & 1,
                ));
                let present = opaque_mask(0u64.wrapping_sub((metadata >> 17) & 1));
                let count = ((metadata >> 1) & 0x7fff)
                    + ((!ct_lt_limbs_be(&draws[lane], &mid) & present) & 1);
                let tie = (ct_eq_limbs(&draws[lane], &lo) & seen)
                    | (ct_eq_limbs(&draws[lane], &mid) & present)
                    | ct_eq_limbs(&draws[lane], z);
                out[lane] = [count, tie];
            }
        }
    }
    pub(crate) fn classify(&self, z: &[u64; 3], draws: &[[u64; 3]]) -> Zeroizing<Vec<[u64; 2]>> {
        let mut result = Zeroizing::new(vec![[0u64; 2]; draws.len()]);
        for (input, output) in draws.chunks(4).zip(result.chunks_mut(4)) {
            let mut padded = Zeroizing::new([[0u64; 3]; 4]);
            padded[..input.len()].copy_from_slice(input);
            let mut selected = Zeroizing::new([[0u64; 2]; 4]);
            self.four(&padded, &mut selected, z);
            output.copy_from_slice(&selected[..output.len()]);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_tree_duplicates_padding_maximum_and_public_partial_batches() {
        for bounds in [
            vec![[0, 0, 0]],
            vec![[0, 0, 1], [0, 0, 2], [0, 0, 3]],
            vec![[0, 0, 1], [0, 0, 1], [0, 0, 1], [0, 0, 2], [0, 0, 3]],
            vec![MAX; 5],
        ] {
            let groups = crate::ct_grouped_cdf::prepare(&bounds);
            let tree = Tree::new(&groups);
            let z = *bounds.last().unwrap();
            let queries: Vec<_> = (0..32).map(|i| [0, 0, i]).chain([MAX]).collect();
            for n in 0..=queries.len() {
                let actual = tree.classify(&z, &queries[..n]);
                for (i, u) in queries[..n].iter().enumerate() {
                    assert_eq!(
                        actual[i],
                        [
                            bounds.iter().filter(|b| *b <= u).count() as u64,
                            0u64.wrapping_sub(u64::from(bounds.contains(u) || *u == z))
                        ]
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod public_padding_tests {
    use super::*;
    #[test]
    fn deployed_public_block_counts_match_independent_padding_gate() {
        for (n, expected) in [
            (33, vec![1, 1, 1, 1, 1, 2]),
            (709, vec![1, 1, 1, 1, 1, 2, 3, 6, 12, 23]),
            (901, vec![1, 1, 1, 1, 1, 2, 4, 8, 15, 29]),
        ] {
            let groups: Vec<_> = (0..n)
                .map(|i| [0, 0, i as u64 + 1, 2 * (i as u64 + 1)])
                .collect();
            let tree = Tree::new(&groups);
            assert_eq!(
                tree.levels.iter().map(Vec::len).collect::<Vec<_>>(),
                expected
            );
        }
    }
}

#[cfg(test)]
mod register_four_tests {
    use super::*;
    #[test]
    fn native_four_matches_grouped_scan_with_all_padding_and_tie_states() {
        let mut seed = 0x563917318bcau64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for n in [1usize, 2, 3, 16, 17, 33, 63, 127, 709, 901] {
            let groups: Vec<[u64; 4]> = (0..n)
                .map(|i| {
                    [
                        i as u64,
                        next(),
                        next(),
                        (((i + 1) as u64) << 1)
                            | (((i % 2) as u64) << 16)
                            | ((u64::from(i + 1 < n)) << 17),
                    ]
                })
                .collect();
            let tree = Tree::new(&groups);
            for (level, descriptor) in tree.levels.iter().zip(&tree.descriptors) {
                assert_eq!(*descriptor, [level.as_ptr() as usize, level.len()]);
            }
            let z = [n as u64, 0, 0];
            let mut probes = vec![[0; 3], [u64::MAX; 3], z];
            for row in &groups {
                probes.push([row[0], row[1], row[2]]);
            }
            for _ in 0..65 {
                probes.push([next() % (n as u64 + 1), next(), next()]);
            }
            for chunk in probes.chunks(4) {
                let mut draws = [[0u64; 3]; 4];
                draws[..chunk.len()].copy_from_slice(chunk);
                let mut actual = [[0u64; 2]; 4];
                tree.four(&draws, &mut actual, &z);
                // The sorting-network scan of the same groups, which shares no code with the tree.
                let expected = crate::ct_grouped_cdf::classify(&groups, &z, &draws);
                assert_eq!(actual[..], expected[..], "public groups {n}");
            }
        }
    }
}
