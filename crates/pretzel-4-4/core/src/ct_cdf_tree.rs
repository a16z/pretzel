//! Exact fixed-depth search over the grouped 192-bit CDF.
use crate::ct::{ct_eq_limbs, ct_lt_limbs_be, opaque_mask};
use zeroize::Zeroizing;
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_ct_tree_four_state\n.p2align 2\n_pretzel44_ct_tree_four_state:\n",
        include_str!("ct_tree_four.S")
    ),
    options(raw)
);
// SAFETY: contract of the assembly routine defined just above (`ct_tree_four.S`). It writes 256
// bytes at `out` (`[[u64; 4]; 8]`), reads 96 bytes at `draws` (four draws of three `u64`) and reads
// `depth` descriptors of two words at `levels`; `depth` must be at least 1. Each descriptor is a
// table address and a block count of at least 1, and the routine reads 448 bytes per block of that
// table, front to back. It uses NEON only, saves and restores d8 to d15 in a 160-byte frame, keeps
// no pointer and has no global state.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn pretzel44_ct_tree_four_state(
        out: *mut u64,
        levels: *const [usize; 2],
        depth: usize,
        draws: *const u64,
    );
}

#[cfg(any(test, not(target_arch = "aarch64")))]
const MAX: [u64; 3] = [u64::MAX; 3];
type Block = [[u32; 16]; 7];
pub(crate) struct Tree {
    // Owns the allocations that `descriptors` points into. Only tests read it by name.
    #[cfg_attr(not(test), allow(dead_code))]
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
    #[cfg(any(test, not(target_arch = "aarch64")))]
    fn eight(&self, draws: &[[u64; 3]; 8], out: &mut [[u64; 2]; 8], z: &[u64; 3]) {
        let mut indices = Zeroizing::new([0u32; 8]);
        let mut last = Zeroizing::new([[0u64; 8]; 3]);
        let mut following = Zeroizing::new([[u64::MAX; 8]; 3]);
        let mut metadata = Zeroizing::new([0u64; 8]);
        let mut seen = Zeroizing::new([0u64; 8]);
        let mut columns = Zeroizing::new([[0u32; 8]; 7]);
        for level in &self.levels {
            gather_eight_into(&mut columns, level, &indices);
            for lane in 0..8 {
                let node = Zeroizing::new(core::array::from_fn(|k| {
                    columns[2 * k][lane] as u64 | ((columns[2 * k + 1][lane] as u64) << 32)
                }));
                let valid = opaque_mask(0u64.wrapping_sub((columns[6][lane] >> 31) as u64));
                let less = ct_lt_limbs_be(&draws[lane], &node);
                let lower = opaque_mask(!less & valid);
                let upper = opaque_mask(less & valid);
                for k in 0..3 {
                    last[k][lane] = (node[k] & lower) | (last[k][lane] & !lower);
                    following[k][lane] = (node[k] & upper) | (following[k][lane] & !upper);
                }
                metadata[lane] = ((columns[6][lane] as u64) & lower) | (metadata[lane] & !lower);
                seen[lane] |= lower;
                // Invalid padding is strictly beyond every possible input.
                indices[lane] = 2 * indices[lane] + (lower as u32 & 1);
            }
        }
        for lane in 0..8 {
            let lo = Zeroizing::new(core::array::from_fn(|k| last[k][lane]));
            let hi = Zeroizing::new(core::array::from_fn(|k| following[k][lane]));
            let mid = Zeroizing::new(crate::ct_grouped_cdf::midpoint(
                *lo,
                *hi,
                (metadata[lane] >> 16) & 1,
            ));
            let present = opaque_mask(0u64.wrapping_sub((metadata[lane] >> 17) & 1));
            let count = ((metadata[lane] >> 1) & 0x7fff)
                + ((!ct_lt_limbs_be(&draws[lane], &mid) & present) & 1);
            let tie = (ct_eq_limbs(&draws[lane], &lo) & seen[lane])
                | (ct_eq_limbs(&draws[lane], &mid) & present)
                | ct_eq_limbs(&draws[lane], z);
            out[lane] = [count, tie];
        }
    }
    #[inline(never)]
    fn four(&self, draws: &[[u64; 3]; 4], out: &mut [[u64; 2]; 4], z: &[u64; 3]) {
        #[cfg(target_arch = "aarch64")]
        {
            assert!(!self.descriptors.is_empty()); // Immutable public shape.
            let mut state = Zeroizing::new([[0u64; 4]; 8]);
            // SAFETY: `state` is a local `[[u64; 4]; 8]` and `draws` a `[[u64; 3]; 4]`.
            // `self.descriptors` is nonempty (asserted above) and private; `new` builds one entry
            // per level from the address and length of a `Vec<Block>` that holds at least one
            // 448-byte block and is owned, unchanged, by `self.levels`, so every table extent the
            // routine reads is live. NEON is in the baseline of every target this crate builds for.
            unsafe {
                pretzel44_ct_tree_four_state(
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

#[inline(never)]
#[cfg(any(test, not(target_arch = "aarch64")))]
fn gather_eight_into(result: &mut [[u32; 8]; 7], table: &[Block], indices: &[u32; 8]) {
    assert!(!table.is_empty()); // Public table shape, fixed by preparation.
    #[cfg(target_arch = "aarch64")]
    // SAFETY: Block is [[u32; 16]; 7], exactly 448 bytes. The nonempty-table assertion permits
    // the count-down scan, which reads seven 64-byte planes per block, eight u32 indices, and
    // writes seven eight-u32 result planes. References exclude overlap; the aarch64/neon cfg
    // supplies NEON and all asm clobbers are declared.
    unsafe {
        core::arch::asm!(
            "ld1 {{v14.4s-v15.4s}}, [{indices}]",
            "ushr v18.4s, v14.4s, #4", "ushr v19.4s, v15.4s, #4",
            "movi v24.4s, #15", "and v16.16b, v14.16b, v24.16b", "and v17.16b, v15.16b, v24.16b",
            "movi v24.16b, #4", "mul v16.4s, v16.4s, v24.4s", "mul v17.4s, v17.4s, v24.4s",
            "mov {tmp:w}, #0x0100", "movk {tmp:w}, #0x0302, lsl #16", "dup v24.4s, {tmp:w}",
            "add v16.4s, v16.4s, v24.4s", "add v17.4s, v17.4s, v24.4s",
            "movi v0.16b, #0",
            "movi v1.16b, #0",
            "movi v2.16b, #0",
            "movi v3.16b, #0",
            "movi v4.16b, #0",
            "movi v5.16b, #0",
            "movi v6.16b, #0",
            "movi v7.16b, #0",
            "movi v8.16b, #0",
            "movi v9.16b, #0",
            "movi v10.16b, #0",
            "movi v11.16b, #0",
            "movi v12.16b, #0",
            "movi v13.16b, #0",
            "mov {block:w}, #0",
            "2:",
            "dup v24.4s, {block:w}", "cmeq v20.4s, v18.4s, v24.4s", "cmeq v21.4s, v19.4s, v24.4s",
            "ld1 {{v24.16b-v27.16b}}, [{table}], #64",
            "tbl v22.16b, {{v24.16b-v27.16b}}, v16.16b",
            "tbl v23.16b, {{v24.16b-v27.16b}}, v17.16b",
            "and v22.16b, v22.16b, v20.16b", "and v23.16b, v23.16b, v21.16b",
            "orr v0.16b, v0.16b, v22.16b", "orr v1.16b, v1.16b, v23.16b",
            "ld1 {{v24.16b-v27.16b}}, [{table}], #64",
            "tbl v22.16b, {{v24.16b-v27.16b}}, v16.16b",
            "tbl v23.16b, {{v24.16b-v27.16b}}, v17.16b",
            "and v22.16b, v22.16b, v20.16b", "and v23.16b, v23.16b, v21.16b",
            "orr v2.16b, v2.16b, v22.16b", "orr v3.16b, v3.16b, v23.16b",
            "ld1 {{v24.16b-v27.16b}}, [{table}], #64",
            "tbl v22.16b, {{v24.16b-v27.16b}}, v16.16b",
            "tbl v23.16b, {{v24.16b-v27.16b}}, v17.16b",
            "and v22.16b, v22.16b, v20.16b", "and v23.16b, v23.16b, v21.16b",
            "orr v4.16b, v4.16b, v22.16b", "orr v5.16b, v5.16b, v23.16b",
            "ld1 {{v24.16b-v27.16b}}, [{table}], #64",
            "tbl v22.16b, {{v24.16b-v27.16b}}, v16.16b",
            "tbl v23.16b, {{v24.16b-v27.16b}}, v17.16b",
            "and v22.16b, v22.16b, v20.16b", "and v23.16b, v23.16b, v21.16b",
            "orr v6.16b, v6.16b, v22.16b", "orr v7.16b, v7.16b, v23.16b",
            "ld1 {{v24.16b-v27.16b}}, [{table}], #64",
            "tbl v22.16b, {{v24.16b-v27.16b}}, v16.16b",
            "tbl v23.16b, {{v24.16b-v27.16b}}, v17.16b",
            "and v22.16b, v22.16b, v20.16b", "and v23.16b, v23.16b, v21.16b",
            "orr v8.16b, v8.16b, v22.16b", "orr v9.16b, v9.16b, v23.16b",
            "ld1 {{v24.16b-v27.16b}}, [{table}], #64",
            "tbl v22.16b, {{v24.16b-v27.16b}}, v16.16b",
            "tbl v23.16b, {{v24.16b-v27.16b}}, v17.16b",
            "and v22.16b, v22.16b, v20.16b", "and v23.16b, v23.16b, v21.16b",
            "orr v10.16b, v10.16b, v22.16b", "orr v11.16b, v11.16b, v23.16b",
            "ld1 {{v24.16b-v27.16b}}, [{table}], #64",
            "tbl v22.16b, {{v24.16b-v27.16b}}, v16.16b",
            "tbl v23.16b, {{v24.16b-v27.16b}}, v17.16b",
            "and v22.16b, v22.16b, v20.16b", "and v23.16b, v23.16b, v21.16b",
            "orr v12.16b, v12.16b, v22.16b", "orr v13.16b, v13.16b, v23.16b",
            "add {block:w}, {block:w}, #1", "subs {count}, {count}, #1", "b.ne 2b",
            "st1 {{v0.4s-v1.4s}}, [{out}], #32",
            "st1 {{v2.4s-v3.4s}}, [{out}], #32",
            "st1 {{v4.4s-v5.4s}}, [{out}], #32",
            "st1 {{v6.4s-v7.4s}}, [{out}], #32",
            "st1 {{v8.4s-v9.4s}}, [{out}], #32",
            "st1 {{v10.4s-v11.4s}}, [{out}], #32",
            "st1 {{v12.4s-v13.4s}}, [{out}], #32",
            "movi v0.16b, #0",
            "movi v1.16b, #0",
            "movi v2.16b, #0",
            "movi v3.16b, #0",
            "movi v4.16b, #0",
            "movi v5.16b, #0",
            "movi v6.16b, #0",
            "movi v7.16b, #0",
            "movi v8.16b, #0",
            "movi v9.16b, #0",
            "movi v10.16b, #0",
            "movi v11.16b, #0",
            "movi v12.16b, #0",
            "movi v13.16b, #0",
            "movi v14.16b, #0",
            "movi v15.16b, #0",
            "movi v16.16b, #0",
            "movi v17.16b, #0",
            "movi v18.16b, #0",
            "movi v19.16b, #0",
            "movi v20.16b, #0",
            "movi v21.16b, #0",
            "movi v22.16b, #0",
            "movi v23.16b, #0",
            "movi v24.16b, #0",
            "movi v25.16b, #0",
            "movi v26.16b, #0",
            "movi v27.16b, #0",
            table=inout(reg) table.as_ptr()=>_,indices=in(reg) indices.as_ptr(),
            out=inout(reg) result.as_mut_ptr()=>_,tmp=out(reg) _,block=out(reg) _,count=inout(reg) table.len()=>_,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
            out("v16") _,
            out("v17") _,
            out("v18") _,
            out("v19") _,
            out("v20") _,
            out("v21") _,
            out("v22") _,
            out("v23") _,
            out("v24") _,
            out("v25") _,
            out("v26") _,
            out("v27") _,
            options(nostack)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arbitrary_eight_gather_and_invalid_indices_match_scalar() {
        let mut seed = 0xa01738ca4918u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u32
        };
        for blocks in [1usize, 2, 3, 8, 32, 64] {
            let table: Vec<Block> = (0..blocks)
                .map(|_| core::array::from_fn(|_| core::array::from_fn(|_| next())))
                .collect();
            for _ in 0..128 {
                let indices = [
                    next() % (blocks as u32 * 16),
                    next() % 2048,
                    next() % 16,
                    next() % (blocks as u32 * 16),
                    0,
                    16 * blocks as u32 - 1,
                    16 * blocks as u32,
                    u32::MAX,
                ];
                let mut actual = Zeroizing::new([[0u32; 8]; 7]);
                gather_eight_into(&mut actual, &table, &indices);
                for column in 0..7 {
                    for lane in 0..8 {
                        let index = indices[lane] as usize;
                        let expected = table.get(index / 16).map_or(0, |b| b[column][index % 16]);
                        assert_eq!(actual[column][lane], expected);
                    }
                }
            }
        }
    }
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
    fn native_four_matches_original_eight_with_all_padding_and_tie_states() {
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
                let mut expected_draws = [[0u64; 3]; 8];
                expected_draws[..4].copy_from_slice(&draws);
                let mut actual = [[0u64; 2]; 4];
                let mut expected = [[0u64; 2]; 8];
                tree.four(&draws, &mut actual, &z);
                tree.eight(&expected_draws, &mut expected, &z);
                assert_eq!(actual, expected[..4], "public groups {n}");
            }
        }
    }
}
