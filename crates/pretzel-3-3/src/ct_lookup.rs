//! Fixed-address word-table lookup. Every public block is read; secret indices
//! select only bytes already held in SIMD registers.
//!
//! Outside test builds this module holds only `check_caps`, which forwards to
//! `ct_caps_piecewise::check_caps`. The lookup, the weight polynomials and the portable
//! statement of the caps are compiled for tests, which compare the piecewise check with them.
#[cfg(test)]
use crate::params_tables::{W_HEAD, W_RES};
#[cfg(test)]
use crate::{ct::ct_lt_u64, params::*};
#[cfg(test)]
use zeroize::Zeroizing;

#[cfg(test)]
pub(crate) fn padded(values: impl IntoIterator<Item = u32>) -> Vec<u32> {
    let mut out: Vec<_> = values.into_iter().collect();
    out.resize((out.len() + 15) / 16 * 16, 0);
    out
}
#[inline(never)]
#[cfg(test)]
pub(crate) fn lookup4(table: &[u32], indices: &[u32; 4]) -> Zeroizing<[u32; 4]> {
    assert!(table.len() % 16 == 0 && table.len() <= u32::MAX as usize);
    let mut result = Zeroizing::new([0u32; 4]);
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `table.len() % 16 == 0` is asserted above and
    // `chunks_exact(16)` yields complete 16-word blocks, each read by four four-lane loads.
    // `indices` and `result` have four `u32` each, read and written by one load and one store. The
    // asm template is an assembler comment that emits no instruction.
    unsafe {
        use core::arch::aarch64::*;
        // Every load below lies in the public complete sixteen-word block.
        let query = vld1q_u32(indices.as_ptr());
        let high = vshrq_n_u32::<4>(query);
        let low = vandq_u32(query, vdupq_n_u32(15));
        let bytes = vreinterpretq_u8_u32(vaddq_u32(
            vmulq_n_u32(low, 0x04040404),
            vdupq_n_u32(0x03020100),
        ));
        let mut selected = vdupq_n_u32(0);
        for (block, words) in table.chunks_exact(16).enumerate() {
            let table = uint8x16x4_t(
                vreinterpretq_u8_u32(vld1q_u32(words.as_ptr())),
                vreinterpretq_u8_u32(vld1q_u32(words.as_ptr().add(4))),
                vreinterpretq_u8_u32(vld1q_u32(words.as_ptr().add(8))),
                vreinterpretq_u8_u32(vld1q_u32(words.as_ptr().add(12))),
            );
            let row = vreinterpretq_u32_u8(vqtbl4q_u8(table, bytes));
            let mut mask = vceqq_u32(high, vdupq_n_u32(block as u32));
            // Identity to the processor; keep all four masks opaque to LLVM.
            core::arch::asm!("/* {value:v} */",value=inout(vreg) mask,options(nomem,nostack,preserves_flags));
            selected = vorrq_u32(selected, vandq_u32(row, mask));
        }
        vst1q_u32(result.as_mut_ptr(), selected);
    }
    result
}
// Exact reconstruction of the public Q20 weight tables without a table scan:
// W[a] = floor(P(a) / 2^K) + e[a], with P a fixed-point polynomial (Horner in
// i64, |intermediate| < 2^62 for every a < 512) and e[a] a two-bit correction
// packed sixteen entries per word. The test below checks equality with W_HEAD
// and W_RES at every index; only the correction words are looked up, through
// the same fixed-address `lookup4` (two sixteen-word blocks instead of 19/29).
#[cfg(test)]
const HEAD_POLY: [i64; 5] = [790596, -15505052, 6679892313574, -77029378717, 162947722014];
#[cfg(test)]
const HEAD_K: u32 = 40;
#[cfg(test)]
const HEAD_FIX: [u32; 32] = [
    0x69655554, 0x9aaa9a59, 0x96aaaaaa, 0xa9696aa6, 0xa6566a9a, 0x55665556, 0x55565599, 0x5655a659,
    0x95659596, 0x56a56999, 0xa966aaaa, 0xaaaaaaaa, 0xaa6a999a, 0x5aa66a96, 0x5555566a, 0x656555a6,
    0x955a5555, 0xeaa9a665, 0x00000003, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
];
#[cfg(test)]
const RES_POLY: [i64; 6] = [
    273,
    843490,
    37538844,
    8899693228055,
    202951428472,
    -1733554901,
];
#[cfg(test)]
const RES_K: u32 = 42;
#[cfg(test)]
const RES_FIX: [u32; 32] = [
    0x05114555, 0x10414005, 0x00500504, 0x41550104, 0x41550511, 0x14000511, 0x15150145, 0x01514555,
    0x11050555, 0x10011155, 0x14144151, 0x50541405, 0x00040440, 0x50514151, 0x00404540, 0x45500051,
    0x55401545, 0x51454510, 0x15145515, 0x50410411, 0x51505555, 0x55455515, 0x14555555, 0x55545145,
    0x44444455, 0x45141544, 0x55545451, 0x569a5659, 0x000000aa, 0x00000000, 0x00000000, 0x00000000,
];

/// floor(P(a) / 2^k) for the fixed-point polynomial; wrapping arithmetic so an
/// out-of-cap magnitude (already recorded in the fail mask) cannot trap.
#[inline(always)]
#[cfg(test)]
fn weight_poly(coefficients: &[i64], k: u32, a: u32) -> u64 {
    let mut acc: i64 = 0;
    for &c in coefficients {
        acc = acc.wrapping_mul(a as i64).wrapping_add(c);
    }
    (acc >> k) as u64
}

/// Both lengths must be multiples of four and at most 1280 (`ct_caps_piecewise` asserts it); the
/// signer passes 1024 and 768.
pub(crate) fn check_caps(head: &[i32], residual: &[i32]) -> u64 {
    crate::ct_caps_piecewise::check_caps(head, residual)
}

/// Arithmetic oracle of the caps, for any public lengths.
#[cfg(test)]
fn check_caps_portable(head: &[i32], residual: &[i32]) -> u64 {
    let mut fail = 0u64;
    let mut q20 = 0u64;
    for (values, poly, k, fix, infinity, euclidean) in [
        (
            head,
            HEAD_POLY.as_slice(),
            HEAD_K,
            HEAD_FIX.as_slice(),
            CAP_INF_HEAD as u64,
            CAP_EUC2_HEAD,
        ),
        (
            residual,
            RES_POLY.as_slice(),
            RES_K,
            RES_FIX.as_slice(),
            CAP_INF_RES as u64,
            CAP_EUC2_RES,
        ),
    ] {
        let mut squares = 0u64;
        for chunk in values.chunks(4) {
            let mut indices = Zeroizing::new([u32::MAX; 4]);
            let mut base = Zeroizing::new([0u64; 4]);
            for (i, &v) in chunk.iter().enumerate() {
                let a = v.unsigned_abs();
                indices[i] = a >> 4;
                fail |= ct_lt_u64(infinity, a as u64);
                // Invalid full-range i32 inputs still reject through infinity;
                // use the same defined modular sum in debug and release builds.
                squares = squares.wrapping_add((a as u64) * (a as u64));
                base[i] = weight_poly(poly, k, a);
            }
            let words = lookup4(fix, &indices);
            for (i, &v) in chunk.iter().enumerate() {
                let a = v.unsigned_abs();
                let correction = (words[i] >> (2 * (a & 15))) & 3;
                q20 = q20.wrapping_add(base[i]).wrapping_add(correction as u64);
            }
        }
        fail |= ct_lt_u64(euclidean, squares);
    }
    fail |= ct_lt_u64(CAP_Q20, q20);
    !fail
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn polynomial_and_correction_reproduce_both_weight_tables_exactly() {
        for (table, poly, k, fix) in [
            (
                W_HEAD.as_slice(),
                HEAD_POLY.as_slice(),
                HEAD_K,
                HEAD_FIX.as_slice(),
            ),
            (
                W_RES.as_slice(),
                RES_POLY.as_slice(),
                RES_K,
                RES_FIX.as_slice(),
            ),
        ] {
            for (a, &w) in table.iter().enumerate() {
                let a = a as u32;
                let word = lookup4(fix, &[a >> 4, 0, 0, 0])[0];
                let value = weight_poly(poly, k, a) + u64::from((word >> (2 * (a & 15))) & 3);
                assert_eq!(value, w as u64, "index {a}");
                // No intermediate of the Horner scheme leaves i64 for any a < 512.
            }
            for a in 0..512i64 {
                let mut acc: i64 = 0;
                for &c in poly {
                    acc = acc.checked_mul(a).unwrap().checked_add(c).unwrap();
                }
            }
        }
    }
    #[test]
    fn all_indices_and_lanes_match_word_tables() {
        for n in [0, 1, 7, 16, 289, 452, 2632] {
            let table = padded((0..n).map(|i| (i as u32).wrapping_mul(0x5fa8391d) ^ 0x8472fb38));
            for lane in 0..4 {
                for index in (0..table.len() as u32 + 16).chain([u32::MAX, 1 << 31, 65536]) {
                    let mut indices = [0, 15, 16, u32::MAX];
                    indices[lane] = index;
                    let result = lookup4(&table, &indices);
                    for j in 0..4 {
                        assert_eq!(
                            result[j],
                            table.get(indices[j] as usize).copied().unwrap_or(0)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn fused_caps_complete_masks_match_reference_at_accept_reject_boundaries() {
        let mut head = vec![0i32; N + ELL * N];
        let mut residual = vec![0i32; M * N];
        let mut accepted = 0;
        let mut rejected = 0;
        // Constant vectors sweep the complete joint capacity transition,
        // separately straddling both Euclidean bounds as well as Q20.
        for a in 0..=70 {
            head.fill(a);
            for b in 0..=130 {
                residual.fill(-b);
                let got = check_caps(&head, &residual);
                assert_eq!(
                    got,
                    check_caps_portable(&head, &residual),
                    "head={a} residual={b}"
                );
                if got == 0 {
                    rejected += 1;
                } else {
                    accepted += 1;
                }
            }
        }
        assert!(accepted > 0 && rejected > 0);
        // Distinct nonconstant signed inputs, including near-capacity cases.
        let mut state = 0x634abd8579012fceu64;
        for case in 0..512 {
            for (values, scale) in [
                (&mut head, 20 + case % 60),
                (&mut residual, 35 + case % 120),
            ] {
                for value in values.iter_mut() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    *value = ((state % ((2 * scale + 1) as u64)) as i32) - scale;
                }
            }
            assert_eq!(
                check_caps(&head, &residual),
                check_caps_portable(&head, &residual)
            );
        }
        for lane in 0..4 {
            for (head_bad, res_bad) in [
                (CAP_INF_HEAD, CAP_INF_RES),
                (CAP_INF_HEAD + 1, CAP_INF_RES),
                (CAP_INF_HEAD, CAP_INF_RES + 1),
                (512, 512),
                (i32::MIN, i32::MAX),
            ] {
                for sign in [-1i32, 1] {
                    head.fill(0);
                    residual.fill(0);
                    head[lane] = head_bad.wrapping_mul(sign);
                    residual[lane] = res_bad.wrapping_mul(sign);
                    assert_eq!(
                        check_caps(&head, &residual),
                        check_caps_portable(&head, &residual)
                    );
                }
            }
        }
        // Short public lengths, multiples of four.
        for h in [0, 4, 8] {
            for r in [0, 4, 8] {
                assert_eq!(
                    check_caps(&head[..h], &residual[..r]),
                    check_caps_portable(&head[..h], &residual[..r])
                );
            }
        }
    }
}

#[cfg(test)]
mod piecewise_predicate_tests {
    use super::*;
    #[test]
    fn complete_predicate_matches_portable_including_invalid() {
        let mut state = 23u64;
        for len in [0, 4, 16, 128, 1024, 1280] {
            for trial in 0..64 {
                let mut make = || {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let v = (state >> 32) as i32;
                    if trial % 2 == 0 {
                        v % 40
                    } else {
                        v
                    }
                };
                let h: Vec<i32> = (0..len).map(|_| make()).collect();
                let r: Vec<i32> = (0..len).map(|_| make()).collect();
                assert_eq!(check_caps(&h, &r), check_caps_portable(&h, &r));
            }
        }
    }
}
