//! Exact cap statistics; finite integer certificate. Each table holds one
//! quartic, in its entry 0: there is a single piece and no lookup.
use crate::{ct::ct_lt_u64, params::*};
use zeroize::Zeroizing;
include!("cap_piecewise_tables.rs");
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_ct_caps_piecewise\n.p2align 2\n_pretzel44_ct_caps_piecewise:\n",
        include_str!("ct_caps_piecewise.S")
    ),
    options(raw)
);
// SAFETY: contract of the assembly routine defined just above (ct_caps_piecewise.S). It reads 16
// `i32` at each of `a`, `b` and `c`, 32 `u32` at `fix` and `count` `i32` at `input`, four at a
// time, and writes three `u64` at `out`. `count` must be a multiple of 4; zero is accepted. No
// alignment is required. It uses NEON only, saves and restores d8 to d15 in a 64-byte frame that it
// clears, keeps no pointer and has no global state.
unsafe extern "C" {
    fn pretzel44_ct_caps_piecewise(
        out: *mut u64,
        input: *const i32,
        count: usize,
        a: *const i32,
        b: *const i32,
        c: *const i32,
        fix: *const u32,
        infinity: u64,
    );
}
fn stats(input: &[i32], head: bool) -> Zeroizing<[u64; 3]> {
    assert!(input.len() <= 1280 && input.len() % 4 == 0);
    let (a, b, c, fix, cap) = if head {
        (&HEAD_A, &HEAD_B, &HEAD_C, &HEAD_FIX, CAP_INF_HEAD)
    } else {
        (&RES_A, &RES_B, &RES_C, &RES_FIX, CAP_INF_RES)
    };
    let mut out = Zeroizing::new([0u64; 3]);
    // Public lengths/mode only; all table extents exact and fixed. The native
    // leaf clears working registers and its 64-byte ABI save frame. Outputs are
    // disjoint, initialized and erased by their explicit owner.
    // SAFETY: input.len()<=1280 and divisible by four is asserted, including zero. A/B/C have
    // 16 i32 entries and fix 32 u32 entries; ct_caps_piecewise.S reads those 64/128-byte tables
    // and exactly input.len() i32 values, then writes the disjoint three-u64 out. This
    // AArch64/neon module supplies NEON.
    unsafe {
        pretzel44_ct_caps_piecewise(
            out.as_mut_ptr(),
            input.as_ptr(),
            input.len(),
            a.as_ptr(),
            b.as_ptr(),
            c.as_ptr(),
            fix.as_ptr(),
            cap as u64,
        );
    }
    out
}
pub(crate) fn check_caps(head: &[i32], res: &[i32]) -> u64 {
    let h = stats(head, true);
    let r = stats(res, false);
    !(h[2]
        | r[2]
        | ct_lt_u64(CAP_EUC2_HEAD, h[1])
        | ct_lt_u64(CAP_EUC2_RES, r[1])
        | ct_lt_u64(CAP_Q20, h[0] + r[0]))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference(input: &[i32], head: bool) -> [u64; 3] {
        let table = if head {
            crate::params_tables::W_HEAD.as_slice()
        } else {
            crate::params_tables::W_RES.as_slice()
        };
        let mut out = [0u64; 3];
        for &v in input {
            let a = v.unsigned_abs() as usize;
            if a >= table.len() {
                out[2] = u64::MAX;
            } else {
                out[0] += table[a] as u64;
                out[1] += (a * a) as u64;
            }
        }
        out
    }
    #[test]
    fn all_magnitudes_lanes_and_full_width_match_exact_tables() {
        for head in [false, true] {
            for a in 0..1024i32 {
                for lane in 0..4 {
                    for sign in [-1, 1] {
                        let mut v = [0i32; 4];
                        v[lane] = a * sign;
                        assert_eq!(*stats(&v, head), reference(&v, head));
                    }
                }
            }
            for value in [i32::MIN, i32::MIN + 1, i32::MAX, -65536, 65536] {
                for lane in 0..4 {
                    let mut v = [0i32; 4];
                    v[lane] = value;
                    assert_eq!(*stats(&v, head), reference(&v, head));
                }
            }
            let mut state = 157u64;
            for len in [0, 4, 16, 128, 1024, 1280] {
                for trial in 0..64 {
                    let v: Vec<i32> = (0..len)
                        .map(|_| {
                            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                            let x = (state >> 32) as i32;
                            if trial % 2 == 0 {
                                x
                            } else {
                                x % 512
                            }
                        })
                        .collect();
                    assert_eq!(*stats(&v, head), reference(&v, head));
                }
            }
        }
    }
}
