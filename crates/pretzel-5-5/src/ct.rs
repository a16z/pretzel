//! Constant-time primitives.
//!
//! Source-level fixed-pattern primitives.
//! Masks are all-ones (u64::MAX) for true, 0 for false.

/// Identity at the machine level, opaque output to the optimizer. Without
/// this barrier the optimizer can turn mask arithmetic into secret-dependent
/// branches. Deliberately NOT `pure` or `readonly`.
#[inline(always)]
pub(crate) fn opaque_mask(mut mask: u64) -> u64 {
    // SAFETY: comment-only assembly leaves the initialized register unchanged,
    // accesses no memory or stack, and does not change flags. No caller contract.
    unsafe {
        core::arch::asm!("/* {value} */", value = inout(reg) mask,
            options(nomem, nostack, preserves_flags));
    }
    mask
}

/// One correction step: for `s` in the open range $(-q, 2q)$ the value equals
/// `s.rem_euclid(q)`. Plain 32-bit arithmetic avoids widening multiplication
/// and allows callers to stay on 32-bit SIMD lanes without extracting operands.
#[inline(always)]
pub(crate) fn reduce_once(s: i32, q: i32) -> i32 {
    debug_assert!(s > -q && s < 2 * q);
    let s = s + (q & (s >> 31));
    s - (q & !((s - q) >> 31))
}

/// Lane extraction and byte sums through Advanced SIMD element moves (UMOV,
/// SMOV) and the vector reductions (UADDLV, SADDLV). The compiler's
/// lowering of `vgetq_lane`/`vaddvq`/`vaddlvq` can use `fmov xN, dM`, which is
/// outside the assumed DIT-covered instruction set. The element moves used
/// here are in its Advanced SIMD group. Inline assembly fixes the instruction.
pub(crate) mod lanes {
    use core::arch::aarch64::*;
    /// Sum of sixteen unsigned bytes (UADDLV to a halfword, UMOV).
    #[inline(always)]
    pub(crate) fn sum_u8x16(v: uint8x16_t) -> u32 {
        let out: u32;
        // SAFETY: register-only, the scratch vector register is written before it is read.
        unsafe {
            core::arch::asm!("uaddlv {t:h}, {v:v}.16b", "umov {out:w}, {t:v}.h[0]",
            out = lateout(reg) out, v = in(vreg) v, t = out(vreg) _,
            options(pure, nomem, nostack, preserves_flags));
        }
        out
    }
    /// Signed sum of sixteen bytes (SADDLV to a halfword, SMOV sign-extended).
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn sum_i8x16(v: int8x16_t) -> i32 {
        let out: i32;
        // SAFETY: AArch64/neon selects Advanced SIMD. SADDLV and SMOV use only initialized registers;
        // the scratch register is written first and all outputs are declared. Memory, stack and flags
        // are untouched.
        unsafe {
            core::arch::asm!("saddlv {t:h}, {v:v}.16b", "smov {out:w}, {t:v}.h[0]",
            out = lateout(reg) out, v = in(vreg) v, t = out(vreg) _,
            options(pure, nomem, nostack, preserves_flags));
        }
        out
    }
}

/// Full Q64.384 comparison, including the integer limb. Dropping that limb
/// would turn a threshold of one into zero.
#[inline(always)]
pub fn ct_lt_fx(a: &crate::fixed::Fx, b: &crate::fixed::Fx) -> u64 {
    {
        let mask: u64;
        // Unsigned seven-limb subtraction, least significant limb first.
        // Final carry is clear exactly when the full 448-bit value a is below
        // b. All inputs are read-only registers; no value controls execution.
        // SAFETY: The AArch64 gate of build.rs selects these integer instructions. Seven initialized input limbs
        // are passed in registers; mask is a declared output and flags are clobbered. No memory or
        // stack is accessed.
        unsafe {
            core::arch::asm!(
                "subs xzr, {a0}, {b0}",
                "sbcs xzr, {a1}, {b1}",
                "sbcs xzr, {a2}, {b2}",
                "sbcs xzr, {a3}, {b3}",
                "sbcs xzr, {a4}, {b4}",
                "sbcs xzr, {a5}, {b5}",
                "sbcs xzr, {a6}, {b6}",
                "csetm {mask}, lo",
                a0=in(reg)a.0[0],a1=in(reg)a.0[1],a2=in(reg)a.0[2],
                a3=in(reg)a.0[3],a4=in(reg)a.0[4],a5=in(reg)a.0[5],a6=in(reg)a.0[6],
                b0=in(reg)b.0[0],b1=in(reg)b.0[1],b2=in(reg)b.0[2],
                b3=in(reg)b.0[3],b4=in(reg)b.0[4],b5=in(reg)b.0[5],b6=in(reg)b.0[6],
                mask=lateout(reg)mask,options(nomem,nostack)
            );
        }
        mask
    }
}

/// Enumerate a public schedule, even for zero-weight/aborted attempts. The
/// callback's first argument identifies the public transport/dummy phase;
/// its mask says whether that slot contributes to the mathematical attempt.
#[allow(dead_code)]
// Keep the explicit lane order and index schedule of the kernel and its oracle.
#[allow(clippy::needless_range_loop)]
pub(crate) fn visit_signing_slots(
    c: &crate::challenge::Challenge,
    mut visit: impl FnMut(bool, usize, u64),
) {
    let weight = crate::challenge::weight(c);
    for j in 0..crate::params::N {
        visit(true, j, 0u64.wrapping_sub(u64::from(c[j])));
    }
    for j in 0..128 {
        let active = ct_lt_u64((j + weight) as u64, 128);
        visit(false, j, active);
    }
}

/// All-ones iff a < b (unsigned).
///
/// Arithmetic mask expressions can become secret-dependent conditional branches.
/// On aarch64, `cmp`/`csetm` produces the mask directly and
/// hides its comparison from the optimizer.
#[inline(always)]
pub fn ct_lt_u64(a: u64, b: u64) -> u64 {
    {
        let m: u64;
        // SAFETY: register-only compare and conditional set; no memory, stack or
        // caller state is touched. Flags are clobbered, which the default
        // options declare.
        unsafe {
            core::arch::asm!("cmp {a}, {b}", "csetm {m}, lo",
                a = in(reg) a, b = in(reg) b, m = lateout(reg) m,
                options(pure, nomem, nostack));
        }
        m
    }
}

/// All-ones iff a == b. Same barrier rationale as `ct_lt_u64`.
#[inline(always)]
pub fn ct_eq_u64(a: u64, b: u64) -> u64 {
    {
        let m: u64;
        // SAFETY: The AArch64 gate of build.rs selects CMP/CSETM. Both inputs are initialized registers, m
        // is written before use, and the default asm options permit flag changes; there are no memory
        // or stack accesses.
        unsafe {
            core::arch::asm!("cmp {a}, {b}", "csetm {m}, eq",
                a = in(reg) a, b = in(reg) b, m = lateout(reg) m,
                options(pure, nomem, nostack));
        }
        m
    }
}

/// b ^ (mask & (a ^ b)): a if mask is all-ones, b if mask is 0.
#[inline(always)]
pub fn ct_select_u64(mask: u64, a: u64, b: u64) -> u64 {
    let mask = opaque_mask(mask);
    b ^ (mask & (a ^ b))
}

#[inline(always)]
pub fn ct_select_i64(mask: u64, a: i64, b: i64) -> i64 {
    let mask = opaque_mask(mask);
    (b as u64 ^ (mask & (a as u64 ^ b as u64))) as i64
}

#[inline(always)]
pub fn ct_select_i32(mask: u64, a: i32, b: i32) -> i32 {
    let m = opaque_mask(mask) as u32;
    (b as u32 ^ (m & (a as u32 ^ b as u32))) as i32
}

/// All-ones iff a < b as K-limb big-endian unsigned integers
/// (limb 0 most significant). Borrow chain, fixed K iterations.
#[inline(always)]
pub fn ct_lt_limbs_be<const K: usize>(a: &[u64; K], b: &[u64; K]) -> u64 {
    // walk most-significant to least: lt if a_i < b_i at the first differing
    // limb; carry an "already decided" mask.
    let mut lt = 0u64;
    let mut decided = 0u64;
    for i in 0..K {
        let this_lt = ct_lt_u64(a[i], b[i]);
        let this_ne = !ct_eq_u64(a[i], b[i]);
        // The barrier keeps both accumulators as mask values each iteration,
        // preventing the comparison chain from becoming secret-dependent branches.
        lt = opaque_mask(lt | (!decided & this_lt));
        decided = opaque_mask(decided | this_ne);
    }
    lt
}

/// All-ones iff a == b as K-limb values.
#[inline(always)]
pub fn ct_eq_limbs<const K: usize>(a: &[u64; K], b: &[u64; K]) -> u64 {
    let mut acc = 0u64;
    for i in 0..K {
        acc |= a[i] ^ b[i];
    }
    ct_eq_u64(acc, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_slot_schedule_is_independent_of_challenge_weight() {
        for weight in [0, 1, 2, 63, 127, 128] {
            let mut c = [false; 256];
            for bit in &mut c[..weight] {
                *bit = true;
            }
            let mut trace = Vec::new();
            let mut active = [0usize; 2];
            visit_signing_slots(&c, |transport, j, mask| {
                trace.push((transport, j));
                active[usize::from(!transport)] += (mask & 1) as usize;
            });
            let expected: Vec<_> = (0..256)
                .map(|j| (true, j))
                .chain((0..128).map(|j| (false, j)))
                .collect();
            assert_eq!(trace, expected);
            assert_eq!(active, [weight, 128 - weight]);
        }
    }

    #[test]
    fn full_fixed_point_comparison_includes_integer_limb() {
        use crate::fixed::Fx;
        let points = [
            Fx::ZERO,
            Fx::ULP,
            Fx::ONE.sub(&Fx::ULP),
            Fx::ONE,
            Fx::ONE.add(&Fx::ULP),
            Fx::from_int(2),
            Fx([u64::MAX; 7]),
        ];
        for a in points {
            for b in points {
                assert_eq!(ct_lt_fx(&a, &b) == u64::MAX, a.lt(&b));
            }
        }
    }

    #[test]
    fn scalar_masks() {
        for mask in [0, 1, 3, 1 << 63, u64::MAX] {
            assert_eq!(opaque_mask(mask), mask);
        }
        assert_eq!(ct_lt_u64(1, 2), u64::MAX);
        assert_eq!(ct_lt_u64(2, 1), 0);
        assert_eq!(ct_lt_u64(5, 5), 0);
        assert_eq!(ct_lt_u64(0, u64::MAX), u64::MAX);
        assert_eq!(ct_lt_u64(u64::MAX, 0), 0);
        assert_eq!(ct_eq_u64(7, 7), u64::MAX);
        assert_eq!(ct_eq_u64(7, 8), 0);
        assert_eq!(ct_select_u64(u64::MAX, 3, 9), 3);
        assert_eq!(ct_select_u64(0, 3, 9), 9);
        assert_eq!(ct_select_i32(u64::MAX, -5, 11), -5);
        assert_eq!(ct_select_i32(0, -5, 11), 11);
    }

    #[test]
    fn limb_compare_matches_u128_extension() {
        let mut st = 0x12345678u64;
        let mut rnd = move || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        for t in 0..20000 {
            let a = [rnd(), rnd(), rnd()];
            let mut b = [rnd(), rnd(), rnd()];
            // force limb equalities often to exercise the chain
            if t % 3 == 0 {
                b[0] = a[0];
            }
            if t % 5 == 0 {
                b[1] = a[1];
            }
            if t % 7 == 0 {
                b = a;
            }
            let av = (a[0] as u128) << 64 | a[1] as u128; // compare top two, then third
            let bv = (b[0] as u128) << 64 | b[1] as u128;
            let expect_lt = av < bv || (av == bv && a[2] < b[2]);
            let expect_eq = a == b;
            assert_eq!(ct_lt_limbs_be(&a, &b) == u64::MAX, expect_lt);
            assert_eq!(ct_eq_limbs(&a, &b) == u64::MAX, expect_eq);
        }
    }
}

#[cfg(test)]
mod native_fx_compare_tests {
    use super::*;
    use crate::fixed::Fx;
    #[test]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn full_width_borrow_chains_and_equality() {
        let mut cases = vec![Fx::ZERO, Fx::ONE, Fx([u64::MAX; 7])];
        for limb in 0..7 {
            for v in [1, 2, u64::MAX - 1, u64::MAX] {
                let mut a = [0; 7];
                a[limb] = v;
                cases.push(Fx(a));
                let mut b = [u64::MAX; 7];
                b[limb] = v;
                cases.push(Fx(b));
                let mut c = a;
                for k in 0..limb {
                    c[k] = u64::MAX;
                }
                cases.push(Fx(c));
            }
        }
        for a in &cases {
            for b in &cases {
                assert_eq!(ct_lt_fx(a, b), 0u64.wrapping_sub(u64::from(a.lt(b))));
            }
        }
    }
}
