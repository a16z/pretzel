//! Constant-time primitives for masks, comparisons and vector extraction.
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
/// `s.rem_euclid(q)`. Plain 32-bit arithmetic avoids a widening multiply and
/// permits vectorization without general/SIMD register moves. Inspect emitted
/// instructions: a remainder expression can introduce 64-bit multiplies and
/// `fmov`/`mov.d` extraction of secret operands.
#[inline(always)]
pub(crate) fn reduce_once(s: i32, q: i32) -> i32 {
    debug_assert!(s > -q && s < 2 * q);
    let s = s + (q & (s >> 31));
    s - (q & !((s - q) >> 31))
}

/// Lane extraction and byte sums through Advanced SIMD element moves (UMOV,
/// SMOV) and the vector reductions (UADDLV, SADDLV). The compiler's
/// lowering for `vgetq_lane`/`vaddvq`/`vaddlvq` can use `fmov xN, dM`.
/// These helpers require the Advanced SIMD element moves covered by the
/// DIT instruction contract instead. Inline assembly fixes the instruction
/// choice.
pub(crate) mod lanes {
    use core::arch::aarch64::*;
    /// Signed sum of sixteen bytes (SADDLV to a halfword, SMOV sign-extended).
    #[inline(always)]
    pub(crate) fn sum_i8x16(v: int8x16_t) -> i32 {
        let out: i32;
        // SAFETY: SADDLV and SMOV use only the initialized vector input and the declared output and
        // scratch registers; no memory, stack or flags are changed.
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
        // SAFETY: base AArch64 instructions on registers only (`nomem`, `nostack`). Every input is
        // an initialized `u64` read through a checked index, the only output is declared, and the
        // options allow the flags to change.
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

/// All-ones iff a < b (unsigned).
///
/// The optimizer can lower an arithmetic mask (including its use inside
/// `ct_lt_limbs_be`) to a comparison followed by conditional branches that
/// materialize 0 or all-ones, creating a secret-dependent instruction trace.
/// On aarch64 the
/// mask is therefore produced by `cmp`/`csetm` directly; the optimizer cannot
/// turn an opaque assembly result into control flow.
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
        // SAFETY: as in `ct_lt_u64`.
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
        // Without the barrier the optimizer can turn this comparison chain
        // into conditional branches on the secret draw.
        // The barrier forces both accumulators
        // to be materialized as mask values every iteration.
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
