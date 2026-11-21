//! NEON (aarch64) vector paths for the hot ring arithmetic.
//! Every function here computes a result BIT-IDENTICAL to its scalar
//! twin in `ring` (all outputs are the unique representative in [0, q)), so it
//! is a drop-in replacement verified by equality tests. Compiled for
//! `target_arch = "aarch64"` only.
//!
//! Reduction covers nonnegative x < 2^29, including products, inverse
//! butterflies and five-product sums. With V = floor(2^31 / q), the
//! doubling high multiply gives q_est = (2 * x * V) >> 32, which is
//! floor(x/q) or one less. Thus the residual is in [0, 2q); one
//! conditional subtraction suffices.

use crate::params::{N, Q};
use crate::ring::Poly;
use core::arch::aarch64::*;

/// Exact low-width replacements. No prepared state or tables are added.
/// All inputs stay within the callers' documented ranges.
///
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values and checked array indexing only; it accesses no memory through a
/// raw pointer.
#[inline(always)]
unsafe fn reduce_i32x4(x: int32x4_t) -> int32x4_t {
    {
        // V=floor(2^31/q): 0 <= x/q-x*V/2^31 < x/2^31 < 1/4.
        // Thus the estimate is floor(x/q) or one less. The residual is in
        // [0,2q), and one conditional subtraction gives the unique residue.
        const V31: i32 = ((1i64 << 31) / Q as i64) as i32;
        let q = vdupq_n_s32(Q);
        let estimate = vqdmulhq_s32(x, vdupq_n_s32(V31));
        let residual = vmlsq_s32(x, estimate, q);
        vsubq_s32(
            residual,
            vandq_s32(vreinterpretq_s32_u32(vcgeq_s32(residual, q)), q),
        )
    }
}

/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values and checked array indexing only; it accesses no memory through a
/// raw pointer.
#[inline(always)]
unsafe fn barrett16(a: int16x8_t) -> int16x8_t {
    {
        // floor((floor(a*V/2^15)+2^10)/2^11)
        // = floor((a*V+2^25)/2^26), including negative a.
        // |a*V| < 2^29, so SQDMULH does not saturate.
        let high = vqdmulhq_s16(a, vdupq_n_s16(BARRETT_V as i16));
        let quotient = vrshrq_n_s16::<11>(high);
        vmlsq_s16(a, quotient, vdupq_n_s16(Q16))
    }
}

/// Pointwise product mod q, bit-identical to `ring::pointwise`.
pub fn pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut r = Poly::ZERO;
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `i` advances by eight while `i < N` (N = 256), so
    // every unaligned four-lane load from `a.0` and `b.0` and every store to `r.0`, at `i` and `i +
    // 4`, stays inside the `N`-element coefficient arrays. `r` is a local, distinct from both
    // inputs.
    unsafe {
        let mut i = 0;
        while i < N {
            // load 8 i32 coefficients from each operand as two i32x4 vectors,
            // multiply into i32 (products < 2^26 fit), reduce, store.
            let a0 = vld1q_s32(a.0.as_ptr().add(i));
            let a1 = vld1q_s32(a.0.as_ptr().add(i + 4));
            let b0 = vld1q_s32(b.0.as_ptr().add(i));
            let b1 = vld1q_s32(b.0.as_ptr().add(i + 4));
            let p0 = reduce_i32x4(vmulq_s32(a0, b0));
            let p1 = reduce_i32x4(vmulq_s32(a1, b1));
            vst1q_s32(r.0.as_mut_ptr().add(i), p0);
            vst1q_s32(r.0.as_mut_ptr().add(i + 4), p1);
            i += 8;
        }
    }
    r
}

/// `acc += a * b` coefficient-wise mod q, in place. For canonical inputs the result equals
/// `acc.add(&pointwise(a, b))`. The product and the sum stay in vector registers and the only
/// store is into `acc`, so no polynomial-sized value is returned or left in a temporary.
pub(crate) fn add_pointwise_assign(acc: &mut Poly, a: &Poly, b: &Poly) {
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `i` advances by eight while `i < N` (N = 256), so
    // every unaligned four-lane load from `a.0`, `b.0` and `acc.0` and every store to `acc.0`,
    // at `i` and `i + 4`, stays inside the `N`-element coefficient arrays. `acc` is an exclusive
    // borrow, distinct from both inputs.
    unsafe {
        let q = vdupq_n_s32(Q);
        let mut i = 0;
        while i < N {
            let a0 = vld1q_s32(a.0.as_ptr().add(i));
            let a1 = vld1q_s32(a.0.as_ptr().add(i + 4));
            let b0 = vld1q_s32(b.0.as_ptr().add(i));
            let b1 = vld1q_s32(b.0.as_ptr().add(i + 4));
            let x0 = vld1q_s32(acc.0.as_ptr().add(i));
            let x1 = vld1q_s32(acc.0.as_ptr().add(i + 4));
            // Canonical accumulator plus canonical product lies in [0, 2q): one
            // conditional subtraction gives the unique residue, as `Poly::add` does.
            let s0 = vaddq_s32(x0, reduce_i32x4(vmulq_s32(a0, b0)));
            let s1 = vaddq_s32(x1, reduce_i32x4(vmulq_s32(a1, b1)));
            let m0 = vreinterpretq_s32_u32(vcgeq_s32(s0, q));
            let m1 = vreinterpretq_s32_u32(vcgeq_s32(s1, q));
            let r0 = vsubq_s32(s0, vandq_s32(m0, q));
            let r1 = vsubq_s32(s1, vandq_s32(m1, q));
            vst1q_s32(acc.0.as_mut_ptr().add(i), r0);
            vst1q_s32(acc.0.as_mut_ptr().add(i + 4), r1);
            i += 8;
        }
    }
}

// ---------------------------------------------------------------------------
// 16-bit lane NTT. Eight butterflies per vector, twiddle products
// a*z - round(a*mu/2^15)*q with centered twiddles z and mu = round(z*2^15/q)
// (`twiddle16`), exact widened Barrett reductions on a fixed
// schedule, and an 8x8 lane transpose for the three innermost layers. The
// transform, twiddle assignment and output order are those of `ring::ntt_scalar`
// and `ring::intt_scalar`; outputs are the canonical residues in [0, q), so
// the results are bit-identical (equality tests below and in `ring`).
//
// Bounds (q = 7681, i16 holds 4.26 q): a twiddle product lies in (-q, q);
// a CT butterfly grows the bound by q per layer; a GS sum doubles it. The
// schedule reduces before any bound reaches 2^15: forward after layers 3 and 6
// (bounds 4q, 3.5q), inverse after layers 2 and 5 (bounds 4q, 4q). The exact
// Barrett step maps to [-q/2, q/2]; the final step adds q to negatives.
// ---------------------------------------------------------------------------

const Q16: i16 = Q as i16;
/// round(2^26 / q); with |a| <= 2^15 the estimate (a*V + 2^25) >> 26 equals
/// round(a / q) exactly, because a/q is never within 2^-14 of a half-integer
/// while the estimate error is below 2^-18 (see the module comment).
const BARRETT_V: i32 = ((1i64 << 26) + Q as i64 / 2) as i32 / Q;
const _: () = assert!(BARRETT_V == 8737);

struct Ntt16Tables {
    /// Forward twiddles zetas[k] as centered residues (`zr`, `izr` for the inverse),
    /// and their companions round(z * 2^15 / q) (`zq`, `izq`); index 0 unused.
    zr: [i16; N],
    zq: [i16; N],
    izr: [i16; N],
    izq: [i16; N],
    /// Transposed-domain twiddle vectors per 64-coefficient super-block:
    /// [len=4 (1 vector), len=2 (2 vectors), len=1 (4 vectors)] x (zr, zq).
    fwd_t: [[[i16; 8]; 14]; 4],
    inv_t: [[[i16; 8]; 14]; 4],
    ninv_r: i16,
    ninv_q: i16,
}

static NTT16: std::sync::OnceLock<Ntt16Tables> = std::sync::OnceLock::new();

fn ntt16_tables() -> &'static Ntt16Tables {
    NTT16.get_or_init(|| {
        let (zetas, inv_zetas, n_inv) = crate::ring::ntt_twiddles();
        let to_r = |z: i32| (z - Q * i32::from(z > Q / 2)) as i16;
        let to_q = |z: i16| ((z as i32 * 32768 + Q / 2).div_euclid(Q)) as i16;
        let mut t = Ntt16Tables {
            zr: [0; N],
            zq: [0; N],
            izr: [0; N],
            izq: [0; N],
            fwd_t: [[[0; 8]; 14]; 4],
            inv_t: [[[0; 8]; 14]; 4],
            ninv_r: to_r(n_inv),
            ninv_q: 0,
        };
        t.ninv_q = to_q(t.ninv_r);
        for k in 0..N {
            t.zr[k] = to_r(zetas[k]);
            t.zq[k] = to_q(t.zr[k]);
            t.izr[k] = to_r(inv_zetas[k]);
            t.izq[k] = to_q(t.izr[k]);
        }
        for sb in 0..4 {
            let s = 64 * sb;
            // forward indices (see the scalar loop): len=4: 32 + s/8 + b;
            // len=2: 64 + s/4 + 2b (+1 for rows 4,5); len=1: 128 + s/2 + 4b + p/2.
            let mut fk = [[0usize; 8]; 7];
            let mut ik = [[0usize; 8]; 7];
            for b in 0..8 {
                fk[0][b] = 32 + s / 8 + b;
                fk[1][b] = 64 + s / 4 + 2 * b;
                fk[2][b] = 64 + s / 4 + 2 * b + 1;
                for h in 0..4 {
                    fk[3 + h][b] = 128 + s / 2 + 4 * b + h;
                }
                // inverse: len=1: 255 - s/2 - 4b - p/2; len=2: 127 - s/4 - 2b (-1 for rows 4,5); len=4: 63 - s/8 - b.
                ik[0][b] = 63 - s / 8 - b;
                ik[1][b] = 127 - s / 4 - 2 * b;
                ik[2][b] = 127 - s / 4 - 2 * b - 1;
                for h in 0..4 {
                    ik[3 + h][b] = 255 - s / 2 - 4 * b - h;
                }
            }
            for v in 0..7 {
                for b in 0..8 {
                    t.fwd_t[sb][2 * v][b] = t.zr[fk[v][b]];
                    t.fwd_t[sb][2 * v + 1][b] = t.zq[fk[v][b]];
                    t.inv_t[sb][2 * v][b] = t.izr[ik[v][b]];
                    t.inv_t[sb][2 * v + 1][b] = t.izq[ik[v][b]];
                }
            }
        }
        t
    })
}

/// Exact Barrett: a - q * round(a / q), result in [-q/2, q/2].
#[cfg(test)]
#[inline(always)]
unsafe fn barrett16_reference(a: int16x8_t) -> int16x8_t {
    let lo = vmovl_s16(vget_low_s16(a));
    let hi = vmovl_high_s16(a);
    let half = vdupq_n_s32(1 << 25);
    let tlo = vshrq_n_s32::<26>(vaddq_s32(vmulq_n_s32(lo, BARRETT_V), half));
    let thi = vshrq_n_s32::<26>(vaddq_s32(vmulq_n_s32(hi, BARRETT_V), half));
    let t = vcombine_s16(vmovn_s32(tlo), vmovn_s32(thi));
    vmlsq_s16(a, t, vdupq_n_s16(Q16))
}

/// [-q/2, q/2] -> [0, q).
///
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values and checked array indexing only; it accesses no memory through a
/// raw pointer.
#[inline(always)]
unsafe fn canonical16(a: int16x8_t) -> int16x8_t {
    let neg = vreinterpretq_s16_u16(vcltzq_s16(a));
    vaddq_s16(a, vandq_s16(neg, vdupq_n_s16(Q16)))
}

/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values and checked array indexing only; it accesses no memory through a
/// raw pointer.
#[inline(always)]
unsafe fn transpose8(r: &mut [int16x8_t; 8]) {
    let a0 = vtrn1q_s16(r[0], r[1]);
    let a1 = vtrn2q_s16(r[0], r[1]);
    let a2 = vtrn1q_s16(r[2], r[3]);
    let a3 = vtrn2q_s16(r[2], r[3]);
    let a4 = vtrn1q_s16(r[4], r[5]);
    let a5 = vtrn2q_s16(r[4], r[5]);
    let a6 = vtrn1q_s16(r[6], r[7]);
    let a7 = vtrn2q_s16(r[6], r[7]);
    let s = |x: int16x8_t| vreinterpretq_s32_s16(x);
    let b0 = vtrn1q_s32(s(a0), s(a2));
    let b2 = vtrn2q_s32(s(a0), s(a2));
    let b1 = vtrn1q_s32(s(a1), s(a3));
    let b3 = vtrn2q_s32(s(a1), s(a3));
    let b4 = vtrn1q_s32(s(a4), s(a6));
    let b6 = vtrn2q_s32(s(a4), s(a6));
    let b5 = vtrn1q_s32(s(a5), s(a7));
    let b7 = vtrn2q_s32(s(a5), s(a7));
    let d = |x: int32x4_t| vreinterpretq_s64_s32(x);
    let u = |x: int64x2_t| vreinterpretq_s16_s64(x);
    r[0] = u(vtrn1q_s64(d(b0), d(b4)));
    r[4] = u(vtrn2q_s64(d(b0), d(b4)));
    r[1] = u(vtrn1q_s64(d(b1), d(b5)));
    r[5] = u(vtrn2q_s64(d(b1), d(b5)));
    r[2] = u(vtrn1q_s64(d(b2), d(b6)));
    r[6] = u(vtrn2q_s64(d(b2), d(b6)));
    r[3] = u(vtrn1q_s64(d(b3), d(b7)));
    r[7] = u(vtrn2q_s64(d(b3), d(b7)));
}

/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. Nothing
/// else is required: each step reads eight `i32` of `p` (two unaligned four-lane loads) and writes
/// eight `i16` of `buf` (one unaligned store) at `i..i + 8` with `i + 8 <= N`, and both arrays have
/// exactly `N = 256` elements.
#[inline(always)]
unsafe fn load16(p: &Poly, buf: &mut [i16; N]) {
    for i in (0..N).step_by(8) {
        let lo = vld1q_s32(p.0.as_ptr().add(i));
        let hi = vld1q_s32(p.0.as_ptr().add(i + 4));
        vst1q_s16(
            buf.as_mut_ptr().add(i),
            vcombine_s16(vmovn_s32(lo), vmovn_s32(hi)),
        );
    }
}

/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. Nothing
/// else is required: each step reads eight `i16` of `buf` (one unaligned load) and writes eight
/// `i32` of `p` (two unaligned four-lane stores) at `i..i + 8` with `i + 8 <= N`, and both arrays
/// have exactly `N = 256` elements.
#[inline(always)]
unsafe fn store32(buf: &[i16; N], p: &mut Poly) {
    for i in (0..N).step_by(8) {
        let v = vld1q_s16(buf.as_ptr().add(i));
        vst1q_s32(p.0.as_mut_ptr().add(i), vmovl_s16(vget_low_s16(v)));
        vst1q_s32(p.0.as_mut_ptr().add(i + 4), vmovl_high_s16(v));
    }
}

/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. Nothing
/// else is required: each step loads and stores eight `i16` (unaligned) at `i..i + 8` with `i + 8
/// <= N` inside the `N`-element array behind the exclusive reference.
#[inline(always)]
unsafe fn barrett_all(buf: &mut [i16; N]) {
    for i in (0..N).step_by(8) {
        let p = buf.as_mut_ptr().add(i);
        vst1q_s16(p, barrett16(vld1q_s16(p)));
    }
}

// Exact modular multiplication for the lazy NTT range.
// z is centered, mu=round(z*2^15/q). The quotient error is
// < |a|/2^16+1/2 <=1, hence a*z-q*round(a*mu/2^15) lies in (-q,q).
// Low-half arithmetic therefore has a unique signed16 interpretation.
// |mu|<=16382<32768, excluding the only SQRDMULH saturation case.
// Intermediate representatives may differ by q; canonical transforms agree.
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values and checked array indexing only; it accesses no memory through a
/// raw pointer.
#[inline(always)]
unsafe fn twiddle16(a: int16x8_t, z: int16x8_t, mu: int16x8_t) -> int16x8_t {
    vmlsq_s16(vmulq_s16(a, z), vqrdmulhq_s16(a, mu), vdupq_n_s16(Q16))
}

/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values and checked array indexing only; it accesses no memory through a
/// raw pointer.
#[inline(always)]
unsafe fn ct_pair(c: &mut [int16x8_t; 8], i: usize, j: usize, zr: int16x8_t, zq: int16x8_t) {
    let t = twiddle16(c[j], zr, zq);
    c[j] = vsubq_s16(c[i], t);
    c[i] = vaddq_s16(c[i], t);
}

/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values and checked array indexing only; it accesses no memory through a
/// raw pointer.
#[inline(always)]
unsafe fn gs_pair(c: &mut [int16x8_t; 8], i: usize, j: usize, zr: int16x8_t, zq: int16x8_t) {
    let u = c[i];
    let v = c[j];
    c[i] = vaddq_s16(u, v);
    c[j] = twiddle16(vsubq_s16(u, v), zr, zq);
}

/// Forward NTT, bit-identical to `ring::ntt_scalar`.
pub fn ntt(p: &mut Poly) {
    let t = ntt16_tables();
    let mut buf = [0i16; N];
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `buf` is a local `[i16; N]` (N = 256) filled by
    // `load16`. In the butterfly loops `len` takes the values 128, 64, 32, 16, 8 and `j + 8 <=
    // start + len`, so the unaligned eight-lane loads and stores at `j` and `j + len` end at or
    // before `start + 2 * len <= N`. The tile loop loads and stores eight lanes at `base + 8 * r`
    // with `base <= 192` and `r < 8`, so it ends at `N`; `tv[i]` is a checked index into rows of
    // exactly eight `i16`, read by one eight-lane load. `t.zr[k]` and `t.zq[k]` are checked.
    // `load16`, `store32` and the vector helpers need NEON only.
    // `bp` is derived once, after `load16` returns, and from there to its last use every access to
    // the buffer goes through `bp`: `barrett_all` receives an exclusive reference reborrowed from
    // `bp`, which is not used after the call returns, and `store32` reads `buf` only after the
    // last use of `bp`.
    unsafe {
        load16(p, &mut buf);
        let bp = buf.as_mut_ptr();
        let mut k = 1usize;
        let mut len = N / 2;
        while len >= 8 {
            let mut start = 0;
            while start < N {
                let zr = vdupq_n_s16(t.zr[k]);
                let zq = vdupq_n_s16(t.zq[k]);
                k += 1;
                let mut j = start;
                while j < start + len {
                    let a = vld1q_s16(bp.add(j));
                    let b = vld1q_s16(bp.add(j + len));
                    let tt = twiddle16(b, zr, zq);
                    vst1q_s16(bp.add(j + len), vsubq_s16(a, tt));
                    vst1q_s16(bp.add(j), vaddq_s16(a, tt));
                    j += 8;
                }
                start += 2 * len;
            }
            if len == 32 {
                barrett_all(&mut *bp.cast::<[i16; N]>());
            }
            len >>= 1;
        }
        debug_assert_eq!(k, 32);
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            transpose8(&mut c);
            let tv = &t.fwd_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            // len = 4
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                ct_pair(&mut c, r, r + 4, zr, zq);
            }
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            // len = 2
            let (zr, zq) = (ld(2), ld(3));
            ct_pair(&mut c, 0, 2, zr, zq);
            ct_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            ct_pair(&mut c, 4, 6, zr, zq);
            ct_pair(&mut c, 5, 7, zr, zq);
            // len = 1
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                ct_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            for r in 0..8 {
                c[r] = canonical16(barrett16(c[r]));
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
        store32(&buf, p);
    }
}

/// Inverse NTT with n^-1 scaling, bit-identical to `ring::intt_scalar`.
pub fn intt(p: &mut Poly) {
    let t = ntt16_tables();
    let mut buf = [0i16; N];
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `buf` is a local `[i16; N]` (N = 256) filled by
    // `load16`. The tile loop loads and stores eight lanes at `base + 8 * r` with `base <= 192` and
    // `r < 8`, so it ends at `N`; `tv[i]` is a checked index into rows of exactly eight `i16`, read
    // by one eight-lane load. In the butterfly loops `len` takes the values 8, 16, 32, 64, 128 and
    // `j + 8 <= start + len`, so the unaligned eight-lane loads and stores at `j` and `j + len` end
    // at or before `start + 2 * len <= N`; the final loop touches `i..i + 8` with `i + 8 <= N`.
    // `t.izr[k]` and `t.izq[k]` are checked. `load16`, `store32` and the vector helpers need
    // NEON only.
    // `bp` is derived once, after `load16` returns, and from there to its last use every access to
    // the buffer goes through `bp`: `barrett_all` receives an exclusive reference reborrowed from
    // `bp`, which is not used after the call returns, and `store32` reads `buf` only after the
    // last use of `bp`.
    unsafe {
        load16(p, &mut buf);
        let bp = buf.as_mut_ptr();
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            transpose8(&mut c);
            let tv = &t.inv_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            // len = 1
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                gs_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            // len = 2
            let (zr, zq) = (ld(2), ld(3));
            gs_pair(&mut c, 0, 2, zr, zq);
            gs_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            gs_pair(&mut c, 4, 6, zr, zq);
            gs_pair(&mut c, 5, 7, zr, zq);
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            // len = 4
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                gs_pair(&mut c, r, r + 4, zr, zq);
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
        let mut k = 31usize;
        let mut len = 8usize;
        while len < N {
            let mut start = 0;
            while start < N {
                let zr = vdupq_n_s16(t.izr[k]);
                let zq = vdupq_n_s16(t.izq[k]);
                k = k.wrapping_sub(1);
                let mut j = start;
                while j < start + len {
                    let u = vld1q_s16(bp.add(j));
                    let v = vld1q_s16(bp.add(j + len));
                    vst1q_s16(bp.add(j), vaddq_s16(u, v));
                    vst1q_s16(bp.add(j + len), twiddle16(vsubq_s16(u, v), zr, zq));
                    j += 8;
                }
                start += 2 * len;
            }
            if len == 16 {
                barrett_all(&mut *bp.cast::<[i16; N]>());
            }
            len <<= 1;
        }
        debug_assert_eq!(k, 0);
        let nr = vdupq_n_s16(t.ninv_r);
        let nq = vdupq_n_s16(t.ninv_q);
        for i in (0..N).step_by(8) {
            let v = vld1q_s16(bp.add(i));
            vst1q_s16(bp.add(i), canonical16(twiddle16(v, nr, nq)));
        }
        store32(&buf, p);
    }
}

/// Constant-time boundary scan for the CT Gaussian sampler,
/// bit-identical to `gauss::Cdt::ct_classify`.
///
/// The boundary prefixes are stored transposed as three u64 planes (limb 0
/// most significant), so each vector step compares the broadcast draw `u`
/// against two 192-bit boundaries at once. The 3-limb big-endian unsigned
/// "less-than" is
///   lt = lt0 | (eq0 & (lt1 | (eq1 & lt2))),
/// and a boundary contributes to the index when NOT lt (u >= b). Index and
/// tie are accumulated in-register (no per-lane branch), then reduced.
///
/// Returns (index_count, tie_mask, above_mask) with the same semantics as the
/// scalar path: `above` (u strictly greater than the z threshold) is computed
/// scalar since it is a single comparison.
pub fn ct_boundary_scan(
    bp0: &[u64],
    bp1: &[u64],
    bp2: &[u64],
    z3: &[u64; 3],
    u: &[u64; 3],
) -> (u64, u64, u64) {
    use crate::ct::{ct_eq_limbs, ct_lt_limbs_be};
    // Safe API: validate every plane before the first vector load, in release too.
    assert_eq!(bp0.len(), bp1.len(), "boundary plane length mismatch");
    assert_eq!(bp0.len(), bp2.len(), "boundary plane length mismatch");
    let n = bp0.len();
    let mut idx = 0u64;
    let mut tie = 0u64;
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). The assertions above give the three planes the same
    // length `n`. Each unaligned two-lane `u64` load at `i` runs under `i + 2 <= n`; the odd tail
    // and the threshold comparison use checked indexing and safe functions.
    unsafe {
        let u0 = vdupq_n_u64(u[0]);
        let u1 = vdupq_n_u64(u[1]);
        let u2 = vdupq_n_u64(u[2]);
        let ones = vdupq_n_u64(1);
        let allf = vdupq_n_u64(u64::MAX);
        let mut idxv = vdupq_n_u64(0);
        let mut tiev = vdupq_n_u64(0);
        let mut i = 0;
        while i + 2 <= n {
            let b0 = vld1q_u64(bp0.as_ptr().add(i));
            let b1 = vld1q_u64(bp1.as_ptr().add(i));
            let b2 = vld1q_u64(bp2.as_ptr().add(i));
            let lt0 = vcltq_u64(u0, b0);
            let eq0 = vceqq_u64(u0, b0);
            let lt1 = vcltq_u64(u1, b1);
            let eq1 = vceqq_u64(u1, b1);
            let lt2 = vcltq_u64(u2, b2);
            let eq2 = vceqq_u64(u2, b2);
            let inner = vorrq_u64(lt1, vandq_u64(eq1, lt2));
            let lt = vorrq_u64(lt0, vandq_u64(eq0, inner));
            let eqall = vandq_u64(eq0, vandq_u64(eq1, eq2));
            // idx += (u >= b) = NOT lt, masked to 1 per lane
            let notlt = veorq_u64(lt, allf);
            idxv = vaddq_u64(idxv, vandq_u64(notlt, ones));
            tiev = vorrq_u64(tiev, eqall);
            i += 2;
        }
        idx += vgetq_lane_u64(idxv, 0) + vgetq_lane_u64(idxv, 1);
        tie |= vgetq_lane_u64(tiev, 0) | vgetq_lane_u64(tiev, 1);
        // scalar tail (odd boundary count)
        while i < n {
            let b = [bp0[i], bp1[i], bp2[i]];
            let lt = ct_lt_limbs_be::<3>(u, &b);
            idx += !lt & 1;
            tie |= ct_eq_limbs::<3>(u, &b);
            i += 1;
        }
        // z threshold (single comparison, scalar)
        let z_lt = ct_lt_limbs_be::<3>(u, z3);
        let z_eq = ct_eq_limbs::<3>(u, z3);
        tie |= z_eq;
        let above = !z_lt & !z_eq;
        (idx, tie, above)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring;

    fn pseudo(seed: u64) -> Poly {
        let mut s = seed | 1;
        let mut p = Poly::ZERO;
        for c in p.0.iter_mut() {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            *c = (s % Q as u64) as i32;
        }
        p
    }

    #[test]
    fn neon_pointwise_matches_scalar() {
        for seed in 0..200u64 {
            let a = pseudo(seed * 2 + 1);
            let b = pseudo(seed * 2 + 2);
            assert_eq!(
                pointwise(&a, &b).0,
                ring::pointwise_scalar(&a, &b).0,
                "seed {seed}"
            );
            let mut acc = pseudo(seed * 2 + 3);
            let expected = acc.add(&ring::pointwise_scalar(&a, &b));
            add_pointwise_assign(&mut acc, &a, &b);
            assert_eq!(acc.0, expected.0, "seed {seed}");
        }
        // boundary coefficients
        let mut a = Poly::ZERO;
        let mut b = Poly::ZERO;
        for i in 0..N {
            a.0[i] = if i % 2 == 0 { 0 } else { Q - 1 };
            b.0[i] = Q - 1;
        }
        assert_eq!(pointwise(&a, &b).0, ring::pointwise_scalar(&a, &b).0);
        let mut acc = b;
        let expected = acc.add(&ring::pointwise_scalar(&a, &b));
        add_pointwise_assign(&mut acc, &a, &b);
        assert_eq!(acc.0, expected.0);
    }

    #[test]
    fn neon_ct_scan_matches_scalar() {
        use crate::gauss::Cdt;
        use crate::params::{PROPOSAL_W0, WE, WS};
        use crate::theta::ThetaCtx;
        let ctx = ThetaCtx::new();
        for (w, even) in [(PROPOSAL_W0, true), (WS, false), (WE, false)] {
            let cdt = Cdt::new(&ctx, w, even);
            let (bp0, bp1, bp2, z3) = cdt.ct_planes();
            let mut st = 0x5deece66du64;
            let mut rnd = move || {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                st
            };
            for t in 0..20_000u32 {
                // random draws plus exact-boundary and off-by-one draws
                let u: [u64; 3] = match t % 4 {
                    0 | 1 => [rnd(), rnd(), rnd()],
                    2 => [
                        bp0[t as usize % bp0.len()],
                        bp1[t as usize % bp1.len()],
                        bp2[t as usize % bp2.len()],
                    ],
                    _ => {
                        let k = t as usize % bp0.len();
                        let mut b = [bp0[k], bp1[k], bp2[k]];
                        if b[2] == 0 {
                            b[2] = 1;
                        } else {
                            b[2] -= 1;
                        }
                        b
                    }
                };
                let got = ct_boundary_scan(bp0, bp1, bp2, z3, &u);
                let want = cdt.ct_classify_scalar_ref(&u);
                assert_eq!(got, want, "w={w} t={t} u={u:?}");
            }
        }
    }

    #[test]
    fn neon16_ntt_and_intt_match_scalar_on_boundary_inputs() {
        let mut cases: Vec<Poly> = vec![Poly::ZERO, Poly([Q - 1; N])];
        cases.push(Poly(core::array::from_fn(|i| {
            if i % 2 == 0 {
                Q - 1
            } else {
                0
            }
        })));
        cases.push(Poly(core::array::from_fn(|i| {
            if i % 3 == 0 {
                Q - 1
            } else {
                1
            }
        })));
        cases.push(Poly(core::array::from_fn(|i| (i as i32 * 3847) % Q)));
        for seed in 0..64u64 {
            cases.push(pseudo(seed * 7919 + 13));
        }
        for c in &cases {
            let mut a = *c;
            let mut b = *c;
            crate::ring::ntt_scalar(&mut a);
            ntt(&mut b);
            assert_eq!(a.0, b.0, "forward");
            let mut a2 = a;
            let mut b2 = a;
            crate::ring::intt_scalar(&mut a2);
            intt(&mut b2);
            assert_eq!(a2.0, b2.0, "inverse");
            assert_eq!(b2.0, c.0, "roundtrip");
        }
    }

    #[test]
    fn neon_ntt_matches_scalar() {
        for seed in 0..100u64 {
            let p = pseudo(seed + 1);
            let mut a = p;
            let mut b = p;
            ntt(&mut a);
            ring::ntt_scalar(&mut b);
            assert_eq!(a.0, b.0, "forward ntt seed {seed}");
        }
    }

    #[test]
    fn neon_intt_matches_scalar_and_roundtrips() {
        for seed in 0..100u64 {
            let p = pseudo(seed + 7);
            let mut a = p;
            let mut b = p;
            intt(&mut a);
            ring::intt_scalar(&mut b);
            assert_eq!(a.0, b.0, "inverse ntt seed {seed}");
            // full round trip via NEON must recover p
            let mut c = p;
            ntt(&mut c);
            intt(&mut c);
            assert_eq!(c.0, p.0, "neon ntt/intt roundtrip seed {seed}");
        }
    }

    #[test]
    fn reduce_covers_full_product_range() {
        // sample the full [0, (q-1)^2] product range densely
        unsafe {
            let mut x = 0i32;
            while x < (Q - 1) * (Q - 1) {
                let v = vld1q_s32(
                    [x, x + 7, x + 4095, x + 58_000_000i32.min((Q - 1) * (Q - 1))].as_ptr(),
                );
                let r = reduce_i32x4(v);
                let mut out = [0i32; 4];
                vst1q_s32(out.as_mut_ptr(), r);
                let inp = [x, x + 7, x + 4095, x + 58_000_000i32.min((Q - 1) * (Q - 1))];
                for k in 0..4 {
                    assert_eq!(out[k], inp[k] % Q, "x={}", inp[k]);
                }
                x += 50_051; // stride coprime-ish to q to hit varied residues
            }
        }
    }
}

#[cfg(test)]
mod exact_reduce_tests {
    use super::*;
    #[test]
    fn barrett_all_signed_inputs_match_widened_reference() {
        unsafe {
            for a in (-32768i32..32768).step_by(8) {
                let input = core::array::from_fn::<_, 8, _>(|i| (a + i as i32) as i16);
                let v = vld1q_s16(input.as_ptr());
                assert_eq!(
                    vminvq_u16(vceqq_s16(barrett16(v), barrett16_reference(v))),
                    u16::MAX,
                    "a={a}"
                );
            }
        }
    }
    #[test]
    fn twiddle_product_all_signed_inputs_and_all_table_twiddles() {
        // Every twiddle the transforms use, with its stored companion: the scaling factor and
        // the forward and inverse tables (the transposed tables are copies of these entries).
        let t = ntt16_tables();
        let mut twiddles = vec![(t.ninv_r, t.ninv_q)];
        for k in 0..N {
            twiddles.push((t.zr[k], t.zq[k]));
            twiddles.push((t.izr[k], t.izq[k]));
        }
        for (z, mu) in twiddles {
            assert!(2 * i32::from(z).abs() < Q, "z={z}");
            // SAFETY: NEON is in the baseline of every target this crate builds for. The load
            // reads the eight `i16` of `input` and the store writes the eight `i16` of `got`.
            unsafe {
                let zv = vdupq_n_s16(z);
                let muv = vdupq_n_s16(mu);
                for a in (-32768i32..32768).step_by(8) {
                    let input = core::array::from_fn::<_, 8, _>(|i| (a + i as i32) as i16);
                    let mut got = [0i16; 8];
                    vst1q_s16(
                        got.as_mut_ptr(),
                        twiddle16(vld1q_s16(input.as_ptr()), zv, muv),
                    );
                    for i in 0..8 {
                        // The product is congruent to a * z modulo q and lies in (-q, q).
                        let product = i32::from(input[i]) * i32::from(z);
                        let value = i32::from(got[i]);
                        assert_eq!((value - product).rem_euclid(Q), 0, "a={}, z={z}", input[i]);
                        assert!(value.abs() < Q, "a={}, z={z}", input[i]);
                    }
                }
            }
        }
    }
    #[test]
    fn residue_all_inputs_below_two_to_29() {
        unsafe {
            for a in (0i32..1 << 29).step_by(4) {
                let input = [a, a + 1, a + 2, a + 3];
                let expected = input.map(|x| x % Q);
                let v = reduce_i32x4(vld1q_s32(input.as_ptr()));
                assert_eq!(
                    vminvq_u32(vceqq_s32(v, vld1q_s32(expected.as_ptr()))),
                    u32::MAX,
                    "a={a}"
                );
            }
        }
    }
}

pub(crate) fn ntt_compact(buf: &mut [i16; N]) {
    let t = ntt16_tables();
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `buf` is an exclusive reference to `[i16; N]` (N =
    // 256). In the butterfly loops `len` takes the values 128, 64, 32, 16, 8 and `j + 8 <= start +
    // len`, so the unaligned eight-lane loads and stores at `j` and `j + len` end at or before
    // `start + 2 * len <= N`. The tile loop loads and stores eight lanes at `base + 8 * r` with
    // `base <= 192` and `r < 8`, so it ends at `N`; `tv[i]` is a checked index into rows of exactly
    // eight `i16`, read by one eight-lane load. `t.zr[k]` and `t.zq[k]` are checked. The vector
    // helpers need NEON only.
    // `bp` is derived once, and from there to its last use every access to the buffer goes through
    // `bp`: `barrett_all` receives an exclusive reference reborrowed from `bp`, which is not used
    // after the call returns. No other path to the buffer is used while `bp` is live.
    unsafe {
        let bp = buf.as_mut_ptr();
        let mut k = 1usize;
        let mut len = N / 2;
        while len >= 8 {
            let mut start = 0;
            while start < N {
                let zr = vdupq_n_s16(t.zr[k]);
                let zq = vdupq_n_s16(t.zq[k]);
                k += 1;
                let mut j = start;
                while j < start + len {
                    let a = vld1q_s16(bp.add(j));
                    let b = vld1q_s16(bp.add(j + len));
                    let tt = twiddle16(b, zr, zq);
                    vst1q_s16(bp.add(j + len), vsubq_s16(a, tt));
                    vst1q_s16(bp.add(j), vaddq_s16(a, tt));
                    j += 8;
                }
                start += 2 * len;
            }
            if len == 32 {
                barrett_all(&mut *bp.cast::<[i16; N]>());
            }
            len >>= 1;
        }
        debug_assert_eq!(k, 32);
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            transpose8(&mut c);
            let tv = &t.fwd_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            // len = 4
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                ct_pair(&mut c, r, r + 4, zr, zq);
            }
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            // len = 2
            let (zr, zq) = (ld(2), ld(3));
            ct_pair(&mut c, 0, 2, zr, zq);
            ct_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            ct_pair(&mut c, 4, 6, zr, zq);
            ct_pair(&mut c, 5, 7, zr, zq);
            // len = 1
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                ct_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            for r in 0..8 {
                c[r] = canonical16(barrett16(c[r]));
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
    }
}

pub(crate) fn dot5_compact<const C: usize>(
    a: &[crate::compact_ring::CompactPoly; C],
    b: &[crate::compact_ring::CompactPoly; C],
) -> Poly {
    const {
        assert!(C >= 4 && C <= 6);
    }

    let mut out = Poly::ZERO;
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `i` runs over multiples of eight below `N = 256`.
    // Each unaligned eight-lane load from `a[c].0` and `b[c].0` (`[i16; N]`, `c` a checked index)
    // and each four-lane store to `out.0` (`[i32; N]`) at `i` and `i + 4` ends at or before `N`.
    // `out` is a local.
    unsafe {
        for i in (0..N).step_by(8) {
            let mut lo = vdupq_n_s32(0);
            let mut hi = vdupq_n_s32(0);
            for c in 0..C {
                let av = vld1q_s16(a[c].0.as_ptr().add(i));
                let bv = vld1q_s16(b[c].0.as_ptr().add(i));
                lo = vmlal_s16(lo, vget_low_s16(av), vget_low_s16(bv));
                hi = vmlal_high_s16(hi, av, bv);
            }
            vst1q_s32(out.0.as_mut_ptr().add(i), reduce_i32x4(lo));
            vst1q_s32(out.0.as_mut_ptr().add(i + 4), reduce_i32x4(hi));
        }
    }
    out
}

#[cfg(test)]
pub(crate) fn dot5_mixed<const C: usize>(
    a: &[crate::compact_ring::CompactPoly; C],
    b: &[Poly; C],
) -> Poly {
    const {
        assert!(C >= 4 && C <= 6);
    }

    let mut out = Poly::ZERO;
    unsafe {
        for i in (0..N).step_by(8) {
            let mut lo = vdupq_n_s32(0);
            let mut hi = vdupq_n_s32(0);
            for c in 0..C {
                let av = vld1q_s16(a[c].0.as_ptr().add(i));
                let bv = vcombine_s16(
                    vmovn_s32(vld1q_s32(b[c].0.as_ptr().add(i))),
                    vmovn_s32(vld1q_s32(b[c].0.as_ptr().add(i + 4))),
                );
                lo = vmlal_s16(lo, vget_low_s16(av), vget_low_s16(bv));
                hi = vmlal_high_s16(hi, av, bv);
            }
            vst1q_s32(out.0.as_mut_ptr().add(i), reduce_i32x4(lo));
            vst1q_s32(out.0.as_mut_ptr().add(i + 4), reduce_i32x4(hi));
        }
    }
    out
}

#[cfg(test)]
pub(crate) fn pointwise_compact(
    a: &crate::compact_ring::CompactPoly,
    b: &crate::compact_ring::CompactPoly,
) -> Poly {
    let mut out = Poly::ZERO;
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `i` advances by eight while `i < N` (N = 256), so
    // every unaligned eight-lane load from `a.0` and `b.0` (`[i16; N]`) at `i`, and every
    // four-lane store to `out.0` (`[i32; N]`) at `i` and `i + 4`, stays inside the arrays. `out`
    // is a local, distinct from both inputs. `reduce_i32x4` needs NEON only.
    unsafe {
        for i in (0..N).step_by(8) {
            let av = vld1q_s16(a.0.as_ptr().add(i));
            let bv = vld1q_s16(b.0.as_ptr().add(i));
            let lo = vmull_s16(vget_low_s16(av), vget_low_s16(bv));
            let hi = vmull_high_s16(av, bv);
            vst1q_s32(out.0.as_mut_ptr().add(i), reduce_i32x4(lo));
            vst1q_s32(out.0.as_mut_ptr().add(i + 4), reduce_i32x4(hi));
        }
    }
    out
}

// Private source path; the emitted owner/cleanup code requires review.
#[inline(always)]
pub(crate) fn private_update_product_add(
    a: &crate::compact_ring::CompactPoly,
    b: &crate::compact_ring::CompactPoly,
    destination: &mut [i32],
) {
    assert_eq!(destination.len(), N);
    let t = ntt16_tables();
    let mut owned = zeroize::Zeroizing::new(crate::compact_ring::CompactPoly::ZERO);
    let buf = &mut owned.0;
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `a.0`, `b.0` and the local `buf` are `[i16; N]` (N
    // = 256) and `destination.len() == N` is asserted above. Loops over `i` touch `i..i + 8` with
    // `i + 8 <= N` in each of them (eight `i16` lanes, or four `i32` lanes at `i` and at `i + 4`).
    // The tile loop loads and stores eight lanes at `base + 8 * r` with `base <= 192` and `r < 8`,
    // so it ends at `N`; `tv[i]` is a checked index into rows of exactly eight `i16`, read by one
    // eight-lane load. In the butterfly loops `len` takes the values 8, 16, 32, 64, 128 and `j + 8
    // <= start + len`, so loads and stores at `j` and `j + len` end at or before `start + 2 * len
    // <= N`. All loads and stores are unaligned forms; `destination` is an exclusive borrow,
    // distinct from the scratch.
    // `bp` is derived once, and from there to its last use every access to the buffer goes through
    // `bp`: `barrett_all` receives an exclusive reference reborrowed from `bp`, which is not used
    // after the call returns. No other path to the buffer is used while `bp` is live.
    unsafe {
        let bp = buf.as_mut_ptr();
        // Exactly the pointwise reduction, then lossless canonical narrowing.
        for i in (0..N).step_by(8) {
            let av = vld1q_s16(a.0.as_ptr().add(i));
            let bv = vld1q_s16(b.0.as_ptr().add(i));
            let lo = reduce_i32x4(vmull_s16(vget_low_s16(av), vget_low_s16(bv)));
            let hi = reduce_i32x4(vmull_high_s16(av, bv));
            vst1q_s16(bp.add(i), vcombine_s16(vmovn_s32(lo), vmovn_s32(hi)));
        }
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            transpose8(&mut c);
            let tv = &t.inv_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            // len = 1
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                gs_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            // len = 2
            let (zr, zq) = (ld(2), ld(3));
            gs_pair(&mut c, 0, 2, zr, zq);
            gs_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            gs_pair(&mut c, 4, 6, zr, zq);
            gs_pair(&mut c, 5, 7, zr, zq);
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            // len = 4
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                gs_pair(&mut c, r, r + 4, zr, zq);
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
        let mut k = 31usize;
        let mut len = 8usize;
        while len < N {
            let mut start = 0;
            while start < N {
                let zr = vdupq_n_s16(t.izr[k]);
                let zq = vdupq_n_s16(t.izq[k]);
                k = k.wrapping_sub(1);
                let mut j = start;
                while j < start + len {
                    let u = vld1q_s16(bp.add(j));
                    let v = vld1q_s16(bp.add(j + len));
                    vst1q_s16(bp.add(j), vaddq_s16(u, v));
                    vst1q_s16(bp.add(j + len), twiddle16(vsubq_s16(u, v), zr, zq));
                    j += 8;
                }
                start += 2 * len;
            }
            if len == 16 {
                barrett_all(&mut *bp.cast::<[i16; N]>());
            }
            len <<= 1;
        }
        debug_assert_eq!(k, 0);
        let nr = vdupq_n_s16(t.ninv_r);
        let nq = vdupq_n_s16(t.ninv_q);
        let q = vdupq_n_s16(Q as i16);
        let half = vdupq_n_s16((Q / 2) as i16);
        for i in (0..N).step_by(8) {
            let canonical = canonical16(twiddle16(vld1q_s16(bp.add(i)), nr, nq));
            let centered = vsubq_s16(
                canonical,
                vandq_s16(vreinterpretq_s16_u16(vcgtq_s16(canonical, half)), q),
            );
            let lo = vaddq_s32(
                vmovl_s16(vget_low_s16(centered)),
                vld1q_s32(destination.as_ptr().add(i)),
            );
            let hi = vaddq_s32(
                vmovl_high_s16(centered),
                vld1q_s32(destination.as_ptr().add(i + 4)),
            );
            vst1q_s32(destination.as_mut_ptr().add(i), lo);
            vst1q_s32(destination.as_mut_ptr().add(i + 4), hi);
        }
    }
}

#[cfg(test)]
fn reference_test_update(
    a: &crate::compact_ring::CompactPoly,
    b: &crate::compact_ring::CompactPoly,
    destination: &mut [i32],
) {
    private_update_product_add(a, b, destination);
}

#[cfg(test)]
mod update_product_tests {
    use super::*;
    use crate::compact_ring::CompactPoly;
    #[repr(C)]
    struct Framed {
        before: [i32; 8],
        value: [i32; N],
        after: [i32; 8],
    }
    #[test]
    fn private_fusion_arbitrary_spectra_match_original_with_canaries() {
        let mut seed = 0xa629441ec18117d9u64;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 32) as u32
        };
        let mut cases = 0usize;
        // Every one-hot frequency at both extremal nonzero canonical values,
        // then zero, maximal, alternating and arbitrary canonical spectra.
        for trial in 0..776 {
            let a = CompactPoly(core::array::from_fn(|i| {
                if trial < 512 {
                    if i == trial / 2 {
                        if trial % 2 == 0 {
                            1
                        } else {
                            (Q - 1) as i16
                        }
                    } else {
                        0
                    }
                } else {
                    match trial {
                        512 => 0,
                        513 => (Q - 1) as i16,
                        514 => {
                            if i % 2 == 0 {
                                0
                            } else {
                                (Q - 1) as i16
                            }
                        }
                        _ => (next() % Q as u32) as i16,
                    }
                }
            }));
            let b = CompactPoly(core::array::from_fn(|i| match trial {
                512 => 0,
                513 => (Q - 1) as i16,
                514 => {
                    if i % 2 == 0 {
                        (Q - 1) as i16
                    } else {
                        0
                    }
                }
                _ => (next() % Q as u32) as i16,
            }));
            let a_before = a;
            let b_before = b;
            let input = core::array::from_fn(|i| match trial % 5 {
                0 => 0,
                1 => i32::MAX - 4096,
                2 => i32::MIN + 4096,
                3 => {
                    if i % 2 == 0 {
                        1355
                    } else {
                        -1355
                    }
                }
                _ => (next() % 65536) as i32 - 32768,
            });
            let mut old = crate::compact_ring::pointwise_compact(&a, &b);
            intt(&mut old);
            let expected: [i32; N] = core::array::from_fn(|i| {
                let v = old.0[i];
                let centered = v - Q * i32::from(v > Q / 2);
                input[i] + centered
            });
            let mut framed = Framed {
                before: [0x137ab4f1; 8],
                value: input,
                after: [0x27a145f3; 8],
            };
            reference_test_update(&a, &b, &mut framed.value);
            assert_eq!(framed.value, expected, "trial {trial}");
            assert_eq!(framed.before, [0x137ab4f1; 8]);
            assert_eq!(framed.after, [0x27a145f3; 8]);
            assert_eq!(a, a_before);
            assert_eq!(b, b_before);
            cases += 1;
        }
        assert_eq!(cases, 776);
    }
}

// Public-only arithmetic; no private caller or shared transform change.
#[inline(never)]
pub(crate) fn public_commitment_row_into<const C: usize>(
    a: &[crate::compact_ring::CompactPoly; C],
    b: &[crate::compact_ring::CompactPoly; C],
    delta: &Poly,
    output: &mut Poly,
) {
    const {
        assert!(C >= 4 && C <= 6);
    }
    // Canonical lanes: at most 6*7680^2 = 353894400 < 2^29.
    // Reduction precedes the inverse-transform butterflies.

    let t = ntt16_tables();
    let mut owned = crate::compact_ring::CompactPoly::ZERO;
    let buf = &mut owned.0;
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `a[c].0`, `b[c].0` and the local `buf` are `[i16;
    // N]`, `delta.0` and `output.0` are `[i32; N]` (N = 256), and `c` is a checked index. Loops
    // over `i` touch `i..i + 8` with `i + 8 <= N` in each of them. The tile loop loads and stores
    // eight lanes at `base + 8 * r` with `base <= 192` and `r < 8`, so it ends at `N`; `tv[i]` is a
    // checked index into rows of exactly eight `i16`, read by one eight-lane load. In the butterfly
    // loops `len` takes the values 8, 16, 32, 64, 128 and `j + 8 <= start + len`, so loads and
    // stores at `j` and `j + len` end at or before `start + 2 * len <= N`. All loads and stores are
    // unaligned forms; `output` is an exclusive borrow.
    // `bp` is derived once, and from there to its last use every access to the buffer goes through
    // `bp`: `barrett_all` receives an exclusive reference reborrowed from `bp`, which is not used
    // after the call returns. No other path to the buffer is used while `bp` is live.
    unsafe {
        let bp = buf.as_mut_ptr();
        for i in (0..N).step_by(8) {
            let mut lo = vdupq_n_s32(0);
            let mut hi = vdupq_n_s32(0);
            for c in 0..C {
                let av = vld1q_s16(a[c].0.as_ptr().add(i));
                let bv = vld1q_s16(b[c].0.as_ptr().add(i));
                lo = vmlal_s16(lo, vget_low_s16(av), vget_low_s16(bv));
                hi = vmlal_high_s16(hi, av, bv);
            }
            let lo = reduce_i32x4(lo);
            let hi = reduce_i32x4(hi);
            vst1q_s16(bp.add(i), vcombine_s16(vmovn_s32(lo), vmovn_s32(hi)));
        }
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            transpose8(&mut c);
            let tv = &t.inv_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            // len = 1
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                gs_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            // len = 2
            let (zr, zq) = (ld(2), ld(3));
            gs_pair(&mut c, 0, 2, zr, zq);
            gs_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            gs_pair(&mut c, 4, 6, zr, zq);
            gs_pair(&mut c, 5, 7, zr, zq);
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            // len = 4
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                gs_pair(&mut c, r, r + 4, zr, zq);
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
        let mut k = 31usize;
        let mut len = 8usize;
        while len < N {
            let mut start = 0;
            while start < N {
                let zr = vdupq_n_s16(t.izr[k]);
                let zq = vdupq_n_s16(t.izq[k]);
                k = k.wrapping_sub(1);
                let mut j = start;
                while j < start + len {
                    let u = vld1q_s16(bp.add(j));
                    let v = vld1q_s16(bp.add(j + len));
                    vst1q_s16(bp.add(j), vaddq_s16(u, v));
                    vst1q_s16(bp.add(j + len), twiddle16(vsubq_s16(u, v), zr, zq));
                    j += 8;
                }
                start += 2 * len;
            }
            if len == 16 {
                barrett_all(&mut *bp.cast::<[i16; N]>());
            }
            len <<= 1;
        }
        debug_assert_eq!(k, 0);
        let nr = vdupq_n_s16(t.ninv_r);
        let nq = vdupq_n_s16(t.ninv_q);
        let q = vdupq_n_s32(Q);
        for i in (0..N).step_by(8) {
            let v = canonical16(twiddle16(vld1q_s16(bp.add(i)), nr, nq));
            let lo = vaddq_s32(
                vmovl_s16(vget_low_s16(v)),
                vld1q_s32(delta.0.as_ptr().add(i)),
            );
            let hi = vaddq_s32(vmovl_high_s16(v), vld1q_s32(delta.0.as_ptr().add(i + 4)));
            let lo = vsubq_s32(lo, vandq_s32(vreinterpretq_s32_u32(vcgeq_s32(lo, q)), q));
            let hi = vsubq_s32(hi, vandq_s32(vreinterpretq_s32_u32(vcgeq_s32(hi, q)), q));
            vst1q_s32(output.0.as_mut_ptr().add(i), lo);
            vst1q_s32(output.0.as_mut_ptr().add(i + 4), hi);
        }
    }
}

#[cfg(test)]
mod public_row_fusion_tests {
    use super::*;
    use crate::compact_ring::CompactPoly;
    #[repr(C)]
    struct Framed {
        before: [i32; 8],
        out: Poly,
        after: [i32; 8],
    }
    fn check_public_row<const C: usize>() {
        let mut state = 0xb961419b62c7ca83u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as u32
        };
        for trial in 0..776 {
            let a: [CompactPoly; C] = core::array::from_fn(|c| {
                CompactPoly(core::array::from_fn(|i| match trial {
                    0..=511 => {
                        if i == trial / 2 {
                            if trial % 2 == 0 {
                                1
                            } else {
                                (Q - 1) as i16
                            }
                        } else {
                            0
                        }
                    }
                    512 => 0,
                    513 => (Q - 1) as i16,
                    514 => {
                        if (i + c) % 2 == 0 {
                            (Q - 1) as i16
                        } else {
                            0
                        }
                    }
                    _ => (next() % Q as u32) as i16,
                }))
            });
            let b: [CompactPoly; C] = core::array::from_fn(|_| {
                CompactPoly(core::array::from_fn(|_| match trial {
                    512 => 0,
                    513 => (Q - 1) as i16,
                    _ => (next() % Q as u32) as i16,
                }))
            });
            let delta = Poly(core::array::from_fn(|i| match trial % 4 {
                0 => 0,
                1 => Q - 1,
                2 => {
                    if i % 2 == 0 {
                        0
                    } else {
                        Q - 1
                    }
                }
                _ => (next() % Q as u32) as i32,
            }));
            let before_a = a;
            let before_b = b;
            let before_d = delta;
            let mut original = crate::compact_ring::dot_compact(&a, &b);
            intt(&mut original);
            let expected = original.add_canonical(&delta);
            let mut f = Framed {
                before: [0x4a673912; 8],
                out: Poly([-173; N]),
                after: [0x34191753; 8],
            };
            public_commitment_row_into(&a, &b, &delta, &mut f.out);
            assert_eq!(f.out, expected, "trial {trial}");
            assert!(f.out.0.iter().all(|&v| (0..Q).contains(&v)));
            assert_eq!(f.before, [0x4a673912; 8]);
            assert_eq!(f.after, [0x34191753; 8]);
            assert_eq!(a, before_a);
            assert_eq!(b, before_b);
            assert_eq!(delta, before_d);
        }
    }
    #[test]
    fn public_row_matches_exact_original_with_guards() {
        check_public_row::<4>();
        check_public_row::<5>();
        check_public_row::<6>();
    }
}

// Public-only suffix entry: len16 and len8 are independent within each64 block.
// Preserve exact twiddle indices and unreduced intermediates before the
// transposed len4/2/1 tail.
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values and checked array indexing only; it accesses no memory through a
/// raw pointer.
#[inline(always)]
unsafe fn public_compact_middle2(c: &mut [int16x8_t; 8], sb: usize, t: &Ntt16Tables) {
    let pair = |c: &mut [int16x8_t; 8], a, b, k| {
        ct_pair(c, a, b, vdupq_n_s16(t.zr[k]), vdupq_n_s16(t.zq[k]))
    };
    // len16: two32-coefficient groups, two vector pairs each.
    pair(c, 0, 2, 8 + 2 * sb);
    pair(c, 1, 3, 8 + 2 * sb);
    pair(c, 4, 6, 9 + 2 * sb);
    pair(c, 5, 7, 9 + 2 * sb);
    // len8: four16-coefficient groups. No reduction at this boundary.
    for r in 0..4 {
        pair(c, 2 * r, 2 * r + 1, 16 + 4 * sb + r);
    }
}

#[cfg(test)]
mod public_compact_suffix_fusion_tests {
    use super::*;
    unsafe fn reference_middle2(buf: &mut [i16; N]) {
        let t = ntt16_tables();
        let bp = buf.as_mut_ptr();
        let mut k = 8;
        for len in [16, 8] {
            for start in (0..N).step_by(2 * len) {
                for j in (start..start + len).step_by(8) {
                    let a = vld1q_s16(bp.add(j));
                    let b = vld1q_s16(bp.add(j + len));
                    let v = twiddle16(b, vdupq_n_s16(t.zr[k]), vdupq_n_s16(t.zq[k]));
                    vst1q_s16(bp.add(j), vaddq_s16(a, v));
                    vst1q_s16(bp.add(j + len), vsubq_s16(a, v));
                }
                k += 1;
            }
        }
        assert_eq!(k, 32);
    }
    #[test]
    fn public_fused_middle2_exact_parent_intermediates_and_twiddles() {
        let mut state = 0x136523u64;
        for trial in 0..1028 {
            // Full supported post-first3 centered range, plus alternating extrema.
            let input = core::array::from_fn(|i| match trial {
                0 => 0,
                1 => (Q / 2) as i16,
                2 => -(Q / 2) as i16,
                3 => {
                    if i % 2 == 0 {
                        (Q / 2) as i16
                    } else {
                        -(Q / 2) as i16
                    }
                }
                _ => {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    ((state >> 32) % Q as u64) as i16 - (Q / 2) as i16
                }
            });
            let mut old = input;
            let mut fused = input;
            unsafe {
                reference_middle2(&mut old);
                for sb in 0..4 {
                    let bp = fused.as_mut_ptr().add(64 * sb);
                    let mut c = core::array::from_fn(|r| vld1q_s16(bp.add(8 * r)));
                    public_compact_middle2(&mut c, sb, ntt16_tables());
                    for r in 0..8 {
                        vst1q_s16(bp.add(8 * r), c[r]);
                    }
                }
            }
            assert_eq!(fused, old, "trial={trial}");
            assert!(fused.iter().all(|&v| (v as i32).abs() < 3 * Q));
        }
    }
}

pub(crate) fn dot5_compact_into<const C: usize>(
    a: &[crate::compact_ring::CompactPoly; C],
    b: &[crate::compact_ring::CompactPoly; C],
    out: &mut Poly,
) {
    const {
        assert!(C >= 4 && C <= 6);
    }

    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `i` runs over multiples of eight below `N = 256`.
    // Each unaligned eight-lane load from `a[c].0` and `b[c].0` (`[i16; N]`, `c` a checked index)
    // and each four-lane store to `out.0` (`[i32; N]`) at `i` and `i + 4` ends at or before `N`.
    // `out` is an exclusive borrow, distinct from the inputs.
    unsafe {
        for i in (0..N).step_by(8) {
            let mut lo = vdupq_n_s32(0);
            let mut hi = vdupq_n_s32(0);
            for c in 0..C {
                let av = vld1q_s16(a[c].0.as_ptr().add(i));
                let bv = vld1q_s16(b[c].0.as_ptr().add(i));
                lo = vmlal_s16(lo, vget_low_s16(av), vget_low_s16(bv));
                hi = vmlal_high_s16(hi, av, bv);
            }
            vst1q_s32(out.0.as_mut_ptr().add(i), reduce_i32x4(lo));
            vst1q_s32(out.0.as_mut_ptr().add(i + 4), reduce_i32x4(hi));
        }
    }
}

#[cfg(test)]
pub(crate) fn dot5_mixed_into<const C: usize>(
    a: &[crate::compact_ring::CompactPoly; C],
    b: &[Poly; C],
    out: &mut Poly,
) {
    const {
        assert!(C >= 4 && C <= 6);
    }

    unsafe {
        for i in (0..N).step_by(8) {
            let mut lo = vdupq_n_s32(0);
            let mut hi = vdupq_n_s32(0);
            for c in 0..C {
                let av = vld1q_s16(a[c].0.as_ptr().add(i));
                let bv = vcombine_s16(
                    vmovn_s32(vld1q_s32(b[c].0.as_ptr().add(i))),
                    vmovn_s32(vld1q_s32(b[c].0.as_ptr().add(i + 4))),
                );
                lo = vmlal_s16(lo, vget_low_s16(av), vget_low_s16(bv));
                hi = vmlal_high_s16(hi, av, bv);
            }
            vst1q_s32(out.0.as_mut_ptr().add(i), reduce_i32x4(lo));
            vst1q_s32(out.0.as_mut_ptr().add(i + 4), reduce_i32x4(hi));
        }
    }
}

#[cfg(test)]
#[inline(never)]
pub(crate) fn public_compact_row_caps_reference(
    a: &[crate::compact_ring::CompactPoly; 4],
    b: &[crate::compact_ring::CompactPoly; 4],
    delta: &Poly,
    local: &[u8; 64],
    labels: &mut [u8; N],
    caps: &[u64; 452],
) -> Option<u64> {
    let mut sums = [0u64; 4];
    let mut bad = false;
    let t = ntt16_tables();
    let mut owned = crate::compact_ring::CompactPoly::ZERO;
    let buf = &mut owned.0;
    // SAFETY: AArch64/neon gates this module. All input, scratch and label
    // arrays have 256 initialized elements; eight-lane loads/stores partition
    // them. The 64-byte local planes use checked indexing. Twiddle arrays
    // contain full vectors, and the lane maximum guards every cap lookup.
    // Exclusive scratch/output borrows are disjoint from shared inputs.
    // `bp` is derived once, and from there to its last use every access to the buffer goes through
    // `bp`: `barrett_all` receives an exclusive reference reborrowed from `bp`, which is not used
    // after the call returns. No other path to the buffer is used while `bp` is live.
    unsafe {
        let bp = buf.as_mut_ptr();
        for i in (0..N).step_by(8) {
            let mut lo = vdupq_n_s32(0);
            let mut hi = vdupq_n_s32(0);
            for c in 0..4 {
                let av = vld1q_s16(a[c].0.as_ptr().add(i));
                let bv = vld1q_s16(b[c].0.as_ptr().add(i));
                lo = vmlal_s16(lo, vget_low_s16(av), vget_low_s16(bv));
                hi = vmlal_high_s16(hi, av, bv);
            }
            let lo = reduce_i32x4(lo);
            let hi = reduce_i32x4(hi);
            vst1q_s16(bp.add(i), vcombine_s16(vmovn_s32(lo), vmovn_s32(hi)));
        }
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            transpose8(&mut c);
            let tv = &t.inv_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            // len = 1
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                gs_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            // len = 2
            let (zr, zq) = (ld(2), ld(3));
            gs_pair(&mut c, 0, 2, zr, zq);
            gs_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            gs_pair(&mut c, 4, 6, zr, zq);
            gs_pair(&mut c, 5, 7, zr, zq);
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            // len = 4
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                gs_pair(&mut c, r, r + 4, zr, zq);
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
        let mut k = 31usize;
        let mut len = 8usize;
        while len < N {
            let mut start = 0;
            while start < N {
                let zr = vdupq_n_s16(t.izr[k]);
                let zq = vdupq_n_s16(t.izq[k]);
                k = k.wrapping_sub(1);
                let mut j = start;
                while j < start + len {
                    let u = vld1q_s16(bp.add(j));
                    let v = vld1q_s16(bp.add(j + len));
                    vst1q_s16(bp.add(j), vaddq_s16(u, v));
                    vst1q_s16(bp.add(j + len), twiddle16(vsubq_s16(u, v), zr, zq));
                    j += 8;
                }
                start += 2 * len;
            }
            if len == 16 {
                barrett_all(&mut *bp.cast::<[i16; N]>());
            }
            len <<= 1;
        }
        debug_assert_eq!(k, 0);
        let nr = vdupq_n_s16(t.ninv_r);
        let nq = vdupq_n_s16(t.ninv_q);
        let q = vdupq_n_s32(Q);
        let recovery = crate::signature_codec::PublicRecoveryTables::new();
        for i in (0..N).step_by(8) {
            let v = canonical16(twiddle16(vld1q_s16(bp.add(i)), nr, nq));
            let lo = vaddq_s32(
                vmovl_s16(vget_low_s16(v)),
                vld1q_s32(delta.0.as_ptr().add(i)),
            );
            let hi = vaddq_s32(vmovl_high_s16(v), vld1q_s32(delta.0.as_ptr().add(i + 4)));
            let lo = vsubq_s32(lo, vandq_s32(vreinterpretq_s32_u32(vcgeq_s32(lo, q)), q));
            let hi = vsubq_s32(hi, vandq_s32(vreinterpretq_s32_u32(vcgeq_s32(hi, q)), q));
            // Each context is canonical after the matrix/dither reduction.
            // Canonical local decoding establishes every input index is <4.
            let x = vreinterpretq_u16_s16(vcombine_s16(vmovn_s32(lo), vmovn_s32(hi)));
            let shifts = vreinterpret_s8_u64(vcreate_u64(0xf9fafbfcfdfeff00));
            let low = vand_u8(vshl_u8(vdup_n_u8(local[i / 8]), shifts), vdup_n_u8(1));
            let high = vand_u8(vshl_u8(vdup_n_u8(local[32 + i / 8]), shifts), vdup_n_u8(1));
            let indices = vorr_u8(low, vshl_n_u8::<1>(high));
            let (u, magnitude) = crate::signature_codec::public_recover8(x, indices, recovery);
            vst1_u8(labels.as_mut_ptr().add(i), u);
            if vmaxvq_u16(magnitude) > crate::params::FORMAT_RES_LIMIT as u16 {
                bad = true;
            } else {
                // SAFETY: the else branch follows the maximum over all eight u16 lanes.
                // Each unchanged lane is therefore <=450, within the fixed452-entry array.
                macro_rules! add_lane {
                    ($lane:literal) => {
                        sums[$lane % 4] +=
                            *caps.get_unchecked(vgetq_lane_u16::<$lane>(magnitude) as usize);
                    };
                }
                add_lane!(0);
                add_lane!(1);
                add_lane!(2);
                add_lane!(3);
                add_lane!(4);
                add_lane!(5);
                add_lane!(6);
                add_lane!(7);
            }
        }
    }
    if bad {
        None
    } else {
        Some(sums.into_iter().sum())
    }
}

#[path = "public_row_caps.rs"]
mod public_row_caps;

#[inline(never)]
pub(crate) fn public_compact_row_caps(
    a: &[crate::compact_ring::CompactPoly; 4],
    b: &[crate::compact_ring::CompactPoly; 4],
    delta: &Poly,
    local: &[u8; 64],
    labels: &mut [core::mem::MaybeUninit<u8>; N],
    caps: &[u64; 452],
) -> Option<u64> {
    let mut scratch = core::mem::MaybeUninit::<[i16; N]>::uninit();
    public_row_caps::run(
        a,
        b,
        delta,
        local,
        labels,
        caps,
        &mut scratch,
        #[cfg(test)]
        &mut public_row_caps::Trace::new(),
    )
}

#[path = "public_response_ntt.rs"]
pub(crate) mod public_response_ntt;
