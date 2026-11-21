//! Exact bounded-tail correlation implementation.
//! All private transform/product/factor/output kernels cross an immediately erased C-ABI boundary.
use crate::params::{DIM, N};
use crate::transport::Vector;
use core::arch::aarch64::*;
use zeroize::Zeroize;
const P: i64 = 516809729;
#[allow(dead_code)]
const ROOT: i64 = 75035968;
const R: i32 = 1115421634;
const _: () = assert!(
    N == 256
        && DIM == 2816
        && crate::params::PROPOSAL_W0 == 9216
        && crate::params::WS == 196
        && crate::params::WE == 121
        && crate::params::SHELL_HI <= 307135
);
// Q384 constructor / Q192 decoder raw supports:168/1149/1462.
// Counts outside constructor rows decode to zero, even on aborted attempts.
// Initial-tail bound only; no post-transport support assumption.
const _: () = {
    let mut b = 1462i64;
    let mut j = 0;
    while j < 6 {
        b += (P * ((1i64 << 31) + b) + (1i64 << 32) - 1) / (1i64 << 32);
        assert!(b < (1i64 << 31));
        j += 1;
    }
    assert!(b == 2098750704);
    assert!(4 * (P - 1) < (1i64 << 31));
    assert!(P > 2 * 256323968 && P > 2 * 258371712);
};
// Accumulate schedule. A transform output is two butterfly layers away from a centered value. A
// product with a centered factor is bounded like one more layer's term. A sum is centered after at
// most four products on top of a centered value (slots 3, 7 and 9 of `accumulate_native`), and
// that sum must fit i32 for `center` to be exact.
const _: () = {
    let mut b = P / 2;
    let mut j = 0;
    while j < 2 {
        b += (P * ((1i64 << 31) + b) + (1i64 << 32) - 1) / (1i64 << 32);
        j += 1;
    }
    assert!(b == 872236972);
    let product = (P * ((1i64 << 31) + b) + (1i64 << 32) - 1) / (1i64 << 32);
    assert!(product == 363360391);
    assert!(P / 2 + 4 * product == 1711846428);
    assert!(P / 2 + 4 * product < (1i64 << 31));
};
#[inline(always)]
fn cent(x: i64) -> i32 {
    ((x + P / 2).rem_euclid(P) - P / 2) as i32
}
#[inline(always)]
fn mu(x: i32) -> i32 {
    ((x as i64 * (1i64 << 31) + P / 2).div_euclid(P)) as i32
}
#[allow(dead_code)]
fn pow(mut a: i64, mut n: u32) -> i64 {
    let mut r = 1;
    while n > 0 {
        if n & 1 != 0 {
            r = r * a % P;
        }
        a = a * a % P;
        n >>= 1;
    }
    r
}
#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct Tables {
    zr: [i32; 64],
    zq: [i32; 64],
    izr: [i32; 64],
    izq: [i32; 64],
    fwd: [[[i32; 4]; 6]; 16],
    inv: [[[i32; 4]; 6]; 16],
}
include!("aux32_static_tables.rs");
fn tables() -> &'static Tables {
    &STATIC_TABLES
}
#[cfg(test)]
fn tables_reference() -> &'static Tables {
    static T: std::sync::OnceLock<Tables> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        for d in 2..=P {
            if d * d > P {
                break;
            }
            assert_ne!(P % d, 0);
        }
        assert_eq!(pow(ROOT, 256), P - 1);
        assert_eq!(pow(ROOT, 512), 1);
        let mut z = [0; N];
        let mut q = [0; N];
        let mut iz = [0; N];
        let mut iq = [0; N];
        for k in 1..N {
            z[k] = cent(pow(ROOT, (k as u8).reverse_bits() as u32));
            q[k] = mu(z[k]);
            iz[k] = -z[k];
            iq[k] = mu(-z[k]);
        }
        let mut t = Tables {
            zr: core::array::from_fn(|i| z[i]),
            zq: core::array::from_fn(|i| q[i]),
            izr: core::array::from_fn(|i| iz[i]),
            izq: core::array::from_fn(|i| iq[i]),
            fwd: [[[0; 4]; 6]; 16],
            inv: [[[0; 4]; 6]; 16],
        };
        for sb in 0..16 {
            for b in 0..4 {
                let fk = [64 + 4 * sb + b, 128 + 8 * sb + 2 * b, 129 + 8 * sb + 2 * b];
                let ik = [127 - 4 * sb - b, 255 - 8 * sb - 2 * b, 254 - 8 * sb - 2 * b];
                for j in 0..3 {
                    t.fwd[sb][2 * j][b] = z[fk[j]];
                    t.fwd[sb][2 * j + 1][b] = q[fk[j]];
                    t.inv[sb][2 * j][b] = iz[ik[j]];
                    t.inv[sb][2 * j + 1][b] = iq[ik[j]];
                }
            }
        }
        t
    })
}
#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers.
unsafe fn raw(a: int32x4_t, b: int32x4_t, m: int32x4_t) -> int32x4_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed.
    unsafe { vmlsq_n_s32(vmulq_s32(a, b), vqrdmulhq_s32(a, m), P as i32) }
}
#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers.
unsafe fn center(a: int32x4_t) -> int32x4_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed.
    unsafe { vmlsq_n_s32(a, vrshrq_n_s32::<28>(vqdmulhq_n_s32(a, R)), P as i32) }
}
#[inline(always)]
#[allow(dead_code)]
/// # Safety
/// Requires AArch64 NEON. buf is an exclusive initialized N=256 array; its complete four-lane groups
/// bound every load and store.
unsafe fn center_all(buf: &mut [i32; N]) {
    // SAFETY: The caller supplies the function safety contract. Requires AArch64 NEON. buf is an
    // exclusive initialized N=256 array; its complete four-lane groups bound every load and store.
    unsafe {
        for j in (0..N).step_by(4) {
            let p = buf.as_mut_ptr().add(j);
            vst1q_s32(p, center(vld1q_s32(p)));
        }
    }
}
#[repr(C, align(8))]
struct Poly([i32; N]);
impl Drop for Poly {
    fn drop(&mut self) {
        // SAFETY: Poly has asserted size 1024 and alignment eight; self.0 contains only initialized
        // i32 values. Drop exclusively owns all 128 u64-sized words and zeroing them preserves integer
        // validity.
        unsafe {
            crate::ct_erase::erase_struct_words(self.0.as_mut_ptr().cast(), 128);
        }
    }
}
const _: () = assert!(core::mem::size_of::<Poly>() == 1024 && core::mem::align_of::<Poly>() == 8);

macro_rules! ctreg {
    ($a:ident,$b:ident,$z:expr,$m:expr) => {{
        let u = $a;
        let v = raw($b, $z, $m);
        $a = vaddq_s32(u, v);
        $b = vsubq_s32(u, v);
    }};
}
macro_rules! gsreg {
    ($a:ident,$b:ident,$z:expr,$m:expr) => {{
        let u = $a;
        let v = $b;
        $a = vaddq_s32(u, v);
        $b = raw(vsubq_s32(u, v), $z, $m);
    }};
}
macro_rules! trreg {
    ($c0:ident,$c1:ident,$c2:ident,$c3:ident) => {{
        let a = vtrn1q_s32($c0, $c1);
        let b = vtrn2q_s32($c0, $c1);
        let d = vtrn1q_s32($c2, $c3);
        let e = vtrn2q_s32($c2, $c3);
        $c0 = vreinterpretq_s32_s64(vtrn1q_s64(
            vreinterpretq_s64_s32(a),
            vreinterpretq_s64_s32(d),
        ));
        $c2 = vreinterpretq_s32_s64(vtrn2q_s64(
            vreinterpretq_s64_s32(a),
            vreinterpretq_s64_s32(d),
        ));
        $c1 = vreinterpretq_s32_s64(vtrn1q_s64(
            vreinterpretq_s64_s32(b),
            vreinterpretq_s64_s32(e),
        ));
        $c3 = vreinterpretq_s32_s64(vtrn2q_s64(
            vreinterpretq_s64_s32(b),
            vreinterpretq_s64_s32(e),
        ));
    }};
}

#[inline(always)]
fn forward_body(buf: &mut [i32; N], t: &Tables) {
    // SAFETY: build.rs restricts the crate to AArch64 macOS with baseline NEON. N=256; the four
    // 64-word tiles and j<64 strided by four keep every vector access in buf. Each selected table row
    // is [i32;4] and checked indexing bounds table selection. buf is exclusively borrowed and disjoint
    // from immutable Tables.
    unsafe {
        let bp = buf.as_mut_ptr();
        for j in (0..64).step_by(4) {
            let mut c0 = vld1q_s32(bp.add(j));
            let mut c1 = vld1q_s32(bp.add(j + 64));
            let mut c2 = vld1q_s32(bp.add(j + 128));
            let mut c3 = vld1q_s32(bp.add(j + 192));
            let z = vdupq_n_s32(t.zr[1]);
            let m = vdupq_n_s32(t.zq[1]);
            ctreg!(c0, c2, z, m);
            ctreg!(c1, c3, z, m);
            let z = vdupq_n_s32(t.zr[2]);
            let m = vdupq_n_s32(t.zq[2]);
            ctreg!(c0, c1, z, m);
            let z = vdupq_n_s32(t.zr[3]);
            let m = vdupq_n_s32(t.zq[3]);
            ctreg!(c2, c3, z, m);
            vst1q_s32(bp.add(j), c0);
            vst1q_s32(bp.add(j + 64), c1);
            vst1q_s32(bp.add(j + 128), c2);
            vst1q_s32(bp.add(j + 192), c3);
        }
        for tile in 0..4 {
            let base = tile * 64;
            let mut c0 = vld1q_s32(bp.add(base));
            let mut c1 = vld1q_s32(bp.add(base + 4));
            let mut c2 = vld1q_s32(bp.add(base + 8));
            let mut c3 = vld1q_s32(bp.add(base + 12));
            let mut c4 = vld1q_s32(bp.add(base + 16));
            let mut c5 = vld1q_s32(bp.add(base + 20));
            let mut c6 = vld1q_s32(bp.add(base + 24));
            let mut c7 = vld1q_s32(bp.add(base + 28));
            let mut c8 = vld1q_s32(bp.add(base + 32));
            let mut c9 = vld1q_s32(bp.add(base + 36));
            let mut c10 = vld1q_s32(bp.add(base + 40));
            let mut c11 = vld1q_s32(bp.add(base + 44));
            let mut c12 = vld1q_s32(bp.add(base + 48));
            let mut c13 = vld1q_s32(bp.add(base + 52));
            let mut c14 = vld1q_s32(bp.add(base + 56));
            let mut c15 = vld1q_s32(bp.add(base + 60));
            let z = vdupq_n_s32(t.zr[4 + tile]);
            let m = vdupq_n_s32(t.zq[4 + tile]);
            ctreg!(c0, c8, z, m);
            ctreg!(c1, c9, z, m);
            ctreg!(c2, c10, z, m);
            ctreg!(c3, c11, z, m);
            ctreg!(c4, c12, z, m);
            ctreg!(c5, c13, z, m);
            ctreg!(c6, c14, z, m);
            ctreg!(c7, c15, z, m);
            let z = vdupq_n_s32(t.zr[8 + tile * 2]);
            let m = vdupq_n_s32(t.zq[8 + tile * 2]);
            ctreg!(c0, c4, z, m);
            ctreg!(c1, c5, z, m);
            ctreg!(c2, c6, z, m);
            ctreg!(c3, c7, z, m);
            let z = vdupq_n_s32(t.zr[8 + tile * 2 + 1]);
            let m = vdupq_n_s32(t.zq[8 + tile * 2 + 1]);
            ctreg!(c8, c12, z, m);
            ctreg!(c9, c13, z, m);
            ctreg!(c10, c14, z, m);
            ctreg!(c11, c15, z, m);
            let z = vdupq_n_s32(t.zr[16 + tile * 4]);
            let m = vdupq_n_s32(t.zq[16 + tile * 4]);
            ctreg!(c0, c2, z, m);
            ctreg!(c1, c3, z, m);
            let z = vdupq_n_s32(t.zr[16 + tile * 4 + 1]);
            let m = vdupq_n_s32(t.zq[16 + tile * 4 + 1]);
            ctreg!(c4, c6, z, m);
            ctreg!(c5, c7, z, m);
            let z = vdupq_n_s32(t.zr[16 + tile * 4 + 2]);
            let m = vdupq_n_s32(t.zq[16 + tile * 4 + 2]);
            ctreg!(c8, c10, z, m);
            ctreg!(c9, c11, z, m);
            let z = vdupq_n_s32(t.zr[16 + tile * 4 + 3]);
            let m = vdupq_n_s32(t.zq[16 + tile * 4 + 3]);
            ctreg!(c12, c14, z, m);
            ctreg!(c13, c15, z, m);
            let z = vdupq_n_s32(t.zr[32 + tile * 8]);
            let m = vdupq_n_s32(t.zq[32 + tile * 8]);
            ctreg!(c0, c1, z, m);
            let z = vdupq_n_s32(t.zr[32 + tile * 8 + 1]);
            let m = vdupq_n_s32(t.zq[32 + tile * 8 + 1]);
            ctreg!(c2, c3, z, m);
            let z = vdupq_n_s32(t.zr[32 + tile * 8 + 2]);
            let m = vdupq_n_s32(t.zq[32 + tile * 8 + 2]);
            ctreg!(c4, c5, z, m);
            let z = vdupq_n_s32(t.zr[32 + tile * 8 + 3]);
            let m = vdupq_n_s32(t.zq[32 + tile * 8 + 3]);
            ctreg!(c6, c7, z, m);
            let z = vdupq_n_s32(t.zr[32 + tile * 8 + 4]);
            let m = vdupq_n_s32(t.zq[32 + tile * 8 + 4]);
            ctreg!(c8, c9, z, m);
            let z = vdupq_n_s32(t.zr[32 + tile * 8 + 5]);
            let m = vdupq_n_s32(t.zq[32 + tile * 8 + 5]);
            ctreg!(c10, c11, z, m);
            let z = vdupq_n_s32(t.zr[32 + tile * 8 + 6]);
            let m = vdupq_n_s32(t.zq[32 + tile * 8 + 6]);
            ctreg!(c12, c13, z, m);
            let z = vdupq_n_s32(t.zr[32 + tile * 8 + 7]);
            let m = vdupq_n_s32(t.zq[32 + tile * 8 + 7]);
            ctreg!(c14, c15, z, m);
            c0 = center(c0);
            c1 = center(c1);
            c2 = center(c2);
            c3 = center(c3);
            c4 = center(c4);
            c5 = center(c5);
            c6 = center(c6);
            c7 = center(c7);
            c8 = center(c8);
            c9 = center(c9);
            c10 = center(c10);
            c11 = center(c11);
            c12 = center(c12);
            c13 = center(c13);
            c14 = center(c14);
            c15 = center(c15);
            trreg!(c0, c1, c2, c3);
            let tv = &t.fwd[tile * 4];
            let z = vld1q_s32(tv[0].as_ptr());
            let m = vld1q_s32(tv[1].as_ptr());
            ctreg!(c0, c2, z, m);
            ctreg!(c1, c3, z, m);
            let z = vld1q_s32(tv[2].as_ptr());
            let m = vld1q_s32(tv[3].as_ptr());
            ctreg!(c0, c1, z, m);
            let z = vld1q_s32(tv[4].as_ptr());
            let m = vld1q_s32(tv[5].as_ptr());
            ctreg!(c2, c3, z, m);
            trreg!(c4, c5, c6, c7);
            let tv = &t.fwd[tile * 4 + 1];
            let z = vld1q_s32(tv[0].as_ptr());
            let m = vld1q_s32(tv[1].as_ptr());
            ctreg!(c4, c6, z, m);
            ctreg!(c5, c7, z, m);
            let z = vld1q_s32(tv[2].as_ptr());
            let m = vld1q_s32(tv[3].as_ptr());
            ctreg!(c4, c5, z, m);
            let z = vld1q_s32(tv[4].as_ptr());
            let m = vld1q_s32(tv[5].as_ptr());
            ctreg!(c6, c7, z, m);
            trreg!(c8, c9, c10, c11);
            let tv = &t.fwd[tile * 4 + 2];
            let z = vld1q_s32(tv[0].as_ptr());
            let m = vld1q_s32(tv[1].as_ptr());
            ctreg!(c8, c10, z, m);
            ctreg!(c9, c11, z, m);
            let z = vld1q_s32(tv[2].as_ptr());
            let m = vld1q_s32(tv[3].as_ptr());
            ctreg!(c8, c9, z, m);
            let z = vld1q_s32(tv[4].as_ptr());
            let m = vld1q_s32(tv[5].as_ptr());
            ctreg!(c10, c11, z, m);
            trreg!(c12, c13, c14, c15);
            let tv = &t.fwd[tile * 4 + 3];
            let z = vld1q_s32(tv[0].as_ptr());
            let m = vld1q_s32(tv[1].as_ptr());
            ctreg!(c12, c14, z, m);
            ctreg!(c13, c15, z, m);
            let z = vld1q_s32(tv[2].as_ptr());
            let m = vld1q_s32(tv[3].as_ptr());
            ctreg!(c12, c13, z, m);
            let z = vld1q_s32(tv[4].as_ptr());
            let m = vld1q_s32(tv[5].as_ptr());
            ctreg!(c14, c15, z, m);
            vst1q_s32(bp.add(base), c0);
            vst1q_s32(bp.add(base + 4), c1);
            vst1q_s32(bp.add(base + 8), c2);
            vst1q_s32(bp.add(base + 12), c3);
            vst1q_s32(bp.add(base + 16), c4);
            vst1q_s32(bp.add(base + 20), c5);
            vst1q_s32(bp.add(base + 24), c6);
            vst1q_s32(bp.add(base + 28), c7);
            vst1q_s32(bp.add(base + 32), c8);
            vst1q_s32(bp.add(base + 36), c9);
            vst1q_s32(bp.add(base + 40), c10);
            vst1q_s32(bp.add(base + 44), c11);
            vst1q_s32(bp.add(base + 48), c12);
            vst1q_s32(bp.add(base + 52), c13);
            vst1q_s32(bp.add(base + 56), c14);
            vst1q_s32(bp.add(base + 60), c15);
        }
    }
}
#[inline(always)]
fn inverse_body(buf: &mut [i32; N], t: &Tables) {
    // SAFETY: build.rs restricts the crate to AArch64 macOS with baseline NEON. N=256; the four
    // 64-word tiles and j<64 strided by four keep every vector access in buf. Each selected table row
    // is [i32;4] and checked indexing bounds table selection. buf is exclusively borrowed and disjoint
    // from immutable Tables.
    unsafe {
        let bp = buf.as_mut_ptr();
        for tile in 0..4 {
            let base = tile * 64;
            let mut c0 = vld1q_s32(bp.add(base));
            let mut c1 = vld1q_s32(bp.add(base + 4));
            let mut c2 = vld1q_s32(bp.add(base + 8));
            let mut c3 = vld1q_s32(bp.add(base + 12));
            let mut c4 = vld1q_s32(bp.add(base + 16));
            let mut c5 = vld1q_s32(bp.add(base + 20));
            let mut c6 = vld1q_s32(bp.add(base + 24));
            let mut c7 = vld1q_s32(bp.add(base + 28));
            let mut c8 = vld1q_s32(bp.add(base + 32));
            let mut c9 = vld1q_s32(bp.add(base + 36));
            let mut c10 = vld1q_s32(bp.add(base + 40));
            let mut c11 = vld1q_s32(bp.add(base + 44));
            let mut c12 = vld1q_s32(bp.add(base + 48));
            let mut c13 = vld1q_s32(bp.add(base + 52));
            let mut c14 = vld1q_s32(bp.add(base + 56));
            let mut c15 = vld1q_s32(bp.add(base + 60));
            let tv = &t.inv[tile * 4];
            let z = vld1q_s32(tv[2].as_ptr());
            let m = vld1q_s32(tv[3].as_ptr());
            gsreg!(c0, c1, z, m);
            let z = vld1q_s32(tv[4].as_ptr());
            let m = vld1q_s32(tv[5].as_ptr());
            gsreg!(c2, c3, z, m);
            let z = vld1q_s32(tv[0].as_ptr());
            let m = vld1q_s32(tv[1].as_ptr());
            gsreg!(c0, c2, z, m);
            gsreg!(c1, c3, z, m);
            trreg!(c0, c1, c2, c3);
            let tv = &t.inv[tile * 4 + 1];
            let z = vld1q_s32(tv[2].as_ptr());
            let m = vld1q_s32(tv[3].as_ptr());
            gsreg!(c4, c5, z, m);
            let z = vld1q_s32(tv[4].as_ptr());
            let m = vld1q_s32(tv[5].as_ptr());
            gsreg!(c6, c7, z, m);
            let z = vld1q_s32(tv[0].as_ptr());
            let m = vld1q_s32(tv[1].as_ptr());
            gsreg!(c4, c6, z, m);
            gsreg!(c5, c7, z, m);
            trreg!(c4, c5, c6, c7);
            let tv = &t.inv[tile * 4 + 2];
            let z = vld1q_s32(tv[2].as_ptr());
            let m = vld1q_s32(tv[3].as_ptr());
            gsreg!(c8, c9, z, m);
            let z = vld1q_s32(tv[4].as_ptr());
            let m = vld1q_s32(tv[5].as_ptr());
            gsreg!(c10, c11, z, m);
            let z = vld1q_s32(tv[0].as_ptr());
            let m = vld1q_s32(tv[1].as_ptr());
            gsreg!(c8, c10, z, m);
            gsreg!(c9, c11, z, m);
            trreg!(c8, c9, c10, c11);
            let tv = &t.inv[tile * 4 + 3];
            let z = vld1q_s32(tv[2].as_ptr());
            let m = vld1q_s32(tv[3].as_ptr());
            gsreg!(c12, c13, z, m);
            let z = vld1q_s32(tv[4].as_ptr());
            let m = vld1q_s32(tv[5].as_ptr());
            gsreg!(c14, c15, z, m);
            let z = vld1q_s32(tv[0].as_ptr());
            let m = vld1q_s32(tv[1].as_ptr());
            gsreg!(c12, c14, z, m);
            gsreg!(c13, c15, z, m);
            trreg!(c12, c13, c14, c15);
            let z = vdupq_n_s32(t.izr[63 - tile * 8]);
            let m = vdupq_n_s32(t.izq[63 - tile * 8]);
            gsreg!(c0, c1, z, m);
            let z = vdupq_n_s32(t.izr[63 - tile * 8 - 1]);
            let m = vdupq_n_s32(t.izq[63 - tile * 8 - 1]);
            gsreg!(c2, c3, z, m);
            let z = vdupq_n_s32(t.izr[63 - tile * 8 - 2]);
            let m = vdupq_n_s32(t.izq[63 - tile * 8 - 2]);
            gsreg!(c4, c5, z, m);
            let z = vdupq_n_s32(t.izr[63 - tile * 8 - 3]);
            let m = vdupq_n_s32(t.izq[63 - tile * 8 - 3]);
            gsreg!(c6, c7, z, m);
            let z = vdupq_n_s32(t.izr[63 - tile * 8 - 4]);
            let m = vdupq_n_s32(t.izq[63 - tile * 8 - 4]);
            gsreg!(c8, c9, z, m);
            let z = vdupq_n_s32(t.izr[63 - tile * 8 - 5]);
            let m = vdupq_n_s32(t.izq[63 - tile * 8 - 5]);
            gsreg!(c10, c11, z, m);
            let z = vdupq_n_s32(t.izr[63 - tile * 8 - 6]);
            let m = vdupq_n_s32(t.izq[63 - tile * 8 - 6]);
            gsreg!(c12, c13, z, m);
            let z = vdupq_n_s32(t.izr[63 - tile * 8 - 7]);
            let m = vdupq_n_s32(t.izq[63 - tile * 8 - 7]);
            gsreg!(c14, c15, z, m);
            c0 = center(c0);
            c1 = center(c1);
            c2 = center(c2);
            c3 = center(c3);
            c4 = center(c4);
            c5 = center(c5);
            c6 = center(c6);
            c7 = center(c7);
            c8 = center(c8);
            c9 = center(c9);
            c10 = center(c10);
            c11 = center(c11);
            c12 = center(c12);
            c13 = center(c13);
            c14 = center(c14);
            c15 = center(c15);
            let z = vdupq_n_s32(t.izr[31 - tile * 4]);
            let m = vdupq_n_s32(t.izq[31 - tile * 4]);
            gsreg!(c0, c2, z, m);
            gsreg!(c1, c3, z, m);
            let z = vdupq_n_s32(t.izr[31 - tile * 4 - 1]);
            let m = vdupq_n_s32(t.izq[31 - tile * 4 - 1]);
            gsreg!(c4, c6, z, m);
            gsreg!(c5, c7, z, m);
            let z = vdupq_n_s32(t.izr[31 - tile * 4 - 2]);
            let m = vdupq_n_s32(t.izq[31 - tile * 4 - 2]);
            gsreg!(c8, c10, z, m);
            gsreg!(c9, c11, z, m);
            let z = vdupq_n_s32(t.izr[31 - tile * 4 - 3]);
            let m = vdupq_n_s32(t.izq[31 - tile * 4 - 3]);
            gsreg!(c12, c14, z, m);
            gsreg!(c13, c15, z, m);
            let z = vdupq_n_s32(t.izr[15 - tile * 2]);
            let m = vdupq_n_s32(t.izq[15 - tile * 2]);
            gsreg!(c0, c4, z, m);
            gsreg!(c1, c5, z, m);
            gsreg!(c2, c6, z, m);
            gsreg!(c3, c7, z, m);
            let z = vdupq_n_s32(t.izr[15 - tile * 2 - 1]);
            let m = vdupq_n_s32(t.izq[15 - tile * 2 - 1]);
            gsreg!(c8, c12, z, m);
            gsreg!(c9, c13, z, m);
            gsreg!(c10, c14, z, m);
            gsreg!(c11, c15, z, m);
            let z = vdupq_n_s32(t.izr[7 - tile]);
            let m = vdupq_n_s32(t.izq[7 - tile]);
            gsreg!(c0, c8, z, m);
            gsreg!(c1, c9, z, m);
            gsreg!(c2, c10, z, m);
            gsreg!(c3, c11, z, m);
            gsreg!(c4, c12, z, m);
            gsreg!(c5, c13, z, m);
            gsreg!(c6, c14, z, m);
            gsreg!(c7, c15, z, m);
            c0 = center(c0);
            c1 = center(c1);
            c2 = center(c2);
            c3 = center(c3);
            c4 = center(c4);
            c5 = center(c5);
            c6 = center(c6);
            c7 = center(c7);
            c8 = center(c8);
            c9 = center(c9);
            c10 = center(c10);
            c11 = center(c11);
            c12 = center(c12);
            c13 = center(c13);
            c14 = center(c14);
            c15 = center(c15);
            vst1q_s32(bp.add(base), c0);
            vst1q_s32(bp.add(base + 4), c1);
            vst1q_s32(bp.add(base + 8), c2);
            vst1q_s32(bp.add(base + 12), c3);
            vst1q_s32(bp.add(base + 16), c4);
            vst1q_s32(bp.add(base + 20), c5);
            vst1q_s32(bp.add(base + 24), c6);
            vst1q_s32(bp.add(base + 28), c7);
            vst1q_s32(bp.add(base + 32), c8);
            vst1q_s32(bp.add(base + 36), c9);
            vst1q_s32(bp.add(base + 40), c10);
            vst1q_s32(bp.add(base + 44), c11);
            vst1q_s32(bp.add(base + 48), c12);
            vst1q_s32(bp.add(base + 52), c13);
            vst1q_s32(bp.add(base + 56), c14);
            vst1q_s32(bp.add(base + 60), c15);
        }
        for j in (0..64).step_by(4) {
            let mut c0 = vld1q_s32(bp.add(j));
            let mut c1 = vld1q_s32(bp.add(j + 64));
            let mut c2 = vld1q_s32(bp.add(j + 128));
            let mut c3 = vld1q_s32(bp.add(j + 192));
            let z = vdupq_n_s32(t.izr[3]);
            let m = vdupq_n_s32(t.izq[3]);
            gsreg!(c0, c1, z, m);
            let z = vdupq_n_s32(t.izr[2]);
            let m = vdupq_n_s32(t.izq[2]);
            gsreg!(c2, c3, z, m);
            let z = vdupq_n_s32(t.izr[1]);
            let m = vdupq_n_s32(t.izq[1]);
            gsreg!(c0, c2, z, m);
            gsreg!(c1, c3, z, m);
            c0 = center(c0);
            c1 = center(c1);
            c2 = center(c2);
            c3 = center(c3);
            vst1q_s32(bp.add(j), c0);
            vst1q_s32(bp.add(j + 64), c1);
            vst1q_s32(bp.add(j + 128), c2);
            vst1q_s32(bp.add(j + 192), c3);
        }
    }
}
pub(crate) struct Key {
    b: [[i32; N]; 10],
    m: [[i32; N]; 10],
}
impl Drop for Key {
    fn drop(&mut self) {
        self.b.zeroize();
        self.m.zeroize();
    }
}
const _: () = assert!(core::mem::size_of::<Key>() == 20480);
// SAFETY: contract of the routines of `reservoir-wrapper.S` declared below (this crate's own
// file, assembled by `build.rs`). Each saves the frame, calls the function defined in this file
// under the same name with the suffix `_impl`, with the argument registers unchanged, then stores
// zero over a fixed range of stack below its own frame, clears the caller-saved registers and the
// flags, and returns no value. Its pointer contract is therefore the `# Safety` section of that
// function. It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions
// only.
unsafe extern "C" {
    fn pretzel55_aux32_factors(a: *const i32, b: *mut i32, m: *mut i32, f: *mut i32, k: usize);
    fn pretzel55_aux32_accumulate(
        a: *const i32,
        b: *const i32,
        m: *const i32,
        f: *mut i32,
        k: usize,
    );
    fn pretzel55_aux32_gram(f: *const i32, out: *mut i64);
    fn pretzel55_aux32_add(f: *const i32, out: *mut i32);
    fn pretzel55_aux32_lead(f: *const i32, y: *const i32, out: *mut i32);
}
impl Key {
    pub(crate) fn empty() -> Self {
        Self {
            b: [[0; N]; 10],
            m: [[0; N]; 10],
        }
    }
    pub(crate) fn populate_gram(&mut self, s: &Vector, gram: &mut [i64; N]) {
        let mut f = Poly([0; N]);
        for k in 0..10 {
            let mut a = Poly([0; N]);
            a.0.copy_from_slice(&s[(k + 1) * N..(k + 2) * N]);
            forward(&mut a.0, tables());
            // SAFETY: build.rs admits AArch64 with baseline NEON. reservoir-wrapper.S forwards this
            // ABI to the corresponding pretzel55_aux32_*_impl below; a, b[k], m[k] and f are distinct
            // initialized [i32;N] arrays, with k in 0..10. N=256 bounds every callback load/store.
            unsafe {
                pretzel55_aux32_factors(
                    a.0.as_ptr(),
                    self.b[k].as_mut_ptr(),
                    self.m[k].as_mut_ptr(),
                    f.0.as_mut_ptr(),
                    k,
                );
            }
        }
        inverse(&mut f.0, tables());
        // SAFETY: build.rs admits AArch64 with baseline NEON. reservoir-wrapper.S forwards this ABI to
        // the corresponding pretzel55_aux32_*_impl below; f is an initialized [i32;N] and gram is a
        // disjoint exclusive [i64;N]. N=256 bounds every callback load/store.
        unsafe {
            pretzel55_aux32_gram(f.0.as_ptr(), gram.as_mut_ptr());
        }
    }
    // Initial supports 1149/1462. Split the first 32 coefficients of secret
    // polynomial 2 into the second group. Bounds 256323968/258371712 are below P/2.
    // This is not an interface for arbitrary or transport-updated vectors.
    #[inline(never)]
    pub(crate) fn write_initial(&self, y: &Vector, out: &mut [i32; N]) {
        const GROUPS: [&[usize]; 2] = [&[0, 1, 2, 5, 6], &[2, 3, 4, 7, 8, 9]];
        for (group, indices) in GROUPS.iter().enumerate() {
            let mut f = Poly([0; N]);
            for (position, &k) in indices.iter().enumerate() {
                let mut a = Poly([0; N]);
                a.0.copy_from_slice(&y[(k + 1) * N..(k + 2) * N]);
                if k == 2 {
                    if group == 0 {
                        a.0[..32].fill(0);
                    } else {
                        a.0[32..].fill(0);
                    }
                }
                forward(&mut a.0, tables());
                // Reset on 0, center after the fourth term and after every later term.
                let accumulation_slot = if position >= 4 { 9 } else { position };
                // SAFETY: build.rs admits AArch64 with baseline NEON. reservoir-wrapper.S forwards
                // this ABI to the corresponding pretzel55_aux32_*_impl below; a, b[k], m[k] and f are
                // distinct initialized [i32;N] arrays; accumulation_slot is 0..3 or 9. N=256 bounds
                // every callback load/store.
                unsafe {
                    pretzel55_aux32_accumulate(
                        a.0.as_ptr(),
                        self.b[k].as_ptr(),
                        self.m[k].as_ptr(),
                        f.0.as_mut_ptr(),
                        accumulation_slot,
                    );
                }
            }
            inverse(&mut f.0, tables());
            // SAFETY: build.rs admits AArch64 with baseline NEON. reservoir-wrapper.S forwards this
            // ABI to the corresponding pretzel55_aux32_*_impl below; f and y's first N words are
            // initialized, and out is a disjoint exclusive [i32;N]; group zero initializes out before
            // group one's add. N=256 bounds every callback load/store.
            unsafe {
                if group == 0 {
                    pretzel55_aux32_lead(f.0.as_ptr(), y.as_ptr(), out.as_mut_ptr());
                } else {
                    pretzel55_aux32_add(f.0.as_ptr(), out.as_mut_ptr());
                }
            }
        }
    }
}
#[inline(always)]
/// # Safety
/// On AArch64 with NEON, a, b and m must point to N=256 initialized aligned i32 values; f must be
/// writable for N values and initialized when k!=0. The output must not overlap any input, and all
/// regions must remain live for the call.
unsafe fn accumulate_native(a: *const i32, b: *const i32, m: *const i32, f: *mut i32, k: usize) {
    // SAFETY: The caller supplies the function safety contract: On AArch64 with NEON, a, b and m must
    // point to N=256 initialized aligned i32 values; f must be writable for N values and initialized
    // when k!=0. The output must not overlap any input, and all regions must remain live for the call.
    unsafe {
        for j in (0..N).step_by(4) {
            let v = raw(
                vld1q_s32(a.add(j)),
                vld1q_s32(b.add(j)),
                vld1q_s32(m.add(j)),
            );
            let at = f.add(j);
            let sum = if k == 0 {
                v
            } else {
                vaddq_s32(vld1q_s32(at), v)
            };
            vst1q_s32(
                at,
                if k == 3 || k == 7 || k == 9 {
                    center(sum)
                } else {
                    sum
                },
            );
        }
    }
}
#[unsafe(no_mangle)]
/// # Safety
/// On AArch64 with NEON, a, b and m must each cover N=256 initialized aligned i32 values; f must
/// exclusively cover N writable i32 values, initialized when k!=0 and disjoint from all inputs. The C
/// ABI entry in reservoir-wrapper.S forwards these pointers unchanged.
pub unsafe extern "C" fn pretzel55_aux32_accumulate_impl(
    a: *const i32,
    b: *const i32,
    m: *const i32,
    f: *mut i32,
    k: usize,
) {
    // SAFETY: The caller supplies the function safety contract: On AArch64 with NEON, a, b and m must
    // each cover N=256 initialized aligned i32 values; f must exclusively cover N writable i32 values,
    // initialized when k!=0 and disjoint from all inputs. The C ABI entry in reservoir-wrapper.S
    // forwards these pointers unchanged.
    unsafe {
        accumulate_native(a, b, m, f, k);
    }
}
#[unsafe(no_mangle)]
/// # Safety
/// On AArch64 with NEON, a must cover N=256 initialized aligned i32 values. b, m and f must each
/// exclusively cover N writable i32 values and be mutually disjoint and disjoint from a; f must be
/// initialized when k!=0. reservoir-wrapper.S forwards this C ABI unchanged.
pub unsafe extern "C" fn pretzel55_aux32_factors_impl(
    a: *const i32,
    b: *mut i32,
    m: *mut i32,
    f: *mut i32,
    k: usize,
) {
    // SAFETY: The caller supplies the function safety contract: On AArch64 with NEON, a must cover
    // N=256 initialized aligned i32 values. b, m and f must each exclusively cover N writable i32
    // values and be mutually disjoint and disjoint from a; f must be initialized when k!=0.
    // reservoir-wrapper.S forwards this C ABI unchanged.
    unsafe {
        let factor = if k < 5 { 121127281i64 } else { -244273348i64 };
        for j in 0..N {
            let mut coefficient = *a.add(N - 1 - j);
            core::arch::asm!("/* {value:w} */",value=inout(reg)coefficient,options(nomem,nostack,preserves_flags));
            let v = cent(coefficient as i64 * factor);
            *b.add(j) = v;
            *m.add(j) = mu(v);
        }
        accumulate_native(a, b, m, f, k);
    }
}
#[unsafe(no_mangle)]
/// # Safety
/// f must cover N=256 initialized aligned i32 values; out must exclusively cover N writable aligned i64
/// values, disjoint from f. All storage must remain live across the reservoir-wrapper.S C ABI call.
pub unsafe extern "C" fn pretzel55_aux32_gram_impl(f: *const i32, out: *mut i64) {
    // SAFETY: The caller supplies the function safety contract: f must cover N=256 initialized aligned
    // i32 values; out must exclusively cover N writable aligned i64 values, disjoint from f. All
    // storage must remain live across the reservoir-wrapper.S C ABI call.
    unsafe {
        for j in 0..N {
            *out.add(j) = *f.add(j) as i64;
        }
    }
}
#[unsafe(no_mangle)]
/// # Safety
/// f and y must each cover N=256 initialized aligned i32 values; out must exclusively cover N writable
/// aligned i32 values and be disjoint from both inputs. Values must keep the i32 multiply/add in range
/// to avoid unwinding through the reservoir-wrapper.S C ABI.
pub unsafe extern "C" fn pretzel55_aux32_lead_impl(f: *const i32, y: *const i32, out: *mut i32) {
    // SAFETY: The caller supplies the function safety contract: f and y must each cover N=256
    // initialized aligned i32 values; out must exclusively cover N writable aligned i32 values and be
    // disjoint from both inputs. Values must keep the i32 multiply/add in range to avoid unwinding
    // through the reservoir-wrapper.S C ABI.
    unsafe {
        for j in 0..N {
            *out.add(j) = *f.add(j) + crate::params::PROPOSAL_W0 as i32 * y.add(j).read();
        }
    }
}

#[cfg(test)]
fn perm(j: usize) -> usize {
    (j & !15) | ((j & 3) << 2) | ((j >> 2) & 3)
}
#[cfg(test)]
// Keep the explicit lane order and index schedule of the kernel and its oracle.
#[allow(clippy::needless_range_loop)]
fn check() -> usize {
    let mut count = 0;
    for k in -5..=5 {
        let threshold = (2 * k + 1) * P / 2;
        for off in -4..=4 {
            let x = threshold + off;
            if (i32::MIN as i64..=i32::MAX as i64).contains(&x) {
                unsafe {
                    assert_eq!(vgetq_lane_s32::<0>(center(vdupq_n_s32(x as i32))), cent(x));
                }
                count += 1;
            }
        }
    }
    let mut seed = 61831u64;
    for _ in 0..100000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let x = (seed >> 32) as i32;
        unsafe {
            assert_eq!(vgetq_lane_s32::<0>(center(vdupq_n_s32(x))), cent(x as i64));
        }
        count += 1;
    }
    let t = tables();
    for trial in 0..16 {
        let mut a = Poly(core::array::from_fn(|i| {
            ((i * 377 + trial * 911) % 2925) as i32 - 1462
        }));
        let original = a.0;
        forward(&mut a.0, t);
        for j in 0..N {
            let root = pow(ROOT, 2 * (j as u8).reverse_bits() as u32 + 1);
            let mut want = 0i64;
            for &v in original.iter().rev() {
                want = (want * root + v as i64).rem_euclid(P);
            }
            assert_eq!(cent(a.0[perm(j)] as i64), cent(want));
            count += 1;
        }
        unsafe {
            center_all(&mut a.0);
        }
        inverse(&mut a.0, t);
        for j in 0..N {
            assert_eq!(a.0[j], cent(original[j] as i64 * 256));
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    #[test]
    fn exact_static_tables_and_center_transform_oracles() {
        assert_eq!(super::tables(), super::tables_reference());
        assert!(super::check() > 100000);
    }
}

// SAFETY: contract of a routine of `reservoir-wrapper.S` (this crate's own file, assembled by
// `build.rs`). It saves the frame, calls the function defined in this file under
// the same name with the suffix `_impl`, with the argument registers unchanged, then stores zero
// over a fixed range of stack below its own frame, clears the caller-saved registers and the flags,
// and returns no value. Its pointer contract is therefore the `# Safety` section of that function.
// It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions only.
unsafe extern "C" {
    fn pretzel55_aux32_forward(buf: *mut i32);
}
fn forward(buf: &mut [i32; N], _t: &Tables) {
    // SAFETY: build.rs admits AArch64 with baseline NEON. reservoir-wrapper.S forwards buf to the
    // corresponding Rust callback below. The exclusive initialized [i32;N] borrow supplies exactly
    // N=256 aligned writable values for its temporary array reference.
    unsafe {
        pretzel55_aux32_forward(buf.as_mut_ptr());
    }
}
#[unsafe(no_mangle)]
/// # Safety
/// On AArch64 with NEON, buf must uniquely borrow N=256 initialized, writable, i32-aligned values for
/// the call from reservoir-wrapper.S. No concurrent or aliased access is permitted while the mutable
/// array reference exists.
pub unsafe extern "C" fn pretzel55_aux32_forward_impl(buf: *mut i32) {
    // SAFETY: The caller supplies the function safety contract: On AArch64 with NEON, buf must
    // uniquely borrow N=256 initialized, writable, i32-aligned values for the call from
    // reservoir-wrapper.S. No concurrent or aliased access is permitted while the mutable array
    // reference exists.
    unsafe {
        forward_body(&mut *(buf as *mut [i32; N]), tables());
    }
}

// SAFETY: contract of a routine of `reservoir-wrapper.S` (this crate's own file, assembled by
// `build.rs`). It saves the frame, calls the function defined in this file under
// the same name with the suffix `_impl`, with the argument registers unchanged, then stores zero
// over a fixed range of stack below its own frame, clears the caller-saved registers and the flags,
// and returns no value. Its pointer contract is therefore the `# Safety` section of that function.
// It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions only.
unsafe extern "C" {
    fn pretzel55_aux32_inverse(buf: *mut i32);
}
fn inverse(buf: &mut [i32; N], _t: &Tables) {
    // SAFETY: build.rs admits AArch64 with baseline NEON. reservoir-wrapper.S forwards buf to the
    // corresponding Rust callback below. The exclusive initialized [i32;N] borrow supplies exactly
    // N=256 aligned writable values for its temporary array reference.
    unsafe {
        pretzel55_aux32_inverse(buf.as_mut_ptr());
    }
}
#[unsafe(no_mangle)]
/// # Safety
/// On AArch64 with NEON, buf must uniquely borrow N=256 initialized, writable, i32-aligned values for
/// the call from reservoir-wrapper.S. No concurrent or aliased access is permitted while the mutable
/// array reference exists.
pub unsafe extern "C" fn pretzel55_aux32_inverse_impl(buf: *mut i32) {
    // SAFETY: The caller supplies the function safety contract: On AArch64 with NEON, buf must
    // uniquely borrow N=256 initialized, writable, i32-aligned values for the call from
    // reservoir-wrapper.S. No concurrent or aliased access is permitted while the mutable array
    // reference exists.
    unsafe {
        inverse_body(&mut *(buf as *mut [i32; N]), tables());
    }
}

// Exact signed reconstruction after separately bounded modular inverse groups.
// The i64 intermediate precedes narrowing; total initial tail plus leading term
// is bounded below 2^31. Caller-owned out is retired
// by its complete owner; this kernel uses the same erased C-ABI wrapper.
#[unsafe(no_mangle)]
/// # Safety
/// f must cover N=256 initialized aligned i32 values and out must exclusively cover N initialized
/// writable aligned i32 values, disjoint from f. Both regions must remain live across the
/// reservoir-wrapper.S C ABI call.
pub unsafe extern "C" fn pretzel55_aux32_add_impl(f: *const i32, out: *mut i32) {
    // SAFETY: The caller supplies the function safety contract: f must cover N=256 initialized aligned
    // i32 values and out must exclusively cover N initialized writable aligned i32 values, disjoint
    // from f. Both regions must remain live across the reservoir-wrapper.S C ABI call.
    unsafe {
        for j in 0..N {
            let sum = (*out.add(j) as i64) + (*f.add(j) as i64);
            *out.add(j) = sum as i32;
        }
    }
}

#[cfg(test)]
mod range_tests {
    use super::*;
    #[test]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn split_groups_match_integer_dot_at_full_new_support() {
        let mut seed = 782194u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for trial in 0..12 {
            let mut key = [0; DIM];
            key[0] = 1;
            for x in &mut key[N..] {
                *x = match trial {
                    0 => 1,
                    1 => -1,
                    _ => (next() % 3) as i32 - 1,
                };
            }
            let response: Vector = core::array::from_fn(|i| {
                let cap = if i < N {
                    168
                } else if i < 6 * N {
                    1149
                } else {
                    1462
                };
                match trial {
                    0 => cap,
                    1 => -cap,
                    2 => {
                        if i % 2 == 0 {
                            cap
                        } else {
                            -cap
                        }
                    }
                    3 => {
                        if i % 256 < 32 {
                            cap
                        } else {
                            -cap
                        }
                    }
                    _ => (next() % (2 * cap + 1) as u64) as i32 - cap,
                }
            });
            let mut prepared = Key::empty();
            let mut gram = [0; N];
            prepared.populate_gram(&key, &mut gram);
            let mut got = [0; N];
            prepared.write_initial(&response, &mut got);
            for j in 0..N {
                assert_eq!(
                    i64::from(got[j]),
                    crate::transport::dot_rotated(&response, &key, j),
                    "trial {} rotation {}",
                    trial,
                    j
                );
            }
        }
    }
}
