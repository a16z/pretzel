//! Exact bounded-tail correlation implementation.
//! All private transform/product/factor/output kernels cross an immediately erased C-ABI boundary.
use crate::params::{DIM, N};
use crate::transport::Vector;
use core::arch::aarch64::*;
use zeroize::Zeroize;
const P: i64 = 516809729;
#[cfg(test)]
const ROOT: i64 = 75035968;
const R: i32 = 1115421634;
const _: () = assert!(
    N == 256
        && DIM == 1792
        && crate::params::PROPOSAL_W0 == 9216
        && crate::params::WS == 196
        && crate::params::WE == 121
        && crate::params::SHELL_HI <= 196045
);
// The bound below starts from 1355 = (2711 - 1) / 2, where 2711 is the number of bounds
// of the error table (`ct_rarequeue.rs`). 154 and 1064 are the same quantity for the
// leading table (155 bounds, one parity) and the secret table (2129 bounds). The signer
// samples through alias and tree tables built from the 192-bit prefixes of the table
// bounds: a value is produced only by a 192-bit draw strictly inside the cell between two
// consecutive prefixes, and a draw on a cell boundary aborts the attempt. The values it
// produces are therefore smaller; the assertions below do not use that and start from 1355.
// The last assertion compares P with twice 233505795 = 1355 * (196045 - 23716), that is
// 1355 times SHELL_HI - W0 of `params.rs`.
// Counts outside constructor rows decode to zero, even on aborted attempts.
// Initial-tail bound only; no post-transport support assumption.
const _: () = {
    let mut b = 1355i64;
    let mut j = 0;
    while j < 6 {
        b += (P * ((1i64 << 31) + b) + (1i64 << 32) - 1) / (1i64 << 32);
        assert!(b < (1i64 << 31));
        j += 1;
    }
    assert!(b == 2098750490);
    assert!(4 * (P - 1) < (1i64 << 31));
    assert!(1355 * (crate::params::SHELL_HI - crate::params::W0) == 233505795);
    assert!(P > 2 * 233505795);
};
#[inline(always)]
fn cent(x: i64) -> i32 {
    ((x + P / 2).rem_euclid(P) - P / 2) as i32
}
#[inline(always)]
fn mu(x: i32) -> i32 {
    ((x as i64 * (1i64 << 31) + P / 2).div_euclid(P)) as i32
}
#[cfg(test)]
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
include!("../../pretzel-4-4/core/src/aux32_static_tables.rs");
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
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer.
#[inline(always)]
unsafe fn raw(a: int32x4_t, b: int32x4_t, m: int32x4_t) -> int32x4_t {
    vmlsq_n_s32(vmulq_s32(a, b), vqrdmulhq_s32(a, m), P as i32)
}
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer.
#[inline(always)]
unsafe fn center(a: int32x4_t) -> int32x4_t {
    vmlsq_n_s32(a, vrshrq_n_s32::<28>(vqdmulhq_n_s32(a, R)), P as i32)
}
#[cfg(test)]
#[inline(always)]
unsafe fn center_all(buf: &mut [i32; N]) {
    for j in (0..N).step_by(4) {
        let p = buf.as_mut_ptr().add(j);
        vst1q_s32(p, center(vld1q_s32(p)));
    }
}
#[repr(C, align(8))]
struct Poly([i32; N]);
impl Drop for Poly {
    fn drop(&mut self) {
        // SAFETY: `Poly` is `repr(C, align(8))` and 1024 bytes long (asserted below), that is 128
        // aligned `u64` words. `drop` has exclusive access, and all-zero bytes are a valid `[i32;
        // N]`.
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
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `buf` is an exclusive `[i32; N]` (N = 256). The
    // first loop loads and stores four lanes at `j`, `j + 64`, `j + 128` and `j + 192` with `j + 4
    // <= 64`; the tile loop at `base + 4 * i` for `i < 16` with `base <= 192`. All of them end at
    // or before `N`. `tv[i]` is a checked index into rows of exactly four `i32`, read by one load,
    // and `t.zr`, `t.zq` are indexed with checks. All loads and stores are unaligned forms.
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
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). `buf` is an exclusive `[i32; N]` (N = 256). The
    // tile loop loads and stores four lanes at `base + 4 * i` for `i < 16` with `base <= 192`; the
    // last loop at `j`, `j + 64`, `j + 128` and `j + 192` with `j + 4 <= 64`. All of them end at or
    // before `N`. `tv[i]` is a checked index into rows of exactly four `i32`, read by one load, and
    // `t.izr`, `t.izq` are indexed with checks. All loads and stores are unaligned forms.
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
    b: [[i32; N]; 6],
    m: [[i32; N]; 6],
}
impl Drop for Key {
    fn drop(&mut self) {
        self.b.zeroize();
        self.m.zeroize();
    }
}
const _: () = assert!(core::mem::size_of::<Key>() == 12288);
// SAFETY: contract of four routines of `reservoir-wrapper.S` (the rank-four file, assembled here
// under this crate's symbol prefix). Each saves the frame, calls the function defined in this file
// under the same name with the suffix `_impl`, with the argument registers unchanged, then stores
// zero over a fixed range of stack below its own frame, clears the caller-saved registers and the
// flags, and returns no value. Its pointer contract is therefore the `# Safety` section of that
// function. It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions
// only.
unsafe extern "C" {
    fn pretzel33_aux32_factors(a: *const i32, b: *mut i32, m: *mut i32, f: *mut i32, k: usize);
    fn pretzel33_aux32_accumulate(
        a: *const i32,
        b: *const i32,
        m: *const i32,
        f: *mut i32,
        k: usize,
    );
    fn pretzel33_aux32_gram(f: *const i32, out: *mut i64);
    fn pretzel33_aux32_lead(f: *const i32, y: *const i32, out: *mut i32);
}
impl Key {
    pub(crate) fn empty() -> Self {
        Self {
            b: [[0; N]; 6],
            m: [[0; N]; 6],
        }
    }
    pub(crate) fn populate_gram(&mut self, s: &Vector, gram: &mut [i64; N]) {
        let mut f = Poly([0; N]);
        for k in 0..6 {
            let mut a = Poly([0; N]);
            a.0.copy_from_slice(&s[(k + 1) * N..(k + 2) * N]);
            forward(&mut a.0);
            // SAFETY: the wrapper forwards to `pretzel33_aux32_factors_impl`. `a.0`, `self.b[k]`,
            // `self.m[k]` and `f.0` are four distinct, initialized, aligned `[i32; N]` arrays, the
            // last three reached through exclusive borrows, and `k < 6`.
            unsafe {
                pretzel33_aux32_factors(
                    a.0.as_ptr(),
                    self.b[k].as_mut_ptr(),
                    self.m[k].as_mut_ptr(),
                    f.0.as_mut_ptr(),
                    k,
                );
            }
        }
        inverse(&mut f.0);
        // SAFETY: the wrapper forwards to `pretzel33_aux32_gram_impl`. `f.0` is an initialized
        // `[i32; N]` and `gram` an exclusive `[i64; N]`, the extents that function reads and
        // writes.
        unsafe {
            pretzel33_aux32_gram(f.0.as_ptr(), gram.as_mut_ptr());
        }
    }
    #[inline(never)]
    pub(crate) fn write_initial(&self, y: &Vector, out: &mut [i32; N]) {
        let mut f = Poly([0; N]);
        for k in 0..6 {
            let mut a = Poly([0; N]);
            a.0.copy_from_slice(&y[(k + 1) * N..(k + 2) * N]);
            forward(&mut a.0);
            // SAFETY: the wrapper forwards to `pretzel33_aux32_accumulate_impl`. `a.0`, `self.b[k]`
            // and `self.m[k]` are initialized `[i32; N]` arrays that are only read; `f.0` is a
            // distinct local `[i32; N]`, initialized, that is read and written.
            unsafe {
                pretzel33_aux32_accumulate(
                    a.0.as_ptr(),
                    self.b[k].as_ptr(),
                    self.m[k].as_ptr(),
                    f.0.as_mut_ptr(),
                    k,
                );
            }
        }
        inverse(&mut f.0);
        // SAFETY: the wrapper forwards to `pretzel33_aux32_lead_impl`. `f.0` is an initialized
        // `[i32; N]`; `y` is an initialized `[i32; DIM]` with `DIM > N`, of which the first `N`
        // entries are read; `out` is an exclusive `[i32; N]`.
        unsafe {
            pretzel33_aux32_lead(f.0.as_ptr(), y.as_ptr(), out.as_mut_ptr());
        }
    }
}
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. `a`,
/// `b` and `m` must be valid for reads of `N = 256` `i32` each, and `f` for writes of `N` `i32`.
/// `f` is also read unless `k == 0`, so it must be initialized in that case. No alignment is
/// required: the loads and stores are unaligned forms.
#[inline(always)]
unsafe fn accumulate_native(a: *const i32, b: *const i32, m: *const i32, f: *mut i32, k: usize) {
    // SAFETY: the caller's contract gives `N` readable `i32` behind `a`, `b` and `m` and `N`
    // writable `i32` behind `f`. `j` runs over the multiples of 4 below `N`, and `f` is read only
    // when `k != 0`, when the caller guarantees it is initialized. `raw` and `center` need NEON
    // only.
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
            vst1q_s32(at, if k == 3 || k == 5 { center(sum) } else { sum });
        }
    }
}
/// # Safety
///
/// `a`, `b` and `m` must be valid for reads of `N = 256` `i32` each, and `f` for writes of `N`
/// `i32`; `f` must be initialized unless `k == 0`. This is the contract of `accumulate_native`. The
/// assembly wrapper `pretzel33_aux32_accumulate` calls this function with its own arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel33_aux32_accumulate_impl(
    a: *const i32,
    b: *const i32,
    m: *const i32,
    f: *mut i32,
    k: usize,
) {
    // SAFETY: the arguments are forwarded unchanged to `accumulate_native`, whose contract is the
    // one this function states. NEON is in the baseline of every target this crate builds for.
    unsafe {
        accumulate_native(a, b, m, f, k);
    }
}
/// # Safety
///
/// `a` must be valid for reads of `N = 256` `i32`; `b`, `m` and `f` for writes of `N` `i32` each;
/// all four must be aligned for `i32`. `f` must be initialized unless `k == 0`. The assembly
/// wrapper `pretzel33_aux32_factors` calls this function with its own arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel33_aux32_factors_impl(
    a: *const i32,
    b: *mut i32,
    m: *mut i32,
    f: *mut i32,
    k: usize,
) {
    // SAFETY: by the caller's contract the typed reads of `a[N - 1 - j]` and the typed writes of
    // `b[j]` and `m[j]` for `j < N` are in bounds and aligned. The asm template is an assembler
    // comment: it emits no instruction and names one register. `accumulate_native` then receives
    // the same four regions, with `b` and `m` initialized by the loop above.
    unsafe {
        let factor = if k < 3 { 121127281i64 } else { -244273348i64 };
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
/// # Safety
///
/// `f` must be valid and aligned for reads of `N = 256` `i32`, and `out` valid and aligned for
/// writes of `N` `i64`. The assembly wrapper `pretzel33_aux32_gram` calls this function with its
/// own arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel33_aux32_gram_impl(f: *const i32, out: *mut i64) {
    // SAFETY: `j < N`, and the caller's contract gives `N` readable `i32` behind `f` and `N`
    // writable `i64` behind `out`, both aligned.
    unsafe {
        for j in 0..N {
            *out.add(j) = *f.add(j) as i64;
        }
    }
}
/// # Safety
///
/// `f` and `y` must be valid and aligned for reads of `N = 256` `i32` each, and `out` valid and
/// aligned for writes of `N` `i32`. The assembly wrapper `pretzel33_aux32_lead` calls this function
/// with its own arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel33_aux32_lead_impl(f: *const i32, y: *const i32, out: *mut i32) {
    // SAFETY: `j < N`, and the caller's contract gives `N` readable `i32` behind `f` and behind `y`
    // and `N` writable `i32` behind `out`, all aligned.
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
    for trial in 0..16 {
        let mut a = Poly(core::array::from_fn(|i| {
            ((i * 377 + trial * 911) % 2711) as i32 - 1355
        }));
        let original = a.0;
        forward(&mut a.0);
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
        inverse(&mut a.0);
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

// SAFETY: contract of a routine of `reservoir-wrapper.S` (the rank-four file, assembled here under
// this crate's symbol prefix). It saves the frame, calls the function defined in this file under
// the same name with the suffix `_impl`, with the argument registers unchanged, then stores zero
// over a fixed range of stack below its own frame, clears the caller-saved registers and the flags,
// and returns no value. Its pointer contract is therefore the `# Safety` section of that function.
// It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions only.
unsafe extern "C" {
    fn pretzel33_aux32_forward(buf: *mut i32);
}
fn forward(buf: &mut [i32; N]) {
    // SAFETY: the wrapper forwards to `pretzel33_aux32_forward_impl`, which needs an exclusive,
    // aligned and initialized `[i32; N]`. `buf` is an exclusive reference to exactly that.
    unsafe {
        pretzel33_aux32_forward(buf.as_mut_ptr());
    }
}
/// # Safety
///
/// `buf` must be aligned for `i32`, valid for reads and writes of `N = 256` initialized `i32`, and
/// not accessed through any other pointer during the call: an exclusive reference to the array is
/// formed. The assembly wrapper `pretzel33_aux32_forward` calls this function with its own
/// argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel33_aux32_forward_impl(buf: *mut i32) {
    // SAFETY: the caller's contract is exactly what forming `&mut [i32; N]` from `buf` requires.
    // `forward_body` and `tables` are safe functions.
    unsafe {
        forward_body(&mut *(buf as *mut [i32; N]), tables());
    }
}

// SAFETY: contract of a routine of `reservoir-wrapper.S` (the rank-four file, assembled here under
// this crate's symbol prefix). It saves the frame, calls the function defined in this file under
// the same name with the suffix `_impl`, with the argument registers unchanged, then stores zero
// over a fixed range of stack below its own frame, clears the caller-saved registers and the flags,
// and returns no value. Its pointer contract is therefore the `# Safety` section of that function.
// It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions only.
unsafe extern "C" {
    fn pretzel33_aux32_inverse(buf: *mut i32);
}
fn inverse(buf: &mut [i32; N]) {
    // SAFETY: the wrapper forwards to `pretzel33_aux32_inverse_impl`, which needs an exclusive,
    // aligned and initialized `[i32; N]`. `buf` is an exclusive reference to exactly that.
    unsafe {
        pretzel33_aux32_inverse(buf.as_mut_ptr());
    }
}
/// # Safety
///
/// `buf` must be aligned for `i32`, valid for reads and writes of `N = 256` initialized `i32`, and
/// not accessed through any other pointer during the call: an exclusive reference to the array is
/// formed. The assembly wrapper `pretzel33_aux32_inverse` calls this function with its own
/// argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel33_aux32_inverse_impl(buf: *mut i32) {
    // SAFETY: the caller's contract is exactly what forming `&mut [i32; N]` from `buf` requires.
    // `inverse_body` and `tables` are safe functions.
    unsafe {
        inverse_body(&mut *(buf as *mut [i32; N]), tables());
    }
}
