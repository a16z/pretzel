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
        && DIM == 2304
        && crate::params::PROPOSAL_W0 == 9216
        && crate::params::WS == 196
        && crate::params::WE == 121
        && crate::params::SHELL_HI <= 244553
);
// The bound below starts from 1355 = (2711 - 1) / 2, the largest value of the error table
// (2711 bounds, `ct_rarequeue.rs`). The transform takes the secret and error blocks only,
// and the secret table ends at 1064, so 1355 bounds every input of the transform.
// The last assertion is the condition for the weighted product to be recovered from its
// residue: its magnitude must stay below P / 2. It cannot be stated for the table values:
// at 1064 (secret) and 1355 (error) the worst case over all keys in the shell is 270955245,
// above P / 2. It is stated for the largest values the signer can hold. The signer samples
// through alias and tree tables built from the 192-bit prefixes of the table bounds: a
// value is produced only by a 192-bit draw strictly inside the cell between two consecutive
// prefixes, and a draw on a cell boundary aborts the attempt. That leaves at most 739
// (secret) and 937 (error) in an output, and 744 and 946 in an aborted attempt.
// 189281598 is the largest value of 196 * 744 * n_s + 121 * 946 * n_e over the numbers
// n_s, n_e <= 1024 of nonzero secret and error coefficients of a ternary key in the shell,
// 196 * n_s + 121 * n_e <= 244553 - 23716 = 220837; it is attained at n_s = 495, n_e = 1023.
// The four figures 739, 937, 744 and 946 are recomputed from the tables by
// `generators/check_sampler_bounds.py --check`, under the rule of the reference classifier
// (`Cdt::ct_classify`); that program also reads the two constants and the maximum below.
// The maximum itself is recomputed here at compile time.
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
};
const _: () = {
    const HELD_SEC: i64 = 744;
    const HELD_ERR: i64 = 946;
    let budget = (crate::params::SHELL_HI - crate::params::W0) as i64;
    let ws = crate::params::WS as i64;
    let we = crate::params::WE as i64;
    assert!(budget == 220837);
    let mut best = 0i64;
    let mut ns = 0i64;
    while ns <= 1024 && ws * ns <= budget {
        let rest = (budget - ws * ns) / we;
        let ne = if rest < 1024 { rest } else { 1024 };
        let value = ws * HELD_SEC * ns + we * HELD_ERR * ne;
        if value > best {
            best = value;
        }
        ns += 1;
    }
    assert!(best == 189281598);
    assert!(P > 2 * best);
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
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target (enforced at the crate root).
#[inline(always)]
unsafe fn raw(a: int32x4_t, b: int32x4_t, m: int32x4_t) -> int32x4_t {
    // SAFETY: The caller supplies NEON availability; these operations use initialized
    // vector values and checked Rust indexing, with no raw memory access.
    unsafe { vmlsq_n_s32(vmulq_s32(a, b), vqrdmulhq_s32(a, m), P as i32) }
}
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target (enforced at the crate root).
#[inline(always)]
unsafe fn center(a: int32x4_t) -> int32x4_t {
    // SAFETY: The caller supplies NEON availability; these operations use initialized
    // vector values and checked Rust indexing, with no raw memory access.
    unsafe { vmlsq_n_s32(a, vrshrq_n_s32::<28>(vqdmulhq_n_s32(a, R)), P as i32) }
}
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target (enforced at the crate root).
#[cfg(test)]
#[inline(always)]
unsafe fn center_all(buf: &mut [i32; N]) {
    // SAFETY: N is 256 and j advances by four, so each four-i32 load/store stays inside the
    // exclusive array; AArch64 NEON is available.
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
        // SAFETY: Poly has repr(C, align(8)); the adjacent assertion fixes its size to 1024 bytes.
        // Drop has exclusive access, and 128 u64 zero stores cover only valid integer storage via
        // ct_erase_words.S.
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
    // SAFETY: The exclusive buf holds N=256 i32 values. Four-lane spans in the first 64-element
    // stripes and each 64-element tile end at or before 256; table indexing is checked. The
    // supported AArch64 target provides NEON.
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
    // SAFETY: The exclusive buf holds N=256 i32 values. Four 64-element tiles and the
    // subsequent four-lane butterfly spans stay inside it; table indexing is checked. The
    // supported AArch64 target provides NEON.
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
    b: [[i32; N]; 8],
    m: [[i32; N]; 8],
}
impl Drop for Key {
    fn drop(&mut self) {
        self.b.zeroize();
        self.m.zeroize();
    }
}
const _: () = assert!(core::mem::size_of::<Key>() == 16384);
// SAFETY: contract of four routines of `reservoir-wrapper.S`. Each saves the frame, calls the
// function defined in this file
// under the same name with the suffix `_impl`, with the argument registers unchanged, then stores
// zero over a fixed range of stack below its own frame, clears the caller-saved registers and the
// flags, and returns no value. Its pointer contract is therefore the `# Safety` section of that
// function. It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions
// only.
unsafe extern "C" {
    fn pretzel44_aux32_factors(a: *const i32, b: *mut i32, m: *mut i32, f: *mut i32, k: usize);
    fn pretzel44_aux32_accumulate(
        a: *const i32,
        b: *const i32,
        m: *const i32,
        f: *mut i32,
        k: usize,
    );
    fn pretzel44_aux32_gram(f: *const i32, out: *mut i64);
    fn pretzel44_aux32_lead(f: *const i32, y: *const i32, out: *mut i32);
}
impl Key {
    pub(crate) fn empty() -> Self {
        Self {
            b: [[0; N]; 8],
            m: [[0; N]; 8],
        }
    }
    pub(crate) fn populate_gram(&mut self, s: &Vector, gram: &mut [i64; N]) {
        let mut f = Poly([0; N]);
        for k in 0..8 {
            let mut a = Poly([0; N]);
            a.0.copy_from_slice(&s[(k + 1) * N..(k + 2) * N]);
            forward(&mut a.0, tables());
            // SAFETY: k<8 indexes the fixed key arrays. a, b[k], m[k] and f each hold N=256 i32 values
            // and are disjoint; f starts initialized. reservoir-wrapper.S forwards these pointers to
            // pretzel44_aux32_factors_impl in this file.
            unsafe {
                pretzel44_aux32_factors(
                    a.0.as_ptr(),
                    self.b[k].as_mut_ptr(),
                    self.m[k].as_mut_ptr(),
                    f.0.as_mut_ptr(),
                    k,
                );
            }
        }
        inverse(&mut f.0, tables());
        // SAFETY: f contains N=256 initialized i32 values and gram is a disjoint exclusive [i64;
        // N]. reservoir-wrapper.S forwards these exact extents to pretzel44_aux32_gram_impl.
        unsafe {
            pretzel44_aux32_gram(f.0.as_ptr(), gram.as_mut_ptr());
        }
    }
    #[inline(never)]
    pub(crate) fn write_initial(&self, y: &Vector, out: &mut [i32; N]) {
        let mut f = Poly([0; N]);
        for k in 0..8 {
            let mut a = Poly([0; N]);
            a.0.copy_from_slice(&y[(k + 1) * N..(k + 2) * N]);
            forward(&mut a.0, tables());
            // SAFETY: k<8 indexes initialized N=256-element factors; a and f are disjoint initialized
            // N-i32 arrays. reservoir-wrapper.S forwards the pointers to pretzel44_aux32_accumulate_impl;
            // k==0 initializes the sum.
            unsafe {
                pretzel44_aux32_accumulate(
                    a.0.as_ptr(),
                    self.b[k].as_ptr(),
                    self.m[k].as_ptr(),
                    f.0.as_mut_ptr(),
                    k,
                );
            }
        }
        inverse(&mut f.0, tables());
        // SAFETY: f has N=256 initialized i32 values, y has at least N, and out is a disjoint
        // exclusive [i32; N]. reservoir-wrapper.S forwards them to pretzel44_aux32_lead_impl, which
        // accesses only 0..N.
        unsafe {
            pretzel44_aux32_lead(f.0.as_ptr(), y.as_ptr(), out.as_mut_ptr());
        }
    }
}
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target (enforced at the crate root).
/// a, b and m must each point to N initialized i32 values; f to N exclusively writable i32
/// values, initialized when k != 0. Inputs must not overlap f.
#[inline(always)]
unsafe fn accumulate_native(a: *const i32, b: *const i32, m: *const i32, f: *mut i32, k: usize) {
    // SAFETY: The caller provides N=256 elements for each pointer. j advances by four; f is
    // read only when the caller promises initialization. The inputs and output are disjoint and
    // the caller supplies NEON.
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
            vst1q_s32(at, if k == 3 || k == 7 { center(sum) } else { sum });
        }
    }
}
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target (enforced at the crate root).
/// a, b and m must each point to N initialized i32 values; f to N exclusively writable i32
/// values, initialized when k != 0. Inputs must not overlap f.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel44_aux32_accumulate_impl(
    a: *const i32,
    b: *const i32,
    m: *const i32,
    f: *mut i32,
    k: usize,
) {
    // SAFETY: The caller provides N=256 elements for each pointer. j advances by four; f is
    // read only when the caller promises initialization. The inputs and output are disjoint and
    // the caller supplies NEON.
    unsafe {
        accumulate_native(a, b, m, f, k);
    }
}
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target (enforced at the crate root).
/// a must read N initialized i32 values; b, m and f must be disjoint, exclusively writable
/// N-i32 regions, also disjoint from a. f must be initialized when k != 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel44_aux32_factors_impl(
    a: *const i32,
    b: *mut i32,
    m: *mut i32,
    f: *mut i32,
    k: usize,
) {
    // SAFETY: The caller supplies the N=256-element extents and disjoint outputs. j and N-1-j
    // stay below N; b and m are fully written before accumulate_native reads them. The
    // comment-only asm has no memory or flag effects.
    unsafe {
        let factor = if k < 4 { 121127281i64 } else { -244273348i64 };
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
/// f must point to N readable initialized i32 values and out to N disjoint, exclusively
/// writable i64 values, aligned for their types.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel44_aux32_gram_impl(f: *const i32, out: *mut i64) {
    // SAFETY: The caller supplies both N=256-element regions; j ranges over 0..N and each
    // output is written without reading its old contents.
    unsafe {
        for j in 0..N {
            *out.add(j) = *f.add(j) as i64;
        }
    }
}
/// # Safety
/// f and y must each point to N readable initialized i32 values and out to a disjoint,
/// exclusively writable N-i32 region, aligned for i32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel44_aux32_lead_impl(f: *const i32, y: *const i32, out: *mut i32) {
    // SAFETY: The caller supplies all N=256-element regions; j ranges over 0..N and each output
    // is written without reading its old contents.
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
    let t = tables();
    for trial in 0..16 {
        let mut a = Poly(core::array::from_fn(|i| {
            ((i * 377 + trial * 911) % 2711) as i32 - 1355
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

// SAFETY: contract of a routine of `reservoir-wrapper.S`. It saves the frame, calls the
// function defined in this file under
// the same name with the suffix `_impl`, with the argument registers unchanged, then stores zero
// over a fixed range of stack below its own frame, clears the caller-saved registers and the flags,
// and returns no value. Its pointer contract is therefore the `# Safety` section of that function.
// It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions only.
unsafe extern "C" {
    fn pretzel44_aux32_forward(buf: *mut i32);
}
fn forward(buf: &mut [i32; N], _t: &Tables) {
    // SAFETY: buf is an exclusive initialized [i32; N], N=256. reservoir-wrapper.S forwards the
    // pointer unchanged to the corresponding transform implementation in this file; AArch64
    // supplies NEON.
    unsafe {
        pretzel44_aux32_forward(buf.as_mut_ptr());
    }
}
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target (enforced at the crate root).
/// buf must point to an aligned, initialized [i32; N] with exclusive access for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel44_aux32_forward_impl(buf: *mut i32) {
    // SAFETY: The caller guarantees exactly the lifetime, alignment, initialization and
    // exclusive N=256-element extent required to form &mut [i32; N]. The selected AArch64
    // target provides NEON to the transform body.
    unsafe {
        forward_body(&mut *(buf as *mut [i32; N]), tables());
    }
}

// SAFETY: contract of a routine of `reservoir-wrapper.S`. It saves the frame, calls the
// function defined in this file under
// the same name with the suffix `_impl`, with the argument registers unchanged, then stores zero
// over a fixed range of stack below its own frame, clears the caller-saved registers and the flags,
// and returns no value. Its pointer contract is therefore the `# Safety` section of that function.
// It keeps no pointer, has no global state, and uses base AArch64 and NEON instructions only.
unsafe extern "C" {
    fn pretzel44_aux32_inverse(buf: *mut i32);
}
fn inverse(buf: &mut [i32; N], _t: &Tables) {
    // SAFETY: buf is an exclusive initialized [i32; N], N=256. reservoir-wrapper.S forwards the
    // pointer unchanged to the corresponding transform implementation in this file; AArch64
    // supplies NEON.
    unsafe {
        pretzel44_aux32_inverse(buf.as_mut_ptr());
    }
}
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target (enforced at the crate root).
/// buf must point to an aligned, initialized [i32; N] with exclusive access for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pretzel44_aux32_inverse_impl(buf: *mut i32) {
    // SAFETY: The caller guarantees exactly the lifetime, alignment, initialization and
    // exclusive N=256-element extent required to form &mut [i32; N]. The selected AArch64
    // target provides NEON to the transform body.
    unsafe {
        inverse_body(&mut *(buf as *mut [i32; N]), tables());
    }
}
