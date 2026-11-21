//! Negacyclic ring `Z_q[X]/(X^256 + 1)` with q = 7681 (fully split: q = 1 mod 512).

use crate::params::{N, Q};
use std::sync::OnceLock;

pub type Coeffs = [i32; N];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Poly(pub Coeffs);

impl zeroize::Zeroize for Poly {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Poly {
    pub const ZERO: Poly = Poly([0; N]);

    /// Reduce all coefficients to [0, q).
    pub fn reduce(&mut self) {
        for c in self.0.iter_mut() {
            *c = c.rem_euclid(Q);
        }
    }

    pub fn add(&self, o: &Poly) -> Poly {
        let mut r = Poly::ZERO;
        for i in 0..N {
            r.0[i] = (self.0[i] + o.0[i]).rem_euclid(Q);
        }
        r
    }

    /// Sum of two canonical polynomials, canonical; one conditional
    /// subtraction instead of a general remainder. Debug-checked inputs.
    pub fn add_canonical(&self, o: &Poly) -> Poly {
        let mut r = Poly::ZERO;
        for i in 0..N {
            debug_assert!((0..Q).contains(&self.0[i]) && (0..Q).contains(&o.0[i]));
            let x = self.0[i] + o.0[i];
            r.0[i] = x - Q * i32::from(x >= Q);
        }
        r
    }

    pub fn sub(&self, o: &Poly) -> Poly {
        let mut r = Poly::ZERO;
        for i in 0..N {
            r.0[i] = (self.0[i] - o.0[i]).rem_euclid(Q);
        }
        r
    }
}

struct NttTables {
    zetas: [i32; N],
    inv_zetas: [i32; N],
    n_inv: i32,
}

static TABLES: OnceLock<NttTables> = OnceLock::new();

fn pow_mod(mut b: i64, mut e: i64, m: i64) -> i64 {
    let mut r = 1i64;
    b %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % m;
        }
        b = b * b % m;
        e >>= 1;
    }
    r
}

fn bitrev8(x: usize) -> usize {
    let mut r = 0;
    for i in 0..8 {
        r |= ((x >> i) & 1) << (7 - i);
    }
    r
}

/// Read-only accessor to the shared NTT twiddle tables (for the NEON path).
#[cfg(target_arch = "aarch64")]
pub(crate) fn ntt_twiddles() -> (&'static [i32; N], &'static [i32; N], i32) {
    let t = tables();
    (&t.zetas, &t.inv_zetas, t.n_inv)
}

fn tables() -> &'static NttTables {
    TABLES.get_or_init(|| {
        let q = Q as i64;
        // find a generator of Z_q^* (q - 1 = 2^9 * 3 * 5)
        let mut g = 0i64;
        for cand in 2..q {
            if pow_mod(cand, (q - 1) / 2, q) != 1
                && pow_mod(cand, (q - 1) / 3, q) != 1
                && pow_mod(cand, (q - 1) / 5, q) != 1
            {
                g = cand;
                break;
            }
        }
        assert!(g != 0);
        let psi = pow_mod(g, (q - 1) / 512, q); // primitive 512th root
        let psi_inv = pow_mod(psi, q - 2, q);
        let _ = psi_inv;
        let mut zetas = [0i32; N];
        let mut inv_zetas = [0i32; N];
        for i in 0..N {
            zetas[i] = pow_mod(psi, bitrev8(i) as i64, q) as i32;
            // inverse butterflies use the negated forward zetas in reverse order
            inv_zetas[i] = ((q - zetas[i] as i64) % q) as i32;
        }
        let n_inv = pow_mod(N as i64, q - 2, q) as i32;
        NttTables {
            zetas,
            inv_zetas,
            n_inv,
        }
    })
}

// Barrett reduction for products of two values in [0, Q): with
// BM = floor(2^43/Q), q_est = (x*BM)>>43 is floor(x/Q) or floor(x/Q)-1 for
// every x < 2^43 (and x*BM < 2^64 holds for x < 2^33; product inputs give
// x < 2^26, so the u64 arithmetic cannot overflow). One conditional
// subtraction lands the remainder in [0, Q). Exact drop-in for `%`.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
const BARRETT_MUL: u64 = (1u64 << 43) / (Q as u64);

#[inline]
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn barrett_reduce(x: u64) -> i32 {
    debug_assert!(x < 1 << 26);
    let q_est = (x * BARRETT_MUL) >> 43;
    let mut r = x - q_est * Q as u64;
    // Masked conditional subtraction (r < 2q, so r - q in i64 range).
    {
        r -= (Q as u64) & crate::ct::opaque_mask(!crate::ct::ct_lt_u64(r, Q as u64));
    }
    debug_assert!(r < Q as u64);
    r as i32
}

/// Canonical residue of x in [0, 2q): one conditional subtraction, masked
/// so the scalar transforms carry no value-dependent branch.
#[inline(always)]
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn csub_q(x: i32) -> i32 {
    debug_assert!((0..2 * Q).contains(&x));
    {
        let ge = crate::ct::opaque_mask(!crate::ct::ct_lt_u64(x as u64, Q as u64)) as u32;
        (x as u32).wrapping_sub(ge & Q as u32) as i32
    }
}

#[inline]
fn mul_mod(a: i32, b: i32) -> i32 {
    debug_assert!((0..Q).contains(&a) && (0..Q).contains(&b));
    barrett_reduce(a as u64 * b as u64)
}

/// Forward NTT in place (Cooley-Tukey, coefficients end in bit-reversed slot order).
pub fn ntt(p: &mut Poly) {
    #[cfg(target_arch = "aarch64")]
    {
        crate::neon::ntt(p);
        return;
    }
}

/// Scalar forward NTT; also the equality reference for the NEON path.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub(crate) fn ntt_scalar(p: &mut Poly) {
    let t = tables();
    let a = &mut p.0;
    let mut k = 1usize;
    let mut len = N / 2;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            let zeta = t.zetas[k];
            k += 1;
            for j in start..start + len {
                // inputs stay in [0, Q); +Q / conditional-subtract replaces rem_euclid
                let tv = mul_mod(zeta, a[j + len]);
                let x = csub_q(a[j] - tv + Q);
                let y = csub_q(a[j] + tv);
                a[j + len] = x;
                a[j] = y;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

/// Inverse NTT in place (Gentleman-Sande).
pub fn intt(p: &mut Poly) {
    #[cfg(target_arch = "aarch64")]
    {
        crate::neon::intt(p);
        return;
    }
}

/// Scalar inverse NTT; also the equality reference for the NEON path.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub(crate) fn intt_scalar(p: &mut Poly) {
    let t = tables();
    let a = &mut p.0;
    let mut k = N - 1;
    let mut len = 1usize;
    while len < N {
        let mut start = 0;
        while start < N {
            let zeta = t.inv_zetas[k];
            k -= 1;
            for j in start..start + len {
                let u = a[j];
                let v = a[j + len];
                let x = csub_q(u + v);
                let y = csub_q(u - v + Q);
                a[j] = x;
                a[j + len] = mul_mod(zeta, y);
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for c in a.iter_mut() {
        *c = mul_mod(*c, t.n_inv);
    }
}

/// Pointwise product of two polynomials already in NTT form.
pub fn pointwise(a: &Poly, b: &Poly) -> Poly {
    #[cfg(target_arch = "aarch64")]
    {
        return crate::neon::pointwise(a, b);
    }
}

/// `acc += a * b` coefficient-wise for canonical NTT-form inputs, in place.
/// For a secret product: no polynomial-sized value leaves `acc`, so nothing
/// secret passes through a by-value temporary or a return slot.
pub(crate) fn add_pointwise_assign(acc: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        acc.0[i] = (acc.0[i] + mul_mod(a.0[i], b.0[i])).rem_euclid(Q);
    }
}

/// Scalar pointwise product; also the equality reference for the NEON path.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub(crate) fn pointwise_scalar(a: &Poly, b: &Poly) -> Poly {
    let mut r = Poly::ZERO;
    for i in 0..N {
        r.0[i] = mul_mod(a.0[i], b.0[i]);
    }
    r
}

// Dedicated five-product contract, not the product-only Barrett domain above.
// For canonical inputs x <= 5*(Q-1)^2 = 294912000 < 2^29.
// With R=2^32 and V=floor(R/Q), floor(x*V/R) is floor(x/Q) or one
// less, because x/R < 1. The residual is in [0,2Q); one subtraction
// suffices. x*V < 2^49 fits u64 (and signed widening NEON lanes).

const DOT5_MAX: u32 = 5 * (Q as u32 - 1) * (Q as u32 - 1);

#[inline]
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn reduce_dot5(x: u32) -> i32 {
    debug_assert!(x <= DOT5_MAX);
    let v = (1u64 << 32) / Q as u64;
    let estimate = ((x as u64 * v) >> 32) as u32;
    let r = x - estimate * Q as u32;
    (r - u32::from(r >= Q as u32) * Q as u32) as i32
}

/// Sum five canonical pointwise products in the NTT slot order.
/// Internal, fixed arity: extending the arity requires a new range argument.
#[cfg(test)]
pub(crate) fn dot5(a: &[Poly; 5], b: &[Poly; 5]) -> Poly {
    debug_assert!(a
        .iter()
        .chain(b.iter())
        .all(|p| p.0.iter().all(|&x| (0..Q).contains(&x))));
    #[cfg(target_arch = "aarch64")]
    {
        return crate::neon::dot5(a, b);
    }
}

#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
fn dot5_scalar(a: &[Poly; 5], b: &[Poly; 5]) -> Poly {
    let mut result = Poly::ZERO;
    for i in 0..N {
        let mut sum = 0u32;
        for c in 0..5 {
            sum += a[c].0[i] as u32 * b[c].0[i] as u32;
        }
        result.0[i] = reduce_dot5(sum);
    }
    result
}

/// Schoolbook negacyclic multiplication (test reference).
#[cfg(test)]
pub fn schoolbook(a: &Poly, b: &Poly) -> Poly {
    let mut acc = [0i64; N];
    for i in 0..N {
        for j in 0..N {
            let k = i + j;
            let v = a.0[i] as i64 * b.0[j] as i64;
            if k < N {
                acc[k] += v;
            } else {
                acc[k - N] -= v;
            }
        }
    }
    let mut r = Poly::ZERO;
    for i in 0..N {
        r.0[i] = (acc[i].rem_euclid(Q as i64)) as i32;
    }
    r
}

/// Full negacyclic product via NTT.
pub fn mul(a: &Poly, b: &Poly) -> Poly {
    let mut fa = *a;
    let mut fb = *b;
    fa.reduce();
    fb.reduce();
    ntt(&mut fa);
    ntt(&mut fb);
    let mut r = pointwise(&fa, &fb);
    intt(&mut r);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo(seed: u64) -> Poly {
        let mut s = seed;
        let mut p = Poly::ZERO;
        for c in p.0.iter_mut() {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *c = ((s >> 33) % Q as u64) as i32;
        }
        p
    }

    #[test]
    fn ntt_roundtrip() {
        let p = pseudo(7);
        let mut q = p;
        ntt(&mut q);
        intt(&mut q);
        assert_eq!(p, q);
    }

    #[test]
    fn ntt_matches_schoolbook() {
        let a = pseudo(1);
        let b = pseudo(2);
        assert_eq!(mul(&a, &b), schoolbook(&a, &b));
    }

    #[test]
    fn negacyclic_wraparound() {
        // X^255 * X = -1
        let mut a = Poly::ZERO;
        a.0[255] = 1;
        let mut b = Poly::ZERO;
        b.0[1] = 1;
        let r = mul(&a, &b);
        let mut expect = Poly::ZERO;
        expect.0[0] = Q - 1;
        assert_eq!(r, expect);
    }

    #[test]
    fn dot5_reduction_boundaries() {
        for k in 0..=DOT5_MAX / Q as u32 {
            let multiple = k * Q as u32;
            for x in [multiple.saturating_sub(1), multiple, multiple + 1, DOT5_MAX] {
                if x <= DOT5_MAX {
                    assert_eq!(reduce_dot5(x), (x % Q as u32) as i32);
                }
            }
        }
    }

    #[test]
    fn dot5_matches_modulo_and_old_path() {
        let check = |a: &[Poly; 5], b: &[Poly; 5]| {
            let mut old = Poly::ZERO;
            for c in 0..5 {
                old = old.add(&pointwise_scalar(&a[c], &b[c]));
            }
            let expected = Poly(core::array::from_fn(|i| {
                let x: u64 = (0..5).map(|c| a[c].0[i] as u64 * b[c].0[i] as u64).sum();
                (x % Q as u64) as i32
            }));
            assert_eq!(old, expected);
            assert_eq!(dot5_scalar(a, b), expected);
            assert_eq!(dot5(a, b), expected);
        };
        for x in [0, 1, Q / 2, Q - 1] {
            for y in [0, 1, Q / 2, Q - 1] {
                check(&[Poly([x; N]); 5], &[Poly([y; N]); 5]);
            }
        }
        for c in 0..5 {
            for i in 0..N {
                let mut a = [Poly::ZERO; 5];
                a[c].0[i] = Q - 1;
                check(&a, &[Poly([Q - 1; N]); 5]);
            }
        }
        for seed in 1..=128 {
            check(
                &core::array::from_fn(|c| pseudo(seed * 11 + c as u64)),
                &core::array::from_fn(|c| pseudo(seed * 19 + c as u64)),
            );
        }
    }
}
