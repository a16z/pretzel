//! Negacyclic ring Z_q\[X\]/(X^256 + 1) with q = 7681 (fully split: q = 1 mod 512).

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

    /// Centered representatives in (-q/2, q/2].
    pub fn centered(&self) -> Poly {
        let mut r = *self;
        for c in r.0.iter_mut() {
            let v = c.rem_euclid(Q);
            *c = if v > Q / 2 { v - Q } else { v };
        }
        r
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
#[cfg(test)]
const BARRETT_MUL: u64 = (1u64 << 43) / (Q as u64);

#[inline]
#[cfg(test)]
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
#[cfg(test)]
fn csub_q(x: i32) -> i32 {
    debug_assert!((0..2 * Q).contains(&x));
    {
        let ge = crate::ct::opaque_mask(!crate::ct::ct_lt_u64(x as u64, Q as u64)) as u32;
        (x as u32).wrapping_sub(ge & Q as u32) as i32
    }
}

#[inline]
#[cfg(test)]
fn mul_mod(a: i32, b: i32) -> i32 {
    debug_assert!((0..Q).contains(&a) && (0..Q).contains(&b));
    barrett_reduce(a as u64 * b as u64)
}

/// Forward NTT in place (Cooley-Tukey, coefficients end in bit-reversed slot order).
pub fn ntt(p: &mut Poly) {
    {
        crate::neon::ntt(p);
    }
}

/// Scalar forward NTT; also the equality reference for the NEON path.
#[cfg(test)]
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
    {
        crate::neon::intt(p);
    }
}

/// Scalar inverse NTT; also the equality reference for the NEON path.
#[cfg(test)]
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
    {
        crate::neon::pointwise(a, b)
    }
}

/// `acc += a * b` coefficient-wise for canonical NTT-form inputs, in place.
/// For a secret product: no polynomial-sized value leaves `acc`, so nothing
/// secret passes through a by-value temporary or a return slot.
pub(crate) fn add_pointwise_assign(acc: &mut Poly, a: &Poly, b: &Poly) {
    crate::neon::add_pointwise_assign(acc, a, b);
}

/// Scalar pointwise product; also the equality reference for the NEON path.
#[cfg(test)]
pub(crate) fn pointwise_scalar(a: &Poly, b: &Poly) -> Poly {
    let mut r = Poly::ZERO;
    for i in 0..N {
        r.0[i] = mul_mod(a.0[i], b.0[i]);
    }
    r
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
}
