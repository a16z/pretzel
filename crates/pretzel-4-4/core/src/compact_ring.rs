//! Exact canonical storage only: no modulus, transform ordering or map change.
use crate::params::{N, Q};
use crate::ring::Poly;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(8))]
pub(crate) struct CompactPoly(pub(crate) [i16; N]);
impl zeroize::Zeroize for CompactPoly {
    fn zeroize(&mut self) {
        const {
            assert!(core::mem::align_of::<CompactPoly>() >= 8);
            assert!(core::mem::size_of::<CompactPoly>() == 2 * N);
            assert!((2 * N) % 8 == 0);
        }
        // Exclusive self is explicitly eight-byte aligned, initialized, exactly
        // 2*N bytes with no padding. Erase that full extent with the
        // word helper; no pointer-alignment inference from a slice.
        // SAFETY: CompactPoly is repr(C, align(8)) over [i16; N], with N=256. Exclusive access through
        // &mut self permits ct_erase_words.S to zero its 2*N/8 aligned words; every resulting i16 value is
        // valid.
        unsafe {
            crate::ct_erase::erase_struct_words((self as *mut Self).cast::<u64>(), 2 * N / 8);
        }
    }
}
impl CompactPoly {
    pub(crate) const ZERO: Self = Self([0; N]);
    #[cfg(test)]
    pub(crate) fn from_canonical(p: &Poly) -> Self {
        debug_assert!(p.0.iter().all(|&x| (0..Q).contains(&x)));
        Self(core::array::from_fn(|i| p.0[i] as i16))
    }
    // Only canonical public-import coefficients enter this specialized route.
    #[cfg(any(test, not(target_arch = "aarch64")))]
    pub(crate) fn forward_canonical(&mut self) {
        debug_assert!(self.0.iter().all(|&x| x >= 0 && (x as i32) < Q));
        #[cfg(target_arch = "aarch64")]
        {
            crate::neon::ntt_compact_public_canonical(&mut self.0);
        }
    }
    pub(crate) fn forward_from_i32(&mut self, input: &[i32]) {
        assert_eq!(input.len(), N);
        for i in 0..N {
            self.0[i] = input[i].rem_euclid(Q) as i16;
        }
        #[cfg(target_arch = "aarch64")]
        {
            crate::neon::ntt_compact(&mut self.0);
        }
    }
}
pub(crate) fn dot_compact(a: &[CompactPoly; 5], b: &[CompactPoly; 5]) -> Poly {
    #[cfg(target_arch = "aarch64")]
    {
        return crate::neon::dot5_compact(a, b);
    }
    #[allow(unreachable_code)]
    {
        let mut out = Poly::ZERO;
        for i in 0..N {
            let mut sum = 0i32;
            for j in 0..5 {
                sum += (a[j].0[i] as i32) * (b[j].0[i] as i32);
            }
            out.0[i] = sum % Q;
        }
        out
    }
}
#[cfg(test)]
pub(crate) fn dot_mixed(a: &[CompactPoly; 5], b: &[Poly; 5]) -> Poly {
    #[cfg(target_arch = "aarch64")]
    {
        return crate::neon::dot5_mixed(a, b);
    }
    #[allow(unreachable_code)]
    {
        let mut out = Poly::ZERO;
        for i in 0..N {
            let mut sum = 0i32;
            for j in 0..5 {
                sum += (a[j].0[i] as i32) * b[j].0[i];
            }
            out.0[i] = sum % Q;
        }
        out
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_ntt_arbitrary_i32_and_dot_match_scalar() {
        let mut state = 671u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as i32
        };
        for trial in 0..128 {
            let input = core::array::from_fn(|i| match trial {
                0 => 0,
                1 => i32::MIN,
                2 => i32::MAX,
                3 => {
                    if i % 2 == 0 {
                        Q - 1
                    } else {
                        1 - Q
                    }
                }
                _ => next(),
            });
            let mut expected = Poly(input);
            expected.reduce();
            crate::ring::ntt_scalar(&mut expected);
            let mut actual = CompactPoly::ZERO;
            actual.forward_from_i32(&input);
            assert_eq!(actual, CompactPoly::from_canonical(&expected));
            let a: [Poly; 5] =
                core::array::from_fn(|_| Poly(core::array::from_fn(|_| next().rem_euclid(Q))));
            let b: [Poly; 5] =
                core::array::from_fn(|_| Poly(core::array::from_fn(|_| next().rem_euclid(Q))));
            let ac = a.map(|x| CompactPoly::from_canonical(&x));
            let bc = b.map(|x| CompactPoly::from_canonical(&x));
            let want = Poly(core::array::from_fn(|i| {
                let mut s = 0i64;
                for j in 0..5 {
                    s += a[j].0[i] as i64 * b[j].0[i] as i64;
                }
                (s % Q as i64) as i32
            }));
            assert_eq!(dot_compact(&ac, &bc), want);
            assert_eq!(dot_mixed(&ac, &b), want);
        }
        let max = [CompactPoly([Q as i16 - 1; N]); 5];
        let wide = [Poly([Q - 1; N]); 5];
        assert_eq!(dot_compact(&max, &max), Poly([5; N]));
        assert_eq!(dot_mixed(&max, &wide), Poly([5; N]));
    }
}

#[cfg(any(test, not(all(target_arch = "aarch64", target_endian = "little"))))]
pub(crate) fn pointwise_compact(a: &CompactPoly, b: &CompactPoly) -> Poly {
    #[cfg(target_arch = "aarch64")]
    {
        return crate::neon::pointwise_compact(a, b);
    }
    #[allow(unreachable_code)]
    {
        let mut out = Poly::ZERO;
        for i in 0..N {
            out.0[i] = ((a.0[i] as i32) * (b.0[i] as i32)) % Q;
        }
        out
    }
}
#[cfg(test)]
mod product_tests {
    use super::*;
    #[test]
    fn compact_products_match_wide() {
        for trial in 0..256 {
            let a = Poly(core::array::from_fn(|i| {
                ((i * 17239 + trial * 3781) % Q as usize) as i32
            }));
            let b = Poly(core::array::from_fn(|i| {
                ((i * 58391 + trial * 27749) % Q as usize) as i32
            }));
            let ac = CompactPoly::from_canonical(&a);
            let bc = CompactPoly::from_canonical(&b);
            let expected = Poly(core::array::from_fn(|i| {
                ((a.0[i] as i64 * b.0[i] as i64) % Q as i64) as i32
            }));
            assert_eq!(pointwise_compact(&ac, &bc), expected);
        }
        let m = CompactPoly([Q as i16 - 1; N]);
        assert_eq!(pointwise_compact(&m, &m), Poly([1; N]));
    }
}

#[cfg(test)]
mod aligned_erase_checks {
    use super::*;
    #[test]
    fn whole_compact_extent_and_neighbor_canaries() {
        #[repr(C, align(8))]
        struct Framed {
            before: [u64; 2],
            value: CompactPoly,
            after: [u64; 2],
        }
        for trial in 0..256 {
            let mut f = Framed {
                before: [0xa137ee1959d16f37; 2],
                value: CompactPoly(core::array::from_fn(|i| (i * 173 + trial * 379) as i16)),
                after: [0x2eb819c911f15d7b; 2],
            };
            zeroize::Zeroize::zeroize(&mut f.value);
            assert!(f.value.0.iter().all(|&x| x == 0));
            assert_eq!(f.before, [0xa137ee1959d16f37; 2]);
            assert_eq!(f.after, [0x2eb819c911f15d7b; 2]);
        }
    }
}

pub(crate) fn dot_compact_into(a: &[CompactPoly; 5], b: &[CompactPoly; 5], out: &mut Poly) {
    #[cfg(target_arch = "aarch64")]
    {
        crate::neon::dot5_compact_into(a, b, out);
        return;
    }
    #[allow(unreachable_code)]
    {
        for i in 0..N {
            let mut sum = 0i32;
            for j in 0..5 {
                sum += (a[j].0[i] as i32) * (b[j].0[i] as i32);
            }
            out.0[i] = sum % Q;
        }
    }
}

#[cfg(test)]
pub(crate) fn dot_mixed_into(a: &[CompactPoly; 5], b: &[Poly; 5], out: &mut Poly) {
    #[cfg(target_arch = "aarch64")]
    {
        crate::neon::dot5_mixed_into(a, b, out);
        return;
    }
    #[allow(unreachable_code)]
    {
        for i in 0..N {
            let mut sum = 0i32;
            for j in 0..5 {
                sum += (a[j].0[i] as i32) * b[j].0[i];
            }
            out.0[i] = sum % Q;
        }
    }
}

#[cfg(test)]
mod caller_owned_dot_tests {
    use super::*;
    #[repr(C)]
    struct Guard {
        before: [u64; 8],
        row: Poly,
        after: [u64; 8],
    }
    #[test]
    fn direct_rows_match_return_and_scalar_oracles_with_canaries() {
        let mut state = 314u64;
        for trial in 0..128 {
            let mut next = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                ((state >> 32) % Q as u64) as i32
            };
            let a: [Poly; 5] = core::array::from_fn(|_| {
                Poly(core::array::from_fn(|_| {
                    if trial == 0 {
                        0
                    } else if trial == 1 {
                        Q - 1
                    } else {
                        next()
                    }
                }))
            });
            let b: [Poly; 5] = core::array::from_fn(|_| {
                Poly(core::array::from_fn(|_| {
                    if trial == 0 || trial == 1 {
                        Q - 1
                    } else {
                        next()
                    }
                }))
            });
            let ac = a.map(|v| CompactPoly::from_canonical(&v));
            let bc = b.map(|v| CompactPoly::from_canonical(&v));
            let scalar = Poly(core::array::from_fn(|i| {
                let mut n = 0i64;
                for c in 0..5 {
                    n += a[c].0[i] as i64 * b[c].0[i] as i64;
                }
                (n % Q as i64) as i32
            }));
            let mut out = Guard {
                before: [0x314e; 8],
                row: Poly([i32::MIN; N]),
                after: [0x390a; 8],
            };
            dot_compact_into(&ac, &bc, &mut out.row);
            assert_eq!(out.row, scalar);
            assert_eq!(out.row, dot_compact(&ac, &bc));
            out.row.0.fill(i32::MAX);
            dot_mixed_into(&ac, &b, &mut out.row);
            assert_eq!(out.row, scalar);
            assert_eq!(out.row, dot_mixed(&ac, &b));
            assert_eq!(out.before, [0x314e; 8]);
            assert_eq!(out.after, [0x390a; 8]);
        }
    }
}
