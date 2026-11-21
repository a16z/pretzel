//! Exact canonical storage only: no modulus, transform ordering or map change.
use crate::params::{N, Q};
use crate::ring::Poly;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(8))]
pub(crate) struct CompactPoly(pub(crate) [i16; N]);
impl zeroize::Zeroize for CompactPoly {
    // Keep the integer predicate and its signedness explicit.
    #[allow(clippy::manual_is_multiple_of)]
    fn zeroize(&mut self) {
        const {
            assert!(core::mem::align_of::<CompactPoly>() >= 8);
            assert!(core::mem::size_of::<CompactPoly>() == 2 * N);
            assert!((2 * N) % 8 == 0);
        }
        // Exclusive self is explicitly eight-byte aligned, initialized, exactly
        // 2*N bytes with no padding. Erase that full extent with the
        // word helper; no pointer-alignment inference from a slice.
        // SAFETY: CompactPoly is exclusively borrowed, aligned to eight bytes, and the assertions
        // above establish exactly 2*N initialized integer bytes. The word eraser writes 2*N/8 words.
        unsafe {
            crate::ct_erase::erase_struct_words((self as *mut Self).cast::<u64>(), 2 * N / 8);
        }
    }
}
impl CompactPoly {
    pub(crate) const ZERO: Self = Self([0; N]);
    #[allow(dead_code)]
    pub(crate) fn from_canonical(p: &Poly) -> Self {
        debug_assert!(p.0.iter().all(|&x| (0..Q).contains(&x)));
        Self(core::array::from_fn(|i| p.0[i] as i16))
    }
    // Only canonical public-import coefficients enter this specialized route.
    pub(crate) fn forward_canonical(&mut self) {
        debug_assert!(self.0.iter().all(|&x| x >= 0 && (x as i32) < Q));
        {
            crate::neon::ntt_compact_public_canonical(&mut self.0);
        }
    }
    pub(crate) fn forward_from_i32(&mut self, input: &[i32]) {
        assert_eq!(input.len(), N);
        crate::neon_canonical_residue::convert(input, &mut self.0);
        {
            crate::neon::ntt_compact(&mut self.0);
        }
    }
    pub(crate) fn forward_from_noncore_bounded(&mut self, input: &[i32]) {
        assert_eq!(input.len(), N);
        crate::noncore_bounded::convert(input, &mut self.0);
        {
            crate::neon::ntt_compact(&mut self.0);
        }
    }
}
pub(crate) fn dot_compact<const C: usize>(a: &[CompactPoly; C], b: &[CompactPoly; C]) -> Poly {
    const {
        assert!(C >= 4 && C <= 6);
    }

    crate::neon::dot5_compact(a, b)
}
#[allow(dead_code)]
pub(crate) fn dot_mixed<const C: usize>(a: &[CompactPoly; C], b: &[Poly; C]) -> Poly {
    const {
        assert!(C >= 4 && C <= 6);
    }

    crate::neon::dot5_mixed(a, b)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    // Keep the independent conversion oracle cases explicit.
    #[allow(clippy::if_same_then_else)]
    // Keep the integer predicate and its signedness explicit.
    #[allow(clippy::manual_is_multiple_of)]
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

#[allow(dead_code)]
pub(crate) fn pointwise_compact(a: &CompactPoly, b: &CompactPoly) -> Poly {
    crate::neon::pointwise_compact(a, b)
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

pub(crate) fn dot_compact_into<const C: usize>(
    a: &[CompactPoly; C],
    b: &[CompactPoly; C],
    out: &mut Poly,
) {
    const {
        assert!(C >= 4 && C <= 6);
    }

    crate::neon::dot5_compact_into(a, b, out);
}

#[allow(dead_code)]
pub(crate) fn dot_mixed_into<const C: usize>(a: &[CompactPoly; C], b: &[Poly; C], out: &mut Poly) {
    const {
        assert!(C >= 4 && C <= 6);
    }

    crate::neon::dot5_mixed_into(a, b, out);
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
    // Keep the independent conversion oracle cases explicit.
    #[allow(clippy::if_same_then_else)]
    // Keep the integer predicate and its signedness explicit.
    #[allow(clippy::manual_is_multiple_of)]
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
                    if trial == 0 {
                        Q - 1
                    } else if trial == 1 {
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

#[cfg(test)]
mod noncore_bounded_tests {
    use super::*;
    #[test]
    fn complete_bounded_domain_ntt_matches_generic() {
        for first in (1 - Q..Q).step_by(N) {
            let input = core::array::from_fn::<_, N, _>(|i| (first + i as i32).min(Q - 1));
            let mut old = CompactPoly::ZERO;
            let mut new = CompactPoly::ZERO;
            old.forward_from_i32(&input);
            new.forward_from_noncore_bounded(&input);
            assert_eq!(old, new);
        }
    }
}
