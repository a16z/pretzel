//! Q64.384 unsigned fixed-point interval arithmetic with directed rounding.
//!
//! A value is `limbs[0..7]` little-endian, worth `sum limbs[i] * 2^(64*i) / 2^384`,
//! so the representable range is `[0, 2^64)` with resolution `2^-384` (one ulp).
//! Every inexact operation exists in `_floor` and `_ceil` form; `Iv` combines
//! them into rigorous enclosures. Overflow of `add`, `mul_floor` and `mul_ceil`
//! is checked in debug builds only (a release build wraps); `sub` panics on
//! underflow in every build. The parameters keep all quantities far below `2^64`.

pub const LIMBS: usize = 7;
pub const FRAC_LIMBS: usize = 6; // 384 fraction bits

/// 2^-64, exactly representable.
pub const TWO_NEG64: f64 = 1.0 / 18446744073709551616.0;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Fx(pub [u64; LIMBS]);

impl zeroize::Zeroize for Fx {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl Fx {
    pub const ZERO: Fx = Fx([0; LIMBS]);
    /// 1.0
    pub const ONE: Fx = {
        let mut l = [0u64; LIMBS];
        l[FRAC_LIMBS] = 1;
        Fx(l)
    };
    /// One ulp = 2^-384.
    pub const ULP: Fx = {
        let mut l = [0u64; LIMBS];
        l[0] = 1;
        Fx(l)
    };

    pub fn from_int(v: u64) -> Fx {
        let mut l = [0u64; LIMBS];
        l[FRAC_LIMBS] = v;
        Fx(l)
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().fold(0u64, |acc, &x| acc | x) == 0
    }

    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn cmp_fx(&self, o: &Fx) -> core::cmp::Ordering {
        for i in (0..LIMBS).rev() {
            if self.0[i] != o.0[i] {
                return self.0[i].cmp(&o.0[i]);
            }
        }
        core::cmp::Ordering::Equal
    }

    /// Nearest-f64 approximation from the integer limb and the top two
    /// fraction limbs; absolute error < 2^-105 + one f64 rounding (2^-53 rel).
    pub fn to_f64(&self) -> f64 {
        self.0[FRAC_LIMBS] as f64
            + self.0[FRAC_LIMBS - 1] as f64 * TWO_NEG64
            + self.0[FRAC_LIMBS - 2] as f64 * TWO_NEG64 * TWO_NEG64
    }

    pub fn lt(&self, o: &Fx) -> bool {
        self.cmp_fx(o) == core::cmp::Ordering::Less
    }
    pub fn le(&self, o: &Fx) -> bool {
        self.cmp_fx(o) != core::cmp::Ordering::Greater
    }

    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    pub fn add(&self, o: &Fx) -> Fx {
        let mut r = [0u64; LIMBS];
        let mut carry = 0u128;
        for i in 0..LIMBS {
            let s = self.0[i] as u128 + o.0[i] as u128 + carry;
            r[i] = s as u64;
            carry = s >> 64;
        }
        // Fixed-outcome range check on secret operands (interval endpoints of the
        // signing filter), performed in debug builds only.
        debug_assert_eq!(carry, 0, "Fx add overflow");
        Fx(r)
    }

    /// self - o; panics on underflow.
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    pub fn sub(&self, o: &Fx) -> Fx {
        let mut r = [0u64; LIMBS];
        let mut borrow = 0i128;
        for i in 0..LIMBS {
            let d = self.0[i] as i128 - o.0[i] as i128 - borrow;
            r[i] = d as u64;
            borrow = (d >> 127) & 1;
        }
        assert_eq!(borrow, 0, "Fx sub underflow");
        Fx(r)
    }

    /// Saturating subtraction (clamps at zero).
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    pub fn sub_sat(&self, o: &Fx) -> Fx {
        {
            let mut r = [0u64; LIMBS];
            let mut borrow = 0i128;
            for i in 0..LIMBS {
                let d = self.0[i] as i128 - o.0[i] as i128 - borrow;
                r[i] = d as u64;
                borrow = (d >> 127) & 1;
            }
            let keep = crate::ct::opaque_mask((borrow as u64).wrapping_sub(1));
            for limb in &mut r {
                *limb &= keep;
            }
            return Fx(r);
        }
    }

    fn mul_raw(&self, o: &Fx) -> ([u64; 2 * LIMBS], bool) {
        {
            self.mul_raw_comba(o)
        }
    }

    /// Exact column product. Each column adds at most seven 128-bit products
    /// and the preceding carry; the overflow counter fits three bits. Public
    /// constant indices expose all carries to the compiler without zero skips.
    fn mul_raw_comba(&self, o: &Fx) -> ([u64; 2 * LIMBS], bool) {
        let mut acc = [0u64; 2 * LIMBS];
        let mut carry = 0u128;
        macro_rules! column {($k:expr;$(($i:expr,$j:expr)),+)=>{{
            let mut sum=carry;let mut high=0u64;
            $(let (next,overflow)=sum.overflowing_add(self.0[$i] as u128*o.0[$j] as u128);sum=next;high+=u64::from(overflow);)+
            acc[$k]=sum as u64;carry=(sum>>64)|((high as u128)<<64);
        }}}
        column!(0;(0,0));
        column!(1;(0,1),(1,0));
        column!(2;(0,2),(1,1),(2,0));
        column!(3;(0,3),(1,2),(2,1),(3,0));
        column!(4;(0,4),(1,3),(2,2),(3,1),(4,0));
        column!(5;(0,5),(1,4),(2,3),(3,2),(4,1),(5,0));
        column!(6;(0,6),(1,5),(2,4),(3,3),(4,2),(5,1),(6,0));
        column!(7;(1,6),(2,5),(3,4),(4,3),(5,2),(6,1));
        column!(8;(2,6),(3,5),(4,4),(5,3),(6,2));
        column!(9;(3,6),(4,5),(5,4),(6,3));
        column!(10;(4,6),(5,5),(6,4));
        column!(11;(5,6),(6,5));
        column!(12;(6,6));
        acc[13] = carry as u64;
        (acc, acc[..FRAC_LIMBS].iter().fold(0, |a, &x| a | x) != 0)
    }

    /// Fixed 49-product schedule. No zero-row skip, carry loop or short-circuit
    /// discarded-bit scan.
    #[allow(dead_code)]
    fn mul_raw_fixed_work(&self, o: &Fx) -> ([u64; 2 * LIMBS], bool) {
        let mut acc = [0u64; 2 * LIMBS];
        for i in 0..LIMBS {
            let mut carry = 0u128;
            for j in 0..LIMBS {
                let t = acc[i + j] as u128 + self.0[i] as u128 * o.0[j] as u128 + carry;
                acc[i + j] = t as u64;
                carry = t >> 64;
            }
            // Earlier rows never touch this word; the final carry is assigned.
            acc[i + LIMBS] = carry as u64;
        }
        let low = acc[..FRAC_LIMBS].iter().fold(0u64, |a, &x| a | x) != 0;
        (acc, low)
    }

    #[allow(dead_code)]
    fn mul_raw_reference(&self, o: &Fx) -> ([u64; 2 * LIMBS], bool) {
        let mut acc = [0u64; 2 * LIMBS];
        for i in 0..LIMBS {
            if self.0[i] == 0 {
                continue;
            }
            let mut carry = 0u128;
            for j in 0..LIMBS {
                let t = acc[i + j] as u128 + self.0[i] as u128 * o.0[j] as u128 + carry;
                acc[i + j] = t as u64;
                carry = t >> 64;
            }
            let mut k = i + LIMBS;
            while carry > 0 {
                let t = acc[k] as u128 + carry;
                acc[k] = t as u64;
                carry = t >> 64;
                k += 1;
            }
        }
        let low_nonzero = acc[..FRAC_LIMBS].iter().any(|&x| x != 0);
        (acc, low_nonzero)
    }

    pub fn mul_floor(&self, o: &Fx) -> Fx {
        let (acc, _) = self.mul_raw(o);
        // Fixed-outcome range check on secret operands (interval products of the
        // signing filter), performed in debug builds only.
        debug_assert_eq!(acc[FRAC_LIMBS + LIMBS], 0, "Fx mul overflow");
        let mut r = [0u64; LIMBS];
        r.copy_from_slice(&acc[FRAC_LIMBS..FRAC_LIMBS + LIMBS]);
        Fx(r)
    }

    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn mul_ceil(&self, o: &Fx) -> Fx {
        let (acc, low) = self.mul_raw(o);
        // Fixed-outcome range check on secret operands (interval products of the
        // signing filter), performed in debug builds only.
        debug_assert_eq!(acc[FRAC_LIMBS + LIMBS], 0, "Fx mul overflow");
        let mut r = [0u64; LIMBS];
        r.copy_from_slice(&acc[FRAC_LIMBS..FRAC_LIMBS + LIMBS]);
        let f = Fx(r);
        {
            let mut increment = Fx::ZERO;
            increment.0[0] = u64::from(low);
            return f.add(&increment);
        }
    }

    /// Divide by a small integer, floor rounding.
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    pub fn div_u64_floor(&self, d: u64) -> Fx {
        let mut r = [0u64; LIMBS];
        let mut rem = 0u128;
        for i in (0..LIMBS).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            r[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        Fx(r)
    }

    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    pub fn div_u64_ceil(&self, d: u64) -> Fx {
        let mut r = [0u64; LIMBS];
        let mut rem = 0u128;
        for i in (0..LIMBS).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            r[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        let f = Fx(r);
        if rem != 0 {
            f.add(&Fx::ULP)
        } else {
            f
        }
    }

    /// Full division self / d, floor rounding, by 448-bit restoring long division.
    /// Slow; init-time only.
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    pub fn div_fx_floor(&self, d: &Fx) -> Fx {
        assert!(!d.is_zero(), "division by zero");
        // numerator = self << 384, as 14 limbs
        let mut num = [0u64; 2 * LIMBS];
        num[FRAC_LIMBS..FRAC_LIMBS + LIMBS].copy_from_slice(&self.0);
        // remainder register (8 limbs is enough: rem < d < 2^448)
        let mut rem = [0u64; LIMBS + 1];
        let mut quo = [0u64; 2 * LIMBS];
        let total_bits = 64 * 2 * LIMBS;
        for bit in (0..total_bits).rev() {
            // rem = rem << 1 | numerator bit
            let mut carry = (num[bit / 64] >> (bit % 64)) & 1;
            for limb in rem.iter_mut() {
                let new_carry = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = new_carry;
            }
            // if rem >= d { rem -= d; quo bit = 1 }
            let mut ge = true;
            if rem[LIMBS] == 0 {
                for i in (0..LIMBS).rev() {
                    if rem[i] != d.0[i] {
                        ge = rem[i] > d.0[i];
                        break;
                    }
                }
            }
            if ge {
                let mut borrow = 0i128;
                for i in 0..LIMBS {
                    let df = rem[i] as i128 - d.0[i] as i128 - borrow;
                    if df < 0 {
                        rem[i] = (df + (1i128 << 64)) as u64;
                        borrow = 1;
                    } else {
                        rem[i] = df as u64;
                        borrow = 0;
                    }
                }
                rem[LIMBS] -= borrow as u64;
                quo[bit / 64] |= 1 << (bit % 64);
            }
        }
        // quotient must fit in Q64.384
        for &l in &quo[LIMBS..] {
            assert_eq!(l, 0, "Fx div overflow");
        }
        let mut r = [0u64; LIMBS];
        r.copy_from_slice(&quo[..LIMBS]);
        Fx(r)
    }

    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn div_fx_ceil(&self, d: &Fx) -> Fx {
        let f = self.div_fx_floor(d);
        // exact iff f*d == self
        let back = f.mul_floor(d);
        if back.cmp_fx(self) == core::cmp::Ordering::Equal && !f.mul_ceil(d).lt(self) {
            // f*d == self exactly (mul_floor equality and no dropped low bits is
            // implied by mul_ceil(d) == mul_floor(d) == self)
            if f.mul_ceil(d).cmp_fx(self) == core::cmp::Ordering::Equal {
                return f;
            }
        }
        f.add(&Fx::ULP)
    }

    /// Position of the highest set bit (0-based over the 448-bit word), or None if zero.
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn top_bit(&self) -> Option<usize> {
        for i in (0..LIMBS).rev() {
            if self.0[i] != 0 {
                return Some(64 * i + 63 - self.0[i].leading_zeros() as usize);
            }
        }
        None
    }
}

/// Closed interval [lo, hi] enclosing an exact real.
#[derive(Clone, Copy, Debug)]
pub struct Iv {
    pub lo: Fx,
    pub hi: Fx,
}

impl Iv {
    pub const ZERO: Iv = Iv {
        lo: Fx::ZERO,
        hi: Fx::ZERO,
    };

    pub fn exact(v: Fx) -> Iv {
        Iv { lo: v, hi: v }
    }

    pub fn valid(&self) -> bool {
        self.lo.le(&self.hi)
    }

    pub fn add(&self, o: &Iv) -> Iv {
        Iv {
            lo: self.lo.add(&o.lo),
            hi: self.hi.add(&o.hi),
        }
    }

    /// self - o with outward rounding; saturates at zero (used only where the
    /// true value is known nonnegative).
    pub fn sub_sat(&self, o: &Iv) -> Iv {
        Iv {
            lo: self.lo.sub_sat(&o.hi),
            hi: self.hi.sub_sat(&o.lo),
        }
    }

    pub fn mul(&self, o: &Iv) -> Iv {
        Iv {
            lo: self.lo.mul_floor(&o.lo),
            hi: self.hi.mul_ceil(&o.hi),
        }
    }

    pub fn div_u64(&self, d: u64) -> Iv {
        Iv {
            lo: self.lo.div_u64_floor(d),
            hi: self.hi.div_u64_ceil(d),
        }
    }

    /// Reciprocal 1/self (self > 0), init-time.
    pub fn recip(&self) -> Iv {
        Iv {
            lo: Fx::ONE.div_fx_floor(&self.hi),
            hi: Fx::ONE.div_fx_ceil(&self.lo),
        }
    }

    pub fn square(&self) -> Iv {
        self.mul(self)
    }

    // Preserve the fixed-width value construction.
    #[allow(clippy::init_numbered_fields)]
    pub fn width_le_ulps(&self, k: u64) -> bool {
        let mut d = self.hi;
        d = d.sub_sat(&self.lo);
        d.le(&Fx {
            0: {
                let mut l = [0u64; LIMBS];
                l[0] = k;
                l
            },
        }
        .clone())
    }
}

/// Parse a Q64.384 hex string into Fx.
// Keep the explicit lane order and index schedule of the kernel and its oracle.
#[allow(clippy::needless_range_loop)]
pub fn fx_from_hex(s: &str) -> Fx {
    let s = s.trim_start_matches("0x");
    assert_eq!(s.len(), 112, "expect 448-bit hex");
    let mut l = [0u64; LIMBS];
    for i in 0..LIMBS {
        let hi = s.len() - 16 * (i + 1);
        l[i] = u64::from_str_radix(&s[hi..hi + 16], 16).unwrap();
    }
    Fx(l)
}

#[cfg(test)]
mod tests {
    #[test]
    fn saturating_subtraction_matches_base32_oracle() {
        use super::*;
        let mut state = 0x168faa40c23795abu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for case in 0..10000 {
            let mut a = Fx(core::array::from_fn(|_| next()));
            let mut b = Fx(core::array::from_fn(|_| next()));
            if case % 3 == 0 {
                b = a;
            }
            if case % 5 == 0 {
                a = Fx::ZERO;
            }
            if case % 7 == 0 {
                b = Fx([u64::MAX; LIMBS]);
            }
            let mut words = [0u64; LIMBS];
            let mut borrow = 0i64;
            for i in 0..2 * LIMBS {
                let ad = ((a.0[i / 2] >> (32 * (i % 2))) & 0xffff_ffff) as i64;
                let bd = ((b.0[i / 2] >> (32 * (i % 2))) & 0xffff_ffff) as i64;
                let d = ad - bd - borrow;
                borrow = i64::from(d < 0);
                words[i / 2] |= ((d as u64) & 0xffff_ffff) << (32 * (i % 2));
            }
            let expected = if borrow != 0 { Fx::ZERO } else { Fx(words) };
            assert_eq!(a.sub_sat(&b), expected, "case {case}");
        }
    }
    #[test]
    fn row_products_match_base16_oracle() {
        use super::*;
        let mut state = 0x725e_b840_91ad_306fu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for case in 0..10000 {
            let mut a = Fx(core::array::from_fn(|_| next()));
            let mut b = Fx(core::array::from_fn(|_| next()));
            match case % 11 {
                0 => a = Fx::ZERO,
                1 => a = Fx::ONE,
                2 => {
                    a = Fx([u64::MAX; LIMBS]);
                    b = a;
                }
                3 => a.0[case % LIMBS] = 0,
                4 => {
                    a = Fx::ULP;
                    b = Fx([u64::MAX; LIMBS]);
                }
                _ => {}
            }
            let reference = a.mul_raw_reference(&b);
            assert_eq!(
                a.mul_raw_fixed_work(&b),
                reference,
                "fixed-work case {case}"
            );
            // Independent radix-2^16 convolution: at most 28 products per
            // column, so the entire column sum fits safely in u64.
            let digits = |x: Fx| -> [u64; 28] {
                core::array::from_fn(|i| (x.0[i / 4] >> (16 * (i % 4))) & 65535)
            };
            let (ad, bd) = (digits(a), digits(b));
            let mut expected = [0u64; 14];
            let mut carry = 0u64;
            for col in 0..56 {
                let mut sum = carry;
                for i in 0..28 {
                    if col >= i && col - i < 28 {
                        sum += ad[i] * bd[col - i];
                    }
                }
                expected[col / 4] |= (sum & 65535) << (16 * (col % 4));
                carry = sum >> 16;
            }
            assert_eq!(carry, 0);
            assert_eq!(reference.0, expected, "independent oracle case {case}");
            assert_eq!(reference.1, expected[..6].iter().any(|&x| x != 0));
        }
    }
    use super::*;

    #[test]
    fn one_times_one() {
        let p = Fx::ONE.mul_floor(&Fx::ONE);
        assert_eq!(p, Fx::ONE);
        assert_eq!(Fx::ONE.mul_ceil(&Fx::ONE), Fx::ONE);
    }

    #[test]
    fn half_squared() {
        let mut h = [0u64; LIMBS];
        h[FRAC_LIMBS - 1] = 1 << 63; // 0.5
        let half = Fx(h);
        let q = half.mul_floor(&half);
        let mut expect = [0u64; LIMBS];
        expect[FRAC_LIMBS - 1] = 1 << 62; // 0.25
        assert_eq!(q, Fx(expect));
    }

    #[test]
    // Preserve the fixed-width value construction.
    #[allow(clippy::init_numbered_fields)]
    fn div_roundtrip() {
        let x = Fx::from_int(3);
        let d = x.div_u64_floor(7); // 3/7
        let back = d.mul_floor(&Fx::from_int(7));
        // 3/7 * 7 within 7 ulps of 3
        let diff = Fx::from_int(3).sub(&back);
        assert!(diff.le(&Fx {
            0: {
                let mut l = [0u64; LIMBS];
                l[0] = 7;
                l
            }
        }));
    }

    #[test]
    fn div_fx_matches_div_u64() {
        let x = Fx::from_int(1);
        let a = x.div_u64_floor(65804);
        let b = x.div_fx_floor(&Fx::from_int(65804));
        assert_eq!(a, b);
    }

    #[test]
    fn recip_of_two() {
        let two = Iv::exact(Fx::from_int(2));
        let r = two.recip();
        let mut h = [0u64; LIMBS];
        h[FRAC_LIMBS - 1] = 1 << 63;
        assert_eq!(r.lo, Fx(h));
        assert_eq!(r.hi, Fx(h));
    }
}

#[cfg(test)]
mod comba_tests {
    use super::*;
    #[test]
    fn all_carries_and_random_full_width_products_match_both_oracles() {
        let mut seed = 0xfdeb721a18u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut cases = vec![Fx::ZERO, Fx::ONE, Fx::ULP, Fx([u64::MAX; 7])];
        for i in 0..7 {
            let mut x = [0u64; 7];
            x[i] = u64::MAX;
            cases.push(Fx(x));
        }
        for a in &cases {
            for b in &cases {
                assert_eq!(a.mul_raw_comba(b), a.mul_raw_fixed_work(b));
                assert_eq!(a.mul_raw_comba(b), a.mul_raw_reference(b));
            }
        }
        for _ in 0..10000 {
            let a = Fx(core::array::from_fn(|_| next()));
            let b = Fx(core::array::from_fn(|_| next()));
            assert_eq!(a.mul_raw_comba(&b), a.mul_raw_fixed_work(&b));
        }
    }
}
