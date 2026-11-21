//! Powers of theta, the transport series T(u,b), branch probabilities f/g,
//! and the parity normalizer lambda, all as rigorous Q64.384 enclosures.

use crate::fixed::{Fx, Iv, LIMBS};
use crate::params::{ENV_DEN, ENV_NUM, PROPOSAL_W0 as W0, THETA_NUM_LIMBS};

/// Max positive exponent bit-length for the ladder: exponents 2ku + k^2 b stay
/// below 2^40 for all reachable (u, b) (|a| < 2^31 enforced in transport).
const POS_BITS: usize = 40;
/// Negative exponents only arise as b+2a in [-b, 0) or b-2a in (-b, 0] during
/// transport (|exponent| <= b <= SHELL_HI < 2^19); tests exercise up to 2^22.
/// theta^(-2^21) < 16, far from Q64.384 overflow.
const NEG_BITS: usize = 22;

/// 4-bit window count covering POS_BITS.
const WIN: usize = POS_BITS / 4;

/// Public fixed work count, excluding the initial constant term.
pub const CT_SERIES_TERMS: u64 = 64;

pub struct ThetaCtx {
    neg2: [Iv; NEG_BITS],
    /// windowed ladder: win[i][j-1] = theta^(j * 16^i), j in 1..=15
    win: [[Iv; 15]; WIN],
    /// 1/M = ENV_DEN/ENV_NUM as an enclosure. Crate-private: the
    /// binary64 ladder caches its image at construction, so the envelope must
    /// not be mutable from outside the crate.
    pub(crate) inv_m: Iv,
    /// lambda = Z_odd / (M * Z_even) at leading weight W0.
    pub(crate) lambda: Iv,
}

/// theta as an exact Fx: numerator * 2^128 / 2^384 = numerator / 2^256.
pub fn theta_fx() -> Fx {
    let mut l = [0u64; LIMBS];
    l[2..6].copy_from_slice(&THETA_NUM_LIMBS);
    Fx(l)
}

impl ThetaCtx {
    pub fn new() -> Self {
        let th = Iv::exact(theta_fx());
        let mut pow2 = [Iv::ZERO; POS_BITS];
        pow2[0] = th;
        for i in 1..POS_BITS {
            pow2[i] = pow2[i - 1].square();
        }
        let inv_th = th.recip();
        let mut neg2 = [Iv::ZERO; NEG_BITS];
        neg2[0] = inv_th;
        for i in 1..NEG_BITS {
            neg2[i] = neg2[i - 1].square();
        }
        let inv_m = Iv::exact(Fx::from_int(ENV_DEN)).div_u64(ENV_NUM);
        // windowed ladder from the binary ladder
        let mut win = [[Iv::ZERO; 15]; WIN];
        for i in 0..WIN {
            let base = pow2[4 * i]; // theta^(16^i)
            win[i][0] = base;
            for j in 1..15 {
                win[i][j] = win[i][j - 1].mul(&base);
            }
        }
        let mut ctx = ThetaCtx {
            neg2,
            win,
            inv_m,
            lambda: Iv::ZERO,
        };
        ctx.lambda = ctx.compute_lambda();
        ctx
    }

    /// theta^n for n >= 0 (4-bit windows). Underflow collapses to [0, ulp].
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn pow(&self, n: u64) -> Iv {
        assert!(n < (1u64 << POS_BITS), "exponent too large: {n}");
        let mut acc: Option<Iv> = None;
        for i in 0..WIN {
            let d = ((n >> (4 * i)) & 0xf) as usize;
            if d == 0 {
                continue;
            }
            let w = &self.win[i][d - 1];
            acc = Some(match acc {
                None => *w,
                Some(a) => {
                    let p = a.mul(w);
                    if p.hi.is_zero() {
                        return Iv {
                            lo: Fx::ZERO,
                            hi: Fx::ULP,
                        };
                    }
                    p
                }
            });
        }
        acc.unwrap_or(Iv::exact(Fx::ONE))
    }

    /// theta^e for possibly negative e (|e| < 2^19 when e < 0).
    pub fn pow_signed(&self, e: i64) -> Iv {
        if e >= 0 {
            self.pow(e as u64)
        } else {
            let n = (-e) as u64;
            assert!(n < (1u64 << NEG_BITS), "negative exponent too large: {e}");
            let mut acc = Iv::exact(Fx::ONE);
            for i in 0..NEG_BITS {
                if (n >> i) & 1 == 1 {
                    acc = acc.mul(&self.neg2[i]);
                }
            }
            acc
        }
    }

    /// T(u, b) = sum_{k>=0} (-1)^k theta^{2ku + k^2 b}, u >= 0, b >= 1.
    /// Alternating with strictly decreasing terms, so the remainder after
    /// truncation is bounded by the first omitted term.
    ///
    /// Terms are updated incrementally: term_{k+1} = term_k * m_k with
    /// m_k = theta^{2u + (2k+1) b}, maintained as m_{k+1} = m_k * theta^{2b}.
    /// Directed rounding on every product keeps the enclosure rigorous.
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn t_series(&self, u: u64, b: u64) -> Iv {
        let mut sum = Iv::exact(Fx::ONE); // k = 0 term
                                          // fast exit: first term theta^{2u+b} already below one ulp
        let e1 = 2u128 * u as u128 + b as u128;
        if e1 >= 1 << POS_BITS {
            return Iv {
                lo: sum.lo.sub_sat(&Fx::ULP),
                hi: sum.hi,
            };
        }
        let mut term = self.pow(e1 as u64); // k = 1 term
        let mut mult = term.mul(&self.pow(2 * b)); // m_1 = theta^{2u+3b}
        let step = self.pow(2 * b);
        let mut k: u64 = 1;
        loop {
            if term.hi.le(&Fx::ULP) {
                // remainder in [0, term.hi] with sign (-1)^k
                return if k % 2 == 1 {
                    Iv {
                        lo: sum.lo.sub_sat(&term.hi),
                        hi: sum.hi,
                    }
                } else {
                    Iv {
                        lo: sum.lo,
                        hi: sum.hi.add(&term.hi),
                    }
                };
            }
            if k % 2 == 1 {
                sum = sum.sub_sat(&term);
            } else {
                sum = sum.add(&term);
            }
            term = term.mul(&mult);
            mult = mult.mul(&step);
            k += 1;
            assert!(k < 4096, "T series failed to converge");
        }
    }

    /// Branch probabilities (f, g) of eqs. (17)-(18) at inner product a and
    /// shift weighted squared norm b = E(s).
    pub fn fg(&self, a: i64, b: u64) -> (Iv, Iv) {
        let bi = b as i64;
        let f = if a >= bi {
            self.t_series(a as u64, b).mul(&self.inv_m)
        } else {
            // theta^{b-2a} T(b-a, b) / M
            let e = bi - 2 * a; // may be negative when a in (b/2, b)
            let scale = self.pow_signed(e);
            scale
                .mul(&self.t_series((bi - a) as u64, b))
                .mul(&self.inv_m)
        };
        let g = if a >= -bi {
            let e = bi + 2 * a; // may be negative when a in [-b, -b/2)
            let scale = self.pow_signed(e);
            scale
                .mul(&self.t_series((bi + a) as u64, b))
                .mul(&self.inv_m)
        } else {
            self.t_series((-a) as u64, b).mul(&self.inv_m)
        };
        (f, g)
    }

    /// Fixed-work theta^n for 0 <= n < 2^40 (no early return, no data-dependent
    /// window skip): every one of the WIN windows multiplies in a masked-scan
    /// selection over its 15 nonzero digits plus the identity for digit 0.
    /// Constant memory-access pattern; used by the CT transport ladder.
    pub fn pow_ct(&self, n: u64) -> Iv {
        self.pow_ct_windows::<WIN, 15>(n)
    }

    /// Public loop bounds. The generic API retains all ten full windows.
    fn pow_ct_windows<const WINDOWS: usize, const LAST_DIGIT: u64>(&self, n: u64) -> Iv {
        use crate::ct::ct_eq_u64;
        let one = Iv::exact(Fx::ONE);
        let mut acc = one;
        for i in 0..WINDOWS {
            let d = (n >> (4 * i)) & 0xf;
            {
                let mut chosen = Iv::ZERO;
                for j in 1u64..=if i + 1 == WINDOWS { LAST_DIGIT } else { 15 } {
                    let mask = crate::ct::opaque_mask(ct_eq_u64(d, j));
                    let entry = &self.win[i][(j - 1) as usize];
                    for k in 0..LIMBS {
                        chosen.lo.0[k] |= entry.lo.0[k] & mask;
                        chosen.hi.0[k] |= entry.hi.0[k] & mask;
                    }
                }
                let identity = crate::ct::opaque_mask(ct_eq_u64(d, 0));
                chosen.lo.0[LIMBS - 1] |= identity & 1;
                chosen.hi.0[LIMBS - 1] |= identity & 1;
                acc = acc.mul(&chosen);
            }
        }
        acc
    }

    /// Fixed-work theta^e for the signed exponent range used by `fg_ct`.
    /// Both the positive (40-bit) and negative (22-bit) ladders are evaluated
    /// and selected by the sign mask; the unused branch runs on masked bits
    /// and is discarded. Callers guarantee |e| < 2^40 for e >= 0 and
    /// |e| < 2^22 for e < 0 (holds for all fg arguments, see the transport
    /// range analysis); the discarded branch may be meaningless.
    pub fn pow_signed_ct(&self, e: i64) -> Iv {
        let neg = ((e >> 63) as u64) & 1; // 1 if e < 0
        let neg_mask = 0u64.wrapping_sub(neg); // all-ones iff negative
        let m = e.unsigned_abs();
        let pos = self.pow_ct(m & ((1u64 << POS_BITS) - 1));
        // negative ladder over the low NEG_BITS bits of |e|
        let one = Iv::exact(Fx::ONE);
        let mut negv = one;
        for i in 0..NEG_BITS {
            let bit = (m >> i) & 1;
            let bm = 0u64.wrapping_sub(bit);
            negv = iv_select(bm, &negv.mul(&self.neg2[i]), &negv);
        }
        iv_select(neg_mask, &negv, &pos)
    }

    /// Fixed public-term-count evaluation of T(u, b); no early exit. Alternating with
    /// decreasing terms, so the remainder after the last term is bounded by
    /// that term's upper endpoint (added with the correct sign). Rigorous
    /// enclosure for every (u, b) in range.
    pub fn t_series_ct(&self, u: u64, b: u64) -> Iv {
        let step = self.pow_ct(2 * b);
        self.t_series_ct_step(u, b, step)
    }
    fn t_series_ct_step(&self, u: u64, b: u64, step: Iv) -> Iv {
        const TERMS: u64 = CT_SERIES_TERMS;
        // k = 1 term: theta^{2u+b}; k = 0 term is exactly 1.
        let e1 = 2u128 * u as u128 + b as u128;
        let in_range = 0u64.wrapping_sub(u64::from(e1 < 1u128 << POS_BITS));
        let power = self.pow_ct(e1 as u64 & ((1u64 << POS_BITS) - 1));
        let mut term = iv_select(
            in_range,
            &power,
            &Iv {
                lo: Fx::ZERO,
                hi: Fx::ULP,
            },
        );
        let mut mult = term.mul(&step); // m_1 = theta^{2u+3b}
        let mut sum = Iv::exact(Fx::ONE);
        let mut k: u64 = 1;
        while k <= TERMS {
            // k parity is public (deterministic loop counter)
            if k % 2 == 1 {
                sum = sum.sub_sat(&term);
            } else {
                sum = sum.add(&term);
            }
            term = term.mul(&mult);
            mult = mult.mul(&step);
            k += 1;
        }
        // remainder bracket: |R| <= term_{TERMS+1}.hi, sign (-1)^{TERMS+1}
        if (TERMS + 1) % 2 == 1 {
            Iv {
                lo: sum.lo.sub_sat(&term.hi),
                hi: sum.hi,
            }
        } else {
            Iv {
                lo: sum.lo,
                hi: sum.hi.add(&term.hi),
            }
        }
    }

    /// Constant-time branch probabilities (f, g): the piecewise selection of
    /// eqs. (17)-(18) is done by CT-selecting the T-argument and scale
    /// exponent from both cases, then evaluating one scale power and one
    /// series per mass. No branch on the secret-dependent sign of a.
    pub fn fg_ct(&self, a: i64, b: u64) -> (Iv, Iv) {
        use crate::ct::ct_select_i64;
        let bi = b as i64;
        // f: a >= b ? (arg=a, e=0) : (arg=b-a, e=b-2a)
        let f_hi = 0u64.wrapping_sub((a >= bi) as u64); // all-ones iff a>=b
        let af = ct_select_i64(f_hi, a, bi - a);
        let ef = ct_select_i64(f_hi, 0, bi - 2 * a);
        // g: a >= -b ? (arg=b+a, e=b+2a) : (arg=-a, e=0)
        let g_hi = 0u64.wrapping_sub((a >= -bi) as u64);
        let ag = ct_select_i64(g_hi, bi + a, -a);
        let eg = ct_select_i64(g_hi, bi + 2 * a, 0);
        let step = self.pow_ct(2 * b);
        let (tf, tg) = (
            self.t_series_ct_step(af as u64, b, step),
            self.t_series_ct_step(ag as u64, b, step),
        );
        let f = self.pow_signed_ct(ef).mul(&tf).mul(&self.inv_m);
        let g = self.pow_signed_ct(eg).mul(&tg).mul(&self.inv_m);
        (f, g)
    }

    /// Parity partition sums at the leading weight: Z_par = sum over x = par mod 2
    /// of theta^{W0 x^2}.
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    fn z_parity(&self, parity: u64) -> Iv {
        let mut sum = if parity == 0 {
            Iv::exact(Fx::ONE)
        } else {
            Iv::ZERO
        };
        let mut x = if parity == 0 { 2u64 } else { 1u64 };
        loop {
            let t = self.pow(W0 * x * x);
            if t.hi.le(&Fx::ULP) {
                // symmetric tail, bounded crudely by 4 remaining ulps
                let mut tail = [0u64; LIMBS];
                tail[0] = 4;
                return Iv {
                    lo: sum.lo,
                    hi: sum.hi.add(&Fx(tail)),
                };
            }
            // both +x and -x
            sum = sum.add(&t).add(&t);
            x += 2;
        }
    }

    fn compute_lambda(&self) -> Iv {
        let ze = self.z_parity(0);
        let zo = self.z_parity(1);
        // lambda = zo / (M * ze) = zo * inv_m * (1/ze)
        zo.mul(&self.inv_m).mul(&ze.recip())
    }

    /// Envelope function M(b) = 1 + theta4(0, theta^b)/theta^b
    ///                        = 1 + (2 T(0,b) - 1) / theta^b   (test support).
    pub fn envelope(&self, b: u64) -> Iv {
        let t0 = self.t_series(0, b);
        let two_t_minus_1 = t0.add(&t0).sub_sat(&Iv::exact(Fx::ONE));
        let qb = self.pow(b);
        Iv::exact(Fx::ONE).add(&two_t_minus_1.mul(&qb.recip()))
    }

    /// Start a lazily refined enclosure of T(u, b); `step2b` must be pow(2b).
    pub fn lazy_t(&self, u: u64, b: u64, step2b: &Iv) -> LazyT {
        let e1 = 2u128 * u as u128 + b as u128;
        let term = if e1 >= 1 << POS_BITS {
            Iv {
                lo: Fx::ZERO,
                hi: Fx::ULP,
            }
        } else {
            self.pow(e1 as u64)
        };
        let mult = term.mul(step2b);
        LazyT {
            sum: Iv::exact(Fx::ONE),
            term,
            mult,
            step: *step2b,
            k: 1,
            done: false,
        }
    }
}

/// Branch-free select between two intervals by an all-ones/zero mask.
#[inline(always)]
// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
fn iv_select(mask: u64, a: &Iv, b: &Iv) -> Iv {
    {
        let mask = crate::ct::opaque_mask(mask);
        let mut out = Iv::ZERO;
        for i in 0..LIMBS {
            out.lo.0[i] = b.lo.0[i] ^ ((a.lo.0[i] ^ b.lo.0[i]) & mask);
            out.hi.0[i] = b.hi.0[i] ^ ((a.hi.0[i] ^ b.hi.0[i]) & mask);
        }
        return out;
    }
}

#[inline(always)]
#[allow(dead_code)]
// Keep the explicit lane order and index schedule of the kernel and its oracle.
#[allow(clippy::needless_range_loop)]
fn fx_select(mask: u64, a: &Fx, b: &Fx) -> Fx {
    let mut r = [0u64; LIMBS];
    for i in 0..LIMBS {
        r[i] = crate::ct::ct_select_u64(mask, a.0[i], b.0[i]);
    }
    Fx(r)
}

/// Lazily refined enclosure of the alternating series T(u, b): each `refine`
/// applies one more term, tightening the bracket returned by `iv`.
pub struct LazyT {
    sum: Iv,
    term: Iv, // next unapplied term (index k)
    mult: Iv,
    step: Iv,
    k: u64,
    done: bool,
}

impl LazyT {
    /// Current rigorous enclosure of T.
    pub fn iv(&self) -> Iv {
        if self.done {
            self.sum
        } else if self.k % 2 == 1 {
            Iv {
                lo: self.sum.lo.sub_sat(&self.term.hi),
                hi: self.sum.hi,
            }
        } else {
            Iv {
                lo: self.sum.lo,
                hi: self.sum.hi.add(&self.term.hi),
            }
        }
    }

    /// Apply one more term; false once exhausted (enclosure final).
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn refine(&mut self) -> bool {
        if self.done {
            return false;
        }
        if self.term.hi.le(&Fx::ULP) {
            // fold the remainder bound into the sum permanently
            self.sum = self.iv();
            self.done = true;
            return false;
        }
        if self.k % 2 == 1 {
            self.sum = self.sum.sub_sat(&self.term);
        } else {
            self.sum = self.sum.add(&self.term);
        }
        self.term = self.term.mul(&self.mult);
        self.mult = self.mult.mul(&self.step);
        self.k += 1;
        true
    }
}

impl Default for ThetaCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::FRAC_LIMBS;
    use crate::params::{PROPOSAL_SHELL_HI as SHELL_HI, PROPOSAL_SHELL_LO as SHELL_LO};

    /// Sampled precision regression, NOT a certificate: the transport branch-mass intervals from
    /// the fixed-point ladder (Fx = 7 x 64 bits, 384 fractional) must stay far
    /// narrower than the transport decision needs. We measure the worst-case
    /// width w(f), w(f+g) over the (a, b) grid and require at least 30 bits of
    /// margin (width < 2^-30); the achieved margin is printed. Ambiguous-abort
    /// mass at the sampled points is constrained by these widths. This does
    /// not establish an all-input or end-to-end statistical-distance bound.
    #[test]
    fn transport_interval_width_margin() {
        let ctx = ThetaCtx::new();
        // highest set fraction bit of a width Fx -> its magnitude 2^(pos-384);
        // -log2(width) = 384 - pos. Zero width -> treat as fully precise.
        let neglog2 = |w: &crate::fixed::Fx| -> i64 {
            match w.top_bit() {
                Some(pos) => 64 * FRAC_LIMBS as i64 - pos as i64,
                None => 1000,
            }
        };
        let mut min_margin = i64::MAX;
        let mut worst = (0i64, 0u64);
        let bs = [SHELL_LO, (SHELL_LO + SHELL_HI) / 2, SHELL_HI];
        for &b in &bs {
            let bi = b as i64;
            // sweep a across the piecewise regions of eqs. (17)-(18)
            let sample_as = [
                -3 * bi,
                -bi - 1,
                -bi,
                -bi / 2,
                -1,
                0,
                1,
                bi / 2,
                bi,
                bi + 1,
                3 * bi,
                -500_000,
                -1000,
                1000,
                500_000,
            ];
            for &a in &sample_as {
                let (f, g) = ctx.fg_ct(a, b);
                let wf = f.hi.sub_sat(&f.lo);
                let t2_lo = f.lo.add(&g.lo);
                let t2_hi = f.hi.add(&g.hi);
                let wfg = t2_hi.sub_sat(&t2_lo);
                for w in [&wf, &wfg] {
                    let m = neglog2(w);
                    if m < min_margin {
                        min_margin = m;
                        worst = (a, b);
                    }
                }
            }
        }
        println!(
            "sampled min transport-boundary precision = 2^-{} bits (worst a={}, b={}); 384-bit fraction",
            min_margin, worst.0, worst.1
        );
        assert!(
            min_margin >= 30,
            "transport interval width margin {min_margin} < 30 bits"
        );
    }

    #[test]
    fn t_series_recursion() {
        // T(a,b) = 1 - theta^{2a+b} T(a+b, b) at a few points
        let ctx = ThetaCtx::new();
        for (a, b) in [(0u64, SHELL_LO), (100_000, SHELL_HI), (300_000, 127_487)] {
            let lhs = ctx.t_series(a, b);
            let rhs = Iv::exact(Fx::ONE).sub_sat(&ctx.pow(2 * a + b).mul(&ctx.t_series(a + b, b)));
            // enclosures must overlap
            assert!(
                lhs.lo.le(&rhs.hi) && rhs.lo.le(&lhs.hi),
                "eq 22 at ({a},{b})"
            );
        }
    }

    #[test]
    fn fg_are_subprobabilities() {
        let ctx = ThetaCtx::new();
        let b = SHELL_HI;
        for a in [
            -3 * b as i64,
            -(b as i64),
            -(b as i64) / 2,
            0,
            (b as i64) / 2,
            b as i64,
            2 * b as i64,
            1_800_000_000,
        ] {
            let (f, g) = ctx.fg(a, b);
            assert!(f.hi.le(&Fx::ONE.add(&Fx::ULP)), "f <= 1 at a={a}");
            assert!(g.hi.le(&Fx::ONE.add(&Fx::ULP)), "g <= 1 at a={a}");
            let s = f.add(&g);
            assert!(s.hi.le(&Fx::ONE.add(&Fx::ULP)), "f+g <= 1 at a={a}");
        }
    }

    #[test]
    fn balance_identity() {
        // theta^{2a+b} f(a+b) + theta^{-2a+b} g(a-b) = 1/M
        let ctx = ThetaCtx::new();
        let b = 200_000u64;
        for a in [-150_000i64, -1, 0, 77_777, 199_999, 200_000, 350_000] {
            let (fp, _) = ctx.fg(a + b as i64, b);
            let (_, gm) = ctx.fg(a - b as i64, b);
            let lhs = ctx
                .pow_signed(2 * a + b as i64)
                .mul(&fp)
                .add(&ctx.pow_signed(-2 * a + b as i64).mul(&gm));
            assert!(
                lhs.lo.le(&ctx.inv_m.hi) && ctx.inv_m.lo.le(&lhs.hi),
                "balance identity at a={a}"
            );
        }
    }
}
