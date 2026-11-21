//! The iterative coset transport kernel over the flat response
//! vector layout [leading 256 | secret 1024 | error 1024].

use crate::fixed::{Fx, FRAC_LIMBS, LIMBS};
use crate::hashes::Xof;
use crate::params::*;
use crate::theta::ThetaCtx;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const LEAD: usize = 0;
pub const SEC: usize = N;
pub const ERR: usize = N + ELL * N;

pub type Vector = [i32; DIM];

/// Weight of coordinate index i.
#[inline]
fn coord_weight(i: usize) -> u64 {
    if i < SEC {
        PROPOSAL_W0
    } else if i < ERR {
        WS
    } else {
        WE
    }
}

/// Public wrapper over the per-index coordinate weight (for the NEON path).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn coord_weight_pub(i: usize) -> u64 {
    coord_weight(i)
}

/// Accepted-key metric; does not select proposal geometry.
pub fn key_energy(x: &Vector) -> u64 {
    let mut e = 0u64;
    for (i, &v) in x.iter().enumerate() {
        let w = if i < SEC {
            W0
        } else if i < ERR {
            WS
        } else {
            WE
        };
        e += w * (v as i64 * v as i64) as u64;
    }
    e
}

/// Proposal weighted energy E(x).
pub fn energy(x: &Vector) -> u64 {
    let mut e = 0u64;
    for (i, &v) in x.iter().enumerate() {
        e += coord_weight(i) * (v as i64 * v as i64) as u64;
    }
    e
}

/// Weighted inner product <z, X^j s>_W without materializing X^j s.
/// Rotation acts within each 256-coefficient polynomial: (X^j p)_i = p_{i-j}
/// with a sign flip on wraparound.
pub fn dot_rotated(z: &Vector, s: &Vector, j: usize) -> i64 {
    let mut acc = 0i64;
    let n_polys = DIM / N;
    for p in 0..n_polys {
        let base = p * N;
        let w = coord_weight(base) as i64;
        let mut sub = 0i64;
        for i in 0..N {
            let (src, sign) = if i >= j { (i - j, 1) } else { (i + N - j, -1) };
            sub += z[base + i] as i64 * (sign * s[base + src]) as i64;
        }
        acc += w * sub;
    }
    acc
}

/// Sparse view of a ternary secret: per 256-coefficient block, the indices
/// carrying +1 and -1. Iterating only nonzeros roughly halves the rotation
/// arithmetic; sums are identical (integer adds, reordered).
pub struct SparseSecret {
    pos: Vec<Vec<u16>>,
    neg: Vec<Vec<u16>>,
    /// cnt_pos[p][c] = number of entries of pos[p] below c (0 <= c <= N), so
    /// the wraparound partition point for shift j is cnt[p][N - j]: O(1)
    /// instead of a binary search per block per step.
    cnt_pos: Vec<Vec<u16>>,
    cnt_neg: Vec<Vec<u16>>,
}

impl Drop for SparseSecret {
    fn drop(&mut self) {
        self.pos.zeroize();
        self.neg.zeroize();
        self.cnt_pos.zeroize();
        self.cnt_neg.zeroize();
    }
}
impl ZeroizeOnDrop for SparseSecret {}

impl SparseSecret {
    pub fn new(s: &Vector) -> SparseSecret {
        let n_polys = DIM / N;
        // Fixed maximum capacity avoids reallocating secret-derived indices.
        let mut pos: Vec<_> = (0..n_polys).map(|_| Vec::with_capacity(N)).collect();
        let mut neg: Vec<_> = (0..n_polys).map(|_| Vec::with_capacity(N)).collect();
        for p in 0..n_polys {
            for i in 0..N {
                match s[p * N + i] {
                    1 => pos[p].push(i as u16),
                    -1 => neg[p].push(i as u16),
                    0 => {}
                    _ => unreachable!("secret is ternary"),
                }
            }
        }
        let counts = |lists: &Vec<Vec<u16>>| -> Vec<Vec<u16>> {
            lists
                .iter()
                .map(|l| {
                    let mut c = vec![0u16; N + 1];
                    for v in 1..=N {
                        c[v] = c[v - 1]
                            + l[c[v - 1] as usize..]
                                .iter()
                                .take_while(|&&x| (x as usize) < v)
                                .count() as u16;
                    }
                    c
                })
                .collect()
        };
        let cnt_pos = counts(&pos);
        let cnt_neg = counts(&neg);
        SparseSecret {
            pos,
            neg,
            cnt_pos,
            cnt_neg,
        }
    }
}

/// dot_rotated over the sparse secret: same integer sum, nonzeros only.
/// The index lists are sorted, so the negacyclic wraparound splits each list
/// at partition_point into two branch-free runs.
pub fn dot_rotated_sparse(z: &Vector, ss: &SparseSecret, j: usize) -> i64 {
    assert!(j < N, "rotation out of range");
    let n_polys = DIM / N;
    let mut acc = 0i64;
    for p in 0..n_polys {
        let base = p * N;
        let w = coord_weight(base) as i64;
        let mut sub = 0i64;
        let pos = &ss.pos[p];
        let neg = &ss.neg[p];
        let kp = ss.cnt_pos[p][N - j] as usize;
        let kn = ss.cnt_neg[p][N - j] as usize;
        // SAFETY: every src is < N by construction; entries below the
        // partition satisfy src + j < N, entries at or above it satisfy
        // N <= src + j < 2N, so all indices stay inside z's block [base,
        // base + N). Checked by the sparse_rotation_matches_dense test and
        // the debug asserts.
        unsafe {
            for &src in pos.get_unchecked(..kp) {
                debug_assert!(src as usize + j < N);
                sub += *z.get_unchecked(base + src as usize + j) as i64;
            }
            for &src in pos.get_unchecked(kp..) {
                debug_assert!((N..2 * N).contains(&(src as usize + j)));
                sub -= *z.get_unchecked(base + src as usize + j - N) as i64;
            }
            for &src in neg.get_unchecked(..kn) {
                sub -= *z.get_unchecked(base + src as usize + j) as i64;
            }
            for &src in neg.get_unchecked(kn..) {
                sub += *z.get_unchecked(base + src as usize + j - N) as i64;
            }
        }
        acc += w * sub;
    }
    acc
}

/// z += sign * X^j s over the sparse secret (same split as the dot).
pub fn add_rotated_sparse(z: &mut Vector, ss: &SparseSecret, j: usize, sign: i32) {
    assert!(j < N, "rotation out of range");
    let n_polys = DIM / N;
    for p in 0..n_polys {
        let base = p * N;
        let pos = &ss.pos[p];
        let neg = &ss.neg[p];
        let kp = ss.cnt_pos[p][N - j] as usize;
        let kn = ss.cnt_neg[p][N - j] as usize;
        // SAFETY: same index invariants as dot_rotated_sparse.
        unsafe {
            for &src in pos.get_unchecked(..kp) {
                *z.get_unchecked_mut(base + src as usize + j) += sign;
            }
            for &src in pos.get_unchecked(kp..) {
                *z.get_unchecked_mut(base + src as usize + j - N) -= sign;
            }
            for &src in neg.get_unchecked(..kn) {
                *z.get_unchecked_mut(base + src as usize + j) -= sign;
            }
            for &src in neg.get_unchecked(kn..) {
                *z.get_unchecked_mut(base + src as usize + j - N) += sign;
            }
        }
    }
}

/// z += sign * X^j s.
pub fn add_rotated(z: &mut Vector, s: &Vector, j: usize, sign: i32) {
    let n_polys = DIM / N;
    for p in 0..n_polys {
        let base = p * N;
        for i in 0..N {
            let (src, sgn) = if i >= j { (i - j, 1) } else { (i + N - j, -1) };
            z[base + i] += sign * sgn * s[base + src];
        }
    }
}

/// A full 384-bit uniform in [0, 1), most-significant limb first (fixed work).
fn uniform_unit(rng: &mut Xof) -> Fx {
    let top = rng.u64();
    complete_uniform(top, rng)
}

/// `top` is the most significant fraction limb; the remaining 320 bits are
/// drawn here, most-significant limb first.
fn complete_uniform(top: u64, rng: &mut Xof) -> Fx {
    let mut limbs = [0u64; LIMBS];
    limbs[FRAC_LIMBS - 1] = top;
    for i in (0..FRAC_LIMBS - 1).rev() {
        limbs[i] = rng.u64();
    }
    Fx(limbs)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Step {
    Minus,
    Plus,
    Abort,
    /// Draw fell in an interval-enclosure gap; abort the attempt.
    Ambiguous,
}

/// Per-key transport context: caches the series step factor theta^(2b).
pub struct StepCtx<'a> {
    pub theta: &'a ThetaCtx,
    pub b: u64,
    step2b: crate::fixed::Iv,
}

impl<'a> StepCtx<'a> {
    /// Same cached interval as `new`, using the fixed-work power schedule.
    /// The key energy is secret-derived, not an automatically public input.
    pub fn new_ct(theta: &'a ThetaCtx, b: u64) -> StepCtx<'a> {
        let step2b = theta.pow_ct(2 * b);
        StepCtx { theta, b, step2b }
    }
    pub fn new(theta: &'a ThetaCtx, b: u64) -> StepCtx<'a> {
        let step2b = theta.pow(2 * b);
        StepCtx { theta, b, step2b }
    }
}

/// One transport decision, by directed fixed-point intervals. There is no end-to-end
/// statistical-distance certificate for this implementation.
pub fn step_decision(sc: &StepCtx, a: i64, rng: &mut Xof) -> Step {
    assert!(a.unsigned_abs() < 1 << 31, "inner product out of range");
    let top = rng.u64();
    {
        let u = complete_uniform(top, rng);
        step_decision_exact(sc, a, &u)
    }
}

/// The exact interval decision for a fully drawn uniform u; lazily refines
/// the two alternating series only until u is classified.
pub fn step_decision_exact(sc: &StepCtx, a: i64, u: &Fx) -> Step {
    step_decision_exact_reference(sc, a, u)
}

/// Wide decision program behind `step_decision_exact`, also used by the
/// equivalence tests.
pub fn step_decision_exact_reference(sc: &StepCtx, a: i64, u: &Fx) -> Step {
    let th = sc.theta;
    let bi = sc.b as i64;
    // f = A * T(uf, b), g = B * T(ug, b)  (eqs. 17-18, scales folded with 1/M)
    let (scale_f, uf) = if a >= bi {
        (th.inv_m, a as u64)
    } else {
        (th.pow_signed(bi - 2 * a).mul(&th.inv_m), (bi - a) as u64)
    };
    let (scale_g, ug) = if a >= -bi {
        (th.pow_signed(bi + 2 * a).mul(&th.inv_m), (bi + a) as u64)
    } else {
        (th.inv_m, (-a) as u64)
    };
    let mut tf = th.lazy_t(uf, sc.b, &sc.step2b);
    let mut tg = th.lazy_t(ug, sc.b, &sc.step2b);
    loop {
        let f = scale_f.mul(&tf.iv());
        let g = scale_g.mul(&tg.iv());
        if u.lt(&f.lo) {
            return Step::Minus;
        }
        let t2_lo = f.lo.add(&g.lo);
        let t2_hi = f.hi.add(&g.hi);
        if !u.lt(&f.hi) && u.lt(&t2_lo) {
            return Step::Plus;
        }
        if !u.lt(&t2_hi) {
            return Step::Abort;
        }
        let p1 = tf.refine();
        let p2 = tg.refine();
        if !p1 && !p2 {
            return Step::Ambiguous;
        }
    }
}

/// Fixed-schedule transport step: fixed-work fg via the CT ladder, a full
/// 384-bit draw always consumed, and a branch-free classification of the draw
/// against the (f, f+g) interval endpoints. Returns a mask triple
/// (minus, plus, abort_or_ambiguous); exactly one is all-ones. The caller
/// applies the dense masked rotation. Full binary noninterference is unproved.
pub fn step_decision_ct(sc: &StepCtx, a: i64, rng: &mut Xof) -> (u64, u64, u64) {
    let (f, g) = sc.theta.fg_ct(a, sc.b);
    let u = uniform_unit(rng);
    classify_intervals_ct(&f, &g, &u)
}

pub(crate) fn classify_intervals_ct(
    f: &crate::fixed::Iv,
    g: &crate::fixed::Iv,
    u: &Fx,
) -> (u64, u64, u64) {
    use crate::ct::ct_lt_fx;
    let lt_flo = ct_lt_fx(u, &f.lo);
    let lt_fhi = ct_lt_fx(u, &f.hi);
    let lt_t2lo = ct_lt_fx(u, &f.lo.add(&g.lo));
    // minus: u < f.lo
    let minus = lt_flo;
    // plus: u >= f.hi AND u < t2_lo
    let plus = !lt_fhi & lt_t2lo & !minus;
    // abort/ambiguous: everything else (u >= t2_hi is a clean abort; the two
    // enclosure gaps [f.lo,f.hi) and [t2_lo,t2_hi) are ambiguous -> abort)
    let other = !minus & !plus;
    (minus, plus, other)
}

/// Constant-time dummy Bernoulli(lambda): full draw, branch-free compare.
/// Returns (pass_mask, fail_or_ambiguous_mask).
pub fn dummy_test_ct(sc: &StepCtx, rng: &mut Xof) -> (u64, u64) {
    dummy_test_theta_ct(sc.theta, rng)
}

/// The dummy decision needs only lambda, not the per-key transport power.
/// This shares the exact comparison and entropy consumption of dummy_test_ct.
pub(crate) fn dummy_test_theta_ct(theta: &ThetaCtx, rng: &mut Xof) -> (u64, u64) {
    let pass = {
        let u = uniform_unit(rng);
        crate::ct::ct_lt_fx(&u, &theta.lambda.lo)
    };
    // The full 384-bit draw is compared with the lower end of the enclosure
    // of lambda; this moves at most the enclosure width from pass into the
    // abort outcome.
    (pass, !pass)
}

/// Dummy Bernoulli(lambda) test: a full 384-bit uniform is drawn and compared
/// with both ends of the enclosure of lambda; a draw inside the enclosure is
/// `Ambiguous`.
pub fn dummy_test(sc: &StepCtx, rng: &mut Xof) -> Step {
    let top = rng.u64();
    let u = complete_uniform(top, rng);
    if u.lt(&sc.theta.lambda.lo) {
        Step::Minus
    } else if !u.lt(&sc.theta.lambda.hi) {
        Step::Abort
    } else {
        Step::Ambiguous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_interval_grid_counts_include_overlap_and_abort() {
        use crate::fixed::Iv;
        let grid = 16u64;
        let point = |n| Fx::from_int(n).div_u64_floor(grid);
        for lo in 0..=grid {
            for hi in lo..=grid + 1 {
                for gl in 0..=grid - lo {
                    let f = Iv {
                        lo: point(lo),
                        hi: point(hi),
                    };
                    let g = Iv::exact(point(gl));
                    let mut counts = [0u64; 3];
                    for u in 0..grid {
                        let (m, p, a) = classify_intervals_ct(&f, &g, &point(u));
                        assert_eq!((m != 0) as u8 + (p != 0) as u8 + (a != 0) as u8, 1);
                        counts[0] += (m != 0) as u64;
                        counts[1] += (p != 0) as u64;
                        counts[2] += (a != 0) as u64;
                    }
                    assert_eq!(
                        counts,
                        [
                            lo,
                            (lo + gl).saturating_sub(hi),
                            grid - lo - (lo + gl).saturating_sub(hi)
                        ]
                    );
                }
            }
        }
    }

    #[test]
    fn fixed_interval_decisions_at_one_and_adjacent_draws() {
        use crate::fixed::Iv;
        let one = Iv::exact(Fx::ONE);
        for u in [Fx::ZERO, Fx::ULP, Fx::ONE.sub(&Fx::ULP)] {
            assert_eq!(classify_intervals_ct(&one, &Iv::ZERO, &u), (u64::MAX, 0, 0));
            assert_eq!(classify_intervals_ct(&Iv::ZERO, &one, &u), (0, u64::MAX, 0));
        }
        assert_eq!(
            classify_intervals_ct(&one, &Iv::ZERO, &Fx::ONE),
            (0, 0, u64::MAX)
        );
    }
    use crate::challenge::Challenge;
    use crate::gauss::{Cdt, Draw};

    fn sample_y(cdts: &(Cdt, Cdt, Cdt), rng: &mut Xof) -> Vector {
        let mut z = [0i32; DIM];
        for i in 0..DIM {
            let cdt = if i < SEC {
                &cdts.0
            } else if i < ERR {
                &cdts.1
            } else {
                &cdts.2
            };
            match cdt.sample(rng) {
                Draw::Value(v) => z[i] = v,
                Draw::Ambiguous => panic!("ambiguous"),
            }
        }
        z
    }

    fn toy_secret(seed: u64) -> Vector {
        // CBD1-like secret via xorshift; leading block is the constant poly 1
        let mut s = [0i32; DIM];
        s[0] = 1;
        let mut st = seed | 1;
        for v in s.iter_mut().skip(N) {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            *v = ((st >> 20) & 1) as i32 - ((st >> 21) & 1) as i32;
        }
        s
    }

    /// Full transport of one attempt; returns accepted z or None.
    fn run_attempt(
        ctx: &ThetaCtx,
        cdts: &(Cdt, Cdt, Cdt),
        s: &Vector,
        b: u64,
        c: &Challenge,
        rng: &mut Xof,
    ) -> Option<Vector> {
        let sc = StepCtx::new(ctx, b);
        let mut z = sample_y(cdts, rng);
        let mut w = 0;
        for j in 0..N {
            if !c[j] {
                continue;
            }
            w += 1;
            let a = dot_rotated(&z, s, j);
            match step_decision(&sc, a, rng) {
                Step::Minus => add_rotated(&mut z, s, j, -1),
                Step::Plus => add_rotated(&mut z, s, j, 1),
                _ => return None,
            }
        }
        for _ in 0..(128 - w) {
            if dummy_test(&sc, rng) != Step::Minus {
                return None;
            }
        }
        Some(z)
    }

    #[test]
    fn rotation_energy_invariance() {
        let s = toy_secret(42);
        let e = energy(&s);
        for j in [1usize, 77, 255] {
            let mut v = [0i32; DIM];
            add_rotated(&mut v, &s, j, 1);
            assert_eq!(energy(&v), e, "E(X^{j} s) = E(s)");
        }
    }

    #[test]
    fn dot_matches_materialized() {
        let s = toy_secret(9);
        let mut z = toy_secret(1234);
        z[100] = 7;
        for j in [0usize, 3, 200] {
            let mut v = [0i32; DIM];
            add_rotated(&mut v, &s, j, 1);
            let direct: i64 = v
                .iter()
                .enumerate()
                .map(|(i, &vi)| coord_weight(i) as i64 * z[i] as i64 * vi as i64)
                .sum();
            assert_eq!(dot_rotated(&z, &s, j), direct);
        }
    }

    #[test]
    fn acceptance_rate_matches_lambda_128() {
        // Monte Carlo diagnostic: the transport-only success rate is compared with lambda^128.
        let ctx = ThetaCtx::new();
        let cdts = (
            Cdt::new(&ctx, PROPOSAL_W0, true),
            Cdt::new(&ctx, WS, false),
            Cdt::new(&ctx, WE, false),
        );
        let s = toy_secret(2024);
        let b = energy(&s);
        assert!(
            (PROPOSAL_SHELL_LO..=PROPOSAL_SHELL_HI).contains(&b),
            "toy key in shell (b={b})"
        );
        // fixed weight-96 challenge
        let mut c = [false; N];
        for j in 0..96 {
            c[2 * j] = true;
        }
        let mut rng = Xof::new(DOM_ATTEMPT, &[b"transport-mc"]);
        let trials = 600;
        let mut acc = 0;
        for _ in 0..trials {
            if run_attempt(&ctx, &cdts, &s, b, &c, &mut rng).is_some() {
                acc += 1;
            }
        }
        let rate = acc as f64 / trials as f64;
        // Deliberately broad deterministic-fixture check, not a proof of the law.
        let expected = ctx.lambda.lo.to_f64().powi(128);
        assert!(
            (rate - expected).abs() < 0.06,
            "acceptance rate {rate} vs {expected}"
        );
    }

    #[test]
    fn transported_parity_equals_challenge() {
        let ctx = ThetaCtx::new();
        let cdts = (
            Cdt::new(&ctx, PROPOSAL_W0, true),
            Cdt::new(&ctx, WS, false),
            Cdt::new(&ctx, WE, false),
        );
        let s = toy_secret(7);
        let b = energy(&s);
        let mut c = [false; N];
        for j in [0usize, 5, 17, 100, 255] {
            c[j] = true;
        }
        let mut rng = Xof::new(DOM_ATTEMPT, &[b"transport-parity"]);
        for _ in 0..50 {
            if let Some(z) = run_attempt(&ctx, &cdts, &s, b, &c, &mut rng) {
                for j in 0..N {
                    assert_eq!(z[j].rem_euclid(2) == 1, c[j], "parity at {j}");
                }
                return;
            }
        }
        panic!("no accepted attempt in 50 tries");
    }

    #[test]
    fn accepted_mean_shift_is_secret_free() {
        // The accepted law is D_c, independent of the key: the secret block of
        // accepted z should have near-zero mean even at challenged positions.
        let ctx = ThetaCtx::new();
        let cdts = (
            Cdt::new(&ctx, PROPOSAL_W0, true),
            Cdt::new(&ctx, WS, false),
            Cdt::new(&ctx, WE, false),
        );
        let s = toy_secret(31337);
        let b = energy(&s);
        let mut c = [false; N];
        for j in 0..128 {
            c[j] = true;
        }
        let mut rng = Xof::new(DOM_ATTEMPT, &[b"transport-zk"]);
        let mut sum = 0f64;
        let mut count = 0f64;
        let mut accepted = 0;
        for _ in 0..120 {
            if let Some(z) = run_attempt(&ctx, &cdts, &s, b, &c, &mut rng) {
                accepted += 1;
                for i in SEC..ERR {
                    sum += z[i] as f64;
                    count += 1.0;
                }
            }
        }
        assert!(accepted >= 40, "too few accepted attempts: {accepted}");
        let mean = sum / count;
        // per-coordinate sigma 44 => sem ~ 44/sqrt(count)
        let sem = 44.0 / count.sqrt();
        assert!(mean.abs() < 5.0 * sem, "mean {mean} vs sem {sem}");
    }

    #[test]
    fn sparse_rotation_matches_dense() {
        let s = toy_secret(77);
        let ss = SparseSecret::new(&s);
        let mut z = toy_secret(555);
        z[3] = 9;
        z[2000] = -4;
        for j in [0usize, 1, 64, 200, 255] {
            assert_eq!(dot_rotated(&z, &s, j), dot_rotated_sparse(&z, &ss, j));
            let mut zd = z;
            let mut zs = z;
            add_rotated(&mut zd, &s, j, -1);
            add_rotated_sparse(&mut zs, &ss, j, -1);
            assert_eq!(zd[..], zs[..]);
            add_rotated(&mut zd, &s, j, 1);
            add_rotated_sparse(&mut zs, &ss, j, 1);
            assert_eq!(zd[..], zs[..]);
        }
    }

    /// fg_ct must enclose the same value as the variable-time fg: the two
    /// intervals overlap (each brackets the true f, g).
    #[test]
    fn fg_ct_encloses_same_as_fg() {
        let ctx = ThetaCtx::new();
        for &b in &[PROPOSAL_SHELL_LO, 150_000u64, PROPOSAL_SHELL_HI] {
            let mut st = 0x243f6a8885a308d3u64;
            let mut rnd = move || {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                st
            };
            for tt in 0..3000 {
                let a: i64 = match tt % 4 {
                    0 => (rnd() % (1 << 30)) as i64 - (1 << 29),
                    1 => (rnd() % (4 * b)) as i64 - 2 * b as i64,
                    2 => (rnd() % 4000) as i64 - 2000,
                    _ => b as i64 + (rnd() % 128) as i64 - 64,
                };
                let (f, g) = ctx.fg(a, b);
                let (fc, gc) = ctx.fg_ct(a, b);
                // intervals overlap: fc.lo <= f.hi && f.lo <= fc.hi
                assert!(fc.lo.le(&f.hi) && f.lo.le(&fc.hi), "f mismatch a={a} b={b}");
                assert!(gc.lo.le(&g.hi) && g.lo.le(&gc.hi), "g mismatch a={a} b={b}");
            }
        }
    }

    /// The CT step decision must match the exact interval decision whenever
    /// the latter is decisive (Minus/Plus/Abort); ambiguous exact draws map
    /// to the CT `other` mask.
    #[test]
    fn step_ct_matches_exact() {
        let ctx = ThetaCtx::new();
        let mut st = 0xb7e151628aed2a6bu64;
        let mut rnd = move || {
            st ^= st << 13;
            st ^= st >> 7;
            st ^= st << 17;
            st
        };
        let mut n_minus = 0u64;
        let mut n_plus = 0u64;
        for t in 0..4000 {
            let b = [PROPOSAL_SHELL_LO, 60_000, 127_487, PROPOSAL_SHELL_HI][t % 4];
            let sc = StepCtx::new(&ctx, b);
            let a = (rnd() % (4 * b)) as i64 - 2 * b as i64;
            // draw the same 384-bit uniform for both paths
            let mut rng_a = Xof::new(DOM_ATTEMPT, &[b"ctstep", &rnd().to_le_bytes()]);
            let mut rng_b = Xof::new(
                DOM_ATTEMPT,
                &[b"ctstep", &{
                    let v = rnd();
                    v.to_le_bytes()
                }],
            );
            // use one rng cloned via same seed to feed identical draws
            let seed = rnd().to_le_bytes();
            let mut r1 = Xof::new(DOM_ATTEMPT, &[b"pair", &seed]);
            let mut r2 = Xof::new(DOM_ATTEMPT, &[b"pair", &seed]);
            let exact = step_decision_exact(&sc, a, &uniform_unit(&mut r1));
            let (minus, plus, other) = step_decision_ct(&sc, a, &mut r2);
            let _ = (&mut rng_a, &mut rng_b);
            match exact {
                Step::Minus => {
                    assert_eq!(minus, u64::MAX, "a={a} exact Minus");
                    n_minus += 1;
                }
                Step::Plus => {
                    assert_eq!(plus, u64::MAX, "a={a} exact Plus");
                    n_plus += 1;
                }
                Step::Abort | Step::Ambiguous => {
                    assert_eq!(other, u64::MAX, "a={a} exact {exact:?}")
                }
            }
        }
        assert!(
            n_minus > 100 && n_plus > 100,
            "decisions exercised m={n_minus} p={n_plus}"
        );
    }
}
