//! Exact CDT sampling of the discrete Gaussians theta^(w x^2).
//!
//! Tables hold interval enclosures of the unnormalized CDF over the canonical
//! symbol order 0, +1, -1, +2, -2, ... (or +2, -2, +4, -4, ... for the
//! even-support leading table). A draw compares a uniform 448-bit value below
//! the total mass Z against the CDF; a draw falling inside an enclosure gap
//! is reported as ambiguous and aborts the signing attempt. No global
//! statistical-distance claim is made for the finite-grid law.

use crate::ct::{ct_eq_limbs, ct_lt_limbs_be, ct_lt_u64, ct_select_i32};
use crate::fixed::{Fx, Iv};
use crate::hashes::Xof;

/// Byte operations used by the ordinary scalar and batched samplers.
pub(crate) trait SampleStream {
    fn fill(&mut self, out: &mut [u8]);
    fn u16(&mut self) -> u16;
}
impl SampleStream for Xof {
    #[inline(always)]
    fn fill(&mut self, out: &mut [u8]) {
        Xof::fill(self, out)
    }
    #[inline(always)]
    fn u16(&mut self) -> u16 {
        Xof::u16(self)
    }
}
use crate::theta::ThetaCtx;

pub struct Cdt {
    /// symbol values, canonical order
    values: Vec<i32>,
    stride: i32,
    /// 192-bit prefix of the total mass z.lo (rejection threshold).
    z3: [u64; 3],
    /// total mass enclosure
    pub z: Iv,
    /// number of random bits needed for a draw below 2^k >= z.hi
    draw_bits: usize,
    cold: std::sync::OnceLock<ColdCdf>,
    lazy_weight: u64,
    lazy_even: bool,
}

/// Public fallback data of Cdt; initialized on first fallback use.
/// The selected high-precision signing path never dereferences this object.
#[doc(hidden)]
pub struct ColdCdf {
    cum_lo: Vec<Fx>,
    cum_hi: Vec<Fx>,
    cum_pref: Vec<u64>,
    z_pref: u64,
    bounds3: Vec<[u64; 3]>,
    bp: [Vec<u64>; 3],
    pref16: Vec<Cell>,
}
impl core::ops::Deref for Cdt {
    type Target = ColdCdf;

    fn deref(&self) -> &ColdCdf {
        self.cold.get_or_init(|| {
            // ThetaCtx's power tables are immutable and determined by public constants.
            // Use the identical constructor and arithmetic, retaining its fallback.
            Self::new_with_cold(&ThetaCtx::new(), self.lazy_weight, self.lazy_even, true)
                .cold
                .into_inner()
                .expect("retained public fallback")
        })
    }
}

type Cell = u16;
const P16_ESCALATE: Cell = 0;
const P16_REJECT: Cell = 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class64 {
    Reject,
    NeedFull,
    Value(usize),
}

/// Classification of a full 64-bit draw prefix against the CDF prefixes;
/// exactly the decision structure of the u64 fast path.
// Explicit returns keep mutually exclusive selector branches structurally aligned.
#[allow(clippy::needless_return)]
// Keep explicit integer boundary arithmetic in the implementation and oracle.
#[allow(clippy::manual_div_ceil)]
fn classify64(cum_pref: &[u64], z_pref: u64, top: u64) -> Class64 {
    if top > z_pref {
        return Class64::Reject;
    }
    if top == z_pref {
        return Class64::NeedFull;
    }
    let mut lo = 0usize;
    let mut hi = cum_pref.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if cum_pref[mid] <= top {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo >= cum_pref.len() {
        return Class64::NeedFull; // tail region below z_pref
    }
    // require a full prefix step of clearance below, so that even the
    // enclosure gap (a few ulps) cannot reach into this draw window
    if lo > 0 && cum_pref[lo - 1] + 1 >= top {
        return Class64::NeedFull;
    }
    Class64::Value(lo)
}

/// Extract bits [shift, shift+64) of an Fx as a u64.
// Keep the integer predicate and its signedness explicit.
#[allow(clippy::manual_is_multiple_of)]
fn window64(v: &Fx, shift: usize) -> u64 {
    let s = shift / 64;
    let off = shift % 64;
    let lo = v.0[s] >> off;
    if off == 0 {
        lo
    } else {
        lo | v.0[s + 1] << (64 - off)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Draw {
    Value(i32),
    Ambiguous,
}

impl Cdt {
    #[inline(always)]
    fn prefix_cell(&self, prefix: usize) -> Cell {
        {
            self.pref16[prefix]
        }
    }
    #[inline(always)]
    fn cell_value(&self, v: Cell) -> i32 {
        {
            self.values[(v - 2) as usize]
        }
    }
    /// Read-only canonical symbols. Mutation would invalidate CDF certificates.
    pub fn values(&self) -> &[i32] {
        &self.values
    }
    /// Exact replacement for the full masked symbol scan, including its zero
    /// output for invalid/tail indices. idx is produced by a bounded CDF scan.
    // Keep explicit integer boundary arithmetic in the implementation and oracle.
    #[allow(clippy::manual_div_ceil)]
    fn decode_index_ct(&self, idx: u64) -> i32 {
        let magnitude = ((idx + 1) / 2) as i32 * self.stride;
        let signed = magnitude * (2 * (idx & 1) as i32 - 1);
        ct_select_i32(ct_lt_u64(idx, self.values.len() as u64), signed, 0)
    }
    /// Public parameter evidence, never signing state. Integers are Q64.384.
    pub fn write_snapshot(&self, name: &str, out: &mut impl std::io::Write) -> std::io::Result<()> {
        let hex = |x: &Fx| {
            x.0.iter()
                .rev()
                .map(|v| format!("{v:016x}"))
                .collect::<String>()
        };
        writeln!(
            out,
            "Z\t{name}\t{}\t{}\t{}",
            self.draw_bits,
            hex(&self.z.lo),
            hex(&self.z.hi)
        )?;
        for ((v, lo), hi) in self.values.iter().zip(&self.cum_lo).zip(&self.cum_hi) {
            writeln!(out, "G\t{name}\t{v}\t{}\t{}", hex(lo), hex(hi))?;
        }
        Ok(())
    }

    /// Build the table for weight w; if `even_only`, restrict support to even x.
    pub fn new(ctx: &ThetaCtx, w: u64, even_only: bool) -> Cdt {
        Self::new_with_cold(ctx, w, even_only, false)
    }
    #[allow(unused_variables)]
    // Keep explicit integer boundary arithmetic in the implementation and oracle.
    #[allow(clippy::manual_div_ceil)]
    fn new_with_cold(ctx: &ThetaCtx, w: u64, even_only: bool, retain_cold: bool) -> Cdt {
        let mut values = Vec::new();
        let mut weights: Vec<Iv> = Vec::new();
        // x = 0
        values.push(0);
        weights.push(Iv::exact(Fx::ONE));
        let step: i64 = if even_only { 2 } else { 1 };
        let mut x = step;
        loop {
            let t = ctx.pow(w * (x * x) as u64);
            if t.hi.le(&Fx::ULP) {
                break;
            }
            values.push(x as i32);
            weights.push(t);
            values.push(-x as i32);
            weights.push(t);
            x += step;
        }
        let mut cum_lo = Vec::with_capacity(values.len());
        let mut cum_hi = Vec::with_capacity(values.len());
        let mut acc = Iv::ZERO;
        for wgt in &weights {
            acc = acc.add(wgt);
            cum_lo.push(acc.lo);
            cum_hi.push(acc.hi);
        }
        // For x the first omitted positive coefficient, successive tail
        // ratios decrease and are at most theta^(w*(2*x*step+step^2)).
        // Bound both signs by 2*theta^(w*x^2)/(1-ratio), with outward rounding.
        let first = ctx.pow(w * (x * x) as u64);
        let ratio = ctx.pow(w * (2 * x * step + step * step) as u64);
        let denom = Iv::exact(Fx::ONE).sub_sat(&ratio);
        assert!(!denom.lo.is_zero());
        let tail = first.add(&first).mul(&denom.recip());
        let z = Iv {
            lo: acc.lo,
            hi: acc.hi.add(&tail.hi),
        };
        let draw_bits = z.hi.top_bit().unwrap() + 1;
        let shift = draw_bits - 64;
        let cum_pref: Vec<u64> = cum_lo.iter().map(|c| window64(c, shift)).collect();
        let z_pref = window64(&z.lo, shift);
        let win3 = |v: &Fx| -> [u64; 3] {
            [
                window64(v, draw_bits - 64),
                window64(v, draw_bits - 128),
                window64(v, draw_bits - 192),
            ]
        };
        // The 192-bit classifier aborts on the lower-prefix cell. Require
        // each whole enclosure to fit that cell, not merely its lower bound.
        for (lo, hi) in cum_lo.iter().zip(&cum_hi) {
            assert_eq!(win3(lo), win3(hi), "CDF enclosure crosses CT prefix cell");
        }
        assert_eq!(
            win3(&z.lo),
            win3(&z.hi),
            "normalizer crosses CT prefix cell"
        );
        let bounds3: Vec<[u64; 3]> = cum_lo.iter().map(&win3).collect();
        let z3 = win3(&z.lo);
        let bp = [
            bounds3.iter().map(|b| b[0]).collect(),
            bounds3.iter().map(|b| b[1]).collect(),
            bounds3.iter().map(|b| b[2]).collect(),
        ];
        let mut pref16 = vec![P16_ESCALATE; 1 << 16];
        for (c, cell) in pref16.iter_mut().enumerate() {
            let min = (c as u64) << 48;
            let max = min | 0x0000_ffff_ffff_ffff;
            *cell = match (
                classify64(&cum_pref, z_pref, min),
                classify64(&cum_pref, z_pref, max),
            ) {
                (Class64::Reject, Class64::Reject) => P16_REJECT,
                (Class64::Value(i), Class64::Value(j)) if i == j => {
                    u16::try_from(i + 2).expect("symbol index fits u16")
                }
                _ => P16_ESCALATE,
            };
        }
        Cdt {
            values,
            stride: step as i32,
            z3,
            z,
            draw_bits,
            lazy_weight: w,
            lazy_even: even_only,
            cold: {
                let data = ColdCdf {
                    cum_lo,
                    cum_hi,
                    cum_pref,
                    z_pref,
                    bounds3,
                    bp,
                    pref16,
                };
                let cell = std::sync::OnceLock::new();
                if retain_cold {
                    assert!(cell.set(data).is_ok());
                }
                cell
            },
        }
    }

    /// Constant-time classification of a 192-bit draw prefix (big-endian
    /// limbs) against the boundary table: fixed full scan, no data-dependent
    /// branches or accesses. Returns (symbol index as count, tie mask,
    /// strictly-above-z mask).
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    fn ct_classify(&self, u: &[u64; 3]) -> (u64, u64, u64) {
        {
            return crate::neon::ct_boundary_scan(
                &self.bp[0],
                &self.bp[1],
                &self.bp[2],
                &self.z3,
                u,
            );
        }
    }

    /// Scalar boundary scan; equality reference for the NEON path.
    #[allow(dead_code)]
    fn ct_classify_scalar(&self, u: &[u64; 3]) -> (u64, u64, u64) {
        let mut idx = 0u64;
        let mut tie = 0u64;
        for b in &self.bounds3 {
            let lt = ct_lt_limbs_be(u, b);
            idx += !lt & 1;
            // a draw equal to a truncated boundary prefix is ambiguous: the
            // true boundary (and its enclosure gap, ~2^-380) lies inside
            // [prefix, prefix + 1); everything else is decided.
            tie |= ct_eq_limbs(u, b);
        }
        let z_lt = ct_lt_limbs_be(u, &self.z3);
        let z_eq = ct_eq_limbs(u, &self.z3);
        tie |= z_eq;
        let above = !z_lt & !z_eq;
        (idx, tie, above)
    }

    /// Test hook: the scalar boundary classifier and the raw planes.
    pub fn ct_classify_scalar_ref(&self, u: &[u64; 3]) -> (u64, u64, u64) {
        self.ct_classify_scalar(u)
    }
    pub fn ct_planes(&self) -> (&[u64], &[u64], &[u64], &[u64; 3]) {
        (&self.bp[0], &self.bp[1], &self.bp[2], &self.z3)
    }

    /// Constant-time draw: exactly 24 bytes per
    /// iteration, full fixed-pattern scan of the boundary table, masked value
    /// selection. `abort` is all-ones on a boundary tie (probability
    /// ~ table_size * 2^-192) and must be folded into the attempt-abort mask
    /// by the caller; the returned value is then meaningless but computed
    /// with the same work. Redraws on rejection depend only on discarded
    /// uniforms against the public threshold.
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub fn sample_ct(&self, rng: &mut Xof) -> (i32, u64) {
        loop {
            let u = [rng.u64(), rng.u64(), rng.u64()];
            let (idx, tie, above) = self.ct_classify(&u);
            if above == u64::MAX {
                continue; // rejection region: public threshold, discarded draw
            }
            return (self.decode_index_ct(idx), tie);
        }
    }

    /// Uniform Fx in [0, 2^draw_bits) via masking; rejection to [0, z).
    /// Slow path; the fast path in `sample` only reaches this on prefix ties.
    // Keep explicit integer boundary arithmetic in the implementation and oracle.
    #[allow(clippy::manual_div_ceil)]
    fn uniform_below_z_full(&self, top: u64, rng: &mut impl SampleStream) -> Fx {
        // reconstruct: draw = top * 2^shift + (shift lower bits)
        let shift = self.draw_bits - 64;
        let mut limbs = [0u64; crate::fixed::LIMBS];
        let mut bytes = [0u8; 8 * crate::fixed::LIMBS];
        rng.fill(&mut bytes[..(shift + 7) / 8]);
        for (i, chunk) in bytes.chunks(8).enumerate() {
            limbs[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        for b in shift..(64 * crate::fixed::LIMBS) {
            limbs[b / 64] &= !(1u64 << (b % 64));
        }
        // add top << shift
        let s = shift / 64;
        let off = shift % 64;
        limbs[s] |= top << off;
        if off > 0 && s + 1 < crate::fixed::LIMBS {
            limbs[s + 1] |= top >> (64 - off);
        }
        Fx(limbs)
    }

    /// Full-width classification of a completed draw (slow path).
    /// None is ordinary rejection, not an unresolved boundary. In particular,
    /// the unused part of the normalizer's 64-bit prefix cell must redraw.
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    // Keep explicit integer boundary arithmetic in the implementation and oracle.
    #[allow(clippy::manual_div_ceil)]
    fn classify_full(&self, u: &Fx) -> Option<Draw> {
        if !u.lt(&self.z.hi) {
            return None;
        }
        if !u.lt(&self.z.lo) {
            return Some(Draw::Ambiguous);
        }
        let mut lo = 0usize;
        let mut hi = self.values.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.cum_lo[mid].le(u) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo >= self.values.len() {
            return Some(Draw::Ambiguous);
        }
        if lo > 0 && u.lt(&self.cum_hi[lo - 1]) {
            return Some(Draw::Ambiguous);
        }
        Some(Draw::Value(self.values[lo]))
    }

    /// Draw one sample. Fastest path: a 2-byte draw resolves via the
    /// 16-bit cell table; cell ties draw 6 more bytes and resolve against the
    /// 64-bit CDF prefixes; only 64-bit prefix ties (probability
    /// ~ table_size * 2^-64) draw the remaining bits and take the full-width
    /// path. The consumed random stream differs between paths, which is
    /// harmless: each coordinate's law is exact either way.
    pub fn sample(&self, rng: &mut Xof) -> Draw {
        self.sample_stream(rng)
    }

    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub(crate) fn sample_stream(&self, rng: &mut impl SampleStream) -> Draw {
        loop {
            let t16 = rng.u16();
            match self.prefix_cell(t16 as usize) {
                P16_REJECT => continue,
                P16_ESCALATE => {}
                v => return Draw::Value(self.cell_value(v)),
            }
            // complete the 64-bit prefix: 6 more bytes as its low 48 bits
            let mut low = [0u8; 8];
            rng.fill(&mut low[..6]);
            let top = ((t16 as u64) << 48) | u64::from_le_bytes(low);
            match classify64(&self.cum_pref, self.z_pref, top) {
                Class64::Reject => continue,
                Class64::Value(i) => return Draw::Value(self.values[i]),
                Class64::NeedFull => {
                    let u = self.uniform_below_z_full(top, rng);
                    match self.classify_full(&u) {
                        None => continue,
                        Some(d) => return d,
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    // the CT attempt uses sample_ct only
    // Explicit returns keep mutually exclusive selector branches structurally aligned.
    #[allow(clippy::needless_return)]
    pub(crate) fn sample_into_stream(
        &self,
        rng: &mut impl SampleStream,
        out: &mut [i32],
    ) -> Result<(), usize> {
        {
            for (i, slot) in out.iter_mut().enumerate() {
                match self.sample_stream(rng) {
                    Draw::Value(v) => *slot = v,
                    Draw::Ambiguous => return Err(i),
                }
            }
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{PROPOSAL_W0, WE, WS};

    #[test]
    fn canonical_decoder_and_random_tape_match_full_scan() {
        let theta = ThetaCtx::new();
        for (w, even) in [(PROPOSAL_W0, true), (WS, false), (WE, false)] {
            let c = Cdt::new(&theta, w, even);
            for idx in 0..=c.values.len() + 1 {
                assert_eq!(
                    c.decode_index_ct(idx as u64),
                    c.values.get(idx).copied().unwrap_or(0)
                );
            }
            let mut a = Xof::new(b"LILT-CDT-DECODE-TEST", &[&w.to_le_bytes()]);
            let mut b = Xof::new(b"LILT-CDT-DECODE-TEST", &[&w.to_le_bytes()]);
            for _ in 0..512 {
                let actual = c.sample_ct(&mut a);
                let reference = loop {
                    let u = [b.u64(), b.u64(), b.u64()];
                    let (idx, tie, above) = c.ct_classify_scalar(&u);
                    if above == u64::MAX {
                        continue;
                    }
                    let mut value = 0;
                    for (i, &v) in c.values.iter().enumerate() {
                        value = ct_select_i32(crate::ct::ct_eq_u64(i as u64, idx), v, value);
                    }
                    break (value, tie);
                };
                assert_eq!(actual, reference);
            }
            for _ in 0..8 {
                assert_eq!(a.u64(), b.u64());
            }
        }
    }

    #[test]
    fn full_normalizer_cell_distinguishes_rejection_from_ambiguity() {
        let theta = ThetaCtx::new();
        for (w, even) in [(PROPOSAL_W0, true), (WS, false), (WE, false)] {
            let cdt = Cdt::new(&theta, w, even);
            assert!(matches!(cdt.classify_full(&Fx::ZERO), Some(Draw::Value(0))));
            assert!(matches!(
                cdt.classify_full(&cdt.z.lo),
                Some(Draw::Ambiguous)
            ));
            assert!(cdt.classify_full(&cdt.z.hi).is_none());
            assert!(cdt.classify_full(&cdt.z.hi.add(&Fx::ULP)).is_none());
        }
    }

    #[test]
    // Keep the integer predicate and its signedness explicit.
    #[allow(clippy::manual_is_multiple_of)]
    fn ct_classify_matches_reference_search() {
        let ctx = ThetaCtx::new();
        for (w, even) in [(PROPOSAL_W0, true), (WS, false), (WE, false)] {
            let cdt = Cdt::new(&ctx, w, even);
            let mut st = 0xabad1deau64;
            let mut rnd = move || {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                st
            };
            for t in 0..30_000u32 {
                // mix random draws with exact-boundary and off-by-one draws
                let u: [u64; 3] = match t % 4 {
                    0 | 1 => [rnd(), rnd(), rnd()],
                    2 => cdt.bounds3[(rnd() as usize) % cdt.bounds3.len()],
                    _ => {
                        let mut b = cdt.bounds3[(rnd() as usize) % cdt.bounds3.len()];
                        // subtract 1 from the 192-bit value
                        if b[2] == 0 {
                            if b[1] == 0 {
                                b[0] = b[0].wrapping_sub(1);
                                b[1] = u64::MAX;
                            } else {
                                b[1] -= 1;
                            }
                            b[2] = u64::MAX;
                        } else {
                            b[2] -= 1;
                        }
                        b
                    }
                };
                let (idx, tie, above) = cdt.ct_classify(&u);
                // reference: linear comparison via u128/limb ordering
                let key = |a: &[u64; 3]| (a[0], a[1], a[2]);
                let ref_idx = cdt.bounds3.iter().filter(|b| key(b) <= key(&u)).count() as u64;
                let ref_tie =
                    cdt.bounds3.iter().any(|b| key(b) == key(&u)) || key(&cdt.z3) == key(&u);
                let ref_above = key(&u) > key(&cdt.z3);
                assert_eq!(idx, ref_idx);
                assert_eq!(tie == u64::MAX, ref_tie);
                assert_eq!(above == u64::MAX, ref_above);
            }
        }
    }

    /// Tape-only redraws: the words consumed by `sample_ct` are exactly
    /// three per rejected leading word plus three for the accepted one, where
    /// rejection is the public comparison against z3 on the tape alone; the
    /// returned symbol is the classification of the accepted word. This test
    /// makes 2304 calls (256, 1024 and 1024 with the three tables), so its total
    /// draw count is 3 * (2304 + R) words with R the tape's rejection count,
    /// independent of every sampled value.
    #[test]
    fn ct_sampler_draw_count_is_a_function_of_the_tape_only() {
        let theta = ThetaCtx::new();
        let tables = [
            Cdt::new(&theta, PROPOSAL_W0, true),
            Cdt::new(&theta, WS, false),
            Cdt::new(&theta, WE, false),
        ];
        let mut total_rejections = 0u64;
        for (t, cdt) in tables.iter().enumerate() {
            let mut live = Xof::new(b"LILT-CT-DRAW-COUNT-v1", &[&[t as u8]]);
            let mut shadow = Xof::new(b"LILT-CT-DRAW-COUNT-v1", &[&[t as u8]]);
            let calls = [256usize, 1024, 1024][t];
            for _ in 0..calls {
                let before = live.batch_test_consumed_pub();
                let (value, tie) = cdt.sample_ct(&mut live);
                let used = live.batch_test_consumed_pub() - before;
                // independent tape scan: count leading words strictly above z3
                let mut rejections = 0u64;
                let accepted = loop {
                    let u = [shadow.u64(), shadow.u64(), shadow.u64()];
                    let key = |a: &[u64; 3]| (a[0], a[1], a[2]);
                    if key(&u) > key(&cdt.z3) {
                        rejections += 1;
                        continue;
                    }
                    break u;
                };
                total_rejections += rejections;
                assert_eq!(used as u64, 24 * (rejections + 1), "bytes per call");
                let (idx, ref_tie, above) = cdt.ct_classify_scalar(&accepted);
                assert_eq!(above, 0);
                assert_eq!((value, tie), (cdt.decode_index_ct(idx), ref_tie));
            }
            assert_eq!(live.u64(), shadow.u64(), "streams stay aligned");
        }
        // acceptance probability z / 2^draw_bits lies in [1/2, 1): some
        // rejections must occur in 2304 draws, or the test proves nothing
        assert!(total_rejections > 0);
    }

    #[test]
    fn pref16_cells_match_classify64() {
        let ctx = ThetaCtx::new();
        for (w, even) in [(PROPOSAL_W0, true), (WS, false), (WE, false)] {
            let cdt = Cdt::new(&ctx, w, even);
            let mut st = 0xdeadbeefcafef00du64;
            let mut decided = 0u64;
            for _ in 0..200_000 {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                let top = st;
                let cell = cdt.prefix_cell((top >> 48) as usize);
                match cell {
                    P16_ESCALATE => {}
                    P16_REJECT => {
                        assert_eq!(classify64(&cdt.cum_pref, cdt.z_pref, top), Class64::Reject);
                        decided += 1;
                    }
                    v => {
                        assert_eq!(
                            classify64(&cdt.cum_pref, cdt.z_pref, top),
                            Class64::Value(
                                cdt.values
                                    .iter()
                                    .position(|&x| x == cdt.cell_value(v))
                                    .unwrap()
                            )
                        );
                        decided += 1;
                    }
                }
            }
            assert!(
                decided > 150_000,
                "cell table decides most draws ({decided})"
            );
        }
    }

    #[test]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn every_prefix_cell_and_sampler_tape_match_reference() {
        let theta = ThetaCtx::new();
        for (w, even) in [(PROPOSAL_W0, true), (WS, false), (WE, false)] {
            let c = Cdt::new(&theta, w, even);
            let mut old = vec![0u16; 1 << 16];
            for i in 0..1 << 16 {
                let lo = (i as u64) << 48;
                let hi = lo | 0x0000_ffff_ffff_ffff;
                old[i] = match (
                    classify64(&c.cum_pref, c.z_pref, lo),
                    classify64(&c.cum_pref, c.z_pref, hi),
                ) {
                    (Class64::Reject, Class64::Reject) => 1,
                    (Class64::Value(a), Class64::Value(b)) if a == b => (a + 2) as u16,
                    _ => 0,
                };
                match old[i] {
                    0 => assert_eq!(c.prefix_cell(i), P16_ESCALATE),
                    1 => assert_eq!(c.prefix_cell(i), P16_REJECT),
                    v => assert_eq!(c.cell_value(c.prefix_cell(i)), c.values[(v - 2) as usize]),
                }
            }
            let mut a = Xof::new(b"LILT-GAUSS-TAPE-v1", &[&w.to_le_bytes()]);
            let mut b = Xof::new(b"LILT-GAUSS-TAPE-v1", &[&w.to_le_bytes()]);
            for _ in 0..20000 {
                let reference = loop {
                    let prefix = b.u16();
                    match old[prefix as usize] {
                        1 => continue,
                        0 => {}
                        v => break Draw::Value(c.values[(v - 2) as usize]),
                    }
                    let mut low = [0u8; 8];
                    b.fill(&mut low[..6]);
                    let top = ((prefix as u64) << 48) | u64::from_le_bytes(low);
                    match classify64(&c.cum_pref, c.z_pref, top) {
                        Class64::Reject => continue,
                        Class64::Value(i) => break Draw::Value(c.values[i]),
                        Class64::NeedFull => {
                            let u = c.uniform_below_z_full(top, &mut b);
                            if let Some(d) = c.classify_full(&u) {
                                break d;
                            }
                        }
                    }
                };
                assert!(match (c.sample(&mut a), reference) {
                    (Draw::Value(x), Draw::Value(y)) => x == y,
                    (Draw::Ambiguous, Draw::Ambiguous) => true,
                    _ => false,
                });
                assert_eq!(
                    a.u64(),
                    b.u64(),
                    "continuation must match after every sample"
                );
            }
        }
    }
}
