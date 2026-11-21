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

/// The ordinary sampler's byte operations. Internal abstraction so
/// borrowed prefix storage does not change the public Xof or CDT API.
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
    alias: Option<crate::ct_alias::Alias>,
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
/// The rare-queue signing path never dereferences this object.
#[doc(hidden)]
pub struct ColdCdf {
    cum_lo: Vec<Fx>,
    cum_hi: Vec<Fx>,
    cum_pref: Vec<u64>,
    z_pref: u64,
    bounds3: Vec<[u64; 3]>,
    // Written by the constructor, read only by tests; kept so that the layout does not change.
    #[cfg_attr(not(test), allow(dead_code))]
    grouped: Vec<[u64; 4]>,
    tree: crate::ct_cdf_tree::Tree,
    #[cfg(target_arch = "aarch64")]
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
        self.pref16[prefix]
    }
    #[inline(always)]
    fn cell_value(&self, v: Cell) -> i32 {
        self.values[(v - 2) as usize]
    }
    /// Read-only canonical symbols. Mutation would invalidate CDF certificates.
    pub fn values(&self) -> &[i32] {
        &self.values
    }
    /// Test access to the 192-bit boundary table and normalizer prefix.
    #[cfg(test)]
    pub(crate) fn ct_tables(&self) -> (&[[u64; 3]], [u64; 3]) {
        (&self.bounds3, self.z3)
    }

    /// Exact replacement for the full masked symbol scan, including its zero
    /// output for invalid/tail indices. idx is produced by a bounded CDF scan.
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
    fn new_with_cold(ctx: &ThetaCtx, w: u64, even_only: bool, retain_cold: bool) -> Cdt {
        let mut values = Vec::new();
        let mut weights: Vec<Iv> = Vec::new();
        // x = 0
        values.push(0);
        weights.push(Iv::exact(Fx::ONE));
        let step = if even_only { 2 } else { 1 };
        // The cast fixes the integer type of the loop counter at this binding.
        #[allow(clippy::unnecessary_cast)]
        let mut x = step as i64;
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
        #[cfg(target_arch = "aarch64")]
        let _ = crate::ct_collapsed_alias::prepare(&bounds3, z3);
        let alias = crate::ct_alias::Alias::new(&bounds3, z3);
        let grouped = crate::ct_grouped_cdf::prepare(&bounds3);
        let tree = crate::ct_cdf_tree::Tree::new(&grouped);
        #[cfg(target_arch = "aarch64")]
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
            alias,

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
                    grouped,
                    tree,
                    #[cfg(target_arch = "aarch64")]
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
    fn ct_classify(&self, u: &[u64; 3]) -> (u64, u64, u64) {
        #[cfg(target_arch = "aarch64")]
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
    #[cfg_attr(target_arch = "aarch64", allow(dead_code))]
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
    #[cfg(target_arch = "aarch64")]
    pub fn ct_classify_scalar_ref(&self, u: &[u64; 3]) -> (u64, u64, u64) {
        self.ct_classify_scalar(u)
    }
    #[cfg(target_arch = "aarch64")]
    pub fn ct_planes(&self) -> (&[u64], &[u64], &[u64], &[u64; 3]) {
        (&self.bp[0], &self.bp[1], &self.bp[2], &self.z3)
    }

    /// Samples through the alias table when the context has one (`self.alias`) and
    /// through `sample_batch_ct_original` otherwise. Returns the abort mask.
    pub(crate) fn sample_batch_ct(&self, rng: &mut Xof, out: &mut [i32]) -> u64 {
        {
            if let Some(alias) = &self.alias {
                let mut draws = crate::ct_alias::new_words::<4>(out.len());
                let mut classified = crate::ct_alias::new_words::<2>(out.len());
                return self.sample_alias_into(alias, rng, out, &mut draws, &mut classified);
            }
            self.sample_batch_ct_original(rng, out)
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn sample_rare_into(
        &self,
        rng: &mut Xof,
        out: &mut [i32],
        records: &mut [u32; crate::scratch::RECORD_WORDS],
        work: &mut [u32; 2048],
    ) -> u64 {
        if out.is_empty() {
            return 0;
        }
        if out.len() > 1024 || out.len() % 4 != 0 {
            return self.sample_batch_ct(rng, out);
        }
        if self.alias.as_ref().and_then(|a| a.rare_parts()).is_none() {
            return self.sample_batch_ct(rng, out);
        }
        crate::ct_rarequeue::sample_erased(self, rng, out, records, work)
    }
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    pub(crate) fn sample_rare_body(
        &self,
        rng: &mut Xof,
        out: &mut [i32],
        records: &mut [u32; crate::scratch::RECORD_WORDS],
        work: &mut [u32; 2048],
    ) -> u64 {
        if let Some(parts) = crate::ct_collapsed_alias::for_z(self.z3) {
            let bad = crate::ct_collapsed_alias::sample(parts, &self.z3, rng, out, records, work);
            return crate::ct_rarequeue::decode_counts(out, self.stride, self.values.len(), bad);
        }
        // The safe outer entry validates the public shape before the C ABI.
        let parts = self
            .alias
            .as_ref()
            .and_then(|a| a.rare_parts())
            .expect("validated public rare table");
        let bad = crate::ct_rarequeue::sample(&parts, &self.z3, rng, out, records, work);
        crate::ct_rarequeue::decode_counts(out, self.stride, self.values.len(), bad)
    }

    fn sample_alias_into(
        &self,
        alias: &crate::ct_alias::Alias,
        rng: &mut Xof,
        out: &mut [i32],
        draws: &mut [[u64; 4]],
        classified: &mut [[u64; 2]],
    ) -> u64 {
        self.sample_alias_small_into(alias, rng, out, draws, classified)
    }

    /// Same public groups of eight accepted uniforms followed by column bits.
    /// Classification consumes no entropy and cannot affect later draws, so
    /// moving it between groups preserves every draw, tie, and stream suffix.
    fn sample_alias_small_into(
        &self,
        alias: &crate::ct_alias::Alias,
        rng: &mut Xof,
        out: &mut [i32],
        draws: &mut [[u64; 4]],
        classified: &mut [[u64; 2]],
    ) -> u64 {
        const CHUNK: usize = 16;
        if draws.len().min(classified.len()) < out.len().min(CHUNK) {
            let mut local_draws = zeroize::Zeroizing::new([[0u64; 4]; CHUNK]);
            let mut local_classified = zeroize::Zeroizing::new([[0u64; 2]; CHUNK]);
            return self.sample_alias_small_into(
                alias,
                rng,
                out,
                &mut *local_draws,
                &mut *local_classified,
            );
        }
        let mut tie = 0;
        for chunk in out.chunks_mut(CHUNK) {
            let n = chunk.len();
            tie |= self.sample_alias_whole_into(
                alias,
                rng,
                chunk,
                &mut draws[..n],
                &mut classified[..n],
            );
        }
        tie
    }

    fn sample_alias_whole_into(
        &self,
        alias: &crate::ct_alias::Alias,
        rng: &mut Xof,
        out: &mut [i32],
        draws: &mut [[u64; 4]],
        classified: &mut [[u64; 2]],
    ) -> u64 {
        let n = out.len();
        let draws = &mut draws[..n];
        let classified = &mut classified[..n];
        {
            for batch in draws.chunks_mut(8) {
                draw_recycled_high_batch(&self.z3, batch, rng);
                // Disjoint fresh bits, consumed after every accepted public
                // group. The last partial group consumes both words as well.
                // Fill the owned erased storage directly: returning u64
                // values can leave a compiler refill temporary outside
                // that storage.
                let mut columns = zeroize::Zeroizing::new([0u8; 16]);
                rng.fill(&mut *columns);
                for (i, u) in batch.iter_mut().enumerate() {
                    u[3] = u16::from_le_bytes([columns[2 * i], columns[2 * i + 1]]) as u64
                        & alias.column_mask();
                }
            }
            alias.classify_into(draws, classified);
            let mut tie = 0;
            for (dst, r) in out.iter_mut().zip(classified.iter()) {
                *dst = self.decode_index_ct(r[0]);
                tie |= r[1];
            }
            tie
        }
    }

    /// Same ordered draws and ties as repeated sample_ct. The only redraw
    /// branch uses the public normalizer and the rejected tape word.
    fn sample_batch_ct_original(&self, rng: &mut Xof, out: &mut [i32]) -> u64 {
        let mut draws = zeroize::Zeroizing::new(vec![[0u64; 3]; out.len()]);
        for u in draws.iter_mut() {
            loop {
                *u = [rng.u64(), rng.u64(), rng.u64()];
                let above = !ct_lt_limbs_be(u, &self.z3) & !ct_eq_limbs(u, &self.z3);
                if above != u64::MAX {
                    break;
                }
            }
        }
        let classified = self.tree.classify(&self.z3, &draws);
        let mut tie = 0;
        for (dst, r) in out.iter_mut().zip(classified.iter()) {
            *dst = self.decode_index_ct(r[0]);
            tie |= r[1];
        }
        tie
    }

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

    #[allow(dead_code)] // the CT attempt uses sample_ct only
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
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{DOM_ATTEMPT, PROPOSAL_W0, WE, WS};

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

    fn stats(w: u64, even: bool, n: usize) -> (f64, f64, i64) {
        let ctx = ThetaCtx::new();
        let cdt = Cdt::new(&ctx, w, even);
        let mut rng = Xof::new(DOM_ATTEMPT, &[b"cdt-test", &[w as u8, even as u8]]);
        let (mut s, mut s2) = (0f64, 0f64);
        let mut parity_odd = 0i64;
        for _ in 0..n {
            match cdt.sample(&mut rng) {
                Draw::Value(v) => {
                    s += v as f64;
                    s2 += (v as f64) * (v as f64);
                    parity_odd += (v & 1).abs() as i64;
                }
                Draw::Ambiguous => panic!("ambiguous draw in test (prob < 2^-370)"),
            }
        }
        (s / n as f64, s2 / n as f64, parity_odd)
    }

    #[test]
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
    /// returned symbol is the classification of the accepted word. The
    /// attempt-level count is fixed: 2304 calls (256 lead, 1024 secret, 1024
    /// error), so the total draw count is 3 * (2304 + R) words with R the
    /// tape's rejection count, independent of every sampled value.
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
    fn ct_sampler_moments_match_law() {
        let ctx = ThetaCtx::new();
        let cdt = Cdt::new(&ctx, WS, false);
        let mut rng = Xof::new(DOM_ATTEMPT, &[b"ct-moments"]);
        let n = 40_000;
        let (mut s, mut s2) = (0f64, 0f64);
        for _ in 0..n {
            let (v, abort) = cdt.sample_ct(&mut rng);
            assert_eq!(abort, 0, "tie probability is 2^-181; must not occur");
            s += v as f64;
            s2 += (v as f64) * (v as f64);
        }
        let mean = s / n as f64;
        let var = s2 / n as f64;
        assert!(mean.abs() < 1.5, "mean {mean}");
        assert!((var / 2129.600127551074 - 1.0).abs() < 0.05, "var {var}");
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

    #[test]
    fn secret_block_moments() {
        // Warm accepted scalar secret-cell variance.
        let (mean, var, _) = stats(WS, false, 40_000);
        assert!(mean.abs() < 1.5, "mean {mean}");
        assert!((var / 2129.600127551074 - 1.0).abs() < 0.05, "var {var}");
    }

    #[test]
    fn error_block_moments() {
        // Warm accepted scalar error-cell variance.
        let (mean, var, _) = stats(WE, false, 40_000);
        assert!(mean.abs() < 2.0, "mean {mean}");
        assert!((var / 3449.600206611657 - 1.0).abs() < 0.05, "var {var}");
    }

    #[test]
    fn leading_even_support() {
        // Warm leading-coordinate table: check the even support.
        let (mean, var, odd) = stats(PROPOSAL_W0, true, 20_000);
        assert_eq!(odd, 0, "even table must emit even values");
        assert!(mean.abs() < 0.2, "mean {mean}");
        // Directed finite-cell variance target, a statistical sanity check.
        assert!((var / 45.29097493489697 - 1.0).abs() < 0.05, "var {var}");
    }

    #[test]
    fn support_extent() {
        let ctx = ThetaCtx::new();
        let c = Cdt::new(&ctx, WS, false);
        let max = c.values.iter().cloned().max().unwrap();
        // Broad support-extent sanity interval for the warm constructor.
        assert!((1000..1100).contains(&max), "support max {max}");
    }
}

#[cfg(test)]
mod ct_batch_tests {
    use super::*;
    #[test]
    fn sorted_sampler_preserves_values_ties_and_stream_continuation() {
        let theta = ThetaCtx::new();
        for (w, even) in [
            (crate::params::PROPOSAL_W0, true),
            (crate::params::WS, false),
            (crate::params::WE, false),
        ] {
            let cdt = Cdt::new(&theta, w, even);
            for n in [0, 1, 31, 256, 1024] {
                let mut a = Xof::new(b"CT-GAUSS-BATCH-REPLAY", &[&w.to_le_bytes()]);
                let mut b = Xof::new(b"CT-GAUSS-BATCH-REPLAY", &[&w.to_le_bytes()]);
                let mut out = vec![0; n];
                let got = cdt.sample_batch_ct_original(&mut a, &mut out);
                let mut ties = 0;
                for value in out {
                    let (v, t) = cdt.sample_ct(&mut b);
                    assert_eq!(v, value);
                    ties |= t;
                }
                assert_eq!(got, ties);
                let mut aa = [0u8; 400];
                let mut bb = aa;
                a.fill(&mut aa);
                b.fill(&mut bb);
                assert_eq!(aa, bb);
            }
        }
    }
}

#[cfg(test)]
mod grouped_cdf_controls {
    use super::*;
    #[test]
    fn every_cdf_boundary_neighbor_and_group_matches_original_rank() {
        let theta = ThetaCtx::new();
        for (cdt, groups, capacity, draws) in [
            (
                Cdt::new(&theta, crate::params::PROPOSAL_W0, true),
                55,
                512,
                256,
            ),
            (Cdt::new(&theta, crate::params::WS, false), 744, 2048, 1024),
            (Cdt::new(&theta, crate::params::WE, false), 945, 2048, 1024),
        ] {
            assert_eq!(cdt.grouped.len(), groups);
            assert_eq!((groups + draws).next_power_of_two(), capacity);
            let mut queries = vec![[0; 3], [u64::MAX; 3]];
            for b in cdt.bounds3.iter().chain(core::iter::once(&cdt.z3)) {
                queries.push(*b);
                for step in [-1i128, 1] {
                    let mut u = *b;
                    let mut carry = step;
                    for k in (0..3).rev() {
                        let v = u[k] as i128 + carry;
                        u[k] = v as u64;
                        carry = v >> 64;
                    }
                    if carry == 0 {
                        queries.push(u);
                    }
                }
            }
            for q in queries.chunks(1024) {
                let got = crate::ct_grouped_cdf::classify(&cdt.grouped, &cdt.z3, q);
                assert_eq!(*cdt.tree.classify(&cdt.z3, q), *got);
                for (i, u) in q.iter().enumerate() {
                    let index = cdt.bounds3.iter().filter(|b| *b <= u).count() as u64;
                    let tie = 0u64.wrapping_sub(u64::from(cdt.bounds3.contains(u) || *u == cdt.z3));
                    assert_eq!(got[i], [index, tie]);
                }
            }
        }
    }
}

#[cfg(test)]
mod alias_stream_tests {
    use super::*;
    #[test]
    fn alias_stream_preserves_normalizer_and_declared_column_consumption() {
        let theta = ThetaCtx::new();
        for (w, even, name) in [
            (crate::params::PROPOSAL_W0, true, "lead"),
            (crate::params::WS, false, "sec"),
            (crate::params::WE, false, "err"),
        ] {
            let cdt = Cdt::new(&theta, w, even);
            let alias = cdt.alias.as_ref().unwrap();
            crate::ct_alias::tests::check_original_bounds(name, &cdt.bounds3, cdt.z3);
            for n in [0, 1, 7, 8, 9, 31, 256, 1024] {
                let mut a = Xof::new(b"CT-ALIAS-STREAM", &[&w.to_le_bytes()]);
                let mut b = Xof::new(b"CT-ALIAS-STREAM", &[&w.to_le_bytes()]);
                let mut out = vec![0; n];
                let got = cdt.sample_batch_ct(&mut a, &mut out);
                let mut want = Vec::new();
                let mut ties = 0;
                for count in (0..n).step_by(8).map(|i| (n - i).min(8)) {
                    let mut draws = Vec::new();
                    let mut bits = std::collections::VecDeque::new();
                    for _ in 0..count {
                        loop {
                            let high = {
                                let d = cdt.z3[0] as u128 + 1;
                                let mut r = 1u128 << 64;
                                let mut value = b.u64() as u128;
                                loop {
                                    if r >= d {
                                        if value < d {
                                            break value as u64;
                                        }
                                        value -= d;
                                        r -= d;
                                    }
                                    while r < d {
                                        if bits.is_empty() {
                                            let word = b.u64();
                                            for i in 0..64 {
                                                bits.push_back((word >> i) & 1);
                                            }
                                        }
                                        value = 2 * value + bits.pop_front().unwrap() as u128;
                                        r *= 2;
                                    }
                                }
                            };
                            let u = [high, b.u64(), b.u64()];
                            if u <= cdt.z3 {
                                draws.push([u[0], u[1], u[2], 0]);
                                break;
                            }
                        }
                    }
                    let columns = [b.u64(), b.u64()];
                    for (i, u) in draws.iter_mut().enumerate() {
                        u[3] = ((columns[i / 4] >> (16 * (i % 4))) as u16 as u64)
                            & alias.column_mask();
                        let r = alias.reference(*u);
                        want.push(cdt.decode_index_ct(r[0]));
                        ties |= r[1];
                    }
                }
                assert_eq!(out, want);
                assert_eq!(got, ties);
                let mut aa = [0u8; 400];
                let mut bb = aa;
                a.fill(&mut aa);
                b.fill(&mut bb);
                assert_eq!(aa, bb);
            }
        }
    }
}

#[cfg(test)]
mod exact_small_alias_tests {
    use super::*;
    #[test]
    fn all_shapes_preserve_values_ties_and_stream_suffix() {
        let ctx = crate::theta::ThetaCtx::new();
        for (weight, even) in [
            (crate::params::PROPOSAL_W0, true),
            (crate::params::WS, false),
            (crate::params::WE, false),
        ] {
            let cdt = Cdt::new(&ctx, weight, even);
            let alias = cdt.alias.as_ref().expect("shipping alias table");
            for n in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257, 1024] {
                for capacity in [0, 1, 15, 16, 32] {
                    let mut a = Xof::new(
                        b"exact-alias-streaming-test",
                        &[
                            &weight.to_le_bytes(),
                            &[even as u8],
                            &(n as u64).to_le_bytes(),
                        ],
                    );
                    let mut b = Xof::new(
                        b"exact-alias-streaming-test",
                        &[
                            &weight.to_le_bytes(),
                            &[even as u8],
                            &(n as u64).to_le_bytes(),
                        ],
                    );
                    let mut expected = vec![0; n];
                    let mut actual = vec![0; n];
                    let mut whole_draws = crate::ct_alias::new_words::<4>(n);
                    let mut whole_classified = crate::ct_alias::new_words::<2>(n);
                    let mut small_draws = crate::ct_alias::new_words::<4>(capacity);
                    let mut small_classified = crate::ct_alias::new_words::<2>(capacity);
                    let x = cdt.sample_alias_whole_into(
                        alias,
                        &mut a,
                        &mut expected,
                        &mut whole_draws,
                        &mut whole_classified,
                    );
                    let y = cdt.sample_alias_small_into(
                        alias,
                        &mut b,
                        &mut actual,
                        &mut small_draws,
                        &mut small_classified,
                    );
                    assert_eq!((expected, x), (actual, y), "n={n}, capacity={capacity}");
                    assert_eq!(
                        a.bytes::<211>(),
                        b.bytes::<211>(),
                        "suffix n={n}, capacity={capacity}"
                    );
                }
            }
        }
    }
}

#[inline(always)]
fn fill_owned_word(rng: &mut Xof, word: &mut u64) {
    // SAFETY: one initialized u64 occupies exactly eight bytes with no
    // padding; the exclusive borrow covers the complete byte view. All bit
    // patterns are valid. Conversion after the fill preserves stream order
    // on big-endian hosts too. The caller owns and erases this word.
    let bytes=
    // SAFETY: word is an exclusive initialized u64: all eight bytes are initialized, u8
    // requires alignment one, and every byte write leaves a valid u64. The byte borrow ends
    // before word is read again.
    unsafe {core::slice::from_raw_parts_mut(core::ptr::from_mut(word).cast::<u8>(),8)};
    rng.fill(bytes);
    *word = u64::from_le(*word);
}

/// Exact high-word Fast Dice Roller. Every emitted high word is uniform on
/// 0..=z[0], independently of its complete rejection/refill pattern. A group
/// owns one erased reservoir; unused bits are discarded before column draws.
fn draw_recycled_high_batch(z: &[u64; 3], batch: &mut [[u64; 4]], rng: &mut Xof) {
    let mut pool = zeroize::Zeroizing::new([0u64; 2]);
    let denominator = z[0] as u128 + 1;
    let mut done = 0;
    rng.consume_attempt_prefix(|bytes| recycle_from_prefix(z, batch, bytes, &mut pool, &mut done));
    for u in &mut batch[done..] {
        loop {
            fill_owned_word(rng, &mut u[0]);
            if u[0] > z[0] {
                let mut c = zeroize::Zeroizing::new(u[0] as u128 - denominator);
                let mut range = (1u128 << 64) - denominator;
                loop {
                    while range < denominator {
                        if pool[1] == 0 {
                            fill_owned_word(rng, &mut pool[0]);
                            pool[1] = 64;
                        }
                        *c = (*c << 1) | (pool[0] & 1) as u128;
                        range <<= 1;
                        pool[0] >>= 1;
                        pool[1] -= 1;
                    }
                    if *c < denominator {
                        u[0] = *c as u64;
                        break;
                    }
                    *c -= denominator;
                    range -= denominator;
                }
            }
            fill_owned_word(rng, &mut u[1]);
            fill_owned_word(rng, &mut u[2]);
            if crate::ct_alias::above_normalizer((&u[..3]).try_into().unwrap(), z) == 0 {
                break;
            }
        }
    }
}

/// Consume precisely the scalar recycling stream. An incomplete candidate is
/// rolled back to its starting byte and reservoir state, then the scalar path
/// resumes from that same point. Already completed draws remain committed.
#[inline(never)]
fn recycle_from_prefix(
    z: &[u64; 3],
    batch: &mut [[u64; 4]],
    bytes: &[u8],
    pool: &mut [u64; 2],
    done: &mut usize,
) -> usize {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    {
        // SAFETY: `z` is three words, `batch` is passed with its own row count, `bytes` with its
        // own length, `pool` is two words and `done` one `usize`: the extents the routine reads and
        // writes. The mutable borrows are distinct from one another and from the shared ones.
        unsafe {
            pretzel44_ct_recycle_prefix(
                z.as_ptr(),
                batch.as_mut_ptr().cast(),
                batch.len(),
                bytes.as_ptr(),
                bytes.len(),
                pool.as_mut_ptr(),
                core::ptr::from_mut(done),
            )
        }
    }
}

#[cfg(test)]
mod recycled_prefix_tests {
    use super::*;
    #[test]
    fn prefix_commit_or_rollback_matches_scalar_words_and_reservoir() {
        let theta = ThetaCtx::new();
        for (w, even) in [
            (crate::params::PROPOSAL_W0, true),
            (crate::params::WS, false),
            (crate::params::WE, false),
        ] {
            let z = Cdt::new(&theta, w, even).z3;
            let mut rng = Xof::new(b"recycle-prefix-test", &[&w.to_le_bytes()]);
            let mut bytes = [0u8; 1024];
            rng.fill(&mut bytes);
            for end in 0..=512 {
                let mut got = [[0u64; 4]; 8];
                let mut pool = [0u64; 2];
                let mut done = 0;
                let used = recycle_from_prefix(&z, &mut got, &bytes[..end], &mut pool, &mut done);
                let mut pos = 0;
                let mut reference_pool = [0u64; 2];
                for u in &got[..done] {
                    let mut read = || {
                        let word = u64::from_le_bytes(bytes[pos..pos + 8].try_into().unwrap());
                        pos += 8;
                        word
                    };
                    loop {
                        let d = z[0] as u128 + 1;
                        let mut h = read() as u128;
                        let mut range = 1u128 << 64;
                        loop {
                            if range >= d {
                                if h < d {
                                    break;
                                }
                                h -= d;
                                range -= d;
                            }
                            while range < d {
                                if reference_pool[1] == 0 {
                                    reference_pool = [read(), 64];
                                }
                                h = 2 * h + (reference_pool[0] & 1) as u128;
                                range *= 2;
                                reference_pool[0] >>= 1;
                                reference_pool[1] -= 1;
                            }
                        }
                        let v = [h as u64, read(), read()];
                        if v <= z {
                            assert_eq!(&u[..3], &v);
                            break;
                        }
                    }
                }
                assert_eq!(used, pos, "end={end}");
                assert_eq!(pool, reference_pool, "end={end}");
            }
        }
    }
}

#[cfg(all(
    target_arch = "aarch64",
    target_endian = "little",
    target_vendor = "apple"
))]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_ct_recycle_prefix\n.p2align 2\n_pretzel44_ct_recycle_prefix:\n",
        include_str!("ct_recycle_prefix.S")
    ),
    options(raw)
);
// SAFETY: contract of the assembly routine defined just above (`ct_recycle_prefix.S`, edited
// compiler output). It reads three `u64` at `z`, reads and writes two `u64` at `pool` and one
// `usize` at `done`, and reads `bytes` eight bytes at a time, each time after checking that eight
// bytes remain below `len`. While `*done < n` it writes the first three words of the 32-byte row
// `*done` of `batch`, so `batch` must have `n` rows and it returns at once when `*done >= n`. It
// saves x21 and x25 to x28 and x30 in a 48-byte frame that it clears, uses base AArch64
// instructions and one vector register copy, keeps no pointer and has no global state.
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
unsafe extern "C" {
    fn pretzel44_ct_recycle_prefix(
        z: *const u64,
        batch: *mut u64,
        n: usize,
        bytes: *const u8,
        len: usize,
        pool: *mut u64,
        done: *mut usize,
    ) -> usize;
}

#[cfg(all(target_arch = "aarch64", test))]
mod lazy_cdf_storage_tests {
    use super::*;
    #[test]
    fn production_rare_sampler_stays_lazy_and_fallback_is_identical() {
        let ctx = ThetaCtx::new();
        for (w, even, n) in [
            (crate::params::PROPOSAL_W0, true, 256),
            (crate::params::WS, false, 1024),
            (crate::params::WE, false, 1024),
        ] {
            let compact = Cdt::new(&ctx, w, even);
            let full = Cdt::new_with_cold(&ctx, w, even, true);
            assert!(compact.cold.get().is_none());
            assert!(full.cold.get().is_some());
            let mut a = Xof::new(b"lazy-cdf-exact-fixture", &[&w.to_le_bytes()]);
            let mut b = Xof::new(b"lazy-cdf-exact-fixture", &[&w.to_le_bytes()]);
            let mut ao = vec![0; n];
            let mut bo = vec![0; n];
            let mut records = [0u32; crate::scratch::RECORD_WORDS];
            let mut work = [0u32; 2048];
            assert_eq!(
                compact.sample_rare_into(&mut a, &mut ao, &mut records, &mut work),
                full.sample_rare_into(&mut b, &mut bo, &mut records, &mut work)
            );
            assert_eq!(ao, bo);
            assert_eq!(a.u64(), b.u64());
            assert!(
                compact.cold.get().is_none(),
                "production sampler initialized fallback"
            );
            let mut ca = Vec::new();
            let mut cb = Vec::new();
            compact.write_snapshot("same", &mut ca).unwrap();
            full.write_snapshot("same", &mut cb).unwrap();
            assert_eq!(ca, cb);
            assert!(compact.cold.get().is_some());
            assert_eq!(compact.bounds3, full.bounds3);
            assert_eq!(compact.cum_pref, full.cum_pref);
        }
    }
}

#[path = "keygen_cdt_static.rs"]
mod keygen_static_cdt;
