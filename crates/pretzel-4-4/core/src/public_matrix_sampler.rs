//! Public-only two-stream sampler. Independent streams; no private sponge API.
use crate::{
    compact_ring::CompactPoly,
    params::{ELL, M, N, Q},
};
use zeroize::Zeroize;
pub(crate) const RATE: usize = 136;
// Whole polynomial interleaving: lane 0 owns even indices, lane 1 odd.
// Odd matrix sizes therefore require unequal whole-polynomial quotas.
#[inline]
// Keep explicit integer boundary arithmetic in the implementation and oracle.
#[allow(clippy::manual_div_ceil)]
fn lane_coefficients(lane: usize) -> usize {
    assert!(lane < 2);
    ((M * ELL + 1 - lane) / 2) * N
}
pub(crate) struct Cursor {
    acc: u32,
    bits: u32,
    used: usize,
}
impl Cursor {
    pub(crate) fn complete(&self, lane: usize) -> bool {
        self.used == lane_coefficients(lane)
    }
    pub(crate) fn new() -> Self {
        Self {
            acc: 0,
            bits: 0,
            used: 0,
        }
    }

    /// Public matrix bytes only, including key generation and secret import.
    pub(crate) fn feed(
        &mut self,
        lane: usize,
        block: &[u8; RATE],
        out: &mut [[CompactPoly; ELL + 1]; M],
    ) {
        #[cfg(test)]
        if SCALAR_ORACLE.with(|flag| flag.get()) {
            self.feed_scalar_oracle(lane, block, out);
            return;
        }
        self.feed_source(lane, &block[..], out);
    }

    /// Borrow one public SHAKE lane in place, including when the scheduler
    /// temporarily puts logical matrix lane zero in physical sponge lane one.
    pub(crate) fn feed_pair(
        &mut self,
        lane: usize,
        pair_lane: usize,
        pair: &[u64; 50],
        out: &mut [[CompactPoly; ELL + 1]; M],
    ) {
        assert!(pair_lane < 2);
        #[cfg(test)]
        if SCALAR_ORACLE.with(|flag| flag.get()) {
            let source = PairRate {
                pair,
                lane: pair_lane,
            };
            let block = zeroize::Zeroizing::new(core::array::from_fn(|pos| source.byte(pos)));
            self.feed_scalar_oracle(lane, &block, out);
            return;
        }
        self.feed_source(
            lane,
            &PairRate {
                pair,
                lane: pair_lane,
            },
            out,
        );
    }

    fn feed_source(
        &mut self,
        lane: usize,
        source: &(impl RateSource + ?Sized),
        out: &mut [[CompactPoly; ELL + 1]; M],
    ) {
        let limit = lane_coefficients(lane);
        assert!(self.used <= limit);
        let mut pos = 0;
        while pos < source.len() && self.used < limit {
            // Eight candidates consume 104 bits exactly. Never batch a quota
            // tail: scalar stopping can leave both residual bits and bytes.
            if self.bits == 0 && source.len() - pos >= 13 && limit - self.used >= 8 {
                let values = source.candidates(pos);
                let offset = self.used % N;
                if N - offset >= 8 {
                    let poly = 2 * (self.used / N) + lane;
                    let dst = &mut out[poly / ELL][poly % ELL + 1].0[offset..offset + 8];
                    self.used += store_eight(values, dst);
                } else {
                    // Only a polynomial boundary needs per-coefficient addressing.
                    for value in values {
                        if (value as i32) < Q {
                            let poly = 2 * (self.used / N) + lane;
                            out[poly / ELL][poly % ELL + 1].0[self.used % N] = value;
                            self.used += 1;
                        }
                    }
                }
                pos += 13;
                // The empty reservoir is unchanged after eight candidates.
                continue;
            }
            self.acc |= (source.byte(pos) as u32) << self.bits;
            self.bits += 8;
            pos += 1;
            if self.bits >= 13 {
                let value = (self.acc & 8191) as i16;
                self.acc >>= 13;
                self.bits -= 13;
                if (value as i32) < Q {
                    let poly = 2 * (self.used / N) + lane;
                    out[poly / ELL][poly % ELL + 1].0[self.used % N] = value;
                    self.used += 1;
                }
            }
        }
    }

    // Scalar rejection routine, reachable only in test builds.
    #[cfg(test)]
    pub(crate) fn feed_scalar_oracle(
        &mut self,
        lane: usize,
        block: &[u8; RATE],
        out: &mut [[CompactPoly; ELL + 1]; M],
    ) {
        let limit = lane_coefficients(lane);
        assert!(self.used <= limit);
        let mut pos = 0usize;
        while pos < RATE {
            if self.used == limit {
                return;
            }
            // Eight candidates occupy exactly 13 bytes. Enter only with an empty
            // reservoir and enough output capacity to process every candidate, so the
            // scalar cursor's early-stop state and fetched-byte extent are preserved.
            if self.bits == 0 && RATE - pos >= 13 && limit - self.used >= 8 {
                let values = eight_candidates(&block[pos..pos + 13]);
                if values.iter().all(|&v| (v as i32) < Q) && N - self.used % N >= 8 {
                    let poly = 2 * (self.used / N) + lane;
                    out[poly / ELL][poly % ELL + 1].0[self.used % N..self.used % N + 8]
                        .copy_from_slice(&values);
                    self.used += 8;
                } else {
                    for v in values {
                        if (v as i32) < Q {
                            let poly = 2 * (self.used / N) + lane;
                            out[poly / ELL][poly % ELL + 1].0[self.used % N] = v;
                            self.used += 1;
                        }
                    }
                }
                pos += 13;
                self.acc = 0;
                self.bits = 0;
                if self.used == limit {
                    return;
                }
                continue;
            }
            // Prelude, rate tail and final<8 accepted positions use the scalar path.
            let byte = block[pos];
            pos += 1;
            self.acc |= (byte as u32) << self.bits;
            self.bits += 8;
            while self.bits >= 13 {
                let v = (self.acc & 8191) as i16;
                self.acc >>= 13;
                self.bits -= 13;
                if (v as i32) < Q {
                    let poly = 2 * (self.used / N) + lane;
                    out[poly / ELL][poly % ELL + 1].0[self.used % N] = v;
                    self.used += 1;
                    if self.used == limit {
                        return;
                    }
                }
            }
        }
    }
}
// Numeric little-endian words avoid a rate-sized copy and work independently
// of the host byte order. All accesses stay within the 136-byte rate.
trait RateSource {
    fn len(&self) -> usize;
    fn byte(&self, pos: usize) -> u8;
    fn candidates(&self, pos: usize) -> [i16; 8];
}
impl RateSource for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
    fn byte(&self, pos: usize) -> u8 {
        self[pos]
    }
    fn candidates(&self, pos: usize) -> [i16; 8] {
        eight_candidates(&self[pos..pos + 13])
    }
}
struct PairRate<'a> {
    pair: &'a [u64; 50],
    lane: usize,
}
impl RateSource for PairRate<'_> {
    fn len(&self) -> usize {
        RATE
    }
    fn byte(&self, pos: usize) -> u8 {
        (self.pair[2 * (pos / 8) + self.lane] >> (8 * (pos % 8))) as u8
    }
    #[inline(always)]
    fn candidates(&self, pos: usize) -> [i16; 8] {
        debug_assert!(pos + 13 <= RATE);
        let index = 2 * (pos / 8) + self.lane;
        // Constant shifts let the compiler use immediate extraction and share
        // the aligned sponge words between both halves of the batch.
        match pos % 8 {
            0 => self.eight_at::<0>(index),
            1 => self.eight_at::<8>(index),
            2 => self.eight_at::<16>(index),
            3 => self.eight_at::<24>(index),
            4 => self.eight_at::<32>(index),
            5 => self.eight_at::<40>(index),
            6 => self.eight_at::<48>(index),
            7 => self.eight_at::<56>(index),
            _ => unreachable!(),
        }
    }
}
impl PairRate<'_> {
    #[inline(always)]
    fn eight_at<const SHIFT: u32>(&self, index: usize) -> [i16; 8] {
        let a = self.pair[index];
        let b = self.pair[index + 2];
        let lo = if SHIFT == 0 {
            a
        } else {
            (a >> SHIFT) | (b << (64 - SHIFT))
        };
        let hi = if SHIFT < 24 {
            (a >> (SHIFT + 40)) | (b << (24 - SHIFT))
        } else if SHIFT == 24 {
            b
        } else {
            let c = self.pair[index + 4];
            (b >> (SHIFT - 24)) | (c << (88 - SHIFT))
        };
        unpack_words(lo, hi)
    }
}

// Public-only scalar stores. Prefix counts depend on the candidates, not on
// the previous output position. Resolve the destination once per batch and
// advance the cursor once, without a shuffle table or a variable-length copy.
#[inline(always)]
fn store_eight(values: [i16; 8], dst: &mut [i16]) -> usize {
    assert_eq!(dst.len(), 8);
    if values.iter().all(|&value| (value as i32) < Q) {
        dst.copy_from_slice(&values);
        return 8;
    }
    let keep = values.map(|value| usize::from((value as i32) < Q));
    let p01 = keep[0] + keep[1];
    let p23 = keep[2] + keep[3];
    let p45 = keep[4] + keep[5];
    let p03 = p01 + p23;
    let p05 = p03 + p45;
    let offsets = [
        0,
        keep[0],
        p01,
        p01 + keep[2],
        p03,
        p03 + keep[4],
        p05,
        p05 + keep[6],
    ];
    for i in 0..8 {
        if keep[i] != 0 {
            // SAFETY: offsets[i] counts accepted candidates strictly before i,
            // so offsets[i] <= i < 8, and dst has exactly eight elements.
            // Rejected candidates perform no write, preserving the unused tail.
            unsafe { *dst.get_unchecked_mut(offsets[i]) = values[i] };
        }
    }
    p05 + keep[6] + keep[7]
}

#[inline]
fn unpack_words(lo: u64, hi: u64) -> [i16; 8] {
    [
        (lo & 8191) as i16,
        ((lo >> 13) & 8191) as i16,
        ((lo >> 26) & 8191) as i16,
        ((lo >> 39) & 8191) as i16,
        ((hi >> 12) & 8191) as i16,
        ((hi >> 25) & 8191) as i16,
        ((hi >> 38) & 8191) as i16,
        ((hi >> 51) & 8191) as i16,
    ]
}

// Two overlapping safe little-endian loads cover all 104 bits, without a
// padded over-read or heap allocation. Values stay in original stream order.
#[inline]
fn eight_candidates(bytes: &[u8]) -> [i16; 8] {
    debug_assert_eq!(bytes.len(), 13);
    let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[5..13].try_into().unwrap());
    unpack_words(lo, hi)
}
impl Drop for Cursor {
    fn drop(&mut self) {
        self.acc.zeroize();
        self.bits.zeroize();
        self.used.zeroize();
    }
}
/// Both public producers share the same in-place paired-state loop.
pub(crate) fn fill_pair(
    pair: &mut [u64; 50],
    mut permute: impl FnMut(&mut [u64; 50]),
    out: &mut [[CompactPoly; ELL + 1]; M],
) {
    let mut cursors = [Cursor::new(), Cursor::new()];
    while cursors
        .iter()
        .enumerate()
        .any(|(lane, c)| !c.complete(lane))
    {
        permute(pair);
        for (lane, cursor) in cursors.iter_mut().enumerate() {
            cursor.feed_pair(lane, lane, pair, out);
        }
    }
}

/// Lockstep portable producer: squeeze both public lanes in their original order.
fn fill(mut next: impl FnMut() -> [[u8; RATE]; 2], out: &mut [[CompactPoly; ELL + 1]; M]) {
    const {
        assert!(M > 0 && ELL > 0 && N == 256);
    }
    let mut cursors = [Cursor::new(), Cursor::new()];
    while cursors
        .iter()
        .enumerate()
        .any(|(lane, c)| !c.complete(lane))
    {
        let mut blocks = zeroize::Zeroizing::new(next());
        for lane in 0..2 {
            cursors[lane].feed(lane, &blocks[lane], out);
        }
        blocks.zeroize();
    }
}
pub(crate) fn public_lockstep(seed: &[u8; 32], out: &mut [[CompactPoly; ELL + 1]; M]) {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    let mut readers = core::array::from_fn::<_, 2, _>(|lane| {
        let mut s = Shake256::default();
        s.update(crate::direct_ntt_profile::MATRIX_DOMAIN);
        s.update(&32u64.to_le_bytes());
        s.update(seed);
        s.update(&1u64.to_le_bytes());
        s.update(&[lane as u8]);
        s.finalize_xof()
    });
    fill(
        || {
            core::array::from_fn(|lane| {
                let mut b = [0u8; RATE];
                readers[lane].read(&mut b);
                b
            })
        },
        out,
    );
}
// The scalar rejection routine is available only to differential tests.
#[cfg(test)]
pub(crate) fn scalar(seed: &[u8; 32], out: &mut [[CompactPoly; ELL + 1]; M]) {
    with_scalar_oracle(|| public_lockstep(seed, out));
}
/// Public-only portable SHAKE producer, sampling each rate buffer in place.
pub(crate) fn public(seed: &[u8; 32], out: &mut [[CompactPoly; ELL + 1]; M]) {
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    for lane in 0..2 {
        let mut sponge = Shake256::default();
        sponge.update(crate::direct_ntt_profile::MATRIX_DOMAIN);
        sponge.update(&32u64.to_le_bytes());
        sponge.update(seed);
        sponge.update(&1u64.to_le_bytes());
        sponge.update(&[lane as u8]);
        let mut reader = sponge.finalize_xof();
        let mut cursor = Cursor::new();
        let mut block = zeroize::Zeroizing::new([0; RATE]);
        while !cursor.complete(lane) {
            reader.read(&mut block[..]);
            cursor.feed(lane, &block, out);
        }
    }
}

// Test-only scoped selection of the scalar routine, never a runtime flag.
#[cfg(test)]
std::thread_local! {
    static SCALAR_ORACLE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn with_scalar_oracle<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            SCALAR_ORACLE.with(|flag| flag.set(self.0));
        }
    }
    let _reset = Reset(SCALAR_ORACLE.with(|flag| flag.replace(true)));
    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Keep explicit integer boundary arithmetic in the implementation and oracle.
    #[allow(clippy::manual_div_ceil)]
    pub(super) fn packed(values: &[u16]) -> Vec<u8> {
        let mut bytes = vec![0u8; (13 * values.len() + 7) / 8];
        for (i, &v) in values.iter().enumerate() {
            for bit in 0..13 {
                bytes[(13 * i + bit) / 8] |= (((v >> bit) & 1) as u8) << ((13 * i + bit) % 8);
            }
        }
        bytes
    }

    pub(super) fn reference_feed(
        c: &mut Cursor,
        lane: usize,
        block: &[u8],
        out: &mut [[CompactPoly; ELL + 1]; M],
    ) -> usize {
        for (pos, &byte) in block.iter().enumerate() {
            if c.used == lane_coefficients(lane) {
                return pos;
            }
            c.acc |= (byte as u32) << c.bits;
            c.bits += 8;
            while c.bits >= 13 {
                let v = (c.acc & 8191) as i16;
                c.acc >>= 13;
                c.bits -= 13;
                if (v as i32) < Q {
                    let poly = 2 * (c.used / N) + lane;
                    out[poly / ELL][poly % ELL + 1].0[c.used % N] = v;
                    c.used += 1;
                    if c.used == lane_coefficients(lane) {
                        return pos + 1;
                    }
                }
            }
        }
        block.len()
    }
    #[test]
    fn matrix13_eight_exhaustive_extraction() {
        for position in 0..8 {
            for value in 0u16..8192 {
                let mut values = [8191u16; 8];
                values[position] = value;
                let bytes = packed(&values);
                assert_eq!(bytes.len(), 13);
                assert_eq!(eight_candidates(&bytes), values.map(|v| v as i16));
            }
        }
    }
    #[test]
    fn matrix13_eight_exact_scalar_state_and_boundaries() {
        for lane in 0..2 {
            for bits in 0..13u32 {
                for used in [
                    0usize,
                    1,
                    248,
                    249,
                    255,
                    256,
                    510,
                    511,
                    lane_coefficients(lane) - 9,
                    lane_coefficients(lane) - 8,
                    lane_coefficients(lane) - 7,
                    lane_coefficients(lane) - 1,
                    lane_coefficients(lane),
                ] {
                    for pattern in 0..8u8 {
                        let acc = if bits == 0 {
                            0
                        } else {
                            (0x19a5u32 >> (pattern % 5)) & ((1 << bits) - 1)
                        };
                        let block = core::array::from_fn(|i| match pattern {
                            0 => 0,
                            1 => 255,
                            2 => 0x1e,
                            3 => 0xe0,
                            _ => (i as u8)
                                .wrapping_mul(37)
                                .wrapping_add(pattern.wrapping_mul(17)),
                        });
                        let mut a = Cursor { acc, bits, used };
                        let mut b = Cursor { acc, bits, used };
                        let mut out = [[CompactPoly([37; N]); ELL + 1]; M];
                        let mut reference = out;
                        a.feed(lane, &block, &mut out);
                        reference_feed(&mut b, lane, &block, &mut reference);
                        assert_eq!((a.acc, a.bits, a.used), (b.acc, b.bits, b.used));
                        for row in 0..M {
                            for col in 0..=ELL {
                                assert_eq!(out[row][col].0, reference[row][col].0);
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn matrix13_exhaustive_symbols_and_rate_reservoir() {
        // Bit-by-bit packer is independent of the streaming reservoir.
        for offset in 0..13 {
            let mut values = vec![8191; offset];
            values.extend(0u16..8192);
            values.extend(vec![0; 2048]);
            let bytes = packed(&values);
            let mut out = [[CompactPoly::ZERO; ELL + 1]; M];
            let mut c = Cursor::new();
            for chunk in bytes.chunks(RATE) {
                let mut block = [0; RATE];
                block[..chunk.len()].copy_from_slice(chunk);
                c.feed(0, &block, &mut out);
                if c.used == lane_coefficients(0) {
                    break;
                }
            }
            assert_eq!(c.used, lane_coefficients(0));
            for i in 0..lane_coefficients(0) {
                let poly = 2 * (i / N);
                assert_eq!(out[poly / ELL][poly % ELL + 1].0[i % N], i as i16);
            }
        }
        for v in 0u16..8192 {
            let mut values = vec![v];
            values.extend(vec![0; 2048]);
            let bytes = packed(&values);
            let mut block = [0; RATE];
            block.copy_from_slice(&bytes[..RATE]);
            let mut out = [[CompactPoly::ZERO; ELL + 1]; M];
            let mut c = Cursor::new();
            c.feed(0, &block, &mut out);
            assert_eq!(out[0][1].0[0], if v < 7681 { v as i16 } else { 0 });
        }
    }
    #[test]
    // Keep explicit integer boundary arithmetic in the implementation and oracle.
    #[allow(clippy::manual_div_ceil)]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn matrix13_unequal_tails_and_preserved_b() {
        for delay in [0usize, 1, 7, 41] {
            let mut calls = 0;
            let mut out = [[CompactPoly::ZERO; ELL + 1]; M];
            for r in 0..M {
                out[r][0] = CompactPoly([37; N]);
            }
            fill(
                || {
                    let i = calls;
                    calls += 1;
                    [[0; RATE], if i < delay { [255; RATE] } else { [0; RATE] }]
                },
                &mut out,
            );
            // A rejected all-ones prefix can straddle a block boundary. Accepted zero
            // values after its boundary need not be all zero, so compare scalar bits.
            assert!(calls >= (13 * lane_coefficients(1) + 8 * RATE - 1) / (8 * RATE) + delay);
            let mut raw = vec![255u8; delay * RATE];
            raw.extend(vec![0u8; calls * RATE]);
            let mut expected = Vec::new();
            for candidate in 0..raw.len() * 8 / 13 {
                let mut v = 0u16;
                for bit in 0..13 {
                    let k = 13 * candidate + bit;
                    v |= (((raw[k / 8] >> (k % 8)) & 1) as u16) << bit;
                }
                if v < 7681 {
                    expected.push(v as i16);
                }
                if expected.len() == lane_coefficients(1) {
                    break;
                }
            }
            assert_eq!(expected.len(), lane_coefficients(1));
            for i in 0..lane_coefficients(1) {
                let poly = 2 * (i / N) + 1;
                assert_eq!(out[poly / ELL][poly % ELL + 1].0[i % N], expected[i]);
            }
            for r in 0..M {
                assert_eq!(out[r][0].0, [37; N]);
                for c in 1..=ELL {
                    assert!(out[r][c].0.iter().all(|&v| v >= 0 && (v as i32) < Q));
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "public_matrix_sampler_tests.rs"]
mod sampler_tests;
