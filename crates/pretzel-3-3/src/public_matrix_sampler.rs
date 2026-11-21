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
    pub(crate) fn feed(
        &mut self,
        lane: usize,
        block: &[u8; RATE],
        out: &mut [[CompactPoly; ELL + 1]; M],
    ) {
        self.feed_source(
            lane,
            |pos| block[pos],
            |pos| eight_candidates(&block[pos..pos + 13]),
            out,
        );
    }
    pub(crate) fn feed_pair(
        &mut self,
        lane: usize,
        pair_lane: usize,
        pair: &[u64; 50],
        out: &mut [[CompactPoly; ELL + 1]; M],
    ) {
        assert!(pair_lane < 2);
        self.feed_source(
            lane,
            |pos| (pair[2 * (pos / 8) + pair_lane] >> (8 * (pos % 8))) as u8,
            |pos| {
                let word = |offset: usize| {
                    let index = 2 * (offset / 8) + pair_lane;
                    let shift = 8 * (offset % 8);
                    if shift == 0 {
                        pair[index]
                    } else {
                        (pair[index] >> shift) | (pair[index + 2] << (64 - shift))
                    }
                };
                let lo = word(pos);
                let hi = word(pos + 5);
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
            },
            out,
        );
    }
    fn feed_source(
        &mut self,
        lane: usize,
        byte_at: impl Fn(usize) -> u8,
        eight_at: impl Fn(usize) -> [i16; 8],
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
                let values = eight_at(pos);
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
            let byte = byte_at(pos);
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
// Two overlapping safe little-endian loads cover all 104 bits, without a
// padded over-read or heap allocation. Values stay in original stream order.
#[inline]
fn eight_candidates(bytes: &[u8]) -> [i16; 8] {
    debug_assert_eq!(bytes.len(), 13);
    let lo = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[5..13].try_into().unwrap());
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
impl Drop for Cursor {
    fn drop(&mut self) {
        self.acc.zeroize();
        self.bits.zeroize();
        self.used.zeroize();
    }
}
pub(crate) fn fill(
    mut next: impl FnMut() -> [[u8; RATE]; 2],
    out: &mut [[CompactPoly; ELL + 1]; M],
) {
    const { assert!(M > 0 && ELL > 0 && N == 256) };
    let mut cursors = [Cursor::new(), Cursor::new()];
    while cursors
        .iter()
        .enumerate()
        .any(|(lane, c)| !c.complete(lane))
    {
        let mut blocks = next();
        for lane in 0..2 {
            cursors[lane].feed(lane, &blocks[lane], out);
        }
        blocks.zeroize();
    }
}
pub(crate) fn scalar(seed: &[u8; 32], out: &mut [[CompactPoly; ELL + 1]; M]) {
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
#[cfg(test)]
mod tests {
    use super::*;
    fn packed(values: &[u16]) -> Vec<u8> {
        let mut bytes = vec![0u8; (13 * values.len() + 7) / 8];
        for (i, &v) in values.iter().enumerate() {
            for bit in 0..13 {
                bytes[(13 * i + bit) / 8] |= (((v >> bit) & 1) as u8) << ((13 * i + bit) % 8);
            }
        }
        bytes
    }

    fn reference_feed(
        c: &mut Cursor,
        lane: usize,
        block: &[u8; RATE],
        out: &mut [[CompactPoly; ELL + 1]; M],
    ) {
        for &byte in block {
            if c.used == lane_coefficients(lane) {
                break;
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
                        return;
                    }
                }
            }
        }
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
