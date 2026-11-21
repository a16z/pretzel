//! Public verifier only: independent SHAKE states share permutation lanes.
#[cfg(test)]
use super::RATE;
#[cfg(test)]
use super::{permute, sponge_permute, PublicReader, Sponge};
#[cfg(test)]
use crate::params::N;
#[cfg(test)]
use crate::{
    params::{M, SALT_BYTES},
    ring::Poly,
};
#[cfg(test)]
use zeroize::Zeroizing;

#[path = "public_pair_flat_arm.rs"]
mod flat_arm;

#[cfg(test)]
struct Pending<'a> {
    sponge: Sponge,
    segments: &'a [&'a [u8]],
    segment: usize,
    offset: usize,
    done: bool,
}
#[cfg(test)]
impl<'a> Pending<'a> {
    fn new(sponge: Sponge, segments: &'a [&'a [u8]]) -> Self {
        Self {
            sponge,
            segments,
            segment: 0,
            offset: 0,
            done: false,
        }
    }
    // Prepare one full absorption block or final padded block. Never permutes.
    fn prepare(&mut self) -> bool {
        assert!(!self.done);
        while self.segment < self.segments.len() {
            let input = self.segments[self.segment];
            if self.offset == input.len() {
                self.segment += 1;
                self.offset = 0;
                continue;
            }
            let count = (RATE - self.sponge.pos).min(input.len() - self.offset);
            let bytes = &input[self.offset..self.offset + count];
            unsafe {
                super::pretzel33_ct_sponge_xor(
                    self.sponge.state.as_mut_ptr(),
                    self.sponge.pos,
                    bytes.as_ptr(),
                    count,
                );
            }
            self.sponge.pos += count;
            self.offset += count;
            if self.sponge.pos == RATE {
                self.sponge.pos = 0;
                return false;
            }
        }
        self.sponge.pad();
        true
    }
}
#[cfg(test)]
fn pair(a: &mut [u64; 25], b: &mut [u64; 25]) {
    // Safe distinct mutable references guarantee nonoverlap and complete extents.
    // The Sponge/PublicReader owners keep their own cleanup.
    if super::available() {
        unsafe {
            flat_arm::permute(a, b);
        }
        return;
    }
    pair_fallback(a, b);
}
#[cfg(test)]
fn pair_fallback(a: &mut [u64; 25], b: &mut [u64; 25]) {
    // Initialized 400-byte public owner; fill it directly, without an array return.
    // Initialization and any compiler-generated copies remain emission costs.
    let mut lanes = Zeroizing::new([0u64; 50]);
    for i in 0..25 {
        lanes[2 * i] = a[i];
        lanes[2 * i + 1] = b[i];
    }
    permute(&mut lanes);
    for i in 0..25 {
        a[i] = lanes[2 * i];
        b[i] = lanes[2 * i + 1];
    }
}
#[cfg(test)]
fn alongside(state: &mut [u64; 25], other: &mut Pending<'_>) {
    if other.done {
        sponge_permute(state);
    } else {
        let final_block = other.prepare();
        pair(state, &mut other.sponge.state);
        other.done = final_block;
    }
}
#[cfg(test)]
struct PairedReader<'a> {
    reader: PublicReader,
    challenge: Pending<'a>,
}
#[cfg(test)]
impl<'a> PairedReader<'a> {
    fn new(mut dither: Pending<'_>, mut challenge: Pending<'a>) -> Self {
        while !dither.done {
            let final_block = dither.prepare();
            alongside(&mut dither.sponge.state, &mut challenge);
            dither.done = final_block;
        }
        let mut reader = PublicReader {
            state: dither.sponge.state,
            pos: 0,
        };
        Self::refresh_bytes(&mut reader);
        Self { reader, challenge }
    }
    fn refresh_bytes(reader: &mut PublicReader) {
        let _ = reader;
    }
    fn refill(reader: &mut PublicReader, challenge: &mut Pending<'_>) {
        alongside(&mut reader.state, challenge);
        Self::refresh_bytes(reader);
        reader.pos = 0;
    }
    fn uniform_into(&mut self, out: &mut [i32]) {
        let Self { reader, challenge } = self;
        reader.uniform_into_with(out, |r| Self::refill(r, challenge));
    }
    #[cfg(test)]
    fn read(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.reader.pos == RATE {
                Self::refill(&mut self.reader, &mut self.challenge);
            }
            let n = out.len().min(RATE - self.reader.pos);
            out[..n]
                .copy_from_slice(&self.reader.rate_bytes()[self.reader.pos..self.reader.pos + n]);
            self.reader.pos += n;
            out = &mut out[n..];
        }
    }
    fn finish_challenge(&mut self) -> [u8; 32] {
        while !self.challenge.done {
            let final_block = self.challenge.prepare();
            sponge_permute(&mut self.challenge.sponge.state);
            self.challenge.done = final_block;
        }
        let mut out = [0; 32];
        for (i, word) in out.chunks_exact_mut(8).enumerate() {
            word.copy_from_slice(&self.challenge.sponge.state[i].to_le_bytes());
        }
        out
    }
}
#[cfg(test)]
pub(crate) fn dither_and_challenge_into(
    dither: Sponge,
    challenge: Sponge,
    mu: &[u8; 64],
    rho: &[u8; SALT_BYTES],
    labels: &[u8],
    delta: &mut [Poly; M],
) -> [u8; 32] {
    let ml = (mu.len() as u64).to_le_bytes();
    let rl = (rho.len() as u64).to_le_bytes();
    let ul = (labels.len() as u64).to_le_bytes();
    let ds: [&[u8]; 2] = [&rl, rho];
    let cs: [&[u8]; 6] = [&ml, mu, &rl, rho, &ul, labels];
    let mut reader = PairedReader::new(Pending::new(dither, &ds), Pending::new(challenge, &cs));
    for p in delta.iter_mut() {
        reader.uniform_into(&mut p.0);
    }
    reader.finish_challenge()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prefix(n: usize, seed: u8) -> Sponge {
        let mut s = Sponge::new();
        let b: Vec<u8> = (0..n)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
            .collect();
        s.absorb(&b);
        s
    }
    fn reference(mut s: Sponge, segments: &[&[u8]]) -> PublicReader {
        for b in segments {
            s.absorb(b);
        }
        PublicReader::from_absorbed(s)
    }
    #[test]
    fn independent_lanes_partial_blocks_and_continuation() {
        for pos in [0, 1, 7, 95, 96, 97, 98, 135, 136, 271] {
            for len in [0, 1, 39, 40, 135, 136, 137, 1024, 1144] {
                let a = prefix(pos, 3);
                let b = prefix(271 - pos, 211);
                let input: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(53)).collect();
                let ds: [&[u8]; 3] = [b"", b"dither", &input];
                let cs: [&[u8]; 3] = [&input, b"", b"challenge"];
                let mut ar = reference(a.clone(), &ds);
                let mut br = reference(b.clone(), &cs);
                let mut paired = PairedReader::new(Pending::new(a, &ds), Pending::new(b, &cs));
                let (mut expected, mut got) = ([0u8; 4097], [0u8; 4097]);
                ar.read(&mut expected);
                paired.read(&mut got);
                assert_eq!(got, expected);
                let mut challenge = [0; 32];
                br.read(&mut challenge);
                assert_eq!(paired.finish_challenge(), challenge);
            }
        }
    }
    #[test]
    fn rejection_tail_and_exact_next_unread_byte() {
        let ds: [&[u8]; 1] = [b"dither"];
        let cs: [&[u8]; 1] = [b"challenge"];
        for pos in [0, 1, 2, 119, 120, 134, 135] {
            let mut paired = PairedReader::new(
                Pending::new(prefix(96, 7), &ds),
                Pending::new(prefix(98, 9), &cs),
            );
            let mut legacy = reference(prefix(96, 7), &ds);
            legacy.refill();
            // Force a full remainder of invalid13-bit candidates; no cutoff.
            paired.reader.rate_bytes_mut().fill(255);
            legacy.rate_bytes_mut().fill(255);
            paired.reader.pos = pos;
            legacy.pos = pos;
            let (mut a, mut b) = ([0; N * 4], [0; N * 4]);
            paired.uniform_into(&mut a);
            legacy.uniform_into(&mut b);
            assert_eq!(a, b);
            let (mut at, mut bt) = ([0; 273], [0; 273]);
            paired.read(&mut at);
            legacy.read(&mut bt);
            assert_eq!(at, bt);
            let mut cr = reference(prefix(98, 9), &cs);
            let mut digest = [0; 32];
            cr.read(&mut digest);
            assert_eq!(paired.finish_challenge(), digest);
        }
    }
    #[test]
    fn early_challenge_completion_and_short_dither() {
        let ds: [&[u8]; 1] = [b"d"];
        let long = [31u8; 4096];
        let cs: [&[u8]; 1] = [&long];
        let mut paired = PairedReader::new(
            Pending::new(prefix(1, 2), &ds),
            Pending::new(prefix(3, 4), &cs),
        );
        let mut cr = reference(prefix(3, 4), &cs);
        let mut want = [0; 32];
        cr.read(&mut want);
        assert_eq!(paired.finish_challenge(), want);
        let mut dr = reference(prefix(1, 2), &ds);
        let (mut a, mut b) = ([0; 555], [0; 555]);
        paired.read(&mut a);
        dr.read(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn caller_output_matches_reference_with_canaries() {
        #[repr(C)]
        struct Guarded {
            before: [u64; 4],
            delta: [Poly; M],
            after: [u64; 4],
        }
        for pos in [0, 1, 96, 98, 135] {
            for len in [0, 1, 135, 136, 137, 1024, 1144] {
                let mu = [29u8; 64];
                let rho = [71u8; SALT_BYTES];
                let labels: Vec<u8> = (0..len).map(|i| (i % 34) as u8).collect();
                let saved = labels.clone();
                let ml = (mu.len() as u64).to_le_bytes();
                let rl = (rho.len() as u64).to_le_bytes();
                let ul = (labels.len() as u64).to_le_bytes();
                let ds: [&[u8]; 2] = [&rl, &rho];
                let cs: [&[u8]; 6] = [&ml, &mu, &rl, &rho, &ul, &labels];
                let mut dr = reference(prefix(pos, 3), &ds);
                let mut cr = reference(prefix(135 - pos, 211), &cs);
                let mut expected = [Poly::ZERO; M];
                for p in &mut expected {
                    dr.uniform_into(&mut p.0);
                }
                let mut want = [0; 32];
                cr.read(&mut want);
                let mut out = Guarded {
                    before: [0x13579bdf2468ace0; 4],
                    delta: [Poly::ZERO; M],
                    after: [0xfedcba9876543210; 4],
                };
                for p in &mut out.delta {
                    p.0.fill(-1);
                }
                let got = dither_and_challenge_into(
                    prefix(pos, 3),
                    prefix(135 - pos, 211),
                    &mu,
                    &rho,
                    &labels,
                    &mut out.delta,
                );
                assert_eq!(got, want);
                for i in 0..M {
                    assert_eq!(out.delta[i].0, expected[i].0);
                }
                assert_eq!(out.before, [0x13579bdf2468ace0; 4]);
                assert_eq!(out.after, [0xfedcba9876543210; 4]);
                assert_eq!(labels, saved);
                assert_eq!(mu, [29u8; 64]);
                assert_eq!(rho, [71u8; SALT_BYTES]);
            }
        }
    }
    #[test]
    fn direct_flat_pair_matches_scalar_and_canaries() {
        // One backing object exercises adjacent owners with eight-byte sentinels;
        // second orientation swaps which distinct state occupies each SIMD lane.
        for seed in 0..64u64 {
            for swapped in [false, true] {
                let mut backing = [0x13579bdf2468ace0u64; 55];
                let (left, right) = backing[1..54].split_at_mut(27);
                let a: &mut [u64; 25] = (&mut left[..25]).try_into().unwrap();
                let b: &mut [u64; 25] = (&mut right[..25]).try_into().unwrap();
                for i in 0..25 {
                    a[i] = seed.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(i as u32) ^ i as u64;
                    b[i] = (!seed).rotate_right(i as u32).wrapping_add(i as u64 * 37);
                }
                if swapped {
                    core::mem::swap(a, b);
                }
                let (mut x, mut y) = (*a, *b);
                for _ in 0..3 {
                    keccak::f1600(&mut x);
                    keccak::f1600(&mut y);
                    pair(a, b);
                    assert_eq!(*a, x);
                    assert_eq!(*b, y);
                }
                for i in [0, 26, 27, 53, 54] {
                    assert_eq!(backing[i], 0x13579bdf2468ace0);
                }
            }
        }
    }
}
