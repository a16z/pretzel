//! Pretzel-(5,5) public preparation. Never an exposed sponge-state oracle.
#[path = "../../pretzel-4-4/core/src/public_dither_destination.rs"]
pub(crate) mod dither_destination;
use super::FastSponge;
// These imports are used only by the reference paths.
#[allow(unused_imports)]
use crate::direct_ntt_profile::matrix13::Cursor;
use crate::{
    compact_ring::CompactPoly,
    dither_frame::{FrameError, DITHER_COEFFICIENTS, EXPANSION_CANDIDATES},
    params::{ELL, M, N, Q},
};
use zeroize::{Zeroize, Zeroizing};
const RATE: usize = 136;
const _: () = assert!(
    M == 5
        && ELL == 5
        && N == 256
        && Q == 7681
        && crate::params::CORE_PK_BYTES == 2112
        && crate::params::PK_BYTES == 2144
);
type Rows = [[CompactPoly; ELL + 1]; M];
const DD: &[u8] = b"LILT-DITH-KEY-v1";
const DM: &[u8] = b"LILT-AC-3:msg";
const DC: &[u8] = b"LILT-AC-3:chal";
#[derive(Clone)]
struct PublicState {
    words: Zeroizing<[u64; 25]>,
    pos: usize,
}
impl PublicState {
    fn new() -> Self {
        Self {
            words: Zeroizing::new([0; 25]),
            pos: 0,
        }
    }
    // Keep the integer predicate and its signedness explicit.
    #[allow(clippy::manual_is_multiple_of)]
    fn absorb(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let n = bytes.len().min(RATE - self.pos);
            let mut i = 0;
            while i < n && (self.pos + i) % 8 != 0 {
                let p = self.pos + i;
                self.words[p / 8] ^= (bytes[i] as u64) << (8 * (p % 8));
                i += 1;
            }
            while i + 8 <= n {
                self.words[(self.pos + i) / 8] ^=
                    u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
                i += 8;
            }
            while i < n {
                let p = self.pos + i;
                self.words[p / 8] ^= (bytes[i] as u64) << (8 * (p % 8));
                i += 1;
            }
            self.pos += n;
            bytes = &bytes[n..];
            if self.pos == RATE {
                super::sponge_permute(&mut self.words);
                self.pos = 0;
            }
        }
    }
    fn part(&mut self, bytes: &[u8]) {
        self.absorb(&(bytes.len() as u64).to_le_bytes());
        self.absorb(bytes);
    }
    fn common(core: &[u8]) -> Self {
        assert_eq!(core.len(), 2112);
        let mut s = Self::new();
        s.part(crate::direct_ntt_profile::PROFILE);
        s.part(core);
        assert_eq!(s.pos, 102);
        s
    }
    fn branch(mut self, domain: &[u8], seed: &[u8]) -> Self {
        assert_eq!(seed.len(), 32);
        assert!([DD, DM, DC].contains(&domain));
        self.absorb(domain);
        if domain == DD {
            self.part(seed)
        } else {
            self.absorb(seed)
        };
        self
    }
    fn owner(&self) -> FastSponge {
        FastSponge::from_common_public_state(&self.words, self.pos)
    }
    fn pad(&mut self) {
        self.words[self.pos / 8] ^= 0x1fu64 << (8 * (self.pos % 8));
        self.words[16] ^= 0x80u64 << 56;
    }
}
impl Drop for PublicState {
    fn drop(&mut self) {
        self.words.zeroize();
        self.pos.zeroize();
        #[cfg(test)]
        ERASE_EVENTS.with(|n| {
            assert!(self.words.iter().all(|&w| w == 0) && self.pos == 0);
            n.set(n.get() + 1);
        });
    }
}
#[cfg(test)]
std::thread_local! {static ERASE_EVENTS:core::cell::Cell<usize>=const{core::cell::Cell::new(0)};}
fn split(body: &[u8]) -> (&[u8], &[u8]) {
    assert_eq!(body.len(), 2144);
    body.split_at(2112)
}
pub(crate) fn prefix(domain: &[u8], body: &[u8]) -> FastSponge {
    let (core, seed) = split(body);
    PublicState::common(core).branch(domain, seed).owner()
}
#[allow(dead_code)]
pub(crate) fn prefixes(body: &[u8]) -> [FastSponge; 2] {
    let (core, seed) = split(body);
    let c = PublicState::common(core);
    [
        c.clone().branch(DM, seed).owner(),
        c.branch(DC, seed).owner(),
    ]
}
pub(crate) fn hash<const L: usize>(domain: &[u8], body: &[u8], parts: &[&[u8]]) -> [u8; L] {
    prefix(domain, body).hash(parts)
}
fn rate(words: &[u64; 25], out: &mut [u8]) {
    assert!(out.len() <= RATE);
    for (chunk, word) in out.chunks_mut(8).zip(words.iter()) {
        let bytes = word.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

fn decode_into(
    mut fill: impl FnMut(&mut [u8]),
    out: &mut [i32; DITHER_COEFFICIENTS],
) -> Result<(), FrameError> {
    let mut block = Zeroizing::new([0u8; RATE]);
    let (mut pos, mut end, mut fetched, mut used) = (0, 0, 0, 0);
    for _ in 0..EXPANSION_CANDIDATES {
        if pos == end {
            end = (2 * EXPANSION_CANDIDATES - fetched).min(RATE);
            fill(&mut block[..end]);
            pos = 0;
            fetched += end;
        }
        let v = u16::from_le_bytes([block[pos], block[pos + 1]]) & 8191;
        pos += 2;
        if v < 7681 {
            out[used] = v as i32;
            used += 1;
            if used == out.len() {
                return Ok(());
            }
        }
    }
    Err(FrameError::DitherExhausted)
}
#[cfg(test)]
pub(crate) fn dither(
    core: &[u8],
    seed: &[u8; 32],
    out: &mut [i32; DITHER_COEFFICIENTS],
) -> Result<(), FrameError> {
    if core.len() != 2112 {
        return Err(FrameError::KeyLength);
    }
    let mut s = PublicState::common(core).branch(DD, seed);
    s.pad();
    decode_into(
        |block| {
            super::sponge_permute(&mut s.words);
            rate(&s.words, block)
        },
        out,
    )
}
pub(crate) fn without_matrix(
    body: &[u8],
    out: &mut [i32; DITHER_COEFFICIENTS],
) -> Result<[FastSponge; 2], FrameError> {
    let (core, seed) = split(body);
    let c = PublicState::common(core);
    let owners = [
        c.clone().branch(DM, seed).owner(),
        c.clone().branch(DC, seed).owner(),
    ];
    let mut d = c.branch(DD, seed);
    d.pad();
    decode_into(
        |block| {
            super::sponge_permute(&mut d.words);
            rate(&d.words, block)
        },
        out,
    )?;
    Ok(owners)
}
// Separate destination decoder keeps secret preparation on without_matrix.
fn without_matrix_public(
    body: &[u8],
    out: &mut impl dither_destination::Destination,
) -> Result<[FastSponge; 2], FrameError> {
    let (core, seed) = split(body);
    let c = PublicState::common(core);
    let owners = [
        c.clone().branch(DM, seed).owner(),
        c.clone().branch(DC, seed).owner(),
    ];
    let mut d = c.branch(DD, seed);
    d.pad();
    dither_destination::decode_words::<25, 1>(
        &mut d.words,
        |words, _end| {
            super::sponge_permute(words);
        },
        out,
    )?;
    Ok(owners)
}
// Public-only Pretzel-(5,5) schedule: offset 102 changes the branch crossings.
// Preserve exact frames and unequal matrix lane quotas; no private inputs.
fn matrix_state(seed: &[u8; 32], lane: u8) -> PublicState {
    let mut s = PublicState::new();
    s.absorb(crate::direct_ntt_profile::MATRIX_DOMAIN);
    s.part(seed);
    s.part(&[lane]);
    s.pad();
    s
}
fn put(pair: &mut [u64; 50], lane: usize, s: &PublicState) {
    for i in 0..25 {
        pair[2 * i + lane] = s.words[i];
    }
}
#[cfg(test)]
fn lane_rate(pair: &[u64; 50], lane: usize, out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let bytes = pair[2 * i + lane].to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}
// Keep the explicit lane order and index schedule of the kernel and its oracle.
#[allow(clippy::needless_range_loop)]
pub(crate) fn fill(
    body: &[u8],
    rows: &mut Rows,
    out: &mut impl dither_destination::Destination,
) -> Result<[FastSponge; 2], FrameError> {
    if super::available() {
        return scheduled(body, rows, out, super::permute);
    }
    let (core, _) = split(body);
    let seed: &[u8; 32] = core[..32].try_into().unwrap();
    let mut pair = Zeroizing::new([0u64; 50]);
    let mut scratch = matrix_state(seed, 0);
    put(&mut pair, 0, &scratch);
    reset_matrix(&mut scratch, seed, 1);
    put(&mut pair, 1, &scratch);
    crate::direct_ntt_profile::matrix13::fill_pair(&mut pair, super::permute_scalar, rows);
    without_matrix_public(body, out)
}

#[cfg(test)]
mod schedule_tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    fn part(s: &mut Shake256, x: &[u8]) {
        s.update(&(x.len() as u64).to_le_bytes());
        s.update(x);
    }
    #[test]
    fn prefix_matches_framed_reference() {
        for domain in [DM, DC] {
            for size in [0usize, 1, 135, 136, 137] {
                let body = [37u8; 2144];
                let input = vec![19u8; size];
                let mut h = Shake256::default();
                part(&mut h, crate::direct_ntt_profile::PROFILE);
                part(&mut h, &body[..2112]);
                h.update(domain);
                h.update(&body[2112..]);
                part(&mut h, &input);
                let mut expected = [0u8; 64];
                h.finalize_xof().read(&mut expected);
                assert_eq!(hash::<64>(domain, &body, &[&input]), expected);
            }
        }
    }
}

// Keep the lane order and index schedule explicit.
#[allow(clippy::needless_range_loop)]
fn scheduled(
    body: &[u8],
    rows: &mut Rows,
    out: &mut impl dither_destination::Destination,
    mut permute: impl FnMut(&mut [u64; 50]),
) -> Result<[FastSponge; 2], FrameError> {
    let (core, seed) = split(body);
    let matrix_seed: &[u8; 32] = core[..32].try_into().unwrap();
    let pl = 14u64.to_le_bytes();
    let cl = 2112u64.to_le_bytes();
    let sl = 32u64.to_le_bytes();
    let mut common = Bytes::new([
        &pl[..],
        crate::direct_ntt_profile::PROFILE.as_slice(),
        &cl[..],
        core,
    ]);
    let mut pair = Zeroizing::new([0u64; 50]);
    let mut scratch = matrix_state(matrix_seed, 0);
    put(&mut pair, 1, &scratch);
    let mut cursors = [Cursor::new(), Cursor::new()];
    // Fifteen blocks cannot complete lane zero (3328 accepted coefficients).
    for _ in 0..15 {
        common.xor(&mut pair, 0, 0, RATE);
        permute(&mut pair);
        cursors[0].feed_pair(0, 1, &pair, rows);
    }
    assert!(!cursors[0].complete(0));
    common.xor(&mut pair, 0, 0, 102);
    let c = state(&pair, 0, 102);
    let matrix0 = state(&pair, 1, 0);
    put(&mut pair, 1, &c);
    let mut d = Bytes::new([DD, &sl[..], seed]);
    let mut m = Bytes::new([DM, seed]);
    let mut h = Bytes::new([DC, seed]);
    d.xor(&mut pair, 0, 102, 34);
    m.xor(&mut pair, 1, 102, 34);
    permute(&mut pair);
    d.xor(&mut pair, 0, 0, 22);
    m.xor(&mut pair, 1, 0, 11);
    let message = FastSponge::from_public_pair(&pair, 1, 11);
    pair[4] ^= 0x1fu64 << 48;
    pair[32] ^= 0x80u64 << 56;
    put(&mut pair, 1, &c);
    h.xor(&mut pair, 1, 102, 34);
    permute(&mut pair);
    h.xor(&mut pair, 1, 0, 12);
    let challenge = FastSponge::from_public_pair(&pair, 1, 12);
    // Dither block one is available. Later dither blocks advance matrix one.
    reset_matrix(&mut scratch, matrix_seed, 1);
    put(&mut pair, 1, &scratch);
    let mut first = true;
    dither_destination::decode_words::<50, 2>(
        &mut pair,
        |pair, _end| {
            if first {
                first = false;
            } else {
                permute(pair);
                cursors[1].feed_pair(1, 1, pair, rows);
            }
        },
        out,
    )?;
    put(&mut pair, 0, &matrix0);
    while cursors
        .iter()
        .enumerate()
        .any(|(lane, c)| !c.complete(lane))
    {
        permute(&mut pair);
        for (lane, cursor) in cursors.iter_mut().enumerate() {
            if !cursor.complete(lane) {
                cursor.feed_pair(lane, lane, &pair, rows);
            }
        }
    }
    Ok([message, challenge])
}

struct Bytes<'a, const K: usize> {
    parts: [&'a [u8]; K],
    part: usize,
    pos: usize,
}
impl<'a, const K: usize> Bytes<'a, K> {
    fn new(parts: [&'a [u8]; K]) -> Self {
        Self {
            parts,
            part: 0,
            pos: 0,
        }
    }
    fn byte(&mut self) -> u8 {
        while self.part < K && self.pos == self.parts[self.part].len() {
            self.part += 1;
            self.pos = 0;
        }
        assert!(self.part < K);
        let b = self.parts[self.part][self.pos];
        self.pos += 1;
        b
    }
    fn word(&mut self) -> u64 {
        while self.part < K && self.pos == self.parts[self.part].len() {
            self.part += 1;
            self.pos = 0;
        }
        assert!(self.part < K);
        if self.parts[self.part].len() - self.pos >= 8 {
            let p = self.pos;
            self.pos += 8;
            return u64::from_le_bytes(self.parts[self.part][p..p + 8].try_into().unwrap());
        }
        // A single boundary word may span any number of empty/short slices.
        let bytes = core::array::from_fn(|_| self.byte());
        u64::from_le_bytes(bytes)
    }
    // Keep the byte alignment predicate explicit.
    #[allow(clippy::manual_is_multiple_of)]
    fn xor(&mut self, pair: &mut [u64; 50], lane: usize, offset: usize, n: usize) {
        assert!(lane < 2 && offset + n <= RATE);
        let end = offset + n;
        let mut i = offset;
        while i < end && i % 8 != 0 {
            pair[2 * (i / 8) + lane] ^= (self.byte() as u64) << (8 * (i % 8));
            i += 1;
        }
        while i + 8 <= end {
            pair[2 * (i / 8) + lane] ^= self.word();
            i += 8;
        }
        while i < end {
            pair[2 * (i / 8) + lane] ^= (self.byte() as u64) << (8 * (i % 8));
            i += 1;
        }
    }
}
fn state(pair: &[u64; 50], lane: usize, pos: usize) -> PublicState {
    PublicState {
        words: Zeroizing::new(core::array::from_fn(|i| pair[2 * i + lane])),
        pos,
    }
}

#[cfg(test)]
// Match the lane and row indexing used by the independent references.
#[allow(clippy::needless_range_loop)]
mod public_preparation_tests {
    use super::*;
    #[test]
    fn public_rows_dither_prefixes_match_independent_routines() {
        for seed in 0..32u8 {
            let body: Vec<u8> = (0..crate::params::PK_BYTES)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
                .collect();
            let mut expected = [[CompactPoly::ZERO; ELL + 1]; M];
            let mut actual = expected;
            for r in 0..M {
                expected[r][0].0.fill(19);
                actual[r][0].0.fill(19);
            }
            let mut d0 = [0; DITHER_COEFFICIENTS];
            let mut d1 = d0;
            // Matrix reference uses independent SHAKE readers in the live scalar sampler.
            crate::direct_ntt_profile::matrix13::scalar(
                body[..32].try_into().unwrap(),
                &mut expected,
            );
            // Prefix/dither reference is the live, separate secret-preparation routine.
            let p0 = without_matrix(&body, &mut d0).unwrap();
            let p1 = fill(&body, &mut actual, &mut d1).unwrap();
            assert_eq!(expected, actual);
            assert_eq!(d0, d1);
            for lane in 0..2 {
                assert_eq!(
                    p0[lane].hash::<64>(&[b"fixed continuation"]),
                    p1[lane].hash::<64>(&[b"fixed continuation"])
                );
            }
            // Exercise the fused schedule with the scalar permutation.
            let mut scheduled_rows = [[CompactPoly::ZERO; ELL + 1]; M];
            for row in &mut scheduled_rows {
                row[0].0.fill(19);
            }
            let mut scheduled_dither = [0; DITHER_COEFFICIENTS];
            let scheduled_prefixes = scheduled(
                &body,
                &mut scheduled_rows,
                &mut scheduled_dither,
                super::super::permute_scalar,
            )
            .unwrap();
            assert_eq!(expected, scheduled_rows);
            assert_eq!(d0, scheduled_dither);
            for lane in 0..2 {
                assert_eq!(
                    p0[lane].hash::<64>(&[b"fixed continuation"]),
                    scheduled_prefixes[lane].hash::<64>(&[b"fixed continuation"])
                );
            }
        }
    }
}

// Raw SHAKE256 of the reconstructed public-key body. This is a separate
// domain from common()/branch(); merging the streams would change key bytes.
pub(crate) fn public_digest(body: &[u8]) -> [u8; 32] {
    let mut s = PublicState::new();
    s.absorb(body);
    s.pad();
    super::sponge_permute(&mut s.words);
    let mut out = [0u8; 32];
    rate(&s.words, &mut out);
    out
}
#[cfg(test)]
mod keyprep_public_digest_tests {
    use super::*;
    #[test]
    fn keyprep_public_digest_matches_scalar_boundaries() {
        for len in [
            0,
            1,
            7,
            8,
            31,
            32,
            135,
            136,
            137,
            271,
            272,
            273,
            crate::params::PK_BYTES,
        ] {
            for seed in [0u8, 1, 127, 255] {
                let bytes: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
                    .collect();
                assert_eq!(public_digest(&bytes), crate::hashes::shake256_32(&bytes));
            }
        }
    }
}

#[cfg(test)]
mod keyprep_public_field_tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    #[test]
    fn keyprep_public_state_fields_and_dither_match_scalar_main() {
        for seed in [0u8, 1, 127, 255] {
            let body: Vec<u8> = (0..crate::params::PK_BYTES)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
                .collect();
            let (core, dseed) = split(&body);
            for domain in [DD, DM, DC] {
                let mut framed = Vec::new();
                for part in [crate::direct_ntt_profile::PROFILE.as_slice(), core] {
                    framed.extend_from_slice(&(part.len() as u64).to_le_bytes());
                    framed.extend_from_slice(part);
                }
                framed.extend_from_slice(domain);
                if domain == DD {
                    framed.extend_from_slice(&32u64.to_le_bytes());
                }
                framed.extend_from_slice(dseed);
                let mut words = [0u64; 25];
                let mut pos = 0;
                for byte in &framed {
                    words[pos / 8] ^= (*byte as u64) << (8 * (pos % 8));
                    pos += 1;
                    if pos == RATE {
                        keccak::f1600(&mut words);
                        pos = 0;
                    }
                }
                let actual = PublicState::common(core).branch(domain, dseed);
                assert_eq!(*actual.words, words);
                assert_eq!(actual.pos, pos);
                if domain == DD {
                    let mut h = Shake256::default();
                    h.update(&framed);
                    let mut reader = h.finalize_xof();
                    let mut expected = [0i32; DITHER_COEFFICIENTS];
                    let mut used = 0;
                    for _ in 0..EXPANSION_CANDIDATES {
                        let mut pair = [0u8; 2];
                        reader.read(&mut pair);
                        let v = u16::from_le_bytes(pair) & 8191;
                        if v < 7681 {
                            expected[used] = v as i32;
                            used += 1;
                            if used == expected.len() {
                                break;
                            }
                        }
                    }
                    let mut actual = [0i32; DITHER_COEFFICIENTS];
                    let result = dither(core, dseed.try_into().unwrap(), &mut actual);
                    assert_eq!(result.is_ok(), used == expected.len());
                    assert_eq!(actual, expected);
                }
            }
        }
    }
}

include!("keygen_dither_check.rs");

#[cfg(test)]
#[path = "../../pretzel-4-4/core/src/public_matrix_schedule_tests.rs"]
mod matrix_sampler_schedule_tests;

// Reference public preparation, used only as a differential oracle.
#[cfg(test)]
fn scheduled_reference(
    body: &[u8],
    rows: &mut Rows,
    out: &mut [i32; DITHER_COEFFICIENTS],
    mut permute: impl FnMut(&mut [u64; 50]),
) -> Result<[FastSponge; 2], FrameError> {
    let (core, seed) = split(body);
    let matrix_seed: &[u8; 32] = core[..32].try_into().unwrap();
    let pl = 14u64.to_le_bytes();
    let cl = 2112u64.to_le_bytes();
    let sl = 32u64.to_le_bytes();
    let mut common = Bytes::new([
        &pl[..],
        crate::direct_ntt_profile::PROFILE.as_slice(),
        &cl[..],
        core,
    ]);
    let mut pair = Zeroizing::new([0u64; 50]);
    put(&mut pair, 1, &matrix_state(matrix_seed, 0));
    let mut cursors = [Cursor::new(), Cursor::new()];
    // Fifteen blocks cannot complete lane zero (3328 accepted coefficients).
    for _ in 0..15 {
        common.xor(&mut pair, 0, 0, RATE);
        permute(&mut pair);
        cursors[0].feed_pair(0, 1, &pair, rows);
    }
    assert!(!cursors[0].complete(0));
    common.xor(&mut pair, 0, 0, 102);
    let c = state(&pair, 0, 102);
    let matrix0 = state(&pair, 1, 0);
    put(&mut pair, 0, &c);
    put(&mut pair, 1, &c);
    let mut d = Bytes::new([DD, &sl[..], seed]);
    let mut m = Bytes::new([DM, seed]);
    let mut h = Bytes::new([DC, seed]);
    d.xor(&mut pair, 0, 102, 34);
    m.xor(&mut pair, 1, 102, 34);
    permute(&mut pair);
    d.xor(&mut pair, 0, 0, 22);
    m.xor(&mut pair, 1, 0, 11);
    let message = state(&pair, 1, 11).owner();
    let mut dstate = state(&pair, 0, 22);
    dstate.pad();
    put(&mut pair, 0, &dstate);
    put(&mut pair, 1, &c);
    h.xor(&mut pair, 1, 102, 34);
    permute(&mut pair);
    h.xor(&mut pair, 1, 0, 12);
    let challenge = state(&pair, 1, 12).owner();
    // Dither block one is available. Later dither blocks advance matrix one.
    put(&mut pair, 1, &matrix_state(matrix_seed, 1));
    let mut first = true;
    decode_public_reference(
        |dst| {
            if first {
                first = false;
            } else {
                permute(&mut pair);
                cursors[1].feed_pair(1, 1, &pair, rows);
            }
            lane_rate(&pair, 0, dst);
        },
        out,
    )?;
    put(&mut pair, 0, &matrix0);
    while cursors
        .iter()
        .enumerate()
        .any(|(lane, c)| !c.complete(lane))
    {
        permute(&mut pair);
        for (lane, cursor) in cursors.iter_mut().enumerate() {
            if !cursor.complete(lane) {
                cursor.feed_pair(lane, lane, &pair, rows);
            }
        }
    }
    Ok([message, challenge])
}
#[cfg(test)]
pub(crate) fn fill_reference(
    body: &[u8],
    rows: &mut Rows,
    out: &mut [i32; DITHER_COEFFICIENTS],
) -> Result<[FastSponge; 2], FrameError> {
    if super::available() {
        return scheduled_reference(body, rows, out, super::permute);
    }
    let (core, _) = split(body);
    let seed: &[u8; 32] = core[..32].try_into().unwrap();
    let mut pair = Zeroizing::new([0u64; 50]);
    put(&mut pair, 0, &matrix_state(seed, 0));
    put(&mut pair, 1, &matrix_state(seed, 1));
    crate::direct_ntt_profile::matrix13::fill_pair(&mut pair, super::permute_scalar, rows);
    without_matrix_public_reference(body, out)
}

fn reset_matrix(s: &mut PublicState, seed: &[u8; 32], lane: u8) {
    s.words.fill(0);
    s.pos = 0;
    s.absorb(crate::direct_ntt_profile::MATRIX_DOMAIN);
    s.part(seed);
    s.part(&[lane]);
    s.pad();
}

#[cfg(test)]
fn without_matrix_public_reference(
    body: &[u8],
    out: &mut [i32; DITHER_COEFFICIENTS],
) -> Result<[FastSponge; 2], FrameError> {
    let (core, seed) = split(body);
    let c = PublicState::common(core);
    let owners = [
        c.clone().branch(DM, seed).owner(),
        c.clone().branch(DC, seed).owner(),
    ];
    let mut d = c.branch(DD, seed);
    d.pad();
    decode_public_reference(
        |block| {
            super::sponge_permute(&mut d.words);
            rate(&d.words, block)
        },
        out,
    )?;
    Ok(owners)
}

#[cfg(test)]
fn decode_public_reference(
    mut fill: impl FnMut(&mut [u8]),
    out: &mut [i32; DITHER_COEFFICIENTS],
) -> Result<(), FrameError> {
    dither_destination::decode_into(
        |block| {
            fill(block);
        },
        out,
    )
}

#[cfg(test)]
#[path = "../../pretzel-4-4/core/src/public_preparation_reference_tests.rs"]
mod preparation_reference_tests;
