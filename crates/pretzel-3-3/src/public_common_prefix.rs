//! profile33 public preparation. Never an exposed sponge-state oracle.
#[path = "../../pretzel-4-4/core/src/public_dither_destination.rs"]
pub(crate) mod dither_destination;
use super::FastSponge;
use crate::direct_ntt_profile::matrix13::Cursor;
use crate::{
    compact_ring::CompactPoly,
    dither_frame::{FrameError, DITHER_COEFFICIENTS, EXPANSION_CANDIDATES},
    params::{ELL, M, N, Q},
};
use zeroize::{Zeroize, Zeroizing};
const RATE: usize = 136;
const _: () = assert!(
    M == 3
        && ELL == 3
        && N == 256
        && Q == 7681
        && crate::params::CORE_PK_BYTES == 1280
        && crate::params::PK_BYTES == 1312
);
type Rows = [[CompactPoly; ELL + 1]; M];
const DD: &[u8] = b"LILT-DITH-KEY-v1";
const DM: &[u8] = b"LILT-AC-3:msg";
const DC: &[u8] = b"LILT-AC-3:chal";
const _: () = assert!(DD.len() == 16 && DM.len() == 13 && DC.len() == 14);
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
                crate::shake2::sponge_permute(&mut self.words);
                self.pos = 0;
            }
        }
    }
    fn part(&mut self, bytes: &[u8]) {
        self.absorb(&(bytes.len() as u64).to_le_bytes());
        self.absorb(bytes);
    }
    fn common(core: &[u8]) -> Self {
        assert_eq!(core.len(), 1280);
        let mut s = Self::new();
        s.part(crate::direct_ntt_profile::PROFILE);
        s.part(core);
        assert_eq!(s.pos, 86);
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
    assert_eq!(body.len(), 1312);
    body.split_at(1280)
}
pub(crate) fn prefix(domain: &[u8], body: &[u8]) -> FastSponge {
    let (core, seed) = split(body);
    PublicState::common(core).branch(domain, seed).owner()
}
#[cfg(test)]
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

// Test-only scoped injection after real public work; never changes a non-test build.
#[cfg(test)]
pub(crate) mod completion_test {
    std::thread_local! {
     static EXHAUST:core::cell::Cell<bool>=const{core::cell::Cell::new(false)};
     static CALLS:core::cell::Cell<usize>=const{core::cell::Cell::new(0)};
     static BYTES:core::cell::Cell<usize>=const{core::cell::Cell::new(0)};
    }
    pub(super) fn note_dither_permutation() {
        if active() {
            CALLS.with(|x| x.set(x.get() + 1));
        }
    }
    pub(super) fn active() -> bool {
        EXHAUST.with(|x| x.get())
    }
    pub(super) fn block(out: &mut [u8]) {
        if active() {
            BYTES.with(|x| x.set(x.get() + out.len()));
            out.fill(255);
        }
    }
    pub(crate) fn exhausted<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                EXHAUST.with(|x| x.set(false));
            }
        }
        EXHAUST.with(|x| assert!(!x.replace(true)));
        CALLS.with(|x| x.set(0));
        BYTES.with(|x| x.set(0));
        let _reset = Reset;
        let value = f();
        (value, CALLS.with(|x| x.get()), BYTES.with(|x| x.get()))
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
            #[cfg(test)]
            completion_test::block(&mut block[..end]);
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
    if core.len() != 1280 {
        return Err(FrameError::KeyLength);
    }
    let mut s = PublicState::common(core).branch(DD, seed);
    s.pad();
    decode_into(
        |block| {
            #[cfg(test)]
            completion_test::note_dither_permutation();
            crate::shake2::sponge_permute(&mut s.words);
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
            #[cfg(test)]
            completion_test::note_dither_permutation();
            crate::shake2::sponge_permute(&mut d.words);
            rate(&d.words, block)
        },
        out,
    )?;
    Ok(owners)
}
// Public-only profile33 schedule, with unequal whole-polynomial lane quotas.
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
    let mut cursors = [Cursor::new(), Cursor::new()];
    while cursors
        .iter()
        .enumerate()
        .any(|(lane, c)| !c.complete(lane))
    {
        super::permute_scalar(&mut pair);
        for (lane, cursor) in cursors.iter_mut().enumerate() {
            cursor.feed_pair(lane, lane, &pair, rows);
        }
    }
    without_matrix_public(body, out)
}
fn scheduled(
    body: &[u8],
    rows: &mut Rows,
    out: &mut impl dither_destination::Destination,
    mut permute: impl FnMut(&mut [u64; 50]),
) -> Result<[FastSponge; 2], FrameError> {
    let (core, seed) = split(body);
    let matrix_seed: &[u8; 32] = core[..32].try_into().unwrap();
    let pl = 14u64.to_le_bytes();
    let cl = 1280u64.to_le_bytes();
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
    // Nine blocks cannot complete lane zero's 1280 accepted coefficients.
    for _ in 0..9 {
        common.xor(&mut pair, 0, 0, RATE);
        permute(&mut pair);
        cursors[0].feed_pair(0, 1, &pair, rows);
    }
    assert!(!cursors[0].complete(0));
    common.xor(&mut pair, 0, 0, 86);
    let matrix0 = state(&pair, 1, 0);
    // Both public branches fit in the common prefix's pending rate block.
    for i in 0..25 {
        pair[2 * i + 1] = pair[2 * i];
    }
    Bytes::new([DM, seed]).xor(&mut pair, 1, 86, 45);
    let message = FastSponge::from_public_pair(&pair, 1, 131);
    for i in 0..25 {
        pair[2 * i + 1] = pair[2 * i];
    }
    Bytes::new([DC, seed]).xor(&mut pair, 1, 86, 46);
    let challenge = FastSponge::from_public_pair(&pair, 1, 132);
    let mut d = Bytes::new([DD, &sl[..], seed]);
    reset_matrix(&mut scratch, matrix_seed, 1);
    put(&mut pair, 1, &scratch);
    // Dither crosses once and ends at six; advance matrix lane one alongside it.
    d.xor(&mut pair, 0, 86, 50);
    permute(&mut pair);
    cursors[1].feed_pair(1, 1, &pair, rows);
    d.xor(&mut pair, 0, 0, 6);
    pair[0] ^= 0x1fu64 << 48;
    pair[32] ^= 0x80u64 << 56;
    dither_destination::decode_words::<50, 2>(
        &mut pair,
        |pair, _end| {
            #[cfg(test)]
            completion_test::note_dither_permutation();
            permute(pair);
            if !cursors[1].complete(1) {
                cursors[1].feed_pair(1, 1, pair, rows);
            }
            #[cfg(test)]
            observe_public_dither(pair, 2, _end);
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
                let body = [37u8; 1312];
                let input = vec![19u8; size];
                let mut h = Shake256::default();
                part(&mut h, crate::direct_ntt_profile::PROFILE);
                part(&mut h, &body[..1280]);
                h.update(domain);
                h.update(&body[1280..]);
                part(&mut h, &input);
                let mut expected = [0u8; 64];
                h.finalize_xof().read(&mut expected);
                assert_eq!(hash::<64>(domain, &body, &[&input]), expected);
            }
        }
    }
}

// Public-only matrix scratch: byte views preserve wire bytes on every endianness.
// Every per-use erase remains, and Zeroizing retires all words on success/error/unwind.
#[cfg(test)]
struct PublicRateScratch {
    words: Zeroizing<[u64; 17]>,
}
#[cfg(test)]
impl core::ops::Deref for PublicRateScratch {
    type Target = [u8; RATE];
    fn deref(&self) -> &Self::Target {
        // Exactly 136 initialized bytes, alignment is stronger than u8; borrowed only.
        // SAFETY: 17 contiguous initialized u64s occupy RATE bytes; every u8 bit pattern
        // is valid, and the shared byte view cannot outlive the self borrow.
        unsafe { &*(self.words.as_ptr().cast::<[u8; RATE]>()) }
    }
}
#[cfg(test)]
impl core::ops::DerefMut for PublicRateScratch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: the same initialized 136-byte layout as Deref; the exclusive borrow
        // excludes aliases, and byte writes cannot invalidate the underlying u64s.
        unsafe { &mut *(self.words.as_mut_ptr().cast::<[u8; RATE]>()) }
    }
}
#[cfg(test)]
impl Zeroize for PublicRateScratch {
    fn zeroize(&mut self) {
        self.words.zeroize();
    }
}
#[cfg(test)]
fn public_rate_scratch() -> PublicRateScratch {
    PublicRateScratch {
        words: Zeroizing::new([0; 17]),
    }
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
    #[test]
    fn public_schedule_exhaustion_preserves_cutoff() {
        let body = [37u8; crate::params::PK_BYTES];
        let mut old = [19; DITHER_COEFFICIENTS];
        let mut new = old;
        let (a, ac, ab) = completion_test::exhausted(|| without_matrix(&body, &mut old));
        let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
        let (b, bc, bb) = completion_test::exhausted(|| {
            scheduled(&body, &mut rows, &mut new, super::super::permute_scalar)
        });
        assert!(matches!(a, Err(FrameError::DitherExhausted)));
        assert!(matches!(b, Err(FrameError::DitherExhausted)));
        let bytes = 2 * EXPANSION_CANDIDATES;
        assert_eq!((ac, ab), ((bytes + RATE - 1) / RATE, bytes));
        assert_eq!((ac, ab), (bc, bb));
        assert_eq!(old, new);
    }
    #[test]
    fn public_word_retirement_clears_all_rate_bytes() {
        let mut rate = public_rate_scratch();
        for b in 0..=255u8 {
            rate.fill(b);
            rate.zeroize();
            assert_eq!(&rate[..], &[0u8; RATE]);
        }
        // Also retire actual serialized matrix lanes after every reuse.
        for iteration in 0..256u64 {
            let pair = core::array::from_fn(|i| {
                iteration
                    .wrapping_mul(0x0102030405060708)
                    .wrapping_add(i as u64)
            });
            for lane in 0..2 {
                let mut expected = [0; RATE];
                lane_rate(&pair, lane, &mut expected);
                lane_rate(&pair, lane, &mut rate[..]);
                assert_eq!(&rate[..], &expected);
                rate.zeroize();
                assert_eq!(&rate[..], &[0u8; RATE]);
            }
        }
    }
}

include!("keygen_dither_check.rs");

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
    let cl = 1280u64.to_le_bytes();
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
    let mut block = public_rate_scratch();
    // Nine blocks cannot complete lane zero's 1280 accepted coefficients.
    for _ in 0..9 {
        common.xor(&mut pair, 0, 0, RATE);
        permute(&mut pair);
        lane_rate(&pair, 1, &mut block[..]);
        cursors[0].feed(0, &block, rows);
        block.zeroize();
    }
    assert!(!cursors[0].complete(0));
    common.xor(&mut pair, 0, 0, 86);
    let c = state(&pair, 0, 86);
    let matrix0 = state(&pair, 1, 0);
    // Message/challenge branches end at 131/132, without crossing the rate.
    let message = c.clone().branch(DM, seed).owner();
    let challenge = c.clone().branch(DC, seed).owner();
    let mut d = Bytes::new([DD, &sl[..], seed]);
    put(&mut pair, 1, &matrix_state(matrix_seed, 1));
    // Dither crosses once and ends at six; advance matrix lane one alongside it.
    d.xor(&mut pair, 0, 86, 50);
    permute(&mut pair);
    lane_rate(&pair, 1, &mut block[..]);
    cursors[1].feed(1, &block, rows);
    block.zeroize();
    d.xor(&mut pair, 0, 0, 6);
    let mut dstate = state(&pair, 0, 6);
    dstate.pad();
    put(&mut pair, 0, &dstate);
    decode_public_reference(
        |dst| {
            #[cfg(test)]
            completion_test::note_dither_permutation();
            permute(&mut pair);
            if !cursors[1].complete(1) {
                lane_rate(&pair, 1, &mut block[..]);
                cursors[1].feed(1, &block, rows);
                block.zeroize();
            }
            lane_rate(&pair, 0, dst)
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
                lane_rate(&pair, lane, &mut block[..]);
                cursor.feed(lane, &block, rows);
                block.zeroize();
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
    let mut cursors = [Cursor::new(), Cursor::new()];
    let mut block = public_rate_scratch();
    while cursors
        .iter()
        .enumerate()
        .any(|(lane, c)| !c.complete(lane))
    {
        super::permute_scalar(&mut pair);
        for (lane, cursor) in cursors.iter_mut().enumerate() {
            lane_rate(&pair, lane, &mut block[..]);
            cursor.feed(lane, &block, rows);
            block.zeroize();
        }
    }
    without_matrix_public_reference(body, out)
}

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
            #[cfg(test)]
            completion_test::note_dither_permutation();
            super::sponge_permute(words);
            #[cfg(test)]
            observe_public_dither(words, 1, _end);
        },
        out,
    )?;
    Ok(owners)
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
fn observe_public_dither(words: &mut [u64], stride: usize, end: usize) {
    if completion_test::active() {
        let mut block = [0u8; RATE];
        completion_test::block(&mut block[..end]);
        for i in 0..RATE / 8 {
            words[stride * i] = u64::MAX;
        }
    }
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
            #[cfg(test)]
            completion_test::note_dither_permutation();
            crate::shake2::sponge_permute(&mut d.words);
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
            completion_test::block(block);
        },
        out,
    )
}

#[cfg(test)]
#[path = "../../pretzel-4-4/core/src/public_preparation_reference_tests.rs"]
mod preparation_reference_tests;
