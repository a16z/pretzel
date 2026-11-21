//! Public-only preparation. Never an exposed sponge-state oracle.
#[path = "public_dither_destination.rs"]
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
    M == 4
        && ELL == 4
        && N == 256
        && Q == 7681
        && crate::params::CORE_PK_BYTES == 1696
        && crate::params::PK_BYTES == 1728
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
        assert_eq!(core.len(), 1696);
        let mut s = Self::new();
        s.part(crate::direct_ntt_profile::PROFILE);
        s.part(core);
        assert_eq!(s.pos, 94);
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
    assert_eq!(body.len(), 1728);
    body.split_at(1696)
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
     static BYTES:core::cell::Cell<usize>=const{core::cell::Cell::new(0)};
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
pub(crate) fn dither(
    core: &[u8],
    seed: &[u8; 32],
    out: &mut [i32; DITHER_COEFFICIENTS],
) -> Result<(), FrameError> {
    if core.len() != 1696 {
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
            #[cfg(test)]
            observe_public_dither(words, 1, _end);
        },
        out,
    )?;
    Ok(owners)
}
// A slice cursor is framing only: no allocation and no private data/state.
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
fn put(pair: &mut [u64; 50], lane: usize, s: &PublicState) {
    for i in 0..25 {
        pair[2 * i + lane] = s.words[i];
    }
}
#[cfg(test)]
fn lane_rate(pair: &[u64; 50], lane: usize, out: &mut [u8]) {
    assert!(lane < 2 && out.len() <= RATE);
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let bytes = pair[2 * i + lane].to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}
fn matrix_state(seed: &[u8; 32], lane: u8) -> PublicState {
    let mut s = PublicState::new();
    s.absorb(crate::direct_ntt_profile::MATRIX_DOMAIN);
    s.part(seed);
    s.part(&[lane]);
    s.pad();
    s
}
/// Only validated spectral rows enter this borrowed public coordinator.
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
    crate::direct_ntt_profile::matrix13::public(seed, rows);
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
    let cl = 1696u64.to_le_bytes();
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
    // The first 12 matrix blocks cannot complete 2048 accepted 13-bit coefficients.
    for _ in 0..12 {
        common.xor(&mut pair, 0, 0, RATE);
        permute(&mut pair);
        cursors[0].feed_pair(0, 1, &pair, rows);
    }
    assert!(!cursors[0].complete(0));
    common.xor(&mut pair, 0, 0, 94);
    let c = state(&pair, 0, 94);
    let matrix0 = state(&pair, 1, 0);
    put(&mut pair, 1, &c);
    let mut d = Bytes::new([DD, &sl[..], seed]);
    let mut m = Bytes::new([DM, seed]);
    let mut h = Bytes::new([DC, seed]);
    d.xor(&mut pair, 0, 94, 42);
    m.xor(&mut pair, 1, 94, 42);
    permute(&mut pair);
    d.xor(&mut pair, 0, 0, 14);
    m.xor(&mut pair, 1, 0, 3);
    let message = FastSponge::from_public_pair(&pair, 1, 3);
    pair[2] ^= 0x1fu64 << 48;
    pair[32] ^= 0x80u64 << 56;
    put(&mut pair, 1, &c);
    h.xor(&mut pair, 1, 94, 42);
    permute(&mut pair);
    h.xor(&mut pair, 1, 0, 4);
    let challenge = FastSponge::from_public_pair(&pair, 1, 4);
    // Dither block1 is already available. Later dither blocks advance matrix1.
    reset_matrix(&mut scratch, matrix_seed, 1);
    put(&mut pair, 1, &scratch);
    let mut first = true;
    dither_destination::decode_words::<50, 2>(
        &mut pair,
        |pair, _end| {
            if first {
                first = false
            } else {
                permute(pair);
                cursors[1].feed_pair(1, 1, pair, rows);
            }
            #[cfg(test)]
            observe_public_dither(pair, 2, _end);
        },
        out,
    )?;
    assert!(!cursors[1].complete(1));
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
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    fn part(h: &mut Shake256, x: &[u8]) {
        h.update(&(x.len() as u64).to_le_bytes());
        h.update(x);
    }
    fn reference<const L: usize>(domain: &[u8], body: &[u8], parts: &[&[u8]]) -> [u8; L] {
        let mut h = Shake256::default();
        part(&mut h, crate::direct_ntt_profile::PROFILE);
        part(&mut h, &body[..1696]);
        h.update(domain);
        if domain == DD {
            part(&mut h, &body[1696..])
        } else {
            h.update(&body[1696..]);
        }
        for p in parts {
            part(&mut h, p)
        }
        let mut out = [0; L];
        h.finalize_xof().read(&mut out);
        out
    }
    fn sample_body(case: u8) -> [u8; 1728] {
        core::array::from_fn(|i| {
            (i as u8)
                .wrapping_mul(37)
                .wrapping_add(case.wrapping_mul(19))
        })
    }
    fn matrix_oracle(seed: &[u8; 32]) -> (Rows, [usize; 2]) {
        let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
        let mut counts = [0; 2];
        for lane in 0..2 {
            let mut h = Shake256::default();
            h.update(crate::direct_ntt_profile::MATRIX_DOMAIN);
            part(&mut h, seed);
            part(&mut h, &[lane as u8]);
            let mut r = h.finalize_xof();
            let mut cursor = Cursor::new();
            while !cursor.complete(lane) {
                let mut block = [0; RATE];
                r.read(&mut block);
                cursor.feed_scalar_oracle(lane, &block, &mut rows);
                counts[lane] += 1;
                block.zeroize();
            }
        }
        (rows, counts)
    }

    #[test]
    fn common_public_exact_standard_shake_and_online_counts() {
        for case in 0..64u8 {
            let body = sample_body(case);
            let seed: &[u8; 32] = body[..32].try_into().unwrap();
            let (expected, t) = matrix_oracle(seed);
            let bytes = reference::<3072>(DD, &body, &[]);
            let mut delta = [0; DITHER_COEFFICIENTS];
            let (mut used, mut words) = (0, 0);
            for p in bytes.chunks_exact(2) {
                words += 1;
                let v = u16::from_le_bytes([p[0], p[1]]) & 8191;
                if v < 7681 {
                    delta[used] = v as i32;
                    used += 1;
                    if used == delta.len() {
                        break;
                    }
                }
            }
            assert_eq!(used, 1024);
            let k = (2 * words + 135) / 136;
            let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
            for row in &mut rows {
                row[0] = CompactPoly([37; N]);
            }
            let mut got = [0; 1024];
            let mut calls = 0;
            let owners = scheduled(&body, &mut rows, &mut got, |pair| {
                calls += 1;
                super::super::permute_scalar(pair)
            })
            .unwrap();
            assert_eq!(calls, 13 + k + (t[0] - 12).max(t[1] - k + 1));
            assert_eq!(got, delta);
            for r in 0..M {
                assert_eq!(rows[r][0].0, [37; N]);
                for c in 1..=ELL {
                    assert_eq!(rows[r][c].0, expected[r][c].0);
                }
            }
            for (domain, owner) in [(DM, &owners[0]), (DC, &owners[1])] {
                assert_eq!(
                    owner.hash::<273>(&[b"context", b"labels"]),
                    reference::<273>(domain, &body, &[b"context", b"labels"])
                );
            }
            let mut separate = [0; 1024];
            let old = without_matrix(&body, &mut separate).unwrap();
            assert_eq!(separate, delta);
            for lane in 0..2 {
                assert_eq!(old[lane].hash::<64>(&[]), owners[lane].hash::<64>(&[]));
            }
            if super::super::available() {
                let mut hw = [[CompactPoly::ZERO; ELL + 1]; M];
                let mut dd = [0; 1024];
                let hh = scheduled(&body, &mut hw, &mut dd, super::super::permute).unwrap();
                assert_eq!(dd, delta);
                for r in 0..M {
                    for c in 1..=ELL {
                        assert_eq!(hw[r][c].0, expected[r][c].0);
                    }
                }
                for lane in 0..2 {
                    assert_eq!(hh[lane].hash::<64>(&[]), owners[lane].hash::<64>(&[]));
                }
            }
        }
    }
    #[test]
    fn common_public_continuation_boundaries_and_cached_uncached() {
        let body = sample_body(7);
        let owners = prefixes(&body);
        for n in [
            0, 1, 119, 120, 121, 127, 128, 129, 131, 132, 133, 134, 135, 136, 137, 255, 272,
        ] {
            let x = vec![n as u8; n];
            let parts = [b"".as_slice(), x.as_slice()];
            for (domain, owner) in [(DM, &owners[0]), (DC, &owners[1])] {
                assert_eq!(
                    owner.hash::<0>(&parts),
                    reference::<0>(domain, &body, &parts)
                );
                assert_eq!(
                    owner.hash::<1>(&parts),
                    reference::<1>(domain, &body, &parts)
                );
                assert_eq!(
                    owner.hash::<32>(&parts),
                    reference::<32>(domain, &body, &parts)
                );
                assert_eq!(
                    owner.hash::<136>(&parts),
                    reference::<136>(domain, &body, &parts)
                );
                assert_eq!(
                    owner.hash::<273>(&parts),
                    reference::<273>(domain, &body, &parts)
                );
                assert_eq!(owner.hash::<64>(&[]), reference::<64>(domain, &body, &[]));
            }
            let mu = crate::hashes::message_rep(&body, b"", &x);
            assert_eq!(mu, owners[0].hash::<64>(&parts));
            let rho = [9; 32];
            assert_eq!(
                crate::hashes::challenge_bytes(&body, &mu, &rho, &x),
                owners[1].hash::<32>(&[&mu, &rho, &x])
            );
        }
    }
    #[test]
    fn common_public_cutoff_and_unwind_owners() {
        for last in 1023..1536 {
            let mut bytes = [255u8; 3072];
            bytes[..2046].fill(0);
            bytes[2 * last..2 * last + 2].fill(0);
            let mut fetched = 0;
            let mut out = [0; 1024];
            assert!(decode_into(
                |b| {
                    b.copy_from_slice(&bytes[fetched..fetched + b.len()]);
                    fetched += b.len()
                },
                &mut out
            )
            .is_ok());
            assert_eq!(fetched, (((2 * (last + 1) + 135) / 136) * 136).min(3072));
        }
        let mut out = [0; 1024];
        let mut fetched = 0;
        assert_eq!(
            decode_into(
                |b| {
                    b.fill(255);
                    fetched += b.len()
                },
                &mut out
            ),
            Err(FrameError::DitherExhausted)
        );
        assert_eq!(fetched, 3072);
        // Inject only the public dither rate lane after real pair permutation;
        // matrix/challenge lanes remain real. The scheduler receives no final length.
        for k in 16usize..=23 {
            let mut bytes = [255u8; 3072];
            bytes[..2046].fill(0);
            let last = (k * 68 - 1).min(1535);
            bytes[2 * last..2 * last + 2].fill(0);
            let body = sample_body(4);
            let seed: &[u8; 32] = body[..32].try_into().unwrap();
            let (_, t) = matrix_oracle(seed);
            let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
            let mut out = [0; 1024];
            let mut calls = 0;
            assert!(scheduled(&body, &mut rows, &mut out, |pair| {
                calls += 1;
                super::super::permute_scalar(pair);
                if calls >= 14 && calls <= 13 + k {
                    let start = (calls - 14) * 136;
                    let mut b = [0u8; 136];
                    let n = (3072 - start).min(136);
                    b[..n].copy_from_slice(&bytes[start..start + n]);
                    for w in 0..17 {
                        pair[2 * w] = u64::from_le_bytes(b[8 * w..8 * w + 8].try_into().unwrap());
                    }
                }
            })
            .is_ok());
            assert_eq!(calls, 13 + k + (t[0] - 12).max(t[1] - k + 1));
            assert_eq!(out, [0; 1024]);
        }
        {
            let body = sample_body(4);
            let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
            let mut out = [0; 1024];
            let mut calls = 0;
            let r = scheduled(&body, &mut rows, &mut out, |pair| {
                calls += 1;
                super::super::permute_scalar(pair);
                if calls >= 14 {
                    for w in 0..17 {
                        pair[2 * w] = u64::MAX;
                    }
                }
            });
            assert!(matches!(r, Err(FrameError::DitherExhausted)));
            assert_eq!(calls, 36);
        }
        for stop in [1, 12, 13, 14, 20] {
            let before = ERASE_EVENTS.with(|n| n.get());
            let body = sample_body(3);
            let mut rows = [[CompactPoly::ZERO; ELL + 1]; M];
            let mut out = [0; 1024];
            let mut calls = 0;
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = scheduled(&body, &mut rows, &mut out, |pair| {
                    calls += 1;
                    if calls == stop {
                        panic!("public scheduler unwind")
                    }
                    super::super::permute_scalar(pair)
                });
            }));
            assert!(r.is_err());
            assert!(ERASE_EVENTS.with(|n| n.get()) > before);
        }
    }
}

#[cfg(test)]
mod word_boundary_tests {
    use super::*;
    #[test]
    fn common_public_word_ingress_and_output_boundaries() {
        let input: [u8; 136] = core::array::from_fn(|i| (i as u8).wrapping_mul(37));
        for offset in 0..=136 {
            for n in [0usize, 1, 3, 4, 7, 8, 14, 42, 94, 136] {
                if offset + n > 136 {
                    continue;
                }
                for split in [
                    0,
                    1.min(n),
                    7.min(n),
                    8.min(n),
                    n / 2,
                    n.saturating_sub(1),
                    n,
                ] {
                    for lane in 0..2 {
                        let mut got = [0x13579bdf2468ace0u64; 50];
                        let mut want = got;
                        let mut cursor = Bytes::new([&input[..split], &[][..], &input[split..n]]);
                        cursor.xor(&mut got, lane, offset, n);
                        for i in 0..n {
                            let p = offset + i;
                            want[2 * (p / 8) + lane] ^= (input[i] as u64) << (8 * (p % 8));
                        }
                        assert_eq!(got, want);
                        for len in [0usize, 1, 3, 4, 7, 8, 14, 42, 94, 135, 136] {
                            let mut output = vec![0; len];
                            lane_rate(&got, lane, &mut output);
                            let expected: Vec<_> = (0..len)
                                .map(|i| (got[2 * (i / 8) + lane] >> (8 * (i % 8))) as u8)
                                .collect();
                            assert_eq!(output, expected);
                        }
                    }
                }
            }
        }
        let mut cursor = Bytes::new([&input[..3], &[][..], &input[3..8]]);
        assert_eq!(
            cursor.word(),
            u64::from_le_bytes(input[..8].try_into().unwrap())
        );
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cursor.byte())).is_err());
    }
}

#[cfg(test)]
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

#[cfg(test)]
#[path = "public_matrix_schedule_tests.rs"]
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
    let cl = 1696u64.to_le_bytes();
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
    // The first 12 matrix blocks cannot complete 2048 accepted 13-bit coefficients.
    for _ in 0..12 {
        common.xor(&mut pair, 0, 0, RATE);
        permute(&mut pair);
        cursors[0].feed_pair(0, 1, &pair, rows);
    }
    assert!(!cursors[0].complete(0));
    common.xor(&mut pair, 0, 0, 94);
    let c = state(&pair, 0, 94);
    let matrix0 = state(&pair, 1, 0);
    put(&mut pair, 0, &c);
    put(&mut pair, 1, &c);
    let mut d = Bytes::new([DD, &sl[..], seed]);
    let mut m = Bytes::new([DM, seed]);
    let mut h = Bytes::new([DC, seed]);
    d.xor(&mut pair, 0, 94, 42);
    m.xor(&mut pair, 1, 94, 42);
    permute(&mut pair);
    d.xor(&mut pair, 0, 0, 14);
    m.xor(&mut pair, 1, 0, 3);
    let message = state(&pair, 1, 3).owner();
    let mut dstate = state(&pair, 0, 14);
    dstate.pad();
    put(&mut pair, 0, &dstate);
    put(&mut pair, 1, &c);
    h.xor(&mut pair, 1, 94, 42);
    permute(&mut pair);
    h.xor(&mut pair, 1, 0, 4);
    let challenge = state(&pair, 1, 4).owner();
    // Dither block1 is already available. Later dither blocks advance matrix1.
    put(&mut pair, 1, &matrix_state(matrix_seed, 1));
    let mut first = true;
    decode_public_reference(
        |dst| {
            if first {
                first = false
            } else {
                permute(&mut pair);
                cursors[1].feed_pair(1, 1, &pair, rows);
            }
            lane_rate(&pair, 0, dst)
        },
        out,
    )?;
    assert!(!cursors[1].complete(1));
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
    crate::direct_ntt_profile::matrix13::public(seed, rows);
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
            completion_test::block(block);
        },
        out,
    )
}

#[cfg(test)]
#[path = "public_preparation_reference_tests.rs"]
mod preparation_reference_tests;
