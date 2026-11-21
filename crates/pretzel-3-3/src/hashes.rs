//! SHAKE256-based expansion: matrix, key material, dither, challenge, salts,
//! and the sampler's random bit stream.

use crate::params::*;
use crate::ring::Poly;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::{Zeroize, Zeroizing};

// One SHAKE256 rate block. Preserve every byte and erasure on drop while
// avoiding bulk over-generation for short salt/hash outputs. Still buffered.
const XOF_BUF: usize = 136;

#[cfg(test)]
mod buffer_tests {
    use super::*;
    #[test]
    fn block_uniform_matches_reference_sampler_and_stream_position() {
        for seed in 0..40u8 {
            let mut a = Xof::new(b"uniform-test", &[&[seed]]);
            let mut b = Xof::new(b"uniform-test", &[&[seed]]);
            // desynchronize the buffer position, including odd offsets
            let skew = (seed as usize * 37) % 140;
            let mut junk = vec![0u8; skew];
            let mut junk2 = junk.clone();
            a.fill(&mut junk);
            b.fill(&mut junk2);
            for _ in 0..5 {
                let x = a.poly_uniform();
                let y = b.poly_uniform_reference();
                assert_eq!(x.0, y.0);
                assert_eq!(a.pos, b.pos);
                assert_eq!(a.consumed, b.consumed);
                assert_eq!(a.u64(), b.u64());
            }
        }
    }

    #[test]
    fn mixed_reads_match_unbuffered_shake_at_boundaries() {
        for case in 0..16u8 {
            let input = vec![case; 2048 + case as usize];
            let parts: &[&[u8]] = &[b"", &input, b"public test fixture"];
            let mut actual = Xof::new(b"buffer-test", parts);
            let mut hash = Shake256::default();
            hash.update(b"buffer-test");
            for part in parts {
                hash.update(&(part.len() as u64).to_le_bytes());
                hash.update(part);
            }
            let mut reference = hash.finalize_xof();
            for len in [0, 1, 2, 7, 8, 135, 136, 137, 2047, 2048, 2049, 5000] {
                let mut a = vec![0; len];
                let mut b = vec![0; len];
                actual.fill(&mut a);
                reference.read(&mut b);
                assert_eq!(a, b);
                let mut b = [0; 8];
                reference.read(&mut b);
                assert_eq!(actual.u64(), u64::from_le_bytes(b));
                let mut b = [0; 2];
                reference.read(&mut b);
                assert_eq!(actual.u16(), u16::from_le_bytes(b));
            }
        }
    }
}

#[derive(Clone)]
enum Reader {
    Standard(sha3::Shake256Reader),
    Prefetched(crate::shake2::Reader),
    Scheduled(crate::ct_stream_schedule::Reader),
}
impl XofReader for Reader {
    fn read(&mut self, out: &mut [u8]) {
        match self {
            Self::Standard(r) => r.read(out),
            Self::Prefetched(r) => r.read(out),
            Self::Scheduled(r) => r.read(out),
        }
    }
}
fn standard_reader(r: sha3::Shake256Reader) -> Reader {
    Reader::Standard(r)
}

/// Buffered SHAKE256 XOF: identical byte stream to unbuffered reads, but
/// served from a block buffer (per-call reader overhead dominates otherwise).
pub struct Xof {
    reader: Reader,
    buf: [u8; XOF_BUF],
    pos: usize,
    #[cfg(test)]
    consumed: usize,
}

impl Drop for Xof {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.pos.zeroize();
        // sha3's zeroize feature erases the permutation state on drop.
        // Its digest wrapper's partial-block buffer is not covered.
    }
}

impl Xof {
    pub fn new(domain: &[u8], parts: &[&[u8]]) -> Xof {
        let mut h = Shake256::default();
        h.update(domain);
        for p in parts {
            // length-prefixed to keep the encoding injective
            h.update(&(p.len() as u64).to_le_bytes());
            h.update(p);
        }
        Xof {
            reader: standard_reader(h.finalize_xof()),
            buf: [0; XOF_BUF],
            pos: XOF_BUF,
            #[cfg(test)]
            consumed: 0,
        }
    }

    /// Continue an already-absorbed state; the caller guarantees the absorbed
    /// bytes equal the exact length-prefixed transcript `new` would absorb.
    pub(crate) fn from_absorbed(h: Shake256) -> Xof {
        Xof {
            reader: standard_reader(h.finalize_xof()),
            buf: [0; XOF_BUF],
            pos: XOF_BUF,
            #[cfg(test)]
            consumed: 0,
        }
    }

    /// Absorb one length-prefixed part into an unfinished state.
    pub(crate) fn absorb_part(h: &mut Shake256, p: &[u8]) {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }

    pub(crate) fn from_prefetched(reader: crate::shake2::Reader) -> Self {
        Self {
            reader: Reader::Prefetched(reader),
            buf: [0; XOF_BUF],
            pos: XOF_BUF,
            #[cfg(test)]
            consumed: 0,
        }
    }

    pub(crate) fn from_scheduled(reader: crate::ct_stream_schedule::Reader) -> Self {
        Self {
            reader: Reader::Scheduled(reader),
            buf: [0; XOF_BUF],
            pos: XOF_BUF,
            #[cfg(test)]
            consumed: 0,
        }
    }

    /// Move a scheduled reader's prefix storage out for pooling (`None` for
    /// the other reader kinds). The stream must not be read afterwards.
    pub(crate) fn take_scheduled_prefix(&mut self) -> Option<crate::ct_erase::Words<17>> {
        match &mut self.reader {
            Reader::Scheduled(r) => Some(r.take_prefix()),
            _ => None,
        }
    }

    #[inline(never)]
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.pos == XOF_BUF {
                if let Reader::Scheduled(reader) = &mut self.reader {
                    reader.read(&mut out[done..]);
                    #[cfg(test)]
                    {
                        self.consumed += out.len() - done;
                    }
                    return;
                }
                self.reader.read(&mut self.buf);
                self.pos = 0;
            }
            let take = (out.len() - done).min(XOF_BUF - self.pos);
            out[done..done + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            #[cfg(test)]
            {
                self.consumed += take;
            }
            done += take;
        }
    }

    /// Borrow generated bytes without refilling or extending a stream. A
    /// scheduled reader owns and later erases the borrowed prefix storage.
    #[inline(always)]
    pub(crate) fn consume_attempt_prefix(&mut self, visit: impl FnOnce(&[u8]) -> usize) -> usize {
        let used = if self.pos < XOF_BUF {
            let used = visit(&self.buf[self.pos..]);
            assert!(used <= XOF_BUF - self.pos);
            self.pos += used;
            used
        } else if let Reader::Scheduled(reader) = &mut self.reader {
            reader.consume_prefix(visit)
        } else {
            let used = visit(&[]);
            assert_eq!(used, 0);
            used
        };
        #[cfg(test)]
        {
            self.consumed += used;
        }
        used
    }

    pub fn bytes<const K: usize>(&mut self) -> [u8; K] {
        let mut b = [0u8; K];
        self.fill(&mut b);
        b
    }

    pub fn u64(&mut self) -> u64 {
        if self.pos + 8 <= XOF_BUF {
            let v = u64::from_le_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
            self.pos += 8;
            #[cfg(test)]
            {
                self.consumed += 8;
            }
            v
        } else {
            u64::from_le_bytes(self.bytes::<8>())
        }
    }

    pub fn u16(&mut self) -> u16 {
        if self.pos + 2 <= XOF_BUF {
            let v = u16::from_le_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
            self.pos += 2;
            #[cfg(test)]
            {
                self.consumed += 2;
            }
            v
        } else {
            u16::from_le_bytes(self.bytes::<2>())
        }
    }

    #[cfg(test)]
    pub(crate) fn batch_test_consumed_pub(&self) -> usize {
        self.consumed
    }

    #[cfg(test)]
    pub(crate) fn batch_test_same_stream(&self, other: &Self) {
        assert_eq!(self.consumed, other.consumed);
        assert_eq!(self.pos, other.pos);
        assert_eq!(self.buf, other.buf);
        let mut a = self.reader.clone();
        let mut b = other.reader.clone();
        let mut aa = [0; 4096];
        let mut bb = [0; 4096];
        a.read(&mut aa);
        b.read(&mut bb);
        assert_eq!(aa, bb);
    }

    /// Uniform value in [0, q) by 13-bit rejection.
    pub fn coeff_mod_q(&mut self) -> i32 {
        loop {
            let v = (self.u16() & 0x1fff) as i32;
            if v < Q {
                return v;
            }
        }
    }

    pub fn poly_uniform(&mut self) -> Poly {
        // Consume the same little-endian u16 sequence as coeff_mod_q, but
        // from the buffered block directly; refill only at block boundaries.
        let mut p = Poly::ZERO;
        let mut i = 0;
        while i < N {
            if self.pos + 2 > XOF_BUF {
                // one straggling byte (odd position) or an empty buffer: the
                // reference path handles the split read exactly
                p.0[i] = self.coeff_mod_q();
                i += 1;
                continue;
            }
            let avail = (XOF_BUF - self.pos) / 2;
            let mut used = 0;
            for pair in self.buf[self.pos..self.pos + 2 * avail].chunks_exact(2) {
                if i == N {
                    break;
                }
                used += 1;
                let v = (u16::from_le_bytes([pair[0], pair[1]]) & 0x1fff) as i32;
                if v < Q {
                    p.0[i] = v;
                    i += 1;
                }
            }
            self.pos += 2 * used;
            #[cfg(test)]
            {
                self.consumed += 2 * used;
            }
        }
        p
    }

    #[cfg(test)]
    pub(crate) fn poly_uniform_compact(&mut self) -> crate::compact_ring::CompactPoly {
        // Consume the same little-endian u16 sequence as coeff_mod_q, but
        // from the buffered block directly; refill only at block boundaries.
        let mut p = crate::compact_ring::CompactPoly::ZERO;
        let mut i = 0;
        while i < N {
            if self.pos + 2 > XOF_BUF {
                // one straggling byte (odd position) or an empty buffer: the
                // reference path handles the split read exactly
                p.0[i] = self.coeff_mod_q() as i16;
                i += 1;
                continue;
            }
            let avail = (XOF_BUF - self.pos) / 2;
            let mut used = 0;
            for pair in self.buf[self.pos..self.pos + 2 * avail].chunks_exact(2) {
                if i == N {
                    break;
                }
                used += 1;
                let v = (u16::from_le_bytes([pair[0], pair[1]]) & 0x1fff) as i32;
                if v < Q {
                    p.0[i] = v as i16;
                    i += 1;
                }
            }
            self.pos += 2 * used;
            #[cfg(test)]
            {
                self.consumed += 2 * used;
            }
        }
        p
    }

    /// Reference sampler kept as the oracle for `poly_uniform`.
    #[cfg(test)]
    pub fn poly_uniform_reference(&mut self) -> Poly {
        let mut p = Poly::ZERO;
        for c in p.0.iter_mut() {
            *c = self.coeff_mod_q();
        }
        p
    }

    /// CBD1 coefficient in {-1, 0, 1}: difference of two bits.
    pub fn poly_cbd1(&mut self) -> Poly {
        let mut p = Poly::ZERO;
        let mut buf = Zeroizing::new([0u8; N / 4]); // 2 bits per coefficient
        self.fill(&mut buf[..]);
        for i in 0..N {
            let byte = buf[i / 4];
            let sh = 2 * (i % 4);
            let a = (byte >> sh) & 1;
            let b = (byte >> (sh + 1)) & 1;
            p.0[i] = a as i32 - b as i32;
        }
        p
    }
}

/// Only public, unfinished absorbing states. Cloning preserves the exact
/// transcript, including the pending partial rate block. Do not finalize the
/// prefix or replace the canonical public key with a digest.
pub(crate) struct PublicPrefixes {
    verify_prefixes: VerifyPrefixes,
    // Stored by the key import; read only by the reference transcripts of the tests.
    #[allow(dead_code)]
    per_rho_dither_pk: Vec<u8>,
    message_fast: crate::shake2::FastSponge,
    challenge_fast: crate::shake2::FastSponge,
}
impl PublicPrefixes {
    #[cfg(test)]
    pub(crate) fn new(pk: &[u8]) -> Self {
        let mut out = Self::build(pk);
        {
            out.per_rho_dither_pk = pk.to_vec();
        }
        out
    }
    /// Move the public wire allocation; no second copy on key import.
    #[cfg(test)]
    pub(crate) fn new_owned(pk: Vec<u8>) -> Self {
        let mut out = Self::build(&pk);
        out.per_rho_dither_pk = pk;
        out
    }
    pub(crate) fn from_scheduled(
        pk: Vec<u8>,
        [message_fast, challenge_fast]: [crate::shake2::FastSponge; 2],
    ) -> Self {
        Self {
            verify_prefixes: VerifyPrefixes::new(),
            per_rho_dither_pk: pk,
            message_fast,
            challenge_fast,
        }
    }
    #[cfg(test)]
    fn build(pk: &[u8]) -> Self {
        let [message_fast, challenge_fast] = if pk.len() == PK_BYTES {
            crate::shake2::common_prefix::prefixes(pk)
        } else {
            crate::shake2::FastSponge::public_prefix_pair([DOM_MSG, DOM_CHAL], PROFILE_ID, pk)
        };
        Self {
            verify_prefixes: VerifyPrefixes::new(),
            per_rho_dither_pk: Vec::new(),
            message_fast,
            challenge_fast,
        }
    }
    // These public-only APIs use the per-rho transcript. Static
    // endpoints do not call these; they borrow the dither of the prepared key instead.
    #[cfg(test)]
    fn per_rho_scalar_prefix(&self) -> Shake256 {
        {
            let mut h = Shake256::default();
            h.update(DOM_DITH);
            for part in [PROFILE_ID, self.per_rho_dither_pk.as_slice()] {
                h.update(&(part.len() as u64).to_le_bytes());
                h.update(part);
            }
            h
        }
    }
    #[cfg(test)]
    fn per_rho_fast_prefix(&self) -> crate::shake2::Sponge {
        {
            let mut sponge = crate::shake2::Sponge::new();
            sponge.absorb(DOM_DITH);
            sponge.part(PROFILE_ID);
            sponge.part(&self.per_rho_dither_pk);
            sponge
        }
    }
    #[cfg(test)]
    fn continue_with(prefix: &Shake256, parts: &[&[u8]]) -> Xof {
        let mut h = prefix.clone();
        for p in parts {
            h.update(&(p.len() as u64).to_le_bytes());
            h.update(p);
        }
        Xof {
            reader: standard_reader(h.finalize_xof()),
            buf: [0; XOF_BUF],
            pos: XOF_BUF,
            #[cfg(test)]
            consumed: 0,
        }
    }
    // Only public verification calls these continuations. Signing uses the
    // private FastSponge path, including its cleanup and interleaved state.
    pub(crate) fn verify_message_rep(&self, context: &[u8], msg: &[u8]) -> [u8; 64] {
        let mut sponge = if context.is_empty() {
            self.verify_prefixes
                .empty_context
                .get_or_init(|| {
                    let mut sponge = self.message_fast.public_prefix_snapshot();
                    sponge.part(&[]);
                    sponge
                })
                .clone()
        } else {
            let mut s = self.message_fast.public_prefix_snapshot();
            s.public_part(context);
            s
        };
        sponge.public_part(msg);
        let mut reader = crate::shake2::PublicReader::from_absorbed(sponge);
        let mut out = [0; 64];
        reader.read(&mut out);
        out
    }
    pub(crate) fn verify_challenge_bytes(
        &self,
        mu: &[u8; 64],
        rho: &[u8; 32],
        labels: &[u8],
    ) -> [u8; 32] {
        let mut sponge = self
            .verify_prefixes
            .challenge_mu64
            .get_or_init(|| {
                let mut sponge = self.challenge_fast.public_prefix_snapshot();
                sponge.absorb(&64u64.to_le_bytes());
                sponge
            })
            .clone();
        sponge.absorb(mu);
        sponge.verify_rho_labels(rho, labels);
        let mut reader = crate::shake2::PublicReader::from_absorbed(sponge);
        let mut out = [0; 32];
        reader.read(&mut out);
        out
    }
    pub(crate) fn message_rep(&self, context: &[u8], msg: &[u8]) -> [u8; 64] {
        self.message_fast.hash(&[context, msg])
    }
    #[cfg(test)]
    pub(crate) fn expand_dither(&self, rho: &[u8; SALT_BYTES]) -> [Poly; M] {
        let mut x = Self::continue_with(&self.per_rho_scalar_prefix(), &[rho]);
        core::array::from_fn(|_| x.poly_uniform())
    }
    /// Test-only: the dither read through `PublicReader`. The tests of this file compare it
    /// with the free function `expand_dither`.
    #[cfg(test)]
    pub(crate) fn expand_dither_fast(&self, rho: &[u8; SALT_BYTES]) -> [Poly; M] {
        let mut sponge = self.per_rho_fast_prefix();
        sponge.part(rho);
        let mut reader = crate::shake2::PublicReader::from_absorbed(sponge);
        core::array::from_fn(|_| {
            let mut poly = Poly::ZERO;
            reader.uniform_into(&mut poly.0);
            poly
        })
    }
    pub(crate) fn challenge_bytes(
        &self,
        mu: &[u8; 64],
        rho: &[u8; SALT_BYTES],
        labels: &[u8],
    ) -> [u8; 32] {
        // Labels remain private during failed signing attempts. The fast
        // continuation uses private-state cleanup, not the public reader.
        self.challenge_fast.hash(&[mu, rho, labels])
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
    #[test]
    fn owned_static_prefix_preserves_all_roles_and_wire_allocation() {
        for n in [0, 1, 135, 136, 137, PK_BYTES] {
            let pk: Vec<u8> = (0..n).map(|i| (i * 37 + n) as u8).collect();
            let expected = pk.clone();
            let ptr = pk.as_ptr();
            let capacity = pk.capacity();
            let cache = PublicPrefixes::new_owned(pk);
            assert_eq!(cache.per_rho_dither_pk.as_ptr(), ptr);
            assert_eq!(cache.per_rho_dither_pk.capacity(), capacity);
            assert_eq!(cache.per_rho_dither_pk, expected);
            for length in [0, 1, 135, 136, 137, 1024] {
                let msg = vec![length as u8; length];
                let context = b"owned-prefix";
                let rho = [length as u8; SALT_BYTES];
                let mu = message_rep(&expected, context, &msg);
                assert_eq!(cache.message_rep(context, &msg), mu);
                assert_eq!(
                    cache.challenge_bytes(&mu, &rho, &msg),
                    challenge_bytes(&expected, &mu, &rho, &msg)
                );
                assert_eq!(cache.expand_dither(&rho), expand_dither(&expected, &rho));
                assert_eq!(
                    cache.expand_dither_fast(&rho),
                    expand_dither(&expected, &rho)
                );
            }
        }
    }
    #[test]
    fn unfinished_prefixes_match_transcript_and_continuations() {
        // Include real wire size and both sides of SHAKE rate boundaries.
        for pk_len in [0, 1, 135, 136, 137, PK_BYTES] {
            let pk: Vec<u8> = (0..pk_len).map(|i| i as u8).collect();
            let cache = PublicPrefixes::new(&pk);
            for len in [0, 1, 127, 135, 136, 137, 1024, 2049] {
                let msg = vec![len as u8; len];
                let context = vec![42; len % 255];
                let rho = [len as u8; SALT_BYTES];
                let mu = message_rep(&pk, &context, &msg);
                assert_eq!(cache.message_rep(&context, &msg), mu);
                assert_eq!(
                    cache.challenge_bytes(&mu, &rho, &msg),
                    challenge_bytes(&pk, &mu, &rho, &msg)
                );
                let a = cache.expand_dither(&rho);
                let b = expand_dither(&pk, &rho);
                for j in 0..M {
                    assert_eq!(a[j].0, b[j].0);
                }
                for domain in [DOM_MSG, DOM_DITH, DOM_CHAL] {
                    // Independent scalar prefix; fast production fields have
                    // the same representation in tests and release builds.
                    let mut prefix = Shake256::default();
                    prefix.update(domain);
                    for part in [PROFILE_ID, &pk] {
                        Xof::absorb_part(&mut prefix, part);
                    }
                    let mut a = PublicPrefixes::continue_with(&prefix, &[&context, &msg]);
                    let mut b = Xof::new(domain, &[PROFILE_ID, &pk, &context, &msg]);
                    for n in [0, 1, 2, 135, 136, 137, 2049] {
                        let mut aa = vec![0; n];
                        let mut bb = vec![0; n];
                        a.fill(&mut aa);
                        b.fill(&mut bb);
                        assert_eq!(aa, bb);
                        assert_eq!(a.u16(), b.u16());
                        assert_eq!(a.u64(), b.u64());
                    }
                }
            }
        }
    }

    #[test]
    fn public_hardware_dither_matches_canonical_stream_and_unbounded_continuation() {
        for pk_len in (0..=136).chain([PK_BYTES]) {
            let pk: Vec<u8> = (0..pk_len).map(|i| (i * 19 + pk_len) as u8).collect();
            let cache = PublicPrefixes::new(&pk);
            let rho = [pk_len as u8; SALT_BYTES];
            let got = cache.expand_dither_fast(&rho);
            let expected = expand_dither(&pk, &rho);
            for lane in 0..M {
                assert_eq!(got[lane].0, expected[lane].0);
            }
            let mut sponge = cache.per_rho_fast_prefix();
            sponge.part(&rho);
            let mut fast = crate::shake2::PublicReader::from_absorbed(sponge);
            let mut reference = Xof::new(DOM_DITH, &[PROFILE_ID, &pk, &rho]);
            // Cross padding, rate and other block boundaries;
            // continue far beyond the bytes normally consumed by dither.
            for n in [0, 1, 2, 135, 136, 137, 2559, 2560, 2561, 8193] {
                let mut actual = vec![0; n];
                let mut want = vec![0; n];
                fast.read(&mut actual);
                reference.fill(&mut want);
                assert_eq!(actual, want, "pk_len={pk_len}, length={n}");
                assert_eq!(fast.u16(), reference.u16());
            }
        }
    }
}

/// Bind profile, canonical public key, application context, and message.
pub fn message_rep(pk: &[u8], context: &[u8], msg: &[u8]) -> [u8; 64] {
    if pk.len() == PK_BYTES {
        return crate::shake2::common_prefix::hash(DOM_MSG, pk, &[context, msg]);
    }
    let mut x = Xof::new(DOM_MSG, &[PROFILE_ID, pk, context, msg]);
    x.bytes::<64>()
}

/// Message-independent dither. Neither message nor context belongs here.
/// Changing this encoding is a protocol change, even at the same wire length.
pub fn expand_dither(pk: &[u8], rho: &[u8; SALT_BYTES]) -> [Poly; M] {
    let mut x = Xof::new(DOM_DITH, &[PROFILE_ID, pk, rho]);
    core::array::from_fn(|_| x.poly_uniform())
}

/// Challenge binds the profile, full public key, context/message, salt, and labels.
pub fn challenge_bytes(
    pk: &[u8],
    mu: &[u8; 64],
    rho: &[u8; SALT_BYTES],
    u_labels: &[u8],
) -> [u8; 32] {
    if pk.len() == PK_BYTES {
        return crate::shake2::common_prefix::hash(DOM_CHAL, pk, &[mu, rho, u_labels]);
    }
    let mut x = Xof::new(DOM_CHAL, &[PROFILE_ID, pk, mu, rho, u_labels]);
    x.bytes::<32>()
}

pub fn shake256_32(data: &[u8]) -> [u8; 32] {
    let mut h = Shake256::default();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

#[cfg(test)]
mod compact_uniform_tests {
    use super::*;
    #[test]
    fn compact_uniform_preserves_odd_offsets_and_following_stream() {
        for seed in 0..8u8 {
            for offset in [0, 1, 135, 136, 137, 1023] {
                let mut a = Xof::new(b"compact-public-sampler", &[&[seed]]);
                let mut b = Xof::new(b"compact-public-sampler", &[&[seed]]);
                let mut skip = vec![0; offset];
                a.fill(&mut skip);
                b.fill(&mut skip);
                for _ in 0..4 {
                    let actual = a.poly_uniform_compact();
                    let expected = b.poly_uniform_reference();
                    assert_eq!(actual.0.map(|x| x as i32), expected.0);
                }
                let (mut x, mut y) = ([0; 257], [0; 257]);
                a.fill(&mut x);
                b.fill(&mut y);
                assert_eq!(x, y);
            }
        }
    }
}

#[cfg(test)]
#[path = "public_message_tests.rs"]
mod public_message_tests;

/// Raw SHAKE256 of public key bytes only: no domain or length prefix.
pub(crate) fn keygen_public_hash(data: &[u8]) -> [u8; 32] {
    let mut sponge = crate::shake2::Sponge::new();
    sponge.absorb(data);
    let mut reader = crate::shake2::PublicReader::from_absorbed(sponge);
    let mut out = [0; 32];
    reader.read(&mut out);
    out
}

#[cfg(test)]
mod keygen_public_hash_tests {
    use super::*;
    #[test]
    fn raw_public_hash_preserves_padding_at_rate_boundaries() {
        for length in [0, 1, 135, 136, 137, 271, 272, 273, 1280, 1312, 1326] {
            let bytes: Vec<u8> = (0..length).map(|i| (i as u8).wrapping_mul(37)).collect();
            assert_eq!(keygen_public_hash(&bytes), shake256_32(&bytes));
        }
    }
}

/// Unfinished public states only.
struct VerifyPrefixes {
    empty_context: std::sync::OnceLock<crate::shake2::Sponge>,
    challenge_mu64: std::sync::OnceLock<crate::shake2::Sponge>,
}
impl VerifyPrefixes {
    fn new() -> Self {
        // Preparation adds only empty cells. Initialized Sponge values retain
        // their Zeroizing state ownership when the cells are dropped.
        Self {
            empty_context: std::sync::OnceLock::new(),
            challenge_mu64: std::sync::OnceLock::new(),
        }
    }
}
