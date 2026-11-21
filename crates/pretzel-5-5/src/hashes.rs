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

/// Buffered SHAKE256 XOF: identical byte stream to unbuffered reads, but
/// served from a block buffer (per-call reader overhead dominates otherwise).
pub struct Xof {
    reader: sha3::Shake256Reader,
    buf: [u8; XOF_BUF],
    pos: usize,
    #[cfg(test)]
    consumed: usize,
}

#[allow(dead_code)]
impl Drop for Xof {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.pos.zeroize();
        // sha3's zeroize feature erases the permutation state on drop.
        // Its digest wrapper's partial-block buffer is not covered.
    }
}

#[allow(dead_code)]
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
            reader: h.finalize_xof(),
            buf: [0; XOF_BUF],
            pos: XOF_BUF,
            #[cfg(test)]
            consumed: 0,
        }
    }

    #[inline(never)]
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut done = 0;
        while done < out.len() {
            if self.pos == XOF_BUF {
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

    #[allow(dead_code)]
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
    message_fast: crate::shake2::FastSponge,
    challenge_fast: crate::shake2::FastSponge,
}
#[allow(dead_code)]
impl PublicPrefixes {
    pub(crate) fn new(pk: &[u8]) -> Self {
        let [message_fast, challenge_fast] = if pk.len() == PK_BYTES {
            crate::shake2::common_prefix::prefixes(pk)
        } else {
            crate::shake2::FastSponge::public_prefix_pair([DOM_MSG, DOM_CHAL], PROFILE_ID, pk)
        };
        Self::from_owners([message_fast, challenge_fast])
    }
    /// The two absorbing states that public-key preparation already holds for this key.
    pub(crate) fn from_owners(
        [message_fast, challenge_fast]: [crate::shake2::FastSponge; 2],
    ) -> Self {
        Self {
            verify_prefixes: VerifyPrefixes::new(&message_fast, &challenge_fast),
            message_fast,
            challenge_fast,
        }
    }
    // The shared constructor tests pass the key bytes as well; nothing stores them.
    #[cfg(test)]
    pub(crate) fn from_scheduled(_pk: Vec<u8>, owners: [crate::shake2::FastSponge; 2]) -> Self {
        Self::from_owners(owners)
    }
    // Only public verification calls these continuations. Signing uses the
    // private FastSponge path, including its cleanup and interleaved state.
    pub(crate) fn verify_message_rep(&self, context: &[u8], msg: &[u8]) -> [u8; 64] {
        let mut sponge = if context.is_empty() {
            self.verify_prefixes.empty_context.clone()
        } else {
            let mut s = self.verify_prefixes.message.clone();
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
        let mut sponge = {
            let mut s = self.verify_prefixes.challenge_mu64.clone();
            s.absorb(mu);
            s
        };
        sponge.verify_rho_labels(rho, labels);
        let mut reader = crate::shake2::PublicReader::from_absorbed(sponge);
        let mut out = [0; 32];
        reader.read(&mut out);
        out
    }
    pub(crate) fn message_rep(&self, context: &[u8], msg: &[u8]) -> [u8; 64] {
        {
            self.message_fast.hash(&[context, msg])
        }
    }
    pub(crate) fn challenge_bytes(
        &self,
        mu: &[u8; 64],
        rho: &[u8; SALT_BYTES],
        labels: &[u8],
    ) -> [u8; 32] {
        // Labels remain private during failed signing attempts. The fast
        // continuation uses private-state cleanup, not the public reader.
        {
            self.challenge_fast.hash(&[mu, rho, labels])
        }
    }
}

#[cfg(test)]
mod prefix_tests {
    use super::*;
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
            }
        }
    }

    #[test]
    fn public_hardware_dither_matches_canonical_stream_and_unbounded_continuation() {
        for pk_len in (0..=136).chain([PK_BYTES]) {
            let pk: Vec<u8> = (0..pk_len).map(|i| (i * 19 + pk_len) as u8).collect();
            let rho = [pk_len as u8; SALT_BYTES];
            let mut sponge = crate::shake2::Sponge::new();
            sponge.absorb(DOM_DITH);
            sponge.part(PROFILE_ID);
            sponge.part(&pk);
            sponge.part(&rho);
            let mut fast = crate::shake2::PublicReader::from_absorbed(sponge);
            let mut reference = Xof::new(DOM_DITH, &[PROFILE_ID, &pk, &rho]);
            // Cross padding, rate and other block boundaries;
            // continue far beyond one block.
            for n in [0, 1, 2, 135, 136, 137, 2559, 2560, 2561, 8193] {
                let mut actual = vec![0; n];
                let mut want = vec![0; n];
                fast.read(&mut actual);
                reference.fill(&mut want);
                assert_eq!(actual, want, "pk_len={pk_len}, length={n}");
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

/// Unfinished public states only.
struct VerifyPrefixes {
    message: crate::shake2::Sponge,
    empty_context: crate::shake2::Sponge,
    challenge_mu64: crate::shake2::Sponge,
}
impl VerifyPrefixes {
    fn new(message: &crate::shake2::FastSponge, challenge: &crate::shake2::FastSponge) -> Self {
        let message = message.public_prefix_snapshot();
        let mut empty_context = message.clone();
        empty_context.part(&[]);
        let mut challenge_mu64 = challenge.public_prefix_snapshot();
        challenge_mu64.absorb(&64u64.to_le_bytes());
        Self {
            message,
            empty_context,
            challenge_mu64,
        }
    }
}
#[cfg(test)]
mod public_prefix_tests {
    use super::*;
    #[test]
    fn prefix_arbitrary_public_transcripts() {
        let mut rng = 0x987654321u64;
        for pk_len in [0, 1, 127, 128, 135, 136, 137, 272, PK_BYTES] {
            let pk: Vec<u8> = (0..pk_len)
                .map(|_| {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    rng as u8
                })
                .collect();
            let prefixes = PublicPrefixes::new(&pk);
            for context_len in [0, 1, 7, 8, 127, 136, 137, 255] {
                let context = vec![context_len as u8; context_len];
                for message_len in [0, 1, 31, 32, 64, 127, 135, 136, 137, 272, 1025] {
                    let msg: Vec<u8> = (0..message_len).map(|i| i as u8).collect();
                    let mu = prefixes.verify_message_rep(&context, &msg);
                    assert_eq!(mu, prefixes.message_rep(&context, &msg));
                    let rho = [message_len as u8; 32];
                    for length in [0, 1, 135, 136, 137, 1280] {
                        let labels = vec![length as u8; length];
                        let mut sponge = prefixes.challenge_fast.public_prefix_snapshot();
                        sponge.part(&mu);
                        sponge.part(&rho);
                        sponge.part(&labels);
                        let mut reader = crate::shake2::PublicReader::from_absorbed(sponge);
                        let mut expected = [0; 32];
                        reader.read(&mut expected);
                        assert_eq!(
                            prefixes.verify_challenge_bytes(&mu, &rho, &labels),
                            expected
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "../../pretzel-4-4/core/src/public_message_tests.rs"]
mod public_message_tests;
