//! Domain-separated attempt streams for the randomized signer.
//!
//! Fresh OS entropy is mandatory; the caller fails closed on RNG errors.
//! No evolving signing state is required. Repeating the entropy, key,
//! message/context, and retry index repeats the entire tape.

use crate::hashes::Xof;
use crate::params::*;
use sha3::digest::Update;
use sha3::Shake256;

// The same string as at Pretzel-(4,4). It is absorbed into the attempt streams, so it is
// part of the format. It contains `lo120000`: 120000 is `SHELL_LO` of Pretzel-(4,4), not
// of this crate (`params.rs`).
pub(crate) const CT_TAPE_DOMAIN: &[u8] = b"ct-schedule-v17-t28-lo120000-hmix192-2p-alias8";

/// Per-key unfinished SHAKE states after the constant prefix
/// (domain, PROFILE_ID[, CT_TAPE_DOMAIN], prf_key, pk) of each stateless
/// attempt stream. Continuing a clone with (mu, retry, entropy) absorbs the
/// exact transcript of `AttemptRandomness::new`; only the per-attempt work of
/// six pk-sized absorptions is saved. Secret-derived: erased on drop.
pub(crate) struct StreamPrefixes {
    scheduled: crate::ct_stream_schedule::Prefixes,
    salt: Shake256,
    lead: Shake256,
    secret: Shake256,
    error: Shake256,
    transport: Shake256,
    dummy: Shake256,
    mask_pair: crate::shake2::Prefixes,
}

impl StreamPrefixes {
    pub(crate) fn new(key: &[u8; 32], pk: &[u8]) -> Self {
        let prefix = |domain: &[u8]| {
            let mut h = Shake256::default();
            h.update(domain);
            Xof::absorb_part(&mut h, PROFILE_ID);
            Xof::absorb_part(&mut h, CT_TAPE_DOMAIN);
            Xof::absorb_part(&mut h, key);
            Xof::absorb_part(&mut h, pk);
            h
        };
        Self {
            scheduled: crate::ct_stream_schedule::Prefixes::new(key, pk),
            salt: prefix(DOM_SALT),
            lead: prefix(DOM_MASK_LEAD),
            secret: prefix(DOM_MASK_SEC),
            error: prefix(DOM_MASK_ERR),
            transport: prefix(DOM_TRANSPORT),
            dummy: prefix(DOM_DUMMY),
            mask_pair: crate::shake2::Prefixes::new(key, pk),
        }
    }
    fn continue_with(h: &Shake256, mu: &[u8; 64], retry: &[u8; 4], entropy: &[u8; 32]) -> Xof {
        let mut h = h.clone();
        Xof::absorb_part(&mut h, mu);
        Xof::absorb_part(&mut h, retry);
        Xof::absorb_part(&mut h, entropy);
        Xof::from_absorbed(h)
    }
}

pub(crate) struct AttemptRandomness<R = Xof> {
    pub rho: [u8; SALT_BYTES],
    pub lead: Xof,
    pub secret: R,
    pub error: R,
    pub transport: Xof,
    pub dummy: Xof,
}

impl AttemptRandomness {
    /// `from_prefixes` with the scheduled prefixes written into the signing
    /// scratch pool (no per-attempt allocation on the native path). The salt
    /// storage is recycled at once; the other five through `recycle`.
    pub(crate) fn from_prefixes_pooled(
        p: &StreamPrefixes,
        mu: &[u8; 64],
        retry: u32,
        entropy: &[u8; 32],
        pool: &mut crate::ct_stream_schedule::PrefixPool,
    ) -> Self {
        if crate::shake2::available() {
            let retry = retry.to_le_bytes();
            let [mut salt, lead, secret, error, transport, dummy] =
                p.scheduled.expand_pooled(mu, &retry, entropy, pool);
            let rho = salt.bytes();
            if let Some(w) = salt.take_scheduled_prefix() {
                pool.recycle(0, w);
            }
            return Self {
                rho,
                lead,
                secret,
                error,
                transport,
                dummy,
            };
        }
        Self::from_prefixes(p, mu, retry, entropy)
    }

    /// Erase and return the pooled prefix storage of every stream. Call after
    /// the attempt, before the streams are dropped.
    pub(crate) fn recycle(&mut self, pool: &mut crate::ct_stream_schedule::PrefixPool) {
        let streams = [
            &mut self.lead,
            &mut self.secret,
            &mut self.error,
            &mut self.transport,
            &mut self.dummy,
        ];
        for (i, x) in streams.into_iter().enumerate() {
            if let Some(w) = x.take_scheduled_prefix() {
                pool.recycle(i + 1, w);
            }
        }
    }

    /// Same tape as `new` for the same (key, pk, mu, retry, entropy).
    pub fn from_prefixes(
        p: &StreamPrefixes,
        mu: &[u8; 64],
        retry: u32,
        entropy: &[u8; 32],
    ) -> Self {
        let retry = retry.to_le_bytes();
        if crate::shake2::available() {
            let [mut salt, lead, secret, error, transport, dummy] =
                p.scheduled.expand(mu, &retry, entropy);
            return Self {
                rho: salt.bytes(),
                lead,
                secret,
                error,
                transport,
                dummy,
            };
        }
        // Reached only when `shake2::available()` was false above, so `pair` is `None` and the
        // secret and error streams continue as scalar sponges.
        let pair = crate::shake2::available().then(|| p.mask_pair.expand(mu, &retry, entropy));
        let (secret, error) = pair.unwrap_or_else(|| {
            (
                StreamPrefixes::continue_with(&p.secret, mu, &retry, entropy),
                StreamPrefixes::continue_with(&p.error, mu, &retry, entropy),
            )
        });
        let rho: [u8; SALT_BYTES] =
            StreamPrefixes::continue_with(&p.salt, mu, &retry, entropy).bytes();
        Self {
            rho,
            lead: StreamPrefixes::continue_with(&p.lead, mu, &retry, entropy),
            secret,
            error,
            transport: StreamPrefixes::continue_with(&p.transport, mu, &retry, entropy),
            dummy: StreamPrefixes::continue_with(&p.dummy, mu, &retry, entropy),
        }
    }

    /// Direct construction; the oracle for `from_prefixes` in tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(key: &[u8; 32], pk: &[u8], mu: &[u8; 64], retry: u32, entropy: &[u8; 32]) -> Self {
        let retry = retry.to_le_bytes();
        let stream = |domain| {
            Xof::new(
                domain,
                &[PROFILE_ID, CT_TAPE_DOMAIN, key, pk, mu, &retry, entropy],
            )
        };
        let rho: [u8; SALT_BYTES] = stream(DOM_SALT).bytes();
        Self {
            rho,
            lead: stream(DOM_MASK_LEAD),
            secret: stream(DOM_MASK_SEC),
            error: stream(DOM_MASK_ERR),
            transport: stream(DOM_TRANSPORT),
            dummy: stream(DOM_DUMMY),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_prefixes_reproduce_the_direct_tape_across_rate_boundaries() {
        // Real wire size plus lengths on both sides of the 136-byte SHAKE rate.
        for pk_len in [0usize, 1, 100, 135, 136, 137, 271, 272, 273, PK_BYTES] {
            let pk: Vec<u8> = (0..pk_len).map(|i| (i * 7 + 3) as u8).collect();
            let key = [0x5au8; 32];
            let prefixes = StreamPrefixes::new(&key, &pk);
            for (retry, mu_byte, ent) in [
                (0u32, 1u8, 2u8),
                (1, 0, 0),
                (511, 255, 17),
                (u32::MAX, 9, 200),
            ] {
                let mu = [mu_byte; 64];
                let entropy = [ent; 32];
                let mut a = AttemptRandomness::new(&key, &pk, &mu, retry, &entropy);
                let mut b = AttemptRandomness::from_prefixes(&prefixes, &mu, retry, &entropy);
                assert_eq!(a.rho, b.rho);
                for (x, y) in [
                    (&mut a.lead, &mut b.lead),
                    (&mut a.secret, &mut b.secret),
                    (&mut a.error, &mut b.error),
                    (&mut a.transport, &mut b.transport),
                    (&mut a.dummy, &mut b.dummy),
                ] {
                    for n in [0usize, 1, 2, 7, 135, 136, 137, 1000] {
                        let mut xa = vec![0u8; n];
                        let mut xb = vec![0u8; n];
                        x.fill(&mut xa);
                        y.fill(&mut xb);
                        assert_eq!(xa, xb);
                        assert_eq!(x.u64(), y.u64());
                        assert_eq!(x.u16(), y.u16());
                    }
                }
            }
        }
    }

    fn fingerprints(pk: &[u8], mu: &[u8; 64], retry: u32, entropy: &[u8; 32]) -> Vec<[u8; 32]> {
        let mut r = AttemptRandomness::new(&[7; 32], pk, mu, retry, entropy);
        vec![
            r.rho,
            r.lead.bytes(),
            r.secret.bytes(),
            r.error.bytes(),
            r.transport.bytes(),
            r.dummy.bytes(),
        ]
    }

    #[test]
    fn domains_and_attempt_inputs_are_separated() {
        let base = fingerprints(b"pk", &[1; 64], 0, &[2; 32]);
        for i in 0..base.len() {
            for j in 0..i {
                assert_ne!(base[i], base[j]);
            }
        }
        for changed in [
            fingerprints(b"other pk", &[1; 64], 0, &[2; 32]),
            fingerprints(b"pk", &[3; 64], 0, &[2; 32]),
            fingerprints(b"pk", &[1; 64], 1, &[2; 32]),
            fingerprints(b"pk", &[1; 64], 0, &[4; 32]),
        ] {
            for (a, b) in base.iter().zip(changed) {
                assert_ne!(*a, b);
            }
        }
        assert_eq!(base, fingerprints(b"pk", &[1; 64], 0, &[2; 32]));
    }

    #[test]
    fn sampler_consumption_cannot_shift_transport_or_dummy_stream() {
        let mut a = AttemptRandomness::new(&[7; 32], b"pk", &[1; 64], 0, &[2; 32]);
        let mut b = AttemptRandomness::new(&[7; 32], b"pk", &[1; 64], 0, &[2; 32]);
        a.lead.fill(&mut [0; 5000]);
        a.secret.fill(&mut [0; 3000]);
        a.error.fill(&mut [0; 1000]);
        assert_eq!(a.transport.bytes::<64>(), b.transport.bytes::<64>());
        a.transport.fill(&mut [0; 3000]);
        assert_eq!(a.dummy.bytes::<64>(), b.dummy.bytes::<64>());
    }
}
