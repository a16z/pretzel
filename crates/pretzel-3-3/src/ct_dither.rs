//! Fixed-work prefix of the canonical uniform-dither expansion.
//!
//! Retain the first M*N accepted 13-bit words from a fixed prefix. A bitonic
//! network compacts them by (rejected, original index), with public addresses.
//! Exhaustion is a mask, never a data-dependent loop or an early return.
use crate::params::{M, N};
#[cfg(test)]
use crate::{
    ct::{ct_lt_u64, opaque_mask},
    hashes::Xof,
    params::Q,
    ring::Poly,
};
#[cfg(test)]
use zeroize::Zeroizing;

pub(crate) const CANDIDATES: usize = 1280;
pub(crate) const NETWORK: usize = 2048;
const _: () = assert!(
    M * N == 768
        && (CANDIDATES - M * N).is_power_of_two()
        && M * N + 2 * (CANDIDATES - M * N) <= NETWORK
        && CANDIDATES <= NETWORK
        && NETWORK.is_power_of_two()
);

#[cfg(test)]
pub(crate) fn expand(rng: &mut Xof) -> ([Poly; M], u64) {
    let mut bytes = Zeroizing::new([0u8; 2 * CANDIDATES]);
    rng.fill(&mut bytes[..]);
    let mut words = Zeroizing::new([0u16; CANDIDATES]);
    for i in 0..CANDIDATES {
        words[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    }
    compact(&words)
}

#[inline(never)] // One complete network body, kept out of line for inspection.
#[cfg(test)]
fn compact(words: &[u16; CANDIDATES]) -> ([Poly; M], u64) {
    compact_u32(words)
}

#[inline(never)]
#[cfg(test)]
fn compact_u32(words: &[u16; CANDIDATES]) -> ([Poly; M], u64) {
    compact_routed(words)
}

/// `expand` with the routing network run in two caller-owned buffers of the
/// erased signing scratch (no allocation per attempt). Same bytes.
#[cfg(test)]
pub(crate) fn expand_into(
    rng: &mut Xof,
    records: &mut [u32; NETWORK],
    next: &mut [u32; NETWORK],
) -> ([Poly; M], u64) {
    let mut tape_words = [0u64; 2 * CANDIDATES / 8];
    let mut bytes = crate::ct_erase::StackByteGuard::new(&mut tape_words);
    rng.fill(&mut bytes[..]);
    let mut words = Zeroizing::new([0u16; CANDIDATES]);
    for i in 0..CANDIDATES {
        words[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    }
    compact_routed_into(&words, records, next)
}

#[cfg(test)]
#[inline(never)] // One complete network body, kept out of line for inspection.
fn compact_routed_into(
    words: &[u16; CANDIDATES],
    records: &mut [u32; NETWORK],
    next: &mut [u32; NETWORK],
) -> ([Poly; M], u64) {
    let mut rank = 0u32;
    for i in 0..CANDIDATES {
        let value = (words[i] & 8191) as u32;
        let valid = opaque_mask(ct_lt_u64(value as u64, Q as u64)) as u32;
        records[i] = ((1 << 31) | ((i as u32 - rank) << 13) | value) & valid;
        rank += valid & 1;
    }
    // Inactive tail (public extent), independent of what the buffer held.
    records[CANDIDATES..].fill(0);
    let routed = crate::ct_compact::route_prefix_into::<13>(
        &mut records[..],
        &mut next[..],
        M * N,
        CANDIDATES - M * N,
    );
    let ok = !ct_lt_u64(rank as u64, (M * N) as u64);
    let mut out = [Poly::ZERO; M];
    for i in 0..M * N {
        let value = (routed[i] & 8191) as u64;
        out[i / N].0[i % N] = (value & opaque_mask(ct_lt_u64(value, Q as u64))) as i32;
    }
    (out, ok)
}

#[cfg(test)]
fn compact_routed(words: &[u16; CANDIDATES]) -> ([Poly; M], u64) {
    let mut records = Zeroizing::new(vec![0u32; NETWORK]);
    let mut rank = 0u32;
    for i in 0..CANDIDATES {
        let value = (words[i] & 8191) as u32;
        let valid = opaque_mask(ct_lt_u64(value as u64, Q as u64)) as u32;
        records[i] = ((1 << 31) | ((i as u32 - rank) << 13) | value) & valid;
        rank += valid & 1;
    }
    // A successful prefix rejects at most CANDIDATES - M*N words, so no
    // accepted word moves further than that; the bounded network equals the
    // full one on the first M*N outputs. An exhausted prefix aborts the
    // attempt; its (possibly merged) records are forced into [0, Q) so every
    // later fixed-work stage still sees canonical coefficients.
    let records = crate::ct_compact::route_prefix::<13>(records, M * N, CANDIDATES - M * N);
    let ok = !ct_lt_u64(rank as u64, (M * N) as u64);
    let mut out = [Poly::ZERO; M];
    for i in 0..M * N {
        let value = (records[i] & 8191) as u64;
        out[i / N].0[i % N] = (value & opaque_mask(ct_lt_u64(value, Q as u64))) as i32;
    }
    (out, ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compare(words: &[u16; CANDIDATES]) {
        let reference: Vec<i32> = words
            .iter()
            .map(|w| (w & 8191) as i32)
            .filter(|&v| v < Q)
            .collect();
        let (out, ok) = compact(words);
        assert_eq!(ok == u64::MAX, reference.len() >= M * N);
        for (i, &v) in out.iter().flat_map(|p| p.0.iter()).enumerate() {
            // Every accepted prefix (at most CANDIDATES - M*N rejections) is
            // reproduced exactly. An exhausted prefix aborts the attempt; its
            // coefficients are only required to be canonical (bounded network).
            if reference.len() >= M * N || CANDIDATES - reference.len() <= CANDIDATES - M * N {
                assert_eq!(v, reference.get(i).copied().unwrap_or(0));
            }
            assert!((0..Q).contains(&v));
        }
    }

    #[test]
    fn compaction_preserves_order_and_masks_exhaustion() {
        for accepted in [0, 1, 511, M * N - 1, M * N, M * N + 1, CANDIDATES] {
            for reverse in [false, true] {
                let mut words = [8191u16; CANDIDATES];
                for i in 0..accepted {
                    let j = if reverse { CANDIDATES - 1 - i } else { i };
                    words[j] = (i as u16 * 7) % (Q as u16);
                }
                compare(&words);
            }
        }
        let mut state = 0x192c467bf081dea3u64;
        for _ in 0..64 {
            let words = core::array::from_fn(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u16
            });
            compare(&words);
        }
    }

    #[test]
    fn scratch_expansion_matches_the_allocating_expansion() {
        let mut records = Box::new([0xffff_ffffu32; NETWORK]);
        let mut next = Box::new([0xffff_ffffu32; NETWORK]);
        for seed in 0..8u8 {
            let mut a = Xof::new(b"public-dither-scratch-test", &[&[seed]]);
            let mut b = Xof::new(b"public-dither-scratch-test", &[&[seed]]);
            let (x, okx) = expand(&mut a);
            let (y, oky) = expand_into(&mut b, &mut records, &mut next);
            assert_eq!(okx, oky);
            for i in 0..M {
                assert_eq!(x[i].0, y[i].0);
            }
        }
    }

    #[test]
    fn bounded_dither_matches_canonical_stream() {
        for seed in 0..32u8 {
            let mut a = Xof::new(b"public-dither-test", &[&[seed]]);
            let mut b = Xof::new(b"public-dither-test", &[&[seed]]);
            let (out, ok) = expand(&mut a);
            assert_eq!(ok, u64::MAX);
            let expected: [Poly; M] = core::array::from_fn(|_| b.poly_uniform());
            for i in 0..M {
                assert_eq!(out[i].0, expected[i].0);
            }
        }
    }
}
