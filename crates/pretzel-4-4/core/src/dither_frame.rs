//! Bounded public dither framing for key generation, signing and verification.
//! Core parsing validates canonical coefficients separately; no seed is certified here.

pub const CORE_PUBLIC_KEY_BYTES: usize = crate::params::CORE_PK_BYTES;
pub const SEED_BYTES: usize = 32;
pub const AUGMENTED_PUBLIC_KEY_BYTES: usize = CORE_PUBLIC_KEY_BYTES + SEED_BYTES;

pub const PROFILE: &[u8; 14] = crate::direct_ntt_profile::PROFILE;
pub const DOMAIN: &[u8] = b"LILT-DITH-KEY-v1";
pub const MAX_CANDIDATES: usize = 2048;
pub const EXPANSION_CANDIDATES: usize = 1536;
pub const DITHER_COEFFICIENTS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    KeyLength,
    CandidateIndex,
    DitherExhausted,
}

pub fn split_public_key(bytes: &[u8]) -> Result<(&[u8], &[u8; SEED_BYTES]), FrameError> {
    if bytes.len() != AUGMENTED_PUBLIC_KEY_BYTES {
        return Err(FrameError::KeyLength);
    }
    let (core, tail) = bytes.split_at(CORE_PUBLIC_KEY_BYTES);
    let seed = tail.try_into().map_err(|_| FrameError::KeyLength)?;
    Ok((core, seed))
}

pub fn encode_public_key(
    core: &[u8],
    seed: &[u8; SEED_BYTES],
) -> Result<[u8; AUGMENTED_PUBLIC_KEY_BYTES], FrameError> {
    if core.len() != CORE_PUBLIC_KEY_BYTES {
        return Err(FrameError::KeyLength);
    }
    let mut out = [0u8; AUGMENTED_PUBLIC_KEY_BYTES];
    out[..CORE_PUBLIC_KEY_BYTES].copy_from_slice(core);
    out[CORE_PUBLIC_KEY_BYTES..].copy_from_slice(seed);
    Ok(out)
}

/// Predetermined distinct inputs: starting seed plus index modulo 2^256.
/// Key generation draws the starting seed independently of the challenge oracle.
pub fn candidate_seed(
    start: &[u8; SEED_BYTES],
    index: usize,
) -> Result<[u8; SEED_BYTES], FrameError> {
    if index >= MAX_CANDIDATES {
        return Err(FrameError::CandidateIndex);
    }
    let mut out = *start;
    let mut carry = index as u16;
    for byte in &mut out {
        let sum = u16::from(*byte) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
    Ok(out)
}

/// Public setup/preparation only. Fixed prefix exhaustion rejects the key seed.
/// Each candidate uses low 13 bits of an independent little-endian u16.
/// No signing salt or augmented-key recursion enters this framing.
pub fn expand(
    core: &[u8],
    seed: &[u8; SEED_BYTES],
) -> Result<[i32; DITHER_COEFFICIENTS], FrameError> {
    if core.len() != CORE_PUBLIC_KEY_BYTES {
        return Err(FrameError::KeyLength);
    }
    expand_bounded(PROFILE.as_slice(), core, seed)
}

// `expansion_bytes` is compiled for tests only, as a differential reference.
#[cfg(test)]
// Public preparation only. Both backends produce the complete original prefix;
// no early stopping or change to the finite candidate/exhaustion law.
fn expansion_bytes(
    profile: &[u8],
    core: &[u8],
    seed: &[u8; SEED_BYTES],
) -> [u8; 2 * EXPANSION_CANDIDATES] {
    if profile == PROFILE.as_slice() {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };
        let mut h = Shake256::default();
        for part in [profile, core] {
            h.update(&(part.len() as u64).to_le_bytes());
            h.update(part);
        }
        h.update(DOMAIN);
        h.update(&32u64.to_le_bytes());
        h.update(seed);
        let mut out = [0; 2 * EXPANSION_CANDIDATES];
        h.finalize_xof().read(&mut out);
        return out;
    }
    {
        let mut sponge = crate::shake2::FastSponge::new();
        sponge.absorb(DOMAIN);
        sponge.part(profile);
        sponge.part(core);
        sponge.part(seed.as_slice());
        // No suffix parts: &[] adds no framed empty part to this transcript.
        sponge.hash::<{ 2 * EXPANSION_CANDIDATES }>(&[])
    }
}

#[cfg(test)]
fn decode_prefix(
    bytes: &[u8; 2 * EXPANSION_CANDIDATES],
) -> Result<[i32; DITHER_COEFFICIENTS], FrameError> {
    let mut out = [0i32; DITHER_COEFFICIENTS];
    let mut used = 0usize;
    for pair in bytes.chunks_exact(2) {
        let value = u16::from_le_bytes([pair[0], pair[1]]) & 8191;
        if value < 7681 && used < out.len() {
            out[used] = i32::from(value);
            used += 1;
        }
    }
    if used == out.len() {
        Ok(out)
    } else {
        Err(FrameError::DitherExhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_roundtrip_length_and_seed_wrap() {
        let core = [3u8; CORE_PUBLIC_KEY_BYTES];
        let seed = [255u8; SEED_BYTES];
        let wire = encode_public_key(&core, &seed).unwrap();
        let (decoded, selected) = split_public_key(&wire).unwrap();
        assert_eq!(decoded, &core);
        assert_eq!(selected, &seed);
        assert_eq!(candidate_seed(&seed, 1).unwrap(), [0u8; SEED_BYTES]);
        assert_eq!(
            candidate_seed(&seed, MAX_CANDIDATES),
            Err(FrameError::CandidateIndex)
        );
        assert_eq!(
            split_public_key(&wire[..wire.len() - 1]),
            Err(FrameError::KeyLength)
        );
    }
    #[test]
    fn prefix_accept_reject_and_no_word_overlap() {
        let zeros = [0u8; 2 * EXPANSION_CANDIDATES];
        assert_eq!(decode_prefix(&zeros).unwrap(), [0; DITHER_COEFFICIENTS]);
        let mut rejected = [255u8; 2 * EXPANSION_CANDIDATES];
        assert_eq!(decode_prefix(&rejected), Err(FrameError::DitherExhausted));
        for i in 0..DITHER_COEFFICIENTS {
            rejected[2 * i..2 * i + 2].copy_from_slice(&(i as u16).to_le_bytes());
        }
        let decoded = decode_prefix(&rejected).unwrap();
        for (i, value) in decoded.iter().enumerate() {
            assert_eq!(*value, i as i32);
        }
    }
}

#[cfg(test)]
mod static_backend_tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    // Independent standard SHAKE construction, not expansion_bytes as its oracle.
    fn reference(
        profile: &[u8],
        core: &[u8],
        seed: &[u8; SEED_BYTES],
    ) -> [u8; 2 * EXPANSION_CANDIDATES] {
        let mut state = Shake256::default();
        state.update(DOMAIN);
        for part in [profile, core, seed.as_slice()] {
            state.update(&(part.len() as u64).to_le_bytes());
            state.update(part);
        }
        let mut bytes = [0u8; 2 * EXPANSION_CANDIDATES];
        state.finalize_xof().read(&mut bytes);
        bytes
    }

    #[test]
    fn complete_static_prefix_matches_independent_shake_both_profiles() {
        for (profile, length) in [
            (b"pretzel-pkd-v1".as_slice(), 1685usize),
            (b"pretzel-pk13v1".as_slice(), 1696usize),
        ] {
            for case in 0..16u8 {
                let core: Vec<u8> = (0..length)
                    .map(|i| match case {
                        0 => 0,
                        1 => 255,
                        _ => (i as u8).wrapping_mul(37).wrapping_add(case),
                    })
                    .collect();
                let seed = core::array::from_fn(|i| match case {
                    0 => 0,
                    1 => 255,
                    _ => (i as u8).wrapping_mul(73).wrapping_add(case),
                });
                let actual = expansion_bytes(profile, &core, &seed);
                let expected = reference(profile, &core, &seed);
                assert_eq!(actual, expected, "profile={profile:?}, case={case}");
                assert_eq!(decode_prefix(&actual), decode_prefix(&expected));
            }
        }
        // The two tags above select the frame that starts with the domain.
        // The profile of this crate absorbs the tag and the core first, then
        // the domain and the seed; `expand` is checked against that frame.
        for case in 0..16u8 {
            let core: Vec<u8> = (0..CORE_PUBLIC_KEY_BYTES)
                .map(|i| match case {
                    0 => 0,
                    1 => 255,
                    _ => (i as u8).wrapping_mul(37).wrapping_add(case),
                })
                .collect();
            let seed: [u8; SEED_BYTES] = core::array::from_fn(|i| match case {
                0 => 0,
                1 => 255,
                _ => (i as u8).wrapping_mul(73).wrapping_add(case),
            });
            let mut state = Shake256::default();
            for part in [PROFILE.as_slice(), core.as_slice()] {
                state.update(&(part.len() as u64).to_le_bytes());
                state.update(part);
            }
            state.update(DOMAIN);
            state.update(&(SEED_BYTES as u64).to_le_bytes());
            state.update(seed.as_slice());
            let mut bytes = [0u8; 2 * EXPANSION_CANDIDATES];
            state.finalize_xof().read(&mut bytes);
            assert_eq!(expand(&core, &seed), decode_prefix(&bytes), "case={case}");
        }
    }

    #[test]
    fn static_prefix_exact_cutoff_rejection_and_length_errors_preserved() {
        let seed = [0u8; SEED_BYTES];
        for length in [0, CORE_PUBLIC_KEY_BYTES - 1, CORE_PUBLIC_KEY_BYTES + 1] {
            assert_eq!(expand(&vec![0; length], &seed), Err(FrameError::KeyLength));
        }
        let mut bytes = [255u8; 2 * EXPANSION_CANDIDATES];
        // Exactly 1023 accepts: exhaustion despite unconsumed rejected suffix.
        for i in 0..DITHER_COEFFICIENTS - 1 {
            bytes[2 * i..2 * i + 2].copy_from_slice(&(i as u16).to_le_bytes());
        }
        assert_eq!(decode_prefix(&bytes), Err(FrameError::DitherExhausted));
        // The final allowed candidate may be the 1024th accept.
        bytes[2 * EXPANSION_CANDIDATES - 2..].copy_from_slice(&7680u16.to_le_bytes());
        let last = decode_prefix(&bytes).unwrap();
        for i in 0..DITHER_COEFFICIENTS - 1 {
            assert_eq!(last[i], i as i32);
        }
        assert_eq!(last[DITHER_COEFFICIENTS - 1], 7680);
        // Threshold and high-bit masking at the only remaining accepting slot.
        for value in [0u16, 7680, 7681, 8191, 8192, 65535] {
            bytes[2 * EXPANSION_CANDIDATES - 2..].copy_from_slice(&value.to_le_bytes());
            let got = decode_prefix(&bytes);
            if value & 8191 < 7681 {
                assert_eq!(got.unwrap()[DITHER_COEFFICIENTS - 1], (value & 8191) as i32);
            } else {
                assert_eq!(got, Err(FrameError::DitherExhausted));
            }
        }
        // All later candidates are ignored after the 1024th accepted value.
        bytes.fill(0);
        let early = decode_prefix(&bytes).unwrap();
        bytes[2 * DITHER_COEFFICIENTS..].fill(255);
        assert_eq!(decode_prefix(&bytes).unwrap(), early);
    }
}

fn decode_bounded(mut next: impl FnMut() -> u16) -> Result<[i32; DITHER_COEFFICIENTS], FrameError> {
    let mut out = [0i32; DITHER_COEFFICIENTS];
    let mut used = 0;
    for _ in 0..EXPANSION_CANDIDATES {
        let value = next() & 8191;
        if value < 7681 {
            out[used] = i32::from(value);
            used += 1;
            if used == out.len() {
                return Ok(out);
            }
        }
    }
    Err(FrameError::DitherExhausted)
}
// Rate-buffered public adapter: physical extraction is bounded by 2 * EXPANSION_CANDIDATES bytes;
// no logical candidate beyond the finite cutoff is requested or examined.

fn decode_rate_buffered(
    mut fill: impl FnMut(&mut [u8]),
) -> Result<[i32; DITHER_COEFFICIENTS], FrameError> {
    let mut block = zeroize::Zeroizing::new([0u8; 136]);
    let mut pos = 0;
    let mut end = 0;
    let mut fetched = 0;
    decode_bounded(|| {
        if pos == end {
            end = (2 * EXPANSION_CANDIDATES - fetched).min(block.len());
            assert!(end >= 2);
            fill(&mut block[..end]);
            fetched += end;
            pos = 0;
        }
        let word = u16::from_le_bytes([block[pos], block[pos + 1]]);
        pos += 2;
        word
    })
}
fn expand_bounded(
    profile: &[u8],
    core: &[u8],
    seed: &[u8; SEED_BYTES],
) -> Result<[i32; DITHER_COEFFICIENTS], FrameError> {
    if profile == PROFILE.as_slice() {
        let mut out = [0; DITHER_COEFFICIENTS];
        crate::shake2::common_prefix::dither(core, seed, &mut out)?;
        return Ok(out);
    }

    {
        let mut sponge = crate::shake2::FastSponge::new();
        sponge.absorb(DOMAIN);
        sponge.part(profile);
        sponge.part(core);
        sponge.part(seed);
        let mut reader = sponge.into_public_reader();
        decode_rate_buffered(|block| reader.fill_public(block))
    }
}

#[cfg(test)]
mod bounded_backend_tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    fn compare(words: &[u16; EXPANSION_CANDIDATES], reads: usize) {
        let mut bytes = [0u8; 2 * EXPANSION_CANDIDATES];
        for (i, w) in words.iter().enumerate() {
            bytes[2 * i..2 * i + 2].copy_from_slice(&w.to_le_bytes());
        }
        let mut used = 0;
        let actual = decode_bounded(|| {
            let w = words[used];
            used += 1;
            w
        });
        assert_eq!(actual, decode_prefix(&bytes));
        assert_eq!(used, reads);
        {
            let mut physical = 0;
            let mut calls = 0;
            let buffered = decode_rate_buffered(|out| {
                assert_eq!(out.len(), (bytes.len() - physical).min(136));
                out.copy_from_slice(&bytes[physical..physical + out.len()]);
                physical += out.len();
                calls += 1;
            });
            assert_eq!(buffered, actual);
            assert_eq!(calls, (2 * reads + 135) / 136);
            assert_eq!(physical, (calls * 136).min(bytes.len()));
        }
    }
    #[test]
    fn bounded_cutoff_every_success_position_and_all_u16_values() {
        compare(&[0; EXPANSION_CANDIDATES], 1024);
        compare(&[65535; EXPANSION_CANDIDATES], 1536);
        for last in 1023..1536 {
            let mut words = [8191u16; EXPANSION_CANDIDATES];
            words[..1023].fill(7680);
            compare(&words, 1536);
            words[last] = 7680;
            compare(&words, last + 1);
            words[last] = 7681;
            compare(&words, 1536);
        }
        for value in 0u16..=u16::MAX {
            let mut words = [0; EXPANSION_CANDIDATES];
            words[0] = value;
            compare(&words, if value & 8191 < 7681 { 1024 } else { 1025 });
        }
    }
    #[test]
    fn bounded_framing_both_profiles_matches_full_independent_shake() {
        for (profile, len) in [
            (b"pretzel-pkd-v1".as_slice(), 1685usize),
            (b"pretzel-pk13v1".as_slice(), 1696usize),
        ] {
            for case in 0..16u8 {
                let core: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(37).wrapping_add(case))
                    .collect();
                let seed = [case; 32];
                let mut h = Shake256::default();
                h.update(DOMAIN);
                for part in [profile, core.as_slice(), seed.as_slice()] {
                    h.update(&(part.len() as u64).to_le_bytes());
                    h.update(part);
                }
                let mut bytes = [0u8; 3072];
                h.finalize_xof().read(&mut bytes);
                assert_eq!(expansion_bytes(profile, &core, &seed), bytes);
                assert_eq!(expand_bounded(profile, &core, &seed), decode_prefix(&bytes));
                {
                    let mut sponge = crate::shake2::FastSponge::new();
                    sponge.absorb(DOMAIN);
                    sponge.part(profile);
                    sponge.part(&core);
                    sponge.part(&seed);
                    let mut reader = sponge.into_public_reader();
                    let actual = decode_rate_buffered(|out| reader.fill_public(out));
                    assert_eq!(actual, decode_prefix(&bytes));
                    let mut accepted = 0;
                    let mut words = 0;
                    for p in bytes.chunks_exact(2) {
                        words += 1;
                        if u16::from_le_bytes([p[0], p[1]]) & 8191 < 7681 {
                            accepted += 1;
                        }
                        if accepted == 1024 {
                            break;
                        }
                    }
                    let k = (2 * words + 135) / 136;
                    assert_eq!(reader.test_operations(), [k, k, (k * 136).min(3072)]);
                }
            }
        }
        for len in [0, CORE_PUBLIC_KEY_BYTES - 1, CORE_PUBLIC_KEY_BYTES + 1] {
            assert_eq!(expand(&vec![0; len], &[0; 32]), Err(FrameError::KeyLength));
        }
    }
}

// Packed-profile preparation only; the general expansion API is the
// nonoptimized fallback and differential oracle. Splitting one wire establishes
// core/seed association without an additional allocation or equality pass.

pub(crate) fn expand_with_prefixes(
    pk: &[u8],
) -> Result<([i32; DITHER_COEFFICIENTS], [crate::shake2::FastSponge; 2]), FrameError> {
    #[cfg(all(
        any(target_os = "linux", target_os = "macos"),
        target_arch = "aarch64",
        test
    ))]
    if crate::timing_state::test_support::reject_prepared() {
        // Test-only exhausted public tape, after the real secret-key hash check.
        // Exercise the actual bounded decoder and PreparedPk error propagation.
        crate::timing_state::test_support::observe("dither-exhaustion-fault");
        decode_rate_buffered(|bytes| bytes.fill(0xff))?;
        unreachable!("an all-rejected dither tape cannot produce a row");
    }
    split_public_key(pk)?;
    {
        let mut flat = [0; DITHER_COEFFICIENTS];
        let owners = crate::shake2::common_prefix::without_matrix(pk, &mut flat)?;
        Ok((flat, owners))
    }
}

#[cfg(test)]
mod scheduled_preparation_tests {
    use super::*;
    #[test]
    fn scheduled_dither_matches_retained_expansion_and_length_errors() {
        for case in 0..8 {
            let core: Vec<u8> = (0..CORE_PUBLIC_KEY_BYTES)
                .map(|i| (i * 73 + case * 19) as u8)
                .collect();
            let seed = [case as u8; 32];
            let wire = encode_public_key(&core, &seed).unwrap();
            let (actual, owners) = expand_with_prefixes(&wire).unwrap();
            assert_eq!(Ok(actual), expand(&core, &seed));
            assert_eq!(
                Ok(actual),
                decode_prefix(&expansion_bytes(PROFILE.as_slice(), &core, &seed))
            );
            let old = crate::shake2::common_prefix::prefixes(&wire);
            for lane in 0..2 {
                assert_eq!(
                    owners[lane].hash::<321>(&[b"context", b"message"]),
                    old[lane].hash::<321>(&[b"context", b"message"])
                );
            }
        }
        for len in [
            0,
            AUGMENTED_PUBLIC_KEY_BYTES - 1,
            AUGMENTED_PUBLIC_KEY_BYTES + 1,
        ] {
            assert!(matches!(
                expand_with_prefixes(&vec![0; len]),
                Err(FrameError::KeyLength)
            ));
        }
    }
    #[test]
    fn scheduled_decoder_injected_every_cutoff_and_exhaustion() {
        let wire = [0x31u8; AUGMENTED_PUBLIC_KEY_BYTES];
        let (core, seed) = split_public_key(&wire).unwrap();
        let profile_len = 14u64.to_le_bytes();
        let core_len = (core.len() as u64).to_le_bytes();
        let seed_len = 32u64.to_le_bytes();
        // Cases 0..512 put the 1024th accept at each legal position; 513 and 514 fail.
        for case in 0..515 {
            let mut injected = [255u8; 2 * EXPANSION_CANDIDATES];
            if case != 513 {
                injected[..2 * 1023].fill(0);
            }
            if case < 513 {
                injected[2 * (1023 + case)..2 * (1024 + case)].fill(0);
            }
            let mut fetched = 0;
            let (result, _owners) = crate::shake2::FastSponge::public_dither_prefix_pair(
                [
                    DOMAIN,
                    &profile_len,
                    PROFILE.as_slice(),
                    &core_len,
                    core,
                    &seed_len,
                    seed.as_slice(),
                ],
                [crate::params::DOM_MSG, crate::params::DOM_CHAL],
                PROFILE.as_slice(),
                &wire,
                |fill| {
                    decode_rate_buffered(|out| {
                        fill(out); // Exercise the real schedule, then inject public words.
                        out.copy_from_slice(&injected[fetched..fetched + out.len()]);
                        fetched += out.len();
                    })
                },
            );
            assert_eq!(result, decode_prefix(&injected));
            let words = if case < 513 { 1024 + case } else { 1536 };
            assert_eq!(fetched, (((2 * words + 135) / 136) * 136).min(3072));
        }
    }
}
