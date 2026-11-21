//! Fused schedule equivalence including defined partial output on exhaustion.
use super::*;

#[test]
fn public_schedule_scalar_equivalence_and_exhaustion() {
    for case in 0..4u8 {
        for stop in [0, DITHER_COEFFICIENTS, EXPANSION_CANDIDATES + 1] {
            let run = || {
                let body = vec![case; crate::params::PK_BYTES];
                let mut rows = [[CompactPoly([37; N]); ELL + 1]; M];
                let mut delta = [-1; DITHER_COEFFICIENTS];
                // A broken schedule must fail before its trace or runtime grows unbounded.
                const MAX_CALLS: usize = 256;
                let mut trace = Vec::with_capacity(MAX_CALLS);
                let mut calls = 0;
                let mut injected = 0;
                // Both schedules absorb the framed common prefix, cross the dither/message
                // branches once, then squeeze dither block one beside the challenge branch.
                let common_bytes =
                    8 + crate::direct_ntt_profile::PROFILE.len() + 8 + crate::params::CORE_PK_BYTES;
                let first_dither = common_bytes / RATE + 2;
                // stop is a one-based candidate index, or zero for the untouched stream.
                // After these blocks, lane zero is restored to matrix stream zero.
                let dither_blocks = (2 * stop.min(EXPANSION_CANDIDATES)).div_ceil(RATE);
                let dither_calls = first_dither..first_dither + dither_blocks;
                let result =
                    scheduled(&body, &mut rows, &mut delta, |pair| {
                        assert!(
                        calls < MAX_CALLS,
                        "public schedule exceeded {} permutation calls: rank={}, case={}, stop={}",
                        MAX_CALLS, M, case, stop,
                    );
                        trace.push(*pair);
                        super::super::permute_scalar(pair);
                        calls += 1;
                        if dither_calls.contains(&calls) {
                            injected += 1;
                            let start = (calls - first_dither) * RATE;
                            let mut bytes = [255; RATE];
                            for j in 0..RATE / 2 {
                                let candidate = start / 2 + j;
                                if candidate < DITHER_COEFFICIENTS - 1 || candidate + 1 == stop {
                                    bytes[2 * j] = 0;
                                    bytes[2 * j + 1] = 0;
                                }
                            }
                            for j in 0..17 {
                                pair[2 * j] =
                                    u64::from_le_bytes(bytes[8 * j..8 * j + 8].try_into().unwrap());
                            }
                        }
                    })
                    .map(|owners| owners.map(|owner| owner.hash::<64>(&[b"continuation"])));
                assert_eq!(injected, dither_blocks);
                (result, rows, delta, trace, calls)
            };
            let actual = run();
            let expected = crate::direct_ntt_profile::matrix13::with_scalar_oracle(run);
            assert_eq!(actual, expected);
            if stop > EXPANSION_CANDIDATES {
                assert_eq!(actual.0, Err(FrameError::DitherExhausted));
                assert_eq!(
                    &actual.2[..DITHER_COEFFICIENTS - 1],
                    &[0; DITHER_COEFFICIENTS - 1]
                );
                assert_eq!(actual.2[DITHER_COEFFICIENTS - 1], -1);
            } else {
                assert!(actual.0.is_ok());
                if stop != 0 {
                    assert_eq!(actual.2, [0; DITHER_COEFFICIENTS]);
                }
            }
        }
    }
}
