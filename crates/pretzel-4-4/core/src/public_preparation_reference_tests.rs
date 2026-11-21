//! Public schedules compared with the byte-buffer reference implementation.
use super::*;

#[test]
fn borrowed_preparation_matches_previous_schedule_and_cutoffs() {
    let mut random = 0x635a_b127_14d8_002fu64;
    for case in 0..12 {
        let body: Vec<u8> = (0..crate::params::PK_BYTES)
            .map(|_| {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                match case {
                    0 => 0,
                    1 => 255,
                    _ => random as u8,
                }
            })
            .collect();
        for stop in [
            0,
            DITHER_COEFFICIENTS,
            EXPANSION_CANDIDATES,
            EXPANSION_CANDIDATES + 1,
        ] {
            let run = |reference: bool| {
                let mut rows = [[CompactPoly([37; N]); ELL + 1]; M];
                let mut delta = [-1; DITHER_COEFFICIENTS];
                let mut trace = Vec::new();
                let mut calls = 0;
                let first = (8
                    + crate::direct_ntt_profile::PROFILE.len()
                    + 8
                    + crate::params::CORE_PK_BYTES)
                    / RATE
                    + 2;
                let blocks = (2 * stop.min(EXPANSION_CANDIDATES)).div_ceil(RATE);
                let mut permute = |pair: &mut [u64; 50]| {
                    assert!(calls < 256);
                    trace.push(*pair);
                    super::super::permute_scalar(pair);
                    calls += 1;
                    if stop != 0 && (first..first + blocks).contains(&calls) {
                        let start = (calls - first) * RATE / 2;
                        let mut block = [255u8; RATE];
                        for j in 0..RATE / 2 {
                            if start + j < DITHER_COEFFICIENTS - 1 || start + j + 1 == stop {
                                block[2 * j..2 * j + 2].fill(0);
                            }
                        }
                        for j in 0..RATE / 8 {
                            pair[2 * j] =
                                u64::from_le_bytes(block[8 * j..8 * j + 8].try_into().unwrap());
                        }
                    }
                };
                let owners = if reference {
                    scheduled_reference(&body, &mut rows, &mut delta, &mut permute)
                } else {
                    scheduled(&body, &mut rows, &mut delta, &mut permute)
                };
                let hashes =
                    owners.map(|owners| owners.map(|owner| owner.hash::<273>(&[b"continuation"])));
                (hashes, rows, delta, trace)
            };
            let actual = run(false);
            assert_eq!(actual, run(true), "case={case}, stop={stop}");
            assert_eq!(actual.0.is_ok(), stop <= EXPANSION_CANDIDATES);
        }
    }
}
