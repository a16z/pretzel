//! Same-wire public matrix expansion using two independent SHAKE lanes.
use super::{permute, Sponge, RATE};
use crate::{
    params::{DOM_MATRIX, ELL, M, N, Q},
    ring::Poly,
};
use zeroize::Zeroizing;

fn framed_pair(seed: &[u8; 32], indices: [[u8; 2]; 2]) -> Zeroizing<[u64; 50]> {
    let states = indices.map(|idx| {
        let mut s = Sponge::new();
        s.absorb(DOM_MATRIX);
        s.part(seed);
        s.part(&idx);
        s.pad();
        s
    });
    Zeroizing::new(core::array::from_fn(|i| states[i % 2].state[i / 2]))
}
fn rate_pair(pair: &[u64; 50]) -> [[u8; RATE]; 2] {
    core::array::from_fn(|lane| {
        core::array::from_fn(|i| (pair[2 * (i / 8) + lane] >> (8 * (i % 8))) as u8)
    })
}
// Return the logical candidates consumed; a completed lane consumes no more.
fn scan_rate(bytes: &[u8; RATE], out: &mut Poly, used: &mut usize) -> usize {
    let mut consumed = 0;
    for pair in bytes.chunks_exact(2) {
        if *used == N {
            break;
        }
        consumed += 1;
        let value = (u16::from_le_bytes([pair[0], pair[1]]) & 8191) as i32;
        if value < Q {
            out.0[*used] = value;
            *used += 1;
        }
    }
    consumed
}
fn uniform_pair(mut next: impl FnMut() -> [[u8; RATE]; 2]) -> [Poly; 2] {
    let mut out = [Poly::ZERO; 2];
    let mut used = [0usize; 2];
    // No finite cutoff: the public rejection law is unbounded.
    while used != [N; 2] {
        let blocks = next();
        for lane in 0..2 {
            scan_rate(&blocks[lane], &mut out[lane], &mut used[lane]);
        }
    }
    out
}
fn expand_pair(
    seed: &[u8; 32],
    indices: [[u8; 2]; 2],
    permutation: fn(&mut [u64; 50]),
) -> [Poly; 2] {
    let mut pair = framed_pair(seed, indices);
    uniform_pair(|| {
        permutation(&mut pair);
        rate_pair(&pair)
    })
}
pub(crate) fn expand_a0(seed: &[u8; 32]) -> [[Poly; ELL]; M] {
    // Public fixed dimensions and row/column order, exactly as hashes::expand_a0.
    assert_eq!(ELL, 4);
    let mut out = [[Poly::ZERO; ELL]; M];
    for r in 0..M {
        for c in (0..ELL).step_by(2) {
            let [a, b] = expand_pair(
                seed,
                [[r as u8, c as u8], [r as u8, (c + 1) as u8]],
                permute,
            );
            out[r][c] = a;
            out[r][c + 1] = b;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    fn oracle(seed: &[u8; 32], idx: &[u8; 2]) -> sha3::Shake256Reader {
        let mut s = Shake256::default();
        s.update(DOM_MATRIX);
        for p in [seed.as_slice(), idx.as_slice()] {
            s.update(&(p.len() as u64).to_le_bytes());
            s.update(p);
        }
        s.finalize_xof()
    }
    #[test]
    fn framing_lane_order_and_long_streams_match_independent_sha3() {
        assert_eq!(DOM_MATRIX.len() + 8 + 32 + 8 + 2, 66);
        for case in 0u8..8 {
            let seed = [case; 32];
            let indices = [[case % 4, 0], [3 - case % 4, 3]];
            let mut pair = framed_pair(&seed, indices);
            let mut readers = indices.map(|idx| oracle(&seed, &idx));
            for block in 0..40 {
                super::super::permute_scalar(&mut pair);
                let got = rate_pair(&pair);
                for lane in 0..2 {
                    let mut expected = [0; RATE];
                    readers[lane].read(&mut expected);
                    assert_eq!(
                        got[lane], expected,
                        "case={case}, block={block}, lane={lane}"
                    );
                }
            }
        }
    }
    #[test]
    fn scanner_threshold_high_bits_guards_and_unequal_long_tails() {
        for value in 0u16..=u16::MAX {
            let mut block = [0; RATE];
            block[..2].copy_from_slice(&value.to_le_bytes());
            let mut out = Poly([-7; N]);
            let mut used = N - 1;
            let consumed = scan_rate(&block, &mut out, &mut used);
            assert_eq!(used, N);
            assert_eq!(
                out.0[N - 1],
                if value & 8191 < Q as u16 {
                    (value & 8191) as i32
                } else {
                    0
                }
            );
            assert!(out.0[..N - 1].iter().all(|&v| v == -7));
            assert_eq!(consumed, if value & 8191 < Q as u16 { 1 } else { 2 });
            assert_eq!(scan_rate(&block, &mut out, &mut used), 0);
        }
        for delay in [0, 1, 5, 18, 41] {
            let mut calls = 0usize;
            let out = uniform_pair(|| {
                let n = calls;
                calls += 1;
                let first = [0u8; RATE];
                let second = if n < delay {
                    [255u8; RATE]
                } else {
                    [0u8; RATE]
                };
                [first, second]
            });
            assert_eq!(out, [Poly::ZERO; 2]);
            assert_eq!(calls, delay + 4);
        }
        // Last rate word may complete a lane, without touching later output.
        let mut block = [255; RATE];
        block[RATE - 2..].copy_from_slice(&7680u16.to_le_bytes());
        let mut out = Poly([-9; N]);
        let mut used = N - 1;
        assert_eq!(scan_rate(&block, &mut out, &mut used), 68);
        assert_eq!(out.0[N - 1], 7680);
    }
    #[test]
    fn full_matrix_matches_scalar_oracle_and_selected_dispatch() {
        for case in 0u8..32 {
            let seed = core::array::from_fn(|i| case.wrapping_mul(37).wrapping_add(i as u8));
            let expected = crate::hashes::expand_a0_scalar(&seed);
            for r in 0..M {
                for c in (0..ELL).step_by(2) {
                    let got = expand_pair(
                        &seed,
                        [[r as u8, c as u8], [r as u8, (c + 1) as u8]],
                        super::super::permute_scalar,
                    );
                    assert_eq!(got, [expected[r][c], expected[r][c + 1]]);
                }
            }
            assert_eq!(crate::hashes::expand_a0(&seed), expected);
            if super::super::available() {
                assert_eq!(super::expand_a0(&seed), expected);
            }
        }
    }
}

// Matrix domain: two streams of 13-bit candidates, paired permutation.

pub(crate) fn expand_public_ntt_into(
    seed: &[u8; 32],
    out: &mut [[crate::compact_ring::CompactPoly; ELL + 1]; M],
) {
    let states = [0u8, 1u8].map(|lane| {
        let mut s = Sponge::new();
        s.absorb(crate::direct_ntt_profile::MATRIX_DOMAIN);
        s.part(seed);
        s.part(&[lane]);
        s.pad();
        s
    });
    let mut pair = Zeroizing::new(core::array::from_fn(|i| states[i % 2].state[i / 2]));
    crate::direct_ntt_profile::matrix13::fill_pair(&mut pair, permute, out);
}

#[cfg(test)]
mod matrix13_paired_tests {
    use super::*;
    #[test]
    fn matrix13_paired_permutation_matches_scalar_matrix() {
        for case in 0..8u8 {
            let seed = core::array::from_fn(|i| case.wrapping_mul(31).wrapping_add(i as u8));
            let states = [0u8, 1u8].map(|lane| {
                let mut s = Sponge::new();
                s.absorb(crate::direct_ntt_profile::MATRIX_DOMAIN);
                s.part(&seed);
                s.part(&[lane]);
                s.pad();
                s
            });
            let mut pair = Zeroizing::new(core::array::from_fn(|i| states[i % 2].state[i / 2]));
            let mut expected = [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M];
            crate::direct_ntt_profile::matrix13::scalar(&seed, &mut expected);
            let mut got = [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M];
            crate::direct_ntt_profile::matrix13::fill_pair(
                &mut pair,
                super::super::permute_scalar,
                &mut got,
            );
            assert_eq!(got, expected);
            if super::super::available() {
                expand_public_ntt_into(&seed, &mut got);
                assert_eq!(got, expected);
            }
        }
    }
}
