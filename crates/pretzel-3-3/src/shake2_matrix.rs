//! Same-wire public matrix expansion using two independent SHAKE lanes.
use super::{permute, Sponge, RATE};
use crate::params::{ELL, M};
use zeroize::Zeroizing;

fn rate_pair(pair: &[u64; 50]) -> [[u8; RATE]; 2] {
    core::array::from_fn(|lane| {
        core::array::from_fn(|i| (pair[2 * (i / 8) + lane] >> (8 * (i % 8))) as u8)
    })
}

// Version2 matrix domain: two streams of 13-bit candidates, paired permutation.
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
    crate::direct_ntt_profile::matrix13::fill(
        || {
            permute(&mut pair);
            rate_pair(&pair)
        },
        out,
    );
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
            crate::direct_ntt_profile::matrix13::fill(
                || {
                    super::super::permute_scalar(&mut pair);
                    rate_pair(&pair)
                },
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
