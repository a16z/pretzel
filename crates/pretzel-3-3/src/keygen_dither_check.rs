// Rank-three version. All state and output here are public.
// Reuse the framed core across candidates; never instantiate a coefficient array.
pub(crate) struct DitherCheck {
    common: PublicState,
}
impl DitherCheck {
    pub(crate) fn new(core: &[u8]) -> Result<Self, FrameError> {
        if core.len() != crate::params::CORE_PK_BYTES {
            return Err(FrameError::KeyLength);
        }
        Ok(Self { common: PublicState::common(core) })
    }
    pub(crate) fn check(&self, seed: &[u8; 32]) -> Result<(), FrameError> {
        let mut state = self.common.clone().branch(DD, seed);
        state.pad();
        count_dither(|block| {
            #[cfg(test)] completion_test::note_dither_permutation();
            super::sponge_permute(&mut state.words);
            rate(&state.words, block);
        })
    }
}
fn count_dither(mut fill: impl FnMut(&mut [u8])) -> Result<(), FrameError> {
    let mut block = Zeroizing::new([0u8; RATE]); // The public decoder block is wiped on drop.
    let mut used = 0usize;
    let mut remaining = EXPANSION_CANDIDATES;
    while remaining != 0 {
        let words = remaining.min(RATE / 2);
        fill(&mut block[..2 * words]);
        #[cfg(test)]
        completion_test::block(&mut block[..2 * words]);
        // Full rate blocks, one accept bit per independent 16-bit word. The
        // bounded final block cannot admit a candidate outside the bounded prefix.
        used += block[..2 * words].chunks_exact(2).map(|pair| {
            usize::from((u16::from_le_bytes([pair[0], pair[1]]) & 8191) < Q as u16)
        }).sum::<usize>();
        if used >= DITHER_COEFFICIENTS {
            return Ok(());
        }
        remaining -= words;
    }
    Err(FrameError::DitherExhausted)
}

#[cfg(test)]
mod keygen_public_dither_tests {
    use super::*;
    #[test]
    fn cached_count_matches_expansion_and_every_cutoff() {
        for case in 0..32u8 {
            let core: Vec<u8> = (0..crate::params::CORE_PK_BYTES)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(case)).collect();
            let checker = DitherCheck::new(&core).unwrap();
            for retry in 0..4u8 {
                let seed = [case.wrapping_add(retry); 32];
                let mut out = [0; DITHER_COEFFICIENTS];
                assert_eq!(checker.check(&seed), dither(&core, &seed, &mut out));
            }
        }
        // Last acceptance at each possible location, including immediately
        // beyond the bounded prefix. Compare with the storing decoder.
        for cutoff in DITHER_COEFFICIENTS..=EXPANSION_CANDIDATES + 1 {
            let mut bytes = vec![255; 2 * (EXPANSION_CANDIDATES + 1)];
            bytes[..2 * (DITHER_COEFFICIENTS - 1)].fill(0);
            bytes[2 * (cutoff - 1)..2 * cutoff].fill(0);
            let mut pos = 0;
            let a = count_dither(|dst| {
                dst.copy_from_slice(&bytes[pos..pos + dst.len()]); pos += dst.len();
            });
            let mut pos = 0;
            let mut out = [0; DITHER_COEFFICIENTS];
            let b = decode_into(|dst| {
                dst.copy_from_slice(&bytes[pos..pos + dst.len()]); pos += dst.len();
            }, &mut out);
            assert_eq!(a, b, "cutoff={cutoff}");
        }
        for value in 0..=u16::MAX {
            let got = count_dither(|dst| {
                for p in dst.chunks_exact_mut(2) { p.copy_from_slice(&value.to_le_bytes()); }
            });
            assert_eq!(got.is_ok(), (value & 8191) < Q as u16);
        }
    }
}
