//! Bounded public setup: select the first candidate whose dither expands.
use crate::{dither_frame as frame, scheme::Error};

/// Validate the public core, then visit the fixed candidate list in order.
/// Expansion exhaustion advances the list; every other error is terminal.
pub(crate) fn prepare(
    core: &[u8],
    start: &[u8; 32],
) -> Result<[u8; frame::AUGMENTED_PUBLIC_KEY_BYTES], Error> {
    // Canonical-byte checks of the core.
    if core.len() != frame::CORE_PUBLIC_KEY_BYTES {
        return Err(Error::KeyFormat);
    }
    crate::encode::decode_b_into(&core[32..], |_, _| {}).ok_or(Error::KeyFormat)?;
    let checker = crate::shake2::common_prefix::DitherCheck::new(core)
        .map_err(|_| Error::DitherSetupFailed)?;
    select_candidate(core, start, |seed| checker.check(seed))
}

// The production caller supplies only the bounded counter above. The closure
// also lets unit tests exercise rare selection outcomes without further selectors.
fn select_candidate(
    core: &[u8],
    start: &[u8; 32],
    mut expand: impl FnMut(&[u8; 32]) -> Result<(), frame::FrameError>,
) -> Result<[u8; frame::AUGMENTED_PUBLIC_KEY_BYTES], Error> {
    for candidate in 0..frame::MAX_CANDIDATES {
        let seed = frame::candidate_seed(start, candidate).map_err(|_| Error::DitherSetupFailed)?;
        match expand(&seed) {
            Ok(()) => {
                return frame::encode_public_key(core, &seed).map_err(|_| Error::DitherSetupFailed);
            }
            Err(frame::FrameError::DitherExhausted) => continue,
            Err(_) => return Err(Error::DitherSetupFailed),
        }
    }
    Err(Error::DitherSetupFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_core_validation_without_matrix_expansion() {
        let seed = [0; 32];
        for length in [
            0,
            31,
            frame::CORE_PUBLIC_KEY_BYTES - 1,
            frame::CORE_PUBLIC_KEY_BYTES + 1,
        ] {
            assert!(matches!(
                prepare(&vec![0; length], &seed),
                Err(Error::KeyFormat)
            ));
        }
        let mut invalid = [255; frame::CORE_PUBLIC_KEY_BYTES];
        invalid[..32].fill(0);
        assert!(matches!(prepare(&invalid, &seed), Err(Error::KeyFormat)));
        crate::direct_ntt_profile::without_expansion(|| {
            assert!(prepare(&[0; frame::CORE_PUBLIC_KEY_BYTES], &seed).is_ok());
        });
    }

    #[test]
    fn exhausted_candidate_advances_in_order() {
        let core = [0; frame::CORE_PUBLIC_KEY_BYTES];
        let start = [255; 32];
        let mut calls = 0;
        let key = select_candidate(&core, &start, |seed| {
            calls += 1;
            match calls {
                1 => {
                    assert_eq!(seed, &start);
                    Err(frame::FrameError::DitherExhausted)
                }
                2 => {
                    assert_eq!(seed, &[0; 32]);
                    Ok(())
                }
                _ => panic!("selection continued after success"),
            }
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(key, frame::encode_public_key(&core, &[0; 32]).unwrap());
    }

    #[test]
    fn terminal_expansion_errors_abort_with_setup_failure() {
        for error in [
            frame::FrameError::KeyLength,
            frame::FrameError::CandidateIndex,
        ] {
            let mut calls = 0;
            let result = select_candidate(&[0; frame::CORE_PUBLIC_KEY_BYTES], &[0; 32], |_| {
                calls += 1;
                Err(error)
            });
            assert!(matches!(result, Err(Error::DitherSetupFailed)));
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn all_candidates_exhaust_at_the_fixed_limit() {
        assert_eq!(frame::MAX_CANDIDATES, 2048);
        let mut calls = 0u64;
        let result = select_candidate(&[0; frame::CORE_PUBLIC_KEY_BYTES], &[0; 32], |seed| {
            let mut expected = [0; 32];
            expected[..8].copy_from_slice(&calls.to_le_bytes());
            assert_eq!(seed, &expected);
            calls += 1;
            Err(frame::FrameError::DitherExhausted)
        });
        assert!(matches!(result, Err(Error::DitherSetupFailed)));
        assert_eq!(calls, 2048);
    }

    #[test]
    fn last_candidate_can_succeed() {
        let core = [0; frame::CORE_PUBLIC_KEY_BYTES];
        let mut calls = 0;
        let key = select_candidate(&core, &[0; 32], |_| {
            calls += 1;
            if calls == 2048 {
                Ok(())
            } else {
                Err(frame::FrameError::DitherExhausted)
            }
        })
        .unwrap();
        let mut last = [0; 32];
        last[..2].copy_from_slice(&2047u16.to_le_bytes());
        assert_eq!(calls, 2048);
        assert_eq!(key, frame::encode_public_key(&core, &last).unwrap());
    }

    #[test]
    fn encoding_failure_is_terminal() {
        let mut calls = 0;
        let result = select_candidate(&[], &[0; 32], |_| {
            calls += 1;
            Ok(())
        });
        assert!(matches!(result, Err(Error::DitherSetupFailed)));
        assert_eq!(calls, 1);
    }
}
