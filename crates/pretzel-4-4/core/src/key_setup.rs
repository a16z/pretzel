//! Select the first candidate with a successful bounded dither expansion.
//! The caller draws only the first candidate seed; the canonical core is still validated.
use crate::{
    dither_frame as frame,
    scheme::{Error, PreparedCorePk},
};
#[cfg(not(test))]
use frame::expand;
#[cfg(test)]
use tests::expand;
pub(crate) fn prepare(
    core: &[u8],
    start: &[u8; 32],
) -> Result<[u8; frame::AUGMENTED_PUBLIC_KEY_BYTES], Error> {
    let _prepared = PreparedCorePk::new(core)?;
    for candidate in 0..frame::MAX_CANDIDATES {
        let seed = frame::candidate_seed(start, candidate).map_err(|_| Error::DitherSetupFailed)?;
        match expand(core, &seed) {
            Ok(_) => {
                return frame::encode_public_key(core, &seed).map_err(|_| Error::DitherSetupFailed)
            }
            Err(frame::FrameError::DitherExhausted) => continue,
            Err(_) => return Err(Error::DitherSetupFailed),
        }
    }
    Err(Error::DitherSetupFailed)
}

#[cfg(test)]
mod tests {
    use super::{frame, prepare};
    use crate::{scheme, EntropyError, EntropySource};
    use std::{cell::RefCell, collections::VecDeque};

    struct ExpansionScript {
        outcomes: VecDeque<Result<(), frame::FrameError>>,
        seeds: Vec<[u8; frame::SEED_BYTES]>,
    }
    thread_local! {
        static EXPANSIONS: RefCell<Option<ExpansionScript>> = const { RefCell::new(None) };
    }

    // Test images alone can replace expansion outcomes. Uninjected tests use
    // the real expansion; production resolves expand directly to frame::expand.
    pub(super) fn expand(
        core: &[u8],
        seed: &[u8; frame::SEED_BYTES],
    ) -> Result<[i32; frame::DITHER_COEFFICIENTS], frame::FrameError> {
        let injected = EXPANSIONS.with(|slot| {
            slot.borrow_mut().as_mut().map(|script| {
                script.seeds.push(*seed);
                script
                    .outcomes
                    .pop_front()
                    .expect("unexpected expansion call")
            })
        });
        match injected {
            Some(outcome) => outcome.map(|()| [0; frame::DITHER_COEFFICIENTS]),
            None => frame::expand(core, seed),
        }
    }

    fn with_expansions(outcomes: Vec<Result<(), frame::FrameError>>, check: impl FnOnce()) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                EXPANSIONS.with(|slot| *slot.borrow_mut() = None);
            }
        }
        EXPANSIONS.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(ExpansionScript {
                outcomes: outcomes.into(),
                seeds: Vec::new(),
            });
        });
        let _reset = Reset;
        check();
    }

    fn assert_candidate_order(start: &[u8; frame::SEED_BYTES], count: usize) {
        EXPANSIONS.with(|slot| {
            let script = slot.borrow();
            let script = script.as_ref().unwrap();
            assert_eq!(script.seeds.len(), count);
            let mut expected = *start;
            for seed in &script.seeds {
                assert_eq!(*seed, expected);
                // Independent little-endian increment, including full wraparound.
                for byte in &mut expected {
                    let (next, carry) = byte.overflowing_add(1);
                    *byte = next;
                    if !carry {
                        break;
                    }
                }
            }
        });
    }

    // An exhausted expansion skips the candidate; any other expansion error, or exhaustion of
    // every candidate, fails the setup.
    #[test]
    fn injected_expansions_preserve_selection_order_and_errors() {
        let mut data = include_bytes!("../../tests/data/keygen-main-rank4.bin").as_slice();
        let magic = b"KEYGEN-PK-SK-ENTROPY-v1\0";
        assert!(data.starts_with(magic));
        data = &data[magic.len()..];
        // The fixture stores tagged public keys; framing takes the untagged body.
        let body = crate::direct_ntt_profile::public_body(field(&mut data)).unwrap();
        assert_eq!(body.len(), frame::AUGMENTED_PUBLIC_KEY_BYTES);
        let (core, _) = frame::split_public_key(body).unwrap();
        assert_eq!(core.len(), frame::CORE_PUBLIC_KEY_BYTES);
        let start = [0xff; frame::SEED_BYTES];
        with_expansions(
            vec![Err(frame::FrameError::DitherExhausted), Ok(())],
            || {
                let selected = prepare(core, &start).unwrap();
                // Candidate one wraps to zero. Compare every core and seed byte
                // without using the candidate or encoding implementation as oracle.
                let mut expected = [0; frame::AUGMENTED_PUBLIC_KEY_BYTES];
                expected[..frame::CORE_PUBLIC_KEY_BYTES].copy_from_slice(core);
                assert_eq!(selected, expected);
                assert_eq!(
                    frame::split_public_key(&selected).unwrap().1,
                    &[0; frame::SEED_BYTES]
                );
                assert_candidate_order(&start, 2);
            },
        );
        for error in [
            frame::FrameError::KeyLength,
            frame::FrameError::CandidateIndex,
        ] {
            with_expansions(vec![Err(error), Ok(())], || {
                assert!(matches!(
                    prepare(core, &start),
                    Err(scheme::Error::DitherSetupFailed)
                ));
                assert_candidate_order(&start, 1);
            });
        }
        with_expansions(
            vec![Err(frame::FrameError::DitherExhausted); frame::MAX_CANDIDATES],
            || {
                assert!(matches!(
                    prepare(core, &start),
                    Err(scheme::Error::DitherSetupFailed)
                ));
                assert_candidate_order(&start, frame::MAX_CANDIDATES);
            },
        );
    }

    struct Tape {
        state: u64,
        calls: Vec<usize>,
    }
    impl EntropySource for Tape {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
            self.calls.push(out.len());
            for b in out {
                self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                *b = (z ^ (z >> 31)) as u8;
            }
            Ok(())
        }
    }
    fn field<'a>(data: &mut &'a [u8]) -> &'a [u8] {
        let n = u64::from_le_bytes(data[..8].try_into().unwrap()) as usize;
        let value = &data[8..8 + n];
        *data = &data[8 + n..];
        value
    }
    // Public SplitMix seeds 0..64, fixture bytes.
    // Covers both entry points. Keys equal the fixture's keys. The entropy record
    // is the fixture's record without its final 32-byte request.
    #[test]
    fn fixed_seeds_match_fixture_keys_without_the_last_entropy_request() {
        let mut data = include_bytes!("../../tests/data/keygen-main-rank4.bin").as_slice();
        let magic = b"KEYGEN-PK-SK-ENTROPY-v1\0";
        assert!(data.starts_with(magic));
        data = &data[magic.len()..];
        let ctx = scheme::Ctx::new();
        let keygen_ctx = scheme::keygen_context::KeygenCtx::new();
        for seed in 0..64 {
            let pk = field(&mut data);
            let sk = field(&mut data);
            let calls = field(&mut data);
            let final_state = u64::from_le_bytes(data[..8].try_into().unwrap());
            data = &data[8..];
            // The fixture's last request is a 32-byte draw that key generation does not make.
            let (retained_calls, removed_call) =
                calls.split_at(calls.len().checked_sub(8).unwrap());
            assert_eq!(removed_call, 32u64.to_le_bytes(), "seed {seed}");
            assert_eq!(
                &retained_calls[retained_calls.len() - 8..],
                32u64.to_le_bytes(),
                "seed {seed}"
            );
            for keygen_only in [false, true] {
                let mut tape = Tape {
                    state: seed,
                    calls: Vec::new(),
                };
                let pair = if keygen_only {
                    scheme::keygen_context::keygen_with_entropy(&keygen_ctx, &mut tape)
                } else {
                    scheme::keygen_with_entropy(&ctx, &mut tape)
                }
                .unwrap();
                assert_eq!(pair.pk.as_slice(), pk, "seed {seed}");
                assert_eq!(pair.sk.as_ref(), sk, "seed {seed}");
                let encoded: Vec<_> = tape
                    .calls
                    .iter()
                    .flat_map(|&n| (n as u64).to_le_bytes())
                    .collect();
                assert_eq!(encoded.as_slice(), retained_calls, "seed {seed}");
                // One further 32-byte fill reaches the fixture's final tape state.
                assert_ne!(tape.state, final_state, "seed {seed}");
                let requests = tape.calls.len();
                tape.fill(&mut [0; 32]).unwrap();
                assert_eq!(tape.calls.len(), requests + 1);
                assert_eq!(tape.state, final_state, "seed {seed}");
            }
        }
        assert!(data.is_empty());
    }
}
