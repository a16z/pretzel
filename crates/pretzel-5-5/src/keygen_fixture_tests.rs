//! Key generation must reproduce `tests/vectors/keygen-vectors.bin`: the
//! public keys, the secret keys and the record of entropy requests for the
//! public seeds 0 to 63. Fixture SHA-256:
//! 4980d06efc02c259412fcb263b7120a462deb0a396069d4aeee9b8d72d0e0162.
//! The fixture records one more entropy request than key generation makes: a
//! final 32-byte draw after the candidate seed. The test requires the keys to
//! equal the fixture's keys, and the entropy record to equal the fixture's
//! record without that final request.
use crate::{Ctx, EntropyError, EntropySource};

struct Tape {
    state: u64,
    calls: Vec<u8>,
}
impl EntropySource for Tape {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        self.calls
            .extend_from_slice(&(out.len() as u64).to_le_bytes());
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
fn field<'a>(input: &mut &'a [u8]) -> &'a [u8] {
    let n = u64::from_le_bytes(input[..8].try_into().unwrap()) as usize;
    let (value, rest) = input[8..].split_at(n);
    *input = rest;
    value
}
#[test]
fn keys_match_fixture_without_its_last_entropy_request() {
    let mut expected = include_bytes!("../tests/vectors/keygen-vectors.bin").as_slice();
    let header = b"KEYGEN-PK-SK-ENTROPY-v1\0";
    assert_eq!(&expected[..header.len()], header);
    expected = &expected[header.len()..];
    let ctx = Ctx::new();
    for seed in 0..64 {
        let mut tape = Tape {
            state: seed,
            calls: Vec::new(),
        };
        let pair = crate::keygen_with_entropy(&ctx, &mut tape).unwrap();
        assert_eq!(
            pair.pk.as_slice(),
            field(&mut expected),
            "public key seed {seed}"
        );
        assert_eq!(
            pair.sk.as_ref(),
            field(&mut expected),
            "secret key seed {seed}"
        );
        // The fixture's last request is the extra 32-byte draw.
        let calls = field(&mut expected);
        let (retained_calls, removed_call) = calls.split_at(calls.len().checked_sub(8).unwrap());
        assert_eq!(
            removed_call,
            32u64.to_le_bytes(),
            "removed call seed {seed}"
        );
        assert_eq!(
            &retained_calls[retained_calls.len() - 8..],
            32u64.to_le_bytes(),
            "candidate seed call seed {seed}"
        );
        assert_eq!(
            tape.calls.as_slice(),
            retained_calls,
            "entropy calls seed {seed}"
        );
        // One further 32-byte fill reaches the fixture's final tape state.
        assert_ne!(
            tape.state.to_le_bytes(),
            expected[..8],
            "entropy state before the removed call, seed {seed}"
        );
        tape.fill(&mut [0; 32]).unwrap();
        assert_eq!(tape.calls.len(), calls.len(), "request count seed {seed}");
        assert_eq!(
            tape.state.to_le_bytes(),
            expected[..8],
            "entropy state seed {seed}"
        );
        expected = &expected[8..];
    }
    assert!(expected.is_empty());
}
/// Fails every request from the `fail_from`-th on, counting each attempt.
struct FailFrom {
    tape: Tape,
    fail_from: usize,
    sizes: Vec<usize>,
}
impl EntropySource for FailFrom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        self.sizes.push(out.len());
        if self.sizes.len() >= self.fail_from {
            return Err(EntropyError);
        }
        self.tape.fill(out)
    }
}
#[test]
fn dither_seed_is_the_last_request_and_its_failure_is_not_retried() {
    let ctx = Ctx::new();
    for seed in 0..4 {
        let source = |fail_from| FailFrom {
            tape: Tape {
                state: seed,
                calls: Vec::new(),
            },
            fail_from,
            sizes: Vec::new(),
        };
        let mut clean = source(usize::MAX);
        crate::keygen_with_entropy(&ctx, &mut clean).unwrap();
        let requests = clean.sizes.len();
        assert_eq!(clean.sizes[requests - 1], 32, "seed {seed}");
        // Failing the single dither-selection request returns at once.
        let mut failing = source(requests);
        assert!(matches!(
            crate::keygen_with_entropy(&ctx, &mut failing),
            Err(crate::Error::RngFailure)
        ));
        assert_eq!(failing.sizes, clean.sizes, "seed {seed}");
        // A further request would fail; key generation never makes one.
        let mut guarded = source(requests + 1);
        crate::keygen_with_entropy(&ctx, &mut guarded).unwrap();
        assert_eq!(guarded.sizes, clean.sizes, "seed {seed}");
    }
}
