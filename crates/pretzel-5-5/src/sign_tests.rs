//! Tests of the signer.
use super::*;
struct Tape {
    x: Xof,
    sizes: Vec<usize>,
}
impl Tape {
    fn new(seed: &[u8]) -> Self {
        Self {
            x: Xof::new(b"HP-FULLATTEMPT-AUDIT-v1", &[seed]),
            sizes: Vec::new(),
        }
    }
}
impl EntropySource for Tape {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
        self.sizes.push(out.len());
        self.x.fill(out);
        Ok(())
    }
}
fn prepared(ctx: &Ctx) -> PreparedSk {
    let kp = keygen_with_entropy(ctx, &mut Tape::new(b"key")).unwrap();
    PreparedSk::new(&kp.sk).unwrap()
}
#[test]
fn same_tape_replay_and_verification() {
    let ctx = Ctx::new();
    let key = prepared(&ctx);
    let verifier = super::super::verifier::PreparedVerifier::new(&ctx).unwrap();
    for seed in [b"first".as_slice(), b"second".as_slice()] {
        let (mut a, mut b) = (Tape::new(seed), Tape::new(seed));
        let (mut sa, mut sb) = (SigningScratch::new(), SigningScratch::new());
        let left = sign_prepared_using(&ctx, &key, &mut sa, b"hp-audit", seed, &mut a).unwrap();
        let right = sign_prepared_using(&ctx, &key, &mut sb, b"hp-audit", seed, &mut b).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.0.len(), SIGNATURE_BYTES);
        assert_eq!(a.sizes, vec![64; left.1 as usize]);
        assert_eq!(a.sizes, b.sizes);
        verifier
            .verify(&key.ppk, b"hp-audit", seed, &left.0)
            .unwrap();
        assert!(sa.is_erased() && sb.is_erased());
        let (mut ca, mut cb) = ([0u8; 64], [0u8; 64]);
        a.x.fill(&mut ca);
        b.x.fill(&mut cb);
        assert_eq!(ca, cb);
    }
}
#[test]
fn partial_entropy_failure_and_unwind() {
    let ctx = Ctx::new();
    let key = prepared(&ctx);
    let mut scratch = SigningScratch::new();
    struct Fail;
    impl EntropySource for Fail {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            assert_eq!(out.len(), 64);
            out[..17].fill(0xa5);
            Err(crate::EntropyError)
        }
    }
    scratch.poison();
    assert!(matches!(
        sign_prepared_using(&ctx, &key, &mut scratch, b"", b"", &mut Fail),
        Err(Error::RngFailure)
    ));
    assert!(scratch.is_erased());
    struct Panic;
    impl EntropySource for Panic {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            assert_eq!(out.len(), 64);
            out[..17].fill(0x5a);
            panic!("injected highprecision entropy panic")
        }
    }
    scratch.poison();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = sign_prepared_using(&ctx, &key, &mut scratch, b"", b"", &mut Panic);
    }));
    assert!(result.is_err());
    assert!(scratch.is_erased());
}

#[test]
fn wide_profile_rejects_old_prepared_keys_and_uses_keyseed64() {
    let ctx = Ctx::new();
    let mut tape = Tape::new(b"wide-key-width");
    let kp = keygen_with_entropy(&ctx, &mut tape).unwrap();
    assert_eq!(&tape.sizes[..2], &[32, 32]);
    assert!(tape.sizes.len() >= 4);
    assert!(tape.sizes[2..tape.sizes.len() - 1].iter().all(|&n| n == 64));
    assert_eq!(tape.sizes[tape.sizes.len() - 1], 32);
    assert_eq!(PUBLIC_KEY_WIRE_BYTES, 2158);
    assert_eq!(SIGNATURE_BYTES, 1908);
    assert_eq!(kp.pk.len(), 2158);
    assert_eq!(&kp.pk[..14], b"PZSP5-R5-N0001");
    let mut old_pk = kp.pk.clone();
    old_pk[..14].copy_from_slice(b"pretzel-nc55v1");
    assert!(matches!(PreparedPk::new(&old_pk), Err(Error::KeyFormat)));
    let mut old_sk = kp.sk.0.to_vec();
    old_sk[..14].copy_from_slice(b"pretzel-nc55v1");
    assert!(matches!(PreparedSk::new(&old_sk), Err(Error::KeyFormat)));
    old_sk.zeroize();
    assert!(PreparedSk::new(&kp.sk).is_ok());
}
#[test]
// The limbs below are recorded values; this repository has no program that reproduces them.
fn lambda_endpoints_match_recorded_limbs() {
    let ctx = Ctx::new();
    assert_eq!(
        ctx.theta.lambda.lo.0,
        [
            16826121694653793682,
            9969555856992479592,
            15793333535006537101,
            15477759375114149748,
            4862992178733847885,
            18432681054106504051,
            0
        ]
    );
    assert_eq!(
        ctx.theta.lambda.hi.0,
        [
            16826121694654906824,
            9969555856992479592,
            15793333535006537101,
            15477759375114149748,
            4862992178733847885,
            18432681054106504051,
            0
        ]
    );
}

// Thread-local, test-only rejection hook: every actual attempt still executes.
// Rejecting a successful outcome exercises retry/cleanup without accepting an
// otherwise rejected attempt. The entire hook is absent from non-test builds.
struct ForcedReject {
    limit: u32,
    attempts: Vec<u32>,
}
std::thread_local! { static FORCED: std::cell::RefCell<Option<ForcedReject>> = const { std::cell::RefCell::new(None) }; }
pub(super) fn controlled_outcome(retry: u32, accepted: bool) -> bool {
    FORCED.with(|cell| match cell.borrow_mut().as_mut() {
        None => accepted,
        Some(state) => {
            state.attempts.push(retry);
            accepted && retry >= state.limit
        }
    })
}
struct RejectGuard;
impl RejectGuard {
    fn first(count: u32) -> Self {
        FORCED.with(|cell| {
            assert!(cell.borrow().is_none());
            *cell.borrow_mut() = Some(ForcedReject {
                limit: count,
                attempts: Vec::new(),
            });
        });
        Self
    }
    fn attempts(&self) -> Vec<u32> {
        FORCED.with(|cell| cell.borrow().as_ref().unwrap().attempts.clone())
    }
}
impl Drop for RejectGuard {
    fn drop(&mut self) {
        FORCED.with(|cell| {
            *cell.borrow_mut() = None;
        });
    }
}
#[test]
fn late_entropy_failure_after_real_rejection() {
    let ctx = Ctx::new();
    let key = prepared(&ctx);
    let mut scratch = SigningScratch::new();
    struct Late {
        tape: Tape,
        calls: usize,
        panic: bool,
    }
    impl EntropySource for Late {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            self.calls += 1;
            assert_eq!(out.len(), 64);
            if self.calls == 2 {
                out[..17].fill(0x5a);
                if self.panic {
                    panic!("injected late entropy panic")
                }
                return Err(crate::EntropyError);
            }
            self.tape.fill(out)
        }
    }
    for panic in [false, true] {
        let guard = RejectGuard::first(1);
        let mut rng = Late {
            tape: Tape::new(b"late"),
            calls: 0,
            panic,
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sign_prepared_using(&ctx, &key, &mut scratch, b"", b"late", &mut rng)
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert!(matches!(result.unwrap(), Err(Error::RngFailure)));
        }
        assert_eq!(rng.calls, 2);
        assert_eq!(guard.attempts(), vec![0]);
        assert!(scratch.is_erased());
        drop(guard);
    }
    // The test hook and scratch from failed calls must not affect a later replay.
    let (mut a, mut b) = (Tape::new(b"reset"), Tape::new(b"reset"));
    let mut fresh = SigningScratch::new();
    let left = sign_prepared_using(&ctx, &key, &mut scratch, b"", b"reset", &mut a).unwrap();
    let right = sign_prepared_using(&ctx, &key, &mut fresh, b"", b"reset", &mut b).unwrap();
    assert_eq!(left, right);
    assert_eq!(a.sizes, b.sizes);
    assert!(scratch.is_erased() && fresh.is_erased());
}
#[test]
fn exact_max_attempts_exhaustion() {
    let ctx = Ctx::new();
    let key = prepared(&ctx);
    let mut scratch = SigningScratch::new();
    let mut rng = Tape::new(b"exhaust");
    let guard = RejectGuard::first(MAX_ATTEMPTS);
    assert!(matches!(
        sign_prepared_using(&ctx, &key, &mut scratch, b"", b"exhaust", &mut rng),
        Err(Error::SignFailed)
    ));
    assert_eq!(guard.attempts(), (0..MAX_ATTEMPTS).collect::<Vec<_>>());
    assert_eq!(rng.sizes, vec![64; MAX_ATTEMPTS as usize]);
    assert!(scratch.is_erased());
}

// A test-only post-admission corruption is the control for release without
// verification: the signer does not check its output before returning it.
// It never changes production entropy, arithmetic or admission decisions.
std::thread_local! {
 static CORRUPT_RELEASE:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};
 static RELEASE_ERASED:std::cell::Cell<Option<bool>>=const{std::cell::Cell::new(None)};
}
pub(super) fn maybe_corrupt_release(signature: &mut [u8]) {
    if CORRUPT_RELEASE.with(|x| x.replace(false)) {
        signature[0] ^= 1;
    }
}

#[test]
fn cached_message_release_matches_public_verification() {
    let ctx = Ctx::new();
    let key = prepared(&ctx);
    let verifier = super::super::verifier::PreparedVerifier::new(&ctx).unwrap();
    for size in [0usize, 32, 4096, 65536] {
        let message = vec![0x5a; size];
        let context = b"cached-message-audit";
        let mut scratch = SigningScratch::new();
        let mut tape = Tape::new(&(size as u64).to_le_bytes());
        let (signature, _) =
            sign_prepared_using(&ctx, &key, &mut scratch, context, &message, &mut tape).unwrap();
        let mu = key.ppk.message_rep(context, &message);
        assert_eq!(mu, key.ppk.prefixes.verify_message_rep(context, &message));
        verifier
            .verify(&key.ppk, context, &message, &signature)
            .unwrap();
        verifier
            .verify_with_message_rep(&key.ppk, &mu, &signature)
            .unwrap();
        let mut wrong_mu = mu;
        wrong_mu[0] ^= 1;
        assert!(verifier
            .verify_with_message_rep(&key.ppk, &wrong_mu, &signature)
            .is_err());
        let mut wrong_message = message.clone();
        wrong_message.push(1);
        assert!(verifier
            .verify(&key.ppk, context, &wrong_message, &signature)
            .is_err());
        assert!(verifier
            .verify(&key.ppk, b"wrong-context", &message, &signature)
            .is_err());
        for offset in [
            0,
            32,
            224,
            1504,
            1505,
            1565,
            1885,
            1886,
            signature.len() - 1,
        ] {
            let mut corrupt = signature.clone();
            corrupt[offset] ^= 1;
            assert!(verifier
                .verify(&key.ppk, context, &message, &corrupt)
                .is_err());
            assert_eq!(
                format!(
                    "{:?}",
                    verifier.verify(&key.ppk, context, &message, &corrupt)
                ),
                format!(
                    "{:?}",
                    verifier.verify_with_message_rep(&key.ppk, &mu, &corrupt)
                )
            );
        }
        assert!(scratch.is_erased());
    }
}

#[test]
fn release_off_corruption_control() {
    let ctx = Ctx::new();
    let key = prepared(&ctx);
    let mut scratch = SigningScratch::new();
    CORRUPT_RELEASE.with(|x| x.set(true));
    let (signature, _) = sign_prepared_using(
        &ctx,
        &key,
        &mut scratch,
        b"release-audit",
        b"corruption-control",
        &mut Tape::new(b"release-corruption"),
    )
    .unwrap();
    assert!(scratch.is_erased());
    assert!(!CORRUPT_RELEASE.with(|x| x.get()));
    assert!(super::super::verifier::PreparedVerifier::new(&ctx)
        .unwrap()
        .verify(
            &key.ppk,
            b"release-audit",
            b"corruption-control",
            &signature
        )
        .is_err());
}

#[path = "normalize_tests.rs"]
mod normalize_tests;
#[path = "packet_owner_tests.rs"]
mod packet_owner_tests;

#[path = "signature_vector_tests.rs"]
mod signature_vector_tests;

include!("sign_transcript_tests.rs");
