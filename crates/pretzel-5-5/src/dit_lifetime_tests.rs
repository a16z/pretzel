//! Native DIT lifetime regressions.
use super::*;
use crate::{Ctx, PreparedSk, SigningScratch};
use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::Zeroize;

fn require(events: &[(&str, u64)], sites: &[&str], expected: u64) {
    for site in sites {
        assert_eq!(
            events.iter().filter(|e| e.0 == *site).count(),
            1,
            "{site}: {events:?}"
        );
        assert!(events.contains(&(*site, expected)), "{events:?}");
    }
    if sites.contains(&"parse-cols-drop") {
        assert_eq!(
            events
                .iter()
                .filter(|e| e.0 == "parse-error-spectra-drop")
                .count(),
            1,
            "{events:?}"
        );
        assert!(
            events.contains(&("parse-error-spectra-drop", expected)),
            "{events:?}"
        );
    }
    assert!(events.iter().all(|e| e.1 == expected), "{events:?}");
}

// Completion events of the stack-range wipes. With the Cargo feature `stack-wipe` exactly
// `with_feature` of them are required, each recorded with DIT on. Without the feature no stack
// range is wiped, and no completion event may be recorded.
fn require_wipes(events: &[(&str, u64)], with_feature: usize) {
    let expected = if cfg!(feature = "stack-wipe") {
        with_feature
    } else {
        0
    };
    let wipes: Vec<u64> = events
        .iter()
        .filter(|e| e.0 == "stack-scrub")
        .map(|e| e.1)
        .collect();
    assert_eq!(wipes.len(), expected, "{events:?}");
    assert!(wipes.iter().all(|state| *state == DIT), "{events:?}");
}

// As `require_wipes` for one wipe, which with the feature is also the last event.
fn require_last_wipe(events: &[(&str, u64)]) {
    require_wipes(events, 1);
    if cfg!(feature = "stack-wipe") {
        assert_eq!(events.last(), Some(&("stack-scrub", DIT)), "{events:?}");
    }
}

#[test]
fn panicking_parent_keeps_children_guarded_once_on_all_entry_modes() {
    use std::{cell::Cell, rc::Rc};
    struct Child {
        count: Rc<Cell<usize>>,
        site: &'static str,
    }
    impl Drop for Child {
        fn drop(&mut self) {
            self.count.set(self.count.get() + 1);
            test_support::observe(self.site);
        }
    }
    struct Parent {
        count: Rc<Cell<usize>>,
        _a: Child,
        _b: Child,
    }
    impl Drop for Parent {
        fn drop(&mut self) {
            self.count.set(self.count.get() + 1);
            test_support::observe("panicking-parent");
            // This test starts the unwind here. Children never panic.
            panic!("injected parent destructor panic");
        }
    }
    for initial in [0, DIT] {
        for mode in [0, 1, 2] {
            let scope = test_support::Scope::new(initial);
            let counts = [
                Rc::new(Cell::new(0)),
                Rc::new(Cell::new(0)),
                Rc::new(Cell::new(0)),
            ];
            scope.fail(mode);
            assert!(catch_unwind(AssertUnwindSafe(|| {
                drop(crate::guarded_drop::GuardedDrop::new(Parent {
                    count: counts[0].clone(),
                    _a: Child {
                        count: counts[1].clone(),
                        site: "child-a",
                    },
                    _b: Child {
                        count: counts[2].clone(),
                        site: "child-b",
                    },
                }));
            }))
            .is_err());
            assert_eq!(counts.map(|c| c.get()), [1, 1, 1]);
            assert_eq!(read() & DIT, initial);
            let expected = if mode == 0 { DIT } else { initial };
            assert_eq!(
                scope.take(),
                [
                    ("panicking-parent", expected),
                    ("child-a", expected),
                    ("child-b", expected)
                ]
            );
        }
    }
}

#[test]
fn real_constructor_unwind_and_post_parse_rejection_retire_temporaries() {
    let pair = crate::keygen(&Ctx::new()).unwrap();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        for site in ["parse-hash-ok", "prepare-exit"] {
            scope.panic_at(site);
            assert!(catch_unwind(|| PreparedSk::new(&pair.sk)).is_err());
            assert_eq!(read() & DIT, initial);
            let events = scope.take();
            require(
                &events,
                &[
                    "parse-hash-ok",
                    "parse-trits-drop",
                    "parse-prf-drop",
                    "parse-s_flat-drop",
                    "parse-cols-drop",
                ],
                DIT,
            );
            if site == "prepare-exit" {
                require(&events, &["parsed-key-drop"], DIT);
            }
            // With the feature `stack-wipe` the stack scrub of the import completes once,
            // after every destructor of the unwinding body and while DIT is still on.
            require_last_wipe(&events);
        }
        // The same two unwinding imports on a painted stack: what the body left inside
        // the erased extent is gone. See `import_unwind_stack` for what is not judged.
        #[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
        {
            let (unwound, reference) = import_unwind_stack::unwinding_reference();
            assert!(unwound, "the reference did not unwind");
            scope.take();
            eprintln!("reference unwind: {}", reference.describe());
            let mut imports = Vec::new();
            for site in ["parse-hash-ok", "prepare-exit"] {
                scope.panic_at(site);
                let (unwound, import) = import_unwind_stack::unwinding_import(&pair.sk);
                assert!(unwound, "{site}: the import did not unwind");
                assert_eq!(read() & DIT, initial);
                assert!(scope.take().contains(&("stack-scrub", DIT)));
                eprintln!("unwinding import at {site}: {}", import.describe());
                imports.push((site, import));
            }
            for (site, import) in &imports {
                import_unwind_stack::judge(site, import, &reference);
            }
        }
        // Mutate the dither seed and authenticate those exact public bytes.
        // Exhaustion is injected into the actual public decoder: this is a
        // late-rejection fault control, not a claimed natural SHAKE preimage.
        let mut bad = pair.sk.to_vec();
        let mut pk = crate::direct_ntt_profile::public_body(&pair.pk)
            .unwrap()
            .to_vec();
        *bad.last_mut().unwrap() ^= 1;
        *pk.last_mut().unwrap() ^= 1;
        let hash_at = bad.len() - 64;
        bad[hash_at..hash_at + 32].copy_from_slice(&crate::hashes::shake256_32(&pk));
        scope.reject(true);
        assert!(matches!(PreparedSk::new(&bad), Err(Error::KeyFormat)));
        scope.reject(false);
        assert_eq!(read() & DIT, initial);
        let events = scope.take();
        require(
            &events,
            &[
                "parse-hash-ok",
                "dither-exhaustion-fault",
                "parse-trits-drop",
                "parse-prf-drop",
                "parse-s_flat-drop",
                "parse-cols-drop",
                "parsed-key-drop",
            ],
            DIT,
        );
        require_last_wipe(&events);
        let outer = Guard::enter().unwrap();
        drop(PreparedSk::new(&pair.sk).unwrap());
        assert_eq!(read() & DIT, DIT);
        let events = scope.take();
        require(
            &events,
            &["prepare-entry", "prepare-exit", "parsed-key-drop"],
            DIT,
        );
        // With the feature `stack-wipe`: one scrub, after the import body and before the
        // returned key is dropped.
        require_wipes(&events, 1);
        if cfg!(feature = "stack-wipe") {
            let at = |site| events.iter().position(|e| e.0 == site).unwrap();
            assert!(at("prepare-exit") < at("stack-scrub"));
            assert!(at("stack-scrub") < at("parsed-key-drop"));
        }
        drop(outer);
        assert_eq!(read() & DIT, initial);
    }
}

fn malformed_shell(pair: &crate::scheme::Keypair) -> Vec<u8> {
    let mut bad = pair.sk.to_vec();
    let mut pk = crate::direct_ntt_profile::public_body(&pair.pk)
        .unwrap()
        .to_vec();
    // All-zero trits violate the shell. Their public b is also zero, so build
    // the correct public bytes and hash instead of merely corrupting the hash.
    let packed = crate::encode::pack_trits(&[0; crate::params::TRIT_COUNT]);
    bad[14 + 32..14 + 32 + packed.len()].copy_from_slice(&packed);
    let b = crate::encode::encode_b(&[0; crate::params::M * crate::params::N]);
    pk[32..32 + b.len()].copy_from_slice(&b);
    let hash = crate::hashes::shake256_32(&pk);
    let hash_at = 14 + 64 + packed.len();
    bad[hash_at..hash_at + 32].copy_from_slice(&hash);
    assert_eq!(&bad[hash_at..hash_at + 32], crate::hashes::shake256_32(&pk));
    bad
}

#[test]
fn hash_consistent_malformed_shell_key_observes_constructor_temporaries() {
    let pair = crate::keygen(&Ctx::new()).unwrap();
    let bad = malformed_shell(&pair);
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        assert!(matches!(PreparedSk::new(&bad), Err(Error::KeyFormat)));
        assert_eq!(read() & DIT, initial);
        let events = scope.take();
        require(
            &events,
            &[
                "prepare-entry",
                "parse-trits-drop",
                "parse-prf-drop",
                "parse-s_flat-drop",
            ],
            DIT,
        );
        require_wipes(&events, 1);
    }
}

#[test]
fn prepared_key_drop_and_caller_scratch_failure_cover_all_entry_modes() {
    let ctx = Ctx::new();
    let pair = crate::keygen(&ctx).unwrap();
    for initial in [0, DIT] {
        for mode in [0, 1, 2] {
            let scope = test_support::Scope::new(initial);
            let prepared = PreparedSk::new(&pair.sk).unwrap();
            let mut scratch = SigningScratch::new();
            scope.take();
            scope.fail(mode);
            scope.entropy_error(true);
            let result = sign_fixture(&ctx, &prepared, &mut scratch);
            let error = if mode == 0 {
                Error::RngFailure
            } else {
                Error::TimingProtectionUnavailable
            };
            assert_eq!(result, Err(error));
            assert!(scratch.is_erased());
            assert_eq!(read() & DIT, initial);
            let events = scope.take();
            if mode == 0 {
                require(&events, &["sign-entropy", "scratch-lease-drop"], DIT);
            } else {
                assert!(
                    events.is_empty(),
                    "signing reached private work: {events:?}"
                );
            }
            scratch.poison();
            scratch.zeroize();
            assert!(scratch.is_erased());
            drop(scratch);
            drop(prepared);
            assert_eq!(read() & DIT, initial);
            let expected = if mode == 0 { DIT } else { initial };
            let events = scope.take();
            require(&events, &["parsed-key-drop"], expected);
            assert_eq!(
                events
                    .iter()
                    .filter(|e| **e == ("scratch-erase", expected))
                    .count(),
                2
            );
            check_extra_key_drop(&events, expected);
        }
    }
}

#[test]
fn real_sign_unwind_erases_leases_scratch_and_prepared_key() {
    let ctx = Ctx::new();
    let pair = crate::keygen(&ctx).unwrap();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        scope.panic_at("sign-entropy");
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let prepared = PreparedSk::new(&pair.sk).unwrap();
            let mut scratch = SigningScratch::new();
            scratch.poison();
            let _ = sign_fixture(&ctx, &prepared, &mut scratch);
        }))
        .is_err());
        assert_eq!(read() & DIT, initial);
        let events = scope.take();
        require(
            &events,
            &[
                "sign-entropy",
                "scratch-lease-drop",
                "scratch-erase",
                "parsed-key-drop",
            ],
            DIT,
        );
        check_extra_key_drop(&events, DIT);
    }
}

#[test]
fn real_used_scratch_tls_teardown_observes_dit_and_restoration() {
    struct AfterCache;
    impl Drop for AfterCache {
        fn drop(&mut self) {
            test_support::observe("tls-after-cache");
        }
    }
    std::thread_local! {
        static AFTER: std::cell::RefCell<Option<AfterCache>> = const { std::cell::RefCell::new(None) };
        static HELD: std::cell::RefCell<Option<SigningScratch>> = const { std::cell::RefCell::new(None) };
    }
    let pair = crate::keygen(&Ctx::new()).unwrap();
    for initial in [0, DIT] {
        for mode in [0, 1, 2] {
            let events = test_support::Events::default();
            let sink = events.clone();
            let raw = pair.sk.to_vec();
            std::thread::spawn(move || {
                let ctx = Ctx::new();
                let scope = test_support::Scope::new(initial);
                let prepared = PreparedSk::new(&raw).unwrap();
                let mut scratch = SigningScratch::new();
                scratch.poison();
                scope.entropy_error(true);
                assert_eq!(
                    sign_fixture(&ctx, &prepared, &mut scratch),
                    Err(Error::RngFailure)
                );
                assert!(scratch.is_erased());
                drop(prepared);
                drop(scope);
                test_support::record_thread(initial, sink);
                AFTER.with(|p| *p.borrow_mut() = Some(AfterCache));
                // The scratch owner is initialized last, so its destructor
                // runs first and the sink and restoration probe survive it.
                HELD.with(|p| *p.borrow_mut() = Some(scratch));
                test_support::set_failure(mode);
            })
            .join()
            .unwrap();
            let events = events.lock().unwrap();
            let expected = if mode == 0 { DIT } else { initial };
            assert_eq!(
                *events,
                [("scratch-erase", expected), ("tls-after-cache", initial)]
            );
        }
    }
}

fn sign_fixture(
    ctx: &Ctx,
    key: &PreparedSk,
    scratch: &mut SigningScratch,
) -> Result<(Vec<u8>, u32), Error> {
    crate::scheme::prepared_signer::sign_prepared_with_scratch(
        ctx,
        key,
        scratch,
        b"",
        b"DIT lifetime",
    )
}

fn check_extra_key_drop(events: &[(&str, u64)], expected: u64) {
    require(events, &["highprecision-drop"], expected);
}

#[test]
fn public_wrappers_fail_before_parse_and_restore_on_unwind() {
    use crate as api;
    let ctx = api::Ctx::new();
    let pair = api::keygen(&ctx).unwrap();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        for mode in [1, 2] {
            scope.fail(mode);
            assert!(matches!(
                api::PreparedSk::new(&pair.sk),
                Err(Error::TimingProtectionUnavailable)
            ));
            assert_eq!(
                api::sign(&ctx, &pair.sk, b"DIT"),
                Err(Error::TimingProtectionUnavailable)
            );
            assert_eq!(
                api::sign_with_context(&ctx, &pair.sk, b"", b"DIT"),
                Err(Error::TimingProtectionUnavailable)
            );
            assert_eq!(read() & DIT, initial);
            assert!(scope.take().is_empty());
        }
        scope.fail(0);
        scope.panic_at("prepare-exit");
        assert!(catch_unwind(AssertUnwindSafe(|| api::sign(&ctx, &pair.sk, b"DIT"))).is_err());
        assert_eq!(read() & DIT, initial);
        require(&scope.take(), &["parsed-key-drop"], DIT);
    }
}

#[test]
fn public_keygen_and_callback_cover_every_draw_private_work_and_cleanup() {
    use crate as api;
    struct Callback;
    impl crate::EntropySource for Callback {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            assert_eq!(read() & DIT, DIT);
            crate::EntropySource::fill(&mut crate::OsEntropy, out)
        }
    }
    let ctx = api::Ctx::new();
    for callback in [false, true] {
        let run = || {
            if callback {
                api::keygen_with_entropy(&ctx, &mut Callback)
            } else {
                api::keygen(&ctx)
            }
        };
        for initial in [0, DIT] {
            let scope = test_support::Scope::new(initial);
            scope.keygen_record();
            let pair = run().unwrap();
            assert_eq!(read() & DIT, initial);
            let tape = scope.keygen_tape();
            // Matrix seed, PRF key, one 64-byte key seed per shell attempt,
            // then the candidate-start seed; nothing is drawn after it.
            assert!(tape.len() >= 4, "{} requests", tape.len());
            assert_eq!(tape[0].len(), 32);
            assert_eq!(tape[1].len(), 32);
            assert!(tape[2..tape.len() - 1].iter().all(|draw| draw.len() == 64));
            assert_eq!(tape[tape.len() - 1].len(), 32);
            let events = scope.take();
            assert!(events.iter().all(|e| e.1 == DIT), "{events:?}");
            // With the feature `stack-wipe` the stack scrub of key generation completes
            // once; without it, never.
            require_wipes(&events, 1);
            assert_eq!(
                events.iter().filter(|e| e.0 == "keygen-entropy").count(),
                tape.len()
            );
            for site in [
                "keygen-private",
                "keygen-pack",
                "keygen-prf-drop",
                "keygen-s0-drop",
                "keygen-e-drop",
                "keygen-acc-drop",
            ] {
                assert!(events.iter().any(|e| e.0 == site), "{site}: {events:?}");
            }
            assert_eq!(
                events.iter().filter(|e| e.0 == "keygen-acc-drop").count(),
                crate::params::M,
                "{events:?}"
            );
            // Replay exactly the successful entropy prefix for every fault.
            for draw in 1..=tape.len() {
                for panic in [false, true] {
                    scope.keygen_replay(&tape, draw, panic);
                    let result = catch_unwind(AssertUnwindSafe(run));
                    if panic {
                        assert!(result.is_err());
                    } else {
                        assert!(matches!(result.unwrap(), Err(Error::RngFailure)));
                    }
                    assert_eq!(read() & DIT, initial);
                    let events = scope.take();
                    assert!(events.iter().all(|e| e.1 == DIT), "{events:?}");
                    assert_eq!(
                        events.iter().filter(|e| e.0 == "keygen-entropy").count(),
                        draw
                    );
                    if draw > 1 {
                        assert!(events.contains(&("keygen-seed_a-drop", DIT)));
                    }
                    if draw > 2 {
                        assert!(events.contains(&("keygen-prf-drop", DIT)));
                    }
                }
            }
            for site in ["keygen-private", "keygen-pack"] {
                scope.keygen_replay(&tape, 0, false);
                scope.panic_at(site);
                assert!(catch_unwind(AssertUnwindSafe(run)).is_err());
                assert_eq!(read() & DIT, initial);
                let events = scope.take();
                assert!(events.iter().all(|e| e.1 == DIT), "{events:?}");
                assert!(events.contains(&(site, DIT)));
                assert!(events.contains(&("keygen-prf-drop", DIT)));
            }
            for mode in [1, 2] {
                scope.fail(mode);
                assert!(matches!(run(), Err(Error::TimingProtectionUnavailable)));
                assert_eq!(read() & DIT, initial);
                assert!(scope.take().is_empty());
            }
            scope.fail(0);
            scope.keygen_replay(&tape, 0, false);
            let replay = run().unwrap();
            assert_eq!(replay.pk, pair.pk);
            assert_eq!(&replay.sk[..], &pair.sk[..]);
            assert_eq!(read() & DIT, initial);
        }
    }
}

#[test]
fn public_sign_outer_guard_covers_return_move_signing_and_drop() {
    use crate as api;
    let ctx = api::Ctx::new();
    let pair = api::keygen(&ctx).unwrap();
    for wrapper in 0..4 {
        let run = || match wrapper {
            0 => api::sign(&ctx, &pair.sk, b"DIT"),
            1 => api::sign_with_context(&ctx, &pair.sk, b"ctx", b"DIT"),
            2 => api::sign_with_stats(&ctx, &pair.sk, b"DIT").map(|(sig, _)| sig),
            3 => crate::scheme::prepared_signer::sign_with_context_and_stats(
                &ctx, &pair.sk, b"ctx", b"DIT",
            )
            .map(|(sig, _)| sig),
            _ => unreachable!(),
        };
        // Every wrapper reaches the shipped signer.
        for initial in [0, DIT] {
            for mode in 0..5 {
                let scope = test_support::Scope::new(initial);
                match mode {
                    1 => scope.entropy_error(true),
                    2 => scope.panic_at("prepare-exit"),
                    3 => scope.panic_at("sign-prepared-return"),
                    4 => scope.panic_at("sign-entropy"),
                    _ => {}
                }
                let result = catch_unwind(AssertUnwindSafe(run));
                if mode >= 2 {
                    assert!(result.is_err());
                } else if mode == 1 {
                    assert_eq!(result.unwrap(), Err(Error::RngFailure));
                } else {
                    assert!(result.unwrap().is_ok());
                }
                assert_eq!(read() & DIT, initial);
                let events = scope.take();
                require(
                    &events,
                    &["prepare-entry", "prepare-exit", "parsed-key-drop"],
                    DIT,
                );
                if mode != 2 {
                    require(&events, &["sign-prepared-return"], DIT);
                    let at = |site| events.iter().position(|e| e.0 == site).unwrap();
                    assert!(at("prepare-exit") < at("sign-prepared-return"));
                    assert!(at("sign-prepared-return") < at("parsed-key-drop"));
                    if mode != 3 {
                        assert!(events.contains(&("sign-entropy", DIT)));
                        assert!(at("sign-prepared-return") < at("sign-entropy"));
                        assert!(at("sign-entropy") < at("parsed-key-drop"));
                    }
                }
            }
            for failure in [1, 2] {
                let scope = test_support::Scope::new(initial);
                scope.fail(failure);
                assert_eq!(run(), Err(Error::TimingProtectionUnavailable));
                assert_eq!(read() & DIT, initial);
                assert!(scope.take().is_empty());
            }
        }
    }
}

#[test]
fn caller_scoped_preparation_covers_owned_return_and_drop() {
    let ctx = Ctx::new();
    let pair = crate::keygen(&ctx).unwrap();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        crate::scheme::with_signing_guard(|| {
            let prepared = PreparedSk::new(&pair.sk)?;
            test_support::observe("caller-prepared-return");
            let mut scratch = SigningScratch::new();
            sign_fixture(&ctx, &prepared, &mut scratch)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(read() & DIT, initial);
        require(
            &scope.take(),
            &["caller-prepared-return", "parsed-key-drop"],
            DIT,
        );
        // Owned moves at caller DIT must leave the secret allocation in place.
        // Source checkpoints alone cannot certify compiler-generated copies.
        let prepared = PreparedSk::new(&pair.sk).unwrap();
        let address = prepared.secret_address();
        let moved = Box::new(prepared);
        assert_eq!(moved.secret_address(), address);
        let prepared = *moved;
        assert_eq!(prepared.secret_address(), address);
        test_support::observe("standalone-prepared-return");
        assert_eq!(read() & DIT, initial);
        drop(prepared);
        let events = scope.take();
        assert!(events.contains(&("standalone-prepared-return", initial)));
        assert!(events.contains(&("parsed-key-drop", DIT)));
        assert_eq!(read() & DIT, initial);
    }
}

#[test]
fn public_sign_malformed_keys_restore_without_entropy() {
    let ctx = Ctx::new();
    let pair = crate::keygen(&ctx).unwrap();
    let shell = malformed_shell(&pair);
    let mut late = pair.sk.to_vec();
    let mut pk = crate::direct_ntt_profile::public_body(&pair.pk)
        .unwrap()
        .to_vec();
    *late.last_mut().unwrap() ^= 1;
    *pk.last_mut().unwrap() ^= 1;
    let hash_at = late.len() - 64;
    late[hash_at..hash_at + 32].copy_from_slice(&crate::hashes::shake256_32(&pk));
    for wrapper in 0..4 {
        let run = |raw: &[u8]| match wrapper {
            0 => crate::sign(&ctx, raw, b"DIT"),
            1 => crate::sign_with_context(&ctx, raw, b"ctx", b"DIT"),
            2 => crate::sign_with_stats(&ctx, raw, b"DIT").map(|v| v.0),
            3 => crate::scheme::prepared_signer::sign_with_context_and_stats(
                &ctx, raw, b"ctx", b"DIT",
            )
            .map(|v| v.0),
            _ => unreachable!(),
        };
        for initial in [0, DIT] {
            for (case, raw) in [&[][..], &shell[..], &late[..]].into_iter().enumerate() {
                let scope = test_support::Scope::new(initial);
                // Explicit injected decoder exhaustion, not a natural fixture.
                scope.reject(case == 2);
                assert_eq!(run(raw), Err(Error::KeyFormat));
                scope.reject(false);
                assert_eq!(read() & DIT, initial);
                let events = scope.take();
                require(&events, &["prepare-entry"], DIT);
                assert!(!events
                    .iter()
                    .any(|e| matches!(e.0, "sign-entropy" | "sign-prepared-return")));
                if case > 0 {
                    require(
                        &events,
                        &["parse-trits-drop", "parse-prf-drop", "parse-s_flat-drop"],
                        DIT,
                    );
                }
                if case == 2 {
                    require(
                        &events,
                        &[
                            "parse-hash-ok",
                            "dither-exhaustion-fault",
                            "parse-cols-drop",
                            "parsed-key-drop",
                        ],
                        DIT,
                    );
                }
                for mode in [1, 2] {
                    scope.fail(mode);
                    assert_eq!(run(raw), Err(Error::TimingProtectionUnavailable));
                    assert_eq!(read() & DIT, initial);
                    assert!(scope.take().is_empty(), "guard failure reached preparation");
                }
            }
        }
    }
}

#[test]
fn erasure_runs_when_dit_entry_fails_capability_failure_class() {
    let pair = crate::keygen(&Ctx::new()).unwrap();
    for initial in [0, DIT] {
        // 1 rejects capability before register access; 2 fails enable readback
        // after enabling and restores the caller's original DIT state.
        for failure in [1, 2] {
            let scope = test_support::Scope::new(initial);
            let mut prepared = PreparedSk::new(&pair.sk).unwrap();
            let allocation = prepared.secret_address();
            prepared.poison_secret_for_dit_test();
            assert_eq!(prepared.secret_address(), allocation);
            let mut scratch = SigningScratch::new();
            scratch.poison();
            assert!(!scratch.is_erased());
            scope.take();
            scope.record_erasure();
            scope.fail(failure);
            assert!(matches!(
                Guard::enter(),
                Err(Error::TimingProtectionUnavailable)
            ));
            assert_eq!(read() & DIT, initial);

            // Explicit clearing and actual Drop both must erase. Re-poison so
            // the destructor cannot pass just because explicit clearing ran.
            scratch.zeroize();
            assert!(scratch.is_erased());
            assert_eq!(read() & DIT, initial);
            scratch.poison();
            assert!(!scratch.is_erased());
            drop(scratch);
            assert_eq!(read() & DIT, initial);
            drop(prepared);
            assert_eq!(read() & DIT, initial);
            assert_eq!(
                scope.take_erasures(),
                [
                    ("scratch-erased", true, initial),
                    ("scratch-erased", true, initial),
                    ("prepared-secret-erased", true, initial),
                    ("correlation-spectra-erased", true, initial),
                ]
            );
            let events = scope.take();
            require(&events, &["parsed-key-drop"], initial);
            check_extra_key_drop(&events, initial);
        }
    }
}

// Observe initialized lanes after the actual Key destructor, never freed memory.
#[test]
fn correlation_spectra_wipe_on_return_and_partial_construction_unwind() {
    let pair = crate::keygen(&Ctx::new()).unwrap();
    for initial in [0, DIT] {
        for site in [
            "correlation-spectra-copy",
            "correlation-spectra-ready",
            "prepare-exit",
        ] {
            let scope = test_support::Scope::new(initial);
            scope.record_erasure();
            scope.panic_at(site);
            assert!(catch_unwind(|| PreparedSk::new(&pair.sk)).is_err());
            assert_eq!(read() & DIT, initial);
            let erasures = scope.take_erasures();
            let spectra: Vec<_> = erasures
                .into_iter()
                .filter(|event| event.0 == "correlation-spectra-erased")
                .collect();
            assert_eq!(spectra, [("correlation-spectra-erased", true, DIT)]);
            assert!(scope.take().contains(&(site, DIT)));
        }
        let scope = test_support::Scope::new(initial);
        let prepared = PreparedSk::new(&pair.sk).unwrap();
        scope.record_erasure();
        drop(prepared);
        assert_eq!(read() & DIT, initial);
        let erasures = scope.take_erasures();
        let spectra: Vec<_> = erasures
            .into_iter()
            .filter(|event| event.0 == "correlation-spectra-erased")
            .collect();
        assert_eq!(spectra, [("correlation-spectra-erased", true, DIT)]);
    }
}

/// Stack painting around a key import that unwinds. Compiled only with the Cargo feature
/// `stack-wipe`, and for optimized builds only: the extent that the import erases is chosen for
/// the frames of optimized images.
///
/// `unwinding_import` fills 524288 bytes of stack directly below its own frame with a pattern
/// that depends on the address, calls `PreparedSk::new` inside `catch_unwind` with a panic
/// injected by the caller, and reads the same bytes back. `unwinding_reference` does the same
/// with `reference_entry` in place of the import: the same scrub, held above a function that
/// fills a local of `BODY_BYTES` zero bytes, as large as the frame of the import body in an
/// optimized program, and panics. Nothing secret is below the scrub of the reference.
///
/// Positions are taken relative to the scrub mark: the address of a local of the function that
/// records the completion of the scrub, which lies directly below the frame that holds the
/// scrub. `EXTENT` is written out here and not taken from the constant of the scrub, so a
/// shorter scrub fails the test.
///
/// Required:
///
/// 1. a scrub completed in the reference and in the import, and the painted region was large
///    enough;
/// 2. within the extent, no nonzero word lies deeper than `ALLOWANCE` bytes below the scrub
///    mark, in the reference and in the import. The top of the erased range is not zero when
///    the panic is caught: after the scrub the unwinder continues from the frame that holds
///    the scrub and writes its own state directly below it;
/// 3. where `SAME_RESIDUE` is true, the deepest nonzero word within the extent lies within
///    `TOLERANCE` bytes of the same depth in the reference and in the import. Observed on
///    optimized unit-test builds: 23719 against 23711 bytes at Pretzel-(4,4) and
///    Pretzel-(5,5); 28327 against 23647 at Pretzel-(3,3), with the present extent as well as
///    with a smaller one. The 4680 further bytes at Pretzel-(3,3) are words written after the
///    scrub (the words nearer the mark agree); what writes them has not been identified, so
///    at Pretzel-(3,3) the comparison is printed and not required. It is an open item.
///
/// Printed to standard error and not required: whether words deeper than the extent were
/// changed in both or in neither (the panic handler runs below the frames of the import before
/// the scrub and can write deeper than the extent, where nothing is erased); the panic mark
/// (the address of a local of the function that raises the panic) below the scrub mark; the
/// deepest changed word below the panic mark; the span of the reference's local; and the
/// nonzero words within the extent in eight bins of 4096 bytes below the scrub mark.
///
/// What the test does not show: what the words left by the unwinder hold, which can include
/// saved register contents; anything about the words that the panic handler wrote deeper than
/// the extent, which no scrub erases; registers. It is one observation of one image, not a
/// bound.
#[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
mod import_unwind_stack {
    use super::*;
    use std::hint::black_box;

    /// Bytes of stack that the key import zeroes below `PreparedSk::new`.
    const EXTENT: usize = 393216;
    /// Frame of the import body in the optimized image of the known-answer programs, in bytes.
    /// The body's frame in the unit-test build is not known and may be larger.
    const BODY_BYTES: usize = 165744;
    /// Deepest nonzero word accepted within the extent, in bytes below the scrub mark.
    const ALLOWANCE: usize = 32768;
    /// Accepted difference between the reference and the import in that depth.
    const TOLERANCE: usize = 256;
    /// Whether that difference is required at this parameter set, or only printed.
    const SAME_RESIDUE: bool = true;
    /// Bytes on each side of the deep end of the extent that are not judged: the scrub mark is
    /// not exactly the top of the erased range.
    const EDGE: usize = 512;
    /// Words painted below the measuring frame: 524288 bytes.
    const PAINT_WORDS: usize = 65536;
    const PATTERN: u64 = 0x5ca7_c4ed_a5a5_5a5a;

    #[inline(always)]
    fn painted(address: usize) -> u64 {
        PATTERN ^ address as u64
    }

    /// Fill PAINT_WORDS words directly below the caller's frame and return the lowest address.
    /// The function is out of line, so the words stay painted after it returns.
    #[inline(never)]
    fn paint() -> usize {
        let mut region = core::mem::MaybeUninit::<[u64; PAINT_WORDS]>::uninit();
        let base = region.as_mut_ptr().cast::<u64>();
        for i in 0..PAINT_WORDS {
            // SAFETY: word `i` of this function's own local array of PAINT_WORDS words.
            unsafe {
                base.add(i).write_volatile(painted(base as usize + 8 * i));
            }
        }
        black_box(base) as usize
    }

    /// What one scan found. Depths are bytes below the scrub mark.
    pub(super) struct Picture {
        /// A scrub completed during the call.
        marked: bool,
        /// Bytes from the top of the painted region down to the scrub mark; negative when the
        /// mark lies above the painted region.
        mark_below_top: isize,
        /// Deepest nonzero word within the extent; 0 when every such word is zero.
        deepest_nonzero: usize,
        /// Words deeper than the extent that no longer hold their paint.
        changed_beyond: usize,
        /// Deepest such word; 0 when there is none.
        deepest_changed: usize,
        /// The lowest painted word changed: the painted region was too small.
        exhausted: bool,
        /// The panic mark, in bytes below the scrub mark; 0 when no panic mark was set.
        panic_below_mark: isize,
        /// Nonzero words within the extent, by depth below the scrub mark in bins of 4096 bytes;
        /// the last bin also counts everything deeper.
        bins: [usize; 8],
        /// The reference's local: its low and high end in bytes below the scrub mark.
        filler: (isize, isize),
    }

    impl Picture {
        pub(super) fn describe(&self) -> String {
            format!(
                "scrub mark {} bytes below the top of the painted region; deepest nonzero word \
                 within the extent {} bytes below the mark; {} words changed deeper than the \
                 extent, the deepest {} bytes below the mark; painted region exhausted: {}; \
                 panic mark {} bytes below the scrub mark; deepest changed word {} bytes below \
                 the panic mark; nonzero words within the extent by 4096-byte bins {:?}; \
                 local of the reference from {} to {} bytes below the scrub mark",
                self.mark_below_top,
                self.deepest_nonzero,
                self.changed_beyond,
                self.deepest_changed,
                self.exhausted,
                self.panic_below_mark,
                self.deepest_changed as isize - self.panic_below_mark,
                self.bins,
                self.filler.1,
                self.filler.0
            )
        }
    }

    /// Read back the region painted by `paint`, from the frame that called `paint`. `mark` is
    /// the scrub mark of the call that ran in between, `panic_mark` its panic mark, and
    /// `filler` the address range of the reference's local (zeros for an import).
    #[inline(never)]
    fn scan(base: usize, mark: usize, panic_mark: usize, filler: (usize, usize)) -> Picture {
        let words = base as *const u64;
        let top = base + 8 * PAINT_WORDS;
        let mut picture = Picture {
            marked: mark != 0,
            mark_below_top: top as isize - mark as isize,
            deepest_nonzero: 0,
            changed_beyond: 0,
            deepest_changed: 0,
            exhausted: false,
            panic_below_mark: if panic_mark == 0 {
                0
            } else {
                mark as isize - panic_mark as isize
            },
            bins: [0; 8],
            filler: (
                mark as isize - filler.0 as isize,
                mark as isize - filler.1 as isize,
            ),
        };
        for i in 0..PAINT_WORDS {
            let address = base + 8 * i;
            // SAFETY: the address lies in this thread's own stack, in the pages that `paint`
            // wrote from the same caller frame, so it is mapped and readable. The words are
            // below the live frames, apart from this function's own, and no reference to them
            // exists; the volatile read takes whatever value is there. The test installs no
            // signal handler, so nothing else writes to this stack.
            let word = unsafe { words.add(i).read_volatile() };
            if i == 0 && word != painted(address) {
                picture.exhausted = true;
            }
            if mark == 0 || address >= mark {
                continue;
            }
            let below = mark - address;
            if below <= EXTENT - EDGE {
                if word != 0 {
                    picture.deepest_nonzero = picture.deepest_nonzero.max(below);
                    picture.bins[(below / 4096).min(7)] += 1;
                }
            } else if below > EXTENT + EDGE && word != painted(address) {
                picture.changed_beyond += 1;
                picture.deepest_changed = picture.deepest_changed.max(below);
            }
        }
        picture
    }

    /// Take the scrub mark of the scrub that completed last on this thread and the panic mark
    /// of the panic that was raised last; each is 0 when there was none.
    #[inline(always)]
    fn take_marks() -> (usize, usize) {
        (
            crate::ct_erase::LAST_SCRUB_MARK.with(|mark| mark.replace(0)),
            crate::ct_erase::LAST_PANIC_MARK.with(|mark| mark.replace(0)),
        )
    }

    std::thread_local! {
        /// Lowest address and one past the highest address of the local of `reference_body`.
        static FILLER: core::cell::Cell<(usize, usize)> = const { core::cell::Cell::new((0, 0)) };
    }

    /// Paint, import `sk` inside `catch_unwind`, and read the stack back. Returns whether the
    /// import unwound, and the picture. Only the read of the scrub mark runs between the three
    /// calls, and all are made from this frame.
    #[inline(never)]
    pub(super) fn unwinding_import(sk: &[u8]) -> (bool, Picture) {
        let base = paint();
        let unwound = catch_unwind(|| PreparedSk::new(sk)).is_err();
        let (mark, panic_mark) = take_marks();
        (unwound, scan(base, mark, panic_mark, (0, 0)))
    }

    /// Holds the scrub of the key import above a callee that only fills its frame and panics.
    #[inline(never)]
    fn reference_entry() {
        let _stack_scrub = crate::ct_erase::StackScrub::<{ EXTENT / 8 }>;
        reference_body();
    }

    #[inline(never)]
    fn reference_body() {
        let filler = [0u8; BODY_BYTES];
        let low = black_box(&filler).as_ptr() as usize;
        FILLER.with(|span| span.set((low, low + BODY_BYTES)));
        crate::ct_erase::mark_panic_point();
        panic!("reference unwind of the stack test: no import below the scrub");
    }

    /// As `unwinding_import`, with `reference_entry` in place of the import.
    #[inline(never)]
    pub(super) fn unwinding_reference() -> (bool, Picture) {
        let base = paint();
        let unwound = catch_unwind(reference_entry).is_err();
        let (mark, panic_mark) = take_marks();
        let filler = FILLER.with(|span| span.replace((0, 0)));
        (unwound, scan(base, mark, panic_mark, filler))
    }

    /// The requirements on one unwinding import against the reference; see the module comment.
    pub(super) fn judge(name: &str, import: &Picture, reference: &Picture) {
        assert!(
            !import.exhausted && !reference.exhausted,
            "{name}: the painted region was too small"
        );
        assert!(
            import.marked && reference.marked,
            "{name}: no scrub completed"
        );
        assert!(
            reference.deepest_nonzero <= ALLOWANCE,
            "{name}: the reference leaves a nonzero word {} bytes below the scrub mark",
            reference.deepest_nonzero
        );
        assert!(
            import.deepest_nonzero <= ALLOWANCE,
            "{name}: the import leaves a nonzero word {} bytes below the scrub mark",
            import.deepest_nonzero
        );
        let same_residue = import.deepest_nonzero.abs_diff(reference.deepest_nonzero) <= TOLERANCE;
        let same_beyond = (import.changed_beyond > 0) == (reference.changed_beyond > 0);
        // Printed in every case; see the module comment.
        eprintln!(
            "{name}: same depth of the residue within {TOLERANCE} bytes: {same_residue}, \
             required here: {SAME_RESIDUE}; words changed deeper than the extent in both or in \
             neither: {same_beyond}, not required"
        );
        assert!(
            same_residue || !SAME_RESIDUE,
            "{name}: the deepest nonzero word within the extent is {} bytes below the scrub mark \
             after the import and {} after the reference",
            import.deepest_nonzero,
            reference.deepest_nonzero
        );
    }
}
