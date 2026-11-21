// Included in the signer test module. Fixtures and emitted data are public.
fn transcript_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn complete_history_transcript() {
    let ctx = Ctx::new();
    let key = prepared(&ctx);
    let mut scratch = SigningScratch::new();
    for seed in [
        b"portfolio-first".as_slice(),
        b"portfolio-second",
        b"portfolio-third",
        b"portfolio-first",
    ] {
        let mut tape = Tape::new(seed);
        let (signature, attempts) = sign_prepared_using(
            &ctx,
            &key,
            &mut scratch,
            b"portfolio-equivalence",
            seed,
            &mut tape,
        )
        .unwrap();
        assert!(scratch.is_erased());
        let mut tail = [0u8; 64];
        tape.x.fill(&mut tail);
        println!(
            "PORTFOLIO1-EQ success {} {} {:?} {} {}",
            transcript_hex(seed),
            attempts,
            tape.sizes,
            transcript_hex(&signature),
            transcript_hex(&tail)
        );
    }
    struct Fault {
        tape: Tape,
        call: usize,
        at: usize,
        panic: bool,
        sizes: Vec<usize>,
    }
    impl EntropySource for Fault {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            self.call += 1;
            self.sizes.push(out.len());
            if self.call == self.at {
                out[..17].fill(0x91);
                if self.panic {
                    panic!("portfolio public failure fixture");
                }
                return Err(crate::EntropyError);
            }
            self.tape.fill(out)
        }
    }
    for at in 1..=4 {
        for panic in [false, true] {
            let guard = RejectGuard::first(4);
            let mut source = Fault {
                tape: Tape::new(b"fault"),
                call: 0,
                at,
                panic,
                sizes: vec![],
            };
            scratch.poison();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sign_prepared_using(&ctx, &key, &mut scratch, b"fault", b"fault", &mut source)
            }));
            let outcome = match result {
                Err(_) => "panic",
                Ok(Err(Error::RngFailure)) => "rng-failure",
                _ => panic!("unexpected fault outcome"),
            };
            assert_eq!(source.call, at);
            assert!(scratch.is_erased());
            let mut tail = [0u8; 64];
            source.tape.x.fill(&mut tail);
            println!(
                "PORTFOLIO1-EQ fault {at} {panic} {outcome} {:?} {:?} {} erased",
                source.sizes,
                guard.attempts(),
                transcript_hex(&tail)
            );
        }
    }
    let mut tape = Tape::new(b"release-check");
    CORRUPT_RELEASE.with(|x| x.set(true));
    RELEASE_ERASED.with(|x| x.set(None));
    let result =
        sign_prepared_using(&ctx, &key, &mut scratch, b"release", b"release", &mut tape);
    assert!(scratch.is_erased());
    assert!(result.is_ok());
    assert_eq!(RELEASE_ERASED.with(|x| x.take()), None);
    let mut tail = [0; 64];
    tape.x.fill(&mut tail);
    println!(
        "PORTFOLIO1-EQ release {:?} {:?} {} release-gate-by-feature",
        result.err(),
        tape.sizes,
        transcript_hex(&tail)
    );
    let guard = RejectGuard::first(MAX_ATTEMPTS);
    let mut tape = Tape::new(b"cap");
    assert!(matches!(
        sign_prepared_using(&ctx, &key, &mut scratch, b"cap", b"cap", &mut tape),
        Err(Error::SignFailed)
    ));
    assert_eq!(guard.attempts(), (0..MAX_ATTEMPTS).collect::<Vec<_>>());
    assert!(scratch.is_erased());
    let mut tail = [0; 64];
    tape.x.fill(&mut tail);
    println!(
        "PORTFOLIO1-EQ cap {:?} {:?} {} erased",
        tape.sizes,
        guard.attempts(),
        transcript_hex(&tail)
    );
    drop(guard);
    // Reuse the same scratch after failed release, exhaustion and unwind.
    let mut tape = Tape::new(b"reset");
    let (signature, attempts) =
        sign_prepared_using(&ctx, &key, &mut scratch, b"reset", b"reset", &mut tape).unwrap();
    assert!(scratch.is_erased());
    let mut tail = [0; 64];
    tape.x.fill(&mut tail);
    println!(
        "PORTFOLIO1-EQ reset {attempts} {:?} {} {} erased",
        tape.sizes,
        transcript_hex(&signature),
        transcript_hex(&tail)
    );
}
