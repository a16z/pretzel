//! Public deterministic fixtures and fault controls, never application entropy.
//! The library is linked unchanged; the public test tape of `entropy.c` supplies its entropy.
use pretzel_4_4::*;
use std::{fs, path::PathBuf};
// SAFETY: the five symbols are defined in `tests/native/entropy.c`, which
// `scripts/run_kat_replay.py` compiles and links into this program; the
// signatures match the C definitions.
unsafe extern "C" {
    fn pretzel_test_tape_reset(seed: u64, fail_at: u64, partial: i32);
    fn pretzel_test_tape_end();
    fn pretzel_test_tape_calls() -> u64;
    fn pretzel_test_tape_bytes() -> u64;
    fn pretzel_test_tape_suffix(out: *mut u8);
}
fn dit() -> u64 {
    let value: u64;
    // SAFETY: user code may read the DIT register on a processor with FEAT_DIT,
    // which `scripts/run_kat_replay.py` requires before it builds this program.
    // The instruction writes only the output register.
    unsafe {
        core::arch::asm!("mrs {value}, S3_3_C4_C2_5",value=out(reg)value,options(nostack,preserves_flags));
    }
    value
}
fn start(seed: u64, fail_at: u64, partial: bool) {
    // SAFETY: the call passes three integers and resets the tape of this
    // thread, which `entropy.c` keeps in thread-local storage.
    unsafe {
        pretzel_test_tape_reset(seed, fail_at, partial as i32);
    }
}
fn finish() -> (u64, u64, [u8; 64]) {
    // SAFETY: `suffix` is 64 writable bytes and `pretzel_test_tape_suffix`
    // writes exactly 64; the other calls take no pointer and touch only the
    // tape of this thread.
    unsafe {
        let mut suffix = [0; 64];
        pretzel_test_tape_suffix(suffix.as_mut_ptr());
        pretzel_test_tape_end();
        (pretzel_test_tape_calls(), pretzel_test_tape_bytes(), suffix)
    }
}
fn main() {
    let out = PathBuf::from(std::env::args().nth(1).expect("public fixture directory"));
    fs::create_dir_all(&out).unwrap();
    let ctx = Ctx::new();
    let before = dit();
    let mut cases = 0;
    let mut faults = 0;
    let mut max_attempts = 0;
    for key in 0..4u64 {
        start(0x505245545a454c00 + key, 0, false);
        let pair = keygen(&ctx).unwrap();
        let key_tape = finish();
        assert!(key_tape.0 > 0, "entropy interposition did not run");
        assert_eq!(dit(), before);
        fs::write(out.join(format!("key-{key}.pk")), &pair.pk).unwrap();
        // These are public-tape test keys, explicitly not deployment secrets.
        fs::write(out.join(format!("key-{key}.fixture-sk")), &*pair.sk).unwrap();
        fs::write(out.join(format!("key-{key}.tape")), format!("{key_tape:?}")).unwrap();
        let sk = PreparedSk::new(&pair.sk).unwrap();
        let pk = PreparedPk::new(&pair.pk).unwrap();
        let mut scratch = SigningScratch::new();
        for case in 0..8u64 {
            let message = vec![case as u8; [0, 32, 4096, 65536][case as usize % 4]];
            let context = vec![0x80 | case as u8; [0, 1, 255, 256][case as usize / 2]];
            let seed = 0x434f4e464f524d00 + key * 16 + case;
            start(seed, 0, false);
            let (signature, attempts) =
                sign_prepared_with_context_and_stats(&ctx, &sk, &context, &message).unwrap();
            let tape = finish();
            assert_eq!(signature.len(), 1361);
            assert_eq!(tape.0, u64::from(attempts));
            assert_eq!(tape.1, 32 * u64::from(attempts));
            max_attempts = max_attempts.max(attempts);
            assert_eq!(dit(), before);
            verify_with_context(&ctx, &pair.pk, &context, &message, &signature).unwrap();
            verify_prepared_with_context(&ctx, &pk, &context, &message, &signature).unwrap();
            if key == 0 && case == 0 {
                for at in 0..signature.len() {
                    let mut bad = signature.clone();
                    bad[at] ^= 1 << (at % 8);
                    assert!(verify_with_context(&ctx, &pair.pk, &context, &message, &bad).is_err());
                    assert!(
                        verify_prepared_with_context(&ctx, &pk, &context, &message, &bad).is_err()
                    );
                }
            }
            for variant in 0..3 {
                start(seed, 0, false);
                let actual = match variant {
                    0 => sign_prepared_with_scratch(&ctx, &sk, &mut scratch, &context, &message)
                        .map(|(s, n)| {
                            assert_eq!(n, attempts);
                            s
                        }),
                    1 => sign_with_context(&ctx, &pair.sk, &context, &message),
                    _ => sign_prepared_with_context(&ctx, &sk, &context, &message),
                }
                .unwrap();
                assert_eq!(finish(), tape);
                assert_eq!(actual, signature);
                assert_eq!(dit(), before);
            }
            // Every entropy call before the successful return is faulted,
            // both without writes and after a partial fill. No output escapes.
            for at in 1..=tape.0 {
                for partial in [false, true] {
                    for owned in [false, true] {
                        start(seed, at, partial);
                        let result = if owned {
                            sign_prepared_with_scratch(&ctx, &sk, &mut scratch, &context, &message)
                        } else {
                            sign_prepared_with_context_and_stats(&ctx, &sk, &context, &message)
                        };
                        let failed = finish();
                        assert!(matches!(result, Err(Error::RngFailure)));
                        assert_eq!(failed.0, at);
                        assert_eq!(dit(), before);
                        faults += 1;
                    }
                }
            }
            start(seed, 0, false);
            assert_eq!(
                sign_prepared_with_context_and_stats(&ctx, &sk, &context, &message).unwrap(),
                (signature.clone(), attempts)
            );
            assert_eq!(finish(), tape);
            let name = format!("key-{key}-case-{case}");
            fs::write(out.join(format!("{name}.sig")), &signature).unwrap();
            fs::write(out.join(format!("{name}.msg")), &message).unwrap();
            fs::write(out.join(format!("{name}.ctx")), &context).unwrap();
            fs::write(
                out.join(format!("{name}.tape")),
                format!("attempts={attempts};{tape:?}"),
            )
            .unwrap();
            println!("{{\"key\":{key},\"case\":{case},\"attempts\":{attempts},\"entropy_calls\":{},\"entropy_bytes\":{}}}",tape.0,tape.1);
            cases += 1;
        }
    }
    assert!(max_attempts > 1, "retry coverage is required");
    println!("{{\"cases\":{cases},\"faults\":{faults},\"max_attempts\":{max_attempts},\"status\":\"passed\"}}");
}
