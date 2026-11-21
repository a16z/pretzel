//! Tests of the crate-root interface of Pretzel-(4,4).
use pretzel_4_4::*;
use std::sync::OnceLock;

// The two stack tests exist only with the Cargo feature `stack-wipe`: without it nothing zeroes a
// range of stack and there is nothing for them to require. They are compiled for optimized builds
// only: the extents are chosen for the frames of optimized images.
#[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
mod sign_stack;

#[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
mod import_stack;

fn fixture() -> &'static (Ctx, Keypair, PreparedSk, PreparedPk) {
    static FIXTURE: OnceLock<(Ctx, Keypair, PreparedSk, PreparedPk)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let ctx = Ctx::new();
        let pair = keygen(&ctx).unwrap();
        let sk = PreparedSk::new(&pair.sk).unwrap();
        let pk = PreparedPk::new(&pair.pk).unwrap();
        (ctx, pair, sk, pk)
    })
}

#[test]
fn ordinary_and_prepared_apis_use_the_selected_format() {
    let (ctx, pair, sk, pk) = fixture();
    assert_eq!(pair.pk.len(), PUBLIC_KEY_BYTES);
    assert_eq!(pair.sk.len(), SECRET_KEY_BYTES);
    assert_eq!(sk.public_key(), pair.pk);
    let message = b"selected PRETZEL API";
    for signature in [
        sign(ctx, &pair.sk, message).unwrap(),
        sign_prepared(ctx, sk, message).unwrap(),
        sign_with_stats(ctx, &pair.sk, message).unwrap().0,
        sign_prepared_with_stats(ctx, sk, message).unwrap().0,
    ] {
        assert_eq!(signature.len(), 1361);
        verify(ctx, &pair.pk, message, &signature).unwrap();
        verify_prepared(ctx, pk, message, &signature).unwrap();
        assert!(verify(ctx, &pair.pk, b"wrong", &signature).is_err());
        assert!(verify_prepared(ctx, pk, b"wrong", &signature).is_err());
    }
}

#[test]
fn contextual_and_scratch_apis_agree_on_acceptance() {
    let (ctx, pair, sk, pk) = fixture();
    let mut scratch = SigningScratch::new();
    let message = b"selected contextual PRETZEL";
    let context = b"application";
    for signature in [
        sign_with_context(ctx, &pair.sk, context, message).unwrap(),
        sign_prepared_with_context(ctx, sk, context, message).unwrap(),
        sign_prepared_with_context_and_stats(ctx, sk, context, message)
            .unwrap()
            .0,
        sign_prepared_with_scratch(ctx, sk, &mut scratch, context, message)
            .unwrap()
            .0,
    ] {
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        verify_with_context(ctx, &pair.pk, context, message, &signature).unwrap();
        verify_prepared_with_context(ctx, pk, context, message, &signature).unwrap();
        assert!(verify_with_context(ctx, &pair.pk, b"wrong", message, &signature).is_err());
        assert!(verify_prepared_with_context(ctx, pk, b"wrong", message, &signature).is_err());
        for size in [0, 1267, 1319, 1360, 1362, 1461] {
            let mut bad = signature.clone();
            bad.resize(size, 0);
            assert!(verify_with_context(ctx, &pair.pk, context, message, &bad).is_err());
            assert!(verify_prepared_with_context(ctx, pk, context, message, &bad).is_err());
        }
    }
}

#[test]
fn native_entropy_errors_and_key_import_rejections_are_preserved() {
    struct FailedEntropy;
    impl EntropySource for FailedEntropy {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
            out.fill(0);
            Err(EntropyError)
        }
    }
    let (ctx, pair, _, _) = fixture();
    assert!(matches!(
        keygen_with_entropy(ctx, &mut FailedEntropy),
        Err(Error::RngFailure)
    ));
    for size in [0, 1, PUBLIC_KEY_BYTES - 1, PUBLIC_KEY_BYTES + 1] {
        assert!(PreparedPk::new(&vec![0; size]).is_err());
    }
    for size in [0, 1, SECRET_KEY_BYTES - 1, SECRET_KEY_BYTES + 1] {
        assert!(PreparedSk::new(&vec![0; size]).is_err());
    }
    let mut wrong_tag = pair.pk.clone();
    wrong_tag[0] ^= 1;
    assert!(PreparedPk::new(&wrong_tag).is_err());
}

#[test]
fn secret_preparation_signing_and_drop_restore_caller_dit() {
    const DIT: u64 = 1 << 24;
    fn read() -> u64 {
        let value: u64;
        // SAFETY: fixture key generation has already required native DIT support.
        unsafe {
            core::arch::asm!("mrs {value}, S3_3_C4_C2_5", value = out(reg) value,
                options(nostack, preserves_flags));
        }
        value
    }
    fn write(value: u64) {
        // SAFETY: native support is established; only DIT state is written.
        unsafe {
            core::arch::asm!("msr S3_3_C4_C2_5, {value}", "dsb nsh", "isb",
                value = in(reg) value, options(nostack, preserves_flags));
        }
    }
    struct Restore(u64);
    impl Drop for Restore {
        fn drop(&mut self) {
            write(self.0);
        }
    }
    // This image uses the production dependency, with no unit-test hooks.
    let (ctx, pair, _, _) = fixture();
    let _restore = Restore(read());
    let mut malformed = pair.sk.to_vec();
    malformed[14 + 576] ^= 1;
    for initial in [0, DIT] {
        write(initial);
        let prepared = PreparedSk::new(&pair.sk).unwrap();
        assert_eq!(read() & DIT, initial);
        drop(prepared);
        assert_eq!(read() & DIT, initial);
        let signature = sign(ctx, &pair.sk, b"DIT restoration").unwrap();
        assert_eq!(read() & DIT, initial);
        verify(ctx, &pair.pk, b"DIT restoration", &signature).unwrap();
        for bad in [b"".as_slice(), malformed.as_slice()] {
            assert!(matches!(PreparedSk::new(bad), Err(Error::KeyFormat)));
            assert_eq!(read() & DIT, initial);
            assert!(matches!(sign(ctx, bad, b""), Err(Error::KeyFormat)));
            assert_eq!(read() & DIT, initial);
        }
    }
}

/// With the feature `stack-wipe`, prepared-key signing zeroes the stack below its entry; see
/// `sign_stack.rs` for what is required and what is not shown. A rejected attempt is frequent
/// enough at this parameter set to require at least one for each entry.
#[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
#[test]
fn prepared_signing_erases_the_stack_below_its_entry() {
    sign_stack::check(true);
}

/// With the feature `stack-wipe`, the import of a stored secret key zeroes 393216 bytes of stack
/// below `PreparedSk::new`, when it accepts the key and when it rejects it; see `import_stack.rs`
/// for what is required and what is not shown.
#[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
#[test]
fn key_import_erases_the_stack_below_its_entry() {
    import_stack::check(393216);
}
