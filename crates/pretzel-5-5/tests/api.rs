//! End-to-end use of the crate-root interface of Pretzel-(5,5): key generation from a fixed
//! public test seed, signing, verification and rejection of changed inputs.
use pretzel_5_5::*;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake256, Shake256Reader};

// The stack test of the key import of the Pretzel-(4,4) crate, compiled against this crate's
// interface. It exists only with the Cargo feature `stack-wipe`: without it nothing zeroes a
// range of stack and there is nothing for it to require. It is compiled for optimized builds
// only: the extent that the import erases is chosen for the frames of optimized images.
#[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
#[path = "../../pretzel-4-4/tests/import_stack.rs"]
mod import_stack;

/// Public test entropy only: a SHAKE256 stream of a fixed label and seed.
struct Tape(Shake256Reader);
impl Tape {
    fn new(seed: u64) -> Self {
        let mut state = Shake256::default();
        state.update(b"PRETZEL55-ROOT-INTERFACE-TEST-v1");
        state.update(&seed.to_le_bytes());
        Self(state.finalize_xof())
    }
}
impl EntropySource for Tape {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        self.0.read(out);
        Ok(())
    }
}

#[test]
fn root_interface_generates_signs_verifies_and_rejects() {
    assert_eq!(SIGNATURE_BYTES, 1908);
    assert_eq!(PUBLIC_KEY_BYTES, 2158);
    assert_eq!(SECRET_KEY_BYTES, 782);
    let ctx = Ctx::new();
    let pair = keygen_with_entropy(&ctx, &mut Tape::new(0)).expect("fixed-seed key generation");
    let again = keygen_with_entropy(&ctx, &mut Tape::new(0)).expect("fixed-seed key generation");
    assert_eq!(pair.pk, again.pk);
    assert_eq!(pair.pk.len(), PUBLIC_KEY_BYTES);
    assert_eq!(pair.sk.len(), SECRET_KEY_BYTES);
    let sk = PreparedSk::new(&pair.sk).expect("secret-key import");
    let pk = PreparedPk::new(&pair.pk).expect("public-key import");
    assert_eq!(sk.public_key(), pair.pk.as_slice());
    assert!(PreparedPk::new(&pair.pk[..PUBLIC_KEY_BYTES - 1]).is_err());
    assert!(PreparedSk::new(&pair.sk[..SECRET_KEY_BYTES - 1]).is_err());

    let message = b"crate-root interface";
    let context = b"application";
    let mut scratch = SigningScratch::new();
    for signature in [
        sign(&ctx, &pair.sk, message).unwrap(),
        sign_with_stats(&ctx, &pair.sk, message).unwrap().0,
        sign_prepared(&ctx, &sk, message).unwrap(),
        sign_prepared_with_stats(&ctx, &sk, message).unwrap().0,
        sign_prepared_with_scratch(&ctx, &sk, &mut scratch, b"", message)
            .unwrap()
            .0,
    ] {
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        verify(&ctx, &pair.pk, message, &signature).unwrap();
        verify_prepared(&ctx, &pk, message, &signature).unwrap();
        assert!(verify(&ctx, &pair.pk, b"another message", &signature).is_err());
        assert!(verify_prepared(&ctx, &pk, b"another message", &signature).is_err());
        assert!(verify_with_context(&ctx, &pair.pk, context, message, &signature).is_err());
        // A changed salt changes the challenge.
        let mut modified = signature.clone();
        modified[0] ^= 1;
        assert!(verify(&ctx, &pair.pk, message, &modified).is_err());
        assert!(verify_prepared(&ctx, &pk, message, &modified).is_err());
        for size in [0, SIGNATURE_BYTES - 1, SIGNATURE_BYTES + 1] {
            let mut resized = signature.clone();
            resized.resize(size, 0);
            assert!(verify(&ctx, &pair.pk, message, &resized).is_err());
            assert!(verify_prepared(&ctx, &pk, message, &resized).is_err());
        }
    }
    for signature in [
        sign_with_context(&ctx, &pair.sk, context, message).unwrap(),
        sign_prepared_with_context(&ctx, &sk, context, message).unwrap(),
        sign_prepared_with_context_and_stats(&ctx, &sk, context, message)
            .unwrap()
            .0,
    ] {
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        verify_with_context(&ctx, &pair.pk, context, message, &signature).unwrap();
        verify_prepared_with_context(&ctx, &pk, context, message, &signature).unwrap();
        assert!(verify(&ctx, &pair.pk, message, &signature).is_err());
        assert!(verify_prepared_with_context(&ctx, &pk, b"other", message, &signature).is_err());
    }
}

/// With the feature `stack-wipe`, the import of a stored secret key zeroes 393216 bytes of stack
/// below `PreparedSk::new`, when it accepts the key and when it rejects it; see `import_stack.rs`
/// in `crates/pretzel-4-4/tests` for what is required and what is not shown.
#[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
#[test]
fn key_import_erases_the_stack_below_its_entry() {
    import_stack::check(393216);
}
