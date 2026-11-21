use super::*;

// Deterministic public test seeds only. These fixtures are not application keys.
struct Tape(Xof);
impl Tape {
    fn new(seed: &[u8]) -> Self {
        Self(Xof::new(b"PRETZEL-U3-PUBLIC-VERIFY-TEST", &[seed]))
    }
}
impl EntropySource for Tape {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
        self.0.fill(out);
        Ok(())
    }
}

// Checks the transformed response columns of every packet whose head decodes.
fn check_columns(signature: &[u8]) {
    if signature.len() == crate::signature_codec::SIGNATURE_BYTES {
        let mut head = [0; 1024];
        if let Ok(decoded) = crate::signature_codec::decode_head_borrowed(
            &signature[32..32 + crate::signature_codec::HEAD_BYTES],
            &mut head,
        ) {
            crate::neon::public_response_ntt::check_decoded_columns(&decoded);
        }
    }
}

// A changed context, message or signature must be rejected.
fn rejects(pk: &PreparedPk, context: &[u8], message: &[u8], signature: &[u8]) {
    assert!(PreparedVerifier
        .verify(pk, context, message, signature)
        .is_err());
    check_columns(signature);
}

#[test]
fn public_verify_levers_valid_and_corrupted_signatures() {
    let ctx = Ctx::new();
    let pair = keygen_with_entropy(&ctx, &mut Tape::new(b"key")).unwrap();
    let sk = PreparedSk::new(&pair.sk).unwrap();
    let pk = PreparedPk::new(&pair.pk).unwrap();
    let mut scratch = SigningScratch::new();
    for (case, length) in [0, 32, 135, 136, 137, 1024, 4096].into_iter().enumerate() {
        let context = vec![0xa5; [0, 7, 136, 273][case % 4]];
        let message = vec![case as u8; length];
        let (signature, _) = super::super::prepared_signer::sign_prepared_using_scratch(
            &ctx,
            &sk,
            &context,
            &message,
            &mut Tape::new(&(case as u64).to_le_bytes()),
            &mut scratch,
        )
        .unwrap();
        PreparedVerifier
            .verify(&pk, &context, &message, &signature)
            .unwrap();
        check_columns(&signature);
        rejects(&pk, b"wrong context", &message, &signature);
        rejects(&pk, &context, b"wrong message", &signature);
        let mut bad = signature.clone();
        // Every bit, including salt, head, exceptions and hint padding.
        for bit in 0..signature.len() * 8 {
            bad[bit / 8] ^= 1 << (bit % 8);
            rejects(&pk, &context, &message, &bad);
            bad[bit / 8] ^= 1 << (bit % 8);
        }
        for len in 0..signature.len() {
            rejects(&pk, &context, &message, &signature[..len]);
        }
        bad.push(0);
        rejects(&pk, &context, &message, &bad);
        // Multi-fault packets are rejected; one byte short is a length error.
        for fill in [0, 0x55, 0xaa, 0xff] {
            bad = signature.clone();
            bad[32..].fill(fill);
            rejects(&pk, b"wrong context", b"wrong message", &bad);
            bad.pop();
            assert!(matches!(
                PreparedVerifier.verify(&pk, b"", b"", &bad),
                Err(Error::SignatureLength)
            ));
            rejects(&pk, b"", b"", &bad);
        }
    }
}

#[test]
fn public_row_body_malformed_keys_and_packets() {
    fn serialized(raw: &[u8], signature: &[u8]) {
        assert!(PreparedVerifier
            .verify_serialized_complete(raw, b"context", b"message", signature)
            .is_err());
    }
    let ctx = Ctx::new();
    let pair = keygen_with_entropy(&ctx, &mut Tape::new(b"row-body-key")).unwrap();
    let pk = PreparedPk::new(&pair.pk).unwrap();
    let mut tape = Tape::new(b"row-body-malformed");
    let mut signature = vec![0; crate::signature_codec::SIGNATURE_BYTES];
    for trial in 0..256 {
        tape.fill(&mut signature).unwrap();
        if trial < 4 {
            signature.fill([0, 0x55, 0xaa, 0xff][trial]);
        }
        rejects(&pk, b"context", b"message", &signature);
    }
    // Malformed public keys are rejected whatever the accompanying signature.
    for len in 0..pair.pk.len() {
        serialized(&pair.pk[..len], &signature);
    }
    let mut key = pair.pk.clone();
    key.push(0);
    serialized(&key, &signature);
    for byte in 0..pair.pk.len() {
        key = pair.pk.clone();
        key[byte] ^= 0x80;
        serialized(&key, &signature);
        serialized(&key, &[]);
    }
    for fill in [0, 0x55, 0xaa, 0xff] {
        key.fill(fill);
        serialized(&key[..pair.pk.len()], &signature);
    }
    for _ in 0..64 {
        tape.fill(&mut key[..pair.pk.len()]).unwrap();
        serialized(&key[..pair.pk.len()], &signature);
    }
}

#[test]
fn public_verify_cached_prefix_rate_boundaries() {
    struct BoundaryTape(Xof);
    impl BoundaryTape {
        fn new(seed: &[u8]) -> Self {
            Self(Xof::new(b"PUBLIC-VERIFY-BOUNDARY-TEST", &[seed]))
        }
    }
    impl EntropySource for BoundaryTape {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            self.0.fill(out);
            Ok(())
        }
    }
    let ctx = Ctx::new();
    let pair = keygen_with_entropy(&ctx, &mut BoundaryTape::new(b"key")).unwrap();
    let sk = PreparedSk::new(&pair.sk).unwrap();
    let mut scratch = SigningScratch::new();
    let prefix_len = 8 + PROFILE_ID.len() + 8 + CORE_PK_BYTES + DOM_MSG.len() + 32;
    for context_len in [0, 1, 135, 136] {
        let context = vec![0xa5; context_len];
        let next = 136 - (prefix_len + 16 + context_len) % 136;
        for length in [
            0,
            135,
            136,
            271,
            272,
            next - 1,
            next,
            next + 135,
            next + 136,
        ] {
            let message = vec![length as u8; length];
            let (signature, _) = super::super::prepared_signer::sign_prepared_using_scratch(
                &ctx,
                &sk,
                &context,
                &message,
                &mut BoundaryTape::new(&(length as u64).to_le_bytes()),
                &mut scratch,
            )
            .unwrap();
            assert_eq!(signature.len(), crate::signature_codec::SIGNATURE_BYTES);
            let pk = PreparedPk::new(&pair.pk).unwrap();
            // Check first verification and later reuse on this same key.
            for _ in 0..2 {
                PreparedVerifier
                    .verify(&pk, &context, &message, &signature)
                    .unwrap();
            }
            check_columns(&signature);
            rejects(&pk, b"different context", &message, &signature);
            rejects(&pk, &context, b"different message", &signature);
            for at in [0, 31, 32, 63, signature.len() / 2, signature.len() - 1] {
                for bit in 0..8 {
                    let mut changed = signature.clone();
                    changed[at] ^= 1 << bit;
                    rejects(&pk, &context, &message, &changed);
                }
            }
            rejects(&pk, &context, &message, &signature[..signature.len() - 1]);
            let mut longer = signature.clone();
            longer.push(0);
            rejects(&pk, &context, &message, &longer);
        }
    }
}

#[test]
fn public_verify_shared_key_first_use_across_threads() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<PreparedPk>();
    let ctx = Ctx::new();
    let pair = keygen_with_entropy(&ctx, &mut Tape::new(b"shared-verify-key")).unwrap();
    let sk = PreparedSk::new(&pair.sk).unwrap();
    let mut scratch = SigningScratch::new();
    let message = b"shared verification prefix";
    let (signature, _) = super::super::prepared_signer::sign_prepared_using_scratch(
        &ctx,
        &sk,
        b"",
        message,
        &mut Tape::new(b"shared-verify-signature"),
        &mut scratch,
    )
    .unwrap();
    let pk = PreparedPk::new(&pair.pk).unwrap();
    let expected = "Ok(())";
    let gate = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let pk = &pk;
                let signature = &signature;
                let gate = &gate;
                scope.spawn(move || {
                    gate.wait();
                    [
                        format!("{:?}", PreparedVerifier.verify(pk, b"", message, signature)),
                        format!("{:?}", PreparedVerifier.verify(pk, b"", message, signature)),
                    ]
                })
            })
            .collect();
        for handle in handles {
            for actual in handle.join().unwrap() {
                assert_eq!(actual, expected);
            }
        }
    });
}
