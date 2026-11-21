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

// A changed context, message or signature must be rejected.
fn rejects(pk: &PreparedPk, context: &[u8], message: &[u8], signature: &[u8]) {
    assert!(PreparedRice
        .verify(pk, context, message, signature)
        .is_err());
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
        let (signature, _) = super::super::prepared_signer::sign_rice_prepared_using_scratch(
            &ctx,
            &sk,
            &context,
            &message,
            &mut Tape::new(&(case as u64).to_le_bytes()),
            &mut scratch,
        )
        .unwrap();
        PreparedRice
            .verify(&pk, &context, &message, &signature)
            .unwrap();
        #[cfg(target_arch = "aarch64")]
        {
            let mut head = [0; 1280];
            let decoded = crate::rice_codec::decode_head_borrowed(
                &signature[32..32 + crate::rice_codec::HEAD_BYTES],
                &mut head,
            )
            .unwrap();
            crate::neon::public_response_ntt::check_decoded_columns(&decoded);
        }
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
        // Corrupt several distant head/hint regions and the challenge together.
        for offset in [32, 63, 64, 127, 128, 255, 256, signature.len() - 1] {
            let mut faults = signature.clone();
            faults[0] ^= 0x80;
            faults[offset] ^= 0x55;
            faults[signature.len() - 2] ^= 0xaa;
            rejects(&pk, b"wrong context", b"wrong message", &faults);
        }
        bad.push(0);
        rejects(&pk, &context, &message, &bad);
        // Multi-fault packets pin decode/cap errors ahead of challenge errors.
        for fill in [0, 0x55, 0xaa, 0xff] {
            bad = signature.clone();
            bad[32..].fill(fill);
            rejects(&pk, b"wrong context", b"wrong message", &bad);
            bad.pop();
            assert!(matches!(
                PreparedRice.verify(&pk, b"", b"", &bad),
                Err(Error::SignatureLength)
            ));
            rejects(&pk, b"", b"", &bad);
        }
    }
}
