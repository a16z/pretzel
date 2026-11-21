//! The prepared public representation preserves signing and verification.
use super::*;

struct Tape(Xof);
impl Tape {
    fn new(seed: u64) -> Self {
        Self(Xof::new(
            b"public preparation identity",
            &[&seed.to_le_bytes()],
        ))
    }
}
impl EntropySource for Tape {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
        self.0.fill(out);
        Ok(())
    }
}

#[test]
fn prepared_public_storage_preserves_signatures_and_verification() {
    let ctx = Ctx::new();
    let expected_size = match M {
        3 => 1160,
        4 => 1361,
        5 => 1908,
        _ => unreachable!(),
    };
    assert_eq!(crate::rice_codec::SIGNATURE_BYTES, expected_size);
    for seed in 0..2 {
        let pair = keygen_with_entropy(&ctx, &mut Tape::new(seed)).unwrap();
        let mut sk = PreparedSk::new(&pair.sk).unwrap();
        let actual = PreparedPk::new(&pair.pk).unwrap();
        sk.ppk = super::prepk_direct_tests::previous(&pair.pk).unwrap();
        let reference = super::prepk_direct_tests::previous(&pair.pk).unwrap();
        super::prepk_direct_tests::assert_same(&actual, &reference);
        super::prepk_direct_tests::assert_same(&sk.ppk, &reference);
        let mut scratch = SigningScratch::new();
        let message = [seed as u8; 137];
        let context = b"public preparation";
        let before = sign_for_preparation_test(
            &ctx,
            &sk,
            context,
            &message,
            &mut Tape::new(seed + 17),
            &mut scratch,
        )
        .unwrap();
        sk.ppk = PreparedPk::new(&pair.pk).unwrap();
        super::prepk_direct_tests::assert_same(&sk.ppk, &reference);
        let after = sign_for_preparation_test(
            &ctx,
            &sk,
            context,
            &message,
            &mut Tape::new(seed + 17),
            &mut scratch,
        )
        .unwrap();
        // Ranks three and four replay the same tape. Pretzel-(5,5) uses OS entropy.
        if M != 5 {
            assert_eq!(before, after);
        }
        let verifier = rice_verify::PreparedRice;
        for (signature, attempts) in [before, after] {
            assert_eq!(signature.len(), expected_size);
            assert!(attempts > 0);
            verifier
                .verify(&actual, context, &message, &signature)
                .unwrap();
            verifier
                .verify(&reference, context, &message, &signature)
                .unwrap();
            let mut bad = signature;
            for index in [0, 31, 32, expected_size / 2, expected_size - 1] {
                bad[index] ^= 0x80;
                assert_eq!(
                    verifier.verify(&actual, context, &message, &bad),
                    verifier.verify(&reference, context, &message, &bad)
                );
                assert!(verifier.verify(&actual, context, &message, &bad).is_err());
                bad[index] ^= 0x80;
            }
            for length in [0, 31, expected_size - 1] {
                assert_eq!(
                    verifier.verify(&actual, context, &message, &bad[..length]),
                    verifier.verify(&reference, context, &message, &bad[..length])
                );
                assert!(verifier
                    .verify(&actual, context, &message, &bad[..length])
                    .is_err());
            }
            assert_eq!(
                verifier.verify(&actual, b"other context", &message, &bad),
                verifier.verify(&reference, b"other context", &message, &bad)
            );
            assert!(verifier
                .verify(&actual, b"other context", &message, &bad)
                .is_err());
        }
        assert_eq!(sk.public_key(), pair.pk.as_slice());
    }
}
