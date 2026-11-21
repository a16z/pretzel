//! Fixed public vectors, stored in `signature_vectors.bin`: four public keys, then 128
//! (attempt count, signature, entropy continuation) rows.
use super::*;
#[test]
fn fixed_signature_vectors_and_entropy_history() {
    const FIXTURE: &[u8] = include_bytes!("signature_vectors.bin");
    const ROW: usize = 4 + 1908 + 64;
    assert_eq!(FIXTURE.len(), 4 * 2158 + 128 * ROW);
    let ctx = Ctx::new();
    let verifier = super::super::super::verifier::PreparedVerifier::new(&ctx).unwrap();
    let mut scratch = SigningScratch::new();
    for key_index in 0..4u64 {
        let key_bytes = key_index.to_le_bytes();
        let mut entropy = Tape {
            x: Xof::new(
                b"PRETZEL-RL5-SPEED-CONFORMANCE-KEY-v1",
                &[&key_bytes, &0u64.to_le_bytes()],
            ),
            sizes: vec![],
        };
        let pair = keygen_with_entropy(&ctx, &mut entropy).unwrap();
        assert_eq!(
            pair.pk.as_slice(),
            &FIXTURE[key_index as usize * 2158..(key_index as usize + 1) * 2158]
        );
        let key = PreparedSk::new(&pair.sk).unwrap();
        for case in 0..32u64 {
            let case_bytes = case.to_le_bytes();
            let context = match case % 3 {
                0 => vec![],
                1 => b"speed-conformance".to_vec(),
                _ => vec![0, 255, key_index as u8, case as u8],
            };
            let mut message = vec![0; [0, 32, 4096][(case as usize / 3) % 3]];
            Xof::new(
                b"PRETZEL-RL5-SPEED-CONFORMANCE-MESSAGE-v1",
                &[&key_bytes, &case_bytes],
            )
            .fill(&mut message);
            let mut tape = Tape {
                x: Xof::new(
                    b"PRETZEL-RL5-SPEED-CONFORMANCE-SIGN-v1",
                    &[&key_bytes, &case_bytes],
                ),
                sizes: vec![],
            };
            let offset = 4 * 2158 + (key_index as usize * 32 + case as usize) * ROW;
            let expected = &FIXTURE[offset..offset + ROW];
            let attempts = u32::from_le_bytes(expected[..4].try_into().unwrap());
            let result =
                sign_prepared_using(&ctx, &key, &mut scratch, &context, &message, &mut tape)
                    .unwrap();
            assert_eq!(result.1, attempts);
            assert_eq!(result.0.as_slice(), &expected[4..4 + 1908]);
            assert_eq!(tape.sizes, vec![64; attempts as usize]);
            let mut tail = [0; 64];
            tape.x.fill(&mut tail);
            assert_eq!(tail.as_slice(), &expected[4 + 1908..]);
            assert!(scratch.is_erased());
            verifier
                .verify_reference(&key.ppk, &context, &message, &result.0)
                .unwrap();
        }
    }
}
