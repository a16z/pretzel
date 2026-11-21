//! Complete public preparation against the reference sampler, for both levels.
use super::*;

#[test]
fn prepared_keys_match_scalar_sampler_for_32_keys() {
    for case in 0..32u8 {
        let coefficients: Vec<i32> = (0..M * N)
            .map(|i| ((i * 31 + case as usize * 127) % Q as usize) as i32)
            .collect();
        let mut body = Vec::with_capacity(PK_BYTES);
        body.extend((0..32).map(|i| case.wrapping_mul(37).wrapping_add(i)));
        body.extend_from_slice(&encode::encode_b(&coefficients));
        body.extend_from_slice(&[case.wrapping_add(5); 32]);
        assert_eq!(body.len(), PK_BYTES);
        let wire = crate::direct_ntt_profile::tag_public(&body);
        let actual = PreparedPk::new(&wire).unwrap();
        let expected = crate::direct_ntt_profile::matrix13::with_scalar_oracle(|| {
            PreparedPk::new(&wire).unwrap()
        });
        assert_eq!(actual.mat.rows, expected.mat.rows);
        assert_eq!(actual.static_delta, expected.static_delta);
        for length in [0, 1, 135, 136, 137, 273] {
            let context = b"sampler comparison";
            let message = vec![case; length];
            let mu = actual.message_rep(context, &message);
            assert_eq!(mu, expected.message_rep(context, &message));
            assert_eq!(
                actual.challenge_bytes(&mu, &[case; SALT_BYTES], &message),
                expected.challenge_bytes(&mu, &[case; SALT_BYTES], &message)
            );
        }
        for length in [0, 13, wire.len() - 1, wire.len() + 1] {
            let mut bad = wire.clone();
            bad.resize(length, 0);
            let actual = PreparedPk::new(&bad).err();
            let expected = crate::direct_ntt_profile::matrix13::with_scalar_oracle(|| {
                PreparedPk::new(&bad).err()
            });
            assert!(matches!(actual, Some(Error::KeyFormat)));
            assert!(matches!(expected, Some(Error::KeyFormat)));
        }
        // Invalid coefficient at each end and in the middle of the public row.
        for index in [0, M * N / 2, M * N - 1] {
            let mut bad = body.clone();
            for bit in 0..13 {
                let k = 13 * index + bit;
                bad[32 + k / 8] |= 1 << (k % 8);
            }
            let bad = crate::direct_ntt_profile::tag_public(&bad);
            assert!(matches!(PreparedPk::new(&bad), Err(Error::KeyFormat)));
            crate::direct_ntt_profile::matrix13::with_scalar_oracle(|| {
                assert!(matches!(PreparedPk::new(&bad), Err(Error::KeyFormat)));
            });
        }
    }
}

struct Tape(Xof);
impl Tape {
    fn new(case: u64) -> Self {
        Self(Xof::new(b"matrix-sampler-keygen", &[&case.to_le_bytes()]))
    }
}
impl EntropySource for Tape {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
        self.0.fill(out);
        Ok(())
    }
}

#[test]
fn keygen_and_secret_import_match_old_sampler_for_32_seeds() {
    let ctx = Ctx::new();
    for case in 0..32u64 {
        let actual = keygen_with_entropy(&ctx, &mut Tape::new(case)).unwrap();
        let expected = crate::direct_ntt_profile::matrix13::with_scalar_oracle(|| {
            keygen_with_entropy(&ctx, &mut Tape::new(case)).unwrap()
        });
        assert_eq!(actual.pk, expected.pk, "public key for seed {case}");
        assert_eq!(
            &actual.sk[..],
            &expected.sk[..],
            "secret key for seed {case}"
        );

        let prepared = PreparedSk::new(&actual.sk).unwrap();
        let reference = crate::direct_ntt_profile::matrix13::with_scalar_oracle(|| {
            PreparedSk::new(&actual.sk).unwrap()
        });
        assert_eq!(prepared.public_key(), actual.pk.as_slice());
        assert_eq!(prepared.public_key(), reference.public_key());
        assert_eq!(prepared.ppk.mat.rows, reference.ppk.mat.rows);
        assert_eq!(prepared.ppk.static_delta, reference.ppk.static_delta);
        assert_eq!(prepared.secret.key.pk, reference.secret.key.pk);
        assert_eq!(prepared.secret.key.prf, reference.secret.key.prf);
        let seed = crate::direct_ntt_profile::public_body(&actual.pk).unwrap()[..32]
            .try_into()
            .unwrap();
        let mut matrix = [[crate::compact_ring::CompactPoly::ZERO; ELL + 1]; M];
        crate::direct_ntt_profile::matrix13::scalar(seed, &mut matrix);
        for (row, expected_row) in prepared.ppk.mat.rows.iter().zip(&matrix) {
            assert_eq!(&row[1..], &expected_row[1..]);
        }
        let message = case.to_le_bytes();
        let mu = prepared.ppk.message_rep(b"sampler import", &message);
        assert_eq!(mu, reference.ppk.message_rep(b"sampler import", &message));
        assert_eq!(
            prepared
                .ppk
                .challenge_bytes(&mu, &[case as u8; SALT_BYTES], &message),
            reference
                .ppk
                .challenge_bytes(&mu, &[case as u8; SALT_BYTES], &message),
        );
    }
}
