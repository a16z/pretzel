//! Optional fixed-profile representation. Tagged endpoints stay strict.
//! This type is not an algorithm discriminator for an untyped protocol.
use super::{Error, PreparedPk};
pub const PUBLIC_KEY_BYTES: usize = 1312;
const _: () = assert!(
    crate::params::M == 3 && crate::params::ELL == 3 && crate::params::PK_BYTES == PUBLIC_KEY_BYTES
);
/// A validated Pretzel-(3,3) public-key body with its prepared key.
/// Serialization omits only the constant external tag; all internal domains are kept.
pub struct TypedPublicKey {
    bytes: [u8; PUBLIC_KEY_BYTES],
    prepared: PreparedPk,
}
impl TypedPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; PUBLIC_KEY_BYTES] = bytes.try_into().map_err(|_| Error::KeyFormat)?;
        let tagged = crate::direct_ntt_profile::tag_public(&bytes);
        let prepared = PreparedPk::new(&tagged)?;
        Ok(Self { bytes, prepared })
    }
    pub fn from_tagged_bytes(tagged: &[u8]) -> Result<Self, Error> {
        Self::from_bytes(crate::direct_ntt_profile::public_body(tagged)?)
    }
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.bytes
    }
    pub fn to_tagged_bytes(&self) -> Vec<u8> {
        crate::direct_ntt_profile::tag_public(&self.bytes)
    }
    pub fn as_prepared(&self) -> &PreparedPk {
        &self.prepared
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::*;
    struct Tape(crate::hashes::Xof);
    impl Tape {
        fn new(s: &[u8]) -> Self {
            Self(crate::hashes::Xof::new(b"PRETZEL33-TYPED-KEY-TEST", &[s]))
        }
    }
    impl crate::entropy::EntropySource for Tape {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            self.0.fill(out);
            Ok(())
        }
    }
    #[test]
    fn exact_lengths_tags_and_canonical_coefficients() {
        for n in [0, 14, 1280, 1311, 1313, 1326] {
            assert!(matches!(
                TypedPublicKey::from_bytes(&vec![0; n]),
                Err(Error::KeyFormat)
            ));
        }
        let kp = keygen_with_entropy(&Ctx::new(), &mut Tape::new(b"key")).unwrap();
        let body = crate::direct_ntt_profile::public_body(&kp.pk).unwrap();
        let typed = TypedPublicKey::from_bytes(body).unwrap();
        assert_eq!(typed.to_tagged_bytes(), kp.pk);
        assert!(PreparedPk::new(body).is_err()); // The tagged API stays strict.
        for i in 0..14 {
            let mut bad = kp.pk.clone();
            bad[i] ^= 1;
            assert!(TypedPublicKey::from_tagged_bytes(&bad).is_err());
        }
        for coefficient in 0..crate::params::M * crate::params::N {
            for value in [crate::params::Q as u16, 8191] {
                let mut bad = body.to_vec();
                for bit in 0..13 {
                    let p = 13 * coefficient + bit;
                    bad[32 + p / 8] = (bad[32 + p / 8] & !(1 << (p % 8)))
                        | ((((value >> bit) & 1) as u8) << (p % 8));
                }
                crate::direct_ntt_profile::without_expansion(|| {
                    assert!(matches!(
                        TypedPublicKey::from_bytes(&bad),
                        Err(Error::KeyFormat)
                    ));
                    assert!(matches!(
                        PreparedPk::new(&crate::direct_ntt_profile::tag_public(&bad)),
                        Err(Error::KeyFormat)
                    ));
                });
            }
        }
    }
    #[test]
    fn prepared_transcripts_and_verification_are_identical() {
        let ctx = Ctx::new();
        let kp = keygen_with_entropy(&ctx, &mut Tape::new(b"equivalence")).unwrap();
        let typed = TypedPublicKey::from_tagged_bytes(&kp.pk).unwrap();
        let old = PreparedPk::new(&kp.pk).unwrap();
        let sk = PreparedSk::new(&kp.sk).unwrap();
        let verifier = verifier::PreparedVerifier::new(&ctx).unwrap();
        assert_eq!(old.static_dither(), typed.as_prepared().static_dither());
        let mut scratch = SigningScratch::new();
        for n in [0usize, 32, 116, 117, 272] {
            let msg = vec![17; n];
            let context = b"typed context";
            let mu = old.message_rep(context, &msg);
            assert_eq!(mu, typed.as_prepared().message_rep(context, &msg));
            let labels = [0u8; crate::params::M * crate::params::N];
            let rho = [7; 32];
            assert_eq!(
                old.challenge_bytes(&mu, &rho, &labels),
                typed.as_prepared().challenge_bytes(&mu, &rho, &labels)
            );
            let (sig, _) = prepared_signer::sign_prepared_using_scratch(
                &ctx,
                &sk,
                context,
                &msg,
                &mut Tape::new(&n.to_le_bytes()),
                &mut scratch,
            )
            .unwrap();
            assert_eq!(verifier.verify(&old, context, &msg, &sig), Ok(()));
            {
                assert_eq!(sig.len(), crate::signature_codec::SIGNATURE_BYTES);
                assert_eq!(
                    verifier.verify_serialized_complete(
                        &typed.to_tagged_bytes(),
                        context,
                        &msg,
                        &sig
                    ),
                    Ok(())
                );
                assert_eq!(
                    verifier.verify_reference(typed.as_prepared(), context, &msg, &sig),
                    Ok(())
                );
                assert!(verifier
                    .verify(typed.as_prepared(), b"wrong context", &msg, &sig)
                    .is_err());
                assert!(verifier
                    .verify(typed.as_prepared(), context, b"different message", &sig)
                    .is_err());
            }
            for packet in [&sig[..], &sig[..sig.len() - 1]] {
                assert_eq!(
                    verifier.verify(&old, context, &msg, packet),
                    verifier.verify(typed.as_prepared(), context, &msg, packet)
                );
            }
            assert!(scratch.is_erased());
        }
    }
    #[test]
    fn finite_expansion_failure_is_preserved() {
        let kp = keygen_with_entropy(&Ctx::new(), &mut Tape::new(b"exhaustion")).unwrap();
        let body = crate::direct_ntt_profile::public_body(&kp.pk).unwrap();
        let (a, _, ab) = crate::shake2::common_prefix::completion_test::exhausted(|| {
            PreparedPk::new(&kp.pk).map(|_| ())
        });
        let (b, _, bb) = crate::shake2::common_prefix::completion_test::exhausted(|| {
            TypedPublicKey::from_bytes(body).map(|_| ())
        });
        assert_eq!(a, Err(Error::KeyFormat));
        assert_eq!(a, b);
        assert_eq!(ab, bb);
    }
}
