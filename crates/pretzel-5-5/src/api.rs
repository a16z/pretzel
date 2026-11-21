//! Public entry points of Pretzel-(5,5) with 1908-byte signatures.
//!
//! Every function of this module forwards to the signer of `scheme::prepared_signer` or to the
//! verifier `scheme::verifier::PreparedVerifier`. The names, the order of arguments and the
//! error conventions are those of the Pretzel-(4,4) crate. Differences from that crate:
//! `Ctx`, `Keypair`, `PreparedPk`, `PreparedSk` and `SigningScratch` are the types of this crate
//! and not wrappers around them; there is no context confined to key generation; signing with a
//! prepared key and no workspace allocates a workspace for the call; and verification from
//! serialized key bytes checks the length of the signature before it reads the key.
//!
//! Keys and signatures cross this interface as byte slices and vectors. Serialized keys carry a
//! 14-byte format tag in front of the key body.
use crate::scheme::{prepared_signer, verifier::PreparedVerifier};
use crate::{Ctx, Error, PreparedPk, PreparedSk, SigningScratch};

/// Length in bytes of a signature: a 32-byte salt and a 1876-byte response.
pub const SIGNATURE_BYTES: usize = prepared_signer::SIGNATURE_BYTES;
/// Length in bytes of a serialized public key, the 14-byte format tag included.
pub const PUBLIC_KEY_BYTES: usize = crate::params::PUBLIC_KEY_WIRE_BYTES;
/// Length in bytes of a serialized secret key, the 14-byte format tag included.
pub const SECRET_KEY_BYTES: usize = crate::params::SECRET_KEY_WIRE_BYTES;
const _: () = {
    assert!(SIGNATURE_BYTES == 1908);
    assert!(SIGNATURE_BYTES == crate::params::SIG_BYTES);
    assert!(PUBLIC_KEY_BYTES == 2158);
    assert!(SECRET_KEY_BYTES == 782);
};

/// Sign `msg` with the serialized secret key `sk` and an empty application context.
///
/// `sk` is secret and must hold `SECRET_KEY_BYTES` bytes. Entropy comes from the operating
/// system. The prepared key and the workspace built for this call are erased before the
/// function returns. Returns a signature of `SIGNATURE_BYTES` bytes. Fails with
/// `Error::KeyFormat` on a malformed key, `Error::RngFailure` when entropy is unavailable,
/// `Error::TimingProtectionUnavailable` when the processor's data-independent timing mode
/// cannot be enabled, and `Error::SignFailed` when no attempt is accepted within the attempt
/// limit.
pub fn sign(ctx: &Ctx, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    sign_with_context(ctx, sk, b"", msg)
}

/// As `sign`, and also returns the number of signing attempts used (1 when the first attempt
/// is accepted). The count is public.
pub fn sign_with_stats(ctx: &Ctx, sk: &[u8], msg: &[u8]) -> Result<(Vec<u8>, u32), Error> {
    prepared_signer::sign_with_context_and_stats(ctx, sk, b"", msg)
}

/// As `sign`, with an application context that is bound separately from the message.
pub fn sign_with_context(
    ctx: &Ctx,
    sk: &[u8],
    context: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    prepared_signer::sign_with_context_and_stats(ctx, sk, context, msg).map(|(sig, _)| sig)
}

/// Sign `msg` with a prepared secret key and an empty application context.
///
/// Entropy comes from the operating system. The workspace allocated for this call is erased
/// after every attempt and when the call ends. Returns a signature of `SIGNATURE_BYTES` bytes.
/// Fails with `Error::RngFailure`, `Error::TimingProtectionUnavailable` or `Error::SignFailed`
/// as `sign` does.
#[inline]
pub fn sign_prepared(ctx: &Ctx, sk: &PreparedSk, msg: &[u8]) -> Result<Vec<u8>, Error> {
    sign_prepared_with_context(ctx, sk, b"", msg)
}

/// As `sign_prepared`, and also returns the number of signing attempts used.
pub fn sign_prepared_with_stats(
    ctx: &Ctx,
    sk: &PreparedSk,
    msg: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    sign_prepared_with_scratch(ctx, sk, &mut SigningScratch::new(), b"", msg)
}

/// As `sign_prepared`, with an application context that is bound separately from the message.
pub fn sign_prepared_with_context(
    ctx: &Ctx,
    sk: &PreparedSk,
    context: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    sign_prepared_with_scratch(ctx, sk, &mut SigningScratch::new(), context, msg)
        .map(|(sig, _)| sig)
}

/// As `sign_prepared_with_context`, and also returns the number of signing attempts used.
#[inline]
pub fn sign_prepared_with_context_and_stats(
    ctx: &Ctx,
    sk: &PreparedSk,
    context: &[u8],
    msg: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    sign_prepared_with_scratch(ctx, sk, &mut SigningScratch::new(), context, msg)
}

/// Sign with a prepared secret key and a workspace owned by the caller. The arguments are the
/// context, the prepared key, the workspace, the application context and the message.
///
/// The workspace is erased after every attempt, on failure and on unwinding, and nothing is
/// kept between calls except its erased capacity. Returns the signature (`SIGNATURE_BYTES`
/// bytes) and the number of attempts used. Fails as `sign_prepared` does.
pub use prepared_signer::sign_prepared_with_scratch;

/// Verify `sig` on `msg` under the serialized public key `pk`, with an empty application
/// context.
///
/// All inputs are public. Returns `Ok(())` only for a valid signature. Fails with
/// `Error::SignatureLength` when the signature does not hold `SIGNATURE_BYTES` bytes,
/// `Error::KeyFormat` on a malformed key, `Error::Decode` on a non-canonical encoding,
/// `Error::CapExceeded` when a norm bound is exceeded and `Error::ChallengeMismatch` otherwise.
pub fn verify(ctx: &Ctx, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    verify_with_context(ctx, pk, b"", msg, sig)
}

/// As `verify`, with an application context that is bound separately from the message.
pub fn verify_with_context(
    ctx: &Ctx,
    pk: &[u8],
    context: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    if sig.len() != crate::params::SIG_BYTES {
        return Err(Error::SignatureLength);
    }
    verify_prepared_with_context(ctx, &PreparedPk::new(pk)?, context, msg, sig)
}

/// Verify `sig` on `msg` under a prepared public key, with an empty application context.
/// Fails as `verify` does, except that the key was already checked.
pub fn verify_prepared(ctx: &Ctx, pk: &PreparedPk, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    verify_prepared_with_context(ctx, pk, b"", msg, sig)
}

/// As `verify_prepared`, with an application context that is bound separately from the message.
pub fn verify_prepared_with_context(
    ctx: &Ctx,
    pk: &PreparedPk,
    context: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    PreparedVerifier::new(ctx)?.verify(pk, context, msg, sig)
}

#[cfg(test)]
mod tests {
    #[test]
    fn root_sign_and_verify_use_the_selected_wire() {
        let ctx = crate::Ctx::new();
        let pair = crate::keygen(&ctx).unwrap();
        let message = b"root API round trip";
        let sig = crate::sign(&ctx, &pair.sk, message).unwrap();
        assert_eq!(sig.len(), 1908);
        assert_eq!(crate::params::SIG_BYTES, sig.len());
        assert_eq!(crate::params::RESP_FIELD_BYTES, 1876);
        assert_eq!(crate::params::HINT_FIELD_BYTES, 0);
        crate::verify(&ctx, &pair.pk, message, &sig).unwrap();
        assert!(crate::verify(&ctx, &pair.pk, b"changed", &sig).is_err());
        assert_eq!(
            crate::verify(&ctx, &pair.pk, message, &sig[..1319]),
            Err(crate::Error::SignatureLength)
        );
        let context = b"application";
        let sig = crate::sign_with_context(&ctx, &pair.sk, context, message).unwrap();
        crate::verify_with_context(&ctx, &pair.pk, context, message, &sig).unwrap();
        assert!(crate::verify(&ctx, &pair.pk, message, &sig).is_err());
        let sk = crate::PreparedSk::new(&pair.sk).unwrap();
        let pk = crate::PreparedPk::new(&pair.pk).unwrap();
        let (sig, attempts) = crate::sign_prepared_with_stats(&ctx, &sk, message).unwrap();
        assert!(attempts > 0);
        crate::verify_prepared(&ctx, &pk, message, &sig).unwrap();
        let sig = crate::sign_prepared_with_context(&ctx, &sk, context, message).unwrap();
        crate::verify_prepared_with_context(&ctx, &pk, context, message, &sig).unwrap();
    }

    #[test]
    fn root_verify_accepts_the_existing_golden_signature() {
        // The first row of the vectors has empty context and empty message.
        const SIGNATURE_VECTORS: &[u8] = include_bytes!("signature_vectors.bin");
        let pk = &SIGNATURE_VECTORS[..2158];
        let offset = 4 * 2158 + 4;
        let sig = &SIGNATURE_VECTORS[offset..offset + 1908];
        crate::verify(&crate::Ctx::new(), pk, b"", sig).unwrap();
    }
}
