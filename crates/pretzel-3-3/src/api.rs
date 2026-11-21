//! Public entry points of Pretzel-(3,3) with 1160-byte signatures.
//!
//! Every function of this module forwards to the signer of `scheme::prepared_signer` or to the
//! verifier `scheme::verifier::PreparedVerifier`. The names, the order of arguments and the
//! error conventions are those of the Pretzel-(4,4) crate. Differences from that crate:
//! `Ctx`, `Keypair`, `PreparedPk`, `PreparedSk` and `SigningScratch` are the types of this crate
//! and not wrappers around them; there is no context confined to key generation; and signing
//! from serialized key bytes prepares the key and then signs with it, each step under its own
//! timing guard, where the Pretzel-(4,4) crate holds one guard around both steps.
//!
//! Keys and signatures cross this interface as byte slices and vectors. Serialized keys carry a
//! 14-byte format tag in front of the key body.
use crate::scheme::{prepared_signer, verifier::PreparedVerifier};
use crate::{Ctx, Error, PreparedPk, PreparedSk};

/// Length in bytes of a signature: a 32-byte salt, a 981-byte response and 147 bytes of hints.
pub const SIGNATURE_BYTES: usize = prepared_signer::SIGNATURE_BYTES;
/// Length in bytes of a serialized public key, the 14-byte format tag included.
pub const PUBLIC_KEY_BYTES: usize = crate::params::PUBLIC_KEY_WIRE_BYTES;
/// Length in bytes of a serialized secret key, the 14-byte format tag included.
pub const SECRET_KEY_BYTES: usize = crate::params::SECRET_KEY_WIRE_BYTES;
const _: () = {
    assert!(SIGNATURE_BYTES == 1160);
    assert!(PUBLIC_KEY_BYTES == 1326);
    assert!(SECRET_KEY_BYTES == 526);
};

/// Sign `message` with the serialized secret key `sk` and an empty application context.
///
/// `sk` is secret and must hold `SECRET_KEY_BYTES` bytes. Entropy comes from the operating
/// system. The prepared key built for this call is erased before the function returns.
/// Returns a signature of `SIGNATURE_BYTES` bytes. Fails with `Error::KeyFormat` on a malformed
/// key, `Error::RngFailure` when entropy is unavailable, `Error::TimingProtectionUnavailable`
/// when the processor's data-independent timing mode cannot be enabled, and `Error::SignFailed`
/// when no attempt is accepted within the attempt limit.
#[inline]
pub fn sign(ctx: &Ctx, sk: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    sign_with_context(ctx, sk, b"", message)
}

/// As `sign`, with an application context that is bound separately from the message.
#[inline]
pub fn sign_with_context(
    ctx: &Ctx,
    sk: &[u8],
    context: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    sign_prepared_with_context(ctx, &PreparedSk::new(sk)?, context, message)
}

/// As `sign`, and also returns the number of signing attempts used (1 when the first attempt
/// is accepted). The count is public.
#[inline]
pub fn sign_with_stats(ctx: &Ctx, sk: &[u8], message: &[u8]) -> Result<(Vec<u8>, u32), Error> {
    sign_prepared_with_stats(ctx, &PreparedSk::new(sk)?, message)
}

/// Sign `message` with a prepared secret key and an empty application context.
///
/// Entropy comes from the operating system. Working memory is erased after every attempt; only
/// erased capacity is kept per thread between calls. Returns a signature of `SIGNATURE_BYTES`
/// bytes. Fails with `Error::RngFailure`, `Error::TimingProtectionUnavailable` or
/// `Error::SignFailed` as `sign` does.
#[inline]
pub fn sign_prepared(ctx: &Ctx, sk: &PreparedSk, message: &[u8]) -> Result<Vec<u8>, Error> {
    sign_prepared_with_context(ctx, sk, b"", message)
}

/// As `sign_prepared`, with an application context that is bound separately from the message.
#[inline]
pub fn sign_prepared_with_context(
    ctx: &Ctx,
    sk: &PreparedSk,
    context: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    sign_prepared_with_context_and_stats(ctx, sk, context, message).map(|(signature, _)| signature)
}

/// As `sign_prepared`, and also returns the number of signing attempts used.
#[inline]
pub fn sign_prepared_with_stats(
    ctx: &Ctx,
    sk: &PreparedSk,
    message: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    sign_prepared_with_context_and_stats(ctx, sk, b"", message)
}

/// As `sign_prepared_with_context`, and also returns the number of signing attempts used.
#[inline]
pub fn sign_prepared_with_context_and_stats(
    ctx: &Ctx,
    sk: &PreparedSk,
    context: &[u8],
    message: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    prepared_signer::sign_prepared_with_context_and_stats(ctx, sk, context, message)
}

/// Sign with a prepared secret key and a workspace owned by the caller. The arguments are the
/// context, the prepared key, the workspace, the application context and the message.
///
/// The workspace is erased after every attempt, on failure and on unwinding, and nothing is
/// kept between calls except its erased capacity. Returns the signature (`SIGNATURE_BYTES`
/// bytes) and the number of attempts used. Fails as `sign_prepared` does.
pub use prepared_signer::sign_prepared_with_scratch;

/// Verify `signature` on `message` under the serialized public key `pk`, with an empty
/// application context.
///
/// All inputs are public. Returns `Ok(())` only for a valid signature. Fails with
/// `Error::KeyFormat` on a malformed key, `Error::SignatureLength` when the signature does not
/// hold `SIGNATURE_BYTES` bytes, `Error::Decode` on a non-canonical encoding,
/// `Error::CapExceeded` when a norm bound is exceeded and `Error::ChallengeMismatch` otherwise.
#[inline]
pub fn verify(ctx: &Ctx, pk: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    verify_with_context(ctx, pk, b"", message, signature)
}

/// As `verify`, with an application context that is bound separately from the message.
#[inline]
pub fn verify_with_context(
    ctx: &Ctx,
    pk: &[u8],
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    PreparedVerifier::new(ctx)?.verify_serialized_complete(pk, context, message, signature)
}

/// Verify `signature` on `message` under a prepared public key, with an empty application
/// context. Fails as `verify` does, except that the key was already checked.
#[inline]
pub fn verify_prepared(
    ctx: &Ctx,
    pk: &PreparedPk,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    verify_prepared_with_context(ctx, pk, b"", message, signature)
}

/// As `verify_prepared`, with an application context that is bound separately from the message.
#[inline]
pub fn verify_prepared_with_context(
    ctx: &Ctx,
    pk: &PreparedPk,
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    PreparedVerifier::new(ctx)?.verify(pk, context, message, signature)
}
