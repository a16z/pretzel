use native::scheme::{prepared_signer, rice_verify::PreparedRice};
use pretzel_4_4_core as native;

pub use native::{EntropyError, EntropySource, Error, OsEntropy, SecretKey};

/// Sizes of the wire format, including the key envelope.
pub mod params {
    pub const SIG_BYTES: usize = super::prepared_signer::RICE_SIGNATURE_BYTES;
    pub const PK_BYTES: usize = super::native::params::PK_BYTES + 14;
    pub const SK_BYTES: usize = super::native::params::SK_BYTES + 14;
}
pub const SIGNATURE_BYTES: usize = params::SIG_BYTES;
pub const PUBLIC_KEY_BYTES: usize = params::PK_BYTES;
pub const SECRET_KEY_BYTES: usize = params::SK_BYTES;
const _: () = {
    assert!(SIGNATURE_BYTES == 1361);
    assert!(PUBLIC_KEY_BYTES == 1742);
    assert!(SECRET_KEY_BYTES == 654);
};

/// Precomputed public tables shared by key generation, signing and verification.
pub struct Ctx(native::Ctx);
impl Ctx {
    pub fn new() -> Self {
        Self(native::Ctx::new())
    }
}
impl Default for Ctx {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialized public key and an owned, erased-on-drop secret key.
pub struct Keypair {
    pub pk: Vec<u8>,
    pub sk: SecretKey,
}

/// A validated public key, prepared for verification.
pub struct PreparedPk(native::PreparedPk);
impl PreparedPk {
    pub fn new(raw: &[u8]) -> Result<Self, Error> {
        native::PreparedPk::new(raw).map(Self)
    }
}

/// A validated secret key and its per-key precomputation.
pub struct PreparedSk(native::PreparedSk);
impl PreparedSk {
    /// Secret state is allocated under DIT. Returning or moving this owner
    /// copies only a heap pointer and public fields.
    pub fn new(raw: &[u8]) -> Result<Self, Error> {
        native::PreparedSk::new(raw).map(Self)
    }
    pub fn public_key(&self) -> &[u8] {
        self.0.public_key()
    }
}

/// Signing workspace owned by the caller and borrowed exclusively by each signing call.
pub struct SigningScratch(native::SigningScratch);
impl SigningScratch {
    pub fn new() -> Self {
        Self(native::SigningScratch::new())
    }
}
impl Default for SigningScratch {
    fn default() -> Self {
        Self::new()
    }
}

pub fn keygen(ctx: &Ctx) -> Result<Keypair, Error> {
    keygen_with_entropy(ctx, &mut OsEntropy)
}

/// The entropy source must satisfy the `EntropySource` contract.
pub fn keygen_with_entropy(ctx: &Ctx, entropy: &mut impl EntropySource) -> Result<Keypair, Error> {
    native::keygen_with_entropy(&ctx.0, entropy).map(|pair| Keypair {
        pk: pair.pk,
        sk: pair.sk,
    })
}

pub fn sign(ctx: &Ctx, sk: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    sign_with_context(ctx, sk, b"", message)
}

pub fn sign_with_context(
    ctx: &Ctx,
    sk: &[u8],
    context: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    prepared_signer::sign_with_context_and_stats(&ctx.0, sk, context, message)
        .map(|(signature, _)| signature)
}

/// Return the signature and the number of complete signing attempts.
pub fn sign_with_stats(ctx: &Ctx, sk: &[u8], message: &[u8]) -> Result<(Vec<u8>, u32), Error> {
    prepared_signer::sign_with_context_and_stats(&ctx.0, sk, b"", message)
}

pub fn sign_prepared(ctx: &Ctx, sk: &PreparedSk, message: &[u8]) -> Result<Vec<u8>, Error> {
    sign_prepared_with_context(ctx, sk, b"", message)
}

pub fn sign_prepared_with_context(
    ctx: &Ctx,
    sk: &PreparedSk,
    context: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    sign_prepared_with_context_and_stats(ctx, sk, context, message).map(|(signature, _)| signature)
}

pub fn sign_prepared_with_stats(
    ctx: &Ctx,
    sk: &PreparedSk,
    message: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    sign_prepared_with_context_and_stats(ctx, sk, b"", message)
}

pub fn sign_prepared_with_context_and_stats(
    ctx: &Ctx,
    sk: &PreparedSk,
    context: &[u8],
    message: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    // No fallible post-encoding step: the release boundary of the core signer
    // applies, including its entropy, retry count and erased-scratch cache.
    prepared_signer::sign_prepared_with_context_and_stats(&ctx.0, &sk.0, context, message)
}

pub fn sign_prepared_with_scratch(
    ctx: &Ctx,
    sk: &PreparedSk,
    scratch: &mut SigningScratch,
    context: &[u8],
    message: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    prepared_signer::sign_prepared_with_scratch(&ctx.0, &sk.0, &mut scratch.0, context, message)
}

pub fn verify(ctx: &Ctx, pk: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    verify_with_context(ctx, pk, b"", message, signature)
}

pub fn verify_with_context(
    ctx: &Ctx,
    pk: &[u8],
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    PreparedRice::new(&ctx.0)?.verify_serialized_complete(pk, context, message, signature)
}

pub fn verify_prepared(
    ctx: &Ctx,
    pk: &PreparedPk,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    verify_prepared_with_context(ctx, pk, b"", message, signature)
}

pub fn verify_prepared_with_context(
    ctx: &Ctx,
    pk: &PreparedPk,
    context: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    PreparedRice::new(&ctx.0)?.verify(&pk.0, context, message, signature)
}

/// A context confined to key generation; signing uses `Ctx`.
pub struct KeygenCtx(native::scheme::keygen_context::KeygenCtx);
impl KeygenCtx {
    pub fn new() -> Self {
        Self(native::scheme::keygen_context::KeygenCtx::new())
    }
}
impl Default for KeygenCtx {
    fn default() -> Self {
        Self::new()
    }
}
pub fn keygen_only_with_entropy(
    ctx: &KeygenCtx,
    entropy: &mut impl EntropySource,
) -> Result<Keypair, Error> {
    native::scheme::keygen_context::keygen_with_entropy(&ctx.0, entropy).map(|pair| Keypair {
        pk: pair.pk,
        sk: pair.sk,
    })
}
pub fn keygen_only(ctx: &KeygenCtx) -> Result<Keypair, Error> {
    keygen_only_with_entropy(ctx, &mut OsEntropy)
}
