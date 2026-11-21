#![deny(unsafe_op_in_unsafe_fn)]
//! Pretzel-(5,5) signature scheme (research candidate).
//!
//! See README.md for the entry points and the validation status.

// A value bound to a name before it is returned stays as written; library code is not rewritten for style.
#![allow(clippy::let_and_return)]

#[cfg(not(target_os = "macos"))]
compile_error!(
    "unsupported target: timing protection exists only for macOS on aarch64; no fallback"
);

#[cfg(target_os = "macos")]
mod timing_state;

mod guarded_drop;

#[doc(hidden)]
pub mod challenge;
#[doc(hidden)]
pub mod ct;
pub(crate) mod ct_deferred;
mod ct_erase;

#[doc(hidden)]
pub mod correlation;
mod ct_dither;
#[cfg(test)]
mod ct_lookup;
mod ct_slots;
#[doc(hidden)]
pub mod encode;
mod entropy;
#[doc(hidden)]
pub mod fixed;
#[doc(hidden)]
pub mod gauss;
#[doc(hidden)]
pub mod hashes;
#[doc(hidden)]
pub mod neon;
#[doc(hidden)]
pub mod params;
#[doc(hidden)]
pub mod params_tables;
#[doc(hidden)]
pub mod quantize;
#[doc(hidden)]
pub mod ring;
#[doc(hidden)]
pub mod scheme;
mod scratch;
#[path = "../../pretzel-4-4/core/src/secret.rs"]
mod secret;
mod shake2;
#[doc(hidden)]
pub mod theta;
#[doc(hidden)]
pub mod transport;

// The public interface of the crate: Pretzel-(5,5) with 1908-byte signatures.
// Everything else that is still `pub` is hidden from the documentation and is not an interface.
mod api;

pub use api::{
    sign, sign_prepared, sign_prepared_with_context, sign_prepared_with_context_and_stats,
    sign_prepared_with_scratch, sign_prepared_with_stats, sign_with_context, sign_with_stats,
    verify, verify_prepared, verify_prepared_with_context, verify_with_context,
};

pub use api::{PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, SIGNATURE_BYTES};

/// Generate a key pair with entropy from the operating system. The public key holds
/// `PUBLIC_KEY_BYTES` bytes and the secret key `SECRET_KEY_BYTES` bytes. Fails with
/// `Error::RngFailure` when entropy is unavailable and `Error::TimingProtectionUnavailable`
/// when the processor's data-independent timing mode cannot be enabled.
pub use scheme::keygen;

/// As `keygen`, with entropy from the given source. The source receives every request for
/// secret randomness and must fill each request completely or return an error.
pub use scheme::keygen_with_entropy;

/// Precomputed public tables shared by key generation, signing and verification. Holds no
/// secret.
pub use scheme::Ctx;

/// Error of every operation of the crate. Carries no secret.
pub use scheme::Error;

/// A generated key pair: the serialized public key (`PUBLIC_KEY_BYTES` bytes) and the
/// serialized secret key (`SECRET_KEY_BYTES` bytes), which is erased when dropped.
pub use scheme::Keypair;

/// A public key checked and expanded for repeated verification. Built with `PreparedPk::new`
/// from `PUBLIC_KEY_BYTES` bytes; fails with `Error::KeyFormat` on any other input.
pub use scheme::PreparedPk;

/// A secret key checked and expanded for repeated signing. Built with `PreparedSk::new` from
/// `SECRET_KEY_BYTES` bytes; fails with `Error::KeyFormat` on a malformed key. The secret state
/// lives in one heap allocation that is erased when the value is dropped;
/// `PreparedSk::public_key` returns the matching serialized public key.
pub use scheme::PreparedSk;

/// Signing workspace owned by the caller, for `sign_prepared_with_scratch`. Erased after every
/// signing attempt and when dropped.
pub use scratch::SigningScratch;

/// Serialized secret key bytes, erased when dropped. Dereferences to a byte slice.
pub use secret::SecretKey;

/// Source of secret randomness for key generation, its error, and the source backed by the
/// operating system.
pub use entropy::{EntropyError, EntropySource, OsEntropy};

mod ct_gram_registers;

mod ct_interval_transport;

mod compact_ring;

mod ct_caps_piecewise;

mod aux32_initial;

#[cfg(not(all(target_os = "macos", target_endian = "little")))]
compile_error!("unsupported target: PRETZEL requires little-endian macOS AArch64");

pub(crate) mod dither_frame;

// Tagged key envelopes and NTT-domain public keys.
mod direct_ntt_profile;

mod attempt_tape;

mod transport_queue;

#[cfg(test)]
mod dither_certificate_tests;
mod dither_setup;
#[cfg(test)]
mod keygen_fixture_tests;
mod signature_codec;
// The verification files compiled into this crate from the Pretzel-(4,4) backend by `#[path]`
// call the codec module `rice_codec`, its name in that crate, where the coding is Rice coding.
use crate::signature_codec as rice_codec;

#[cfg(test)]
mod public_known_answer_tests;
mod target_contract;

mod neon_mod_arith;

mod neon_canonical_residue;

mod noncore_bounded;

mod signer_erase;
