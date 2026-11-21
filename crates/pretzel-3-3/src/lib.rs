//! Pretzel-(3,3) signature scheme (research candidate).

// Index loops stay explicit in fixed-time arithmetic so that the access pattern is visible to review.
#![allow(clippy::needless_range_loop)]
// Rounding up and divisibility tests keep their explicit operators; arithmetic on secret paths is not rewritten for style.
#![allow(clippy::manual_div_ceil, clippy::manual_is_multiple_of)]
// Range checks stay as two explicit comparisons.
#![allow(clippy::manual_range_contains)]
// Shift, mask and sum expressions keep their written grouping; arithmetic on secret paths is not rewritten for style.
#![allow(clippy::precedence)]
// Reject conditions keep their written form so that each check stays one visible clause.
#![allow(clippy::nonminimal_bool)]
// Codecs return `Err(())`: callers map every failure to a single rejection and no cause is carried.
#![allow(clippy::result_unit_err)]
// Signatures spell out their fixed-size array types and pass each buffer separately, so that lengths are visible at the call.
#![allow(clippy::type_complexity, clippy::too_many_arguments)]
// Verification keeps one nested block per stage, so that each branch reads against the stage list.
#![allow(clippy::collapsible_else_if)]
// Encoders and contexts are built only through `new`; there is no `Default`, so none is created implicitly.
#![allow(clippy::new_without_default)]
// Byte counts are written as length times element size, beside the capacity counts they are reported with.
#![allow(clippy::manual_slice_size_calculation)]
// Schedule loops keep their index binding; loops on secret paths are not rewritten for style.
#![allow(clippy::unused_enumerate_index)]
// Signing names the scratch constructor at the call, so that the allocation it performs is visible there.
#![allow(clippy::unwrap_or_default)]

#[cfg(not(all(
    target_arch = "aarch64",
    target_os = "macos",
    target_vendor = "apple",
    target_endian = "little",
    target_pointer_width = "64"
)))]
compile_error!("unsupported target: Pretzel-(3,3) requires AArch64 macOS (Apple silicon)");

mod guarded_drop;
mod timing_state;

#[doc(hidden)]
pub mod challenge;
#[doc(hidden)]
pub mod ct;
mod ct_alias;
mod ct_erase;
// Sorting networks of the reference classifier `ct_grouped_cdf::classify`, which is compiled for
// tests only.
#[cfg(test)]
mod ct_sort;
// Reached only through `ct_sort::sort_cdf` and `ct_sort::merge_cdf`, which are compiled under the same condition.
#[cfg(test)]
mod ct_cdf_pair;
// Reached only through the reference expansions of `ct_dither`, which are compiled for tests only.
#[cfg(test)]
mod ct_compact;
pub(crate) mod ct_deferred;

#[doc(hidden)]
pub mod correlation;
mod ct_dither;
mod ct_lookup;
mod ct_slots;
mod ct_stream_schedule;
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
mod randomness;
#[doc(hidden)]
pub mod ring;
#[doc(hidden)]
pub mod scheme;
mod scratch;
mod secret;
mod shake2;
#[doc(hidden)]
pub mod theta;
#[doc(hidden)]
pub mod transport;

// The public interface of the crate: Pretzel-(3,3) with 1160-byte signatures.
// Everything else that is still `pub` is hidden from the documentation and is not an interface,
// except `scheme::fixed_profile_key`, the interface for the 1312-byte public-key body.
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
/// secret. Building one is costly; build it once and reuse it.
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

#[path = "../../pretzel-4-4/core/src/ct_grouped_cdf.rs"]
mod ct_grouped_cdf;

mod ct_cdf_tree;

mod ct_rarequeue;

mod ct_interval_transport;

mod ct_collapsed_alias;

mod compact_ring;

mod ct_caps_piecewise;

mod aux32_initial;

pub(crate) mod dither_frame;

// Tagged key envelopes and NTT-domain public keys.
mod direct_ntt_profile;

mod dither_setup;
mod signature_codec;

// The test file `public_preparation_wire_tests.rs`, shared with the Pretzel-(4,4) backend, names
// the codec module as that crate does.
#[cfg(test)]
use crate::signature_codec as rice_codec;
