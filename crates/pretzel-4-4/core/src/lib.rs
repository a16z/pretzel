//! Backend of Pretzel-(4,4) (research implementation).

#![deny(unsafe_op_in_unsafe_fn)]
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
// A return that ends a target-specific block stays: the portable path follows it in other configurations.
#![allow(clippy::needless_return)]
// A value bound to a name before it is returned stays as written; library code is not rewritten for style.
#![allow(clippy::let_and_return)]
// Iterator adapters, option combinators and size expressions on signing and verification paths keep their written form.
#![allow(
    clippy::map_clone,
    clippy::unnecessary_map_or,
    clippy::unwrap_or_default,
    clippy::manual_slice_size_calculation
)]
// The explicit borrow at the residual filter marks the boundary of the signer's buffers.
#![allow(clippy::needless_borrow)]
// The schedule loop keeps its index binding; loops on these paths are not rewritten for style.
#![allow(clippy::unused_enumerate_index)]
// Contexts and encoders are built by explicit `new()` calls only; no `Default` is offered.
#![allow(clippy::new_without_default)]

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!(
    "unsupported target: timing protection exists only for macOS on aarch64; no fallback"
);

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
mod timing_state;

pub mod challenge;

// Sorting networks of the reference classifier `ct_grouped_cdf::classify`, which is compiled for
// tests only.
#[cfg(test)]
mod ct_sort;

mod ct_erase;

mod ct_alias;

pub mod ct;
#[cfg(test)]
#[cfg(target_arch = "aarch64")]
mod ct_cdf_pair;

pub(crate) mod ct_deferred;

mod ct_lookup;

mod ct_slots;

mod ct_dither;

pub mod correlation;

pub mod encode;
pub mod fixed;

pub mod gauss;
pub mod hashes;

mod shake2;

mod ct_stream_schedule;

#[cfg(target_arch = "aarch64")]
pub mod neon;
pub mod params;
pub mod params_tables;
pub mod quantize;
mod randomness;
pub mod ring;
pub mod scheme;

mod guarded_drop;
mod scratch;
mod secret;

// Compile the actual public wrappers into the native DIT unit-test image.
#[cfg(test)]
extern crate self as pretzel_4_4_core;
#[cfg(test)]
#[path = "../../src/api.rs"]
// The wrappers are compiled for the tests that call them; their public re-exports have no reader in this image.
#[allow(dead_code, unused_imports)]
mod api_for_dit_tests;
pub mod entropy;
#[cfg(test)]
mod lean_correspondence_tests;
pub mod theta;
pub mod transport;

pub use entropy::{EntropyError, EntropySource, OsEntropy};
pub use scratch::SigningScratch;
pub use secret::SecretKey;

pub use scheme::{keygen, keygen_with_entropy, Ctx, Error, Keypair, PreparedPk, PreparedSk};

mod ct_gram_registers;

mod ct_grouped_cdf;

mod ct_cdf_tree;

#[cfg(target_arch = "aarch64")]
mod ct_rarequeue;

mod ct_interval_transport;

#[cfg(target_arch = "aarch64")]
mod ct_collapsed_alias;

mod compact_ring;

#[cfg(target_arch = "aarch64")]
mod ct_caps_piecewise;

mod aux32_initial;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64", target_endian = "little")))]
compile_error!("unsupported target: PRETZEL requires little-endian macOS AArch64");

// Public dither framing is shared by setup, signing and verification.

pub(crate) mod dither_frame;

// Tagged key envelopes and NTT-domain public keys.

mod direct_ntt_profile;

mod rice_codec;

mod key_setup;

// Appendix D byte conformance, compiled only in the backend test image.
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_arch = "aarch64",
    target_endian = "little",
    test
))]
#[path = "../../tests/spec_domains.rs"]
mod spec_domains;
