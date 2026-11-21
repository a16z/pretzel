//! Pretzel-(4,4) signatures of 1361 bytes.
//!
//! The tests are finite checks of the build, the interface and the signer.
//! Builds for Apple silicon macOS only.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(all(target_arch = "aarch64", target_os = "macos", target_endian = "little")))]
compile_error!("unsupported target: PRETZEL (4,4) requires little-endian macOS AArch64");

#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_endian = "little"
))]
mod api;
#[cfg(all(
    target_arch = "aarch64",
    any(target_os = "linux", target_os = "macos"),
    target_endian = "little"
))]
pub use api::*;
