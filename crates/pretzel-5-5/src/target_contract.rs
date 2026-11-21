//! Native profile contract: little-endian macOS AArch64 and the signature size.
#[cfg(not(all(target_os = "macos", target_endian = "little")))]
compile_error!("unsupported target: PRETZEL (5,5) requires little-endian macOS AArch64");
const _: () = assert!(crate::signature_codec::SIGNATURE_BYTES == 1908);
const _: () = assert!(crate::signature_codec::HEAD_BYTES == 1876);
const _: () = assert!(crate::signature_codec::HEAD_EXCEPTIONS == 40);
const _: () = assert!(crate::signature_codec::LABEL_EXCEPTIONS == 16);
