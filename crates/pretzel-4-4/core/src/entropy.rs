//! Entropy sources for stateless randomized key generation and signing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntropyError;

/// Fill every requested byte from a cryptographic entropy source or return Err.
/// Custom implementations are for audited integrations and fault-injection tests.
pub trait EntropySource {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError>;
}

#[derive(Default)]
pub struct OsEntropy;
impl EntropySource for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        #[cfg(all(
            any(target_os = "linux", target_os = "macos"),
            target_arch = "aarch64",
            test
        ))]
        if crate::timing_state::test_support::entropy_fault() {
            return Err(EntropyError);
        }
        // This symbol exists only in explicitly linked public-fixture executables.
        // The default production build has neither the call nor the fixture tape.
        #[cfg(all(feature = "conformance", target_os = "macos"))]
        {
            // SAFETY: declared only with the `conformance` feature on macOS. The symbol is supplied
            // by the fixture executable that links this crate (`tests/native/entropy.c`): it writes
            // at most `len` bytes at `out`, reads nothing through it and keeps no pointer.
            unsafe extern "C" {
                fn pretzel_test_logical_entropy(out: *mut u8, len: usize) -> i32;
            }
            // SAFETY: out is writable for len bytes; the harness owns thread-local state.
            match unsafe { pretzel_test_logical_entropy(out.as_mut_ptr(), out.len()) } {
                0 => return Ok(()),
                1 => {} // Inactive tape: exercise real OS entropy as usual.
                _ => return Err(EntropyError),
            }
        }
        getrandom::getrandom(out).map_err(|_| EntropyError)
    }
}
