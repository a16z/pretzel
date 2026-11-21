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
        getrandom::getrandom(out).map_err(|_| EntropyError)
    }
}
