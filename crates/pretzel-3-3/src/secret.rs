//! Owned serialized secret material. No implicit cloning or secret Debug output.
use core::{fmt, ops::Deref};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Erased on normal drop and unwinding. Does not erase caller-created copies,
/// registers, swap, crash dumps, or memory on process abort.
pub struct SecretKey(pub(crate) crate::guarded_drop::GuardedDrop<Zeroizing<Vec<u8>>>);

impl Deref for SecretKey {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}
impl ZeroizeOnDrop for SecretKey {}
