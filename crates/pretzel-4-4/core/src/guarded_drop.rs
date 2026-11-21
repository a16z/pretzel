//! Keep timing protection alive through the complete destructor tree.
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

pub(crate) struct GuardedDrop<T>(ManuallyDrop<T>);

impl<T> GuardedDrop<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(ManuallyDrop::new(value))
    }
}
impl<T> Deref for GuardedDrop<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T> DerefMut for GuardedDrop<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T> Drop for GuardedDrop<T> {
    fn drop(&mut self) {
        // Cleanup must not panic or leave secrets resident if DIT is unavailable.
        // These owners erase with value-independent stores, lengths and addresses.
        // Hold the guard through field destructors too, including on unwinding.
        #[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
        let _timing_state = crate::timing_state::Guard::enter().ok();
        // SAFETY: this is the sole destruction of the owned value. ManuallyDrop
        // prevents automatic field destruction, and no reference escapes Drop.
        unsafe {
            ManuallyDrop::drop(&mut self.0);
        }
    }
}
