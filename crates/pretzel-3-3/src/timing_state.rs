//! macOS aarch64 DIT scope, not a CPU timing certificate.
//! Scheduling must preserve PSTATE.DIT; signal handlers and callbacks must not
//! leave it disabled. In particular, macOS does not undo a handler's raw DIT
//! clear on signal return (observed on an M3 Max).
//! DIT instruction coverage and data-dependent prefetch remain target contracts.

use crate::Error;
use core::{arch::asm, marker::PhantomData};
use std::rc::Rc;

const DIT: u64 = 1 << 24;

// These assembly blocks deliberately have memory effects to the compiler.
// The generic system-register name avoids enabling unrelated ISA extensions.
fn read() -> u64 {
    let value;
    // SAFETY: called only after the platform capability check on this thread.
    unsafe {
        asm!("mrs {value}, S3_3_C4_C2_5", value = out(reg) value,
                  options(nostack, preserves_flags));
    }
    value
}

#[cfg(test)]
fn write(value: u64) {
    // SAFETY: only a saved DIT value or DIT=1 is written on a supported CPU.
    // DSB NSH; ISB is the architectural fallback speculation barrier. Keep
    // both compiler memory ordering and the entry barrier before secret loads.
    unsafe {
        asm!("msr S3_3_C4_C2_5, {value}", "dsb nsh", "isb",
                  value = in(reg) value, options(nostack, preserves_flags));
    }
}

pub(crate) struct Guard {
    state: platform::State,
    // Timing state belongs to a thread; the guard must not be Send or Sync.
    _thread: PhantomData<Rc<()>>,
}

impl Guard {
    pub(crate) fn enter() -> Result<Self, Error> {
        let supported = platform::supported();
        #[cfg(test)]
        let supported = supported && test_support::failure() != 1;
        Self::enter_supported(supported)
    }

    fn enter_supported(supported: bool) -> Result<Self, Error> {
        if !supported {
            return Err(Error::TimingProtectionUnavailable);
        }
        let guard = Self {
            state: platform::State::enable()?,
            _thread: PhantomData,
        };
        let enabled = read() & DIT != 0;
        #[cfg(test)]
        let enabled = enabled && test_support::failure() != 2;
        if !enabled {
            // Drop restores the prior state even if the enable check fails.
            return Err(Error::TimingProtectionUnavailable);
        }
        Ok(guard)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Complete earlier memory accesses before potentially disabling DIT.
        // SAFETY: this barrier is available on all supported aarch64 CPUs.
        unsafe {
            asm!("dsb nsh", "isb", options(nostack, preserves_flags));
        }
        self.state.restore();
    }
}

mod platform {
    use super::*;

    // Apple's timingsafe.h declares an opaque uint64_t token. Resolve both
    // functions before calling either: the APIs were introduced in macOS 15.2.
    // An older OS, missing symbol, denied sysctl, or unsupported CPU fails closed.
    type Enable = unsafe extern "C" fn() -> u64;
    type Restore = unsafe extern "C" fn(u64);

    pub(super) fn supported() -> bool {
        static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *SUPPORTED.get_or_init(query_supported)
    }

    fn query_supported() -> bool {
        let mut value: libc::c_int = 0;
        let mut size = core::mem::size_of_val(&value);
        // SAFETY: the terminated name and correctly sized writable buffer live
        // through the call; no sysctl is written.
        let result = unsafe {
            libc::sysctlbyname(
                c"hw.optional.arm.FEAT_DIT".as_ptr(),
                (&mut value as *mut libc::c_int).cast(),
                &mut size,
                core::ptr::null_mut(),
                0,
            )
        };
        result == 0 && size == core::mem::size_of_val(&value) && value == 1
    }

    fn resolve() -> Result<(Enable, Restore), Error> {
        static API: std::sync::OnceLock<Option<(Enable, Restore)>> = std::sync::OnceLock::new();
        (*API.get_or_init(|| lookup().ok())).ok_or(Error::TimingProtectionUnavailable)
    }

    fn lookup() -> Result<(Enable, Restore), Error> {
        // SAFETY: RTLD_DEFAULT and these terminated, public system-symbol names
        // are valid. The addresses belong to libSystem, which remains loaded.
        let (enable, restore) = unsafe {
            (
                libc::dlsym(
                    libc::RTLD_DEFAULT,
                    c"timingsafe_enable_if_supported".as_ptr(),
                ),
                libc::dlsym(
                    libc::RTLD_DEFAULT,
                    c"timingsafe_restore_if_supported".as_ptr(),
                ),
            )
        };
        require_symbols(enable, restore)?;
        // SAFETY: both nonnull symbols have the exact C signatures in
        // timingsafe.h. The opaque token is never interpreted by this module.
        Ok(unsafe {
            (
                core::mem::transmute::<*mut libc::c_void, Enable>(enable),
                core::mem::transmute::<*mut libc::c_void, Restore>(restore),
            )
        })
    }

    fn require_symbols(enable: *mut libc::c_void, restore: *mut libc::c_void) -> Result<(), Error> {
        if enable.is_null() || restore.is_null() {
            Err(Error::TimingProtectionUnavailable)
        } else {
            Ok(())
        }
    }

    pub(super) struct State {
        token: u64,
        restore: Restore,
    }
    impl State {
        pub(super) fn enable() -> Result<Self, Error> {
            let (enable, restore) = resolve()?;
            // SAFETY: supported() succeeded; the API supplies Apple's entry
            // safeguards and must be paired on this thread with its own token.
            Ok(Self {
                token: unsafe { enable() },
                restore,
            })
        }
        pub(super) fn restore(&self) {
            // SAFETY: this is the matching token/function on the same thread.
            unsafe {
                (self.restore)(self.token);
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn either_missing_api_fails_closed() {
        let absent = core::ptr::null_mut();
        let present = core::ptr::NonNull::<libc::c_void>::dangling().as_ptr();
        for (enable, restore) in [(absent, absent), (present, absent), (absent, present)] {
            assert_eq!(
                require_symbols(enable, restore),
                Err(Error::TimingProtectionUnavailable)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_fails_before_register_access() {
        assert!(matches!(
            Guard::enter_supported(false),
            Err(Error::TimingProtectionUnavailable)
        ));
    }

    #[test]
    fn native_nested_error_and_unwind_restore() {
        assert!(
            platform::supported(),
            "this native test requires the declared DIT target"
        );
        let before = read();
        {
            let _outer = Guard::enter().unwrap();
            assert_eq!(read() & DIT, DIT);
            {
                let _inner = Guard::enter().unwrap();
                assert_eq!(read() & DIT, DIT);
            }
            assert_eq!(read() & DIT, DIT);
            let result = (|| -> Result<(), Error> {
                let _inner = Guard::enter()?;
                Err(Error::RngFailure)
            })();
            assert_eq!(result, Err(Error::RngFailure));
            assert_eq!(read() & DIT, DIT);
            assert!(std::panic::catch_unwind(|| {
                let _inner = Guard::enter().unwrap();
                panic!("exercise unwind restoration");
            })
            .is_err());
            assert_eq!(read() & DIT, DIT);
        }
        assert_eq!(read(), before);
    }

    #[test]
    fn both_entry_states_and_thread_handoffs_restore() {
        assert!(platform::supported(), "requires the declared DIT target");
        let original = read();
        for initial in [0, DIT] {
            write(initial);
            {
                let _guard = Guard::enter().unwrap();
                assert_eq!(read() & DIT, DIT);
                let (send, recv) = std::sync::mpsc::sync_channel(0);
                let (reply, replies) = std::sync::mpsc::sync_channel(0);
                let worker = std::thread::spawn(move || {
                    assert!(platform::supported());
                    let before = read();
                    write(0);
                    for _ in 0..1024 {
                        recv.recv().unwrap();
                        assert_eq!(read() & DIT, 0);
                        reply.send(()).unwrap();
                    }
                    write(before);
                });
                for _ in 0..1024 {
                    send.send(()).unwrap();
                    replies.recv().unwrap();
                    assert_eq!(read() & DIT, DIT);
                }
                worker.join().unwrap();
            }
            assert_eq!(read() & DIT, initial);
        }
        write(original);
    }
}

#[cfg(test)]
#[path = "dit_test_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "dit_lifetime_tests.rs"]
mod lifetime_tests;
