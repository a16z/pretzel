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

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    // Apple's timingsafe.h declares an opaque uint64_t token. Resolve both
    // functions before calling either: the APIs were introduced in macOS 15.2.
    // An older OS, missing symbol, denied sysctl, or unsupported CPU fails closed.
    type Enable = unsafe extern "C" fn() -> u64;
    type Restore = unsafe extern "C" fn(u64);

    // The capability and the two libSystem entry points cannot change while the
    // process runs, so they are looked up once. Every guard still enables DIT,
    // reads it back and restores it with its own token.
    pub(super) fn supported() -> bool {
        static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *SUPPORTED.get_or_init(query_supported)
    }

    fn query_supported() -> bool {
        let mut value: libc::c_int = 0;
        let mut size = core::mem::size_of_val(&value);
        // SAFETY: The NUL-terminated sysctl name is live, value is an exclusive aligned c_int, and
        // size supplies its exact capacity via a separate writable size_t. The null new-value pointer
        // with length zero requests a read only.
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
        // SAFETY: RTLD_DEFAULT and the NUL-terminated system-symbol names satisfy dlsym's interface.
        // libSystem remains loaded for the process lifetime, and null addresses are rejected by
        // require_symbols before use.
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
        // SAFETY: require_symbols has rejected null addresses. The libSystem symbols use
        // timingsafe.h's C ABI, matching Enable and Restore; the library remains loaded and the opaque
        // u64 token is passed back unchanged.
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
                // SAFETY: Guard::enter checked platform support and resolve obtained the matching
                // libSystem Enable/Restore pair. The opaque token is retained in this guard and
                // restored on the same thread; its Rc marker prevents Send/Sync.
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

// Thread-local observation and fault injection exist only in unit-test images.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::cell::{Cell, RefCell};
    pub(super) type Events = std::sync::Arc<std::sync::Mutex<Vec<(&'static str, u64)>>>;
    type Erasures = Vec<(&'static str, bool, u64)>;
    std::thread_local! {
        static ERASURES: RefCell<Option<Erasures>> = const { RefCell::new(None) };
        static FAILURE: Cell<u8> = const { Cell::new(0) };
        static PANIC_AT: Cell<Option<&'static str>> = const { Cell::new(None) };
        static REJECT_PREPARED: Cell<bool> = const { Cell::new(false) };
        static ENTROPY_ERROR: Cell<bool> = const { Cell::new(false) };
        // Initialize before any scratch TLS so this sink survives its teardown.
        static EVENTS: RefCell<Option<Events>> = const { RefCell::new(None) };
    }
    pub(super) fn failure() -> u8 {
        FAILURE.try_with(Cell::get).unwrap_or(0)
    }
    pub(super) fn set_failure(mode: u8) {
        FAILURE.with(|f| f.set(mode));
    }
    pub(crate) fn observe(site: &'static str) {
        let _ = EVENTS.try_with(|events| {
            if let Some(events) = events.borrow().as_ref() {
                // Observation must never cause a second panic during cleanup.
                let mut events = events.lock().unwrap_or_else(|e| e.into_inner());
                events.push((site, read() & DIT));
            }
        });
    }
    // Inspect live, initialized fields after the real zeroizer and before free.
    // Keep observations separate from lifetime events; never assert in Drop.
    pub(crate) fn observe_erasure(site: &'static str, erased: impl FnOnce() -> bool) {
        let _ = ERASURES.try_with(|events| {
            if let Some(events) = events.borrow_mut().as_mut() {
                events.push((site, erased(), read() & DIT));
            }
        });
    }
    pub(crate) fn checkpoint(site: &'static str) {
        observe(site);
        let panic = PANIC_AT.with(|p| {
            if p.get() == Some(site) {
                p.set(None);
                true
            } else {
                false
            }
        });
        if panic {
            #[cfg(feature = "stack-wipe")]
            crate::ct_erase::mark_panic_point();
            panic!("injected DIT lifetime unwind at {site}");
        }
    }
    pub(crate) fn reject_prepared() -> bool {
        REJECT_PREPARED.with(Cell::get)
    }
    pub(crate) fn entropy_fault() -> bool {
        checkpoint("sign-entropy");
        ENTROPY_ERROR.with(Cell::get)
    }
    // Wrap the actual zeroizer only in tests; drop it before recording completion.
    pub(crate) struct Traced<T: zeroize::Zeroize> {
        value: Option<zeroize::Zeroizing<T>>,
        site: &'static str,
    }
    impl<T: zeroize::Zeroize> Traced<T> {
        pub(crate) fn new(value: zeroize::Zeroizing<T>, site: &'static str) -> Self {
            Self {
                value: Some(value),
                site,
            }
        }
    }
    impl<T: zeroize::Zeroize> core::ops::Deref for Traced<T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.value.as_ref().unwrap()
        }
    }
    impl<T: zeroize::Zeroize> core::ops::DerefMut for Traced<T> {
        fn deref_mut(&mut self) -> &mut T {
            self.value.as_mut().unwrap()
        }
    }
    impl<T: zeroize::Zeroize> Drop for Traced<T> {
        fn drop(&mut self) {
            drop(self.value.take());
            observe(self.site);
        }
    }
    pub(super) fn record_thread(initial: u64, events: Events) {
        assert!(platform::supported(), "requires the declared DIT target");
        EVENTS.with(|e| *e.borrow_mut() = Some(events));
        write(initial);
    }
    #[derive(Default)]
    struct KeygenPlan {
        tape: Vec<Vec<u8>>,
        index: usize,
        replay: bool,
        fail_at: usize,
        panic: bool,
    }
    std::thread_local! {
        static KEYGEN: RefCell<Option<KeygenPlan>> = const { RefCell::new(None) };
    }
    pub(crate) struct KeygenEntropy<'a, R: crate::EntropySource>(pub(crate) &'a mut R);
    impl<R: crate::EntropySource> crate::EntropySource for KeygenEntropy<'_, R> {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> {
            checkpoint("keygen-entropy");
            // Release the RefCell borrow before injecting any panic.
            let action = KEYGEN.with(|p| {
                let mut p = p.borrow_mut();
                let plan = p.as_mut()?;
                plan.index += 1;
                if plan.index == plan.fail_at {
                    // Leave a real partial draw in the actual random owner.
                    let prefix = out.len() / 2;
                    out[..prefix].copy_from_slice(&plan.tape[plan.index - 1][..prefix]);
                    return Some(Err(plan.panic));
                }
                if plan.replay {
                    out.copy_from_slice(&plan.tape[plan.index - 1]);
                    return Some(Ok(()));
                }
                None
            });
            match action {
                Some(Err(true)) => panic!("injected keygen entropy panic"),
                Some(Err(false)) => return Err(crate::EntropyError),
                Some(Ok(())) => return Ok(()),
                None => {}
            }
            self.0.fill(out)?;
            KEYGEN.with(|p| {
                if let Some(plan) = p.borrow_mut().as_mut() {
                    plan.tape.push(out.to_vec());
                }
            });
            Ok(())
        }
    }
    pub(super) struct Scope {
        original: u64,
        events: Events,
    }
    impl Scope {
        pub(super) fn new(initial: u64) -> Self {
            assert!(platform::supported(), "requires the declared DIT target");
            let original = read();
            let events = Events::default();
            record_thread(initial, events.clone());
            Self { original, events }
        }
        pub(super) fn keygen_record(&self) {
            KEYGEN.with(|p| *p.borrow_mut() = Some(KeygenPlan::default()));
        }
        pub(super) fn keygen_tape(&self) -> Vec<Vec<u8>> {
            KEYGEN.with(|p| p.borrow().as_ref().unwrap().tape.clone())
        }
        pub(super) fn keygen_replay(&self, tape: &[Vec<u8>], fail_at: usize, panic: bool) {
            KEYGEN.with(|p| {
                *p.borrow_mut() = Some(KeygenPlan {
                    tape: tape.to_vec(),
                    index: 0,
                    replay: true,
                    fail_at,
                    panic,
                })
            });
        }
        pub(super) fn record_erasure(&self) {
            ERASURES.with(|e| *e.borrow_mut() = Some(Vec::new()));
        }
        pub(super) fn take_erasures(&self) -> Erasures {
            ERASURES.with(|e| core::mem::take(e.borrow_mut().as_mut().unwrap()))
        }
        pub(super) fn fail(&self, mode: u8) {
            set_failure(mode);
        }
        pub(super) fn panic_at(&self, site: &'static str) {
            PANIC_AT.with(|p| p.set(Some(site)));
        }
        pub(super) fn reject(&self, value: bool) {
            REJECT_PREPARED.with(|p| p.set(value));
        }
        pub(super) fn entropy_error(&self, value: bool) {
            ENTROPY_ERROR.with(|p| p.set(value));
        }
        pub(super) fn take(&self) -> Vec<(&'static str, u64)> {
            core::mem::take(&mut *self.events.lock().unwrap())
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            KEYGEN.with(|p| *p.borrow_mut() = None);
            ERASURES.with(|e| *e.borrow_mut() = None);
            set_failure(0);
            PANIC_AT.with(|p| p.set(None));
            REJECT_PREPARED.with(|p| p.set(false));
            ENTROPY_ERROR.with(|p| p.set(false));
            EVENTS.with(|e| *e.borrow_mut() = None);
            write(self.original);
        }
    }
}

#[cfg(test)]
#[path = "dit_lifetime_tests.rs"]
mod followup_tests;
