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
mod signing_boundary_tests {
    use super::*;
    use crate::api_for_dit_tests as api;
    use zeroize::Zeroize;

    fn assert_preparation(events: &[(&str, u64)], complete: bool) {
        assert_eq!(events.iter().filter(|e| e.0 == "prepare-entry").count(), 1);
        assert_eq!(
            events.iter().filter(|e| e.0 == "prepare-exit").count(),
            usize::from(complete)
        );
        assert!(events.iter().all(|e| e.1 == DIT), "{events:?}");
    }

    #[test]
    fn prepared_and_public_sign_restore_both_states_on_success_and_bad_key() {
        let ctx = api::Ctx::new();
        let pair = api::keygen(&ctx).unwrap();
        for initial in [0, DIT] {
            let scope = test_support::Scope::new(initial);
            let prepared = api::PreparedSk::new(&pair.sk).unwrap();
            assert_eq!(read() & DIT, initial);
            assert_preparation(&scope.take(), true);
            drop(prepared);
            assert_eq!(read() & DIT, initial);
            let events = scope.take();
            assert_eq!(events, [("parsed-key-drop", DIT), ("prefix-drop", DIT)]);
            for kind in 0..3 {
                let signature = match kind {
                    0 => api::sign(&ctx, &pair.sk, b"DIT boundary"),
                    1 => api::sign_with_context(&ctx, &pair.sk, b"", b"DIT boundary"),
                    _ => api::sign_with_stats(&ctx, &pair.sk, b"DIT boundary").map(|v| v.0),
                }
                .unwrap();
                assert_eq!(read() & DIT, initial);
                let events = scope.take();
                assert_preparation(&events, true);
                assert!(events.contains(&("parsed-key-drop", DIT)));
                assert!(events.contains(&("prefix-drop", DIT)));
                api::verify(&ctx, &pair.pk, b"DIT boundary", &signature).unwrap();
            }
            // Exact-length corruption reaches secret parsing and cleanup before
            // the hash check fails; the empty slice covers the early error too.
            let mut malformed = pair.sk.to_vec();
            malformed[14 + 576] ^= 1;
            for bad in [b"".as_slice(), malformed.as_slice()] {
                assert!(matches!(api::PreparedSk::new(bad), Err(Error::KeyFormat)));
                assert_eq!(read() & DIT, initial);
                assert_preparation(&scope.take(), false);
                for kind in 0..3 {
                    let result = match kind {
                        0 => api::sign(&ctx, bad, b"DIT boundary"),
                        1 => api::sign_with_context(&ctx, bad, b"", b"DIT boundary"),
                        _ => api::sign_with_stats(&ctx, bad, b"DIT boundary").map(|v| v.0),
                    };
                    assert!(matches!(result, Err(Error::KeyFormat)));
                    assert_eq!(read() & DIT, initial);
                    assert_preparation(&scope.take(), false);
                }
            }
        }
    }

    #[test]
    fn preparation_fails_closed_before_parse_on_capability_and_readback_failure() {
        let ctx = api::Ctx::new();
        for initial in [0, DIT] {
            for mode in [1, 2] {
                let scope = test_support::Scope::new(initial);
                scope.fail(mode);
                assert!(matches!(
                    api::PreparedSk::new(&[]),
                    Err(Error::TimingProtectionUnavailable)
                ));
                assert!(matches!(
                    api::sign(&ctx, &[], b""),
                    Err(Error::TimingProtectionUnavailable)
                ));
                assert!(scope.take().is_empty(), "private preparation was reached");
                assert_eq!(read() & DIT, initial);
            }
        }
    }

    #[test]
    fn scratch_erases_and_restores_even_when_enable_fails() {
        for initial in [0, DIT] {
            for mode in [0, 1, 2] {
                let scope = test_support::Scope::new(initial);
                let mut scratch = crate::SigningScratch::new();
                scratch.poison();
                scope.fail(mode);
                scratch.zeroize();
                assert!(scratch.is_erased());
                assert_eq!(read() & DIT, initial);
                scratch.poison();
                drop(scratch);
                assert_eq!(read() & DIT, initial);
                let expected = if mode == 0 { DIT } else { initial };
                assert_eq!(
                    scope.take(),
                    [("scratch-erase", expected), ("scratch-erase", expected)]
                );
            }
        }
    }

    #[test]
    fn guarded_drop_covers_field_destructors_and_unwind_without_skipping_cleanup() {
        struct Leaf;
        impl Drop for Leaf {
            fn drop(&mut self) {
                test_support::observe("leaf-drop");
            }
        }
        struct Owner {
            _leaf: Leaf,
        }
        impl Drop for Owner {
            fn drop(&mut self) {
                test_support::observe("owner-drop");
            }
        }
        for initial in [0, DIT] {
            for mode in [0, 1, 2] {
                let scope = test_support::Scope::new(initial);
                scope.fail(mode);
                let owner = crate::guarded_drop::GuardedDrop::new(Owner { _leaf: Leaf });
                drop(owner);
                assert_eq!(read() & DIT, initial);
                let expected = if mode == 0 { DIT } else { initial };
                assert_eq!(
                    scope.take(),
                    [("owner-drop", expected), ("leaf-drop", expected)]
                );
                assert!(std::panic::catch_unwind(|| {
                    let _owner = crate::guarded_drop::GuardedDrop::new(Owner { _leaf: Leaf });
                    panic!("exercise guarded owner cleanup");
                })
                .is_err());
                assert_eq!(read() & DIT, initial);
                assert_eq!(
                    scope.take(),
                    [("owner-drop", expected), ("leaf-drop", expected)]
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "dit_lifetime_tests.rs"]
mod lifetime_tests;
