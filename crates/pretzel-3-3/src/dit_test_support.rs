//! Test-only thread-local fault injection and live DIT observations.
use super::*;
use std::cell::{Cell, RefCell};
type Events = Vec<(&'static str, u64)>;
std::thread_local! {
    static FAILURE: Cell<u8> = const { Cell::new(0) };
    static PANIC_AT: Cell<Option<&'static str>> = const { Cell::new(None) };
    static ENTROPY_ERROR: Cell<bool> = const { Cell::new(false) };
    static EVENTS: RefCell<Option<Events>> = const { RefCell::new(None) };
}
pub(super) fn failure() -> u8 {
    FAILURE.with(Cell::get)
}
pub(crate) fn observe(site: &'static str) {
    let _ = EVENTS.try_with(|events| {
        if let Some(events) = events.borrow_mut().as_mut() {
            events.push((site, read() & DIT));
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
// Last field of the heap secret: observe after the real field destructors.
pub(crate) struct Retired(pub(crate) &'static str);
impl Drop for Retired {
    fn drop(&mut self) {
        observe(self.0);
    }
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
}
impl Scope {
    pub(super) fn new(initial: u64) -> Self {
        assert!(platform::supported(), "requires the declared DIT target");
        let original = read();
        EVENTS.with(|e| *e.borrow_mut() = Some(Vec::new()));
        write(initial);
        Self { original }
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
    pub(super) fn fail(&self, mode: u8) {
        FAILURE.with(|f| f.set(mode));
    }
    pub(super) fn panic_at(&self, site: &'static str) {
        PANIC_AT.with(|p| p.set(Some(site)));
    }
    pub(super) fn take(&self) -> Events {
        EVENTS.with(|e| core::mem::take(e.borrow_mut().as_mut().unwrap()))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        KEYGEN.with(|p| *p.borrow_mut() = None);
        FAILURE.with(|f| f.set(0));
        PANIC_AT.with(|p| p.set(None));
        ENTROPY_ERROR.with(|p| p.set(false));
        EVENTS.with(|e| *e.borrow_mut() = None);
        write(self.original);
    }
}

// For tests outside `timing_state`, which can neither name `Scope` nor read the timing flag: one
// call, made with the flag clear or set at entry and, when `guard_failure` is 1 or 2, with that
// injected failure of the timing guard. A panic of the call is caught here, so the events of its
// unwinding are kept.
pub(crate) struct Recorded<T> {
    // What the call returned, or the payload of its panic.
    pub(crate) value: std::thread::Result<T>,
    // Every observed site in order, each with whether the timing flag was set there.
    pub(crate) events: Vec<(&'static str, bool)>,
    // Whether the timing flag is back to its entry value after the call.
    pub(crate) restored: bool,
}
pub(crate) fn record<T>(
    set_at_entry: bool,
    guard_failure: u8,
    call: impl FnOnce() -> T,
) -> Recorded<T> {
    let initial = if set_at_entry { DIT } else { 0 };
    let scope = Scope::new(initial);
    scope.fail(guard_failure);
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(call));
    let restored = read() & DIT == initial;
    let events = scope
        .take()
        .into_iter()
        .map(|(site, state)| (site, state == DIT))
        .collect();
    Recorded {
        value,
        events,
        restored,
    }
}
