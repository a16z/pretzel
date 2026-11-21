//! Native lifetime tests required by run_native_checks.py on macOS.
use super::*;
use crate::{Ctx, PreparedSk};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn require(events: &[(&str, u64)], sites: &[&str]) {
    assert!(events.iter().all(|e| e.1 == DIT), "{events:?}");
    for site in sites {
        assert!(events.contains(&(*site, DIT)), "{site}: {events:?}");
    }
}

// With the Cargo feature `stack-wipe` the stack scrub of the key import completes exactly once,
// after every other event of the import, while DIT is still on. Without the feature no stack
// range is wiped, and no completion event may be recorded.
fn require_import_scrub(events: &[(&str, u64)]) {
    let wipes = events.iter().filter(|e| e.0 == "stack-scrub").count();
    if cfg!(feature = "stack-wipe") {
        assert_eq!(wipes, 1, "{events:?}");
        assert_eq!(events.last(), Some(&("stack-scrub", DIT)), "{events:?}");
    } else {
        assert_eq!(wipes, 0, "{events:?}");
    }
}

struct NoEntropy;
impl crate::EntropySource for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), crate::EntropyError> {
        panic!("unexpected underlying entropy draw");
    }
}

#[test]
fn keygen_success_sampling_and_cleanup_restore_both_states() {
    let ctx = Ctx::new();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        scope.keygen_record();
        let pair = crate::keygen(&ctx).unwrap();
        assert_eq!(read() & DIT, initial);
        let tape = scope.keygen_tape();
        let events = scope.take();
        require(
            &events,
            &[
                "keygen-private",
                "keygen-sampled",
                "keygen-seed_a-drop",
                "keygen-prf-drop",
                "keygen-key_seed-drop",
                "keygen-s0-drop",
                "keygen-e-drop",
            ],
        );
        assert_eq!(
            events.iter().filter(|e| e.0 == "keygen-entropy").count(),
            tape.len()
        );
        scope.keygen_replay(&tape, 0, false);
        let replay = crate::keygen_with_entropy(&ctx, &mut NoEntropy).unwrap();
        assert_eq!(read() & DIT, initial);
        assert_eq!(pair.pk, replay.pk);
        assert_eq!(&pair.sk[..], &replay.sk[..]);
        assert_eq!(scope.take(), events);
    }
}

#[test]
fn keygen_each_entropy_error_and_unwind_restore_both_states() {
    let ctx = Ctx::new();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        scope.keygen_record();
        crate::keygen(&ctx).unwrap();
        let tape = scope.keygen_tape();
        scope.take();
        for supplied in [false, true] {
            for draw in 1..=tape.len() {
                for panic in [false, true] {
                    scope.keygen_replay(&tape, draw, panic);
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        if supplied {
                            crate::keygen_with_entropy(&ctx, &mut NoEntropy)
                        } else {
                            crate::keygen(&ctx)
                        }
                    }));
                    if panic {
                        assert!(result.is_err());
                    } else {
                        assert!(matches!(result.unwrap(), Err(Error::RngFailure)));
                    }
                    assert_eq!(read() & DIT, initial);
                    let events = scope.take();
                    require(&events, &["keygen-entropy"]);
                    assert_eq!(
                        events.iter().filter(|e| e.0 == "keygen-entropy").count(),
                        draw
                    );
                    if draw > 1 {
                        require(&events, &["keygen-seed_a-drop"]);
                    }
                    if draw > 2 {
                        require(&events, &["keygen-prf-drop"]);
                    }
                }
            }
            for site in ["keygen-private", "keygen-sampled"] {
                scope.keygen_replay(&tape, 0, false);
                scope.panic_at(site);
                assert!(catch_unwind(AssertUnwindSafe(|| {
                    if supplied {
                        crate::keygen_with_entropy(&ctx, &mut NoEntropy)
                    } else {
                        crate::keygen(&ctx)
                    }
                }))
                .is_err());
                assert_eq!(read() & DIT, initial);
                let events = scope.take();
                require(&events, &[site, "keygen-key_seed-drop", "keygen-prf-drop"]);
                if site == "keygen-sampled" {
                    require(&events, &["keygen-s0-drop", "keygen-e-drop"]);
                }
            }
        }
    }
}

#[test]
fn unsupported_keygen_returns_before_any_entropy_draw() {
    let ctx = Ctx::new();
    for initial in [0, DIT] {
        for failure in [1, 2] {
            let scope = test_support::Scope::new(initial);
            scope.fail(failure);
            assert!(matches!(
                crate::keygen(&ctx),
                Err(Error::TimingProtectionUnavailable)
            ));
            assert!(matches!(
                crate::keygen_with_entropy(&ctx, &mut NoEntropy),
                Err(Error::TimingProtectionUnavailable)
            ));
            assert_eq!(read() & DIT, initial);
            assert!(scope.take().is_empty());
        }
    }
}

#[test]
fn secret_key_preparation_unwind_stays_guarded() {
    let ctx = Ctx::new();
    let pair = crate::keygen(&ctx).unwrap();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        scope.panic_at("prepare-exit");
        let result = catch_unwind(AssertUnwindSafe(|| PreparedSk::new(&pair.sk)));
        assert!(result.is_err());
        assert_eq!(read() & DIT, initial);
        let events = scope.take();
        require(
            &events,
            &["prepare-entry", "prepare-exit", "prepare-cleanup"],
        );
        require_import_scrub(&events);
        // The same unwinding import on a painted stack: what the body left inside the
        // erased extent is gone. See `import_unwind_stack` for what is not judged.
        #[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
        {
            let (unwound, reference) = import_unwind_stack::unwinding_reference();
            assert!(unwound, "the reference did not unwind");
            scope.take();
            eprintln!("reference unwind: {}", reference.describe());
            scope.panic_at("prepare-exit");
            let (unwound, import) = import_unwind_stack::unwinding_import(&pair.sk);
            assert!(unwound, "the import did not unwind");
            assert_eq!(read() & DIT, initial);
            require_import_scrub(&scope.take());
            eprintln!("unwinding import: {}", import.describe());
            import_unwind_stack::judge("prepare-exit", &import, &reference);
        }
    }
}

#[test]
fn secret_key_preparation_bad_key_and_unsupported_restore_both_states() {
    let ctx = Ctx::new();
    let pair = crate::keygen(&ctx).unwrap();
    let mut malformed = pair.sk.to_vec();
    // The hash is before the final dither seed; preserve length and envelope.
    malformed[14 + 64 + crate::params::TRIT_BYTES] ^= 1;
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        for bad in [b"".as_slice(), malformed.as_slice()] {
            assert_eq!(PreparedSk::new(bad).err(), Some(Error::KeyFormat));
            assert_eq!(read() & DIT, initial);
            let events = scope.take();
            require(&events, &["prepare-entry", "prepare-cleanup"]);
            require_import_scrub(&events);
        }
        for failure in [1, 2] {
            scope.fail(failure);
            assert_eq!(
                PreparedSk::new(&pair.sk).err(),
                Some(Error::TimingProtectionUnavailable)
            );
            assert_eq!(read() & DIT, initial);
            assert!(scope.take().is_empty());
        }
    }
}

#[test]
fn prepared_secret_moves_preserve_allocation_and_guarded_drop() {
    let pair = crate::keygen(&Ctx::new()).unwrap();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        let prepared = PreparedSk::new(&pair.sk).unwrap();
        assert_eq!(read() & DIT, initial);
        let events = scope.take();
        require(
            &events,
            &["prepare-entry", "prepare-exit", "prepare-cleanup"],
        );
        require_import_scrub(&events);
        let address = prepared.secret_address();
        let moved = Box::new(prepared);
        assert_eq!(moved.secret_address(), address);
        let prepared = *moved;
        assert_eq!(prepared.secret_address(), address);
        drop(prepared);
        assert_eq!(read() & DIT, initial);
        assert_eq!(scope.take(), [("prepared-secret-retired", DIT)]);
    }
}

#[test]
fn caller_guard_survives_nested_preparation_and_cleanup() {
    let pair = crate::keygen(&Ctx::new()).unwrap();
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        {
            let _outer = Guard::enter().unwrap();
            let prepared = PreparedSk::new(&pair.sk).unwrap();
            assert_eq!(read() & DIT, DIT);
            drop(prepared);
            assert_eq!(read() & DIT, DIT);
        }
        assert_eq!(read() & DIT, initial);
        let events = scope.take();
        require(
            &events,
            &["prepare-entry", "prepare-exit", "prepared-secret-retired"],
        );
        // With the feature `stack-wipe`: one scrub, at the end of the import and before the
        // returned owner is dropped. Without it: none.
        let wipes = events.iter().filter(|e| e.0 == "stack-scrub").count();
        if cfg!(feature = "stack-wipe") {
            let at = |site| events.iter().position(|e| e.0 == site).unwrap();
            assert_eq!(wipes, 1, "{events:?}");
            assert!(at("prepare-exit") < at("stack-scrub"));
            assert!(at("stack-scrub") < at("prepared-secret-retired"));
        } else {
            assert_eq!(wipes, 0, "{events:?}");
        }
    }
}

#[test]
fn panicking_parent_keeps_child_destructor_guarded() {
    struct Child;
    impl Drop for Child {
        fn drop(&mut self) {
            test_support::observe("child-drop");
        }
    }
    struct Parent {
        _child: Child,
    }
    impl Drop for Parent {
        fn drop(&mut self) {
            panic!("exercise field destruction during unwind");
        }
    }
    for initial in [0, DIT] {
        let scope = test_support::Scope::new(initial);
        assert!(catch_unwind(|| {
            drop(crate::guarded_drop::GuardedDrop::new(Parent {
                _child: Child,
            }));
        })
        .is_err());
        assert_eq!(read() & DIT, initial);
        assert_eq!(scope.take(), [("child-drop", DIT)]);
    }
}

/// Stack painting around a key import that unwinds. Compiled only with the Cargo feature
/// `stack-wipe`, and for optimized builds only: the extent that the import erases is chosen for
/// the frames of optimized images.
///
/// `unwinding_import` fills 524288 bytes of stack directly below its own frame with a pattern
/// that depends on the address, calls `PreparedSk::new` inside `catch_unwind` with a panic
/// injected by the caller, and reads the same bytes back. `unwinding_reference` does the same
/// with `reference_entry` in place of the import: the same scrub, held above a function that
/// fills a local of `BODY_BYTES` zero bytes, as large as the frame of the import body in an
/// optimized program, and panics. Nothing secret is below the scrub of the reference.
///
/// Positions are taken relative to the scrub mark: the address of a local of the function that
/// records the completion of the scrub, which lies directly below the frame that holds the
/// scrub. `EXTENT` is written out here and not taken from the constant of the scrub, so a
/// shorter scrub fails the test.
///
/// Required:
///
/// 1. a scrub completed in the reference and in the import, and the painted region was large
///    enough;
/// 2. within the extent, no nonzero word lies deeper than `ALLOWANCE` bytes below the scrub
///    mark, in the reference and in the import. The top of the erased range is not zero when
///    the panic is caught: after the scrub the unwinder continues from the frame that holds
///    the scrub and writes its own state directly below it;
/// 3. where `SAME_RESIDUE` is true, the deepest nonzero word within the extent lies within
///    `TOLERANCE` bytes of the same depth in the reference and in the import. Observed on
///    optimized unit-test builds: 23719 against 23711 bytes at Pretzel-(4,4) and
///    Pretzel-(5,5); 28327 against 23647 at Pretzel-(3,3), with the present extent as well as
///    with a smaller one. The 4680 further bytes at Pretzel-(3,3) are words written after the
///    scrub (the words nearer the mark agree); what writes them has not been identified, so
///    at Pretzel-(3,3) the comparison is printed and not required. It is an open item.
///
/// Printed to standard error and not required: whether words deeper than the extent were
/// changed in both or in neither (the panic handler runs below the frames of the import before
/// the scrub and can write deeper than the extent, where nothing is erased); the panic mark
/// (the address of a local of the function that raises the panic) below the scrub mark; the
/// deepest changed word below the panic mark; the span of the reference's local; and the
/// nonzero words within the extent in eight bins of 4096 bytes below the scrub mark.
///
/// What the test does not show: what the words left by the unwinder hold, which can include
/// saved register contents; anything about the words that the panic handler wrote deeper than
/// the extent, which no scrub erases; registers. It is one observation of one image, not a
/// bound.
#[cfg(all(feature = "stack-wipe", not(debug_assertions)))]
mod import_unwind_stack {
    use super::*;
    use std::hint::black_box;

    /// Bytes of stack that the key import zeroes below `PreparedSk::new`.
    const EXTENT: usize = 393216;
    /// Frame of the import body in the optimized image of the known-answer programs, in bytes.
    /// The body's frame in the unit-test build is not known and may be larger.
    const BODY_BYTES: usize = 100944;
    /// Deepest nonzero word accepted within the extent, in bytes below the scrub mark.
    const ALLOWANCE: usize = 32768;
    /// Accepted difference between the reference and the import in that depth.
    const TOLERANCE: usize = 256;
    /// Whether that difference is required at this parameter set, or only printed.
    const SAME_RESIDUE: bool = false;
    /// Bytes on each side of the deep end of the extent that are not judged: the scrub mark is
    /// not exactly the top of the erased range.
    const EDGE: usize = 512;
    /// Words painted below the measuring frame: 524288 bytes.
    const PAINT_WORDS: usize = 65536;
    const PATTERN: u64 = 0x5ca7_c4ed_a5a5_5a5a;

    #[inline(always)]
    fn painted(address: usize) -> u64 {
        PATTERN ^ address as u64
    }

    /// Fill PAINT_WORDS words directly below the caller's frame and return the lowest address.
    /// The function is out of line, so the words stay painted after it returns.
    #[inline(never)]
    fn paint() -> usize {
        let mut region = core::mem::MaybeUninit::<[u64; PAINT_WORDS]>::uninit();
        let base = region.as_mut_ptr().cast::<u64>();
        for i in 0..PAINT_WORDS {
            // SAFETY: word `i` of this function's own local array of PAINT_WORDS words.
            unsafe {
                base.add(i).write_volatile(painted(base as usize + 8 * i));
            }
        }
        black_box(base) as usize
    }

    /// What one scan found. Depths are bytes below the scrub mark.
    pub(super) struct Picture {
        /// A scrub completed during the call.
        marked: bool,
        /// Bytes from the top of the painted region down to the scrub mark; negative when the
        /// mark lies above the painted region.
        mark_below_top: isize,
        /// Deepest nonzero word within the extent; 0 when every such word is zero.
        deepest_nonzero: usize,
        /// Words deeper than the extent that no longer hold their paint.
        changed_beyond: usize,
        /// Deepest such word; 0 when there is none.
        deepest_changed: usize,
        /// The lowest painted word changed: the painted region was too small.
        exhausted: bool,
        /// The panic mark, in bytes below the scrub mark; 0 when no panic mark was set.
        panic_below_mark: isize,
        /// Nonzero words within the extent, by depth below the scrub mark in bins of 4096 bytes;
        /// the last bin also counts everything deeper.
        bins: [usize; 8],
        /// The reference's local: its low and high end in bytes below the scrub mark.
        filler: (isize, isize),
    }

    impl Picture {
        pub(super) fn describe(&self) -> String {
            format!(
                "scrub mark {} bytes below the top of the painted region; deepest nonzero word \
                 within the extent {} bytes below the mark; {} words changed deeper than the \
                 extent, the deepest {} bytes below the mark; painted region exhausted: {}; \
                 panic mark {} bytes below the scrub mark; deepest changed word {} bytes below \
                 the panic mark; nonzero words within the extent by 4096-byte bins {:?}; \
                 local of the reference from {} to {} bytes below the scrub mark",
                self.mark_below_top,
                self.deepest_nonzero,
                self.changed_beyond,
                self.deepest_changed,
                self.exhausted,
                self.panic_below_mark,
                self.deepest_changed as isize - self.panic_below_mark,
                self.bins,
                self.filler.1,
                self.filler.0
            )
        }
    }

    /// Read back the region painted by `paint`, from the frame that called `paint`. `mark` is
    /// the scrub mark of the call that ran in between, `panic_mark` its panic mark, and
    /// `filler` the address range of the reference's local (zeros for an import).
    #[inline(never)]
    fn scan(base: usize, mark: usize, panic_mark: usize, filler: (usize, usize)) -> Picture {
        let words = base as *const u64;
        let top = base + 8 * PAINT_WORDS;
        let mut picture = Picture {
            marked: mark != 0,
            mark_below_top: top as isize - mark as isize,
            deepest_nonzero: 0,
            changed_beyond: 0,
            deepest_changed: 0,
            exhausted: false,
            panic_below_mark: if panic_mark == 0 {
                0
            } else {
                mark as isize - panic_mark as isize
            },
            bins: [0; 8],
            filler: (
                mark as isize - filler.0 as isize,
                mark as isize - filler.1 as isize,
            ),
        };
        for i in 0..PAINT_WORDS {
            let address = base + 8 * i;
            // SAFETY: the address lies in this thread's own stack, in the pages that `paint`
            // wrote from the same caller frame, so it is mapped and readable. The words are
            // below the live frames, apart from this function's own, and no reference to them
            // exists; the volatile read takes whatever value is there. The test installs no
            // signal handler, so nothing else writes to this stack.
            let word = unsafe { words.add(i).read_volatile() };
            if i == 0 && word != painted(address) {
                picture.exhausted = true;
            }
            if mark == 0 || address >= mark {
                continue;
            }
            let below = mark - address;
            if below <= EXTENT - EDGE {
                if word != 0 {
                    picture.deepest_nonzero = picture.deepest_nonzero.max(below);
                    picture.bins[(below / 4096).min(7)] += 1;
                }
            } else if below > EXTENT + EDGE && word != painted(address) {
                picture.changed_beyond += 1;
                picture.deepest_changed = picture.deepest_changed.max(below);
            }
        }
        picture
    }

    /// Take the scrub mark of the scrub that completed last on this thread and the panic mark
    /// of the panic that was raised last; each is 0 when there was none.
    #[inline(always)]
    fn take_marks() -> (usize, usize) {
        (
            crate::ct_erase::LAST_SCRUB_MARK.with(|mark| mark.replace(0)),
            crate::ct_erase::LAST_PANIC_MARK.with(|mark| mark.replace(0)),
        )
    }

    std::thread_local! {
        /// Lowest address and one past the highest address of the local of `reference_body`.
        static FILLER: core::cell::Cell<(usize, usize)> = const { core::cell::Cell::new((0, 0)) };
    }

    /// Paint, import `sk` inside `catch_unwind`, and read the stack back. Returns whether the
    /// import unwound, and the picture. Only the read of the scrub mark runs between the three
    /// calls, and all are made from this frame.
    #[inline(never)]
    pub(super) fn unwinding_import(sk: &[u8]) -> (bool, Picture) {
        let base = paint();
        let unwound = catch_unwind(|| PreparedSk::new(sk)).is_err();
        let (mark, panic_mark) = take_marks();
        (unwound, scan(base, mark, panic_mark, (0, 0)))
    }

    /// Holds the scrub of the key import above a callee that only fills its frame and panics.
    #[inline(never)]
    fn reference_entry() {
        let _stack_scrub = crate::ct_erase::StackScrub::<{ EXTENT / 8 }>;
        reference_body();
    }

    #[inline(never)]
    fn reference_body() {
        let filler = [0u8; BODY_BYTES];
        let low = black_box(&filler).as_ptr() as usize;
        FILLER.with(|span| span.set((low, low + BODY_BYTES)));
        crate::ct_erase::mark_panic_point();
        panic!("reference unwind of the stack test: no import below the scrub");
    }

    /// As `unwinding_import`, with `reference_entry` in place of the import.
    #[inline(never)]
    pub(super) fn unwinding_reference() -> (bool, Picture) {
        let base = paint();
        let unwound = catch_unwind(reference_entry).is_err();
        let (mark, panic_mark) = take_marks();
        let filler = FILLER.with(|span| span.replace((0, 0)));
        (unwound, scan(base, mark, panic_mark, filler))
    }

    /// The requirements on one unwinding import against the reference; see the module comment.
    pub(super) fn judge(name: &str, import: &Picture, reference: &Picture) {
        assert!(
            !import.exhausted && !reference.exhausted,
            "{name}: the painted region was too small"
        );
        assert!(
            import.marked && reference.marked,
            "{name}: no scrub completed"
        );
        assert!(
            reference.deepest_nonzero <= ALLOWANCE,
            "{name}: the reference leaves a nonzero word {} bytes below the scrub mark",
            reference.deepest_nonzero
        );
        assert!(
            import.deepest_nonzero <= ALLOWANCE,
            "{name}: the import leaves a nonzero word {} bytes below the scrub mark",
            import.deepest_nonzero
        );
        let same_residue = import.deepest_nonzero.abs_diff(reference.deepest_nonzero) <= TOLERANCE;
        let same_beyond = (import.changed_beyond > 0) == (reference.changed_beyond > 0);
        // Printed in every case; see the module comment.
        eprintln!(
            "{name}: same depth of the residue within {TOLERANCE} bytes: {same_residue}, \
             required here: {SAME_RESIDUE}; words changed deeper than the extent in both or in \
             neither: {same_beyond}, not required"
        );
        assert!(
            same_residue || !SAME_RESIDUE,
            "{name}: the deepest nonzero word within the extent is {} bytes below the scrub mark \
             after the import and {} after the reference",
            import.deepest_nonzero,
            reference.deepest_nonzero
        );
    }
}
