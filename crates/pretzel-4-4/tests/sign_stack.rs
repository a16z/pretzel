//! Stack painting around prepared-key signing.
//!
//! This file is a module of `tests/api.rs` in `crates/pretzel-4-4` and in `crates/pretzel-3-3`.
//! Each crate supplies its own names through `use super::*`. It is compiled only with the Cargo
//! feature `stack-wipe` of the crate: without the feature nothing zeroes a range of stack.
//!
//! A measuring function fills 262144 bytes of stack directly below its own frame with a pattern
//! that depends on the address, calls a prepared-key signing entry of the crate root, and reads
//! the same bytes back. With the feature the signer zeroes 73728 bytes of stack below the
//! function that calls its retry loop before it returns, so the test requires, for every call:
//!
//! 1. every word from `ALLOWANCE` bytes to 73728 bytes below the measuring frame is zero: nothing
//!    that the retry loop, an attempt or their callees wrote there is left, and the paint is gone;
//! 2. a run of at least `MIN_ZERO_RUN` zero bytes exists;
//! 3. the paint deeper than 73728 bytes plus twice `ALLOWANCE` is intact: the signer did not go
//!    deeper than the erased extent, and the scrub wrote nothing far outside it.
//!
//! Without the scrub the first two fail, because signing leaves tens of kilobytes of its frames in
//! that range.
//!
//! What the test does not show: anything about registers; the content of the first `ALLOWANCE`
//! bytes, which hold the frame of the function that keeps the scrub guard and the frames of its
//! callers down from the test; the frames of secret-key import, which signing from a serialized
//! key runs before the prepared-key entry; and any build other than the optimized one, whose frame
//! sizes the extent is chosen for. It is one finite observation of one image, not a bound on the
//! stack depth of signing.
use super::*;
use std::hint::black_box;

type Signed = Result<(Vec<u8>, u32), Error>;

/// Bytes of stack that prepared-key signing zeroes below the function that calls its retry loop.
const EXTENT: usize = 73728;
/// Words painted below the measuring frame before each call: 262144 bytes.
const PAINT_WORDS: usize = 32768;
/// Bytes directly below the measuring frame that the test does not judge. They hold what is live
/// while the scrub runs or is written after it: the frames of the crate-root entry and of the
/// function that keeps the scrub guard, the registers that the scrub routine saves on entry, the
/// call that restores the timing state after the scrub, and the frame of `scan`. The entry frames
/// are about 450 to 560 bytes in the optimized image; 1024 leaves room for a different inlining.
const ALLOWANCE: usize = 1024;
/// Shortest run of zero bytes accepted as the trace of the scrub. The signing body is deeper than
/// this, so its frames cannot contain such a run unless they were erased.
const MIN_ZERO_RUN: usize = 28000;
const PATTERN: u64 = 0x5ca7_c4ed_a5a5_5a5a;
/// Measured calls for each entry.
const CALLS: usize = 256;

#[inline(always)]
fn painted(address: usize) -> u64 {
    PATTERN ^ address as u64
}

/// Fill PAINT_WORDS words directly below the caller's frame and return the lowest address. The
/// function is out of line, so the words stay painted after it returns.
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

#[derive(Default)]
struct Picture {
    /// Longest run of zero bytes in the painted region, counted in whole words.
    zero_run: usize,
    /// Distance in bytes below the top of the painted region of the deepest word within EXTENT
    /// that is not zero; 0 when every such word is zero.
    deepest_nonzero: usize,
    /// Words deeper than EXTENT plus twice ALLOWANCE that no longer hold their paint.
    changed_beyond: usize,
}

/// Read back the region painted by `paint`. Called from the frame that called `paint`, so the
/// region is where the frames of the signing call lay.
#[inline(never)]
fn scan(base: usize) -> Picture {
    let words = base as *const u64;
    let mut picture = Picture::default();
    let mut run = 0usize;
    for i in 0..PAINT_WORDS {
        // Distance in bytes from the top of the painted region to the low end of word `i`.
        let depth = 8 * (PAINT_WORDS - i);
        // SAFETY: the address lies in this thread's own stack, in the pages that `paint` wrote
        // from the same caller frame, so it is mapped and readable. The words are below the live
        // frames, apart from this function's own, and no reference to them exists; the volatile
        // read takes whatever value is there. The test installs no signal handler, so nothing
        // else writes to this stack.
        let word = unsafe { words.add(i).read_volatile() };
        if word == 0 {
            run += 8;
            picture.zero_run = picture.zero_run.max(run);
        } else {
            run = 0;
            if depth <= EXTENT {
                picture.deepest_nonzero = picture.deepest_nonzero.max(depth);
            }
        }
        if depth > EXTENT + 2 * ALLOWANCE && word != painted(base + 8 * i) {
            picture.changed_beyond += 1;
        }
    }
    picture
}

#[derive(Clone, Copy)]
enum Entry {
    CallerScratch,
    CrateScratch,
}

/// `sign_prepared_with_scratch` of the crate root: prepared key, workspace owned by the caller.
#[inline(never)]
fn sign_with_caller_scratch(
    ctx: &Ctx,
    sk: &PreparedSk,
    scratch: &mut SigningScratch,
    message: &[u8],
) -> Signed {
    sign_prepared_with_scratch(ctx, sk, scratch, b"", message)
}

/// `sign_prepared_with_stats` of the crate root: prepared key, workspace chosen by the crate.
#[inline(never)]
fn sign_with_crate_scratch(ctx: &Ctx, sk: &PreparedSk, message: &[u8]) -> Signed {
    sign_prepared_with_stats(ctx, sk, message)
}

/// Paint, sign once through `entry`, and read the stack back. Nothing runs between the three
/// calls, and all three are made from this frame.
#[inline(never)]
fn measure(
    entry: Entry,
    ctx: &Ctx,
    sk: &PreparedSk,
    scratch: &mut SigningScratch,
    message: &[u8],
) -> (Signed, Picture) {
    let base = paint();
    let signed = match entry {
        Entry::CallerScratch => sign_with_caller_scratch(ctx, sk, scratch, message),
        Entry::CrateScratch => sign_with_crate_scratch(ctx, sk, message),
    };
    let picture = scan(base);
    (signed, picture)
}

fn run(require_retry: bool) {
    let ctx = Ctx::new();
    let pair = keygen(&ctx).expect("key generation");
    let sk = PreparedSk::new(&pair.sk).expect("secret-key import");
    let mut scratch = SigningScratch::new();
    for (entry, name) in [
        (Entry::CallerScratch, "sign_prepared_with_scratch"),
        (Entry::CrateScratch, "sign_prepared_with_stats"),
    ] {
        // The first calls on this thread run one-time lookups and set up thread-local storage,
        // which are not part of the signing body. Their pictures are not judged.
        for _ in 0..4 {
            let (signed, _) = measure(entry, &ctx, &sk, &mut scratch, b"first calls");
            assert!(signed.is_ok(), "{name}: signing failed");
        }
        let mut retries = 0u32;
        let mut deepest = 0usize;
        for call in 0..CALLS {
            let message = vec![call as u8; [0, 32, 136, 1024][call % 4]];
            let (signed, picture) = measure(entry, &ctx, &sk, &mut scratch, &message);
            let (signature, attempts) = signed.expect("signing");
            assert!(
                picture.deepest_nonzero <= ALLOWANCE,
                "{name}: a nonzero word is left {} bytes below the measuring frame",
                picture.deepest_nonzero
            );
            assert!(
                picture.zero_run >= MIN_ZERO_RUN,
                "{name}: the longest zeroed run is {} bytes",
                picture.zero_run
            );
            assert_eq!(
                picture.changed_beyond, 0,
                "{name}: words were written deeper than the erased extent"
            );
            if call < 8 {
                verify(&ctx, &pair.pk, &message, &signature).expect("verification");
            }
            if attempts > 1 {
                retries += 1;
            }
            deepest = deepest.max(picture.deepest_nonzero);
        }
        assert!(
            !require_retry || retries > 0,
            "{name}: no call with a rejected attempt among {CALLS} calls"
        );
        println!("{name}: deepest nonzero word {deepest} bytes below the measuring frame");
    }
}

/// Run the measurement on a thread with a stack of known size. `require_retry` also requires at
/// least one call with a rejected attempt for each entry.
pub(super) fn check(require_retry: bool) {
    let worker = std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(move || run(require_retry))
        .expect("spawn the measuring thread");
    worker.join().expect("the measuring thread failed");
}
