//! Stack painting around the import of a stored secret key.
//!
//! This file is a module of `tests/api.rs` in `crates/pretzel-4-4`, in `crates/pretzel-3-3` and in
//! `crates/pretzel-5-5`. Each crate supplies its own names through `use super::*` and passes the
//! extent that its import erases. It is compiled only with the Cargo feature `stack-wipe` of the
//! crate: without the feature nothing zeroes a range of stack.
//!
//! A measuring function fills 524288 bytes of stack directly below its own frame with a pattern
//! that depends on the address, calls `PreparedSk::new` of the crate root, and reads the same
//! bytes back. With the feature `PreparedSk::new` zeroes a fixed extent of stack below its own
//! frame before it returns, on success and when it rejects the key, so the test requires, for
//! every call:
//!
//! 1. every word from `ALLOWANCE` bytes to the extent below the measuring frame is zero: nothing
//!    that the import body or its callees wrote there is left, and the paint is gone;
//! 2. the paint deeper than the extent plus twice `ALLOWANCE` is intact: nothing was written
//!    there by the import or by the scrub. The band between the extent and that depth is not
//!    judged.
//!
//! The calls are imports of valid keys and of five invalid encodings of each key, which the
//! import rejects at different points: before reading the key, while decoding the secret
//! coefficients, and at the public-key hash check after the secret arithmetic.
//!
//! Without the scrub the first requirement fails on every call: a rejected key leaves the paint,
//! and a parsed key leaves about a hundred kilobytes of the frames of the import.
//!
//! What the test does not show: anything about registers; the content of the first `ALLOWANCE`
//! bytes, which hold the frame of `PreparedSk::new`, which keeps the scrub guard, and the frames
//! of its callers down from the test; an import that unwinds, which the timing lifetime tests of
//! the library observe; and any build other than the optimized one, whose frame sizes the extent
//! is chosen for. It is one finite observation of one image, not a bound on the stack depth of
//! the import.
use super::*;
use std::hint::black_box;

type Imported = Result<PreparedSk, Error>;

/// Words painted below the measuring frame before each call: 524288 bytes.
const PAINT_WORDS: usize = 65536;
/// Bytes directly below the measuring frame that the test does not judge. They hold what is live
/// while the scrub runs or is written after it: the frames of the crate-root entry and of
/// `PreparedSk::new`, the registers that the scrub routine saves on entry, the call that restores
/// the timing state after the scrub, and the frame of `scan`.
const ALLOWANCE: usize = 4096;
const PATTERN: u64 = 0x5ca7_c4ed_a5a5_5a5a;
/// Keys generated for the test.
const KEYS: usize = 4;
/// Judged imports of each valid key.
const CALLS: usize = 32;

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
    /// Distance in bytes below the top of the painted region of the deepest word within the
    /// extent that is not zero; 0 when every such word is zero.
    deepest_nonzero: usize,
    /// Words deeper than the extent plus twice ALLOWANCE that no longer hold their paint.
    changed_beyond: usize,
}

/// Read back the region painted by `paint`. Called from the frame that called `paint`, so the
/// region is where the frames of the import lay.
#[inline(never)]
fn scan(base: usize, extent: usize) -> Picture {
    let words = base as *const u64;
    let mut picture = Picture::default();
    for i in 0..PAINT_WORDS {
        // Distance in bytes from the top of the painted region to the low end of word `i`.
        let depth = 8 * (PAINT_WORDS - i);
        // SAFETY: the address lies in this thread's own stack, in the pages that `paint` wrote
        // from the same caller frame, so it is mapped and readable. The words are below the live
        // frames, apart from this function's own, and no reference to them exists; the volatile
        // read takes whatever value is there. The test installs no signal handler, so nothing
        // else writes to this stack.
        let word = unsafe { words.add(i).read_volatile() };
        if depth <= extent && word != 0 {
            picture.deepest_nonzero = picture.deepest_nonzero.max(depth);
        }
        if depth > extent + 2 * ALLOWANCE && word != painted(base + 8 * i) {
            picture.changed_beyond += 1;
        }
    }
    picture
}

/// `PreparedSk::new` of the crate root.
#[inline(never)]
fn import(sk: &[u8]) -> Imported {
    PreparedSk::new(sk)
}

/// Paint, import `sk` once, and read the stack back. Nothing runs between the three calls, and
/// all three are made from this frame.
#[inline(never)]
fn measure(sk: &[u8], extent: usize) -> (Imported, Picture) {
    let base = paint();
    let imported = import(sk);
    let picture = scan(base, extent);
    (imported, picture)
}

/// Five encodings that the import rejects, made from the valid key `sk`. A stored key is a
/// 14-byte format tag, the 32-byte matrix seed, the packed secret coefficients (two bits each),
/// the 32-byte hashing key, the 32-byte hash of the public key and a 32-byte public seed.
fn invalid_encodings(sk: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let size = sk.len();
    let mut tag = sk.to_vec();
    tag[0] ^= 1;
    // The two-bit code 3 is not a secret coefficient.
    let mut coefficient = sk.to_vec();
    coefficient[14 + 32] |= 3;
    let mut hash = sk.to_vec();
    hash[size - 64] ^= 1;
    vec![
        ("an empty key", Vec::new()),
        ("a key one byte short", sk[..size - 1].to_vec()),
        ("a changed format tag", tag),
        ("a secret coefficient code that is not allowed", coefficient),
        ("a changed public-key hash", hash),
    ]
}

fn judge(name: &str, picture: &Picture, deepest: &mut usize) {
    assert!(
        picture.deepest_nonzero <= ALLOWANCE,
        "{name}: a nonzero word is left {} bytes below the measuring frame",
        picture.deepest_nonzero
    );
    assert_eq!(
        picture.changed_beyond, 0,
        "{name}: words were written deeper than the erased extent"
    );
    *deepest = (*deepest).max(picture.deepest_nonzero);
}

fn run(extent: usize) {
    assert!(8 * PAINT_WORDS >= extent + 16 * ALLOWANCE);
    let ctx = Ctx::new();
    let mut deepest = 0usize;
    for key in 0..KEYS {
        let pair = keygen(&ctx).expect("key generation");
        if key == 0 {
            // The first calls on this thread run one-time lookups, which are not part of the
            // import body. Their pictures are not judged.
            for _ in 0..4 {
                let (imported, _) = measure(&pair.sk, extent);
                assert!(imported.is_ok(), "the import of a valid key failed");
                let (rejected, _) = measure(&pair.sk[..1], extent);
                assert!(rejected.is_err(), "a one-byte key was accepted");
            }
        }
        for _ in 0..CALLS {
            let (imported, picture) = measure(&pair.sk, extent);
            let Ok(sk) = imported else {
                panic!("the import of a valid key failed");
            };
            judge("a valid key", &picture, &mut deepest);
            assert!(sk.public_key() == pair.pk.as_slice());
        }
        for (name, encoding) in invalid_encodings(&pair.sk) {
            let (imported, picture) = measure(&encoding, extent);
            assert!(
                matches!(imported, Err(Error::KeyFormat)),
                "{name}: not rejected as a key-format error"
            );
            judge(name, &picture, &mut deepest);
        }
    }
    println!("key import: deepest nonzero word {deepest} bytes below the measuring frame");
}

/// Run the measurement on a thread with a stack of known size. `extent` is the number of bytes
/// that `PreparedSk::new` of the crate erases below its own frame.
pub(super) fn check(extent: usize) {
    let worker = std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(move || run(extent))
        .expect("spawn the measuring thread");
    worker.join().expect("the measuring thread failed");
}
