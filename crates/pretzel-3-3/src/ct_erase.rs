//! Private owners for plain word arrays with one full-capacity erase.
//! The allocation is never exposed or resized. All lengths are public.
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{compiler_fence, Ordering};

/// Byte view of exclusively borrowed, initialized word storage. The caller
/// normally supplies a stack array. Drop erases the complete backing slice,
/// including any unused byte suffix, through the word eraser.
///
/// The borrow keeps the backing storage in place while the byte view exists.
/// This only erases that backing storage; it does not claim to erase other
/// register or compiler-generated copies of values read from the view.
pub(crate) struct StackByteGuard<'a> {
    words: &'a mut [u64],
}
impl<'a> StackByteGuard<'a> {
    #[inline(always)]
    pub(crate) fn new(words: &'a mut [u64]) -> Self {
        Self { words }
    }
}
impl Deref for StackByteGuard<'_> {
    type Target = [u8];
    #[inline(always)]
    fn deref(&self) -> &[u8] {
        // SAFETY: u64 slices are initialized, have no element padding, and
        // every byte pattern is a valid u8. The returned immutable view is
        // bounded by the exact backing extent and by this borrow of self.
        unsafe {
            core::slice::from_raw_parts(
                self.words.as_ptr().cast(),
                core::mem::size_of_val(self.words),
            )
        }
    }
}
impl DerefMut for StackByteGuard<'_> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, with exclusive access to both the guard and its
        // borrowed words. No other live byte/word view can overlap this one.
        unsafe {
            core::slice::from_raw_parts_mut(
                self.words.as_mut_ptr().cast(),
                core::mem::size_of_val(self.words),
            )
        }
    }
}
impl Drop for StackByteGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: the backing slice is exclusively borrowed, writable,
        // eight-byte aligned, and exactly words.len() words long. Empty
        // slices are allowed; the eraser performs no writes in that case.
        unsafe {
            erase_struct_words(self.words.as_mut_ptr(), self.words.len());
        }
    }
}

pub(crate) struct Words<const N: usize> {
    words: Vec<[u64; N]>,
}
impl<const N: usize> Words<N> {
    pub(crate) fn new(len: usize) -> Self {
        assert!(N != 0, "word owner requires a nonzero array width");
        Self {
            words: vec![[0; N]; len],
        }
    }
    /// Owner without storage (no allocation); the place holder left behind
    /// when a reader's prefix is moved back into the signing scratch pool.
    pub(crate) fn empty() -> Self {
        assert!(N != 0, "word owner requires a nonzero array width");
        Self { words: Vec::new() }
    }
    /// Erase the whole allocation now (the destructor erases it again).
    #[inline(always)]
    pub(crate) fn erase(&mut self) {
        self.erase_allocation();
    }
    #[inline(always)]
    fn erase_allocation(&mut self) {
        // Vec's allocation bounds imply capacity*N*8 <= isize::MAX.
        // u64 arrays have no padding, all-zero is valid, and spare capacity
        // can be written without first reading its uninitialized contents.
        let count = self.words.capacity() * N;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: this owner has exclusive access to the entire allocation.
        // Even when count is zero, the pointer remains aligned and no store
        // is performed. This helper writes exactly count words, using the
        // public extent; it never reads any old buffer contents.
        unsafe {
            erase_words(self.words.as_mut_ptr().cast(), count);
        }
        compiler_fence(Ordering::SeqCst);
    }
}
impl<const N: usize> Clone for Words<N> {
    fn clone(&self) -> Self {
        Self {
            words: self.words.clone(),
        }
    }
}
impl<const N: usize> Deref for Words<N> {
    type Target = [[u64; N]];
    fn deref(&self) -> &Self::Target {
        &self.words
    }
}
impl<const N: usize> DerefMut for Words<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.words
    }
}
impl<const N: usize> Drop for Words<N> {
    fn drop(&mut self) {
        self.erase_allocation();
        // Normal field destruction now releases the same Vec allocation.
        // Its plain u64 elements have no element destructor or second wipe.
    }
}

/// Erase `count` words of a caller-owned plain-integer object.
/// SAFETY (caller): exclusive, writable, eight-byte aligned, `count` words long.
///
/// # Safety
///
/// `ptr` must be aligned for `u64` and valid for writes of `count` 8-byte words that nothing else
/// accesses during the call, and all-zero bytes must be a valid value for the object that owns
/// them. The words need not be initialized. With `count == 0` no access is made.
#[inline(always)]
pub(crate) unsafe fn erase_struct_words(ptr: *mut u64, count: usize) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: the arguments are forwarded unchanged to `erase_words`, which has the same contract
    // as this function.
    unsafe {
        erase_words(ptr, count);
    }
    compiler_fence(Ordering::SeqCst);
}

/// # Safety
///
/// `ptr` must be aligned for `u64` and valid for writes of `count` 8-byte words that nothing else
/// accesses during the call, and all-zero bytes must be a valid value for the object that owns
/// them. The words need not be initialized. With `count == 0` no access is made.
#[inline(always)]
unsafe fn erase_words(ptr: *mut u64, count: usize) {
    // SAFETY: forwarded exclusive pointer and writable public word count.
    unsafe {
        pretzel33_ct_erase_words(ptr, count);
    }
}

core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel33_ct_erase_words\n.p2align 2\n_pretzel33_ct_erase_words:\n",
        include_str!("../../pretzel-4-4/core/src/ct_erase_words.S")
    ),
    options(raw)
);
// SAFETY: contract of the assembly routine defined just above (the rank-four file
// `ct_erase_words.S` under this crate's symbol name). It stores zero to exactly `count` 8-byte
// words starting at `ptr` (64-byte groups, then word pairs, then one word) and reads no memory.
// `count` may be zero. It is a leaf routine with no stack use, changes only x0 to x2 and the flags,
// keeps no pointer and has no global state. It uses base AArch64 instructions only.
unsafe extern "C" {
    fn pretzel33_ct_erase_words(ptr: *mut u64, count: usize);
}

// Stack-range wipes, compiled only with the Cargo feature `stack-wipe`. Without it
// none of the items from here to the end of the included file exists.
//
// 72 KiB below the frame that calls the retry loop of the signer. The signing
// body (the retry loop, one attempt and their callees) was measured 29440 bytes
// deep below that frame in an optimized program and 37600 bytes in the optimized
// unit-test build of this crate. Measured on those builds, not bounded, and not
// a bound on entropy callbacks or future builds. Recheck the depth when the
// compiler, the target or the signing code changes.
#[cfg(feature = "stack-wipe")]
pub(crate) const SIGN_SCRUB_WORDS: usize = 9216;

// 384 KiB below the frame of `PreparedSk::new`, which holds the scrub of the key
// import. The import was measured 109832 bytes deep in an optimized program and
// 219088 bytes deep in the optimized unit-test build of this crate, about twice
// as deep. The depth is measured on those builds, not bounded, and it is the
// depth of an import that returns: a panic inside the import runs the panic
// handler below its frames, possibly deeper than the extent. Recheck the depth
// when the compiler, the target or the import code changes.
#[cfg(feature = "stack-wipe")]
pub(crate) const IMPORT_SCRUB_WORDS: usize = 49152;

// Unit-test images keep the scrub mark: the address of a local of the function below,
// which runs when a scrub has completed and lies directly below the frame that holds the
// scrub. The stack tests measure depths from it.
#[cfg(all(test, feature = "stack-wipe"))]
std::thread_local! {
    pub(crate) static LAST_SCRUB_MARK: core::cell::Cell<usize> =
        const { core::cell::Cell::new(0) };
    pub(crate) static LAST_PANIC_MARK: core::cell::Cell<usize> =
        const { core::cell::Cell::new(0) };
}

// Unit-test images keep the panic mark: the address of a local of the function that is about
// to raise a panic for a test. The stack tests measure from it what the panic wrote below.
#[cfg(all(test, feature = "stack-wipe"))]
#[inline(always)]
pub(crate) fn mark_panic_point() {
    let local = 0u8;
    let mark = core::hint::black_box(&local) as *const u8 as usize;
    let _ = LAST_PANIC_MARK.try_with(|slot| slot.set(mark));
}

// Unit-test images with the DIT trace record completion of the stack scrub.
#[cfg(all(test, feature = "stack-wipe"))]
fn observe_stack_scrub() {
    let local = 0u8;
    let mark = core::hint::black_box(&local) as *const u8 as usize;
    let _ = LAST_SCRUB_MARK.try_with(|slot| slot.set(mark));
    crate::timing_state::test_support::observe("stack-scrub");
}

// The scrub of the rank-four backend, compiled here with this crate's word eraser.
#[cfg(feature = "stack-wipe")]
include!("../../pretzel-4-4/core/src/stack_scrub.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_byte_guard_erases_the_full_borrowed_extent_and_preserves_sentinels() {
        for words in [0, 1, 2, 3, 20, 52, 320] {
            for offset in [2, 3] {
                let mut backing = [0x0123_4567_89ab_cdefu64; 325];
                {
                    let mut bytes = StackByteGuard::new(&mut backing[offset..offset + words]);
                    assert_eq!(bytes.len(), words * 8);
                    // Leave an initialized but unused suffix, as in the
                    // sampler's final partial group; Drop must erase it too.
                    let used = bytes.len() / 2;
                    bytes[..used].fill(0xa5);
                    assert!(bytes[..used].iter().all(|&x| x == 0xa5));
                }
                assert!(backing[..offset]
                    .iter()
                    .all(|&x| x == 0x0123_4567_89ab_cdef));
                assert!(backing[offset..offset + words].iter().all(|&x| x == 0));
                assert!(backing[offset + words..]
                    .iter()
                    .all(|&x| x == 0x0123_4567_89ab_cdef));
            }
        }
    }

    #[test]
    fn stack_byte_guard_erases_on_unwind() {
        let mut words = [u64::MAX; 20];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut bytes = StackByteGuard::new(&mut words);
            bytes[..17].fill(0xa5);
            panic!("exercise stack byte guard unwind");
        }));
        assert!(result.is_err());
        assert!(words.iter().all(|&x| x == 0));
    }
    #[test]
    fn erases_exact_extent_at_both_word_alignments() {
        for n in [
            0, 1, 2, 3, 7, 8, 15, 16, 17, 511, 512, 1023, 1024, 4095, 4096,
        ] {
            for offset in [2, 3] {
                let mut storage = vec![0x123456789abcdef0u64; n + offset + 2];
                unsafe {
                    erase_words(storage.as_mut_ptr().add(offset), n);
                }
                assert!(storage[..offset].iter().all(|&x| x == 0x123456789abcdef0));
                assert!(storage[offset..offset + n].iter().all(|&x| x == 0));
                assert!(storage[offset + n..]
                    .iter()
                    .all(|&x| x == 0x123456789abcdef0));
            }
        }
    }
    #[test]
    fn erases_initialized_and_spare_capacity_without_changing_shape() {
        fn check<const N: usize>() {
            for (len, capacity) in [
                (0, 0),
                (0, 7),
                (1, 1),
                (1, 17),
                (8, 8),
                (8, 19),
                (256, 300),
                (1024, 1031),
            ] {
                let mut words = Vec::with_capacity(capacity);
                words.resize(len, [u64::MAX; N]);
                let cap = words.capacity();
                // Initialize spare words for observation in this test only.
                for i in len..cap {
                    unsafe {
                        words.as_mut_ptr().add(i).write([u64::MAX; N]);
                    }
                }
                let mut owner = Words { words };
                let address = owner.words.as_ptr();
                owner.erase_allocation();
                assert_eq!(owner.len(), len);
                assert_eq!(owner.words.capacity(), cap);
                assert_eq!(owner.words.as_ptr(), address);
                for i in 0..cap {
                    assert_eq!(unsafe { *address.add(i) }, [0; N]);
                }
                // The normal destructor remains responsible for freeing it.
            }
        }
        check::<1>();
        check::<2>();
        check::<4>();
    }
    #[test]
    #[should_panic(expected = "nonzero array width")]
    fn zero_width_owner_is_rejected() {
        let _ = Words::<0>::new(0);
    }
}

/// An allocation whose entire capacity is already erased. This owner has no
/// mutable dereference and no constructor accepting an arbitrary Vec.
/// It can become writable only by consuming it into Words, whose destructor
/// erases. Thus freeing this clean owner requires no second erasure pass.
pub(crate) struct ErasedWords<const N: usize> {
    words: Vec<[u64; N]>,
}
impl<const N: usize> ErasedWords<N> {
    pub(crate) fn new(len: usize) -> Self {
        assert!(N != 0);
        let mut words = vec![[0u64; N]; len];
        // Initialized elements are zero by construction. Explicitly erase
        // spare capacity too; do not assume Vec capacity equals length.
        let initialized = words.len() * N;
        let spare = (words.capacity() - words.len()) * N;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: the `Vec` allocation holds `capacity * N` aligned `u64` slots. `initialized = len
        // * N` and `spare = (capacity - len) * N` partition it, so the erased range is the unused
        // suffix, which only this function can reach and which has no validity requirement. With
        // `spare == 0` the routine makes no access.
        unsafe {
            erase_words(words.as_mut_ptr().cast::<u64>().add(initialized), spare);
        }
        compiler_fence(Ordering::SeqCst);
        Self { words }
    }
    pub(crate) fn empty() -> Self {
        assert!(N != 0);
        Self { words: Vec::new() }
    }
    pub(crate) fn into_words(self) -> Words<N> {
        Words { words: self.words }
    }
}
impl<const N: usize> Deref for ErasedWords<N> {
    type Target = [[u64; N]];
    fn deref(&self) -> &Self::Target {
        &self.words
    }
}
impl<const N: usize> Words<N> {
    pub(crate) fn into_erased(mut self) -> ErasedWords<N> {
        self.erase_allocation();
        // The ordinary Words destructor sees an empty owner; the erased
        // allocation moves without copying any payload.
        ErasedWords {
            words: core::mem::take(&mut self.words),
        }
    }
}
#[cfg(test)]
mod erased_owner_tests {
    use super::*;
    #[test]
    fn clean_transfer_covers_spare_capacity_and_preserves_allocation() {
        assert_eq!(
            core::mem::size_of::<Words<17>>(),
            core::mem::size_of::<ErasedWords<17>>()
        );
        for n in [0, 1, 7, 19, 20] {
            let mut dirty = Words::<17>::new(n);
            dirty.words.reserve(7);
            let len = dirty.words.len();
            let cap = dirty.words.capacity();
            let ptr = dirty.words.as_mut_ptr();
            unsafe {
                for j in 0..cap * 17 {
                    ptr.cast::<u64>().add(j).write(0x9d29cb437145dfe1);
                }
            }
            let clean = dirty.into_erased();
            assert_eq!(
                (
                    clean.words.as_ptr(),
                    clean.words.len(),
                    clean.words.capacity()
                ),
                (ptr as *const _, len, cap)
            );
            unsafe {
                assert!(
                    core::slice::from_raw_parts(clean.words.as_ptr().cast::<u64>(), cap * 17)
                        .iter()
                        .all(|&v| v == 0)
                );
            }
            let mut dirty = clean.into_words();
            for row in dirty.iter_mut() {
                row.fill(0xffffffffff);
            }
            let clean = dirty.into_erased();
            unsafe {
                assert!(
                    core::slice::from_raw_parts(clean.words.as_ptr().cast::<u64>(), cap * 17)
                        .iter()
                        .all(|&v| v == 0)
                );
            }
        }
    }
}
