// Value-preserving stack scrub for private entry points. The three crates include
// this file only with their Cargo feature `stack-wipe`, which is off by default.
// Callee frames below an entry (sampler middle16, geometry refine, Keccak/XOF,
// the signer frame itself) can keep private-derived data after return.
// A StackScrub guard is created at the entry and its Drop, on normal return and
// on unwinding, calls scrub_stack from the entry frame, directly above the
// out-of-line private body. scrub_stack owns a fresh WORDS-word local region,
// which therefore lies over the stack the body used, and zeroes it with the word
// eraser. It writes only its own local, so no output value can change.
// The including crate chooses each public extent and defines
// observe_stack_scrub, the test-only completion event. Coverage of all callee
// frames requires depth validation on the emitted image; a fixed extent alone
// does not establish coverage. Registers and live caller frames are not erased.
#[inline(never)]
pub(crate) fn scrub_stack<const WORDS: usize>() {
    let mut region = core::mem::MaybeUninit::<[u64; WORDS]>::uninit();
    // SAFETY: exclusive local storage, eight-byte aligned, exactly WORDS words.
    unsafe {
        erase_struct_words(region.as_mut_ptr().cast::<u64>(), WORDS);
    }
    core::hint::black_box(&region);
}

pub(crate) struct StackScrub<const WORDS: usize>;
impl<const WORDS: usize> Drop for StackScrub<WORDS> {
    #[inline(always)]
    fn drop(&mut self) {
        scrub_stack::<WORDS>();
        // Observe completion of the real scrub, never a substitute eraser.
        #[cfg(test)]
        observe_stack_scrub();
    }
}
