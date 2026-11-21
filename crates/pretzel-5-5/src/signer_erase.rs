//! Erasure dispatch for explicitly signer-owned storage only.
//! Shared owners and the verifier use ct_erase and pretzel55_ct_erase_words.

use core::sync::atomic::{compiler_fence, Ordering};

/// Same exclusive, writable, eight-byte aligned, full-extent contract as
/// ct_erase::erase_struct_words. The addresses and word count are public.
#[inline(always)]
/// # Safety
/// ptr must cover count writable u64 words in one live allocation, aligned to eight bytes, exclusively
/// accessible and with a representable nonwrapping byte extent. Storage may be uninitialized but must
/// permit zeroing. The AArch64 helper checks DCZID_EL0 before using DC ZVA.
pub(crate) unsafe fn erase_struct_words(ptr: *mut u64, count: usize) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: forwarded caller contract. The eraser zeros only complete interior
    // cache blocks, with word stores at both ends and its store-loop fallback.
    // The caller supplies count writable, eight-byte-aligned words in one exclusive
    // allocation. signer_erase_words_zva.S reads DCZID_EL0 and uses DC ZVA only when permitted with
    // 64-byte blocks wholly inside that region; scalar prefix/tail and fallback stores cover only the
    // requested words.
    unsafe {
        pretzel55_signer_erase_words_zva(ptr, count);
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel55_signer_erase_words_zva\n.p2align 2\n_pretzel55_signer_erase_words_zva:\n",
        include_str!("signer_erase_words_zva.S")
    ),
    options(raw)
);
// SAFETY: contract of the assembly routine defined just above (`signer_erase_words_zva.S`). It
// stores zero to exactly `count` 8-byte words starting at `ptr` and reads none of them. `ptr` must
// be aligned for `u64`. When `DCZID_EL0` allows it with a 64-byte block, whole 64-byte blocks
// inside the range are cleared with `DC ZVA`; otherwise plain stores are used. It is a leaf routine
// with no stack use, changes only x0 to x5 and the flags, keeps no pointer and has no global state.
// Base AArch64 instructions only.
unsafe extern "C" {
    fn pretzel55_signer_erase_words_zva(ptr: *mut u64, count: usize);
}

// The stack-range wipe of the signer, compiled only with the Cargo feature
// `stack-wipe`. Identical local extent and retirement lifetime to StackScrub.
// A distinct function prevents changing the verifier or key-preparation roots.
#[cfg(feature = "stack-wipe")]
#[inline(never)]
fn scrub_stack<const WORDS: usize>() {
    let mut region = core::mem::MaybeUninit::<[u64; WORDS]>::uninit();
    // SAFETY: exclusive local, eight-byte aligned, exactly WORDS words long.
    unsafe {
        erase_struct_words(region.as_mut_ptr().cast::<u64>(), WORDS);
    }
    core::hint::black_box(&region);
}

#[cfg(feature = "stack-wipe")]
pub(crate) struct StackScrub<const WORDS: usize>;
#[cfg(feature = "stack-wipe")]
impl<const WORDS: usize> Drop for StackScrub<WORDS> {
    #[inline(always)]
    fn drop(&mut self) {
        scrub_stack::<WORDS>();
    }
}

#[cfg(test)]
#[path = "signer_erase_tests.rs"]
mod tests;
