//! Exact full-extent clearing, including unaligned byte owners and padding.
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel55_proposal_retire_bytes\n.p2align 2\n_pretzel55_proposal_retire_bytes:\n",
        include_str!("retirement.S")
    ),
    options(raw)
);
// SAFETY: contract of the assembly routine defined just above (retirement.S). It stores zero to
// exactly the `bytes` bytes starting at `ptr` (byte stores up to an 8-byte boundary, then 64-byte,
// 16-byte and 8-byte groups and a byte tail) and reads no memory. It accepts any alignment and
// `bytes == 0`, uses no stack and no SIMD register, changes only x0 to x2 and the flags, keeps no
// pointer and has no global state, so concurrent calls on disjoint ranges are independent. It uses
// base AArch64 instructions only.
unsafe extern "C" {
    fn pretzel55_proposal_retire_bytes(ptr: *mut u8, bytes: usize);
}

/// SAFETY: exclusive writable allocation of at least `bytes` bytes, with no
/// live overlapping references. Alignment is unrestricted. No bytes are read.
///
/// # Safety
///
/// `ptr` must be valid for writes of `bytes` bytes and no reference to that range may be live
/// during the call. Any alignment is accepted and `bytes` may be zero. Zero must be a valid value
/// for whatever the range holds afterwards.
pub(crate) unsafe fn erase(ptr: *mut u8, bytes: usize) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: the caller guarantees that `ptr` is valid for writes of `bytes` bytes with no live
    // reference to them, which is the whole contract of the routine.
    unsafe {
        pretzel55_proposal_retire_bytes(ptr, bytes);
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proposal_retirement_exact_extents_and_alignments() {
        for n in [
            0, 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 65, 136, 10944, 16560, 27504,
        ] {
            for offset in 0..16 {
                let mut memory = vec![0xa5u8; n + offset + 16];
                // SAFETY: `memory` has `n + offset + 16` bytes, so the pointer at `offset` is valid
                // for writes of `n` bytes; no reference to the vector is live during the call.
                unsafe {
                    erase(memory.as_mut_ptr().add(offset), n);
                }
                assert!(memory[..offset].iter().all(|x| *x == 0xa5));
                assert!(memory[offset..offset + n].iter().all(|x| *x == 0));
                assert!(memory[offset + n..].iter().all(|x| *x == 0xa5));
            }
        }
    }
}
