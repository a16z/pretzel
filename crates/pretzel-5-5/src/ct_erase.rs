//! Erasure helpers and guards for plain word storage. All lengths are public.
use core::sync::atomic::{compiler_fence, Ordering};

/// Erase `count` words of a caller-owned plain-integer object.
#[inline(always)]
/// # Safety
/// ptr must cover count writable u64 words in one live allocation, aligned to eight bytes, with
/// exclusive access and a representable byte extent. The storage may be uninitialized; it must permit
/// an all-zero representation and contain no live pointer/reference values invalidated by erasure.
pub(crate) unsafe fn erase_struct_words(ptr: *mut u64, count: usize) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: The caller supplies an exclusive, writable, eight-byte-aligned region of count u64
    // words. Forwarding the same pointer and count preserves erase_words' contract.
    unsafe {
        erase_words(ptr, count);
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline(always)]
/// # Safety
/// ptr must cover count writable u64 words in one live allocation, aligned to eight bytes, with
/// exclusive access and a representable byte extent. The storage may be uninitialized and must permit
/// zeroing; the implementation writes without reading it.
unsafe fn erase_words(ptr: *mut u64, count: usize) {
    // SAFETY: forwarded exclusive pointer and writable public word count.
    // The caller supplies count writable, eight-byte-aligned words. The AArch64 helper in
    // crates/pretzel-4-4/core/src/ct_erase_words.S writes pairs then a possible final word,
    // checks zero count, and never reads the uninitialized contents.
    unsafe {
        pretzel55_ct_erase_words(ptr, count);
    }
}

#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel55_ct_erase_words\n.p2align 2\n_pretzel55_ct_erase_words:\n",
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
    fn pretzel55_ct_erase_words(ptr: *mut u64, count: usize);
}

// Stack-range wipes, compiled only with the Cargo feature `stack-wipe`. Without it
// none of the items from here to the end of the included file exists.
//
// Scrub extents: signing 64 KiB, key generation 128 KiB, preparation 384 KiB.
// The macOS release-image depth gate of key generation requires a further 32 KiB
// margin. The extents of signing and preparation are checked against measured
// depths of particular builds, not against a bound.
#[cfg(feature = "stack-wipe")]
pub(crate) const SIGN_SCRUB_WORDS: usize = 8192;
#[cfg(feature = "stack-wipe")]
pub(crate) const KEYGEN_SCRUB_WORDS: usize = 16384;
#[cfg(feature = "stack-wipe")]
pub(crate) const PREPARE_SCRUB_WORDS: usize = 49152;

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
    #[cfg(target_os = "macos")]
    crate::timing_state::test_support::observe("stack-scrub");
}

#[cfg(feature = "stack-wipe")]
include!("../../pretzel-4-4/core/src/stack_scrub.rs");

#[cfg(test)]
mod tests {
    use super::*;

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
}

// Zero-initialized owners, identical extent/lifetime, fenced eraser.
pub(crate) mod zeroed_owners {
    use core::ops::{Deref, DerefMut};
    macro_rules! owner {
        ($name:ident, $element:ty) => {
            #[repr(C, align(8))]
            pub(crate) struct $name<const N: usize>([$element; N]);
            impl<const N: usize> $name<N> {
                pub(crate) fn zero() -> Self {
                    const {
                        assert!(N * core::mem::size_of::<$element>() % 8 == 0);
                    }
                    Self([0; N])
                }
            }
            impl<const N: usize> Deref for $name<N> {
                type Target = [$element; N];
                fn deref(&self) -> &Self::Target {
                    &self.0
                }
            }
            impl<const N: usize> DerefMut for $name<N> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    &mut self.0
                }
            }
            impl<const N: usize> Drop for $name<N> {
                fn drop(&mut self) {
                    // All bit patterns valid; exclusive, 8-byte aligned owner.
                    // Its extent is a multiple of 8, with no tail padding.
                    // SAFETY: The repr(C, align(8)) owner contains only integers; zero() asserts its
                    // byte extent is divisible by eight. Drop exclusively owns those bytes, so
                    // N*size_of::<element>()/8 word stores remain within the initialized array.
                    unsafe {
                        super::erase_struct_words(
                            self.0.as_mut_ptr().cast(),
                            N * core::mem::size_of::<$element>() / 8,
                        );
                    }
                }
            }
        };
    }
    owner!(I16, i16);
    owner!(I32, i32);

    #[cfg(test)]
    mod tests {
        use super::*;
        use core::mem::ManuallyDrop;
        // Keep backing storage alive for observation while retiring the owner
        // in-place through the same Drop implementation, including unwinding.
        struct Retire(*mut I32<1536>);
        impl Drop for Retire {
            fn drop(&mut self) {
                unsafe {
                    core::ptr::drop_in_place(self.0);
                }
            }
        }
        #[test]
        fn head_retirement_on_error_and_unwind() {
            for unwind in [false, true] {
                let mut storage = ManuallyDrop::new(I32::<1536>::zero());
                let p = core::ptr::addr_of_mut!(storage).cast::<I32<1536>>();
                let caught =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), ()> {
                        let _retire = Retire(p);
                        unsafe {
                            (&mut *p).fill(-17);
                        }
                        if unwind {
                            panic!("public test panic");
                        }
                        Err(())
                    }));
                if unwind {
                    assert!(caught.is_err());
                } else {
                    assert_eq!(caught.unwrap(), Err(()));
                }
                let bytes = core::ptr::addr_of!(storage).cast::<i32>();
                unsafe {
                    for i in 0..1536 {
                        assert_eq!(bytes.add(i).read_volatile(), 0);
                    }
                }
            }
        }

        #[test]
        fn full_ntt_and_head_erasure_preserves_neighbors() {
            #[repr(C)]
            struct Framed {
                before: [u64; 2],
                value: ManuallyDrop<I32<1536>>,
                after: [u64; 2],
            }
            let mut f = Framed {
                before: [17; 2],
                value: ManuallyDrop::new(I32::zero()),
                after: [23; 2],
            };
            f.value.fill(-1);
            unsafe {
                ManuallyDrop::drop(&mut f.value);
                let p = core::ptr::addr_of!(f.value).cast::<i32>();
                // Storage remains allocated in ManuallyDrop; read integer bytes,
                // without forming a reference to the dropped owner.
                for i in 0..1536 {
                    assert_eq!(p.add(i).read_volatile(), 0);
                }
            }
            assert_eq!(f.before, [17; 2]);
            assert_eq!(f.after, [23; 2]);
            let mut ntt = ManuallyDrop::new(I16::<256>::zero());
            ntt.fill(1234);
            unsafe {
                ManuallyDrop::drop(&mut ntt);
                let p = core::ptr::addr_of!(ntt).cast::<i16>();
                for i in 0..256 {
                    assert_eq!(p.add(i).read_volatile(), 0);
                }
            }
        }
    }
}
