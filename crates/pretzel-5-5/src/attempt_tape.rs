//! Paired expansion of the attempt tapes.
use crate::{
    challenge::Challenge,
    ct_slots::{Positions, Record, FIRST_ROWS, SECOND_ROWS},
    params::N,
};
use core::{
    mem::MaybeUninit,
    sync::atomic::{compiler_fence, Ordering},
};
use pretzel_5_5_proposal::conditional_initial::Workspace;
use zeroize::Zeroizing;
pub(crate) const DOMAIN: &[u8] = b"PRETZEL-FAST55-W075-Q64-FIXED10-attempt-v1";
/// Reusable allocation capacity only; no record array duplicates the slots.
#[repr(C)]
pub(crate) struct Storage {
    work: MaybeUninit<Workspace>,
    entropy: [u8; 10944],
    transport: [u8; 6144],
}
impl Storage {
    #[cfg(test)]
    pub(crate) fn lease(storage: &mut MaybeUninit<Self>) -> Lease<'_> {
        // Entire extent zeroed directly, without constructing a large stack value.
        unsafe {
            storage
                .as_mut_ptr()
                .cast::<u8>()
                .write_bytes(0, core::mem::size_of::<Self>());
        }
        Lease {
            storage: unsafe { storage.assume_init_mut() },
        }
    }
}
pub(crate) struct Lease<'a> {
    storage: &'a mut Storage,
}
const _: () = {
    assert!(core::mem::align_of::<Storage>() >= core::mem::align_of::<u64>());
    assert!(core::mem::size_of::<Storage>().is_multiple_of(core::mem::size_of::<u64>()));
};
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        // Exclusive owner, aligned base and whole extent established above.
        // Retain volatile stores for every byte, including padding and entropy.
        // SAFETY: Storage has the asserted u64 alignment and size divisible by eight. This lease
        // exclusively borrows the whole allocation; the eraser only writes zero and does not read
        // MaybeUninit contents or padding.
        unsafe {
            crate::signer_erase::erase_struct_words(
                (self.storage as *mut Storage).cast::<u64>(),
                core::mem::size_of::<Storage>() / 8,
            );
        }
        compiler_fence(Ordering::SeqCst);
    }
}
/// One-shot proposal followed by delayed slots after the challenge exists.
/// Attempt lease owns both tape buffers. External z/records remain under caller lease.
pub(crate) struct PendingSlots<'a> {
    transport: &'a mut [u8; 6144],
}
impl Lease<'_> {
    pub(crate) fn proposal<E, F: FnOnce(&mut [u8; 64]) -> Result<(), E>>(
        &mut self,
        key: &[u8; 32],
        mu: &[u8],
        attempt: u32,
        fill: F,
        z: &mut [i32; 2816],
        abort: &mut u64,
    ) -> Result<PendingSlots<'_>, E> {
        z.fill(0);
        let mut seed = Zeroizing::new([0u8; 64]);
        if let Err(e) = fill(&mut seed) {
            *abort = u64::MAX;
            return Err(e);
        }
        let retry = attempt.to_le_bytes();
        let transport = &mut self.storage.transport;
        let bad = pretzel_5_5_proposal::conditional_initial::generate(
            |out| {
                crate::shake2::expand_attempt_balanced(
                    DOMAIN,
                    &[b"coretail10944-balanced-A-v1", key, mu, &retry, &*seed],
                    &[
                        b"coretail10944-transport6144-balanced-B-v1",
                        key,
                        mu,
                        &retry,
                        &*seed,
                    ],
                    out,
                    transport,
                );
                Ok::<(), core::convert::Infallible>(())
            },
            &mut self.storage.entropy,
            &mut self.storage.work,
            z,
        )
        .unwrap();
        *abort |= crate::ct::opaque_mask(0u64.wrapping_sub(crate::ct::opaque_mask(u64::from(bad))));
        Ok(PendingSlots { transport })
    }
}
impl PendingSlots<'_> {
    pub(crate) fn slots<'a>(
        self,
        c: &Challenge,
        records: &'a mut [Record; FIRST_ROWS],
        next: &'a mut [Record; SECOND_ROWS],
        base: &[i32; N],
    ) -> Positions<'a> {
        let mut cursor = 0;
        let out = Positions::new_iid384_with_fill(
            c,
            |dst| {
                let end = cursor + dst.len();
                dst.copy_from_slice(&self.transport[cursor..end]);
                cursor = end;
            },
            records,
            next,
            Some(base),
        );
        assert_eq!(cursor, 6144);
        out
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    #[test]
    fn storage_retirement_and_fresh_lease() {
        let mut owner = Box::<Storage>::new_uninit();
        for byte in [0xa5u8, 0x5a] {
            {
                let lease = Storage::lease(&mut owner);
                assert!(lease.storage.entropy.iter().all(|&v| v == 0));
                lease.storage.entropy.fill(byte);
                lease.storage.transport.fill(byte);
                unsafe {
                    lease
                        .storage
                        .work
                        .as_mut_ptr()
                        .cast::<u8>()
                        .write_bytes(byte, core::mem::size_of::<Workspace>());
                }
            }
            // Entry writes the complete extent, and Drop writes it again. Padding is
            // therefore initialized, so inspecting these owned bytes is valid.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    owner.as_ptr().cast::<u8>(),
                    core::mem::size_of::<Storage>(),
                )
            };
            assert!(bytes.iter().all(|&v| v == 0));
        }
    }
}

#[cfg(test)]
mod paired_storage_tests {
    use super::*;
    #[test]
    fn paired_transport_buffer_erased_on_unwind() {
        let mut owner = Box::<Storage>::new_uninit();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let lease = Storage::lease(&mut owner);
            lease.storage.transport.fill(0xa5);
            lease.storage.entropy.fill(0x5a);
            panic!("injected paired storage panic");
        }));
        assert!(result.is_err());
        let bytes = unsafe {
            core::slice::from_raw_parts(
                owner.as_ptr().cast::<u8>(),
                core::mem::size_of::<Storage>(),
            )
        };
        assert!(bytes.iter().all(|&b| b == 0));
    }
}

pub(crate) struct InitializedStorage(Box<MaybeUninit<Storage>>);

impl InitializedStorage {
    pub(crate) fn new() -> Self {
        let mut storage = Box::<Storage>::new_uninit();
        // Full-extent clear, exactly once.
        // SAFETY: Box::new_uninit allocates size_of::<Storage>() writable bytes with Storage
        // alignment. This unique owner zeros the entire allocation, including padding; Storage
        // contains MaybeUninit<Workspace> and byte arrays, for which zero is valid.
        unsafe {
            storage
                .as_mut_ptr()
                .cast::<u8>()
                .write_bytes(0, core::mem::size_of::<Storage>());
        }
        Self(storage)
    }

    pub(crate) fn lease(&mut self) -> Lease<'_> {
        // Only Lease can write private data. Its Drop clears the
        // entire allocation on success, rejection, errors and unwinding.
        // The exclusive borrow prevents overlapping leases. No raw storage
        // accessor or lease-without-Drop path is exposed by this owner.
        Lease {
            // SAFETY: new() initialized the full Storage allocation; its fields are
            // MaybeUninit<Workspace> and byte arrays. The private owner exposes only exclusive leases
            // and its retirement preserves valid storage, so this initialized mutable view lasts only
            // for the lease.
            storage: unsafe { self.0.assume_init_mut() },
        }
    }
}

#[cfg(test)]
mod noncore_storage_tests {
    use super::*;
    const BEFORE: u64 = 0x127543679abbcdef;
    const AFTER: u64 = 0xfedcba9876543210;

    fn dirty(lease: &mut Lease<'_>, byte: u8) {
        unsafe {
            (lease.storage as *mut Storage)
                .cast::<u8>()
                .write_bytes(byte, core::mem::size_of::<Storage>());
        }
    }
    fn zero(storage: &MaybeUninit<Storage>) -> bool {
        unsafe {
            core::slice::from_raw_parts(
                storage.as_ptr().cast::<u8>(),
                core::mem::size_of::<Storage>(),
            )
        }
        .iter()
        .all(|&b| b == 0)
    }

    #[test]
    fn entire_extent_and_canaries_on_normal_and_unwind() {
        #[repr(C)]
        struct Frame {
            before: [u64; 2],
            value: MaybeUninit<Storage>,
            after: [u64; 2],
        }
        let mut frame = Box::new(Frame {
            before: [BEFORE; 2],
            value: MaybeUninit::uninit(),
            after: [AFTER; 2],
        });
        for panic in [false, true] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut lease = Storage::lease(&mut frame.value);
                dirty(&mut lease, 0xa5);
                if panic {
                    panic!("injected outer storage unwind");
                }
            }));
            assert_eq!(result.is_err(), panic);
            assert!(zero(&frame.value));
            assert_eq!(frame.before, [BEFORE; 2]);
            assert_eq!(frame.after, [AFTER; 2]);
        }
    }

    #[test]
    fn fresh_retry_error_and_unwind_have_identical_zero_entry() {
        let mut storage = InitializedStorage::new();
        for attempt in 0..512 {
            assert!(zero(&storage.0));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut lease = storage.lease();
                assert!(lease.storage.entropy.iter().all(|&b| b == 0));
                assert!(lease.storage.transport.iter().all(|&b| b == 0));
                dirty(&mut lease, (attempt % 255 + 1) as u8);
                if attempt == 257 {
                    panic!("injected reusable owner unwind");
                }
                Err::<(), u8>(9)
            }));
            if attempt == 257 {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap(), Err(9));
            }
            assert!(zero(&storage.0));
        }
    }
}

// `SigningScratch` holds `InitializedStorage` for its whole lifetime. The owner
// is all-zero at construction and after every Lease Drop (success, rejection,
// error and unwind), so every lease starts at zero without a per-call clear.

impl InitializedStorage {
    /// Full-extent erase, used by `SigningScratch` zeroize and Drop. The extent
    /// is already zero whenever no lease is live; this is an added retirement.
    pub(crate) fn erase(&mut self) {
        // SAFETY: exclusive owner of an eight-byte aligned allocation whose
        // size is a multiple of eight (asserted above for Storage).
        unsafe {
            crate::signer_erase::erase_struct_words(
                self.0.as_mut_ptr().cast::<u64>(),
                core::mem::size_of::<Storage>() / 8,
            );
        }
    }
    pub(crate) fn is_zero(&self) -> bool {
        // SAFETY: `self.0` owns `size_of::<Storage>()` bytes. `new` writes zero over all of them,
        // padding included. The only other writers are a `Lease`, whose `Drop` rewrites the whole
        // extent with zero words before the exclusive borrow taken by `lease` ends, and `erase`,
        // which writes zero words. With `&self` no lease is live, so every byte is initialized and
        // the slice may view them as `u8`. This needs every lease to be dropped (a lease leaked
        // with `core::mem::forget` skips the rewrite), and nothing in this crate forgets a lease.
        unsafe {
            core::slice::from_raw_parts(
                self.0.as_ptr().cast::<u8>(),
                core::mem::size_of::<Storage>(),
            )
        }
        .iter()
        .all(|&b| b == 0)
    }
}

#[cfg(test)]
mod aux_scratch_storage_tests {
    use super::*;

    #[test]
    fn scratch_owned_storage_has_zero_entry_across_calls_errors_and_unwind() {
        let mut scratch = crate::scratch::SigningScratch::new();
        for call in 0..64 {
            for attempt in 0..4 {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let (_buffers, lease) = scratch.lease_pair();
                    assert!(lease.storage.entropy.iter().all(|&b| b == 0));
                    assert!(lease.storage.transport.iter().all(|&b| b == 0));
                    unsafe {
                        (&mut *lease.storage as *mut Storage)
                            .cast::<u8>()
                            .write_bytes(0xa5 ^ attempt as u8, core::mem::size_of::<Storage>());
                    }
                    if call == 33 && attempt == 2 {
                        panic!("injected scratch storage unwind");
                    }
                    Err::<(), u8>(1)
                }));
                if call == 33 && attempt == 2 {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap(), Err(1));
                }
                assert!(scratch.attempt_storage_is_zero());
            }
        }
        {
            let (_buffers, lease) = scratch.lease_pair();
            unsafe {
                (&mut *lease.storage as *mut Storage)
                    .cast::<u8>()
                    .write_bytes(0x3c, core::mem::size_of::<Storage>());
            }
        }
        assert!(scratch.attempt_storage_is_zero());
        assert!(scratch_is_erased_after_zeroize(&mut scratch));
    }

    fn scratch_is_erased_after_zeroize(scratch: &mut crate::scratch::SigningScratch) -> bool {
        use zeroize::Zeroize;
        scratch.zeroize();
        scratch.attempt_storage_is_zero()
    }
}
