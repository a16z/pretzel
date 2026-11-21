//! Exclusive reusable attempt buffers. No key, entropy or signature caching.
use crate::params::{M, N};
use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Gaussian draw scratch: one public sixteen-row group for direct dyadic
/// or exact alias streaming, otherwise the longest of the three mask streams.
pub(crate) const DRAW_ROWS: usize = 16;
const _: () = assert!(DRAW_ROWS == 16 || DRAW_ROWS == 32 || N <= DRAW_ROWS);
/// Signature staging buffer, padded to whole words for the wide erase.
pub(crate) const SIG_PAD: usize = 3104;

/// Length in words of `Buffers::dither_records`.
pub(crate) const RECORD_WORDS: usize = 1034;
pub(crate) const RECORD_RANK: usize = 1032;
#[repr(C, align(8))]
pub(crate) struct Buffers {
    pub(crate) commitment: [crate::ring::Poly; M],
    pub(crate) labels: [i32; M * N],
    pub(crate) label_bytes: [u8; M * N],
    pub(crate) xs: [i32; M * N],
    pub(crate) hints: [i32; M * N],
    pub(crate) residual: [i32; M * N],
    // Constant-time attempt workspaces of `sign_attempt` that are kept
    // in the scratch: allocated with the scratch and erased with the lease
    // after every attempt. The function keeps its other workspaces on its stack.
    // At this parameter set it does not use `draws` and `classified`.
    /// The two workspaces of the mask sampler (`records` and `work` of
    /// `Cdt::sample_rare_into`). The dither expansion that their names refer to is
    /// compiled for tests only (`ct_dither.rs`).
    pub(crate) dither_records: [u32; RECORD_WORDS],
    pub(crate) dither_next: [u32; crate::ct_dither::NETWORK],
    /// Slot routing network, two stages of N records.
    pub(crate) slot_records: [crate::ct_slots::Record; crate::ct_slots::FIRST_ROWS],
    pub(crate) slot_next: [crate::ct_slots::Record; crate::ct_slots::SECOND_ROWS],
    /// Gaussian uniforms and their classifications, one stream at a time.
    pub(crate) draws: [[u64; 4]; DRAW_ROWS],
    pub(crate) classified: [[u64; 2]; DRAW_ROWS],
    /// Encoded signature of the attempt; copied out only after the public
    /// abort decision accepts it.
    pub(crate) sig: [u8; SIG_PAD],
}

#[repr(C, align(8))]
struct Storage {
    attempt: Buffers,
}

/// Zero-initialized heap storage without a stack temporary of the full size.
fn zeroed_storage() -> Box<Storage> {
    let layout = std::alloc::Layout::new::<Storage>();
    // SAFETY: `Storage` holds plain integer arrays only (repr(C), no padding
    // requirements beyond eight-byte alignment), so the all-zero bit pattern
    // is a valid value; a null result aborts through the standard handler.
    unsafe {
        let p = std::alloc::alloc_zeroed(layout);
        if p.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        Box::from_raw(p.cast::<Storage>())
    }
}
impl Zeroize for Buffers {
    fn zeroize(&mut self) {
        // Plain integer fields without padding (repr(C), sizes multiples of
        // eight): one wide fixed-count store loop over the whole struct.
        {
            const _: () = assert!(core::mem::size_of::<Buffers>() % 8 == 0);
            // SAFETY: exclusive access to an initialized plain-integer struct
            // aligned to eight bytes; every byte written is inside it.
            unsafe {
                crate::ct_erase::erase_struct_words(
                    self as *mut Buffers as *mut u64,
                    core::mem::size_of::<Buffers>() / 8,
                );
            }
        }
    }
}

/// Caller-owned signing workspace, reusable across keys and messages.
///
/// One fixed-size heap allocation, no Clone or Debug. Signing requires an
/// exclusive mutable borrow, so safe Rust cannot sign concurrently or
/// reentrantly using this workspace. Use a separate workspace per concurrent
/// operation. Ctx and prepared keys remain immutable and shareable.
///
/// The selected buffers are erased after EVERY attempt, including failure and
/// panic unwinding, and on drop. This is not whole-process memory erasure:
/// compiler temporaries, registers, unrelated locals, aborting panics, process
/// termination and forgotten/leaked allocations are outside that guarantee.
///
/// Simultaneous aliases cannot be passed to signing in safe Rust:
/// ```compile_fail,E0499
/// use pretzel_3_3::{Ctx, PreparedSk, SigningScratch, sign_prepared_with_scratch};
/// fn conflicting(ctx: &Ctx, key: &PreparedSk, scratch: &mut SigningScratch) {
///     let first = &mut *scratch;
///     let second = &mut *scratch;
///     let _ = sign_prepared_with_scratch(ctx, key, first, b"", b"one");
///     let _ = sign_prepared_with_scratch(ctx, key, second, b"", b"two");
/// }
/// ```
pub struct SigningScratch {
    storage: Box<Storage>,
    /// Prefix storage of the six scheduled tape streams (per call, not per attempt).
    pool: crate::guarded_drop::GuardedDrop<crate::ct_stream_schedule::PrefixPool>,
}
impl SigningScratch {
    /// Heap payload of the fixed-size block, excluding allocator metadata, the
    /// owning pointer and the scheduled prefix pool.
    pub const PAYLOAD_BYTES: usize = std::mem::size_of::<Storage>();
    pub fn new() -> Self {
        Self {
            storage: zeroed_storage(),
            pool: crate::guarded_drop::GuardedDrop::new(
                crate::ct_stream_schedule::PrefixPool::new(),
            ),
        }
    }
    pub(crate) fn lease(&mut self) -> Lease<'_> {
        Lease {
            attempt: &mut self.storage.attempt,
            pool: &mut self.pool,
        }
    }

    #[cfg(test)]
    pub(crate) fn poison(&mut self) {
        for row in &mut self.storage.attempt.commitment {
            row.0.fill(i32::MIN);
        }
        self.storage.attempt.labels.fill(i32::MIN);
        self.storage.attempt.label_bytes.fill(0xff);
        self.storage.attempt.xs.fill(i32::MAX);
        self.storage.attempt.hints.fill(-999);
        self.storage.attempt.residual.fill(999);
        {
            let b = &mut self.storage.attempt;
            b.dither_records.fill(7);
            b.dither_next.fill(9);
            b.slot_records.fill([5; crate::ct_slots::WORDS]);
            b.slot_next.fill([6; crate::ct_slots::WORDS]);
            b.draws.fill([1; 4]);
            b.classified.fill([2; 2]);
            b.sig.fill(0xa5);
        }
    }
    #[allow(dead_code)]
    pub(crate) fn is_erased(&self) -> bool {
        if !self.pool.is_erased() {
            return false;
        }
        let b = &self.storage.attempt;
        if b.commitment.iter().any(|row| row.0.iter().any(|&x| x != 0)) {
            return false;
        }
        if b.dither_records
            .iter()
            .chain(&b.dither_next)
            .any(|&x| x != 0)
            || b.slot_records
                .iter()
                .chain(&b.slot_next)
                .flatten()
                .any(|&x| x != 0)
            || b.draws.iter().flatten().any(|&x| x != 0)
            || b.classified.iter().flatten().any(|&x| x != 0)
            || b.sig.iter().any(|&x| x != 0)
        {
            return false;
        }
        b.labels
            .iter()
            .chain(&b.xs)
            .chain(&b.hints)
            .chain(&b.residual)
            .all(|&x| x == 0)
            && b.label_bytes.iter().all(|&x| x == 0)
    }
}
impl Default for SigningScratch {
    fn default() -> Self {
        Self::new()
    }
}
impl Zeroize for SigningScratch {
    fn zeroize(&mut self) {
        // Also covers explicit clearing and scratch dropped after the signing
        // guard (cold/reentrant calls, TLS teardown and caller-owned scratch).
        // Erase even on enable failure: all writes are value-independent.
        let _timing_state = crate::timing_state::Guard::enter().ok();
        self.storage.attempt.zeroize();
    }
}
impl Drop for SigningScratch {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for SigningScratch {}

pub(crate) struct Lease<'a> {
    attempt: &'a mut Buffers,
    pool: &'a mut crate::ct_stream_schedule::PrefixPool,
}
impl Lease<'_> {
    /// The attempt buffers and the scheduled prefix pool, borrowed together.
    pub(crate) fn with_pool(
        &mut self,
    ) -> (&mut Buffers, &mut crate::ct_stream_schedule::PrefixPool) {
        (self.attempt, self.pool)
    }
}
impl Deref for Lease<'_> {
    type Target = Buffers;
    fn deref(&self) -> &Buffers {
        self.attempt
    }
}
impl DerefMut for Lease<'_> {
    fn deref_mut(&mut self) -> &mut Buffers {
        self.attempt
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.attempt.zeroize();
    }
}
