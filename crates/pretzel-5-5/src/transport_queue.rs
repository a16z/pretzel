//! Transport queue of the signer: the `Prepared` values and the dispatcher that `bound_batch`
//! runs for every signing attempt.
use crate::ct_slots::{Positions, Record};
use core::sync::atomic::{compiler_fence, Ordering};
// Identity value barrier.
#[inline(always)]
fn opaque_mask(mut value: u64) -> u64 {
    // SAFETY: The AArch64 gate of build.rs selects a supported register class. Comment-only asm preserves the
    // initialized inout value, memory, stack and flags; all register effects are declared. It is
    // deliberately not pure.
    unsafe {
        core::arch::asm!("/* {value} */",value=inout(reg)value,options(nomem,nostack,preserves_flags));
    }
    value
}
#[inline(always)]
fn predicate(bit: bool) -> u64 {
    opaque_mask(bit as u64)
}
#[inline(always)]
fn mask(bit: bool) -> u64 {
    opaque_mask(0u64.wrapping_sub(bit as u64))
}
#[inline(always)]
fn select(m: u64, a: u64, b: u64) -> u64 {
    let m = opaque_mask(m);
    b ^ ((a ^ b) & m)
}
pub(crate) struct Prepared {
    b: u64,
    fine: pretzel_5_5_transport_decision::Prepared,
    coarse: crate::ct_interval_transport::Prepared,
}
impl Prepared {
    pub(crate) fn new(b: u64) -> Option<Self> {
        Some(Self {
            b,
            fine: pretzel_5_5_transport_decision::prepare(b)?,
            coarse: crate::ct_interval_transport::Prepared::new(b),
        })
    }
    pub(crate) fn coarse(&self) -> &[i64; 12] {
        self.coarse.coarse_coefficients()
    }
}
// The fine object contains private key-derived coefficients; explicit retirement.
impl Drop for Prepared {
    fn drop(&mut self) {
        #[cfg(all(test, target_os = "macos"))]
        crate::timing_state::test_support::observe("highprecision-drop");
        // SAFETY: samplers/transport-decision/src/lib.rs defines pretzel_5_5_transport_decision::Prepared as repr(C), a u64 followed by 58
        // [u64;6] coefficients. Zero is valid for every field and there is no destructor; Drop
        // exclusively owns this region and writes exactly size_of::<Prepared>() bytes.
        unsafe {
            let p = (&mut self.fine as *mut pretzel_5_5_transport_decision::Prepared).cast::<u8>();
            for i in 0..core::mem::size_of::<pretzel_5_5_transport_decision::Prepared>() {
                p.add(i).write_volatile(0);
            }
        }
        // SAFETY: Drop has exclusive access to the live initialized u64 field b. Its naturally aligned
        // address remains valid for this single volatile zero store.
        unsafe {
            core::ptr::write_volatile(&mut self.b, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Saved {
    slot: u64,
    a: i64,
    x: i64,
    live: u64,
}
const ZERO: Saved = Saved {
    slot: 0,
    a: 0,
    x: 0,
    live: 0,
};
/// Fixed capacities; records are borrowed, never copied or redrawn.
/// Caller supplies slots from the one-shot IID384 PendingSlots constructor.
pub(crate) struct State<'a> {
    records: &'a [Record],
    geometry: [Saved; 13],
    correction: [Saved; 10],
    ng: u64,
    nc: u64,
    abort: u64,
}
impl<'a> State<'a> {
    pub(crate) fn new(slots: &'a Positions<'_>) -> Self {
        assert_eq!(slots.record_slice().len(), 128);
        Self {
            records: slots.record_slice(),
            geometry: [ZERO; 13],
            correction: [ZERO; 10],
            ng: 0,
            nc: 0,
            abort: 0,
        }
    }
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn push<const C: usize>(
        queue: &mut [Saved; C],
        rank: &mut u64,
        abort: &mut u64,
        marked: bool,
        slot: usize,
        a: i64,
        x: i64,
    ) {
        let marked = predicate(marked);
        let valid = (predicate(slot < 128) & predicate(a.unsigned_abs() <= i32::MAX as u64))
            & predicate(x >= -848)
            & predicate(x <= 296263654);
        *abort |=
            opaque_mask(0u64.wrapping_sub(marked & (predicate(*rank >= C as u64) | (valid ^ 1))));
        // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. queue exclusively borrows C initialized
        // Saved values; push_queue visits each value within its four repr(C) 64-bit fields. Rank
        // only selects register masks, and marked & valid is a bit, including on rejected inputs.
        unsafe {
            queue_neon::push_queue(queue, *rank, marked & valid, slot as u64, a, x);
        }
        *rank = rank.wrapping_add(marked);
    }
    /// Locator proposal n must satisfy the distance<1 contract.
    pub(crate) fn defer_geometry(&mut self, marked: bool, slot: usize, n: i64) {
        Self::push(
            &mut self.geometry,
            &mut self.ng,
            &mut self.abort,
            marked,
            slot,
            0,
            n,
        );
    }
    /// Save precoin a and resolved X before subsequent optimistic state updates.
    pub(crate) fn defer_correction(&mut self, marked: bool, slot: usize, a: i64, x: i64) {
        Self::push(
            &mut self.correction,
            &mut self.nc,
            &mut self.abort,
            marked,
            slot,
            a,
            x,
        );
    }
    fn coin(&self, slot: u64) -> [u64; 6] {
        // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. coin checks records.len()==128 before its
        // loads; Record has eight initialized u64 words under this profile, and slot selects register
        // masks rather than memory addresses.
        unsafe { queue_neon::coin(self.records, slot) }
    }
    /// Semantic refinement adapter only. No native locator/caller batch replacement.
    /// Writes results by full scan so saved slot never indexes private memory.
    pub(crate) fn finish_geometry(&mut self, out: &mut [i64; 128]) -> u64 {
        let magnitudes =
            zeroize::Zeroizing::new(core::array::from_fn(|j| self.geometry[j].x.unsigned_abs()));
        let mut prefixes = pretzel_5_5_transport_locator::Prefixes::zeroed();
        pretzel_5_5_transport_locator::prefix13(&magnitudes, &mut prefixes);
        for j in 0..13 {
            let q = self.geometry[j];
            let mut raw = self.coin(q.slot);
            let r = pretzel_5_5_transport_locator::refine_prefixed(&raw, q.x, prefixes.get(j));
            self.abort |= q.live & mask(r.bad);
            // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. out is an exclusive [i64;128], and
            // scatter traverses it in pairs without using q.slot as an address; all lane inputs are
            // initialized values.
            unsafe {
                queue_neon::scatter(out, q.slot, q.live, r.value);
            }
            clear_coin(&mut raw);
        }
        self.abort
    }
    /// Full joint rejection is !fine && !union, not merely !fine.
    pub(crate) fn finish_correction_semantic(&mut self, p: &Prepared) -> u64 {
        for j in 0..10 {
            let q = self.correction[j];
            let mut raw = self.coin(q.slot);
            let accepted = pretzel_5_5_transport_decision::decide(&p.fine, q.a, &raw);
            let plus = union(q.x, p, q.a.unsigned_abs());
            self.abort |=
                q.live & opaque_mask(0u64.wrapping_sub(predicate(!accepted) & predicate(!plus)));
            clear_coin(&mut raw);
        }
        self.abort
    }
}
fn union_reference(x: i64, b: u64, t: u64) -> bool {
    let mut index = 0u64;
    for step in [32, 16, 8, 4, 2, 1] {
        let j = index + step;
        let e = j * (b * j + 2 * t);
        index += step * predicate((e as i64) < x);
    }
    (predicate((index & 1) != 0) & predicate(x > 0)) != 0
}
fn clear_coin(raw: &mut [u64; 6]) {
    for x in raw {
        // SAFETY: Each x is an exclusive borrow of one initialized u64 in the six-word raw array. The
        // aligned volatile store writes that word while its allocation remains live.
        unsafe {
            core::ptr::write_volatile(x, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}
impl Drop for State<'_> {
    fn drop(&mut self) {
        for q in self.geometry.iter_mut().chain(self.correction.iter_mut()) {
            // SAFETY: Saved is repr(C) with four 64-bit integer fields; all-zero is valid. iter_mut
            // supplies exclusive live objects, and the byte loop writes exactly size_of::<Saved>()
            // bytes without reading padding or escaping the object.
            unsafe {
                let p = (q as *mut Saved).cast::<u8>();
                for i in 0..core::mem::size_of::<Saved>() {
                    p.add(i).write_volatile(0);
                }
            }
        }
        // SAFETY: Drop exclusively owns the live initialized integer fields ng, nc and abort. Each
        // volatile zero store uses its field's natural alignment and exact extent.
        unsafe {
            core::ptr::write_volatile(&mut self.ng, 0);
            core::ptr::write_volatile(&mut self.nc, 0);
            core::ptr::write_volatile(&mut self.abort, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Explicit sequential owner interface: Read observes state before this slot's
/// coin decision; Apply performs that signed update before the next Read.
/// Implementor must use fixed-address/routed-dot kernels and return no coin data.
pub(crate) enum Action {
    Read {
        slot: usize,
        rotation: u8,
    },
    Apply {
        slot: usize,
        rotation: u8,
        sign: i32,
    },
}
impl<'a> State<'a> {
    /// Dispatcher run by `bound_batch`. Its schedule is fixed in the source; no test of
    /// this repository checks the compiled code or its erasure.
    /// X/n/marked must come from the locator on these same coins.
    /// For unmarked entries X is already exact; marked entries use n refinement.
    /// lambda is the production lower endpoint, unsigned Q384 <=1.
    /// Global preparation failures are supplied as full mask, never suppressed.
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    // Keep the kernel interface and explicit independent inputs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch<F: FnMut(Action) -> i64>(
        mut self,
        p: &Prepared,
        x: &mut [i64; 128],
        n: &[i64; 128],
        marked: &[bool; 128],
        lambda: &[u64; 7],
        prepare_bad: u64,
        mut state: F,
    ) -> u64 {
        self.abort |= mask(prepare_bad != 0);
        let invalid_lambda = (predicate(lambda[6] > 1)
            | (predicate(lambda[6] == 1)
                & predicate(lambda[..6].iter().fold(0u64, |acc, &v| acc | v) != 0)))
            != 0;
        self.abort |= mask(invalid_lambda);
        // Refinement and global bad occur before the optimistic walk, matching the
        // eager convention.
        for slot in 0..128 {
            self.defer_geometry(marked[slot], slot, n[slot]);
        }
        self.finish_geometry(x);
        for slot in 0..128 {
            let label = self.records[slot][0];
            let active = opaque_mask(label >> 63);
            let rotation = label as u8;
            let actual_a = state(Action::Read { slot, rotation });
            let valid = actual_a.unsigned_abs() <= i32::MAX as u64;
            self.abort |= mask(!valid);
            let a = select(mask(valid), actual_a as u64, 0) as i64;
            let xv = x[slot];
            let valid_x = (predicate(xv >= -848) & predicate(xv <= 296263654)) != 0;
            self.abort |= mask(!valid_x);
            let xx = select(mask(valid_x), xv as u64, 0) as i64;
            let t = a.unsigned_abs();
            let clipped = select(opaque_mask(0u64.wrapping_sub(predicate(t > p.b))), p.b, t);
            let y = (clipped * clipped) << 25;
            let u = 2 * ((y as i64) - (7i64 << 58));
            let coeff = p.coarse();
            let mut h = coeff[1];
            for j in 2..12 {
                h = coeff[j] + (((h as i128) * (u as i128)) >> 62) as i64;
            }
            let inside = (predicate(t < p.b) | predicate(a == -(p.b as i64))) != 0;
            h = (h as u64 & mask(inside)) as i64;
            let coin_high = self.records[slot][6];
            let q = (((coin_high as u128) * 65586) >> 18) as i64;
            let delta = q + h - (1i64 << 62);
            let radius = (1i64 << 28) + 32;
            let correction_mark = ((predicate(active != 0) & predicate(delta >= -radius))
                & predicate(delta <= radius))
                != 0;
            self.defer_correction(correction_mark, slot, a, xx);
            let plus = predicate(union(xx, p, t));
            let minus = predicate(delta <= radius) & (1 - plus);
            let negative = predicate(a < 0);
            let unswapped = (plus as i32) - (minus as i32);
            let signed = unswapped * (1 - 2 * negative as i32);
            let active_reject = active & (1 - (plus | minus));
            // Strict unsigned seven-limb comparison, using SAME immutable full coin.
            let mut borrow = 0u64;
            for j in 0..7 {
                let limb = if j == 6 { 0 } else { self.records[slot][j + 1] };
                let (v, b1) = limb.overflowing_sub(lambda[j]);
                let (_, b2) = v.overflowing_sub(borrow);
                borrow = predicate(b1) | predicate(b2);
            }
            let dummy_reject = (1 - active) & (1 - borrow);
            self.abort |= opaque_mask(0u64.wrapping_sub(active_reject | dummy_reject));
            let sign = (signed as u32
                & (opaque_mask(0u64.wrapping_sub(active)) & !self.abort) as u32)
                as i32;
            let _ = state(Action::Apply {
                slot,
                rotation,
                sign,
            });
        }
        self.finish_correction_semantic(p)
    }
}

#[repr(C)]
struct LocatorReply {
    ceil_guess: i64,
    nearest: i64,
    ambiguous: u64,
}
// SAFETY: both functions are C, defined in `interval-geometric.c` (the first under the name
// `geometric`, renamed by a macro of `interval-transport.c`, which includes that file through
// `interval-geometric-prepare.c` and which `build.rs` compiles into `libinterval_transport.a`).
// `LocatorReply` is `repr(C)` with the fields of the C struct `result` in the same order:
// `int64_t`, `int64_t`, `uint64_t`. `pretzel55_interval_geometric` reads six `u64` at `raw` and
// returns one reply by value. `pretzel55_geometric_four` reads six `u64` at each of `raw`, `raw +
// 8`, `raw + 16` and `raw + 24` (offsets in `u64`) and writes four replies at `out`. Besides these
// they access only constants of that file and their own stack, and they do not unwind.
extern "C" {
    #[cfg(test)]
    fn pretzel55_interval_geometric(raw: *const u64) -> LocatorReply;
    fn pretzel55_geometric_four(raw: *const u64, out: *mut LocatorReply);
}
#[inline(always)]
fn locator_valid(r: &LocatorReply) -> bool {
    ((predicate(r.ambiguous <= 1) & predicate(r.nearest >= -849))
        & predicate(r.nearest <= 296263653)
        & predicate(r.ceil_guess >= -848)
        & predicate(r.ceil_guess <= 296263654))
        != 0
}
/// Locates the 128 slots four at a time with `pretzel55_geometric_four` (interval-geometric.c),
/// then runs `State::dispatch` on the results and returns its value.
pub(crate) fn bound_batch(
    p: &Prepared,
    slots: &Positions<'_>,
    lambda: &crate::fixed::Fx,
    incoming: u64,
    deferred: &mut crate::ct_deferred::Deferred,
    packed: &crate::ct_gram_registers::Packed,
) -> u64 {
    assert_eq!(deferred.recorded, 0);
    let mut x = zeroize::Zeroizing::new([0i64; 128]);
    let mut n = zeroize::Zeroizing::new([0i64; 128]);
    let mut marked = zeroize::Zeroizing::new([false; 128]);
    let mut bad = incoming;
    // Public groups of four retain exactly the same six-limb coins.
    let mut batch = LocatorBatch::new();
    for group in 0..32 {
        let first = 4 * group;
        // SAFETY: `Positions` always borrows 128 records of eight `u64` (`ct_slots.rs`), 1024 words
        // as a flattened view. `raw` is word `8 * first + 1` of that view, a pointer derived from
        // the view from that word to its end. `first = 4 * group` with `group < 32`, so
        // `first <= 124`. `pretzel55_geometric_four` (`interval-geometric.c`) only reads through
        // `raw`, and what it reads is `raw[8 * i]` to `raw[8 * i + 5]` for `i < 4`: words 1 to 6
        // of records `first` to `first + 3`, the last being `raw[29]`, at most word 1022 of the
        // view. `raw` has the alignment of the records. The callee writes the four `repr(C)`
        // replies of `batch`, which this function owns, and keeps neither pointer.
        unsafe {
            pretzel55_geometric_four(
                slots.record_slice().as_flattened()[8 * first + 1..].as_ptr(),
                batch.0.as_mut_ptr(),
            );
        }
        for lane in 0..4 {
            let slot = first + lane;
            let row = &slots.record_slice()[slot];
            let r = &batch.0[lane];
            let nz = predicate(row[1..7].iter().fold(0u64, |v, x| v | x) != 0);
            let valid = predicate(locator_valid(r));
            bad |= opaque_mask(0u64.wrapping_sub((nz ^ 1) | (valid ^ 1)));
            x[slot] = select(
                opaque_mask(0u64.wrapping_sub(valid)),
                r.ceil_guess as u64,
                0,
            ) as i64;
            n[slot] = select(opaque_mask(0u64.wrapping_sub(valid)), r.nearest as u64, 0) as i64;
            marked[slot] = ((valid & nz) & predicate(r.ambiguous != 0)) != 0;
        }
    }
    State::new(slots).dispatch(
        p,
        &mut x,
        &n,
        &marked,
        &lambda.0,
        bad,
        |action| match action {
            Action::Read { slot, rotation } => {
                deferred.dot_with_base(packed, rotation as u64, &slots.record_slice()[slot][0])
            }
            Action::Apply {
                slot,
                rotation,
                sign,
            } => {
                deferred.record(slot, rotation as u64, sign);
                0
            }
        },
    )
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    fn capacity<const C: usize>() {
        let mut queue = [ZERO; C];
        let (mut rank, mut abort) = (0u64, 0u64);
        for slot in 0..C {
            State::push(
                &mut queue,
                &mut rank,
                &mut abort,
                true,
                slot,
                slot as i64,
                slot as i64,
            );
        }
        assert_eq!(rank, C as u64);
        assert_eq!(abort, 0);
        State::push(&mut queue, &mut rank, &mut abort, true, C, 7, 9);
        assert_eq!(abort, u64::MAX);
        assert_eq!(rank, C as u64 + 1);
        for (i, q) in queue.iter().enumerate() {
            assert_eq!(
                (q.slot, q.a, q.x, q.live),
                (i as u64, i as i64, i as i64, u64::MAX)
            );
        }
        State::push(&mut queue, &mut rank, &mut abort, false, 127, 0, 0);
        assert_eq!(abort, u64::MAX);
        assert_eq!(rank, C as u64 + 1);
        let mut fresh = [ZERO; C];
        let (mut fresh_rank, mut fresh_abort) = (0, 0);
        State::push(
            &mut fresh,
            &mut fresh_rank,
            &mut fresh_abort,
            true,
            127,
            -3,
            8,
        );
        assert_eq!((fresh_rank, fresh_abort), (1, 0));
        assert_eq!((fresh[0].slot, fresh[0].a, fresh[0].x), (127, -3, 8));
    }
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn scalar_push<const C: usize>(
        queue: &mut [Saved; C],
        rank: &mut u64,
        abort: &mut u64,
        marked: bool,
        slot: usize,
        a: i64,
        x: i64,
    ) {
        let marked = predicate(marked);
        let valid = (predicate(slot < 128) & predicate(a.unsigned_abs() <= i32::MAX as u64))
            & predicate(x >= -848)
            & predicate(x <= 296263654);
        *abort |=
            opaque_mask(0u64.wrapping_sub(marked & (predicate(*rank >= C as u64) | (valid ^ 1))));
        for j in 0..C {
            let m = opaque_mask(0u64.wrapping_sub((marked & valid) & predicate(*rank == j as u64)));
            // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. queue[j] is a checked exclusive borrow
            // of one initialized Saved, whose four repr(C) 64-bit fields cover update's two vector
            // loads and stores. All resulting integer bit patterns are valid.
            unsafe {
                queue_neon::update(&mut queue[j], m, slot as u64, a, x);
            }
        }
        *rank = rank.wrapping_add(marked);
    }
    #[test]
    fn queue_push_matches_scalar_at_all_ranks_and_boundaries() {
        fn check<const C: usize>() {
            for initial_rank in (0..=(C as u64 + 2)).chain([1u64 << 63, u64::MAX - 1, u64::MAX]) {
                for marked in [false, true] {
                    for slot in [0, 127, 128, usize::MAX] {
                        for a in [
                            i64::MIN,
                            -(i32::MAX as i64) - 1,
                            -(i32::MAX as i64),
                            -1,
                            0,
                            1,
                            i32::MAX as i64,
                            i32::MAX as i64 + 1,
                            i64::MAX,
                        ] {
                            for x in [i64::MIN, -849, -848, 0, 296263654, 296263655, i64::MAX] {
                                let old: [Saved; C] = core::array::from_fn(|j| Saved {
                                    slot: 91 + j as u64,
                                    a: -23 - j as i64,
                                    x: 17 + 3 * j as i64,
                                    live: match j % 4 {
                                        0 => 0,
                                        1 => u64::MAX,
                                        2 => 1u64 << j,
                                        _ => 0x5555_aaaa_5555_aaaa ^ (1u64 << j),
                                    },
                                });
                                let mut queue = old;
                                let mut expected = old;
                                let mut expected_rank = initial_rank;
                                let mut expected_abort = 0x20;
                                scalar_push(
                                    &mut expected,
                                    &mut expected_rank,
                                    &mut expected_abort,
                                    marked,
                                    slot,
                                    a,
                                    x,
                                );
                                let mut rank = initial_rank;
                                let mut abort = 0x20;
                                State::push(&mut queue, &mut rank, &mut abort, marked, slot, a, x);
                                assert_eq!((rank, abort), (expected_rank, expected_abort));
                                for (got, want) in queue.iter().zip(expected.iter()) {
                                    assert_eq!(
                                        (got.slot, got.a, got.x, got.live),
                                        (want.slot, want.a, want.x, want.live)
                                    );
                                }
                                let valid = slot < 128
                                    && a.unsigned_abs() <= i32::MAX as u64
                                    && (-848..=296263654).contains(&x);
                                assert_eq!(rank, initial_rank.wrapping_add(marked as u64));
                                assert_eq!(
                                    abort,
                                    0x20 | if marked && (initial_rank >= C as u64 || !valid) {
                                        u64::MAX
                                    } else {
                                        0
                                    }
                                );
                                for (j, q) in queue.iter().enumerate() {
                                    let changed = marked && valid && initial_rank == j as u64;
                                    assert_eq!(
                                        q.slot,
                                        if changed { slot as u64 } else { old[j].slot }
                                    );
                                    assert_eq!(q.a, if changed { a } else { old[j].a });
                                    assert_eq!(q.x, if changed { x } else { old[j].x });
                                    assert_eq!(
                                        q.live,
                                        if changed { u64::MAX } else { old[j].live }
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        check::<10>();
        check::<13>();
    }
    #[test]
    fn geometry_queue_exact_capacity_and_overflow() {
        capacity::<13>();
    }
    #[test]
    fn correction_queue_exact_capacity_and_overflow() {
        capacity::<10>();
    }
}

#[cfg(test)]
mod locator_bound_tests {
    use super::*;
    #[test]
    fn nearest_below_resolved_minimum_is_valid_and_unmarked() {
        let raw = [u64::MAX; 6];
        // SAFETY: raw provides six initialized, aligned u64 words for the AArch64 locator's reads;
        // the borrowed array remains live throughout the call.
        let r = unsafe { pretzel55_interval_geometric(raw.as_ptr()) };
        assert_eq!((r.ceil_guess, r.nearest, r.ambiguous), (-848, -849, 0));
        assert!(locator_valid(&r));
    }
    #[test]
    fn least_nonzero_coin_reaches_positive_endpoint() {
        let raw = [1, 0, 0, 0, 0, 0];
        // SAFETY: raw provides six initialized, aligned u64 words for the AArch64 locator's reads;
        // the borrowed array remains live throughout the call.
        let r = unsafe { pretzel55_interval_geometric(raw.as_ptr()) };
        assert_eq!(
            (r.ceil_guess, r.nearest, r.ambiguous),
            (296263654, 296263653, 0)
        );
        assert!(locator_valid(&r));
    }
}

mod queue_neon {
    use super::*;
    use core::arch::aarch64::*;

    #[inline(always)]
    /// # Safety
    /// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers.
    /// Identity asm preserves its declared inout register and has no memory, stack or flag effects.
    unsafe fn opaque(mut v: uint64x2_t) -> uint64x2_t {
        // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an
        // initialized vector and no memory is accessed. The comment-only asm preserves its declared
        // inout register, stack and flags.
        unsafe {
            core::arch::asm!("/* {v:v} */", v = inout(vreg) v,
                options(nomem, nostack, preserves_flags));
            v
        }
    }

    // Saved has four initialized u64-width fields and no padding. Address and
    // loop count are public. The incoming m already has producer/full barriers.
    #[inline(always)]
    #[cfg(test)]
    /// # Safety
    /// Requires AArch64 NEON. Saved is repr(C) with four initialized 64-bit integer fields and asserted
    /// size 32. The exclusive borrow covers both two-word reads/stores; zero and all lane bit patterns
    /// remain valid.
    pub(super) unsafe fn update(q: &mut Saved, m: u64, slot: u64, a: i64, x: i64) {
        // SAFETY: The caller supplies the function safety contract. Requires AArch64 NEON. Saved is
        // repr(C) with four initialized 64-bit integer fields and asserted size 32. The exclusive
        // borrow covers both two-word reads/stores; zero and all lane bit patterns remain valid.
        unsafe {
            const {
                assert!(core::mem::size_of::<Saved>() == 32);
            }
            let mask = opaque(vdupq_n_u64(m));
            let lo = vcombine_u64(vcreate_u64(slot), vcreate_u64(a as u64));
            let hi = vcombine_u64(vcreate_u64(x as u64), vcreate_u64(u64::MAX));
            let p = (q as *mut Saved).cast::<u64>();
            vst1q_u64(p, vbslq_u64(mask, lo, vld1q_u64(p)));
            // live | m = select(m, MAX, live), including an inactive old record.
            vst1q_u64(p.add(2), vbslq_u64(mask, hi, vld1q_u64(p.add(2))));
        }
    }

    #[inline(always)]
    /// # Safety
    /// Requires AArch64 NEON. records.len()==128 is asserted; under the shipped profile each Record is
    /// eight initialized u64 words. Loads at offsets 1,3,5 each read two words; slot affects masks
    /// only. The six-word output is local and exclusive.
    pub(super) unsafe fn coin(records: &[Record], slot: u64) -> [u64; 6] {
        // SAFETY: The caller supplies the function safety contract. Requires AArch64 NEON.
        // records.len()==128 is asserted; under the shipped profile each Record is eight initialized
        // u64 words. Loads at offsets 1,3,5 each read two words; slot affects masks only. The six-word
        // output is local and exclusive.
        unsafe {
            assert_eq!(records.len(), 128);
            let mut a = vdupq_n_u64(0);
            let mut b = a;
            let mut c = a;
            for (i, record) in records.iter().enumerate() {
                // The predicate is opaque before negation and vector composition.
                let m = opaque(vdupq_n_u64(opaque_mask(
                    0u64.wrapping_sub(predicate(slot == i as u64)),
                )));
                let p = record.as_ptr().add(1);
                a = vorrq_u64(a, vandq_u64(vld1q_u64(p), m));
                b = vorrq_u64(b, vandq_u64(vld1q_u64(p.add(2)), m));
                c = vorrq_u64(c, vandq_u64(vld1q_u64(p.add(4)), m));
            }
            let mut out = [0u64; 6];
            vst1q_u64(out.as_mut_ptr(), a);
            vst1q_u64(out.as_mut_ptr().add(2), b);
            vst1q_u64(out.as_mut_ptr().add(4), c);
            out
        }
    }

    // Queue insertion: construct the two replacement vectors once and
    // keep equality in vector registers across the same C public addresses.
    #[inline(always)]
    /// # Safety
    /// Requires AArch64 NEON. The exclusive queue borrow supplies initialized Saved values; all
    /// accesses cover only their four repr(C) 64-bit fields. Rank selects masks, never addresses.
    pub(super) unsafe fn push_queue<const C: usize>(
        queue: &mut [Saved; C],
        rank: u64,
        enabled: u64,
        slot: u64,
        a: i64,
        x: i64,
    ) {
        // SAFETY: The caller guarantees NEON. Saved is repr(C), with four initialized 64-bit integer
        // fields and asserted size 32. Each iter_mut borrow is exclusive and covers both two-word
        // loads/stores at offsets 0 and 2; all integer bit patterns are valid. Rank and enabled only
        // affect register masks, so even an out-of-range rank cannot produce an invalid address.
        unsafe {
            const {
                assert!(core::mem::size_of::<Saved>() == 32);
            }
            let ranks = vdupq_n_u64(rank);
            let active = opaque(vdupq_n_u64(0u64.wrapping_sub(enabled)));
            let lo = vcombine_u64(vcreate_u64(slot), vcreate_u64(a as u64));
            let hi = vcombine_u64(vcreate_u64(x as u64), vcreate_u64(u64::MAX));
            let mut index = vdupq_n_u64(0);
            let step = vdupq_n_u64(1);
            for q in queue.iter_mut() {
                let equal = opaque(vceqq_u64(ranks, index));
                let m = opaque(vandq_u64(active, equal));
                let p = (q as *mut Saved).cast::<u64>();
                vst1q_u64(p, vbslq_u64(m, lo, vld1q_u64(p)));
                vst1q_u64(p.add(2), vbslq_u64(m, hi, vld1q_u64(p.add(2))));
                index = vaddq_u64(index, step);
            }
        }
    }

    #[inline(always)]
    /// # Safety
    /// Requires AArch64 NEON. The exclusive initialized [i64;128] is visited in complete two-word
    /// groups. slot and live select register masks only and never determine a memory address.
    pub(super) unsafe fn scatter(out: &mut [i64; 128], slot: u64, live: u64, value: i64) {
        // SAFETY: The caller supplies the function safety contract. Requires AArch64 NEON. The
        // exclusive initialized [i64;128] is visited in complete two-word groups. slot and live select
        // register masks only and never determine a memory address.
        unsafe {
            let slots = vdupq_n_u64(slot);
            let active = vdupq_n_u64(live);
            let replacement = vdupq_n_s64(value);
            let mut index = vcombine_u64(vcreate_u64(0), vcreate_u64(1));
            for i in (0..128).step_by(2) {
                let equal = opaque(vceqq_u64(slots, index));
                let m = opaque(vandq_u64(active, equal));
                let p = out.as_mut_ptr().add(i);
                vst1q_s64(p, vbslq_s64(m, replacement, vld1q_s64(p)));
                index = vaddq_u64(index, vdupq_n_u64(2));
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn queue_updates_preserve_all_fields_and_masks() {
            for m in [0, u64::MAX] {
                for x in [i64::MIN, -848, 0, 296263654, i64::MAX] {
                    let mut q = Saved {
                        slot: 127,
                        a: -17,
                        x: 99,
                        live: 7,
                    };
                    let old = q;
                    // SAFETY: This module is AArch64-only. q exclusively owns an initialized Saved;
                    // its four repr(C) integer fields cover both vector loads and stores.
                    unsafe {
                        update(&mut q, m, 42, -123, x);
                    }
                    assert_eq!(q.slot, select(m, 42, old.slot));
                    assert_eq!(q.a, select(m, (-123i64) as u64, old.a as u64) as i64);
                    assert_eq!(q.x, select(m, x as u64, old.x as u64) as i64);
                    assert_eq!(q.live, old.live | m);
                }
            }
        }
        #[test]
        fn scans_match_scalar_for_every_slot_and_invalid_slots() {
            let rows: [Record; 128] = core::array::from_fn(|i| {
                core::array::from_fn(|j| {
                    (i as u64 * 173 + j as u64).wrapping_mul(0x123456789abcdef)
                })
            });
            for slot in (0..130).chain([u64::MAX]) {
                let mut want = [0u64; 6];
                for (i, row) in rows.iter().enumerate() {
                    let m = mask(slot == i as u64);
                    for (k, value) in want.iter_mut().enumerate() {
                        *value |= row[k + 1] & m;
                    }
                }
                // SAFETY: This module is AArch64-only. rows contains exactly 128 initialized Records;
                // coin reads only words 1..7 of each record, and slot only affects register masks.
                assert_eq!(unsafe { coin(&rows, slot) }, want);
                for live in [0, u64::MAX] {
                    let mut out = core::array::from_fn(|i| i as i64 - 64);
                    let mut expected = out;
                    for (i, value) in expected.iter_mut().enumerate() {
                        let m = live & mask(slot == i as u64);
                        *value = select(m, (-731i64) as u64, *value as u64) as i64;
                    }
                    // SAFETY: This module is AArch64-only. out is an exclusive initialized [i64;128];
                    // scatter visits complete pairs in bounds, while slot and live only select masks.
                    unsafe {
                        scatter(&mut out, slot, live, -731);
                    }
                    assert_eq!(out, expected);
                }
            }
        }
    }
}

// The additional batch has its own owner.
#[repr(C)]
struct LocatorBatch([LocatorReply; 4]);
impl LocatorBatch {
    fn new() -> Self {
        Self(core::array::from_fn(|_| LocatorReply {
            ceil_guess: 0,
            nearest: 0,
            ambiguous: 0,
        }))
    }
}
impl Drop for LocatorBatch {
    fn drop(&mut self) {
        const {
            assert!(core::mem::size_of::<Self>() == 96);
            assert!(core::mem::align_of::<Self>() == 8);
        }
        // repr(C) gives a padding-free 96-byte region; every byte is initialized.
        // SAFETY: Self is repr(C) and consists of integer fields; the assertions establish its 96-byte
        // extent and eight-byte alignment. Drop exclusively owns the twelve initialized words, and
        // zero is a valid representation.
        unsafe {
            let p = (self as *mut Self).cast::<u64>();
            for i in 0..12 {
                p.add(i).write_volatile(0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}
#[cfg(test)]
#[path = "locator_tests.rs"]
mod locator_tests;

fn union(x: i64, p: &Prepared, t: u64) -> bool {
    union_reference(x, p.b, t)
}
