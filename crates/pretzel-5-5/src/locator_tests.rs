// Tests of the four-lane locator against the scalar routine, and of the erasure of its owner.
use super::*;
#[test]
fn four_slot_locator_matches_scalar_on_arbitrary_coins() {
    let mut state = 0x58b1_3819_7432_ab01u64;
    let mut records = [[0u64; 8]; 4];
    for trial in 0..8192 {
        for row in &mut records {
            for word in row.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *word = state;
            }
        }
        if trial < 384 {
            for (lane, row) in records.iter_mut().enumerate() {
                row[1..7].fill(0);
                let bit = (trial + lane) % 384;
                row[1 + bit / 64] = 1u64 << (bit % 64);
            }
        }
        if trial == 384 {
            for row in &mut records {
                row[1..7].fill(0);
            }
        }
        if trial == 385 {
            for row in &mut records {
                row[1..7].fill(u64::MAX);
            }
        }
        let mut batch = LocatorBatch::new();
        unsafe {
            pretzel55_geometric_four(records.as_flattened()[1..].as_ptr(), batch.0.as_mut_ptr());
        }
        for (lane, row) in records.iter().enumerate() {
            let expected = unsafe { pretzel55_interval_geometric(row[1..].as_ptr()) };
            let actual = &batch.0[lane];
            assert_eq!(
                (actual.ceil_guess, actual.nearest, actual.ambiguous),
                (expected.ceil_guess, expected.nearest, expected.ambiguous),
                "trial {trial}, lane {lane}"
            );
        }
    }
}
#[test]
fn four_slot_locator_owner_erases_on_unwind() {
    let mut memory = core::mem::MaybeUninit::<LocatorBatch>::uninit();
    let ptr = memory.as_mut_ptr();
    // SAFETY: `ptr` is the aligned slot of `memory`, written once here.
    unsafe {
        ptr.write(LocatorBatch::new());
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        struct Retire(*mut LocatorBatch);
        impl Drop for Retire {
            fn drop(&mut self) {
                // SAFETY: the slot was initialized above and this guard is its only drop.
                unsafe {
                    core::ptr::drop_in_place(self.0);
                }
            }
        }
        let _retire = Retire(ptr);
        // SAFETY: the slot is initialized and nothing else refers to it during these writes.
        unsafe {
            for v in &mut (*ptr).0 {
                v.ceil_guess = -17;
                v.nearest = 29;
                v.ambiguous = 1;
            }
        }
        panic!("injected locator panic");
    }));
    assert!(result.is_err());
    // Drop writes the entire initialized, padding-free repr(C) extent.
    // SAFETY: `memory` is live, and all of its bytes were written by `new` and by the drop.
    let bytes = unsafe {
        core::slice::from_raw_parts(ptr.cast::<u8>(), core::mem::size_of::<LocatorBatch>())
    };
    assert!(bytes.iter().all(|&b| b == 0));
}
