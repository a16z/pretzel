//! Warm-only reservoir dispatch with exact constructor boundary guards.
use crate::hashes::Xof;
include!("warm_tail_tables.rs");
include!("warm_collapsed_identities.rs");
include!("reservoir_tables.rs");
pub(crate) fn sample(
    parts: &Table,
    z: &[u64; 3],
    rng: &mut Xof,
    out: &mut [i32],
    records: &mut [u32; crate::scratch::RECORD_WORDS],
    work: &mut [u32; 2048],
) -> u64 {
    assert!(out.len() <= 1024 && out.len() % 4 == 0);
    assert_eq!(*z, parts.z);
    let t = if core::ptr::eq(parts, &SEC) {
        &RESERVOIR_SEC
    } else {
        assert!(core::ptr::eq(parts, &ERR));
        &RESERVOIR_ERR
    };
    let tape=
 // SAFETY: records is an exclusive initialized [u32; RECORD_WORDS], with RECORD_WORDS=1034,
 // covering the 2632-byte tape prefix. u8 alignment is one and every byte pattern remains
 // valid for the original u32 storage.
 unsafe{core::slice::from_raw_parts_mut(records.as_mut_ptr().cast::<u8>(),2632)};
    rng.fill(tape);
    let(_,words,_)=
 // SAFETY: work is an exclusive initialized [u32; 2048]. align_to_mut selects a properly
 // aligned u64 middle slice; both integer types accept every bit pattern, and the returned
 // regions are disjoint.
 unsafe{work.align_to_mut::<u64>()};
    assert!(words.len() * 8 >= 8000);
    // SAFETY: contract of `pretzel44_reservoir_sample` (stated at its declaration). `out` has `n =
    // out.len()` `i32`, a multiple of 4 and at most 1024 (asserted above). `tape` has the 2632
    // bytes the routine reads. `t` is one of the two static descriptors. `words` is aligned for
    // `u64`, initialized and at least 8000 bytes long (asserted above), which covers the 7328-byte
    // workspace; it is distinct from `out` and `tape`.
    unsafe {
        pretzel44_reservoir_sample(
            out.as_mut_ptr(),
            tape.as_ptr(),
            t,
            words.as_mut_ptr().cast::<u32>(),
            out.len(),
        )
    }
}
