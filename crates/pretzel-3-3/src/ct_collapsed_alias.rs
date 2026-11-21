//! Warm-only reservoir dispatch with exact constructor boundary guards.
use crate::hashes::Xof;
include!("warm_tail_tables.rs");
include!("../../pretzel-4-4/core/src/warm_collapsed_identities.rs");
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
    // SAFETY: `records` is an exclusive, initialized `[u32; RECORD_WORDS]` (1034 words, 4136
    // bytes). The byte view covers its first 2056 or 2632 bytes, any byte pattern is valid `u32`
    // content, and `records` is not used again while `tape` is alive.
    let tape = unsafe {
        core::slice::from_raw_parts_mut(
            records.as_mut_ptr().cast::<u8>(),
            if out.len() == 768 { 2056 } else { 2632 },
        )
    };
    rng.fill(tape);
    // SAFETY: `work` is an exclusive, initialized `[u32; 2048]`; `u64` has no invalid bit pattern
    // and no padding, so the aligned middle part may be viewed as `u64`. Its length is checked just
    // below.
    let (_, words, _) = unsafe { work.align_to_mut::<u64>() };
    assert!(words.len() * 8 >= 8000);
    // SAFETY: contract of `pretzel33_reservoir_sample` (stated at its declaration). `out` has `n =
    // out.len()` `i32`, a multiple of 4 and at most 1024 (asserted above). `tape` has 2056 bytes
    // when `n == 768` and 2632 bytes otherwise, the two extents the routine reads. `t` is one of
    // the two static descriptors. `words` is aligned for `u64`, initialized and at least 8000 bytes
    // long (asserted above), which covers the 7328-byte workspace; it is distinct from `out` and
    // `tape`.
    unsafe {
        pretzel33_reservoir_sample(
            out.as_mut_ptr(),
            tape.as_ptr(),
            t,
            words.as_mut_ptr().cast::<u32>(),
            out.len(),
        )
    }
}

#[cfg(test)]
mod rank3_length_tests {
    use super::*;
    unsafe extern "C" {
        fn reservoir_sample_reference(
            out: *mut i32,
            tape: *const u8,
            t: *const Reservoir,
            work: *mut u32,
            n: usize,
        ) -> u64;
        fn pretzel33_reservoir_sample_impl(
            out: *mut i32,
            tape: *const u8,
            t: *const Reservoir,
            work: *mut u32,
            n: usize,
        ) -> u64;
    }
    #[test]
    fn prefix_matches_reference_when_reference_succeeds() {
        let mut seed = 2026092801u64;
        let mut tape = [0u8; 2632];
        let mut checks = 0;
        for t in [&RESERVOIR_SEC, &RESERVOIR_ERR] {
            for n in [768usize, 1024] {
                for trial in 0..512 {
                    for b in &mut tape {
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        *b = seed as u8;
                    }
                    if trial < 2 {
                        tape.fill(if trial == 0 { 0 } else { 255 });
                    }
                    let mut packed = tape;
                    if n == 768 {
                        packed[1728..2056].copy_from_slice(&tape[2304..2632]);
                    }
                    let mut a = [0i32; 1024];
                    let mut b = [0i32; 1024];
                    let mut wa = [0u64; 1000];
                    let mut wb = [0u64; 1000];
                    let x = unsafe {
                        reservoir_sample_reference(
                            a.as_mut_ptr(),
                            tape.as_ptr(),
                            t,
                            wa.as_mut_ptr().cast(),
                            n,
                        )
                    };
                    let y = unsafe {
                        pretzel33_reservoir_sample_impl(
                            b.as_mut_ptr(),
                            packed.as_ptr(),
                            t,
                            wb.as_mut_ptr().cast(),
                            n,
                        )
                    };
                    if x == 0 {
                        assert_eq!(y, 0);
                        assert_eq!(a[..n], b[..n]);
                        checks += 1;
                    }
                    if n == 1024 {
                        assert_eq!(x, y);
                        assert_eq!(a, b);
                    }
                }
            }
        }
        assert!(checks > 1900);
        println!("successful reference comparisons: {}", checks);
    }
}
