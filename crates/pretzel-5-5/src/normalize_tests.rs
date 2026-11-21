// Test-only highest-limb oracle. Production has only select-before-normalize.
fn reference(raw: [u64; 6]) -> [u64; 2] {
    let Some(i) = raw.iter().rposition(|x| *x != 0) else {
        return [1 << 62, 0];
    };
    let shift = raw[i].leading_zeros();
    let pair = ((raw[i] as u128) << 64) | if i == 0 { 0 } else { raw[i - 1] as u128 };
    [
        ((pair << shift) >> 65) as u64,
        (64 * (i + 1)) as u64 - shift as u64,
    ]
}
unsafe extern "C" {
    fn pretzel55_normalization_gate(raw: *const u64, out: *mut u64);
}
#[test]
fn normalization_all_boundaries() {
    fn check(raw: [u64; 6]) {
        let mut out = [0; 2];
        unsafe {
            pretzel55_normalization_gate(raw.as_ptr(), out.as_mut_ptr());
        }
        assert_eq!(out, reference(raw), "{raw:?}");
    }
    check([0; 6]);
    check([u64::MAX; 6]);
    for limb in 0..6 {
        for bit in 0..64 {
            for low in [0, 1, u64::MAX] {
                for delta in [0u64, 1, u64::MAX] {
                    let mut raw = [0; 6];
                    raw[limb] = (1u64 << bit).wrapping_add(delta);
                    if limb > 0 {
                        raw[limb - 1] = low;
                    }
                    check(raw);
                }
            }
        }
    }
    let mut seed = 0x504f525431u64;
    for _ in 0..16384 {
        check(core::array::from_fn(|_| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            seed
        }));
    }
}

#[test]
fn normalization_fixed_outputs() {
    for (raw, expected) in [
        ([0; 6], [1 << 62, 0]),
        ([1, 0, 0, 0, 0, 0], [1 << 62, 1]),
        ([0, 0, 0, 0, 0, 1], [1 << 62, 321]),
        ([u64::MAX; 6], [(1 << 63) - 1, 384]),
    ] {
        let mut out = [0; 2];
        unsafe {
            pretzel55_normalization_gate(raw.as_ptr(), out.as_mut_ptr());
        }
        assert_eq!(out, expected);
    }
}
