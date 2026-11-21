// Tests of the NEON admission functions against the scalar predicate of `signature_codec.rs`.
use super::*;

#[test]
fn rank_matches_scalar_on_the_complete_valid_rectangle() {
    // SAFETY: NEON is in the AArch64 baseline; `rank` works on registers and each store
    // writes the four lanes of a local `[u32; 4]`.
    unsafe {
        for label in 0..64 {
            for residual in -450..=450 {
                let mut got = [0; 4];
                vst1q_u32(
                    got.as_mut_ptr(),
                    rank(vdupq_n_s32(label), vdupq_n_s32(residual)),
                );
                assert_eq!(got, [super::super::private_index(label, residual); 4]);
            }
        }
    }
}

fn compare(head: &[i32; HEAD_COEFFICIENTS], labels: &[i32; LABELS], residual: &[i32; LABELS]) {
    let (mut old, mut new) = ([i32::MIN; LABELS], [i32::MAX; LABELS]);
    let expected = super::super::capacity_mask_scalar(head, labels, residual, &mut old);
    // SAFETY: NEON is in the AArch64 baseline; the arrays have the lengths the function requires
    // and `new` is exclusive and disjoint from the inputs.
    let actual = unsafe { capacity_mask(head, labels, residual, &mut new) };
    assert_eq!((actual, new), (expected, old));
}

#[test]
fn admission_boundaries_and_invalid_lanes_match_all_outputs() {
    let (mut head, mut labels, mut residual) = ([0; HEAD_COEFFICIENTS], [0; LABELS], [0; LABELS]);
    compare(&head, &labels, &residual);
    for i in [0, 1, 2, 3, 252, 255, 256, 257, 1532, 1535] {
        for v in [
            i32::MIN,
            -289,
            -288,
            -129,
            -128,
            -96,
            -95,
            -33,
            -32,
            31,
            32,
            95,
            96,
            127,
            128,
            288,
            289,
            i32::MAX,
        ] {
            head[i] = v;
            compare(&head, &labels, &residual);
        }
        head[i] = 0;
    }
    for i in [0, 1, 2, 3, 1276, 1277, 1278, 1279] {
        for u in [i32::MIN, -1, 0, 1, 2, 62, 63, 64, i32::MAX] {
            for r in [i32::MIN, -451, -450, -1, 0, 1, 450, 451, i32::MAX] {
                labels[i] = u;
                residual[i] = r;
                compare(&head, &labels, &residual);
            }
        }
        labels[i] = 0;
        residual[i] = 0;
    }
    for count in [39, 40, 41] {
        head.fill(0);
        head[..count].fill(32);
        compare(&head, &labels, &residual);
    }
    head.fill(0);
    // The scalar rank oracle chooses one rank-four witness, independently
    // of the vector implementation; counts straddle the local exception cap.
    let (u, r) = (0..64)
        .flat_map(|u| (-450..=450).map(move |r| (u, r)))
        .find(|&(u, r)| super::super::private_index(u, r) == 4)
        .unwrap();
    for count in [15, 16, 17] {
        labels.fill(0);
        residual.fill(0);
        labels[..count].fill(u);
        residual[..count].fill(r);
        compare(&head, &labels, &residual);
    }
}

#[test]
fn mixed_lanes_do_not_share_counts_or_validity() {
    let mut state = 0x1908_2026_1024_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as u32
    };
    for _ in 0..256 {
        let head = core::array::from_fn(|i| {
            (next() % if i < 256 { 193 } else { 579 }) as i32 - if i < 256 { 96 } else { 289 }
        });
        let labels = core::array::from_fn(|_| (next() % 68) as i32 - 2);
        let residual = core::array::from_fn(|_| (next() % 905) as i32 - 452);
        compare(&head, &labels, &residual);
    }
}
