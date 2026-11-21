use super::*;
use crate::compact_ring::CompactPoly;

const C: usize = crate::params::ELL + 1;
const L: usize = 64;
const INDICES: u8 = 4;

fn hints(indices: &[u8; N]) -> [u8; L] {
    let mut out = [0; L];
    for i in 0..N {
        out[i / 8] |= (indices[i] & 1) << (i % 8);
        out[32 + i / 8] |= ((indices[i] >> 1) & 1) << (i % 8);
    }
    out
}

fn compare(a: &[CompactPoly; C], b: &[CompactPoly; C], delta: &Poly, local: &[u8; L]) -> Trace {
    // Distinct low words detect wrong cap indices as well as squared norms.
    // 256*451 < 2^32 and 256*451^2 < 2^32, so neither packed field overflows.
    let caps = core::array::from_fn(|i| ((i * i) as u64) << 32 | i as u64);
    let mut scratch = core::mem::MaybeUninit::new([123i16; N]);
    let mut old_scratch = [-123i16; N];
    #[repr(C)]
    struct Labels {
        before: [u8; 16],
        values: [core::mem::MaybeUninit<u8>; N],
        after: [u8; 16],
    }
    let mut labels = Labels {
        before: [0x57; 16],
        values: [core::mem::MaybeUninit::new(0x5a); N],
        after: [0x75; 16],
    };
    let mut expected = [0xa5; N];
    let mut trace = Trace::new();
    let mut old = Trace::new();
    let actual = run(
        a,
        b,
        delta,
        local,
        &mut labels.values,
        &caps,
        &mut scratch,
        &mut trace,
    );
    // SAFETY: run writes all labels on success and cap failure.
    let values = unsafe { &*labels.values.as_ptr().cast::<[u8; N]>() };
    let want = reference(
        a,
        b,
        delta,
        local,
        &mut expected,
        &caps,
        &mut old_scratch,
        &mut old,
    );
    let mut base_labels = [0xa5; N];
    let base = super::super::public_compact_row_caps_reference(
        a,
        b,
        delta,
        local,
        &mut base_labels,
        &caps,
    );
    assert_eq!(actual, base);
    assert_eq!(values, &base_labels);
    assert_eq!(actual, want);
    assert_eq!(values, &expected);
    assert_eq!(trace, old);
    assert_eq!(
        trace.failures.trailing_zeros(),
        old.failures.trailing_zeros()
    );
    assert_eq!(labels.before, [0x57; 16]);
    assert_eq!(labels.after, [0x75; 16]);
    // SAFETY: run writes every scratch coefficient before any possible return.
    assert_eq!(unsafe { scratch.assume_init() }, old_scratch);
    trace
}

#[test]
fn random_rows_and_all_canonical_endpoints() {
    let mut state = 0x713f5bc2u64;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (state >> 32) as u32
    };
    for trial in 0..800 {
        let mut make = || {
            CompactPoly(core::array::from_fn(|i| match trial {
                0 => 0,
                1 => (Q - 1) as i16,
                2 => {
                    if i % 2 == 0 {
                        0
                    } else {
                        (Q - 1) as i16
                    }
                }
                3..=258 => {
                    if i == trial - 3 {
                        (Q - 1) as i16
                    } else {
                        0
                    }
                }
                _ => (next() % Q as u32) as i16,
            }))
        };
        let a = core::array::from_fn(|_| make());
        let b = core::array::from_fn(|_| make());
        let delta = Poly(core::array::from_fn(|i| match trial {
            0 => 0,
            1 => Q - 1,
            2 => {
                if i % 2 == 0 {
                    0
                } else {
                    Q - 1
                }
            }
            _ => (next() % Q as u32) as i32,
        }));
        let indices = core::array::from_fn(|_| (next() % u32::from(INDICES)) as u8);
        compare(&a, &b, &delta, &hints(&indices));
    }
    // Each coefficient domain endpoint independently, not just equal operands.
    for av in [0, 1, Q / 2, Q / 2 + 1, Q - 2, Q - 1] {
        for bv in [0, 1, Q / 2, Q / 2 + 1, Q - 2, Q - 1] {
            for dv in [0, Q - 1] {
                compare(
                    &[CompactPoly([av as i16; N]); C],
                    &[CompactPoly([bv as i16; N]); C],
                    &Poly([dv; N]),
                    &hints(&[INDICES - 1; N]),
                );
            }
        }
    }
}

#[test]
fn every_context_and_hint_and_each_failure_position() {
    let zero = [CompactPoly::ZERO; C];
    let mut witness = None;
    let mut saw_450 = false;
    let mut saw_451 = false;
    for index in 0..INDICES {
        for base in (0..Q as usize).step_by(N) {
            let delta = Poly(core::array::from_fn(|i| ((base + i) % Q as usize) as i32));
            let trace = compare(&zero, &zero, &delta, &hints(&[index; N]));
            for i in 0..N {
                let scalar = crate::signature_codec::recover(delta.0[i], index);
                assert_eq!(scalar.is_err(), trace.magnitudes[i] > 450);
                if let Ok((_, r)) = scalar {
                    assert_eq!(r.unsigned_abs() as u16, trace.magnitudes[i]);
                } else {
                    witness = Some((delta.0[i], index));
                }
                saw_450 |= trace.magnitudes[i] == 450;
                saw_451 |= trace.magnitudes[i] == 451;
            }
        }
    }
    assert!(saw_450 && saw_451);
    let (x, index) = witness.expect("a rejection must be exercised");
    for position in 0..N {
        let mut delta = Poly::ZERO;
        let mut indices = [0; N];
        delta.0[position] = x;
        indices[position] = index;
        let trace = compare(&zero, &zero, &delta, &hints(&indices));
        assert_eq!(trace.failures, 1u32 << (position / 8));
        // Multiple failures keep their positions and still write all labels.
        delta.0[N - 1] = x;
        indices[N - 1] = index;
        let trace = compare(&zero, &zero, &delta, &hints(&indices));
        assert_eq!(trace.failures, (1u32 << (position / 8)) | (1u32 << 31));
    }
}

#[test]
fn reduction_boundaries_and_full_lazy_i16_domain() {
    let max = C as i32 * (Q - 1) * (Q - 1);
    // SAFETY: AArch64 gates the parent module. All vectors are initialized;
    // the four/eight-lane stores below exactly fit their stack arrays.
    unsafe {
        for multiple in 0..=max / Q + 1 {
            for offset in [-1, 0, 1] {
                let x = multiple * Q + offset;
                if !(0..=max).contains(&x) {
                    continue;
                }
                let mut actual = [0; 4];
                vst1q_s32(actual.as_mut_ptr(), reduce_i32x4(vdupq_n_s32(x)));
                assert_eq!(actual, [x % Q; 4]);
            }
        }
        let mut actual = [0; 4];
        vst1q_s32(actual.as_mut_ptr(), reduce_i32x4(vdupq_n_s32(max)));
        assert_eq!(actual, [max % Q; 4]);
        // Exhaust all signed lanes, including either side of each half-q bound.
        for base in (-32768..32768).step_by(8) {
            let input: [i16; 8] = core::array::from_fn(|i| (base + i as i32) as i16);
            let mut actual = [0; 8];
            vst1q_s16(actual.as_mut_ptr(), barrett16(vld1q_s16(input.as_ptr())));
            for i in 0..8 {
                let x = i32::from(input[i]);
                let expected = (x + Q / 2).rem_euclid(Q) - Q / 2;
                assert_eq!(i32::from(actual[i]), expected);
            }
        }
    }
}
