// Tests of the eight-lane recovery lookup against the scalar recovery of `signature_codec.rs`.
use super::*;

#[test]
fn recovery_matches_every_u16_context_u8_rank_pair() {
    // SAFETY: NEON is in the AArch64 baseline; every load and store covers a whole local array
    // of eight lanes, and `recover8` accepts any context and index.
    unsafe {
        for x in 0..=u16::MAX {
            for base in (0..256u16).step_by(8) {
                let indices: [u8; 8] = core::array::from_fn(|j| (base + j as u16) as u8);
                let (a, b) = recover8(vdupq_n_u16(x), vld1_u8(indices.as_ptr()), Tables::new());
                let (mut labels, mut magnitudes) = ([0u8; 8], [0u16; 8]);
                vst1_u8(labels.as_mut_ptr(), a);
                vst1q_u16(magnitudes.as_mut_ptr(), b);
                for j in 0..8 {
                    let expected = if x < 7681 && indices[j] < 8 {
                        let entry =
                            super::super::PUBLIC_RECOVERY[usize::from(x)][usize::from(indices[j])];
                        if entry == u16::MAX {
                            (0, 451)
                        } else {
                            ((entry & 63) as u8, entry >> 6)
                        }
                    } else {
                        (0, 451)
                    };
                    assert_eq!(
                        (labels[j], magnitudes[j]),
                        expected,
                        "context {x}, rank {}",
                        indices[j]
                    );
                }
            }
        }
    }
}

#[test]
fn recovery_mixed_boundary_lanes() {
    // SAFETY: as in the test above: whole local arrays of eight lanes, any context and index.
    unsafe {
        let xs = [0, 1, 7679, 7680, 7681, 32768, 65534, 65535];
        for index in 0..=u8::MAX {
            let (a, b) = recover8(vld1q_u16(xs.as_ptr()), vdup_n_u8(index), Tables::new());
            let (mut labels, mut magnitudes) = ([0u8; 8], [0u16; 8]);
            vst1_u8(labels.as_mut_ptr(), a);
            vst1q_u16(magnitudes.as_mut_ptr(), b);
            for j in 0..8 {
                let expected = super::super::recover(i32::from(xs[j]), index);
                match expected {
                    Ok((u, r)) => {
                        assert_eq!((labels[j], magnitudes[j]), (u, r.unsigned_abs() as u16))
                    }
                    Err(()) => assert_eq!((labels[j], magnitudes[j]), (0, 451)),
                }
            }
        }
    }
}
