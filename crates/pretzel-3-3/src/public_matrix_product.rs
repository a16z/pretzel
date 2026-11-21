//! Public matrix product of the verifier.
use super::*;

// Public verification only: final canonical matrix output belongs to the caller.
impl MatrixAh {
    #[inline(always)]
    pub(super) fn apply_public_into(
        &self,
        z: &[i32; N + ELL * N],
        delta: &[Poly; M],
        out: &mut [Poly; M],
    ) {
        {
            let mut cols = [crate::compact_ring::CompactPoly::ZERO; ELL + 1];
            self.fill_compact(z, &mut cols);
            for r in 0..M {
                crate::neon::public_commitment_row_into(
                    &self.rows[r],
                    &cols,
                    &delta[r],
                    &mut out[r],
                );
            }
        }
    }
}

#[cfg(test)]
mod public_row_fusion_tests {
    use super::*;
    #[test]
    fn matrix_fusion_matches_return_and_preserves_inputs() {
        #[repr(C)]
        struct Framed {
            before: [i32; 8],
            out: [Poly; M],
            after: [i32; 8],
        }
        for keys in 0..8 {
            let mat = prepare_core_matrix(&crate::scheme::packed13_screened_test_core(keys as u64))
                .unwrap();
            for case in 0..16usize {
                let z: [i32; N + ELL * N] = core::array::from_fn(|i| match case {
                    0 => 0,
                    1 => i32::MIN,
                    2 => i32::MAX,
                    3 => {
                        if i % 2 == 0 {
                            -2048
                        } else {
                            2047
                        }
                    }
                    4 => {
                        if i % 2 == 0 {
                            -Q
                        } else {
                            Q
                        }
                    }
                    5 => -1,
                    6 => Q - 1,
                    _ => {
                        if i == (case - 7) * 127 % (N + ELL * N) {
                            if case % 2 == 0 {
                                -289
                            } else {
                                289
                            }
                        } else {
                            ((i * 719 + case * 131) % 15363) as i32 - 7681
                        }
                    }
                });
                let delta = core::array::from_fn(|r| {
                    Poly(core::array::from_fn(|i| {
                        ((r * 997 + i * 43 + case) % Q as usize) as i32
                    }))
                });
                let before_z = z;
                let before_delta = delta;
                let expected = mat.apply_public(&z, &delta);
                let mut frame = Framed {
                    before: [0x12345678; 8],
                    out: [Poly([i32::MIN; N]); M],
                    after: [0x23456789; 8],
                };
                mat.apply_public_into(&z, &delta, &mut frame.out);
                let out = frame.out;
                assert_eq!(frame.before, [0x12345678; 8]);
                assert_eq!(frame.after, [0x23456789; 8]);
                assert_eq!(out, expected, "key{keys} case{case}");
                assert_eq!(z, before_z);
                assert_eq!(delta, before_delta);
                assert!(out.iter().all(|p| p.0.iter().all(|&x| (0..Q).contains(&x))));
            }
        }
    }
}
