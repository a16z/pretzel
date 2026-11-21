//! Public decoded-response ingress fused into the first three NTT layers.
//! Rank-three version; preparation and signing have their own entrypoints.
use super::*;

pub(crate) fn forward(
    head: &crate::signature_codec::DecodedHead<'_>,
    column: usize,
) -> crate::compact_ring::CompactPoly {
    assert!(column < crate::params::ELL + 1);
    let input = head.values()[column * N..(column + 1) * N]
        .try_into()
        .unwrap();
    let mut out = core::mem::MaybeUninit::uninit();
    forward_values(input, &mut out);
    // SAFETY: forward_values writes all N coefficients before returning.
    crate::compact_ring::CompactPoly(unsafe { out.assume_init() })
}

// Keep the lane indices visibly identical to the transform schedule.
#[allow(clippy::needless_range_loop)]
fn forward_values(input: &[i32; N], out: &mut core::mem::MaybeUninit<[i16; N]>) {
    // Successful decoding establishes this bound at rank three (the sparse head is tighter).
    // The canonical conversion below is exact before any butterfly, including zero.
    debug_assert!(input.iter().all(|&x| (-288..=288).contains(&x)));
    let t = ntt16_tables();
    // SAFETY: `build.rs` asserts an AArch64 target, where NEON is in the baseline. For
    // base=0,8,16,24 and r<8, base+32*r+8<=256 bounds both four-i32 loads and
    // the eight-i16 store. Decoded coefficients fit i16; adding q to negatives
    // gives exactly [0,q). Each output is initialized before the suffix reads
    // it. Only raw pointers address the MaybeUninit storage until it is complete.
    // The suffix addresses four complete 64-coefficient tiles. Input and
    // output borrows are disjoint; all twiddle rows contain eight i16 values.
    unsafe {
        let bp = out.as_mut_ptr().cast::<i16>();
        for base in (0..32).step_by(8) {
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| {
                let p = input.as_ptr().add(base + 32 * r);
                let x = vcombine_s16(vmovn_s32(vld1q_s32(p)), vmovn_s32(vld1q_s32(p.add(4))));
                vaddq_s16(x, vandq_s16(vshrq_n_s16::<15>(x), vdupq_n_s16(Q as i16)))
            });
            let pair = |c: &mut [int16x8_t; 8], a, b, k| {
                ct_pair(c, a, b, vdupq_n_s16(t.zr[k]), vdupq_n_s16(t.zq[k]));
            };
            for r in 0..4 {
                pair(&mut c, r, r + 4, 1);
            }
            pair(&mut c, 0, 2, 2);
            pair(&mut c, 1, 3, 2);
            pair(&mut c, 4, 6, 3);
            pair(&mut c, 5, 7, 3);
            for r in 0..4 {
                pair(&mut c, 2 * r, 2 * r + 1, 4 + r);
            }
            for r in 0..8 {
                vst1q_s16(bp.add(base + 32 * r), barrett16(c[r]));
            }
        }
        // Identical remaining layers and reduction points. This ingress is
        // separate from the entrypoints of preparation and signing.
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            public_compact_middle2(&mut c, sb, t);
            transpose8(&mut c);
            let tv = &t.fwd_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                ct_pair(&mut c, r, r + 4, zr, zq);
            }
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            let (zr, zq) = (ld(2), ld(3));
            ct_pair(&mut c, 0, 2, zr, zq);
            ct_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            ct_pair(&mut c, 4, 6, zr, zq);
            ct_pair(&mut c, 5, 7, zr, zq);
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                ct_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            for r in 0..8 {
                c[r] = canonical16(barrett16(c[r]));
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn check_decoded_columns(head: &crate::signature_codec::DecodedHead<'_>) {
    for column in 0..crate::params::ELL + 1 {
        let mut canonical = [0; N];
        head.write_canonical_column(column, &mut canonical);
        let mut scalar = crate::ring::Poly(canonical.map(i32::from));
        crate::ring::ntt_scalar(&mut scalar);
        let actual = forward(head, column);
        assert_eq!(actual.0.map(i32::from), scalar.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compare(input: [i32; N]) {
        #[repr(C)]
        struct Guarded {
            before: [i16; 8],
            output: core::mem::MaybeUninit<[i16; N]>,
            after: [i16; 8],
        }
        let mut actual = Guarded {
            before: [12345; 8],
            output: core::mem::MaybeUninit::new([i16::MIN; N]),
            after: [-12345; 8],
        };
        let mut scalar = crate::ring::Poly(input.map(|x| x.rem_euclid(Q)));
        crate::ring::ntt_scalar(&mut scalar);
        forward_values(&input, &mut actual.output);
        // SAFETY: forward_values initializes every coefficient before returning.
        let output = unsafe { actual.output.assume_init() };
        assert_eq!(output.map(i32::from), scalar.0);
        assert_eq!(actual.before, [12345; 8]);
        assert_eq!(actual.after, [-12345; 8]);
    }

    #[test]
    fn bounded_response_matches_scalar_transform() {
        // Every allowed signed value in every lane, with unequal neighbors.
        for first in 0..577 {
            compare(core::array::from_fn(|i| {
                ((first + 37 * i) % 577) as i32 - 288
            }));
        }
        for value in [-288, -255, -95, -32, -1, 0, 1, 31, 95, 255, 288] {
            compare([value; N]);
            for position in 0..N {
                let mut input = [0; N];
                input[position] = value;
                compare(input);
            }
        }
        let mut rng = 0x7319abdfu64;
        for _ in 0..256 {
            compare(core::array::from_fn(|_| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                (rng % 577) as i32 - 288
            }));
        }
    }
}
