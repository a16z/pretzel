//! Public verification only: compare response parity directly with the folded hash.
pub(super) fn matches(head: &[i32; 256], digest: &[u8; 32]) -> bool {
    let weight: u32 =
        digest[..31].iter().map(|b| b.count_ones()).sum::<u32>() + (digest[31] & 127).count_ones();
    let flip = 0u16.wrapping_sub(u16::from(weight > 128));
    let mut bad = 0u16;
    for block in 0..16 {
        // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. head has 256 initialized i32 entries and
        // block<16 bounds all four loads within its 16-element block. weights has exactly 16 bytes;
        // the remaining operations use initialized registers only.
        let actual = unsafe {
            use core::arch::aarch64::*;
            let h = head.as_ptr().add(16 * block);
            let a = vcombine_s16(vmovn_s32(vld1q_s32(h)), vmovn_s32(vld1q_s32(h.add(4))));
            let b = vcombine_s16(
                vmovn_s32(vld1q_s32(h.add(8))),
                vmovn_s32(vld1q_s32(h.add(12))),
            );
            let bytes = vreinterpretq_u8_s8(vcombine_s8(vmovn_s16(a), vmovn_s16(b)));
            let weights = [1u8, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
            let bits = vmulq_u8(vandq_u8(bytes, vdupq_n_u8(1)), vld1q_u8(weights.as_ptr()));
            let sums = vpaddlq_u32(vpaddlq_u16(vpaddlq_u8(bits)));
            (vgetq_lane_u64::<0>(sums) as u16) | ((vgetq_lane_u64::<1>(sums) as u16) << 8)
        };
        let mut expected = u16::from_le_bytes([digest[2 * block], digest[2 * block + 1]]);
        if block == 15 {
            expected &= 32767;
        }
        bad |= actual ^ expected ^ flip;
    }
    bad == 0
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reference_and_every_parity_flip() {
        let mut state = 20260928u64;
        for _ in 0..10000 {
            let mut digest = [0; 32];
            for b in &mut digest {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = state as u8;
            }
            let mut expected = [0i32; 256];
            for i in 0..255 {
                expected[i] = i32::from((digest[i / 8] >> (i % 8)) & 1);
            }
            let flip = i32::from(expected.iter().sum::<i32>() > 128);
            for v in &mut expected {
                *v ^= flip;
                *v -= 128;
            }
            assert!(matches(&expected, &digest));
            for i in 0..256 {
                expected[i] ^= 1;
                assert!(!matches(&expected, &digest));
                expected[i] ^= 1;
            }
        }
    }
}

#[cfg(test)]
fn matches_reference(head: &[i32; 256], digest: &[u8; 32]) -> bool {
    let mut folded = *digest;
    folded[31] &= 127;
    let weight: u32 = folded
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()).count_ones())
        .sum();
    let flip = 0u8.wrapping_sub(u8::from(weight > 128));
    for b in &mut folded {
        *b ^= flip;
    }
    unsafe {
        use core::arch::aarch64::*;
        let shift = [
            0i8, -1, -2, -3, -4, -5, -6, -7, 0, -1, -2, -3, -4, -5, -6, -7,
        ];
        let shift = vld1q_s8(shift.as_ptr());
        let one = vdupq_n_u8(1);
        let mut bad = vdupq_n_u8(0);
        for block in 0..16 {
            let h = head.as_ptr().add(16 * block);
            let a = vcombine_s16(vmovn_s32(vld1q_s32(h)), vmovn_s32(vld1q_s32(h.add(4))));
            let b = vcombine_s16(
                vmovn_s32(vld1q_s32(h.add(8))),
                vmovn_s32(vld1q_s32(h.add(12))),
            );
            let actual = vreinterpretq_u8_s8(vcombine_s8(vmovn_s16(a), vmovn_s16(b)));
            let bytes = vcombine_u8(
                vdup_n_u8(folded[2 * block]),
                vdup_n_u8(folded[2 * block + 1]),
            );
            let expected = vshlq_u8(bytes, shift);
            bad = vorrq_u8(bad, vandq_u8(veorq_u8(actual, expected), one));
        }
        vmaxvq_u8(bad) == 0
    }
}

#[cfg(test)]
mod match_tests {
    use super::*;
    #[test]
    fn match_all_weights_and_full_i32() {
        for weight in 0..=256 {
            let mut digest = [0u8; 32];
            for i in 0..weight {
                digest[i / 8] |= 1 << (i % 8);
            }
            let flip = i32::from(weight.min(255) > 128);
            let mut head = core::array::from_fn(|i| {
                if i < 255 {
                    ((digest[i / 8] >> (i % 8)) & 1) as i32 ^ flip
                } else {
                    flip
                }
            });
            assert_eq!(matches(&head, &digest), matches_reference(&head, &digest));
            assert!(matches(&head, &digest));
            for i in 0..256 {
                head[i] ^= 1;
                assert!(!matches(&head, &digest));
                head[i] ^= 1;
            }
            for value in &mut head {
                *value |= i32::MIN;
            }
            assert!(matches(&head, &digest));
        }
        let mut rng = 0xaabbccddeeffu64;
        for _ in 0..10000 {
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let digest = core::array::from_fn(|_| next() as u8);
            let head = core::array::from_fn(|_| next() as i32);
            assert_eq!(matches(&head, &digest), matches_reference(&head, &digest));
        }
    }
}
