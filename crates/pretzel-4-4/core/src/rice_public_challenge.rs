//! Public verification only: compare response parity directly with the folded hash.
pub(super) fn matches(head: &[i32; 256], digest: &[u8; 32]) -> bool {
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
    #[cfg(target_arch = "aarch64")]
    // SAFETY: head is a typed [i32; 256]. Sixteen groups each read sixteen i32 values, and
    // shift contains 16 bytes; folded has 32 bytes with checked indexing. The aarch64 cfg
    // supplies NEON.
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
