//! Exact canonical residues for every i32, four independent NEON lanes.
use core::arch::aarch64::*;
#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers. Identity
/// asm preserves its declared inout register and has no memory, stack or flag effects.
unsafe fn opaque(mut v: uint32x4_t) -> uint32x4_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed. The comment-only asm preserves its declared inout register,
    // stack and flags.
    unsafe {
        core::arch::asm!("/* {v:v} */", v = inout(vreg) v,
            options(nomem, nostack, preserves_flags));
        v
    }
}
#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers.
unsafe fn canonical4(x: int32x4_t) -> int32x4_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed.
    unsafe {
        let modulus = vdupq_n_u32(7681);
        // VABS wraps MIN; its unsigned interpretation is the exact magnitude.
        let magnitude = vreinterpretq_u32_s32(vabsq_s32(x));
        let reciprocal = vdup_n_u32(559168);
        let low = vshrn_n_u64::<32>(vmull_u32(vget_low_u32(magnitude), reciprocal));
        let high = vshrn_n_u64::<32>(vmull_u32(vget_high_u32(magnitude), reciprocal));
        let quotient = vcombine_u32(low, high);
        // 559168*7681 = 2^32+2112. On magnitude <= 2^31, this
        // quotient is floor(magnitude/7681) or one larger. The signed
        // interpretation of the wrapping subtraction is in [-7680,7680].
        let r = vreinterpretq_s32_u32(vsubq_u32(magnitude, vmulq_u32(quotient, modulus)));
        let below = opaque(vcltq_s32(r, vdupq_n_s32(0)));
        let positive = vaddq_u32(vreinterpretq_u32_s32(r), vandq_u32(below, modulus));
        let negative = opaque(vcltq_s32(x, vdupq_n_s32(0)));
        let signed = vbslq_u32(negative, vsubq_u32(modulus, positive), positive);
        let wrap = opaque(vcgeq_u32(signed, modulus));
        vreinterpretq_s32_u32(vsubq_u32(signed, vandq_u32(wrap, modulus)))
    }
}

pub(super) fn convert(input: &[i32], out: &mut [i16; 256]) {
    assert_eq!(input.len(), 256);
    // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. input.len()==256 is asserted; each
    // eight-lane step reads two complete four-i32 blocks and writes eight i16 values into the
    // exclusive 256-element output.
    unsafe {
        for i in (0..256).step_by(8) {
            let a = canonical4(vld1q_s32(input.as_ptr().add(i)));
            let b = canonical4(vld1q_s32(input.as_ptr().add(i + 4)));
            vst1q_s16(
                out.as_mut_ptr().add(i),
                vcombine_s16(vmovn_s32(a), vmovn_s32(b)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_conversion_extremes_quotient_boundaries_and_random() {
        let mut s = 101u64;
        for trial in 0..2048 {
            let input = core::array::from_fn::<_, 256, _>(|i| match trial {
                0 => i32::MIN,
                1 => i32::MAX,
                2 => [-7681, -1, 0, 1, 7680, 7681, 7682, -7682][i % 8],
                _ => {
                    s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (s >> 32) as i32
                }
            });
            let mut out = [0; 256];
            convert(&input, &mut out);
            for i in 0..256 {
                assert_eq!(out[i] as i32, input[i].rem_euclid(7681));
            }
        }
        for q in [1, 2, 65535, 139791, 279583] {
            let input: [i32; 256] = core::array::from_fn(|i| {
                (q * 7681i64 + i as i64 - 128).clamp(i32::MIN as i64, i32::MAX as i64) as i32
            });
            let mut out = [0; 256];
            convert(&input, &mut out);
            for i in 0..256 {
                assert_eq!(out[i] as i32, input[i].rem_euclid(7681));
            }
        }
    }
}
