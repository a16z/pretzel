//! Private ingress with the caller-established -Q < x < Q contract.
use core::arch::aarch64::*;

/// The caller proves the bound from the proposal support or <=128 unit updates.
/// This function is deliberately separate from arbitrary-i32 normalization.
pub(super) fn convert(input: &[i32], out: &mut [i16; 256]) {
    assert_eq!(input.len(), 256);
    // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. input.len()==256 is asserted, and each
    // eight-lane iteration reads two complete four-i32 blocks and writes eight i16 values into the
    // exclusive 256-element output. The identity asm has only declared register effects.
    unsafe {
        for i in (0..256).step_by(8) {
            let a = vld1q_s32(input.as_ptr().add(i));
            let b = vld1q_s32(input.as_ptr().add(i + 4));
            let mut ma = vcltq_s32(a, vdupq_n_s32(0));
            let mut mb = vcltq_s32(b, vdupq_n_s32(0));
            core::arch::asm!("/* {ma:v} {mb:v} */", ma = inout(vreg) ma,
                mb = inout(vreg) mb, options(nomem, nostack, preserves_flags));
            let a = vaddq_s32(a, vreinterpretq_s32_u32(vandq_u32(ma, vdupq_n_u32(7681))));
            let b = vaddq_s32(b, vreinterpretq_s32_u32(vandq_u32(mb, vdupq_n_u32(7681))));
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
    fn every_bounded_residue_matches_arbitrary_i32_converter() {
        for first in (-7680i32..=7680).step_by(256) {
            let input = core::array::from_fn::<_, 256, _>(|i| (first + i as i32).min(7680));
            let mut got = [0i16; 256];
            let mut old = [0i16; 256];
            convert(&input, &mut got);
            crate::neon_canonical_residue::convert(&input, &mut old);
            assert_eq!(got, old);
            for (x, y) in input.into_iter().zip(got) {
                assert_eq!(i32::from(y), x.rem_euclid(7681));
            }
        }
    }
}
