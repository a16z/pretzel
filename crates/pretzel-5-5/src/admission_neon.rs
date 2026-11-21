//! Admission with four independent lanes and the scalar predicates.
//! Native private admission for the 1908-byte signature codec on AArch64.
use super::{HEAD_COEFFICIENTS, HEAD_EXCEPTIONS, LABELS, LABEL_EXCEPTIONS};
use core::arch::aarch64::*;

// Every scalar private predicate has a lane-wise producer barrier here.
#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers. Identity
/// asm preserves its declared inout register and has no memory, stack or flag effects.
unsafe fn opaque(mut value: uint32x4_t) -> uint32x4_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed. The comment-only asm preserves its declared inout register,
    // stack and flags.
    unsafe {
        core::arch::asm!("/* {value:v} */", value = inout(vreg) value,
            options(nomem, nostack, preserves_flags));
        value
    }
}

// Comparisons supply all-one masks; counts consume their low 0/1 bits.
#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers.
unsafe fn bit(value: uint32x4_t) -> uint32x4_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed.
    unsafe { vandq_u32(value, vdupq_n_u32(1)) }
}

// Inputs have already been masked into label 0..63, residual -450..450.
// The result agrees with the scalar rank, including missing rank 8.
#[inline(always)]
#[cfg(test)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers.
unsafe fn rank(label: int32x4_t, residual: int32x4_t) -> uint32x4_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed.
    unsafe {
        let zero = vdupq_n_s32(0);
        let nonzero = opaque(vmvnq_u32(vceqq_s32(label, zero)));
        let even = opaque(vceqq_s32(vandq_s32(label, vdupq_n_s32(1)), zero));
        let center = vaddq_s32(
            vaddq_s32(vmulq_n_s32(label, 120), vdupq_n_s32(60)),
            vreinterpretq_s32_u32(bit(vandq_u32(nonzero, even))),
        );
        let reflected = vsubq_s32(center, vshlq_n_s32::<1>(residual));
        let below = vreinterpretq_s32_u32(bit(opaque(vcltq_s32(reflected, zero))));
        let above = vreinterpretq_s32_u32(bit(opaque(vcgeq_s32(reflected, vdupq_n_s32(7681)))));
        let endpoint = vaddq_s32(reflected, vmulq_n_s32(vsubq_s32(below, above), 7681));
        let shifted = vaddq_s32(endpoint, vdupq_n_s32(59));
        // 59 <= shifted <= 7739. Since 8739*120 = 2^20+104 and
        // 7739*104 < 2^20, floor(shifted*8739/2^20) = floor(shifted/120).
        // The product is below 2^27, so the 32-bit multiply is exact.
        let count = vreinterpretq_s32_u32(vshrq_n_u32::<20>(vmulq_n_u32(
            vreinterpretq_u32_s32(shifted),
            8739,
        )));
        let gt_one = opaque(vcgtq_s32(count, vdupq_n_s32(1)));
        let odd = opaque(vmvnq_u32(vceqq_s32(vandq_s32(count, vdupq_n_s32(1)), zero)));
        let boundary = opaque(vceqq_s32(shifted, vmulq_n_s32(count, 120)));
        let correction = vreinterpretq_s32_u32(bit(vandq_u32(vandq_u32(gt_one, odd), boundary)));
        let prefix = vaddq_s32(
            vsubq_s32(count, correction),
            vshlq_n_s32::<6>(vsubq_s32(above, below)),
        );
        let negative =
            vreinterpretq_s32_u32(opaque(vshrq_n_u32::<31>(vreinterpretq_u32_s32(residual))));
        vreinterpretq_u32_s32(vsubq_s32(
            vmulq_s32(
                vsubq_s32(vshlq_n_s32::<1>(negative), vdupq_n_s32(1)),
                vsubq_s32(prefix, label),
            ),
            negative,
        ))
    }
}

/// Fixed 384 head blocks and 320 label blocks. No private table access.
/// Caller keeps the local owner and full normal/unwind stack scrub.
/// SAFETY: AArch64 supplies NEON; all loads/stores cover four in-range i32s.
#[cfg(test)]
/// # Safety
/// Requires AArch64 NEON. head length is checked against HEAD_COEFFICIENTS; the LABELS-sized arrays
/// supply all four-lane groups. local must remain exclusive and disjoint from the initialized inputs;
/// lane values are masked before rank arithmetic.
pub(super) unsafe fn capacity_mask(
    head: &[i32],
    labels: &[i32; LABELS],
    residual: &[i32; LABELS],
    local: &mut [i32; LABELS],
) -> u64 {
    // SAFETY: The caller supplies the function safety contract. Requires AArch64 NEON. head length is
    // checked against HEAD_COEFFICIENTS; the LABELS-sized arrays supply all four-lane groups. local
    // must remain exclusive and disjoint from the initialized inputs; lane values are masked before
    // rank arithmetic.
    unsafe {
        assert_eq!(head.len(), HEAD_COEFFICIENTS);
        let mut failed = vdupq_n_u32(0);
        let mut heads = vdupq_n_u32(0);
        let mut locals = vdupq_n_u32(0);
        for i in (0..HEAD_COEFFICIENTS).step_by(4) {
            let (cap, half) = if i < 256 { (95, 32) } else { (288, 128) };
            let value = vld1q_s32(head.as_ptr().add(i));
            // VABS wraps MIN to 0x80000000; the unsigned comparison rejects it.
            failed = vorrq_u32(
                failed,
                opaque(vcgtq_u32(
                    vreinterpretq_u32_s32(vabsq_s32(value)),
                    vdupq_n_u32(cap),
                )),
            );
            let low = opaque(vcltq_s32(value, vdupq_n_s32(-half)));
            let high = opaque(vcgeq_s32(value, vdupq_n_s32(half)));
            heads = vaddq_u32(heads, bit(vorrq_u32(low, high)));
        }
        for i in (0..LABELS).step_by(4) {
            let label = vld1q_s32(labels.as_ptr().add(i));
            let r = vld1q_s32(residual.as_ptr().add(i));
            let nonnegative = opaque(vcgeq_s32(label, vdupq_n_s32(0)));
            let in_labels = opaque(vcltq_s32(label, vdupq_n_s32(64)));
            let in_residuals = opaque(vcleq_u32(
                vreinterpretq_u32_s32(vabsq_s32(r)),
                vdupq_n_u32(450),
            ));
            let valid = vandq_u32(vandq_u32(nonnegative, in_labels), in_residuals);
            failed = vorrq_u32(failed, vmvnq_u32(valid));
            // Keep the separate barrier on the composed validity mask too.
            let mask = vreinterpretq_s32_u32(opaque(valid));
            let ranked = rank(vandq_s32(label, mask), vandq_s32(r, mask));
            vst1q_s32(local.as_mut_ptr().add(i), vreinterpretq_s32_u32(ranked));
            failed = vorrq_u32(failed, opaque(vcgeq_u32(ranked, vdupq_n_u32(8))));
            locals = vaddq_u32(locals, bit(opaque(vcgeq_u32(ranked, vdupq_n_u32(4)))));
        }
        let mut bad = u64::from(vmaxvq_u32(failed) & 1);
        bad |= super::opaque_mask(u64::from(vaddvq_u32(heads) > HEAD_EXCEPTIONS as u32));
        bad |= super::opaque_mask(u64::from(vaddvq_u32(locals) > LABEL_EXCEPTIONS as u32));
        super::opaque_mask(0u64.wrapping_sub(1 - bad))
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

// Same admission as `capacity_mask`: the i32 head loop and the i32 validity
// masking are the same; only the rank map runs in eight i16 lanes. After
// masking, label is in 0..=63 and residual in -450..=450, so every rank
// intermediate lies in [-840, 8521] and i16 arithmetic equals the integer
// arithmetic of `rank`. Each private predicate keeps a lane-wise barrier.

#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers. Identity
/// asm preserves its declared inout register and has no memory, stack or flag effects.
unsafe fn opaque16(mut value: uint16x8_t) -> uint16x8_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed. The comment-only asm preserves its declared inout register,
    // stack and flags.
    unsafe {
        // SAFETY: identity assembly preserves the vector, flags and memory.
        core::arch::asm!("/* {value:v} */", value = inout(vreg) value,
            options(nomem, nostack, preserves_flags));
        value
    }
}

#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers.
unsafe fn bit16(value: uint16x8_t) -> uint16x8_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed.
    unsafe { vandq_u16(value, vdupq_n_u16(1)) }
}

#[inline(always)]
/// # Safety
/// Requires AArch64 NEON. The initialized vector operands are processed entirely in registers.
unsafe fn rank16(label: int16x8_t, residual: int16x8_t) -> int16x8_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed.
    unsafe {
        let zero = vdupq_n_s16(0);
        let nonzero = opaque16(vmvnq_u16(vceqq_s16(label, zero)));
        let even = opaque16(vceqq_s16(vandq_s16(label, vdupq_n_s16(1)), zero));
        let center = vaddq_s16(
            vaddq_s16(vmulq_n_s16(label, 120), vdupq_n_s16(60)),
            vreinterpretq_s16_u16(bit16(vandq_u16(nonzero, even))),
        );
        let reflected = vsubq_s16(center, vshlq_n_s16::<1>(residual));
        let below = vreinterpretq_s16_u16(bit16(opaque16(vcltq_s16(reflected, zero))));
        let above = vreinterpretq_s16_u16(bit16(opaque16(vcgeq_s16(reflected, vdupq_n_s16(7681)))));
        let endpoint = vaddq_s16(reflected, vmulq_n_s16(vsubq_s16(below, above), 7681));
        let shifted = vaddq_s16(endpoint, vdupq_n_s16(59));
        // 59 <= shifted <= 7739: floor(shifted * 8739 / 2^20) = floor(shifted / 120),
        // with the same constant and the exact 32-bit product of `rank`.
        let s = vreinterpretq_u16_s16(shifted);
        let low = vshrq_n_u32::<20>(vmull_n_u16(vget_low_u16(s), 8739));
        let high = vshrq_n_u32::<20>(vmull_high_n_u16(s, 8739));
        let count = vreinterpretq_s16_u16(vcombine_u16(vmovn_u32(low), vmovn_u32(high)));
        let gt_one = opaque16(vcgtq_s16(count, vdupq_n_s16(1)));
        let odd = opaque16(vmvnq_u16(vceqq_s16(vandq_s16(count, vdupq_n_s16(1)), zero)));
        let boundary = opaque16(vceqq_s16(shifted, vmulq_n_s16(count, 120)));
        let correction = vreinterpretq_s16_u16(bit16(vandq_u16(vandq_u16(gt_one, odd), boundary)));
        let prefix = vaddq_s16(
            vsubq_s16(count, correction),
            vshlq_n_s16::<6>(vsubq_s16(above, below)),
        );
        let negative =
            vreinterpretq_s16_u16(opaque16(vshrq_n_u16::<15>(vreinterpretq_u16_s16(residual))));
        vsubq_s16(
            vmulq_s16(
                vsubq_s16(vshlq_n_s16::<1>(negative), vdupq_n_s16(1)),
                vsubq_s16(prefix, label),
            ),
            negative,
        )
    }
}

/// Fixed 384 head blocks and 160 eight-lane label blocks.
/// SAFETY: AArch64 NEON; every load/store covers in-range elements.
/// # Safety
/// Requires AArch64 NEON. head length is checked against HEAD_COEFFICIENTS; HEAD_COEFFICIENTS is
/// divisible by four and LABELS by eight. Fixed arrays provide the complete lane groups, and local is
/// exclusive and disjoint from all inputs. Invalid lanes are masked before rank arithmetic.
pub(super) unsafe fn capacity_mask_aux_i16(
    head: &[i32],
    labels: &[i32; LABELS],
    residual: &[i32; LABELS],
    local: &mut [i32; LABELS],
) -> u64 {
    // SAFETY: The caller supplies the function safety contract. Requires AArch64 NEON. head length is
    // checked against HEAD_COEFFICIENTS; HEAD_COEFFICIENTS is divisible by four and LABELS by eight.
    // Fixed arrays provide the complete lane groups, and local is exclusive and disjoint from all
    // inputs. Invalid lanes are masked before rank arithmetic.
    unsafe {
        assert_eq!(head.len(), HEAD_COEFFICIENTS);
        let mut failed = vdupq_n_u32(0);
        let mut heads = vdupq_n_u32(0);
        for i in (0..HEAD_COEFFICIENTS).step_by(4) {
            let (cap, half) = if i < 256 {
                (crate::params::FORMAT_HEAD_LIMIT_LEAD as u32, 32)
            } else {
                (crate::params::FORMAT_HEAD_LIMIT as u32, 128)
            };
            let value = vld1q_s32(head.as_ptr().add(i));
            failed = vorrq_u32(
                failed,
                opaque(vcgtq_u32(
                    vreinterpretq_u32_s32(vabsq_s32(value)),
                    vdupq_n_u32(cap),
                )),
            );
            let low = opaque(vcltq_s32(value, vdupq_n_s32(-half)));
            let high = opaque(vcgeq_s32(value, vdupq_n_s32(half)));
            heads = vaddq_u32(heads, bit(vorrq_u32(low, high)));
        }
        let mut failed16 = vdupq_n_u16(0);
        let mut locals = vdupq_n_u16(0);
        for i in (0..LABELS).step_by(8) {
            let mut masked = [(vdupq_n_s32(0), vdupq_n_s32(0)); 2];
            for (k, slot) in masked.iter_mut().enumerate() {
                let label = vld1q_s32(labels.as_ptr().add(i + 4 * k));
                let r = vld1q_s32(residual.as_ptr().add(i + 4 * k));
                let nonnegative = opaque(vcgeq_s32(label, vdupq_n_s32(0)));
                let in_labels = opaque(vcltq_s32(label, vdupq_n_s32(64)));
                let in_residuals = opaque(vcleq_u32(
                    vreinterpretq_u32_s32(vabsq_s32(r)),
                    vdupq_n_u32(crate::params::FORMAT_RES_LIMIT as u32),
                ));
                let valid = vandq_u32(vandq_u32(nonnegative, in_labels), in_residuals);
                failed = vorrq_u32(failed, vmvnq_u32(valid));
                let mask = vreinterpretq_s32_u32(opaque(valid));
                *slot = (vandq_s32(label, mask), vandq_s32(r, mask));
            }
            let label16 = vcombine_s16(vmovn_s32(masked[0].0), vmovn_s32(masked[1].0));
            let residual16 = vcombine_s16(vmovn_s32(masked[0].1), vmovn_s32(masked[1].1));
            let ranked = rank16(label16, residual16);
            vst1q_s32(local.as_mut_ptr().add(i), vmovl_s16(vget_low_s16(ranked)));
            vst1q_s32(local.as_mut_ptr().add(i + 4), vmovl_high_s16(ranked));
            let unsigned = vreinterpretq_u16_s16(ranked);
            // Ranks are in i16 range, so these unsigned u16 tests equal the u32 tests.
            failed16 = vorrq_u16(failed16, opaque16(vcgeq_u16(unsigned, vdupq_n_u16(8))));
            locals = vaddq_u16(locals, bit16(opaque16(vcgeq_u16(unsigned, vdupq_n_u16(4)))));
        }
        let mut bad = u64::from((vmaxvq_u32(failed) | u32::from(vmaxvq_u16(failed16))) & 1);
        bad |= super::opaque_mask(u64::from(vaddvq_u32(heads) > HEAD_EXCEPTIONS as u32));
        bad |= super::opaque_mask(u64::from(
            u32::from(vaddvq_u16(locals)) > LABEL_EXCEPTIONS as u32,
        ));
        super::opaque_mask(0u64.wrapping_sub(1 - bad))
    }
}

#[cfg(test)]
mod aux_admission_tests {
    use super::*;

    #[test]
    fn rank16_matches_rank_on_the_complete_valid_rectangle() {
        unsafe {
            for label in 0..64i16 {
                for residual in -450..=450i16 {
                    let mut wide = [0u32; 4];
                    vst1q_u32(
                        wide.as_mut_ptr(),
                        rank(vdupq_n_s32(label.into()), vdupq_n_s32(residual.into())),
                    );
                    let mut narrow = [0i16; 8];
                    vst1q_s16(
                        narrow.as_mut_ptr(),
                        rank16(vdupq_n_s16(label), vdupq_n_s16(residual)),
                    );
                    for x in narrow {
                        assert_eq!(i32::from(x), wide[0] as i32, "{label} {residual}");
                    }
                    assert_eq!(
                        wide[0] as i32,
                        super::super::private_index(label.into(), residual.into()) as i32
                    );
                }
            }
        }
    }

    fn compare(head: &[i32; HEAD_COEFFICIENTS], labels: &[i32; LABELS], residual: &[i32; LABELS]) {
        let (mut old, mut new, mut scalar) = ([i32::MIN; LABELS], [i32::MAX; LABELS], [7; LABELS]);
        let expected = unsafe { capacity_mask(head, labels, residual, &mut old) };
        let actual = unsafe { capacity_mask_aux_i16(head, labels, residual, &mut new) };
        let reference = super::super::capacity_mask_scalar(head, labels, residual, &mut scalar);
        assert_eq!(actual, expected);
        assert_eq!(actual, reference);
        assert_eq!(new, old);
        assert_eq!(new, scalar);
    }

    #[test]
    fn complete_valid_domain_in_packets_and_invalid_lanes() {
        let mut pairs = Vec::new();
        for label in 0..64 {
            for residual in -450..=450 {
                pairs.push((label, residual));
            }
        }
        let head = [0i32; HEAD_COEFFICIENTS];
        for chunk in pairs.chunks(LABELS) {
            let mut labels = [0i32; LABELS];
            let mut residual = [0i32; LABELS];
            for (i, &(l, r)) in chunk.iter().enumerate() {
                labels[i] = l;
                residual[i] = r;
            }
            compare(&head, &labels, &residual);
        }
        let bad_labels = [-1, 64, 65, i32::MIN, i32::MAX, -64];
        let bad_residuals = [451, -451, i32::MIN, i32::MAX, 1 << 16, -(1 << 16)];
        for (k, (&l, &r)) in bad_labels.iter().zip(&bad_residuals).enumerate() {
            let mut labels = [5i32; LABELS];
            let mut residual = [-3i32; LABELS];
            labels[k * 97 % LABELS] = l;
            residual[(k * 211 + 3) % LABELS] = r;
            labels[(k * 13 + 8) % LABELS] = l;
            residual[(k * 13 + 8) % LABELS] = r;
            compare(&head, &labels, &residual);
        }
    }

    #[test]
    fn random_packets_and_exception_count_thresholds() {
        let mut seed = 0xa2a2_2026u64;
        let mut next = move || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 33) as i32
        };
        for trial in 0..2048usize {
            let mut head = [0i32; HEAD_COEFFICIENTS];
            let mut labels = [0i32; LABELS];
            let mut residual = [0i32; LABELS];
            for (i, x) in head.iter_mut().enumerate() {
                let (cap, half) = if i < 256 { (95, 32) } else { (288, 128) };
                *x = if next() % 64 == 0 {
                    next() % (cap + 2) * if next() & 1 == 0 { 1 } else { -1 }
                } else {
                    next() % half
                };
            }
            for (label, r) in labels.iter_mut().zip(residual.iter_mut()) {
                *label = next().rem_euclid(if trial.is_multiple_of(9) { 70 } else { 64 })
                    - if trial.is_multiple_of(13) { 3 } else { 0 };
                *r = next().rem_euclid(if trial.is_multiple_of(11) { 921 } else { 901 }) - 450;
            }
            compare(&head, &labels, &residual);
        }
    }
}
