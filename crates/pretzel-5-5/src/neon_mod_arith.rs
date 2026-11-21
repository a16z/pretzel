// Four-lane modular arithmetic with bounded inputs and outputs.
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
unsafe fn qmasked(v: uint32x4_t) -> int32x4_t {
    // SAFETY: The caller guarantees NEON for the register intrinsics; every operand is an initialized
    // vector and no memory is accessed.
    unsafe { vandq_s32(vreinterpretq_s32_u32(v), vdupq_n_s32(7681)) }
}

pub(super) fn add_canonical(out: &mut [i32; 256], delta: &[i32; 256]) {
    // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. out and delta are disjoint 256-element
    // i32 arrays; i advances by four through exactly 256 lanes, and the identity asm changes only its
    // declared register.
    unsafe {
        for i in (0..256).step_by(4) {
            let p = out.as_mut_ptr().add(i);
            let x = vaddq_s32(vld1q_s32(p), vld1q_s32(delta.as_ptr().add(i)));
            let ge = opaque(vcgeq_s32(x, vdupq_n_s32(7681)));
            vst1q_s32(p, vsubq_s32(x, qmasked(ge)));
        }
    }
}

pub(super) fn residual(
    labels: &[i32; 1280],
    t: &[crate::ring::Poly; 5],
    e: &[i32],
    out: &mut [i32; 1280],
) {
    assert!(e.len() >= 1280);
    // SAFETY: The AArch64 gate of build.rs supplies baseline NEON. e.len()>=1280 is asserted; five
    // 256-lane Poly rows and the 1280-element labels/out arrays cover j=r*256+i through j+3. Output is
    // exclusively borrowed and disjoint from inputs.
    unsafe {
        let zero = vdupq_n_s32(0);
        for (r, row) in t.iter().enumerate() {
            for i in (0..256).step_by(4) {
                let j = r * 256 + i;
                let s = vsubq_s32(
                    vld1q_s32(row.0.as_ptr().add(i)),
                    vld1q_s32(e.as_ptr().add(j)),
                );
                let s = vaddq_s32(s, qmasked(opaque(vcltq_s32(s, zero))));
                let x = vsubq_s32(s, qmasked(opaque(vcgeq_s32(s, vdupq_n_s32(7681)))));
                let label = vld1q_s32(labels.as_ptr().add(j));
                let nz = opaque(vmvnq_u32(vceqq_s32(label, zero)));
                let even = opaque(vceqq_s32(vandq_s32(label, vdupq_n_s32(1)), zero));
                let bit = vreinterpretq_s32_u32(vandq_u32(vandq_u32(nz, even), vdupq_n_u32(1)));
                let center = vaddq_s32(vaddq_s32(vmulq_n_s32(label, 120), vdupq_n_s32(60)), bit);
                let difference = vsubq_s32(center, x);
                let residue = vaddq_s32(difference, qmasked(opaque(vcltq_s32(difference, zero))));
                let result = vsubq_s32(
                    residue,
                    qmasked(opaque(vcgtq_s32(residue, vdupq_n_s32(3840)))),
                );
                vst1q_s32(out.as_mut_ptr().add(j), result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_add_boundaries_and_residuals_match_scalar() {
        for a in [0, 1, 3840, 7680] {
            for b in 0..7681 {
                let mut out = [a; 256];
                add_canonical(&mut out, &[b; 256]);
                assert!(out.iter().all(|&v| v == (a + b) % 7681));
            }
        }
        for trial in 0..64 {
            let labels = core::array::from_fn(|i| ((i + trial) % 64) as i32);
            let t = core::array::from_fn(|r| {
                crate::ring::Poly(core::array::from_fn(|i| {
                    ((r * 256 + i * 71 + trial) % 7681) as i32
                }))
            });
            let e: [i32; 1280] = core::array::from_fn(|i| match i % 5 {
                0 => -7680,
                1 => 7680,
                _ => ((i * 31 + trial) % 15361) as i32 - 7680,
            });
            let mut out = [0; 1280];
            residual(&labels, &t, &e, &mut out);
            for i in 0..1280 {
                let x = crate::ct::reduce_once(t[i / 256].0[i % 256] - e[i], 7681);
                let d = crate::quantize::center(labels[i]) - x;
                let v = d + 7681 * i32::from(d < 0);
                assert_eq!(out[i], v - 7681 * i32::from(v > 3840));
            }
        }
    }
}
