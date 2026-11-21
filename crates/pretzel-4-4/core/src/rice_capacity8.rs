//! Fixed-address eight-lane private capacity scan. No secret-indexed memory.
//! Caller supplies canonical labels and centered native residuals, also on aborts.
use super::public_recovery::{centers8, context_data8, Tables};
use core::arch::aarch64::*;
/// # Safety
/// Call only on AArch64 with NEON, guaranteed by the supported target and the module cfg.
#[inline(never)]
pub(super) unsafe fn scan(
    labels: &[i32; 1024],
    residual: &[i32; 1024],
    local: &mut [i32; 1024],
) -> (u64, u64) {
    // SAFETY: The references supply disjoint 1024-element arrays. The eight-lane loop uses
    // i and i+4 for four-i32 accesses, all within 1024; Tables owns complete initialized
    // register tables and the caller supplies NEON.
    unsafe {
        let tables = Tables::new();
        let mut bad = vdupq_n_u16(0);
        let mut count = vdupq_n_u16(0);
        for i in (0..1024).step_by(8) {
            let u = vcombine_s16(
                vmovn_s32(vld1q_s32(labels.as_ptr().add(i))),
                vmovn_s32(vld1q_s32(labels.as_ptr().add(i + 4))),
            );
            let r = vcombine_s16(
                vmovn_s32(vld1q_s32(residual.as_ptr().add(i))),
                vmovn_s32(vld1q_s32(residual.as_ptr().add(i + 4))),
            );
            let center =
                vreinterpretq_s16_u16(centers8(vmovn_u16(vreinterpretq_u16_s16(u)), tables));
            let x = vsubq_s16(center, r);
            let x = vsubq_s16(
                vaddq_s16(
                    x,
                    vandq_s16(
                        vreinterpretq_s16_u16(vcltq_s16(x, vdupq_n_s16(0))),
                        vdupq_n_s16(7681),
                    ),
                ),
                vandq_s16(
                    vreinterpretq_s16_u16(vcgeq_s16(x, vdupq_n_s16(7681))),
                    vdupq_n_s16(7681),
                ),
            );
            let (j, side) = context_data8(vreinterpretq_u16_s16(x), tables);
            let difference = vsubq_s16(u, vreinterpretq_s16_u16(j));
            let distance = vsubq_s16(
                vaddq_s16(
                    difference,
                    vandq_s16(
                        vreinterpretq_s16_u16(vcltq_s16(difference, vdupq_n_s16(-17))),
                        vdupq_n_s16(34),
                    ),
                ),
                vandq_s16(
                    vreinterpretq_s16_u16(vcgeq_s16(difference, vdupq_n_s16(17))),
                    vdupq_n_s16(34),
                ),
            );
            let directed = vmulq_s16(distance, side);
            let a = vceqq_s16(directed, vdupq_n_s16(0));
            let b = vceqq_s16(directed, vdupq_n_s16(1));
            let d = vceqq_s16(directed, vdupq_n_s16(-1));
            let e = vceqq_s16(directed, vdupq_n_s16(2));
            let k = vaddq_u16(
                vaddq_u16(vandq_u16(b, vdupq_n_u16(1)), vandq_u16(d, vdupq_n_u16(2))),
                vandq_u16(e, vdupq_n_u16(3)),
            );
            vst1q_s32(
                local.as_mut_ptr().add(i),
                vreinterpretq_s32_u32(vmovl_u16(vget_low_u16(k))),
            );
            vst1q_s32(
                local.as_mut_ptr().add(i + 4),
                vreinterpretq_s32_u32(vmovl_high_u16(k)),
            );
            count = vaddq_u16(
                count,
                vandq_u16(vcgeq_u16(k, vdupq_n_u16(2)), vdupq_n_u16(1)),
            );
            bad = vorrq_u16(bad, vmvnq_u16(vorrq_u16(vorrq_u16(a, b), vorrq_u16(d, e))));
            bad = vorrq_u16(
                bad,
                vcgtq_u16(
                    vreinterpretq_u16_s16(vabsq_s16(r)),
                    vdupq_n_u16(crate::params::FORMAT_RES_LIMIT as u16),
                ),
            );
        }
        (
            0u64.wrapping_sub(u64::from(vmaxvq_u16(bad) != 0)),
            u64::from(vaddvq_u16(count)),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::FORMAT_RES_LIMIT;
    #[test]
    fn exhaustive_context_label_equivalence() {
        for u in 0..34 {
            for base in (0..7681).step_by(1024) {
                let labels = [u; 1024];
                let residual = core::array::from_fn(|i| {
                    super::super::centered(super::super::center(u) - ((base + i) % 7681) as i32)
                });
                let mut local = [0; 1024];
                let (bad, count) = unsafe { scan(&labels, &residual, &mut local) };
                let mut eb = 0u64;
                let mut ec = 0;
                for i in 0..1024 {
                    let x = ((base + i) % 7681) as i32;
                    let l = super::super::local_labels(x);
                    let k =
                        i32::from(u == l[1]) + 2 * i32::from(u == l[2]) + 3 * i32::from(u == l[3]);
                    assert_eq!(local[i], k);
                    ec += u64::from(k >= 2);
                    eb |= 0u64.wrapping_sub(u64::from(
                        !l.contains(&u) || residual[i].unsigned_abs() > FORMAT_RES_LIMIT as u32,
                    ));
                }
                assert_eq!((bad, count), (eb, ec));
            }
        }
    }
}
