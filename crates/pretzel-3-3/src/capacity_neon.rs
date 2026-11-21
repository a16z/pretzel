//! Fixed-address four-lane capacity scan; no secret-indexed table.
use crate::params::FORMAT_RES_LIMIT;
use core::arch::aarch64::*;
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer.
#[inline(always)]
unsafe fn splat(x: i32) -> int32x4_t {
    vdupq_n_s32(x)
}
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer.
#[inline(always)]
unsafe fn mulhi(x: uint32x4_t, m: u32) -> uint32x4_t {
    vcombine_u32(
        vshrn_n_u64::<32>(vmull_n_u32(vget_low_u32(x), m)),
        vshrn_n_u64::<32>(vmull_n_u32(vget_high_u32(x), m)),
    )
}
const fn center_plane(shift: u32) -> [u8; 48] {
    let mut out = [0; 48];
    let mut j = 0;
    while j < 34 {
        out[j] = (super::center(j as i32) >> shift) as u8;
        j += 1;
    }
    out
}
const fn midpoint_plane(shift: u32) -> [u8; 48] {
    let mut out = [0; 48];
    let mut j = 0;
    while j < 34 {
        let left = if j == 0 {
            super::center(33) - 7681
        } else {
            super::center(j as i32 - 1)
        };
        let right = if j == 33 {
            super::center(0) + 7681
        } else {
            super::center(j as i32 + 1)
        };
        out[j] = ((left + right) >> shift) as u8;
        j += 1;
    }
    out
}
static MID_LOW: [u8; 48] = midpoint_plane(0);
static MID_HIGH: [u8; 48] = midpoint_plane(8);
static LOW: [u8; 48] = center_plane(0);
static HIGH: [u8; 48] = center_plane(8);
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer. The table
/// lookup is a register operation: an index outside the three table registers yields zero.
#[inline(always)]
unsafe fn c(j: int32x4_t, lo: uint8x16x3_t, hi: uint8x16x3_t) -> int32x4_t {
    // All tables are in registers. The byte index is data, never an address.
    let index = vreinterpretq_u8_s32(j);
    let low = vandq_u32(
        vreinterpretq_u32_u8(vqtbl3q_u8(lo, index)),
        vdupq_n_u32(255),
    );
    let high = vandq_u32(
        vreinterpretq_u32_u8(vqtbl3q_u8(hi, index)),
        vdupq_n_u32(255),
    );
    vreinterpretq_s32_u32(vorrq_u32(low, vshlq_n_u32::<8>(high)))
}
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer.
#[inline(always)]
unsafe fn modulo(x: int32x4_t, q: i32) -> int32x4_t {
    vsubq_s32(
        vaddq_s32(
            x,
            vreinterpretq_s32_u32(vandq_u32(vcltq_s32(x, splat(0)), vdupq_n_u32(q as u32))),
        ),
        vreinterpretq_s32_u32(vandq_u32(vcgeq_s32(x, splat(q)), vdupq_n_u32(q as u32))),
    )
}
/// The caller supplies canonical labels and centered native residuals. The one
/// division, by q, is a multiplication by the reciprocal 559168, exact on its
/// bounded positive domain (checked by a test).
///
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. Nothing
/// else is required for memory safety: the four 48-byte tables are read by three unaligned 16-byte
/// loads each, and the loop reads four `i32` from `labels` and `residual` and writes four to
/// `local` at every multiple of 4 below 768, the exact length of the three arrays.
#[inline(never)]
pub(super) unsafe fn scan(
    labels: &[i32; 768],
    residual: &[i32; 768],
    local: &mut [i32; 768],
) -> (u64, u64) {
    let lo = uint8x16x3_t(
        vld1q_u8(LOW.as_ptr()),
        vld1q_u8(LOW.as_ptr().add(16)),
        vld1q_u8(LOW.as_ptr().add(32)),
    );
    let hi = uint8x16x3_t(
        vld1q_u8(HIGH.as_ptr()),
        vld1q_u8(HIGH.as_ptr().add(16)),
        vld1q_u8(HIGH.as_ptr().add(32)),
    );
    let ml = uint8x16x3_t(
        vld1q_u8(MID_LOW.as_ptr()),
        vld1q_u8(MID_LOW.as_ptr().add(16)),
        vld1q_u8(MID_LOW.as_ptr().add(32)),
    );
    let mh = uint8x16x3_t(
        vld1q_u8(MID_HIGH.as_ptr()),
        vld1q_u8(MID_HIGH.as_ptr().add(16)),
        vld1q_u8(MID_HIGH.as_ptr().add(32)),
    );
    let mut bad = vdupq_n_u32(0);
    let mut count = vdupq_n_u32(0);
    for i in (0..768).step_by(4) {
        let u = vld1q_s32(labels.as_ptr().add(i));
        let r = vld1q_s32(residual.as_ptr().add(i));
        let x = modulo(vsubq_s32(c(u, lo, hi), r), 7681);
        let j = vreinterpretq_s32_u32(mulhi(vreinterpretq_u32_s32(vmulq_n_s32(x, 34)), 559168));
        let s = vsubq_s32(
            splat(1),
            vreinterpretq_s32_u32(vandq_u32(
                vcleq_s32(vaddq_s32(x, x), c(j, ml, mh)),
                vdupq_n_u32(2),
            )),
        );
        let difference = vsubq_s32(u, j);
        let distance = vsubq_s32(
            vaddq_s32(
                difference,
                vreinterpretq_s32_u32(vandq_u32(
                    vcltq_s32(difference, splat(-17)),
                    vdupq_n_u32(34),
                )),
            ),
            vreinterpretq_s32_u32(vandq_u32(vcgeq_s32(difference, splat(17)), vdupq_n_u32(34))),
        );
        let directed = vmulq_s32(distance, s);
        let a = vceqq_s32(directed, splat(0));
        let b = vceqq_s32(directed, splat(1));
        let d = vceqq_s32(directed, splat(-1));
        let e = vceqq_s32(directed, splat(2));
        let k = vaddq_u32(
            vaddq_u32(vandq_u32(b, vdupq_n_u32(1)), vandq_u32(d, vdupq_n_u32(2))),
            vandq_u32(e, vdupq_n_u32(3)),
        );
        vst1q_s32(local.as_mut_ptr().add(i), vreinterpretq_s32_u32(k));
        count = vaddq_u32(
            count,
            vandq_u32(vcgeq_u32(k, vdupq_n_u32(2)), vdupq_n_u32(1)),
        );
        bad = vorrq_u32(bad, vmvnq_u32(vorrq_u32(vorrq_u32(a, b), vorrq_u32(d, e))));
        bad = vorrq_u32(
            bad,
            vcgtq_u32(
                vreinterpretq_u32_s32(vabsq_s32(r)),
                vdupq_n_u32(FORMAT_RES_LIMIT as u32),
            ),
        );
    }
    (
        0u64.wrapping_sub(u64::from(vmaxvq_u32(bad) != 0)),
        u64::from(vaddvq_u32(count)),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reciprocals_are_exact_on_complete_domains() {
        for (divisor, max, m) in [(34, 102, 126322568u64), (7681, 261120, 559168)] {
            for x in 0..=max {
                assert_eq!(x / divisor, ((x as u64 * m) >> 32) as i32);
            }
        }
    }
    #[test]
    fn all_context_label_pairs_match_scalar() {
        for u in 0..34 {
            for base in (0..7681).step_by(768) {
                let labels = [u; 768];
                let residual = core::array::from_fn(|i| {
                    super::super::centered(super::super::center(u) - ((base + i) % 7681) as i32)
                });
                let mut local = [0; 768];
                let (bad, count) = unsafe { scan(&labels, &residual, &mut local) };
                let mut expected_bad = 0u64;
                let mut expected_count = 0;
                for i in 0..768 {
                    let x = ((base + i) % 7681) as i32;
                    let l = super::super::local_labels(x);
                    let k =
                        i32::from(u == l[1]) + 2 * i32::from(u == l[2]) + 3 * i32::from(u == l[3]);
                    assert_eq!(local[i], k);
                    expected_count += u64::from(k >= 2);
                    expected_bad |= 0u64.wrapping_sub(u64::from(
                        !l.contains(&u) || residual[i].unsigned_abs() > 450,
                    ));
                }
                assert_eq!((bad, count), (expected_bad, expected_count));
            }
        }
    }
}
