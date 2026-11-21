//! Public-only eight-lane label recovery, also suitable for a fused NTT tail.
use core::arch::aarch64::*;
const fn plane(midpoint: bool, shift: u32) -> [u8; 48] {
    let mut out = [0; 48];
    let mut j = 0;
    while j < 34 {
        let value = if midpoint {
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
            left + right
        } else {
            super::center(j as i32)
        };
        out[j] = (value >> shift) as u8;
        j += 1;
    }
    out
}
static CENTER_LO: [u8; 48] = plane(false, 0);
static CENTER_HI: [u8; 48] = plane(false, 8);
static MID_LO: [u8; 48] = plane(true, 0);
static MID_HI: [u8; 48] = plane(true, 8);
#[derive(Clone, Copy)]
pub(crate) struct Tables {
    lo: uint8x16x3_t,
    hi: uint8x16x3_t,
    ml: uint8x16x3_t,
    mh: uint8x16x3_t,
}
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. Nothing
/// else is required: the three unaligned 16-byte loads cover exactly the 48 bytes behind the
/// reference.
#[inline(always)]
unsafe fn load(p: &[u8; 48]) -> uint8x16x3_t {
    uint8x16x3_t(
        vld1q_u8(p.as_ptr()),
        vld1q_u8(p.as_ptr().add(16)),
        vld1q_u8(p.as_ptr().add(32)),
    )
}
impl Tables {
    /// # Safety
    ///
    /// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
    /// macOS, where NEON is in the baseline, so every caller in this crate meets this.
    /// Nothing else is required: the four tables are 48-byte statics, the extent `load` reads.
    #[inline(always)]
    pub(crate) unsafe fn new() -> Self {
        Self {
            lo: load(&CENTER_LO),
            hi: load(&CENTER_HI),
            ml: load(&MID_LO),
            mh: load(&MID_HI),
        }
    }
}
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer. The table
/// lookup is a register operation: an index outside the three table registers yields zero.
#[inline(always)]
unsafe fn lookup(j: uint8x8_t, lo: uint8x16x3_t, hi: uint8x16x3_t) -> uint16x8_t {
    let index = vcombine_u8(j, vdup_n_u8(0));
    vreinterpretq_u16_u8(vzip1q_u8(vqtbl3q_u8(lo, index), vqtbl3q_u8(hi, index)))
}
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer.
#[inline(always)]
pub(crate) unsafe fn context_data8(x: uint16x8_t, t: Tables) -> (uint16x8_t, int16x8_t) {
    // The approximate quotient overestimates floor(34*x/7681) by at most one.
    let guess = vcombine_u16(
        vshrn_n_u32::<16>(vmull_n_u16(vget_low_u16(x), 291)),
        vshrn_n_u32::<16>(vmull_n_u16(vget_high_u16(x), 291)),
    );
    // ceil(j*q/34)=226*j-floor(3*j/34), for 0<=j<=34.
    let floor = vaddq_u16(
        vaddq_u16(
            vandq_u16(vcgeq_u16(guess, vdupq_n_u16(12)), vdupq_n_u16(1)),
            vandq_u16(vcgeq_u16(guess, vdupq_n_u16(23)), vdupq_n_u16(1)),
        ),
        vandq_u16(vcgeq_u16(guess, vdupq_n_u16(34)), vdupq_n_u16(1)),
    );
    let boundary = vsubq_u16(vmulq_n_u16(guess, 226), floor);
    let j = vsubq_u16(guess, vandq_u16(vcltq_u16(x, boundary), vdupq_n_u16(1)));
    let mid = lookup(vmovn_u16(j), t.ml, t.mh);
    let side = vreinterpretq_s16_u16(vsubq_u16(
        vdupq_n_u16(1),
        vandq_u16(vcleq_u16(vaddq_u16(x, x), mid), vdupq_n_u16(2)),
    ));
    (j, side)
}
/// Preconditions x<7681, k<4 in every lane. Returns canonical label and unsigned
/// circular residual magnitude. The caller must still enforce magnitude<=450.
///
/// # Safety
///
/// The caller must run on a CPU with NEON. `build.rs` asserts a little-endian AArch64 target on
/// macOS, where NEON is in the baseline, so every caller in this crate meets this. The
/// function works on vector values only; it accesses no memory through a raw pointer. The lane
/// preconditions stated above are needed for the documented result, not for memory safety.
#[inline(always)]
pub(crate) unsafe fn recover8(x: uint16x8_t, k: uint8x8_t, t: Tables) -> (uint8x8_t, uint16x8_t) {
    let (j, side) = context_data8(x, t);
    let direction_bytes = vreinterpret_s8_u8(vget_low_u8(vqtbl1q_u8(
        vreinterpretq_u8_u32(vdupq_n_u32(0x02ff0100)),
        vcombine_u8(k, vdup_n_u8(0)),
    )));
    let u = vaddq_s16(
        vreinterpretq_s16_u16(j),
        vmulq_s16(side, vmovl_s8(direction_bytes)),
    );
    let u = vsubq_s16(
        vaddq_s16(
            u,
            vandq_s16(
                vreinterpretq_s16_u16(vcltq_s16(u, vdupq_n_s16(0))),
                vdupq_n_s16(34),
            ),
        ),
        vandq_s16(
            vreinterpretq_s16_u16(vcgeq_s16(u, vdupq_n_s16(34))),
            vdupq_n_s16(34),
        ),
    );
    let labels = vmovn_u16(vreinterpretq_u16_s16(u));
    let centers = lookup(labels, t.lo, t.hi);
    let distance = vabdq_u16(centers, x);
    let magnitude = vminq_u16(distance, vsubq_u16(vdupq_n_u16(7681), distance));
    (labels, magnitude)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_contexts_and_indices() {
        unsafe {
            let t = Tables::new();
            for k in 0..4 {
                for base in (0..7681).step_by(8) {
                    let x: [u16; 8] = core::array::from_fn(|i| ((base + i) % 7681) as u16);
                    let (u, m) = recover8(vld1q_u16(x.as_ptr()), vdup_n_u8(k), t);
                    let mut labels = [0; 8];
                    let mut mag = [0; 8];
                    vst1_u8(labels.as_mut_ptr(), u);
                    vst1q_u16(mag.as_mut_ptr(), m);
                    for i in 0..8 {
                        let expected = super::super::local_labels(x[i] as i32)[k as usize];
                        assert_eq!(labels[i], expected as u8);
                        assert_eq!(
                            mag[i],
                            super::super::centered(super::super::center(expected) - x[i] as i32)
                                .unsigned_abs() as u16
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn quotient_correction_exact() {
        for x in 0..7681 {
            let j = x * 291 / 65536;
            assert!((j == 34 * x / 7681) || (j == 34 * x / 7681 + 1));
            let boundary = 226 * j - 3 * j / 34;
            assert_eq!(j - i32::from(x < boundary), 34 * x / 7681);
        }
    }
}
