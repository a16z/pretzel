//! Public row verification only. Also compiled into `crates/pretzel-5-5` by path.
#![allow(clippy::needless_range_loop, clippy::too_many_arguments)]
use super::*;

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Trace {
    inverse: [i16; N],
    magnitudes: [u16; N],
    failures: u32,
    sums: [u64; 4],
}

#[cfg(test)]
impl Trace {
    pub(super) fn new() -> Self {
        Self {
            inverse: [0; N],
            magnitudes: [0; N],
            failures: 0,
            sums: [0; 4],
        }
    }
}

#[inline(always)]
pub(super) fn run<const C: usize, const L: usize>(
    a: &[crate::compact_ring::CompactPoly; C],
    b: &[crate::compact_ring::CompactPoly; C],
    delta: &Poly,
    local: &[u8; L],
    labels: &mut [u8; N],
    caps: &[u64; 452],
    buf: &mut [i16; N],
    #[cfg(test)] trace: &mut Trace,
) -> Option<u64> {
    const {
        assert!(N == 256 && ((C == 5 && L == 64) || (C == 6 && L == 256)));
    }
    let mut sums = [0u64; 4];
    let mut bad = false;
    let t = ntt16_tables();
    // SAFETY: The neon module is gated by AArch64/neon. All polynomial and scratch arrays have N=256
    // initialized coefficients. Transform lengths are powers of two: outer runs partition N into
    // complete eight-lane pairs; sb<4 and r<8 bound each 64-coefficient tile. Twiddle rows contain
    // eight initialized i16 lanes and use checked indexing. Output/scratch owners are exclusive and
    // disjoint from shared inputs. The asserted L permits two checked byte-plane
    // accesses or one eight-byte load within local. labels and test trace arrays
    // have N entries; the vector maximum guards every unchecked cap lookup.
    // `bp` is derived once, and from there to its last use every access to the buffer goes through
    // `bp`: `barrett_all` receives an exclusive reference reborrowed from `bp`, which is not used
    // after the call returns, and the test trace copies through a shared reference reborrowed from
    // `bp`. No other path to the buffer is used while `bp` is live.
    unsafe {
        let bp = buf.as_mut_ptr();
        // Base transform schedule: a fused schedule increases code size and
        // rematerializes recovery constants.
        for i in (0..N).step_by(8) {
            let mut lo = vdupq_n_s32(0);
            let mut hi = vdupq_n_s32(0);
            for c in 0..C {
                let av = vld1q_s16(a[c].0.as_ptr().add(i));
                let bv = vld1q_s16(b[c].0.as_ptr().add(i));
                lo = vmlal_s16(lo, vget_low_s16(av), vget_low_s16(bv));
                hi = vmlal_high_s16(hi, av, bv);
            }
            let lo = reduce_i32x4(lo);
            let hi = reduce_i32x4(hi);
            vst1q_s16(bp.add(i), vcombine_s16(vmovn_s32(lo), vmovn_s32(hi)));
        }
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            transpose8(&mut c);
            let tv = &t.inv_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            // len = 1
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                gs_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            // len = 2
            let (zr, zq) = (ld(2), ld(3));
            gs_pair(&mut c, 0, 2, zr, zq);
            gs_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            gs_pair(&mut c, 4, 6, zr, zq);
            gs_pair(&mut c, 5, 7, zr, zq);
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            // len = 4
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                gs_pair(&mut c, r, r + 4, zr, zq);
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
        let mut k = 31usize;
        let mut len = 8usize;
        while len < N {
            let mut start = 0;
            while start < N {
                let zr = vdupq_n_s16(t.izr[k]);
                let zq = vdupq_n_s16(t.izq[k]);
                k = k.wrapping_sub(1);
                let mut j = start;
                while j < start + len {
                    let u = vld1q_s16(bp.add(j));
                    let v = vld1q_s16(bp.add(j + len));
                    vst1q_s16(bp.add(j), vaddq_s16(u, v));
                    vst1q_s16(bp.add(j + len), twiddle16(vsubq_s16(u, v), zr, zq));
                    j += 8;
                }
                start += 2 * len;
            }
            if len == 16 {
                barrett_all(&mut *bp.cast::<[i16; N]>());
            }
            len <<= 1;
        }
        debug_assert_eq!(k, 0);
        #[cfg(test)]
        {
            trace.inverse.copy_from_slice(&*bp.cast::<[i16; N]>());
        }
        let nr = vdupq_n_s16(t.ninv_r);
        let nq = vdupq_n_s16(t.ninv_q);
        let q = vdupq_n_u16(Q as u16);
        let recovery = crate::rice_codec::PublicRecoveryTables::new();
        for i in (0..N).step_by(8) {
            let v = canonical16(twiddle16(vld1q_s16(bp.add(i)), nr, nq));
            // PreparedPk's public dither and v are canonical in [0,Q).
            // Narrow before adding: sum <= 2*7680 = 15360, so no lane wraps.
            // For sum<Q, sum-Q wraps above sum in u16; otherwise it is smaller.
            // Unsigned min therefore gives the same single subtraction as the
            // two-vector i32 form, including contexts whose recovery fails.
            let dither = vcombine_s16(
                vmovn_s32(vld1q_s32(delta.0.as_ptr().add(i))),
                vmovn_s32(vld1q_s32(delta.0.as_ptr().add(i + 4))),
            );
            let sum = vreinterpretq_u16_s16(vaddq_s16(v, dither));
            let x = vminq_u16(sum, vsubq_u16(sum, q));
            let indices = if L == 64 {
                let shifts = vreinterpret_s8_u64(vcreate_u64(0xf9fafbfcfdfeff00));
                let low = vand_u8(vshl_u8(vdup_n_u8(local[i / 8]), shifts), vdup_n_u8(1));
                let high = vand_u8(vshl_u8(vdup_n_u8(local[32 + i / 8]), shifts), vdup_n_u8(1));
                vorr_u8(low, vshl_n_u8::<1>(high))
            } else {
                vld1_u8(local.as_ptr().add(i))
            };
            let (u, magnitude) = crate::rice_codec::public_recover8(x, indices, recovery);
            vst1_u8(labels.as_mut_ptr().add(i), u);
            #[cfg(test)]
            {
                vst1q_u16(trace.magnitudes.as_mut_ptr().add(i), magnitude);
                if vmaxvq_u16(magnitude) > crate::params::FORMAT_RES_LIMIT as u16 {
                    trace.failures |= 1u32 << (i / 8);
                }
            }
            if vmaxvq_u16(magnitude) > crate::params::FORMAT_RES_LIMIT as u16 {
                bad = true;
            } else {
                // SAFETY: the else branch follows the maximum over all eight u16 lanes.
                // Each unchanged lane is therefore <=450, within the fixed452-entry array.
                macro_rules! add_lane {
                    ($lane:literal) => {
                        sums[$lane % 4] +=
                            *caps.get_unchecked(vgetq_lane_u16::<$lane>(magnitude) as usize);
                    };
                }
                add_lane!(0);
                add_lane!(1);
                add_lane!(2);
                add_lane!(3);
                add_lane!(4);
                add_lane!(5);
                add_lane!(6);
                add_lane!(7);
            }
        }
    }
    #[cfg(test)]
    {
        trace.sums = sums;
    }
    if bad {
        None
    } else {
        Some(sums.into_iter().sum())
    }
}

#[cfg(test)]
#[inline(always)]
pub(super) fn reference<const C: usize, const L: usize>(
    a: &[crate::compact_ring::CompactPoly; C],
    b: &[crate::compact_ring::CompactPoly; C],
    delta: &Poly,
    local: &[u8; L],
    labels: &mut [u8; N],
    caps: &[u64; 452],
    buf: &mut [i16; N],
    #[cfg(test)] trace: &mut Trace,
) -> Option<u64> {
    const {
        assert!(N == 256 && ((C == 5 && L == 64) || (C == 6 && L == 256)));
    }
    let mut sums = [0u64; 4];
    let mut bad = false;
    let t = ntt16_tables();
    // SAFETY: The neon module is gated by AArch64/neon. All polynomial and scratch arrays have N=256
    // initialized coefficients. Transform lengths are powers of two: outer runs partition N into
    // complete eight-lane pairs; sb<4 and r<8 bound each 64-coefficient tile. Twiddle rows contain
    // eight initialized i16 lanes and use checked indexing. Output/scratch owners are exclusive and
    // disjoint from shared inputs. The asserted L permits two checked byte-plane
    // accesses or one eight-byte load within local. labels and test trace arrays
    // have N entries; the vector maximum guards every unchecked cap lookup.
    // `bp` is derived once, and from there to its last use every access to the buffer goes through
    // `bp`: `barrett_all` receives an exclusive reference reborrowed from `bp`, which is not used
    // after the call returns, and the test trace copies through a shared reference reborrowed from
    // `bp`. No other path to the buffer is used while `bp` is live.
    unsafe {
        let bp = buf.as_mut_ptr();
        for i in (0..N).step_by(8) {
            let mut lo = vdupq_n_s32(0);
            let mut hi = vdupq_n_s32(0);
            for c in 0..C {
                let av = vld1q_s16(a[c].0.as_ptr().add(i));
                let bv = vld1q_s16(b[c].0.as_ptr().add(i));
                lo = vmlal_s16(lo, vget_low_s16(av), vget_low_s16(bv));
                hi = vmlal_high_s16(hi, av, bv);
            }
            let lo = reduce_i32x4(lo);
            let hi = reduce_i32x4(hi);
            vst1q_s16(bp.add(i), vcombine_s16(vmovn_s32(lo), vmovn_s32(hi)));
        }
        for sb in 0..4 {
            let base = 64 * sb;
            let mut c: [int16x8_t; 8] = core::array::from_fn(|r| vld1q_s16(bp.add(base + 8 * r)));
            transpose8(&mut c);
            let tv = &t.inv_t[sb];
            let ld = |i: usize| vld1q_s16(tv[i].as_ptr());
            // len = 1
            for h in 0..4 {
                let (zr, zq) = (ld(6 + 2 * h), ld(7 + 2 * h));
                gs_pair(&mut c, 2 * h, 2 * h + 1, zr, zq);
            }
            // len = 2
            let (zr, zq) = (ld(2), ld(3));
            gs_pair(&mut c, 0, 2, zr, zq);
            gs_pair(&mut c, 1, 3, zr, zq);
            let (zr, zq) = (ld(4), ld(5));
            gs_pair(&mut c, 4, 6, zr, zq);
            gs_pair(&mut c, 5, 7, zr, zq);
            for r in 0..8 {
                c[r] = barrett16(c[r]);
            }
            // len = 4
            let (zr, zq) = (ld(0), ld(1));
            for r in 0..4 {
                gs_pair(&mut c, r, r + 4, zr, zq);
            }
            transpose8(&mut c);
            for r in 0..8 {
                vst1q_s16(bp.add(base + 8 * r), c[r]);
            }
        }
        let mut k = 31usize;
        let mut len = 8usize;
        while len < N {
            let mut start = 0;
            while start < N {
                let zr = vdupq_n_s16(t.izr[k]);
                let zq = vdupq_n_s16(t.izq[k]);
                k = k.wrapping_sub(1);
                let mut j = start;
                while j < start + len {
                    let u = vld1q_s16(bp.add(j));
                    let v = vld1q_s16(bp.add(j + len));
                    vst1q_s16(bp.add(j), vaddq_s16(u, v));
                    vst1q_s16(bp.add(j + len), twiddle16(vsubq_s16(u, v), zr, zq));
                    j += 8;
                }
                start += 2 * len;
            }
            if len == 16 {
                barrett_all(&mut *bp.cast::<[i16; N]>());
            }
            len <<= 1;
        }
        debug_assert_eq!(k, 0);
        #[cfg(test)]
        {
            trace.inverse.copy_from_slice(&*bp.cast::<[i16; N]>());
        }
        let nr = vdupq_n_s16(t.ninv_r);
        let nq = vdupq_n_s16(t.ninv_q);
        let q = vdupq_n_s32(Q);
        let recovery = crate::rice_codec::PublicRecoveryTables::new();
        for i in (0..N).step_by(8) {
            let v = canonical16(twiddle16(vld1q_s16(bp.add(i)), nr, nq));
            let lo = vaddq_s32(
                vmovl_s16(vget_low_s16(v)),
                vld1q_s32(delta.0.as_ptr().add(i)),
            );
            let hi = vaddq_s32(vmovl_high_s16(v), vld1q_s32(delta.0.as_ptr().add(i + 4)));
            let lo = vsubq_s32(lo, vandq_s32(vreinterpretq_s32_u32(vcgeq_s32(lo, q)), q));
            let hi = vsubq_s32(hi, vandq_s32(vreinterpretq_s32_u32(vcgeq_s32(hi, q)), q));
            // Each context is canonical after the matrix/dither reduction.
            // Decoding establishes two-bit indices (L=64) or indices <8 (L=256).
            let x = vreinterpretq_u16_s16(vcombine_s16(vmovn_s32(lo), vmovn_s32(hi)));
            let indices = if L == 64 {
                let shifts = vreinterpret_s8_u64(vcreate_u64(0xf9fafbfcfdfeff00));
                let low = vand_u8(vshl_u8(vdup_n_u8(local[i / 8]), shifts), vdup_n_u8(1));
                let high = vand_u8(vshl_u8(vdup_n_u8(local[32 + i / 8]), shifts), vdup_n_u8(1));
                vorr_u8(low, vshl_n_u8::<1>(high))
            } else {
                vld1_u8(local.as_ptr().add(i))
            };
            let (u, magnitude) = crate::rice_codec::public_recover8(x, indices, recovery);
            vst1_u8(labels.as_mut_ptr().add(i), u);
            #[cfg(test)]
            {
                vst1q_u16(trace.magnitudes.as_mut_ptr().add(i), magnitude);
                if vmaxvq_u16(magnitude) > crate::params::FORMAT_RES_LIMIT as u16 {
                    trace.failures |= 1u32 << (i / 8);
                }
            }
            if vmaxvq_u16(magnitude) > crate::params::FORMAT_RES_LIMIT as u16 {
                bad = true;
            } else {
                // SAFETY: the else branch follows the maximum over all eight u16 lanes.
                // Each unchanged lane is therefore <=450, within the fixed452-entry array.
                macro_rules! add_lane {
                    ($lane:literal) => {
                        sums[$lane % 4] +=
                            *caps.get_unchecked(vgetq_lane_u16::<$lane>(magnitude) as usize);
                    };
                }
                add_lane!(0);
                add_lane!(1);
                add_lane!(2);
                add_lane!(3);
                add_lane!(4);
                add_lane!(5);
                add_lane!(6);
                add_lane!(7);
            }
        }
    }
    #[cfg(test)]
    {
        trace.sums = sums;
    }
    if bad {
        None
    } else {
        Some(sums.into_iter().sum())
    }
}

#[cfg(test)]
#[path = "public_row_caps_tests.rs"]
mod tests;
