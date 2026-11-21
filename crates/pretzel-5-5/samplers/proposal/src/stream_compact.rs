//! ARM stream compaction. The abstract schedule does not certify emitted code.
//! All table addresses are public. Indices below select bytes within registers.
//! Caller owns and erases metadata, ranks, and registers/spills.
use std::arch::aarch64::*;
// Identity value barrier.
// SAFETY: comment-only assembly leaves its initialized register unchanged;
// it accesses no memory/stack and preserves flags. Deliberately not pure.
#[inline(always)]
fn opaque_mask(mut value: u64) -> u64 {
    // SAFETY: the template is an assembler comment, so no instruction is emitted. The only operand
    // is a general-purpose register holding an initialized u64; no memory, stack or flag is
    // touched, as the options state.
    unsafe {
        core::arch::asm!("/* {value} */",value=inout(reg)value,options(nomem,nostack,preserves_flags));
    }
    value
}
const PACK4: [u8; 64] = [
    255, 255, 255, 255, 0, 255, 255, 255, 1, 255, 255, 255, 0, 1, 255, 255, 2, 255, 255, 255, 0, 2,
    255, 255, 1, 2, 255, 255, 0, 1, 2, 255, 3, 255, 255, 255, 0, 3, 255, 255, 1, 3, 255, 255, 0, 1,
    3, 255, 2, 3, 255, 255, 0, 2, 3, 255, 1, 2, 3, 255, 0, 1, 2, 3,
];
const I: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const REPEAT4: [u8; 16] = [0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3];
const W4: [u8; 16] = [1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8, 1, 2, 4, 8];
const BASE4: [u8; 16] = [0, 0, 0, 0, 4, 4, 4, 4, 8, 8, 8, 8, 12, 12, 12, 12];
const FIRST: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2];
const SECOND: [u8; 16] = [1, 1, 1, 1, 1, 1, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3];
/// Input lanes are exactly zero or one. Return original indices in stable
/// order; padding bytes are 255. No mask-dependent memory address.
///
/// # Safety
/// The CPU must have NEON (every AArch64 target of this crate has it). The function reads only the constant tables of this module.
#[inline(always)]
pub unsafe fn compact_indices(pending: uint8x16_t) -> (uint8x16_t, u8) {
    let i = vld1q_u8(I.as_ptr());
    let ff = vdupq_n_u8(255);
    let m32 = vpaddlq_u16(vpaddlq_u8(vmulq_u8(pending, vld1q_u8(W4.as_ptr()))));
    let m8 = vcombine_u8(
        vmovn_u16(vcombine_u16(vmovn_u32(m32), vdup_n_u16(0))),
        vdup_n_u8(0),
    );
    let count4 = vcntq_u8(m8);
    let q = vorrq_u8(
        vshlq_n_u8::<2>(vqtbl1q_u8(m8, vld1q_u8(REPEAT4.as_ptr()))),
        vandq_u8(i, vdupq_n_u8(3)),
    );
    let p = PACK4.as_ptr();
    let table = uint8x16x4_t(
        vld1q_u8(p),
        vld1q_u8(p.add(16)),
        vld1q_u8(p.add(32)),
        vld1q_u8(p.add(48)),
    );
    let local = vqtbl4q_u8(table, q);
    let local = vbslq_u8(
        vcltq_u8(local, vdupq_n_u8(4)),
        vaddq_u8(local, vld1q_u8(BASE4.as_ptr())),
        ff,
    );
    let a = vqtbl1q_u8(count4, vld1q_u8(FIRST.as_ptr()));
    let b = vqtbl1q_u8(count4, vld1q_u8(SECOND.as_ptr()));
    let k = vandq_u8(i, vdupq_n_u8(7));
    let base = vandq_u8(i, vdupq_n_u8(8));
    let q = vbslq_u8(
        vcltq_u8(k, a),
        vaddq_u8(base, k),
        vsubq_u8(vaddq_u8(vaddq_u8(base, vdupq_n_u8(4)), k), a),
    );
    let q = vbslq_u8(vcltq_u8(k, vaddq_u8(a, b)), q, ff);
    let half = vbslq_u8(vcltq_u8(k, vaddq_u8(a, b)), vqtbl1q_u8(local, q), ff);
    let first = vgetq_lane_u8::<0>(count4) + vgetq_lane_u8::<1>(count4);
    let count = vaddvq_u8(pending);
    let a = vdupq_n_u8(first);
    let q = vbslq_u8(vcltq_u8(i, a), i, vsubq_u8(vaddq_u8(vdupq_n_u8(8), i), a));
    let q = vbslq_u8(vcltq_u8(i, vdupq_n_u8(count)), q, ff);
    (
        vbslq_u8(vcltq_u8(i, vdupq_n_u8(count)), vqtbl1q_u8(half, q), ff),
        count,
    )
}
/// Generate the append index for one public 16-byte segment of a queue.
/// K is 8, 16 or 64; segment is in 0..ceil(K/16). old<=2560; new<=16.
///
/// # Safety
/// The CPU must have NEON (every AArch64 target of this crate has it). The function reads only the constant tables of this module.
#[inline(always)]
pub unsafe fn append_index<const K: usize>(old: u16, new: u8, segment: usize) -> uint8x16_t {
    let pos = vaddq_u8(vld1q_u8(I.as_ptr()), vdupq_n_u8((16 * segment) as u8));
    let index = vsubq_u8(pos, vdupq_n_u8(old as u8));
    // Once old>=K, no new entry can fit. This guard is essential: without it,
    // truncating old to u8 could wrap and overwrite prior queue entries.
    let live = vdupq_n_u8(opaque_mask(0u64.wrapping_sub((old < K as u16) as u64)) as u8);
    let valid = vandq_u8(
        vandq_u8(vcltq_u8(index, vdupq_n_u8(new)), live),
        vcltq_u8(pos, vdupq_n_u8(K as u8)),
    );
    vbslq_u8(valid, index, vdupq_n_u8(255))
}
/// One plane update; caller loops over the public 5 or 14 metadata planes.
/// dst is an aligned-or-unaligned valid 16-byte region at a PUBLIC address.
///
/// # Safety
/// The CPU must have NEON (every AArch64 target of this crate has it). `dst` must be valid for reads and writes of 16 bytes.
#[inline(always)]
pub unsafe fn append_plane(dst: *mut u8, packed: uint8x16_t, index: uint8x16_t) {
    // Invariant: old unfilled slots are zero; new and old live ranges disjoint.
    vst1q_u8(dst, vorrq_u8(vld1q_u8(dst), vqtbl1q_u8(packed, index)));
}
/// Store active flag and stable global rank. Other lanes get zero.
///
/// # Safety
/// The CPU must have NEON (every AArch64 target of this crate has it). `dst` must be valid for writes of 16 `u16` values; no alignment is required.
#[inline(always)]
pub unsafe fn ranks16(pending: uint8x16_t, old: u16, dst: *mut u16) {
    let z = vdupq_n_u8(0);
    let mut s = pending;
    s = vaddq_u8(s, vextq_u8::<15>(z, s));
    s = vaddq_u8(s, vextq_u8::<14>(z, s));
    s = vaddq_u8(s, vextq_u8::<12>(z, s));
    s = vaddq_u8(s, vextq_u8::<8>(z, s));
    let ex = vsubq_u8(s, pending);
    let active = vcgtq_u8(pending, z);
    let a = [vmovl_u8(vget_low_u8(active)), vmovl_high_u8(active)];
    let r = [vmovl_u8(vget_low_u8(ex)), vmovl_high_u8(ex)];
    for half in 0..2 {
        let mask = vcgtq_u16(a[half], vdupq_n_u16(0));
        let rank = vorrq_u16(vaddq_u16(r[half], vdupq_n_u16(old)), vdupq_n_u16(32768));
        vst1q_u16(dst.add(8 * half), vandq_u16(rank, mask));
    }
}

#[cfg(test)]
mod conditional_stream_tests {
    use super::*;
    #[test]
    fn every_mask_native_compaction_and_ranks() {
        // SAFETY: NEON is a baseline feature of the AArch64 targets this crate builds for. `p`,
        // `got` and `ranks` are local arrays of 16 elements, the exact extent of each unaligned
        // load and store and of the 16 `u16` that `ranks16` writes.
        unsafe {
            for m in 0..65536u32 {
                let mut p = [0u8; 16];
                for i in 0..16 {
                    p[i] = ((m >> i) & 1) as u8;
                }
                let v = vld1q_u8(p.as_ptr());
                let (ix, n) = compact_indices(v);
                let mut got = [0u8; 16];
                vst1q_u8(got.as_mut_ptr(), ix);
                let mut want = [255u8; 16];
                let mut k = 0;
                for i in 0..16 {
                    if p[i] != 0 {
                        want[k] = i as u8;
                        k += 1;
                    }
                }
                assert_eq!(got, want);
                assert_eq!(n as usize, k);
                for base in [0u16, 63, 64, 255, 256, 2544] {
                    let mut ranks = [0u16; 16];
                    ranks16(v, base, ranks.as_mut_ptr());
                    let mut k = base;
                    for i in 0..16 {
                        assert_eq!(
                            ranks[i],
                            if p[i] != 0 {
                                let r = 32768 | k;
                                k += 1;
                                r
                            } else {
                                0
                            }
                        );
                    }
                }
            }
        }
    }
    /// # Safety
    ///
    /// The CPU must have NEON (every AArch64 target of this crate has it). `K` must be at most 64,
    /// so that the `(K + 15) / 16` segments of 16 bytes stay inside the 64-byte `data` array.
    unsafe fn append_cases<const K: usize>() {
        for old in 0..=2560u16 {
            for new in 0..=16u8 {
                let mut data = [0u8; 64];
                let mut want = [0u8; 64];
                for i in 0..K.min(old as usize) {
                    data[i] = (i + 1) as u8;
                    want[i] = data[i];
                }
                let mut src = [0u8; 16];
                for i in 0..new as usize {
                    src[i] = 101 + i as u8;
                    if old as usize + i < K {
                        want[old as usize + i] = src[i];
                    }
                }
                for seg in 0..(K + 15) / 16 {
                    let ix = append_index::<K>(old, new, seg);
                    append_plane(data.as_mut_ptr().add(seg * 16), vld1q_u8(src.as_ptr()), ix);
                }
                assert_eq!(data, want);
            }
        }
    }
    #[test]
    fn every_append_count_including_wrap() {
        // SAFETY: NEON is a baseline feature of the AArch64 targets this crate builds for, and all
        // values of `K` (8, 16 and 64) are at most 64.
        unsafe {
            append_cases::<8>();
            append_cases::<16>();
            append_cases::<64>();
        }
    }
}
