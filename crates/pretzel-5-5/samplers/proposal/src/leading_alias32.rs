//! Finite leading alias law with independent fixed-prefix coins.
use crate::simd_lookup::{self, Stage};
use std::arch::aarch64::*;
use std::sync::atomic::{compiler_fence, Ordering};
#[path = "leading_alias32_tables.rs"]
mod tables;
pub const ENTROPY: usize = 1856;
#[repr(C, align(16))]
pub struct Workspace {
    coins: [u32; 256],
    ready: [u8; 256],
    ranks: [u16; 256],
    columns: [u8; 16],
    planes: [[u8; 16]; 5],
    final_columns: [u16; 16],
    final_signs: [u8; 16],
    words: [[u64; 5]; 16],
    cuts: [[u8; 16]; 40],
    values: [i32; 16],
    tape: [u8; 40],
}
impl Workspace {
    pub const fn new() -> Self {
        Self {
            coins: [0; 256],
            ready: [0; 256],
            ranks: [0; 256],
            columns: [0; 16],
            planes: [[0; 16]; 5],
            final_columns: [0; 16],
            final_signs: [0; 16],
            words: [[0; 5]; 16],
            cuts: [[0; 16]; 40],
            values: [0; 16],
            tape: [0; 40],
        }
    }
    pub fn clear(&mut self) {
        // SAFETY: `self` is a unique reference to `size_of::<Self>()` writable bytes. The type is
        // `repr(C, align(16))`, so the pointer is aligned for `u64` and the size is a multiple of
        // 16; the loop writes exactly `size / 8` words, trailing padding included. All fields are
        // integer arrays, so zero is a valid value.
        unsafe {
            let p = (self as *mut Self).cast::<u64>();
            for i in 0..std::mem::size_of::<Self>() / 8 {
                p.add(i).write_volatile(0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        self.clear();
    }
}
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
/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). There is no other
/// requirement: the two unaligned 64-byte table loads cover exactly the 128-byte `row`.
#[inline(always)]
unsafe fn lookup(row: &[u8; 128], indices: uint8x16_t) -> uint8x16_t {
    let mut result = vdupq_n_u8(0);
    for block in 0..2 {
        let p = row.as_ptr().add(64 * block);
        let t = uint8x16x4_t(
            vld1q_u8(p),
            vld1q_u8(p.add(16)),
            vld1q_u8(p.add(32)),
            vld1q_u8(p.add(48)),
        );
        result = vorrq_u8(
            result,
            vqtbl4q_u8(t, vsubq_u8(indices, vdupq_n_u8((64 * block) as u8))),
        );
    }
    result
}
// Private indices are used only by register-table instructions. Every address
// and trip count below is public.
#[cfg(not(target_endian = "little"))]
compile_error!("leading compaction requires little-endian AArch64");
/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). There is no other
/// requirement: with `batch < 16` the loads read `w.ready` (256 bytes) at `16 * batch`, and
/// `entropy` (1856 bytes) at `16 * batch` for 16 bytes and at `256 + 64 * batch` for 64 bytes,
/// ending at byte 1280 at most; each `w.planes[k]` is a 16-byte array, which is all `append_plane`
/// touches.
#[inline(always)]
unsafe fn compact_leading_records(entropy: &[u8; ENTROPY], w: &mut Workspace) {
    use crate::stream_compact::{append_index, append_plane, compact_indices};
    // Initial lookup planes are dead after all 16 initial batches. Reuse their
    // owned storage; preserve the Workspace layout and cleanup owner.
    for plane in 0..5 {
        vst1q_u8(w.planes[plane].as_mut_ptr(), vdupq_n_u8(0));
    }
    let mut queued = 0u16;
    for batch in 0..16 {
        let pending = vsubq_u8(vdupq_n_u8(1), vld1q_u8(w.ready.as_ptr().add(16 * batch)));
        let (map, added) = compact_indices(pending);
        // K=16 is separately checked for every old<=2560 and added<=16.
        let index = append_index::<16>(queued, added, 0);
        let metadata = vld1q_u8(entropy.as_ptr().add(16 * batch));
        let coin = vld4q_u8(entropy.as_ptr().add(256 + 64 * batch));
        append_plane(w.planes[0].as_mut_ptr(), vqtbl1q_u8(metadata, map), index);
        append_plane(w.planes[1].as_mut_ptr(), vqtbl1q_u8(coin.0, map), index);
        append_plane(w.planes[2].as_mut_ptr(), vqtbl1q_u8(coin.1, map), index);
        append_plane(w.planes[3].as_mut_ptr(), vqtbl1q_u8(coin.2, map), index);
        append_plane(w.planes[4].as_mut_ptr(), vqtbl1q_u8(coin.3, map), index);
        queued += added as u16;
    }
}

/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). `ranks` must be valid for
/// reads of 4 `u16` and `out` for reads and writes of 4 `i32`; no alignment is required.
#[inline(always)]
unsafe fn scatter_leading_four(
    ready: uint32x4_t,
    ranks: *const u16,
    out: *mut i32,
    values: uint8x16x4_t,
) {
    let rank = vmovl_u16(vld1_u16(ranks));
    let active = vandq_u32(
        vceqq_u32(ready, vdupq_n_u32(0)),
        vcltq_u32(rank, vdupq_n_u32(16)),
    );
    // Little-endian AArch64: each u32 contains four increasing byte indices.
    // The capacity check precedes register lookup; overflow keeps the old out.
    let index = vaddq_u32(vmulq_n_u32(rank, 0x04040404), vdupq_n_u32(0x03020100));
    let index = vbslq_u32(active, index, vdupq_n_u32(u32::MAX));
    let value = vreinterpretq_s32_u8(vqtbl4q_u8(values, vreinterpretq_u8_u32(index)));
    vst1q_s32(out, vbslq_s32(active, value, vld1q_s32(out)));
}

/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). There is no other
/// requirement: `w.values` is 16 `i32`, read as 64 bytes; with `batch < 16` each call passes
/// offsets `16 * batch + {0, 4, 8, 12}` into the 256-entry `w.ranks` and `out`, and four entries
/// are accessed from each.
#[inline(always)]
unsafe fn scatter_leading_records(w: &Workspace, out: &mut [i32; 256]) {
    let p = w.values.as_ptr().cast::<u8>();
    let values = uint8x16x4_t(
        vld1q_u8(p),
        vld1q_u8(p.add(16)),
        vld1q_u8(p.add(32)),
        vld1q_u8(p.add(48)),
    );
    for batch in 0..16 {
        let i = 16 * batch;
        let ready = vld1q_u8(w.ready.as_ptr().add(i));
        let lo = vmovl_u8(vget_low_u8(ready));
        let hi = vmovl_high_u8(ready);
        scatter_leading_four(
            vmovl_u16(vget_low_u16(lo)),
            w.ranks.as_ptr().add(i),
            out.as_mut_ptr().add(i),
            values,
        );
        scatter_leading_four(
            vmovl_u16(vget_high_u16(lo)),
            w.ranks.as_ptr().add(i + 4),
            out.as_mut_ptr().add(i + 4),
            values,
        );
        scatter_leading_four(
            vmovl_u16(vget_low_u16(hi)),
            w.ranks.as_ptr().add(i + 8),
            out.as_mut_ptr().add(i + 8),
            values,
        );
        scatter_leading_four(
            vmovl_u16(vget_high_u16(hi)),
            w.ranks.as_ptr().add(i + 12),
            out.as_mut_ptr().add(i + 12),
            values,
        );
    }
}

pub fn sample(entropy: &[u8; ENTROPY], out: &mut [i32; 256], w: &mut Workspace) -> bool {
    let bad = sample_owned(entropy, out, w);
    w.clear();
    bad
}
/// Internal: caller supplies zeroed storage and an enclosing cleanup owner.
pub(crate) fn sample_owned(
    entropy: &[u8; ENTROPY],
    out: &mut [i32; 256],
    w: &mut Workspace,
) -> bool {
    let mut abort = 0u32;
    for batch in 0..16 {
        for lane in 0..16 {
            let i = 16 * batch + lane;
            w.columns[lane] = entropy[i] >> 1;
            w.coins[i] = u32::from_be_bytes(entropy[256 + 4 * i..260 + 4 * i].try_into().unwrap());
        }
        // SAFETY: feature: NEON only (baseline of the AArch64 targets this crate builds for).
        // Lengths: `w.columns` and each `w.planes[p]` are 16-byte arrays, one unaligned 16-byte
        // load or store each; the table rows are 128-byte arrays, as `lookup` requires.
        unsafe {
            let cols = vld1q_u8(w.columns.as_ptr());
            for p in 0..5 {
                vst1q_u8(w.planes[p].as_mut_ptr(), lookup(&tables::PLANES[p], cols));
            }
        }
        for lane in 0..16 {
            let i = 16 * batch + lane;
            let col = w.columns[lane] as u32;
            let cut = u32::from_be_bytes(core::array::from_fn(|j| w.planes[j][lane]));
            let full = opaque_mask(u64::from(col == 0)) as u32;
            let ready = full | (opaque_mask(u64::from(w.coins[i] != cut)) as u32);
            let take = full | (opaque_mask(u64::from(w.coins[i] < cut)) as u32);
            let mask = opaque_mask(0u64.wrapping_sub(take as u64)) as u32;
            let bad = opaque_mask(u64::from(col >= 85)) as u32;
            let primary = (2 * col) & (opaque_mask(0u64.wrapping_sub((1 - bad) as u64)) as u32);
            let value = ((primary & mask) | ((w.planes[4][lane] as u32) & !mask)) as i32;
            out[i] = value * (1 - 2 * (entropy[i] & 1) as i32)
                & (opaque_mask(0u64.wrapping_sub(ready as u64)) as i32);
            w.ready[i] = opaque_mask(u64::from(ready)) as u8;
            abort |= ready & take & bad;
        }
    }
    let mut count = 0u16;
    for i in 0..256 {
        w.ranks[i] = count;
        count += (1 - w.ready[i]) as u16;
    }
    // SAFETY: NEON is a baseline feature of the AArch64 targets this crate builds for, which is the
    // only requirement of `compact_leading_records`.
    unsafe {
        compact_leading_records(entropy, w);
    }
    for slot in 0..16 {
        let metadata = w.planes[0][slot];
        w.final_columns[slot] = (metadata >> 1) as u16;
        w.final_signs[slot] = metadata & 1;
        for byte in 0..4 {
            w.tape[byte] = w.planes[1 + byte][slot];
        }
        w.tape[4..].copy_from_slice(&entropy[1280 + 36 * slot..1316 + 36 * slot]);
        for j in 0..5 {
            w.words[slot][j] = u64::from_be_bytes(w.tape[8 * j..8 * j + 8].try_into().unwrap());
        }
    }
    let main = simd_lookup::leading_even16(Stage::Main, &w.final_columns);
    let middle = simd_lookup::leading_even16(Stage::Middle, &w.final_columns);
    let tail = simd_lookup::leading_even16(Stage::Final, &w.final_columns);
    abort |= (main.invalid | middle.invalid | tail.invalid) as u32;
    for lane in 0..16 {
        for p in 0..3 {
            w.cuts[p][lane] = main.bytes[p * 16 + lane];
        }
        for p in 0..11 {
            w.cuts[3 + p][lane] = middle.bytes[p * 16 + lane];
        }
        for p in 0..26 {
            w.cuts[14 + p][lane] = tail.bytes[p * 16 + lane];
        }
        let metadata = (0..4).fold(0u32, |a, j| {
            a | ((main.bytes[(3 + j) * 16 + lane] as u32) << (8 * j))
        });
        let mut borrow = 0u64;
        for limb in (0..5).rev() {
            let cut = u64::from_be_bytes(core::array::from_fn(|j| w.cuts[8 * limb + j][lane]));
            let (a, b) = w.words[lane][limb].overflowing_sub(cut);
            let (_, d) = a.overflowing_sub(borrow);
            borrow = opaque_mask(u64::from(b)) | opaque_mask(u64::from(d));
        }
        let take = (borrow as u32) | ((metadata >> 24) & 1);
        let mask = opaque_mask(0u64.wrapping_sub(take as u64)) as u32;
        let primary = metadata & 2047;
        let alias = (metadata >> 11) & 2047;
        let value = ((primary & mask) | (alias & !mask)) as i32;
        w.values[lane] = value * (1 - 2 * w.final_signs[lane] as i32);
        abort |= (take & ((metadata >> 22) & 1)) | ((1 - take) & ((metadata >> 23) & 1));
    }
    // SAFETY: NEON is a baseline feature of the AArch64 targets this crate builds for, which is the
    // only requirement of `scatter_leading_records`.
    unsafe {
        scatter_leading_records(w, out);
    }
    abort |= opaque_mask(u64::from(count > 16)) as u32;
    let mut keep = 0u32.wrapping_sub((abort == 0) as u32);
    // SAFETY: the template is an assembler comment, so no instruction is emitted. The only operand
    // is the 32-bit view of a general-purpose register holding an initialized value; no memory,
    // stack or flag is touched, as the options state.
    unsafe {
        core::arch::asm!("/* {keep:w} */",keep=inout(reg) keep,options(nomem,nostack,preserves_flags));
    }
    for x in out {
        *x &= keep as i32;
    }
    abort != 0
}

/// The 40-byte cut of the tie stage of one column, assembled as `sample_owned` does.
#[cfg(test)]
fn fixture_cut(column: usize) -> [u8; 40] {
    let columns = [column as u16; 16];
    let main = simd_lookup::leading_even16(Stage::Main, &columns);
    let middle = simd_lookup::leading_even16(Stage::Middle, &columns);
    let tail = simd_lookup::leading_even16(Stage::Final, &columns);
    let mut cut = [0u8; 40];
    for p in 0..3 {
        cut[p] = main.bytes[16 * p];
    }
    for p in 0..11 {
        cut[3 + p] = middle.bytes[16 * p];
    }
    for p in 0..26 {
        cut[14 + p] = tail.bytes[16 * p];
    }
    cut
}

/// Input `row` of the fixture set of `sample`; the generators README states the rule.
#[cfg(test)]
pub(crate) fn fixture_input(row: usize) -> [u8; ENTROPY] {
    const QUEUED: [usize; 9] = [0, 1, 2, 15, 16, 17, 31, 255, 256];
    let mut e = [0u8; ENTROPY];
    if row < 24 {
        crate::fixture_gen::expand("leading-alias32", row as u32, &mut e);
    } else if row == 25 {
        e.fill(255);
    } else if (26..794).contains(&row) {
        // One lane: the 320-bit word is the cut of its column minus one, the cut, or plus one.
        let i = row - 26;
        let mut word = fixture_cut(i / 6);
        if i % 3 != 1 {
            crate::fixture_gen::step(&mut word, i as i32 % 3 - 1);
        }
        e[0] = (2 * (i / 6) + (i % 6) / 3) as u8;
        e[256..260].copy_from_slice(&word[..4]);
        e[1280..1316].copy_from_slice(&word[4..]);
    } else if row >= 794 {
        fixture_queue(&mut e, QUEUED[row - 794]);
    }
    e
}

/// `count` lanes whose 32-bit coin equals the cut of their column. The other lanes hold
/// column 0, which resolves at once.
#[cfg(test)]
fn fixture_queue(e: &mut [u8; ENTROPY], count: usize) {
    let mut lanes = Vec::new();
    for j in 0..count {
        if count <= 31 {
            lanes.push(37 * (j % 7) + 3 * (j / 7));
        } else {
            lanes.push(j);
        }
    }
    lanes.sort_unstable();
    for (i, lane) in lanes.into_iter().enumerate() {
        let column = 1 + i % 127;
        e[lane] = (2 * column + i % 2) as u8;
        for j in 0..4 {
            e[256 + 4 * lane + j] = tables::PLANES[j][column];
        }
    }
    crate::fixture_gen::expand("leading-alias32-queue", 0, &mut e[1280..]);
}

#[cfg(test)]
mod conditional_leading_alias32_tests {
    use super::*;

    use crate::fixture_gen as fx;

    // SHA-256 of the records built below; `generators/gen_proposal_fixtures.py` pins the same
    // value for the records its model of this function produces.
    const PIN: &str = "2df04288385c029cfee00112fd1bcd86aef7cce5de44b013daef46504a127a40";

    #[test]
    fn independent_retained_alias_and_queue_fixtures() {
        let mut hash = fx::Records::new();
        let mut w = Workspace::new();
        let mut out = [0; 256];
        let mut aborts = Vec::new();
        for row in 0..803 {
            let e = fixture_input(row);
            let bad = sample(&e, &mut out, &mut w);
            if bad {
                aborts.push(row);
                assert_eq!(out, [0; 256]);
            }
            hash.update(&e);
            hash.update(&[bad as u8]);
            for value in out {
                hash.update(&value.to_le_bytes());
            }
            hash.end();
            // SAFETY: `sample` ended with `clear`, which wrote every 8-byte word of `w` in place,
            // trailing padding included, and `w` has not moved since; the view covers exactly
            // `size_of::<Workspace>()` bytes of that live object.
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&w as *const Workspace).cast::<u8>(),
                    core::mem::size_of::<Workspace>(),
                )
            };
            assert!(bytes.iter().all(|&x| x == 0));
        }
        // The rows with 17, 31, 255 and 256 queued lanes overflow the queue of 16.
        assert_eq!(aborts, [799, 800, 801, 802]);
        hash.check("leading-alias32", PIN);
    }
}
