//! Complete core/tail major sampler. Fixed queues and active-record aborts.
use crate::main_kernel::Output;
use crate::stream_compact::{append_index, append_plane, compact_indices, ranks16};
use std::arch::aarch64::*;
pub const N: usize = 2560;
pub const ENTROPY: usize = 9088;
#[repr(C, align(16))]
pub struct Workspace {
    ranks: [u16; N],
    queue: [[u8; 64]; 5],
    meta: [[u8; 16]; 14],
    final_meta: [[u8; 16]; 14],
    middle_ranks: [u16; 64],
    middle_values: [i16; 64],
    final_values: [i16; 64],
    records: [[u8; 64]; 8],
    live: [u8; 16],
    signs: [u8; 16],
    out: Output,
    final_work: crate::coretail_final::Scratch,
}
impl Workspace {
    pub fn new() -> Self {
        Self {
            ranks: [0; N],
            queue: [[0; 64]; 5],
            meta: [[0; 16]; 14],
            final_meta: [[0; 16]; 14],
            middle_ranks: [0; 64],
            middle_values: [0; 64],
            final_values: [0; 64],
            records: [[0; 64]; 8],
            live: [0; 16],
            signs: [0; 16],
            out: Output::new(),
            final_work: crate::coretail_final::Scratch::new(),
        }
    }
    pub fn clear(&mut self) {
        // SAFETY: `self` is a unique reference to `size_of::<Self>()` writable bytes. The type is
        // `repr(C, align(16))`, so the pointer is aligned for `u64` and the size is a multiple of
        // 16; the loop writes exactly `size / 8` words. All fields, nested structs included, are
        // integer arrays, so zero is a valid value.
        unsafe {
            let p = (self as *mut Self).cast::<u64>();
            for i in 0..std::mem::size_of::<Self>() / 8 {
                p.add(i).write_volatile(0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
    pub fn cleared_bytes_are_zero(&self) -> bool {
        // SAFETY: `self` is a shared reference to an initialized `Workspace`, valid for reads of
        // `size_of::<Self>()` bytes. The `repr(C)` layout has no padding (every field starts at a
        // multiple of its alignment and the fields sum to the full 8112 bytes), so each byte is an
        // initialized integer byte; `u8` needs no alignment.
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Self).cast::<u8>(),
                std::mem::size_of::<Self>(),
            )
            .iter()
            .all(|x| *x == 0)
        }
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
#[inline(never)]
fn scatter<const M: usize>(ranks: &[u16; M], refined: &[i16; 64], out: &mut [i16; M]) {
    // SAFETY: feature: NEON only (baseline of the AArch64 targets this crate builds for). Lengths:
    // `refined` is 64 `i16`, that is 128 bytes, read as eight 16-byte blocks. The loop reads and
    // writes 8 lanes at `i`, a multiple of 8 below `M`; this private function is instantiated only
    // with `M = 64` and `M = 2560`, both multiples of 8, so `i + 8 <= M` for `ranks` and `out`. The
    // private rank only indexes bytes inside the two table registers. Alignment: unaligned loads
    // and stores; the `i16` to `u8` pointer cast only lowers the alignment requirement.
    unsafe {
        let p = refined.as_ptr().cast::<u8>();
        let a = uint8x16x4_t(
            vld1q_u8(p),
            vld1q_u8(p.add(16)),
            vld1q_u8(p.add(32)),
            vld1q_u8(p.add(48)),
        );
        let b = uint8x16x4_t(
            vld1q_u8(p.add(64)),
            vld1q_u8(p.add(80)),
            vld1q_u8(p.add(96)),
            vld1q_u8(p.add(112)),
        );
        for i in (0..M).step_by(8) {
            let r = vld1q_u16(ranks.as_ptr().add(i));
            let active = vcgtq_u16(vandq_u16(r, vdupq_n_u16(32768)), vdupq_n_u16(0));
            let rank = vandq_u16(r, vdupq_n_u16(32767));
            let index = vaddq_u16(vmulq_n_u16(rank, 0x0202), vdupq_n_u16(0x0100));
            let index = vreinterpretq_u8_u16(vbslq_u16(
                vcltq_u16(rank, vdupq_n_u16(64)),
                index,
                vdupq_n_u16(65535),
            ));
            let value = vorrq_u8(
                vqtbl4q_u8(a, index),
                vqtbl4q_u8(b, vsubq_u8(index, vdupq_n_u8(64))),
            );
            let old = vld1q_s16(out.as_ptr().add(i));
            vst1q_s16(
                out.as_mut_ptr().add(i),
                vbslq_s16(active, vreinterpretq_s16_u8(value), old),
            );
        }
    }
}

pub fn sample(e: &[u8; ENTROPY], out: &mut [i16; N], w: &mut Workspace) -> bool {
    let bad = sample_owned(e, out, w);
    w.clear();
    bad
}
/// Caller supplies initialized zero storage and owns complete retirement.
pub(crate) fn sample_owned(e: &[u8; ENTROPY], out: &mut [i16; N], w: &mut Workspace) -> bool {
    let mut count = 0u16;
    for batch in 0..160 {
        let at = 16 * batch;
        // SAFETY: feature: NEON only (baseline of the AArch64 targets this crate builds for).
        // Lengths: `shifts` and `w.signs` are 16-byte arrays, one unaligned 16-byte load and store.
        // The entropy bytes are read by checked indexing.
        unsafe {
            let signs = vcombine_u8(vdup_n_u8(e[2560 + at / 8]), vdup_n_u8(e[2561 + at / 8]));
            let shifts = [
                0i8, -1, -2, -3, -4, -5, -6, -7, 0, -1, -2, -3, -4, -5, -6, -7,
            ];
            vst1q_u8(
                w.signs.as_mut_ptr(),
                vandq_u8(vshlq_u8(signs, vld1q_s8(shifts.as_ptr())), vdupq_n_u8(1)),
            );
        }
        let col = e[at..at + 16].try_into().unwrap();
        let coins = e[2880 + 2 * at..2912 + 2 * at].try_into().unwrap();
        {
            if batch < 80 {
                crate::coretail_main::core16::<0>(col, &w.signs, coins, &mut w.out);
            } else {
                crate::coretail_main::core16::<1>(col, &w.signs, coins, &mut w.out);
            }
        }
        // SAFETY: feature: NEON only (baseline of the AArch64 targets this crate builds for).
        // Lengths: `w.out.ready`, `col` and `w.signs` are 16-byte arrays; `coins` has 32 bytes, the
        // amount `vld2q_u8` reads; `ranks16` writes 16 `u16` at `at <= 2544` into `w.ranks`, which
        // has 2560; `append_major_tbx` stays inside the five 64-byte queue rows. Alignment:
        // unaligned accesses only.
        unsafe {
            let pending = vsubq_u8(vdupq_n_u8(1), vld1q_u8(w.out.ready.as_ptr()));
            let (map, n) = compact_indices(pending);
            ranks16(pending, count, w.ranks.as_mut_ptr().add(at));
            let coin = vld2q_u8(coins.as_ptr());
            let payload = [
                vld1q_u8(col.as_ptr()),
                vld1q_u8(w.signs.as_ptr()),
                coin.0,
                coin.1,
                vdupq_n_u8((batch >= 80) as u8),
            ];
            append_major_tbx(&mut w.queue, payload, map, count);
            count += n as u16;
        }
        out[at..at + 16].copy_from_slice(&w.out.values);
    }
    let mut bad = opaque_mask((count > 64) as u64);
    let mut final_count = 0u16;
    for batch in 0..4 {
        for lane in 0..16 {
            let slot = 16 * batch + lane;
            let at = 8000 + 9 * slot;
            w.meta[0][lane] = w.queue[4][slot];
            w.meta[1][lane] = w.queue[0][slot];
            w.meta[2][lane] = w.queue[1][slot];
            w.meta[3][lane] = w.queue[2][slot];
            w.meta[4][lane] = w.queue[3][slot];
            for p in 0..4 {
                w.meta[5 + p][lane] = e[at + p];
            }
            w.meta[9][lane] = e[at + 4];
            for p in 0..4 {
                w.meta[10 + p][lane] = e[at + 5 + p];
            }
            w.live[lane] = opaque_mask(((slot as u16) < count) as u64) as u8;
        }
        crate::coretail_middle::middle16(&w.meta, &mut w.out);
        // SAFETY: feature: NEON only (baseline of the AArch64 targets this crate builds for).
        // Lengths: `w.out.ready` and `w.live` are 16-byte arrays; `ranks16` writes 16 `u16` at `16
        // * batch` with `batch < 4` into the 64-entry `w.middle_ranks`; each `w.meta[p]` and
        // `w.final_meta[p]` is a 16-byte array, which is all `append_plane` reads and writes.
        // Alignment: unaligned accesses only.
        unsafe {
            let pending = vandq_u8(
                vsubq_u8(vdupq_n_u8(1), vld1q_u8(w.out.ready.as_ptr())),
                vld1q_u8(w.live.as_ptr()),
            );
            let (map, n) = compact_indices(pending);
            ranks16(
                pending,
                final_count,
                w.middle_ranks.as_mut_ptr().add(16 * batch),
            );
            let ix = append_index::<8>(final_count, n, 0);
            for p in 0..14 {
                append_plane(
                    w.final_meta[p].as_mut_ptr(),
                    vqtbl1q_u8(vld1q_u8(w.meta[p].as_ptr()), map),
                    ix,
                );
            }
            final_count += n as u16;
        }
        for lane in 0..16 {
            w.middle_values[16 * batch + lane] =
                w.out.values[lane] & (opaque_mask(0u64.wrapping_sub(w.live[lane] as u64)) as i16);
        }
    }
    bad |= opaque_mask((final_count > 8) as u64);
    for lane in 0..8 {
        w.records[lane].copy_from_slice(&e[8576 + 64 * lane..8640 + 64 * lane]);
    }
    for lane in 0..16 {
        w.live[lane] =
            ((lane < 8) as u8) & (opaque_mask((lane < (final_count as usize)) as u64) as u8);
    }
    let final_out: &mut [i16; 16] = (&mut w.final_values[..16]).try_into().unwrap();
    bad |= opaque_mask(crate::coretail_final::final8(
        &w.final_meta,
        &w.records,
        &w.live,
        final_out,
        &mut w.final_work,
    ) as u64);
    for lane in 0..16 {
        let sign = opaque_mask(0u64.wrapping_sub(w.final_meta[2][lane] as u64)) as i16;
        w.final_values[lane] = (w.final_values[lane] ^ sign) - sign;
    }
    scatter(&w.middle_ranks, &w.final_values, &mut w.middle_values);
    scatter(&w.ranks, &w.middle_values, out);
    let mut keep = 0u32.wrapping_sub((bad ^ 1) as u32);
    // SAFETY: the template is an assembler comment, so no instruction is emitted. The only operand
    // is the 32-bit view of a general-purpose register holding an initialized value; no memory,
    // stack or flag is touched, as the options state.
    unsafe {
        core::arch::asm!("/* {keep:w} */",keep=inout(reg)keep,options(nomem,nostack,preserves_flags));
    }
    for x in out {
        *x &= keep as i16;
    }
    bad != 0
}
/// Input `row` of the fixture set of `sample`; the generators README states the rule.
#[cfg(test)]
pub(crate) fn fixture_input(row: usize) -> [u8; ENTROPY] {
    let mut e = [0u8; ENTROPY];
    crate::fixture_gen::expand("coretail-major", row as u32, &mut e);
    if (35..=37).contains(&row) {
        fixture_pending(&mut e, 28 + row, false, 0);
    } else if (39..=41).contains(&row) {
        fixture_pending(&mut e, row - 32, true, 0);
    } else if row == 43 || row == 44 {
        fixture_pending(&mut e, row - 36, true, 1280);
    } else if row == 55 || row == 69 {
        let case = crate::coretail_final::fixture_cases::overflow((row == 69) as usize);
        fixture_embed(&mut e, &case, 0);
    } else if (70..98).contains(&row) {
        // The 28 cases of the last stage that do not fail: the thirty without the two overflows.
        let mut index = row - 70;
        if index >= 14 {
            index += 1;
        }
        let case = crate::coretail_final::fixture_cases::all()[index];
        let sign = (row - 70 + case[0] as usize) % 2;
        fixture_embed(&mut e, &case, sign as u8);
    } else if row == 98 {
        // The chain of family 1 that ends at 1020, which row 96 carries negated, with sign 0.
        let case = crate::coretail_final::fixture_cases::all()[27];
        fixture_embed(&mut e, &case, 0);
    }
    e
}

/// Every lane resolves at once (column 0), except `count` lanes, 39 apart from lane `first`,
/// whose coin equals the 16-bit cut of their column; with `to_last_stage` the next 32 coin bits
/// equal the cut as well.
#[cfg(test)]
fn fixture_pending(e: &mut [u8; ENTROPY], count: usize, to_last_stage: bool, first: usize) {
    e[..N].fill(0);
    for j in 0..count {
        let n = first + 39 * j;
        let family = (n >= 1280) as usize;
        let column = 1 + j;
        let (cut, _) = crate::coretail_main::fixture_cut(family, column);
        e[n] = column as u8;
        e[2880 + 2 * n..2882 + 2 * n].copy_from_slice(&cut.to_be_bytes());
        if to_last_stage {
            for p in 0..4 {
                let byte = crate::coretail_middle::fixture_plane(family, 2 + p, column);
                e[8000 + 9 * j + p] = byte;
            }
        }
    }
}

/// The first lane of the family of `case` (lane 0 or lane 1280) carries that case of the last
/// stage with the given sign: its column, its coin bits and its record. For family 1 the columns
/// of lanes 0 to 1279 are set to 0, so that the lane is the first one queued.
#[cfg(test)]
fn fixture_embed(e: &mut [u8; ENTROPY], case: &[u8; 78], sign: u8) {
    let n = 1280 * case[0] as usize;
    e[..n].fill(0);
    e[n] = case[1];
    e[2560 + n / 8] = (e[2560 + n / 8] & 0xfe) | sign;
    e[2880 + 2 * n..2882 + 2 * n].copy_from_slice(&case[3..5]);
    e[8000..8009].copy_from_slice(&case[5..14]);
    e[8576..8640].copy_from_slice(&case[14..]);
}

#[cfg(test)]
mod conditional_coretail_major_tests {
    use super::*;

    use crate::fixture_gen as fx;

    // SHA-256 of the records built below; `generators/gen_proposal_fixtures.py` pins the same
    // value for the records its model of this function produces.
    const PIN: &str = "854abe1af9fe8f170935b81a6c0d93fc8894b0b56ba0f637b0b4a1a72bdeec92";

    #[test]
    fn independent_complete_major_fixtures() {
        let mut hash = fx::Records::new();
        let mut w = Workspace::new();
        let mut out = [0i16; N];
        let mut aborts = Vec::new();
        for row in 0..198 {
            let e = fixture_input(row);
            let bad = sample(&e, &mut out, &mut w);
            if bad {
                aborts.push(row);
                assert_eq!(out, [0i16; N]);
            }
            hash.update(&e);
            hash.update(&[bad as u8]);
            for value in out {
                hash.update(&value.to_le_bytes());
            }
            hash.end();
            assert!(w.cleared_bytes_are_zero());
        }
        // Rows 37 and 41 overflow the two queues; rows 55 and 69 overflow the record cursor.
        // Rows 70 to 98 carry the other cases of the last stage to the output and do not abort.
        assert_eq!(aborts, [37, 41, 55, 69]);
        hash.check("coretail-major", PIN);
    }
}

// The queue starts zero and every append writes a previously unfilled interval.
// Both implementations touch all four public segments of all five planes.
/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). There is no other
/// requirement: every 16-byte access is at `16 * seg` with `seg < 4` inside a 64-byte queue row.
#[cfg(test)]
#[inline(always)]
unsafe fn append_major_reference(
    queue: &mut [[u8; 64]; 5],
    payload: [uint8x16_t; 5],
    map: uint8x16_t,
    count: u16,
    n: u8,
) {
    for seg in 0..4 {
        let ix = append_index::<64>(count, n, seg);
        for p in 0..5 {
            append_plane(
                queue[p].as_mut_ptr().add(16 * seg),
                vqtbl1q_u8(payload[p], map),
                ix,
            );
        }
    }
}

/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). There is no other
/// requirement: every 16-byte load and store is at `16 * seg` with `seg < 4` inside a 64-byte queue
/// row, and `count` only selects bytes inside registers.
#[inline(always)]
unsafe fn append_major_tbx(
    queue: &mut [[u8; 64]; 5],
    payload: [uint8x16_t; 5],
    map: uint8x16_t,
    count: u16,
) {
    let offsets = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let offset = vld1q_u8(offsets.as_ptr());
    // Essential overflow guard: count can exceed 255, but never 2560.
    let dead = vdupq_n_u8(opaque_mask(0u64.wrapping_sub((count >= 64) as u64)) as u8);
    for seg in 0..4 {
        let pos = vaddq_u8(offset, vdupq_n_u8((16 * seg) as u8));
        let relative = vsubq_u8(pos, vdupq_n_u8(count as u8));
        // map[n..] is 255. TBX, unlike TBL, also keeps 255 for relative>=16.
        let source = vorrq_u8(vqtbx1q_u8(vdupq_n_u8(255), map, relative), dead);
        for p in 0..5 {
            let dst = queue[p].as_mut_ptr().add(16 * seg);
            vst1q_u8(dst, vqtbx1q_u8(vld1q_u8(dst), payload[p], source));
        }
    }
}

#[cfg(test)]
mod proposal_append_tests {
    use super::*;
    /// # Safety
    ///
    /// The CPU must have NEON (every AArch64 target of this crate has it). There is no other
    /// requirement: all loads read local 16-byte arrays.
    unsafe fn check(mask: u16, count: u16, seed: &mut u64) {
        let pending: [u8; 16] = core::array::from_fn(|i| ((mask >> i) & 1) as u8);
        let (map, n) = compact_indices(vld1q_u8(pending.as_ptr()));
        let mut next = || {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed as u8
        };
        let bytes: [[u8; 16]; 5] = core::array::from_fn(|_| core::array::from_fn(|_| next()));
        let payload = core::array::from_fn(|p| vld1q_u8(bytes[p].as_ptr()));
        let mut a: [[u8; 64]; 5] = core::array::from_fn(|_| {
            core::array::from_fn(|i| {
                if i < usize::from(count).min(64) {
                    next()
                } else {
                    0
                }
            })
        });
        let mut b = a;
        append_major_reference(&mut a, payload, map, count, n);
        append_major_tbx(&mut b, payload, map, count);
        assert_eq!(a, b, "mask={mask} count={count}");
    }
    #[test]
    fn proposal_append_all_masks_boundaries_and_random() {
        let mut seed = 20261110u64;
        // SAFETY: NEON is a baseline feature of the AArch64 targets this crate builds for, which is
        // the only requirement of `check`.
        unsafe {
            for mask in 0..=u16::MAX {
                for count in [
                    0, 1, 15, 16, 17, 31, 32, 47, 48, 49, 63, 64, 65, 255, 256, 2544, 2560,
                ] {
                    check(mask, count, &mut seed);
                }
            }
            for count in 0..=2560 {
                for n in 0..=16 {
                    check(((1u32 << n) - 1) as u16, count, &mut seed);
                }
                for _ in 0..8 {
                    check(seed as u16, count, &mut seed);
                }
            }
        }
    }
}
