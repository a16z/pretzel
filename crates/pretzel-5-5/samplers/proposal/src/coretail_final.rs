//! Six fixed levels, private cursors select bytes only inside registers.
use std::arch::aarch64::*;
static TABLE: &[u8; 125952] = include_bytes!("coretail-final-planes.bin");
#[repr(C, align(16))]
pub struct Scratch {
    window: [[u8; 64]; 8],
    word: [[u64; 5]; 8],
    cut: [[u64; 5]; 8],
    columns: [u8; 16],
    other: [u8; 16],
    cursor: [u16; 8],
    active: [u8; 8],
    values: [i16; 8],
    bad: [u8; 8],
    plane: [u8; 16],
}
impl Scratch {
    pub fn new() -> Self {
        Self {
            window: [[0; 64]; 8],
            word: [[0; 5]; 8],
            cut: [[0; 5]; 8],
            columns: [0; 16],
            other: [0; 16],
            cursor: [0; 8],
            active: [0; 8],
            values: [0; 8],
            bad: [0; 8],
            plane: [0; 16],
        }
    }
    pub fn clear(&mut self) {
        // SAFETY: `self` is a unique reference to `size_of::<Self>()` writable bytes. The type is
        // `repr(C, align(16))`, so the pointer is aligned for `u64` and the size is a multiple of
        // 16; the loop writes exactly `size / 8` words. All fields are integer arrays, so zero is a
        // valid value.
        unsafe {
            let p = (self as *mut Self).cast::<u64>();
            for i in 0..std::mem::size_of::<Self>() / 8 {
                p.add(i).write_volatile(0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
impl Drop for Scratch {
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
// Each private comparison is opaque before composition; fixed scalar arithmetic.
#[inline(always)]
fn predicate(value: bool) -> u32 {
    opaque_mask(value as u64) as u32
}
#[inline(always)]
fn private_min(value: u32, cap: u32) -> u32 {
    let above = predicate(value > cap);
    let mask = opaque_mask(0u64.wrapping_sub(above as u64)) as u32;
    (value & !mask) | (cap & mask)
}
#[inline(always)]
fn private_saturating_sub(value: u32, amount: u32) -> u32 {
    let below = predicate(value < amount);
    let mask = opaque_mask(0u64.wrapping_sub((below ^ 1) as u64)) as u32;
    value.wrapping_sub(amount) & mask
}
/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). `row` must be valid for
/// reads of 256 bytes; the four unaligned 64-byte table loads cover exactly that range.
#[inline(always)]
unsafe fn lookup(row: *const u8, col: uint8x16_t) -> uint8x16_t {
    let mut out = vdupq_n_u8(0);
    for b in 0..4 {
        let p = row.add(64 * b);
        let t = uint8x16x4_t(
            vld1q_u8(p),
            vld1q_u8(p.add(16)),
            vld1q_u8(p.add(32)),
            vld1q_u8(p.add(48)),
        );
        out = vorrq_u8(
            out,
            vqtbl4q_u8(t, vsubq_u8(col, vdupq_n_u8((64 * b) as u8))),
        );
    }
    out
}
/// cursor<=512, so byte indices plus offsets are at most 127, never wrap.
///
/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). There is no other
/// requirement: the loads and stores stay inside the two 64-byte arrays and a local 16-byte array,
/// and `cursor` only selects bytes inside registers.
#[inline(never)]
unsafe fn window(record: &[u8; 64], cursor: u16, out: &mut [u8; 64]) {
    let p = record.as_ptr();
    let table = uint8x16x4_t(
        vld1q_u8(p),
        vld1q_u8(p.add(16)),
        vld1q_u8(p.add(32)),
        vld1q_u8(p.add(48)),
    );
    let ix = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let base = vaddq_u8(vld1q_u8(ix.as_ptr()), vdupq_n_u8((cursor / 8) as u8));
    let mut blocks = [vdupq_n_u8(0); 5];
    for j in 0..4 {
        blocks[j] = vqtbl4q_u8(table, vaddq_u8(base, vdupq_n_u8((16 * j) as u8)));
    }
    let shift = (cursor % 8) as i8;
    for j in 0..4 {
        let next = vextq_u8::<1>(blocks[j], blocks[j + 1]);
        let x = vorrq_u8(
            vshlq_u8(blocks[j], vdupq_n_s8(shift)),
            vshlq_u8(next, vdupq_n_s8(shift - 8)),
        );
        vst1q_u8(out.as_mut_ptr().add(16 * j), x);
    }
}
/// All eight physical records run; padded lanes never load nonexistent records.
/// Returns active-record failures; signs are applied by the caller.
#[inline(never)]
pub fn final8(
    meta: &[[u8; 16]; 14],
    records: &[[u8; 64]; 8],
    live: &[u8; 16],
    out: &mut [i16; 16],
    s: &mut Scratch,
) -> bool {
    s.cursor.fill(0);
    s.values.fill(0);
    s.bad.fill(0);
    s.active.copy_from_slice(&live[..8]);
    for level in 0..6 {
        let prefix = if level == 0 {
            6
        } else if level == 1 {
            4
        } else {
            0
        };
        for lane in 0..8 {
            // SAFETY: NEON is a baseline feature of the AArch64 targets this crate builds for;
            // `window` has no other requirement and receives two distinct 64-byte arrays.
            unsafe {
                window(&records[lane], s.cursor[lane], &mut s.window[lane]);
            }
        }
        for lane in 0..8 {
            s.columns[lane] = if level == 0 {
                meta[1][lane]
            } else if level == 1 {
                meta[9][lane]
            } else {
                s.window[lane][0]
            };
            for limb in 0..5 {
                let mut x = 0u64;
                for byte in 0..8 {
                    let at = 8 * limb + byte;
                    let v = if at < prefix {
                        meta[if level == 0 { 3 + at } else { 10 + at }][lane]
                    } else {
                        s.window[lane][at - prefix + usize::from(level >= 2)]
                    };
                    x = (x << 8) | v as u64;
                }
                s.word[lane][limb] = x;
                s.cut[lane][limb] = 0;
            }
        }
        // SAFETY: feature: NEON only (baseline of the AArch64 targets this crate builds for).
        // Lengths: `TABLE` has 125952 = 6 * 2 * 41 * 256 bytes; with `level < 6` and `plane < 41`
        // the two 256-byte rows read by `lookup` start at `level * 20992 + plane * 256` and 10496
        // bytes later, so the last byte read is at most byte 125951. `s.columns`, `meta[0]` and
        // `s.plane` are 16-byte arrays, one 16-byte load or store each. Alignment: byte loads and
        // stores need none.
        unsafe {
            let col = vld1q_u8(s.columns.as_ptr());
            let family = vld1q_u8(meta[0].as_ptr());
            let mask = vceqq_u8(family, vdupq_n_u8(0));
            for plane in 0..41 {
                let row = TABLE.as_ptr().add(level * 20992 + plane * 256);
                let a = lookup(row, col);
                let b = lookup(row.add(10496), col);
                vst1q_u8(s.plane.as_mut_ptr(), vbslq_u8(mask, a, b));
                if plane < 40 {
                    for lane in 0..8 {
                        s.cut[lane][plane / 8] =
                            (s.cut[lane][plane / 8] << 8) | s.plane[lane] as u64;
                    }
                } else {
                    s.other.copy_from_slice(&s.plane);
                }
            }
        }
        for lane in 0..8 {
            let (less, common, nonzero) = {
                let mut eq = 1u32;
                let mut less = 0u32;
                let mut common = 0u32;
                let mut nonzero = 0u64;
                for limb in 0..5 {
                    let u = s.word[lane][limb];
                    let t = s.cut[lane][limb];
                    let x = u ^ t;
                    less |= eq * predicate(u < t);
                    common += eq * x.leading_zeros();
                    eq *= predicate(x == 0);
                    nonzero |= t;
                }
                (less, common, nonzero)
            };
            let full = predicate(s.columns[lane] == s.other[lane]);
            let endpoint = full | predicate(nonzero == 0);
            let need = private_saturating_sub(private_min(common + 1, 320), (8 * prefix) as u32)
                * (1 - endpoint);
            let take = full | less;
            let mask = opaque_mask(0u64.wrapping_sub(take as u64)) as u8;
            let chosen = (s.columns[lane] & mask) | (s.other[lane] & !mask);
            let active = opaque_mask(s.active[lane] as u64) as u32;
            let consumed = active * (need + 8 * u32::from(level >= 2));
            let next = s.cursor[lane] as u32 + consumed;
            s.bad[lane] |= predicate(next > 512) as u8;
            s.cursor[lane] = private_min(next, 512) as u16;
            let done = active * predicate(chosen != 255);
            let mask = opaque_mask(0u64.wrapping_sub(done as u64)) as i16;
            s.values[lane] =
                (s.values[lane] & !mask) | (((255 * level + chosen as usize) as i16) & mask);
            s.active[lane] = (active * predicate(chosen == 255)) as u8;
        }
    }
    let mut bad = 0u8;
    for lane in 0..8 {
        let cap = 1149 + 313 * meta[0][lane] as i16;
        let failed = s.bad[lane] | s.active[lane] | predicate(s.values[lane] > cap) as u8;
        bad |= failed & live[lane];
        out[lane] = s.values[lane]
            & (opaque_mask(0u64.wrapping_sub((live[lane] & (1 - failed)) as u64)) as i16);
    }
    out[8..].fill(0);
    bad != 0
}
/// The 40-byte cut and the alias of one column at one level, for the tests that build inputs
/// from the table.
#[cfg(test)]
pub(crate) fn fixture_cut(level: usize, family: usize, column: usize) -> ([u8; 40], u8) {
    let base = level * 20992 + family * 10496 + column;
    let mut cut = [0u8; 40];
    for plane in 0..40 {
        cut[plane] = TABLE[base + 256 * plane];
    }
    (cut, TABLE[base + 256 * 40])
}

/// Hand-built inputs of `final8`: 14 metadata bytes, then the 64-byte record. The generators
/// README describes each kind.
#[cfg(test)]
pub(crate) mod fixture_cases {
    use super::fixture_cut;

    use crate::fixture_gen as fx;

    pub(crate) type Case = [u8; 78];

    /// The coin equals the 48-bit prefix of the cut of column 1; the record decides.
    pub(crate) fn tie(family: usize, index: usize) -> Case {
        let (cut, _) = fixture_cut(0, family, 1);
        let mut case = [0u8; 78];
        case[0] = family as u8;
        case[1] = 1;
        case[3..9].copy_from_slice(&cut[..6]);
        let seed = (4 * family + index) as u32;
        fx::expand("coretail-final", seed, &mut case[9..]);
        case
    }

    /// The 320-bit word is the cut of column 1 plus `delta` (-1, 0 or 1).
    pub(crate) fn edge(family: usize, delta: i32) -> Case {
        let (mut word, _) = fixture_cut(0, family, 1);
        if delta != 0 {
            fx::step(&mut word, delta);
        }
        let mut case = [0u8; 78];
        case[0] = family as u8;
        case[1] = 1;
        case[3..9].copy_from_slice(&word[..6]);
        case[14..48].copy_from_slice(&word[6..]);
        case
    }

    /// Every word is zero; the record holds only the columns of levels two and later, each at
    /// the bit position the previous levels leave the cursor at.
    pub(crate) fn chain(family: usize, columns: &[u8]) -> Case {
        let mut case = [0u8; 78];
        case[0] = family as u8;
        case[1] = columns[0];
        case[9] = columns[1];
        let mut cursor = 0;
        for level in 0..columns.len() {
            let column = columns[level];
            let mut prefix = 0;
            if level == 0 {
                prefix = 48;
            } else if level == 1 {
                prefix = 32;
            }
            if level >= 2 {
                for k in 0..8 {
                    fx::set_bit(&mut case[14..], cursor + k, (column >> (7 - k)) & 1);
                }
                cursor += 8;
            }
            let (cut, alias) = fixture_cut(level, family, column as usize);
            if alias != column && cut != [0u8; 40] {
                let mut zeros = 0;
                while fx::bit(&cut, zeros) == 0 {
                    zeros += 1;
                }
                if zeros + 1 > prefix {
                    cursor += zeros + 1 - prefix;
                }
            }
        }
        case
    }

    /// Column 255 with the word one step below its cut, then column 1 with the word equal to
    /// its cut for as long as the record lasts: the cursor passes the end of the record.
    pub(crate) fn overflow(family: usize) -> Case {
        let (mut word, _) = fixture_cut(0, family, 255);
        let mut last = 319;
        while fx::bit(&word, last) == 0 {
            last -= 1;
        }
        fx::set_bit(&mut word, last, 0);
        let (next, _) = fixture_cut(1, family, 1);
        let mut case = [0u8; 78];
        case[0] = family as u8;
        case[1] = 255;
        case[3..9].copy_from_slice(&word[..6]);
        case[9] = 1;
        case[10..14].copy_from_slice(&next[..4]);
        case[14..48].copy_from_slice(&word[6..]);
        let cursor = last + 1 - 48;
        for i in 0..512 - cursor {
            if 32 + i < 320 {
                fx::set_bit(&mut case[14..], cursor + i, fx::bit(&next, 32 + i));
            }
        }
        case
    }

    /// The thirty cases: for each family four ties, three edges, seven chains, one overflow.
    pub(crate) fn all() -> Vec<Case> {
        let mut cases = Vec::new();
        for family in 0..2 {
            for index in 0..4 {
                cases.push(tie(family, index));
            }
            for delta in [-1, 0, 1] {
                cases.push(edge(family, delta));
            }
            cases.push(chain(family, &[255, 254]));
            cases.push(chain(family, &[255, 255]));
            cases.push(chain(family, &[255, 255, 254]));
            cases.push(chain(family, &[255, 255, 255]));
            cases.push(chain(family, &[255, 255, 255, 254]));
            cases.push(chain(family, &[255, 255, 255, 255]));
            if family == 0 {
                cases.push(chain(family, &[255, 255, 255, 255, 129]));
            } else {
                cases.push(chain(family, &[255, 255, 255, 255, 255, 187]));
            }
            cases.push(overflow(family));
        }
        cases
    }
}

#[cfg(test)]
mod conditional_coretail_final_tests {
    use super::*;

    use crate::fixture_gen as fx;

    // SHA-256 of the records built below; `generators/gen_proposal_fixtures.py` pins the same
    // value for the records its model of this function produces.
    const PIN: &str = "9a1dc9cf2ca1040109f777893fe1dffb614b3f269eb8653af13d37097f04d98c";

    #[test]
    fn every_bit_cursor_window() {
        let record = core::array::from_fn(|i| (i * 73 + 19) as u8);
        for cursor in 0..=512u16 {
            let mut got = [0u8; 64];
            // SAFETY: NEON is a baseline feature of the AArch64 targets this crate builds for;
            // `window` has no other requirement.
            unsafe {
                window(&record, cursor, &mut got);
            }
            for bit in 0..512 {
                let at = cursor as usize + bit;
                let expected = if at < 512 {
                    (record[at / 8] >> (7 - at % 8)) & 1
                } else {
                    0
                };
                assert_eq!((got[bit / 8] >> (7 - bit % 8)) & 1, expected);
            }
        }
    }
    #[test]
    fn independent_final_records() {
        let cases = fixture_cases::all();
        let count = cases.len();
        assert_eq!(count, 30);
        let mut s = Scratch::new();
        let mut out = [0i16; 16];
        // Each record alone, in lane `index % 8`: its own failure flag and value.
        let mut results = vec![[0u8; 3]; count];
        for (index, case) in cases.iter().enumerate() {
            let lane = index % 8;
            let mut meta = [[0u8; 16]; 14];
            let mut records = [[0u8; 64]; 8];
            let mut live = [0u8; 16];
            for p in 0..14 {
                meta[p][lane] = case[p];
            }
            records[lane].copy_from_slice(&case[14..]);
            live[lane] = 1;
            let bad = final8(&meta, &records, &live, &mut out, &mut s);
            let value = out[lane].to_le_bytes();
            results[index] = [bad as u8, value[0], value[1]];
            for other in 0..16 {
                assert!(other == lane || out[other] == 0);
            }
        }
        // The two overflow cases fail, and no other.
        assert_eq!(results.iter().filter(|r| r[0] != 0).count(), 2);
        assert_eq!((results[14][0], results[29][0]), (1, 1));
        // Windows of eight live records, wrapping: the flag is the OR of the records' flags.
        for start in (0..count).step_by(8) {
            let mut meta = [[0u8; 16]; 14];
            let mut records = [[0u8; 64]; 8];
            let mut live = [0u8; 16];
            let mut wanted_bad = false;
            for lane in 0..8 {
                let at = (start + lane) % count;
                for p in 0..14 {
                    meta[p][lane] = cases[at][p];
                }
                records[lane].copy_from_slice(&cases[at][14..]);
                live[lane] = 1;
                wanted_bad |= results[at][0] != 0;
            }
            let bad = final8(&meta, &records, &live, &mut out, &mut s);
            assert_eq!(bad, wanted_bad);
            for lane in 0..8 {
                let at = (start + lane) % count;
                let value = i16::from_le_bytes([results[at][1], results[at][2]]);
                assert_eq!(out[lane], value);
            }
            assert_eq!(&out[8..], &[0; 8]);
        }
        let mut hash = fx::Records::new();
        for index in 0..count {
            hash.update(&cases[index]);
            hash.update(&results[index]);
            hash.end();
        }
        hash.check("coretail-final", PIN);
    }
}
