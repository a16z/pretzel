//! Stage lookups only. The samplers and their queues are in other modules.
//! Caller retains columns across queues; never secret-index this metadata.
use core::sync::atomic::{compiler_fence, Ordering};
#[derive(Clone, Copy)]
pub enum Stage {
    Main,
    Middle,
    Final,
}
impl Stage {
    fn range(self) -> (usize, usize) {
        match self {
            Self::Main => (0, 7),
            Self::Middle => (7, 11),
            Self::Final => (18, 26),
        }
    }
}
struct Table {
    columns: usize,
    planes: &'static [u8],
}
const EVEN: Table = Table {
    columns: 128,
    planes: include_bytes!("lead_even.bin"),
};
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.global _pretzel55_proposal_planes16\n",
        include_str!("planes16_apple.S")
    ),
    options(raw)
);
// SAFETY: contract of the assembly routine defined just above (planes16_apple.S). It
// reads 32 bytes at `indices`, writes `16 * count` bytes at `out`, and for each plane `p < count`
// and block `b < blocks` reads 16 bytes at `planes + 16 * p + 704 * b`. `count` and
// `blocks` must be at least 1: both loops test after the decrement. No alignment is required. It
// is a leaf routine that uses no stack, changes only
// caller-saved registers (x0, x8 to x12, v0 to v5, v16 to v19, v24 to v30), keeps no pointer and
// has no global state, so it may be called concurrently. It uses NEON instructions only.
extern "C" {
    fn pretzel55_proposal_planes16(
        out: *mut u8,
        planes: *const u8,
        blocks: usize,
        indices: *const u8,
        count: usize,
    );
}
fn wipe(a: &mut [u8]) {
    for x in a {
        // SAFETY: `x` is a unique reference to one byte of the slice, valid for a volatile write.
        unsafe {
            core::ptr::write_volatile(x, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}
/// Plane-major result, public stage length. Bytes beyond planes*16 stay zero.
/// invalid is a private aggregate bit; caller must OR it into whole-attempt abort.
pub struct Lookup16 {
    pub bytes: [u8; 416],
    pub planes: usize,
    pub invalid: u64,
}
impl Drop for Lookup16 {
    fn drop(&mut self) {
        const {
            assert!(core::mem::align_of::<Self>() >= 8 && core::mem::size_of::<Self>() % 8 == 0);
        }
        // SAFETY: `self` is a unique reference to `size_of::<Self>()` writable bytes; the constant
        // assertion above checks that the alignment is at least 8 and the size a multiple of 8, so
        // the loop writes exactly the object in aligned words. All fields are integers, so zero is
        // a valid value.
        unsafe {
            let p = (self as *mut Self).cast::<u64>();
            for i in 0..core::mem::size_of::<Self>() / 8 {
                p.add(i).write_volatile(0);
            }
        }
        compiler_fence(Ordering::SeqCst);
    }
}
fn scan(table: &Table, stage: Stage, columns: &[u16; 16]) -> Lookup16 {
    let (offset, count) = stage.range();
    scan_range(table, offset, count, columns)
}
fn scan_range(table: &Table, offset: usize, count: usize, columns: &[u16; 16]) -> Lookup16 {
    let mut out = Lookup16 {
        bytes: [0; 416],
        planes: count,
        invalid: 0,
    };
    let mut ix = [0u8; 32];
    for l in 0..16 {
        ix[l] = (columns[l] & 15) as u8;
        ix[16 + l] = (columns[l] >> 4) as u8;
    }
    // SAFETY: feature: the routine uses NEON only (baseline of the AArch64 targets this crate
    // builds for). Lengths: `ix` has the 32 bytes read; `out.bytes` has 416 bytes and the callers
    // pass `(offset, count)` of (0, 7), (7, 11) or (18, 26), so at most 416 are written. A table
    // has `columns / 16` blocks of 704 bytes (44 planes of 16): the one table passed here is
    // 5632 = 8 * 704 bytes long and `offset + count` is at most 44, so every 16-byte read stays
    // inside its block. The table length is that of the included file, not checked by the
    // compiler.
    unsafe {
        pretzel55_proposal_planes16(
            out.bytes.as_mut_ptr(),
            table.planes.as_ptr().add(offset * 16),
            table.columns / 16,
            ix.as_ptr(),
            count,
        );
    }
    wipe(&mut ix);
    out
}
/// Lookup in the leading-even table for one stage. The stage and the table are public.
pub fn leading_even16(stage: Stage, columns: &[u16; 16]) -> Lookup16 {
    let mut out = scan(&EVEN, stage, columns);
    for c in columns {
        out.invalid |= (*c >= 128) as u64;
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_rows_all_stages_match_plane_oracle() {
        for first in (0..EVEN.columns).step_by(16) {
            let columns = core::array::from_fn(|i| (first + i) as u16);
            for stage in [Stage::Main, Stage::Middle, Stage::Final] {
                let (offset, count) = stage.range();
                let got = leading_even16(stage, &columns);
                assert_eq!(got.invalid, 0);
                for p in 0..count {
                    for l in 0..16 {
                        let c = first + l;
                        assert_eq!(
                            got.bytes[p * 16 + l],
                            EVEN.planes[(c / 16) * 704 + (offset + p) * 16 + c % 16]
                        );
                    }
                }
                assert!(got.bytes[count * 16..].iter().all(|&b| b == 0));
            }
        }
        assert_eq!(leading_even16(Stage::Final, &[128; 16]).invalid, 1);
    }
}

#[cfg(test)]
mod erase_boundary_tests {
    use super::*;
    #[test]
    fn complete_erasure_preserves_canaries() {
        #[repr(C)]
        struct Guarded {
            before: u64,
            value: core::mem::MaybeUninit<Lookup16>,
            after: u64,
        }
        let mut g = Guarded {
            before: 0x123456789abcdef0,
            value: core::mem::MaybeUninit::uninit(),
            after: 0xfedcba9876543210,
        };
        // SAFETY: `p` points to the live `MaybeUninit<Lookup16>` slot. The byte fill initializes
        // all of it, and any bit pattern is a valid `Lookup16` (integers only), so the single
        // `drop_in_place` and the byte view of the same `size_of::<Lookup16>()` bytes afterwards
        // are valid.
        unsafe {
            let p = g.value.as_mut_ptr();
            p.cast::<u8>()
                .write_bytes(0xa5, core::mem::size_of::<Lookup16>());
            core::ptr::drop_in_place(p);
            let bytes =
                core::slice::from_raw_parts(p.cast::<u8>(), core::mem::size_of::<Lookup16>());
            assert!(bytes.iter().all(|&b| b == 0));
        }
        assert_eq!(g.before, 0x123456789abcdef0);
        assert_eq!(g.after, 0xfedcba9876543210);
    }
}

#[cfg(test)]
mod conditional_leading_lookup_tests {
    use super::*;
    // On a tie, the leading sampler takes its value from the metadata of the main stage: the
    // primary in bits 0 to 10, the alias in bits 11 to 21, and bit 22 set when taking the primary
    // aborts. Both fields stay within the support 168 for every column, and a column whose
    // primary aborts has a zero 320-bit cut, so that its primary is never taken.
    #[test]
    fn leading_tie_fields_stay_within_the_support() {
        for first in (0..128).step_by(16) {
            let c: [u16; 16] = core::array::from_fn(|i| (first + i) as u16);
            let main = leading_even16(Stage::Main, &c);
            let middle = leading_even16(Stage::Middle, &c);
            let tail = leading_even16(Stage::Final, &c);
            assert_eq!(main.invalid | middle.invalid | tail.invalid, 0);
            for lane in 0..16 {
                let metadata = (0..4).fold(0u32, |a, j| {
                    a | ((main.bytes[(3 + j) * 16 + lane] as u32) << (8 * j))
                });
                let primary = metadata & 2047;
                let alias = (metadata >> 11) & 2047;
                assert!(primary <= 168, "column {}", first + lane);
                assert!(alias <= 168, "column {}", first + lane);
                if (metadata >> 22) & 1 != 0 {
                    let cut_is_zero = (0..3).all(|p| main.bytes[p * 16 + lane] == 0)
                        && (0..11).all(|p| middle.bytes[p * 16 + lane] == 0)
                        && (0..26).all(|p| tail.bytes[p * 16 + lane] == 0);
                    assert!(cut_is_zero, "column {}", first + lane);
                }
            }
        }
    }
}
