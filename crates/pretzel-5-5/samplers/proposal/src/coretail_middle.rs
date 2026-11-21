//! Fixed public scans for the two prefix comparisons. Caller owns scratch.
use crate::main_kernel::Output;
use std::arch::aarch64::*;
static TABLE: &[u8; 6144] = include_bytes!("coretail-middle-planes.bin");
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
/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). `plane` must be below 12:
/// `TABLE` has 6144 = 2 * 12 * 256 bytes and the two 256-byte rows read start at `256 * plane` and
/// `3072 + 256 * plane`.
#[inline(always)]
unsafe fn mixed(plane: usize, col: uint8x16_t, family: uint8x16_t) -> uint8x16_t {
    let a = lookup(TABLE.as_ptr().add(256 * plane), col);
    let b = lookup(TABLE.as_ptr().add(3072 + 256 * plane), col);
    vbslq_u8(vceqq_u8(family, vdupq_n_u8(0)), a, b)
}
/// Metadata planes: family,column,sign,main48[6],tailcolumn,tail32[4].
/// In the first two levels the only zero 320-bit cut is that of the self-alias column, which
/// stands for a full cut. A lane whose coin equals the table prefix is left not ready here.
#[inline(never)]
pub fn middle16(meta: &[[u8; 16]; 14], out: &mut Output) {
    // SAFETY: feature: NEON only (baseline of the AArch64 targets this crate builds for). Lengths:
    // every `meta[k]` is a 16-byte array reached by checked indexing and read with one 16-byte
    // load; `mixed` is called with planes 0 to 11, inside the 6144-byte table; `out.values` holds
    // 16 `i16` and `out.ready` 16 bytes, written in full. Alignment: unaligned accesses only.
    unsafe {
        let family = vld1q_u8(meta[0].as_ptr());
        let main = vld1q_u8(meta[1].as_ptr());
        let tail = vld1q_u8(meta[9].as_ptr());
        let z = vdupq_n_u8(0);
        let all = vdupq_n_u8(255);
        let mut same = all;
        let mut less = z;
        for p in 0..6 {
            let t = mixed(p, main, family);
            let u = vld1q_u8(meta[3 + p].as_ptr());
            less = vorrq_u8(less, vandq_u8(same, vcltq_u8(u, t)));
            same = vandq_u8(same, vceqq_u8(u, t));
        }
        let other = mixed(6, main, family);
        let main_full = vceqq_u8(main, other);
        let main_ready = vorrq_u8(vmvnq_u8(same), main_full);
        let a = vbslq_u8(vorrq_u8(less, main_full), main, other);
        same = all;
        less = z;
        for p in 0..4 {
            let t = mixed(7 + p, tail, family);
            let u = vld1q_u8(meta[10 + p].as_ptr());
            less = vorrq_u8(less, vandq_u8(same, vcltq_u8(u, t)));
            same = vandq_u8(same, vceqq_u8(u, t));
        }
        let other = mixed(11, tail, family);
        let tail_full = vceqq_u8(tail, other);
        let tail_ready = vorrq_u8(vmvnq_u8(same), tail_full);
        let b = vbslq_u8(vorrq_u8(less, tail_full), tail, other);
        let escape = vceqq_u8(a, all);
        let ready = vandq_u8(
            main_ready,
            vorrq_u8(
                vmvnq_u8(escape),
                vandq_u8(tail_ready, vmvnq_u8(vceqq_u8(b, all))),
            ),
        );
        let aa = [vmovl_u8(vget_low_u8(a)), vmovl_high_u8(a)];
        let bb = [vmovl_u8(vget_low_u8(b)), vmovl_high_u8(b)];
        let rr = [vmovl_u8(vget_low_u8(ready)), vmovl_high_u8(ready)];
        let sign = vandq_u8(vld1q_u8(meta[2].as_ptr()), vdupq_n_u8(1));
        let ss = [vmovl_u8(vget_low_u8(sign)), vmovl_high_u8(sign)];
        for h in 0..2 {
            let x = vbslq_u16(
                vceqq_u16(aa[h], vdupq_n_u16(255)),
                vaddq_u16(bb[h], vdupq_n_u16(255)),
                aa[h],
            );
            let neg = vnegq_s16(vreinterpretq_s16_u16(ss[h]));
            let value = vsubq_s16(veorq_s16(vreinterpretq_s16_u16(x), neg), neg);
            vst1q_s16(
                out.values.as_mut_ptr().add(8 * h),
                vbslq_s16(vcgtq_u16(rr[h], vdupq_n_u16(0)), value, vdupq_n_s16(0)),
            );
        }
        vst1q_u8(out.ready.as_mut_ptr(), vandq_u8(ready, vdupq_n_u8(1)));
    }
}
/// One byte of the table, for the tests that build inputs from it.
#[cfg(test)]
pub(crate) fn fixture_plane(family: usize, plane: usize, column: usize) -> u8 {
    TABLE[3072 * family + 256 * plane + column]
}

#[cfg(test)]
mod conditional_coretail_middle_tests {
    use super::*;

    use crate::fixture_gen as fx;

    // SHA-256 of the records built below; `generators/gen_proposal_fixtures.py` pins the same
    // value for the records its model of this function produces.
    const PIN: &str = "f1818ab0abbe22c2450957caf39eea8d86805437b085de05401d40d0495ecec5";

    /// Boundary values of the cut held in `count` planes from `first`, whose alias is in the
    /// next plane. A column that is its own alias uses the largest value as its cut.
    fn cuts(family: usize, column: usize, first: usize, count: usize) -> Vec<u64> {
        let top = (1u64 << (8 * count)) - 1;
        let mut cut = 0u64;
        for p in 0..count {
            cut = (cut << 8) | fixture_plane(family, first + p, column) as u64;
        }
        if fixture_plane(family, first + count, column) as usize == column {
            cut = top;
        }
        fx::boundary(cut, top)
    }

    /// The 14 metadata bytes of every record, in the order of the rule.
    fn inputs() -> Vec<[u8; 14]> {
        let mut rows = Vec::new();
        for column in 0..256usize {
            for family in 0..2usize {
                let tail = (column + 13) % 256;
                for main in cuts(family, column, 0, 6) {
                    for coin in cuts(family, tail, 7, 4) {
                        for sign in 0..2u8 {
                            let mut row = [0u8; 14];
                            row[0] = family as u8;
                            row[1] = column as u8;
                            row[2] = sign;
                            row[3..9].copy_from_slice(&main.to_be_bytes()[2..]);
                            row[9] = tail as u8;
                            row[10..].copy_from_slice(&(coin as u32).to_be_bytes());
                            rows.push(row);
                        }
                    }
                }
                for coin in cuts(family, column, 7, 4) {
                    for sign in 0..2u8 {
                        let mut row = [0u8; 14];
                        row[0] = family as u8;
                        row[1] = 255;
                        row[2] = sign;
                        row[9] = column as u8;
                        row[10..].copy_from_slice(&(coin as u32).to_be_bytes());
                        rows.push(row);
                    }
                }
            }
        }
        rows
    }

    #[test]
    fn mixed_family_prefix_boundaries() {
        let rows = inputs();
        let count = rows.len();
        assert_eq!(count, 29288);
        let mut results = vec![[0u8; 3]; count];
        let mut seen = vec![false; count];
        let mut out = Output::new();
        let mut meta = [[0u8; 16]; 14];
        for start in (0..count).step_by(16) {
            for lane in 0..16 {
                let row = &rows[(start + lane) % count];
                for p in 0..14 {
                    meta[p][lane] = row[p];
                }
            }
            middle16(&meta, &mut out);
            for lane in 0..16 {
                let at = (start + lane) % count;
                let value = out.values[lane].to_le_bytes();
                let result = [out.ready[lane], value[0], value[1]];
                // The last window wraps to the first records, which must give the same result.
                assert!(!seen[at] || results[at] == result);
                results[at] = result;
                seen[at] = true;
            }
        }
        let mut hash = fx::Records::new();
        for at in 0..count {
            hash.update(&rows[at]);
            hash.update(&results[at]);
            hash.end();
        }
        hash.check("coretail-middle", PIN);
    }
}
