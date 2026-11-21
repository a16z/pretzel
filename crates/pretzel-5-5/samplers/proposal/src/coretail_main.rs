//! Core-tail sampler using the main kernel's Output.
//! Only F=0/1 are public families; emitted-code validation is a separate requirement.
use crate::main_kernel::Output;
use std::arch::aarch64::*;
#[path = "coretail_main_tables.rs"]
mod tables;
/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). There is no other
/// requirement: the four unaligned 64-byte table loads cover exactly the 256-byte `row`.
#[inline(always)]
unsafe fn lookup(row: &[u8; 256], ix: uint8x16_t) -> uint8x16_t {
    let mut out = vdupq_n_u8(0);
    for b in 0..4 {
        let p = row.as_ptr().add(64 * b);
        let t = uint8x16x4_t(
            vld1q_u8(p),
            vld1q_u8(p.add(16)),
            vld1q_u8(p.add(32)),
            vld1q_u8(p.add(48)),
        );
        out = vorrq_u8(out, vqtbl4q_u8(t, vsubq_u8(ix, vdupq_n_u8((64 * b) as u8))));
    }
    out
}
/// # Safety
///
/// The CPU must have NEON (every AArch64 target of this crate has it). The function works on
/// register values only.
#[inline(always)]
unsafe fn widen(x: uint8x16_t) -> [uint16x8_t; 2] {
    [vmovl_u8(vget_low_u8(x)), vmovl_high_u8(x)]
}
#[inline(never)]
pub fn core16<const F: usize>(
    columns: &[u8; 16],
    signs: &[u8; 16],
    coins: &[u8; 32],
    out: &mut Output,
) {
    assert!(F < 2);
    // SAFETY: feature: NEON only (baseline of the AArch64 targets this crate builds for). Lengths:
    // `columns` and `signs` are 16-byte arrays (one 16-byte load each); `coins` has 32 bytes, read
    // at offsets 0 and 16; `out.values` holds 16 `i16`, written as two groups of 8 at offsets 0 and
    // 8; `out.ready` has 16 bytes, one store. Table rows are 256-byte arrays chosen by checked
    // indexing (`F < 2` is asserted). Alignment: `vld1q`/`vst1q` are unaligned accesses.
    unsafe {
        let col = vld1q_u8(columns.as_ptr());
        let lo = widen(lookup(&tables::MAIN[F][0], col));
        let hi = widen(lookup(&tables::MAIN[F][1], col));
        let other = lookup(&tables::MAIN[F][2], col);
        let c = widen(col);
        let o = widen(other);
        let sign = widen(vandq_u8(vld1q_u8(signs.as_ptr()), vdupq_n_u8(1)));
        let mut ready = [vdupq_n_u16(0); 2];
        for half in 0..2 {
            let t = vorrq_u16(lo[half], vshlq_n_u16::<8>(hi[half]));
            let u = vreinterpretq_u16_u8(vrev16q_u8(vld1q_u8(coins.as_ptr().add(16 * half))));
            // A lane is resolved when the coin prefix differs from the cut prefix, or when
            // its alias equals its column, where either branch returns the column. In
            // `MAIN` the cut prefix is zero for exactly the columns whose alias equals the
            // column (one in each table), so a zero prefix never selects a different value.
            let resolved = vorrq_u16(vmvnq_u16(vceqq_u16(u, t)), vceqq_u16(c[half], o[half]));
            let x = vbslq_u16(vcltq_u16(u, t), c[half], o[half]);
            ready[half] = vandq_u16(resolved, vmvnq_u16(vceqq_u16(x, vdupq_n_u16(255))));
            let neg = vnegq_s16(vreinterpretq_s16_u16(sign[half]));
            let signed = vsubq_s16(veorq_s16(vreinterpretq_s16_u16(x), neg), neg);
            vst1q_s16(
                out.values.as_mut_ptr().add(8 * half),
                vreinterpretq_s16_u16(vandq_u16(vreinterpretq_u16_s16(signed), ready[half])),
            );
        }
        vst1q_u8(
            out.ready.as_mut_ptr(),
            vandq_u8(
                vcombine_u8(vmovn_u16(ready[0]), vmovn_u16(ready[1])),
                vdupq_n_u8(1),
            ),
        );
    }
}

/// The 16-bit cut and the alias of one column, for the tests that build inputs from the table.
#[cfg(test)]
pub(crate) fn fixture_cut(family: usize, column: usize) -> (u16, u8) {
    let row = &tables::MAIN[family];
    let cut = u16::from_le_bytes([row[0][column], row[1][column]]);
    (cut, row[2][column])
}

#[cfg(test)]
mod conditional_coretail_main_tests {
    use super::*;

    use crate::fixture_gen as fx;

    // SHA-256 of the records built below; `generators/gen_proposal_fixtures.py` pins the same
    // value for the records its model of this function produces.
    const PIN: &str = "d0b247d20b7a5af394470c75576d825bafbaa81673ef41d2d71a3961199608f4";

    #[test]
    fn independent_prefix_boundaries() {
        let mut hash = fx::Records::new();
        let mut records = 0;
        let mut out = Output::new();
        for family in 0..2usize {
            for column in 0..256usize {
                let (mut cut, alias) = fixture_cut(family, column);
                if alias as usize == column {
                    cut = 0xffff;
                }
                for coin in fx::boundary(cut as u64, 0xffff) {
                    for sign in 0..2u8 {
                        let col = [column as u8; 16];
                        let signs = [sign; 16];
                        let coin = (coin as u16).to_be_bytes();
                        let mut coins = [0u8; 32];
                        for i in 0..16 {
                            coins[2 * i..2 * i + 2].copy_from_slice(&coin);
                        }
                        if family == 0 {
                            core16::<0>(&col, &signs, &coins, &mut out);
                        } else {
                            core16::<1>(&col, &signs, &coins, &mut out);
                        }
                        assert_eq!(out.ready, [out.ready[0]; 16]);
                        assert_eq!(out.values, [out.values[0]; 16]);
                        let value = out.values[0].to_le_bytes();
                        hash.update(&[family as u8, column as u8, sign, coin[1], coin[0]]);
                        hash.update(&[out.ready[0], value[0], value[1]]);
                        hash.end();
                        records += 1;
                    }
                }
            }
        }
        assert_eq!(records, 5112);
        hash.check("coretail-main", PIN);
    }
}
