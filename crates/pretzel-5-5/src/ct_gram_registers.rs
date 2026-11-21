//! Fixed-address reconstruction of a bounded negacyclic autocorrelation row.
use zeroize::Zeroize;
pub(crate) struct Packed {
    pub(crate) low: [u16; 128],
    pub(crate) high: [u8; 64],
}
impl Packed {
    pub(crate) fn empty() -> Self {
        Self {
            low: [0; 128],
            high: [0; 64],
        }
    }
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn new(gram: &[i64; 256]) -> Self {
        assert!(gram[128] == 0, "invalid Gram midpoint");
        for j in 1..128 {
            assert!(gram[256 - j] == -gram[j], "invalid Gram symmetry");
        }
        let mut result = Self::empty();
        for j in 0..128 {
            assert!(gram[j].unsigned_abs() <= crate::params::SHELL_HI);
            result.low[j] = gram[j] as u16;
            result.high[j / 2] |= (((gram[j] >> 16) & 15) as u8) << ((j & 1) * 4);
        }
        for j in 0..128 {
            let nibble = ((result.high[j / 2] >> ((j & 1) * 4)) & 15) as i32;
            let upper = (nibble << 28) >> 12;
            assert!(
                (upper | result.low[j] as i32) as i64 == gram[j],
                "invalid packed Gram reconstruction"
            );
        }
        result
    }
    pub(crate) fn erase(&mut self) {
        self.low.zeroize();
        self.high.zeroize();
    }
}
impl Drop for Packed {
    fn drop(&mut self) {
        self.erase();
    }
}

#[inline(never)]
#[allow(dead_code)]
pub(crate) fn update(
    packed: &Packed,
    a: &mut [i32; 256],
    d: &mut [i32; 256],
    index: u64,
    sign: i32,
) {
    // TBL/TBX addresses are the fixed register lists; secret indices select
    // bytes in those registers. Each loop iteration writes four public lanes.
    // SAFETY: The AArch64/neon-gated module supplies Advanced SIMD. Packed holds 128 initialized u16
    // low words and 64 high bytes. Assembly loads exactly those 320 bytes and its 64 iterations
    // read/write four i32 values in each of the exclusive 256-element a/d arrays; register lookup
    // never creates a secret-derived memory address. Scratch and flag effects are declared.
    unsafe {
        core::arch::asm!(
            "ld1 {{v0.16b-v3.16b}}, [{low}], #64",
            "ld1 {{v4.16b-v7.16b}}, [{low}], #64",
            "ld1 {{v8.16b-v11.16b}}, [{low}], #64",
            "ld1 {{v12.16b-v15.16b}}, [{low}]",
            "ld1 {{v16.16b-v19.16b}}, [{high}]",
            "movi v20.4s, #0", "mov {tmp:w}, #1", "ins v20.s[1], {tmp:w}",
            "mov {tmp:w}, #2", "ins v20.s[2], {tmp:w}",
            "mov {tmp:w}, #3", "ins v20.s[3], {tmp:w}",
            "and {tmp}, {index}, #255", "dup v21.4s, {tmp:w}",
            "dup v22.4s, {sign:w}", "cmp {index}, #256", "csetm {valid:w}, lo",
            "mov {count:w}, #64",
            "2:",
            "sub v23.4s, v20.4s, v21.4s", "sshr v24.4s, v23.4s, #31",
            "movi v25.4s, #255", "and v23.16b, v23.16b, v25.16b",
            "movi v26.4s, #128", "cmhi v27.4s, v23.4s, v26.4s",
            "eor v24.16b, v24.16b, v27.16b", "neg v28.4s, v23.4s",
            "and v28.16b, v28.16b, v25.16b", "bsl v27.16b, v28.16b, v23.16b",
            "mov v23.16b, v27.16b", "cmeq v31.4s, v23.4s, v26.4s",
            // Four low-halfwords become eight independent byte indices.
            "xtn v25.4h, v23.4s", "shl v25.4h, v25.4h, #1",
            "shl v26.4h, v25.4h, #8", "orr v25.8b, v25.8b, v26.8b",
            "movi v26.4h, #1, lsl #8", "add v25.4h, v25.4h, v26.4h",
            "movi v26.8b, #64",
            "tbl v28.8b, {{v0.16b-v3.16b}}, v25.8b",
            "sub v25.8b, v25.8b, v26.8b",
            "tbx v28.8b, {{v4.16b-v7.16b}}, v25.8b",
            "sub v25.8b, v25.8b, v26.8b",
            "tbx v28.8b, {{v8.16b-v11.16b}}, v25.8b",
            "sub v25.8b, v25.8b, v26.8b",
            "tbx v28.8b, {{v12.16b-v15.16b}}, v25.8b",
            "uxtl v28.4s, v28.4h",
            // One upper nibble per coefficient, followed by signed extension.
            "ushr v25.4s, v23.4s, #1", "xtn v25.4h, v25.4s", "xtn v25.8b, v25.8h",
            "tbl v29.8b, {{v16.16b-v19.16b}}, v25.8b",
            "uxtl v29.8h, v29.8b", "uxtl v29.4s, v29.4h",
            "movi v26.4s, #1", "and v25.16b, v23.16b, v26.16b",
            "shl v25.4s, v25.4s, #2", "neg v25.4s, v25.4s",
            "ushl v29.4s, v29.4s, v25.4s", "shl v29.4s, v29.4s, #28",
            "sshr v29.4s, v29.4s, #12", "orr v28.16b, v28.16b, v29.16b",
            "eor v28.16b, v28.16b, v24.16b", "sub v28.4s, v28.4s, v24.4s",
            "bic v28.16b, v28.16b, v31.16b",
            "ld1 {{v29.4s}}, [{a}]", "mla v29.4s, v28.4s, v22.4s",
            "st1 {{v29.4s}}, [{a}], #16",
            "cmeq v25.4s, v20.4s, v21.4s", "dup v26.4s, {valid:w}",
            "and v25.16b, v25.16b, v26.16b", "and v25.16b, v25.16b, v22.16b",
            "ld1 {{v29.4s}}, [{d}]", "add v29.4s, v29.4s, v25.4s",
            "st1 {{v29.4s}}, [{d}], #16",
            "movi v25.4s, #4", "add v20.4s, v20.4s, v25.4s",
            "subs {count:w}, {count:w}, #1", "b.ne 2b",
            // Erase all newly held table and working registers before returning.
            "movi v0.16b, #0",
            "movi v1.16b, #0",
            "movi v2.16b, #0",
            "movi v3.16b, #0",
            "movi v4.16b, #0",
            "movi v5.16b, #0",
            "movi v6.16b, #0",
            "movi v7.16b, #0",
            "movi v8.16b, #0",
            "movi v9.16b, #0",
            "movi v10.16b, #0",
            "movi v11.16b, #0",
            "movi v12.16b, #0",
            "movi v13.16b, #0",
            "movi v14.16b, #0",
            "movi v15.16b, #0",
            "movi v16.16b, #0",
            "movi v17.16b, #0",
            "movi v18.16b, #0",
            "movi v19.16b, #0",
            "movi v20.16b, #0",
            "movi v21.16b, #0",
            "movi v22.16b, #0",
            "movi v23.16b, #0",
            "movi v24.16b, #0",
            "movi v25.16b, #0",
            "movi v26.16b, #0",
            "movi v27.16b, #0",
            "movi v28.16b, #0",
            "movi v29.16b, #0",
            "movi v30.16b, #0",
            "movi v31.16b, #0",
            low=inout(reg) packed.low.as_ptr()=>_, high=in(reg) packed.high.as_ptr(),
            a=inout(reg) a.as_mut_ptr()=>_,d=inout(reg) d.as_mut_ptr()=>_,
            index=in(reg) index,sign=in(reg) sign,
            tmp=out(reg) _,valid=out(reg) _,count=out(reg) _,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            out("v4") _,
            out("v5") _,
            out("v6") _,
            out("v7") _,
            out("v8") _,
            out("v9") _,
            out("v10") _,
            out("v11") _,
            out("v12") _,
            out("v13") _,
            out("v14") _,
            out("v15") _,
            out("v16") _,
            out("v17") _,
            out("v18") _,
            out("v19") _,
            out("v20") _,
            out("v21") _,
            out("v22") _,
            out("v23") _,
            out("v24") _,
            out("v25") _,
            out("v26") _,
            out("v27") _,
            out("v28") _,
            out("v29") _,
            out("v30") _,
            out("v31") _,
            options(nostack)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    fn register_rotation_preserves_all_coefficients_and_updates() {
        let mut rng = 0xb547793343ff21u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for case in 0..16 {
            // The shell bound SHELL_HI of this parameter set.
            let hi = crate::params::SHELL_HI as i64;
            let mut gram = [0i64; 256];
            gram[0] = hi;
            for j in 1..128 {
                gram[j] = if case < 8 {
                    [-hi, -196608, -65536, -1, 0, 65535, 196608, hi][case].clamp(-hi, hi)
                } else {
                    (next() % (2 * hi as u64 + 1)) as i64 - hi
                };
                gram[256 - j] = -gram[j];
            }
            let packed = Packed::new(&gram);
            for index in (0..256u64).chain([256, 511, 65536, u64::MAX]) {
                for sign in [-1, 0, 1] {
                    let mut a = core::array::from_fn(|_| next() as i32);
                    let mut d = core::array::from_fn(|_| next() as i32);
                    let before_a = a;
                    let before_d = d;
                    update(&packed, &mut a, &mut d, index, sign);
                    let i = (index & 255) as usize;
                    for j in 0..256 {
                        let value = if j < i {
                            -gram[j + 256 - i]
                        } else {
                            gram[j - i]
                        } as i32;
                        assert_eq!(
                            a[j],
                            before_a[j].wrapping_add(sign * value),
                            "case {case}, index {index}, sign {sign}, lane {j}"
                        );
                        assert_eq!(
                            d[j],
                            before_d[j].wrapping_add(if j as u64 == index { sign } else { 0 })
                        );
                    }
                }
            }
        }
    }
}
