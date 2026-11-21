//! Deferred correlation updates for the compact fixed-schedule signer.
//!
//! The row state a[j] = <y, rot_j(s)> is only ever read at the secret slot
//! index and only its increments matter for later slots. With the negacyclic
//! Gram row G (G[k] = <rot_0(s), rot_k(s)>, G[256-k] = -G[k], G[128] = 0),
//! the update of slot s' adds sign_{s'} G[|j - j_{s'}|] to a[j] for every j.
//! Hence the dot of slot s is
//!   a_s(j_s) = a_0[j_s] + sum_{s' < s} sign_{s'} G[|j_s - j_{s'}|],
//! an exact integer identity, so the signer's decisions are unchanged and the
//! 256-lane rotated-row rewrite per slot is not needed. Slots decided later
//! hold sign 0, so the sum need only cover the recorded public prefix, rounded
//! up to a complete vector block. Its length depends only on the slots
//! recorded (`record(slot, ...)` is compiled for tests only; the signer's
//! slots are written by the native transport), never on an index, sign,
//! active mask or abort. All secret
//! indexing goes through fixed-register
//! byte permutes (TBL/TBX) on aarch64, exactly like `ct_gram_registers`.
use crate::params::N;
use zeroize::Zeroize;

pub(crate) struct Deferred {
    /// Byte planes of the initial row a_0 (little-endian i32), for TBL lookup.
    #[cfg(test)]
    planes: [[u8; N]; 4],
    /// Secret slot indices in public slot order; unfilled slots hold 0.
    pub(crate) idx: [u8; 128],
    /// Signs in public slot order as i32 and as i8; unfilled slots hold 0.
    #[cfg(test)]
    sgn: [i32; 128],
    pub(crate) sgn8: [i8; 128],
    /// One past the greatest recorded public slot. All later signs are zero.
    pub(crate) recorded: usize,
    /// Byte planes of the packed Gram row G[0..128] (low byte, high byte of
    /// the low halfword) for two-register TBL/TBX lookups; nibbles stay in
    /// `Packed.high`.
    pub(crate) glo: [u8; 128],
    pub(crate) ghi: [u8; 128],
}
impl Drop for Deferred {
    fn drop(&mut self) {
        #[cfg(test)]
        {
            self.planes.zeroize();
            self.sgn.zeroize();
        }
        self.idx.zeroize();
        self.sgn8.zeroize();
        {
            self.glo.zeroize();
            self.ghi.zeroize();
        }
    }
}
impl Deferred {
    pub(crate) fn new(packed: &crate::ct_gram_registers::Packed) -> Self {
        let (glo, ghi) = {
            let mut glo = [0u8; 128];
            let mut ghi = [0u8; 128];
            for k in 0..128 {
                let b = packed.low[k].to_le_bytes();
                glo[k] = b[0];
                ghi[k] = b[1];
            }
            (glo, ghi)
        };
        Self {
            #[cfg(test)]
            planes: [[0; N]; 4],
            idx: [0; 128],
            #[cfg(test)]
            sgn: [0; 128],
            sgn8: [0; 128],
            recorded: 0,
            glo,
            ghi,
        }
    }
    /// The same state with the byte planes of the initial row `a0`, which `dot` reads.
    #[cfg(test)]
    fn with_row(a0: &[i32; N], packed: &crate::ct_gram_registers::Packed) -> Self {
        let mut state = Self::new(packed);
        for j in 0..N {
            let b = a0[j].to_le_bytes();
            for p in 0..4 {
                state.planes[p][j] = b[p];
            }
        }
        state
    }
    /// Record the decided sign of a public slot (index is secret).
    #[cfg(test)]
    pub(crate) fn record(&mut self, slot: usize, index: u64, sign: i32) {
        debug_assert!(index < N as u64 && (-1..=1).contains(&sign));
        self.idx[slot] = index as u8;
        #[cfg(test)]
        {
            self.sgn[slot] = sign;
        }
        self.sgn8[slot] = sign as i8;
        self.recorded = self.recorded.max(slot + 1);
    }
    /// a_0[index] + sum_s sign_s G[|index - j_s|], omitting known-zero future slots.
    #[inline(never)]
    #[cfg(test)]
    pub(crate) fn dot(&self, packed: &crate::ct_gram_registers::Packed, index: u64) -> i64 {
        debug_assert!(index < N as u64);
        dot_asm(self, packed, index as u8) as i64
    }
    /// Same dot, using a_0[index] carried by the oblivious slot router.
    #[cfg(test)]
    #[inline(never)]
    pub(crate) fn dot_with_base(
        &self,
        packed: &crate::ct_gram_registers::Packed,
        index: u64,
        base: &u64,
    ) -> i64 {
        unsafe {
            pretzel33_ct_routed_dot(
                self.idx.as_ptr(),
                self.sgn8.as_ptr(),
                self.glo.as_ptr(),
                self.ghi.as_ptr(),
                packed.high.as_ptr(),
                self.recorded.div_ceil(16),
                index,
                base,
            )
        }
    }
    /// d[i] = sum_s sign_s [j_s == i], fixed schedule over all (i, s).
    pub(crate) fn materialize_updates(&self, d: &mut [i32; N]) {
        // SAFETY: NEON is in the baseline of every target this crate builds for. `self.idx` and
        // `self.sgn8` have 128 bytes each and `b < 8` bounds the 16-byte unaligned loads at `16 *
        // b`. `d` is indexed with checks.
        unsafe {
            use core::arch::aarch64::*;
            let idx: [uint8x16_t; 8] =
                core::array::from_fn(|b| vld1q_u8(self.idx.as_ptr().add(16 * b)));
            let sgn: [int8x16_t; 8] =
                core::array::from_fn(|b| vld1q_s8(self.sgn8.as_ptr().add(16 * b)));
            for i in 0..N {
                let iv = vdupq_n_u8(i as u8);
                let mut acc = vdupq_n_s8(0);
                for b in 0..8 {
                    acc = vaddq_s8(
                        acc,
                        vandq_s8(vreinterpretq_s8_u8(vceqq_u8(idx[b], iv)), sgn[b]),
                    );
                }
                d[i] += crate::ct::lanes::sum_i8x16(acc);
            }
        }
    }
}

#[cfg(test)]
fn dot_neon(state: &Deferred, packed: &crate::ct_gram_registers::Packed, index: u8) -> i32 {
    use core::arch::aarch64::*;
    unsafe {
        #[inline(always)]
        unsafe fn table256(t: &[u8; 256], i: uint8x16_t) -> uint8x16_t {
            let sixty_four = vdupq_n_u8(64);
            let mut r = vqtbl4q_u8(vld1q_u8_x4(t.as_ptr()), i);
            let i = vsubq_u8(i, sixty_four);
            r = vqtbx4q_u8(r, vld1q_u8_x4(t.as_ptr().add(64)), i);
            let i = vsubq_u8(i, sixty_four);
            r = vqtbx4q_u8(r, vld1q_u8_x4(t.as_ptr().add(128)), i);
            let i = vsubq_u8(i, sixty_four);
            vqtbx4q_u8(r, vld1q_u8_x4(t.as_ptr().add(192)), i)
        }
        let jv = vdupq_n_u8(index);
        // a_0[index]: one byte per plane, lane 0 of each permute.
        let mut a0 = [0u8; 4];
        for p in 0..4 {
            a0[p] = vgetq_lane_u8::<0>(table256(&state.planes[p], jv));
        }
        let low_bytes: &[u8; 256] = core::mem::transmute(&packed.low); // little-endian u16 entries
        let high_table = vld1q_u8_x4(packed.high.as_ptr());
        let c128 = vdupq_n_u8(128);
        let one = vdupq_n_u8(1);
        let fifteen = vdupq_n_u8(15);
        let mut acc = [vdupq_n_s32(0); 4];
        for block in 0..state.recorded.div_ceil(16) {
            let jb = vld1q_u8(state.idx.as_ptr().add(16 * block));
            let k = vabdq_u8(jv, jb);
            let wrap = vcgtq_u8(k, c128);
            let kf = vbslq_u8(
                wrap,
                vreinterpretq_u8_s8(vnegq_s8(vreinterpretq_s8_u8(k))),
                k,
            );
            let is128 = vceqq_u8(kf, c128);
            let lo_i = vshlq_n_u8::<1>(kf);
            let hi_i = vorrq_u8(lo_i, one);
            let b0 = table256(low_bytes, lo_i);
            let b1 = table256(low_bytes, hi_i);
            let nb = vqtbl4q_u8(high_table, vshrq_n_u8::<1>(kf));
            let shift = vshlq_n_u8::<2>(vandq_u8(kf, one));
            let nib = vandq_u8(vshlq_u8(nb, vnegq_s8(vreinterpretq_s8_u8(shift))), fifteen);
            let lo16 = [
                vorrq_u16(
                    vmovl_u8(vget_low_u8(b0)),
                    vshlq_n_u16::<8>(vmovl_u8(vget_low_u8(b1))),
                ),
                vorrq_u16(vmovl_high_u8(b0), vshlq_n_u16::<8>(vmovl_high_u8(b1))),
            ];
            let nib16 = [vmovl_u8(vget_low_u8(nib)), vmovl_high_u8(nib)];
            let wrap16 = [
                vmovl_s8(vget_low_s8(vreinterpretq_s8_u8(wrap))),
                vmovl_high_s8(vreinterpretq_s8_u8(wrap)),
            ];
            let keep16 = [
                vmovl_s8(vget_low_s8(vreinterpretq_s8_u8(is128))),
                vmovl_high_s8(vreinterpretq_s8_u8(is128)),
            ];
            for q in 0..4 {
                let h = q >> 1;
                let (v32, n32, w32, z32) = if q & 1 == 0 {
                    (
                        vmovl_u16(vget_low_u16(lo16[h])),
                        vmovl_u16(vget_low_u16(nib16[h])),
                        vmovl_s16(vget_low_s16(wrap16[h])),
                        vmovl_s16(vget_low_s16(keep16[h])),
                    )
                } else {
                    (
                        vmovl_high_u16(lo16[h]),
                        vmovl_high_u16(nib16[h]),
                        vmovl_high_s16(wrap16[h]),
                        vmovl_high_s16(keep16[h]),
                    )
                };
                let raw = vreinterpretq_s32_u32(vorrq_u32(v32, vshlq_n_u32::<16>(n32)));
                let g = vshrq_n_s32::<12>(vshlq_n_s32::<12>(raw));
                let g = vsubq_s32(veorq_s32(g, w32), w32);
                let g = vbicq_s32(g, z32);
                acc[q] = vmlaq_s32(
                    acc[q],
                    g,
                    vld1q_s32(state.sgn.as_ptr().add(16 * block + 4 * q)),
                );
            }
        }
        let sum = vaddq_s32(vaddq_s32(acc[0], acc[1]), vaddq_s32(acc[2], acc[3]));
        (i32::from_le_bytes(a0)).wrapping_add(vaddvq_s32(sum))
    }
}

#[inline(always)]
#[cfg(test)]
fn dot_asm(state: &Deferred, packed: &crate::ct_gram_registers::Packed, index: u8) -> i32 {
    dot_asm_inner(state, packed, index)
}
/// Assembly dot: sum over the public recorded prefix of e_s G[k_s] plus a_0[index],
/// with e_s = sign_s (-1)^{wrap_s} and k_s the folded distance. The Gram
/// entry is G = b0 + 256 b1 + 65536 sext4(n); with D(e,v) the signed byte
/// dot product (SDOT), sum e b0 = D(e,b0) + 256 D(e,b0>>7) because SDOT reads
/// b0 as a signed byte, so the total is
///   D(e,b0) + 256 [D(e,b0>>7) + D(e,b1)] + 65536 [D(e,b1>>7) + D(e,sext4 n)].
/// Every lane sum stays below 2^13 before scaling, so the three accumulators
/// fit i32 lanes. Secret bytes only ever select register bytes (TBL/TBX) or
/// enter arithmetic; loop bounds and addresses are public. All vector
/// registers used are erased before return.
#[cfg(test)]
#[inline(never)]
fn dot_asm_inner(state: &Deferred, packed: &crate::ct_gram_registers::Packed, index: u8) -> i32 {
    let mut total: u64;
    let mut a0: u64;
    let planes = state.planes.as_flattened().as_ptr().wrapping_add(3 * N);
    unsafe {
        core::arch::asm!(
            "dup v20.16b, {index:w}", "movi v21.16b, #128", "movi v22.16b, #64", "movi v23.16b, #1",
            "movi v24.16b, #0", "movi v25.16b, #0", "movi v26.16b, #0",
            // The zero-prefix branch and block count depend only on public slots.
            "cbz {count}, 4f",
            "ld1 {{v0.16b-v3.16b}}, [{glo}], #64", "ld1 {{v4.16b-v7.16b}}, [{glo}]",
            "ld1 {{v8.16b-v11.16b}}, [{ghi}], #64", "ld1 {{v12.16b-v15.16b}}, [{ghi}]",
            "ld1 {{v16.16b-v19.16b}}, [{high}]",
            "2:",
            "ld1 {{v27.16b}}, [{idx}], #16",
            "uabd v27.16b, v20.16b, v27.16b",
            "cmhi v28.16b, v27.16b, v21.16b",
            "neg v29.16b, v27.16b",
            "bit v27.16b, v29.16b, v28.16b",
            "cmeq v29.16b, v27.16b, v21.16b",
            "ld1 {{v30.16b}}, [{sgn}], #16",
            "eor v30.16b, v30.16b, v28.16b", "sub v30.16b, v30.16b, v28.16b",
            "bic v30.16b, v30.16b, v29.16b",
            "tbl v31.16b, {{v0.16b-v3.16b}}, v27.16b",
            "sub v29.16b, v27.16b, v22.16b",
            "tbx v31.16b, {{v4.16b-v7.16b}}, v29.16b",
            "tbl v28.16b, {{v8.16b-v11.16b}}, v27.16b",
            "tbx v28.16b, {{v12.16b-v15.16b}}, v29.16b",
            "ushr v29.16b, v27.16b, #1",
            "tbl v29.16b, {{v16.16b-v19.16b}}, v29.16b",
            "and v27.16b, v27.16b, v23.16b",
            "shl v27.16b, v27.16b, #2",
            "neg v27.16b, v27.16b",
            "ushl v29.16b, v29.16b, v27.16b",
            "shl v29.16b, v29.16b, #4", "sshr v29.16b, v29.16b, #4",
            "sdot v24.4s, v30.16b, v31.16b",
            "ushr v31.16b, v31.16b, #7",
            "sdot v25.4s, v30.16b, v31.16b",
            "sdot v25.4s, v30.16b, v28.16b",
            "ushr v28.16b, v28.16b, #7",
            "sdot v26.4s, v30.16b, v28.16b",
            "sdot v26.4s, v30.16b, v29.16b",
            "subs {count:w}, {count:w}, #1", "b.ne 2b",
            "4:",
            "shl v25.4s, v25.4s, #8", "shl v26.4s, v26.4s, #16",
            "add v24.4s, v24.4s, v25.4s", "add v24.4s, v24.4s, v26.4s",
            "addv s24, v24.4s",
            "umov {total:w}, v24.s[0]",
            // a_0[index]: byte planes 3, 2, 1, 0 (pointer starts at plane 3).
            "mov {a0}, #0", "mov {count:w}, #4",
            "3:",
            "mov v27.16b, v20.16b",
            "ld1 {{v0.16b-v3.16b}}, [{planes}], #64", "tbl v28.16b, {{v0.16b-v3.16b}}, v27.16b",
            "sub v27.16b, v27.16b, v22.16b",
            "ld1 {{v0.16b-v3.16b}}, [{planes}], #64", "tbx v28.16b, {{v0.16b-v3.16b}}, v27.16b",
            "sub v27.16b, v27.16b, v22.16b",
            "ld1 {{v0.16b-v3.16b}}, [{planes}], #64", "tbx v28.16b, {{v0.16b-v3.16b}}, v27.16b",
            "sub v27.16b, v27.16b, v22.16b",
            "ld1 {{v0.16b-v3.16b}}, [{planes}], #64", "tbx v28.16b, {{v0.16b-v3.16b}}, v27.16b",
            "umov {tmp:w}, v28.b[0]",
            "orr {a0}, {tmp}, {a0}, lsl #8",
            "sub {planes}, {planes}, #512",
            "subs {count:w}, {count:w}, #1", "b.ne 3b",
            "movi v0.16b, #0", "movi v1.16b, #0", "movi v2.16b, #0", "movi v3.16b, #0",
            "movi v4.16b, #0", "movi v5.16b, #0", "movi v6.16b, #0", "movi v7.16b, #0",
            "movi v8.16b, #0", "movi v9.16b, #0", "movi v10.16b, #0", "movi v11.16b, #0",
            "movi v12.16b, #0", "movi v13.16b, #0", "movi v14.16b, #0", "movi v15.16b, #0",
            "movi v16.16b, #0", "movi v17.16b, #0", "movi v18.16b, #0", "movi v19.16b, #0",
            "movi v20.16b, #0", "movi v21.16b, #0", "movi v22.16b, #0", "movi v23.16b, #0",
            "movi v24.16b, #0", "movi v25.16b, #0", "movi v26.16b, #0", "movi v27.16b, #0",
            "movi v28.16b, #0", "movi v29.16b, #0", "movi v30.16b, #0", "movi v31.16b, #0",
            glo=inout(reg) state.glo.as_ptr()=>_, ghi=inout(reg) state.ghi.as_ptr()=>_,
            high=in(reg) packed.high.as_ptr(),
            idx=inout(reg) state.idx.as_ptr()=>_, sgn=inout(reg) state.sgn8.as_ptr()=>_,
            planes=inout(reg) planes=>_,
            index=in(reg) index as u64,
            total=out(reg) total, a0=out(reg) a0, tmp=out(reg) _, count=inout(reg) state.recorded.div_ceil(16)=>_,
            out("v0") _,out("v1") _,out("v2") _,out("v3") _,out("v4") _,out("v5") _,out("v6") _,out("v7") _,
            out("v8") _,out("v9") _,out("v10") _,out("v11") _,out("v12") _,out("v13") _,out("v14") _,out("v15") _,
            out("v16") _,out("v17") _,out("v18") _,out("v19") _,out("v20") _,out("v21") _,out("v22") _,out("v23") _,
            out("v24") _,out("v25") _,out("v26") _,out("v27") _,out("v28") _,out("v29") _,out("v30") _,out("v31") _,
            options(nostack)
        );
    }
    (a0 as u32 as i32).wrapping_add(total as u32 as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::params::*;
    fn xs(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }
    #[test]
    fn deferred_dots_and_updates_match_the_rewriting_state_on_random_slot_sequences() {
        let mut st = 0x7e5u64;
        for trial in 0..6 {
            let s_flat: crate::transport::Vector = core::array::from_fn(|i| {
                if i == 0 {
                    1
                } else if i < N {
                    0
                } else {
                    match (xs(&mut st) >> 3) % 4 {
                        0 => -1,
                        1 => 1,
                        _ => 0,
                    }
                }
            });
            let key = crate::correlation::Key::new(&s_flat);
            let z: crate::transport::Vector =
                core::array::from_fn(|_| ((xs(&mut st) >> 5) % 61) as i32 - 30);
            let mut reference = key.start(&z);
            let mut deferred = Deferred::with_row(reference.row(), &key.packed_gram);
            let mut seen = [0i32; N];
            for slot in 0..128u64 {
                let j = if trial % 2 == 0 {
                    (xs(&mut st) >> 9) % 256
                } else {
                    [0, 255, 128, 127, 129, 1, 254, 7][slot as usize % 8]
                };
                let sign = match (xs(&mut st) >> 11) % 3 {
                    0 => -1,
                    1 => 0,
                    _ => 1,
                };
                let expected = reference.dot_oblivious(j);
                let got = deferred.dot(&key.packed_gram, j);
                assert_eq!(got, expected, "trial {trial} slot {slot} index {j}");
                reference.update_oblivious(&key, j, sign);
                deferred.record(slot as usize, j, sign);
                seen[j as usize] += sign;
            }
            let mut d = [0i32; N];
            deferred.materialize_updates(&mut d);
            assert_eq!(d, seen);
            assert_eq!(&d, reference.updates());
        }
    }
    #[test]
    fn assembly_dot_matches_the_intrinsics_dot_on_extreme_gram_rows() {
        let mut st = 0x4242u64;
        let hi = SHELL_HI as i64;
        for case in 0..12 {
            let mut gram = [0i64; 256];
            gram[0] = hi;
            for j in 1..128 {
                gram[j] = if case < 8 {
                    [-hi, -196608, -65536, -1, 0, 65535, 196608, hi][case].clamp(-hi, hi)
                } else {
                    (xs(&mut st) % (2 * hi as u64 + 1)) as i64 - hi
                };
                gram[256 - j] = -gram[j];
            }
            let packed = crate::ct_gram_registers::Packed::new(&gram);
            let a0: [i32; N] = core::array::from_fn(|_| xs(&mut st) as i32);
            let mut deferred = Deferred::with_row(&a0, &packed);
            for slot in 0..128 {
                let j = if slot % 2 == 0 {
                    xs(&mut st) % 256
                } else {
                    [0, 255, 128, 127, 129, 1, 254, 7][slot % 8]
                };
                let sign = match (xs(&mut st) >> 11) % 3 {
                    0 => -1,
                    1 => 0,
                    _ => 1,
                };
                deferred.record(slot, j, sign);
            }
            for index in (0..N).map(|i| i as u8) {
                assert_eq!(
                    dot_asm(&deferred, &packed, index),
                    dot_neon(&deferred, &packed, index),
                    "case {case} index {index}"
                );
                assert_eq!(
                    deferred.dot_with_base(
                        &packed,
                        index as u64,
                        &((a0[index as usize] as u32 as u64) << 16)
                    ),
                    dot_asm(&deferred, &packed, index) as i64
                );
            }
        }
    }
    #[test]
    fn deferred_dot_at_every_index_pair_matches_the_gram_identity() {
        let mut st = 0x99u64;
        let s_flat: crate::transport::Vector = core::array::from_fn(|i| {
            if i == 0 {
                1
            } else if i < N {
                0
            } else {
                match (xs(&mut st) >> 3) % 4 {
                    0 => -1,
                    1 => 1,
                    _ => 0,
                }
            }
        });
        let key = crate::correlation::Key::new(&s_flat);
        let a0 = [0i32; N];
        for j_prev in [0u64, 1, 2, 63, 64, 127, 128, 129, 200, 254, 255] {
            let mut deferred = Deferred::with_row(&a0, &key.packed_gram);
            deferred.record(5, j_prev, 1);
            deferred.record(77, j_prev, -1);
            deferred.record(78, (j_prev + 3) % 256, 1);
            for j in 0..N as u64 {
                let g = |k: u64| key.gram_entry(k);
                let expected = g((j as i64 - j_prev as i64).unsigned_abs())
                    - g((j as i64 - j_prev as i64).unsigned_abs())
                    + g((j as i64 - ((j_prev + 3) % 256) as i64).unsigned_abs());
                assert_eq!(
                    deferred.dot(&key.packed_gram, j),
                    expected,
                    "j={j} prev={j_prev}"
                );
            }
        }
        let _ = SHELL_HI;
    }
    #[test]
    fn every_public_prefix_matches_the_complete_zero_padded_sum() {
        let mut seed = 0x8797133u64;
        let mut gram = [0i64; N];
        gram[0] = SHELL_HI as i64;
        for j in 1..128 {
            gram[j] = match j % 5 {
                0 => -(SHELL_HI as i64),
                1 => SHELL_HI as i64,
                2 => -65536,
                3 => 65535,
                _ => 0,
            };
            gram[N - j] = -gram[j];
        }
        let packed = crate::ct_gram_registers::Packed::new(&gram);
        let a0 = core::array::from_fn(|_| xs(&mut seed) as i32);
        let mut state = Deferred::with_row(&a0, &packed);
        for prefix in 0..=128 {
            assert_eq!(state.recorded, prefix);
            for index in [0, 1, 63, 64, 127, 128, 129, 255] {
                let truncated = state.dot(&packed, index);
                assert_eq!(
                    state.dot_with_base(
                        &packed,
                        index,
                        &((a0[index as usize] as u32 as u64) << 16)
                    ),
                    truncated
                );
                state.recorded = 128;
                let complete = state.dot(&packed, index);
                state.recorded = prefix;
                assert_eq!(truncated, complete, "prefix {prefix} index {index}");
            }
            if prefix < 128 {
                // Zero signs must advance the same public prefix as nonzero signs.
                state.record(prefix, xs(&mut seed) % 256, [-1, 0, 1][prefix % 3]);
            }
        }
    }
}

#[cfg(test)]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel33_ct_routed_dot\n.p2align 2\n_pretzel33_ct_routed_dot:\n",
        include_str!("../../pretzel-4-4/core/src/ct_routed_dot.S")
    ),
    options(raw)
);
// SAFETY: contract of `pretzel33_ct_routed_dot`, which the `global_asm!` item above assembles from
// `ct_routed_dot.S` of the rank-four crate; it is assembled and declared for test builds only (the
// signer's batch calls `pretzel33_ct_routed_dot_keep_tables` of `transport-tables.S`). It reads `16
// * blocks` bytes at `idx` and at `signs`, eight bytes at `label` and, unless `blocks` is zero, 128
// bytes at `glo`, 128 at `ghi` and 64 at `high`. It writes through no pointer and uses the low byte
// of `index` as a number. It executes SDOT, which needs FEAT_DotProd: `build.rs` calls
// `require_dot_product`, which refuses a target that does not enable `dotprod`, and nothing tests
// for it at run time. It saves and restores d8 to d15 in a 64-byte frame that it clears, writes no
// callee-saved general register and keeps no pointer.
#[cfg(test)]
unsafe extern "C" {
    fn pretzel33_ct_routed_dot(
        idx: *const u8,
        signs: *const i8,
        glo: *const u8,
        ghi: *const u8,
        high: *const u8,
        blocks: usize,
        index: u64,
        label: *const u64,
    ) -> i64;
}
