//! Fixed-address compaction of original challenge-indexed transport draws.
#[cfg(test)]
use crate::challenge::weight;
#[cfg(test)]
use crate::fixed::Fx;
use crate::{challenge::Challenge, ct::opaque_mask, hashes::Xof, params::N};
#[cfg(test)]
use zeroize::Zeroizing;

pub(crate) const WORDS: usize = 8;
pub(crate) type Record = [u64; WORDS];
// With coins assigned after routing, stage one needs only N labels; stage
// two also holds all 128 final records. These are public storage extents.
pub(crate) const FIRST_ROWS: usize = N / WORDS;
pub(crate) const SECOND_ROWS: usize = 128;

/// Slot records in caller-owned buffers of the erased signing scratch (no
/// allocation per attempt). `records` and `next` are the two stages of the
/// routing network; the routed view is whichever holds the final stage.
pub(crate) struct Positions<'a> {
    records: &'a [Record],
}
impl<'a> Positions<'a> {
    pub(crate) fn native_records(&self) -> *const u64 {
        const _: () = assert!(WORDS == 8);
        self.records.as_ptr().cast()
    }
    pub(crate) fn interval_coin_ptr(&self) -> *const u64 {
        self.records.as_flattened()[1..].as_ptr()
    }

    #[cfg(test)]
    pub(crate) fn new(
        c: &Challenge,
        rng: &mut Xof,
        records: &'a mut [Record; FIRST_ROWS],
        next: &'a mut [Record; SECOND_ROWS],
    ) -> Self {
        debug_assert!(weight(c) <= 128);
        Self::new_packed_coins(c, rng, records, next, None)
    }
    /// Route only position labels, then assign independent 384-bit uniforms
    /// in public slot order. Original conditional joint law, different tape map.
    #[cfg(test)]
    fn label_original_packed_coins(
        c: &Challenge,
        rng: &mut Xof,
        records: &'a mut [Record; FIRST_ROWS],
        next: &'a mut [Record; SECOND_ROWS],
        base: Option<&[i32; N]>,
    ) -> Self {
        let a = &mut records.as_flattened_mut()[..N];
        let b = &mut next.as_flattened_mut()[..N];
        let mut rank = 0u64;
        for j in 0..N {
            let active = u64::from(c[j]);
            let mask = opaque_mask(0u64.wrapping_sub(active));
            a[j] = ((1 << 63)
                | (((j as u64) - rank) << 8)
                | j as u64
                | ((base.map_or(0, |row| row[j]) as u32 as u64) << 16))
                & mask;
            rank += active;
        }
        // Public eight-stage shift network; the final stage only needs the
        // first 128 outputs. All addresses depend on j and stride, never c.
        for stage in 0..8 {
            let stride = 1usize << stage;
            let bit = (stride as u64) << 8;
            let (input, output) = if stage & 1 == 0 {
                (&*a, &mut *b)
            } else {
                (&*b, &mut *a)
            };
            let limit = if stage == 7 { 128 } else { N };
            for j in 0..limit {
                let keep = opaque_mask(0u64.wrapping_sub(u64::from(input[j] & bit == 0)));
                let mut label = input[j] & keep;
                if j + stride < N {
                    let take =
                        opaque_mask(0u64.wrapping_sub(u64::from(input[j + stride] & bit != 0)));
                    label |= input[j + stride] & take;
                }
                output[j] = label & !bit;
            }
        }
        // Eight stages leave labels in a; b's storage can now be reused.
        // Coins as in the paper, Appendix D.4: each of the 128 positions has its own
        // independent high 128 bits, and all share one low 256-bit tail, kept in an
        // erased owner. The coins are therefore not independent; the paper charges the
        // correlation in the comparison of Appendix F, subject to Assumption F.1.
        let mut shared_words = [0u64; 4];
        let mut shared_tail = crate::ct_erase::StackByteGuard::new(&mut shared_words);
        rng.fill(&mut shared_tail);
        // One common low 256-bit tail, independent high 128 bits per slot.
        #[cfg(target_arch = "aarch64")]
        let copied_coins=rng.consume_attempt_prefix(|bytes|{
            if bytes.len()<128*16{return 0;}
            unsafe{core::arch::asm!(
                "ldp q0,q1,[{tail}]",
                "ext v0.16b,v0.16b,v0.16b,#8", "ext v1.16b,v1.16b,v1.16b,#8",
                "mov {count},#128", "2:",
                "ldr q2,[{src}]", "ext v2.16b,v2.16b,v2.16b,#8",
                "stur q1,[{dst},#8]", "stur q0,[{dst},#24]", "stur q2,[{dst},#40]",
                "str xzr,[{dst},#56]", "add {src},{src},#16", "add {dst},{dst},#64",
                "subs {count},{count},#1", "b.ne 2b",
                "movi v0.2d,#0", "movi v1.2d,#0", "movi v2.2d,#0",
                tail=in(reg) shared_tail.as_ptr(),src=inout(reg) bytes.as_ptr()=>_,dst=inout(reg) next.as_mut_ptr()=>_,count=out(reg) _,out("v0") _,out("v1") _,out("v2") _,options(nostack));}
            128*16
        })!=0;
        for slot in 0..128 {
            #[cfg(target_arch = "aarch64")]
            #[allow(unused_variables)] // read only by the portable branch below
            let label = if let Some(row) = base {
                // Keep the added correlation payload inside its erased owners
                // and explicitly cleared asm temporaries across coin fills.
                unsafe {
                    core::arch::asm!(
                    "ldr {value}, [{src}]", "ldr {base:w}, [{row}]",
                    "asr {mask}, {value}, #63", "bic {base}, {base}, {mask}",
                    "orr {value}, {value}, {base}, lsl #16", "str {value}, [{dst}]",
                    "mov {value}, xzr", "mov {base}, xzr", "mov {mask}, xzr",
                    src=in(reg) records.as_flattened().as_ptr().add(slot),
                    dst=in(reg) next[slot].as_mut_ptr(),row=in(reg) row.as_ptr(),
                    value=out(reg) _,base=out(reg) _,mask=out(reg) _,options(nostack));
                }
                0u64 // selected exclusive coins do not inspect this local value
            } else {
                let label = records.as_flattened()[slot];
                next[slot][0] = label;
                label
            };
            #[allow(unused_variables)] // read only by the portable branch below
            let mask = u64::MAX; // Inactive slots use these independent coins only for dummy tests.
            if !copied_coins {
                let mut block_words = [0u64; 2];
                let mut block = crate::ct_erase::StackByteGuard::new(&mut block_words);
                rng.fill(&mut block);
                #[cfg(target_arch = "aarch64")]
                // Keep private coin bytes inside the explicit erased owners
                // and these three explicitly cleared vector registers.
                // Exclusive-slot coins make mask all-ones for every slot.
                unsafe {
                    core::arch::asm!(
                    "ldp q0, q1, [{tail}]",
                    "ext v2.16b, v1.16b, v1.16b, #8",
                    "stur q2, [{dst}, #8]",
                    "ext v2.16b, v0.16b, v0.16b, #8",
                    "stur q2, [{dst}, #24]",
                    "ldr q2, [{high}]",
                    "ext v2.16b, v2.16b, v2.16b, #8",
                    "stur q2, [{dst}, #40]",
                    "movi v0.2d, #0", "movi v1.2d, #0", "movi v2.2d, #0",
                    tail=in(reg) shared_tail.as_ptr(),high=in(reg) block.as_ptr(),
                    dst=in(reg) next[slot].as_mut_ptr(),
                    out("v0") _,out("v1") _,out("v2") _,options(nostack));
                }
            }
            next[slot][7] = 0;
        }
        Self { records: &next[..] }
    }

    fn new_packed_coins(
        c: &Challenge,
        rng: &mut Xof,
        records: &'a mut [Record; FIRST_ROWS],
        next: &'a mut [Record; SECOND_ROWS],
        base: Option<&[i32; N]>,
    ) -> Self {
        let a = &mut records.as_flattened_mut()[..N];
        let b = &mut next.as_flattened_mut()[..N];
        let mut rank = 0u64;
        for j in 0..N {
            let active = u64::from(c[j]);
            let mask = opaque_mask(0u64.wrapping_sub(active));
            a[j] = ((1 << 63)
                | (((j as u64) - rank) << 8)
                | j as u64
                | ((base.map_or(0, |row| row[j]) as u32 as u64) << 16))
                & mask;
            rank += active;
        }
        // Public eight-stage shift network; the final stage only needs the
        // first 128 outputs. All addresses depend on j and stride, never c.
        for stage in 0..8 {
            let stride = 1usize << stage;
            #[allow(unused_variables)] // read only by the portable branch below
            let bit = (stride as u64) << 8;
            let (input, output) = if stage & 1 == 0 {
                (&*a, &mut *b)
            } else {
                (&*b, &mut *a)
            };
            #[allow(unused_variables)] // read only by the portable branch below
            let limit = if stage == 7 { 128 } else { N };
            #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
            label_route_stage(input, output, stage);
        }
        // Eight stages leave labels in a; b's storage can now be reused.
        // Coins as in the paper, Appendix D.4: each of the 128 positions has its own
        // independent high 128 bits, and all share one low 256-bit tail, kept in an
        // erased owner. The coins are therefore not independent; the paper charges the
        // correlation in the comparison of Appendix F, subject to Assumption F.1.
        let mut shared_words = [0u64; 4];
        let mut shared_tail = crate::ct_erase::StackByteGuard::new(&mut shared_words);
        rng.fill(&mut shared_tail);
        // One common low 256-bit tail, independent high 128 bits per slot.
        #[cfg(target_arch = "aarch64")]
        let copied_coins=rng.consume_attempt_prefix(|bytes|{
            if bytes.len()<128*16{return 0;}
            // SAFETY: The byte-length check supplies 128*16 input bytes, shared_tail owns 32 bytes, and
            // next has 128 eight-u64 records. Each iteration writes offsets 8..64 in one 64-byte
            // record. These borrows are disjoint; the aarch64 guard supplies NEON and asm
            // outputs/clobbers are declared.
            unsafe{core::arch::asm!(
                "ldp q0,q1,[{tail}]",
                "ext v0.16b,v0.16b,v0.16b,#8", "ext v1.16b,v1.16b,v1.16b,#8",
                "mov {count},#128", "2:",
                "ldr q2,[{src}]", "ext v2.16b,v2.16b,v2.16b,#8",
                "stur q1,[{dst},#8]", "stur q0,[{dst},#24]", "stur q2,[{dst},#40]",
                "str xzr,[{dst},#56]", "add {src},{src},#16", "add {dst},{dst},#64",
                "subs {count},{count},#1", "b.ne 2b",
                "movi v0.2d,#0", "movi v1.2d,#0", "movi v2.2d,#0",
                tail=in(reg) shared_tail.as_ptr(),src=inout(reg) bytes.as_ptr()=>_,dst=inout(reg) next.as_mut_ptr()=>_,count=out(reg) _,out("v0") _,out("v1") _,out("v2") _,options(nostack));}
            128*16
        })!=0;
        for slot in 0..128 {
            #[cfg(target_arch = "aarch64")]
            #[allow(unused_variables)] // read only by the portable branch below
            let label = if let Some(row) = base {
                // Keep the added correlation payload inside its erased owners
                // and explicitly cleared asm temporaries across coin fills.
                // SAFETY: slot<128 indexes the initialized flattened record words and next records; base is
                // an N-element i32 array. The asm reads one source u64 and the first row i32 and writes
                // next[slot][0]. Borrowed regions are disjoint and all scratch/flag effects are declared on
                // this AArch64 path.
                unsafe {
                    core::arch::asm!(
                    "ldr {value}, [{src}]", "ldr {base:w}, [{row}]",
                    "asr {mask}, {value}, #63", "bic {base}, {base}, {mask}",
                    "orr {value}, {value}, {base}, lsl #16", "str {value}, [{dst}]",
                    "mov {value}, xzr", "mov {base}, xzr", "mov {mask}, xzr",
                    src=in(reg) records.as_flattened().as_ptr().add(slot),
                    dst=in(reg) next[slot].as_mut_ptr(),row=in(reg) row.as_ptr(),
                    value=out(reg) _,base=out(reg) _,mask=out(reg) _,options(nostack));
                }
                0u64 // selected exclusive coins do not inspect this local value
            } else {
                let label = records.as_flattened()[slot];
                next[slot][0] = label;
                label
            };
            #[allow(unused_variables)] // read only by the portable branch below
            let mask = u64::MAX; // Inactive slots use these independent coins only for dummy tests.
            if !copied_coins {
                let mut block_words = [0u64; 2];
                let mut block = crate::ct_erase::StackByteGuard::new(&mut block_words);
                rng.fill(&mut block);
                #[cfg(target_arch = "aarch64")]
                // Keep private coin bytes inside the explicit erased owners
                // and these three explicitly cleared vector registers.
                // Exclusive-slot coins make mask all-ones for every slot.
                // SAFETY: shared_tail owns 32 initialized bytes and block owns 16. next[slot] is a disjoint
                // exclusive eight-u64 record; the three 16-byte stores at offsets 8,24,40 end at byte 56
                // within its 64 bytes. The aarch64 guard supplies NEON and clobbers are declared.
                unsafe {
                    core::arch::asm!(
                    "ldp q0, q1, [{tail}]",
                    "ext v2.16b, v1.16b, v1.16b, #8",
                    "stur q2, [{dst}, #8]",
                    "ext v2.16b, v0.16b, v0.16b, #8",
                    "stur q2, [{dst}, #24]",
                    "ldr q2, [{high}]",
                    "ext v2.16b, v2.16b, v2.16b, #8",
                    "stur q2, [{dst}, #40]",
                    "movi v0.2d, #0", "movi v1.2d, #0", "movi v2.2d, #0",
                    tail=in(reg) shared_tail.as_ptr(),high=in(reg) block.as_ptr(),
                    dst=in(reg) next[slot].as_mut_ptr(),
                    out("v0") _,out("v1") _,out("v2") _,options(nostack));
                }
            }
            next[slot][7] = 0;
        }
        Self { records: &next[..] }
    }
    /// Carry initial correlations through the label routing network.
    /// Only fixed j/slot addresses are read; the routing masks are unchanged.
    pub(crate) fn new_with_base(
        c: &Challenge,
        rng: &mut Xof,
        records: &'a mut [Record; FIRST_ROWS],
        next: &'a mut [Record; SECOND_ROWS],
        base: &[i32; N],
    ) -> Self {
        Self::new_packed_coins(c, rng, records, next, Some(base))
    }
    #[cfg(test)]
    pub(crate) fn base_word(&self, slot: usize) -> &u64 {
        &self.records[slot][0]
    }
    #[cfg(test)]
    pub(crate) fn base(&self, slot: usize) -> i32 {
        (self.records[slot][0] >> 16) as u32 as i32
    }
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    #[cfg(any(test, not(target_arch = "aarch64")))]
    fn metadata(record: &Record) -> (u64, u64) {
        let index;
        let active;
        // The full label also carries a secret correlation. Expose only its
        // index and active bit to Rust, clearing the full-word temporary.
        // SAFETY: record is an initialized eight-u64 array, so its first eight bytes are readable
        // for the borrow. The AArch64 asm only reads that word and writes declared registers;
        // readonly/nostack match its effects.
        unsafe {
            core::arch::asm!(
            "ldr {value}, [{src}]", "and {index}, {value}, #255",
            "asr {active}, {value}, #63", "mov {value}, xzr",
            src=in(reg) record.as_ptr(),index=out(reg) index,active=out(reg) active,
            value=out(reg) _,options(nostack,readonly));
        }
        (index, active)
    }
    #[cfg(test)]
    pub(crate) fn get(&self, slot: usize) -> (u64, u64, Zeroizing<Fx>) {
        // slot is a PUBLIC fixed loop counter. The resulting index is secret.
        let record = &self.records[slot];
        #[cfg(target_arch = "aarch64")]
        let (index, active) = Self::metadata(record);
        let mut u = Zeroizing::new(Fx::ZERO);
        u.0[..6].copy_from_slice(&record[1..7]);
        (index, active, u)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routed_bases_preserve_every_slot_coin_and_inactive_index_zero() {
        let base: [i32; N] = core::array::from_fn(|i| {
            [i32::MIN, i32::MAX, -1, 0, 1, 0x12345678][i % 6].wrapping_add(i as i32)
        });
        for weight in 0..=128 {
            for stride in [1, 73, 255] {
                let mut c = [false; N];
                for i in 0..weight {
                    c[(i * stride) % N] = true;
                }
                let mut r0 = Xof::new(b"PRETZEL-ROUTED-BASE", &[]);
                let mut r1 = Xof::new(b"PRETZEL-ROUTED-BASE", &[]);
                let mut a0 = Box::new([[0u64; WORDS]; FIRST_ROWS]);
                let mut b0 = Box::new([[0u64; WORDS]; SECOND_ROWS]);
                let mut a1 = Box::new([[0u64; WORDS]; FIRST_ROWS]);
                let mut b1 = Box::new([[0u64; WORDS]; SECOND_ROWS]);
                let old = Positions::new(&c, &mut r0, &mut a0, &mut b0);
                let new = Positions::new_with_base(&c, &mut r1, &mut a1, &mut b1, &base);
                for slot in 0..128 {
                    let (oi, oa, ou) = old.get(slot);
                    let (ni, na, nu) = new.get(slot);
                    assert_eq!((oi, oa, *ou), (ni, na, *nu));
                    assert_eq!(new.base(slot), base[ni as usize]);
                }
                for _ in 0..16 {
                    assert_eq!(r0.u64(), r1.u64());
                }
            }
        }
    }

    #[test]
    fn exclusive_coins_preserve_profile_draws_and_partition_every_weight() {
        for w in 0..=128 {
            let mut c = [false; N];
            for i in 0..w {
                c[(i * 73) % N] = true;
            }
            let mut a = Xof::new(b"PRETZEL-EXCLUSIVE-COINS-TEST", &[]);
            let mut b = Xof::new(b"PRETZEL-EXCLUSIVE-COINS-TEST", &[]);
            let mut records = Box::new([[0u64; WORDS]; FIRST_ROWS]);
            let mut next = Box::new([[0u64; WORDS]; SECOND_ROWS]);
            let slots = Positions::new(&c, &mut b, &mut records, &mut next);
            let tail = {
                let mut t = [0u64; 4];
                for limb in (0..4).rev() {
                    t[limb] = a.u64();
                }
                t
            };
            for slot in 0..128 {
                let mut want = Fx::ZERO;
                {
                    want.0[..4].copy_from_slice(&tail);
                    want.0[5] = a.u64();
                    want.0[4] = a.u64();
                }
                let (index, active, got) = slots.get(slot);
                assert_eq!(*got, want);
                assert_eq!(active, if slot < w { u64::MAX } else { 0 });
                if slot >= w {
                    assert_eq!(index, 0);
                }
            }
            for _ in 0..16 {
                assert_eq!(a.u64(), b.u64());
            }
        }
    }
    #[test]
    fn every_folded_weight_preserves_active_order_and_profile_draws() {
        for w in 0..=128 {
            for pattern in 0..3 {
                let mut c = [false; N];
                for i in 0..w {
                    c[match pattern {
                        0 => i,
                        1 => N - 1 - i,
                        _ => (i * 73) % N,
                    }] = true;
                }
                let mut a = Xof::new(b"LILT-COMPACT-SLOTS-TEST-v1", &[]);
                let mut b = Xof::new(b"LILT-COMPACT-SLOTS-TEST-v1", &[]);
                let active_indices: Vec<_> = (0..N).filter(|&j| c[j]).collect();
                let draw_count = 128;
                let tail = {
                    let mut t = [0u64; 4];
                    for limb in (0..4).rev() {
                        t[limb] = a.u64();
                    }
                    t
                };
                let expected: Vec<_> = (0..draw_count)
                    .map(|j| {
                        let mut draw = Fx::ZERO;
                        {
                            draw.0[..4].copy_from_slice(&tail);
                            draw.0[5] = a.u64();
                            draw.0[4] = a.u64();
                        }
                        let j = active_indices.get(j).copied().unwrap_or(N);
                        (j, draw)
                    })
                    .filter(|(j, _)| *j < N && c[*j])
                    .collect();
                let mut records = Box::new([[0u64; WORDS]; FIRST_ROWS]);
                let mut next = Box::new([[0u64; WORDS]; SECOND_ROWS]);
                let actual = Positions::new(&c, &mut b, &mut records, &mut next);
                for slot in 0..128 {
                    let (j, mask, draw) = actual.get(slot);
                    if slot < w {
                        assert_eq!(j, expected[slot].0 as u64);
                        assert_eq!(*draw, expected[slot].1);
                        assert_eq!(mask, u64::MAX);
                    } else {
                        assert_eq!(mask, 0);
                    }
                }
                for _ in 0..16 {
                    assert_eq!(a.u64(), b.u64());
                }
            }
        }
    }
}

// Two adjacent labels, not two words of one full record. Only public
// pointers/counts enter GPRs; all loaded private labels stay in v0..v3.
#[cfg(all(target_arch = "aarch64", target_endian = "little"))]
#[inline(always)]
fn label_route_stage(input: &[u64], output: &mut [u64], stage: usize) {
    assert!(input.len() >= N && output.len() >= N && stage < 8);
    let stride = 1usize << stage;
    let limit = if stage == 7 { 128 } else { N };
    let both = core::cmp::min(limit, N - stride);
    let bulk = both / 2;
    let fringe = both % 2;
    let tail = limit / 2 - bulk - fringe;
    let bit = (stride as u64) << 8;
    // Both arrays are disjoint scratch owners. The stage0 fringe
    // has one valid neighbor: LDR D1 zeroes its high lane, never reads N.
    // SAFETY: The assertions provide at least N=256 words per disjoint slice and stage<8. bulk
    // handles complete two-word neighbors, fringe reads only the last valid neighbor word, and
    // tail writes only up to limit<=N. The aarch64 cfg supplies NEON and all asm clobbers are
    // declared.
    unsafe {
        core::arch::asm!(
        "dup v4.2d, {bit}",
        "cbz {bulk}, 3f", "2:",
        "ldr q0, [{src}], #16", "ldr q1, [{neighbor}], #16",
        "cmtst v2.2d, v0.2d, v4.2d", "bic v0.16b, v0.16b, v2.16b",
        "cmtst v3.2d, v1.2d, v4.2d", "and v1.16b, v1.16b, v3.16b",
        "orr v0.16b, v0.16b, v1.16b", "bic v0.16b, v0.16b, v4.16b",
        "str q0, [{dst}], #16", "subs {bulk}, {bulk}, #1", "b.ne 2b",
        "3:", "cbz {fringe}, 4f",
        "ldr q0, [{src}], #16", "ldr d1, [{neighbor}]",
        "cmtst v2.2d, v0.2d, v4.2d", "bic v0.16b, v0.16b, v2.16b",
        "cmtst v3.2d, v1.2d, v4.2d", "and v1.16b, v1.16b, v3.16b",
        "orr v0.16b, v0.16b, v1.16b", "bic v0.16b, v0.16b, v4.16b",
        "str q0, [{dst}], #16",
        "4:", "cbz {tail}, 6f", "5:",
        "ldr q0, [{src}], #16", "cmtst v2.2d, v0.2d, v4.2d",
        "bic v0.16b, v0.16b, v2.16b", "bic v0.16b, v0.16b, v4.16b",
        "str q0, [{dst}], #16", "subs {tail}, {tail}, #1", "b.ne 5b",
        "6:",
        "movi v0.2d,#0", "movi v1.2d,#0", "movi v2.2d,#0",
        "movi v3.2d,#0", "movi v4.2d,#0",
        src=inout(reg) input.as_ptr()=>_,
        neighbor=inout(reg) input.as_ptr().add(stride)=>_,
        dst=inout(reg) output.as_mut_ptr()=>_,
        bulk=inout(reg) bulk=>_,fringe=in(reg) fringe,tail=inout(reg) tail=>_,bit=in(reg) bit,
        out("v0") _,out("v1") _,out("v2") _,out("v3") _,out("v4") _,
        options(nostack));
    }
}

#[cfg(all(target_arch = "aarch64", target_endian = "little", test))]
mod label_simd_tests {
    use super::*;
    #[repr(C, align(16))]
    struct Guarded {
        pre: [u64; 2],
        data: [u64; N],
        post: [u64; 2],
    }
    fn scalar_stage(input: &[u64; N], output: &mut [u64; N], stage: usize) {
        let stride = 1usize << stage;
        let bit = (stride as u64) << 8;
        let limit = if stage == 7 { 128 } else { N };
        for j in 0..limit {
            let keep = opaque_mask(0u64.wrapping_sub(u64::from(input[j] & bit == 0)));
            let mut label = input[j] & keep;
            if j + stride < N {
                let take = opaque_mask(0u64.wrapping_sub(u64::from(input[j + stride] & bit != 0)));
                label |= input[j + stride] & take;
            }
            output[j] = label & !bit;
        }
    }
    #[test]
    fn packed_label_stages_match_scalar_payloads_and_fringe() {
        let mut cases = 0;
        for stage in 0..8 {
            for pattern in 0..132usize {
                let input = Guarded {
                    pre: [0x1367; 2],
                    data: core::array::from_fn(|i| match pattern {
                        0 => 0,
                        1 => u64::MAX,
                        2..=65 => 1u64 << (pattern - 2),
                        66..=129 => !(1u64 << (pattern - 66)),
                        130 => (i as u64)
                            .wrapping_mul(0x9e3779b97f4a7c15)
                            .rotate_left((i % 64) as u32),
                        _ => {
                            ((i as u64).wrapping_mul(0xd1342543de82ef95))
                                ^ if i % 2 == 0 { u64::MAX } else { 0 }
                        }
                    }),
                    post: [u64::MAX; 2],
                };
                let before = input.data;
                let mut output = Guarded {
                    pre: [0x3579; 2],
                    data: core::array::from_fn(|i| 0xa55a000000000000 | i as u64),
                    post: [0x468a; 2],
                };
                let mut expected = output.data;
                scalar_stage(&input.data, &mut expected, stage);
                label_route_stage(&input.data, &mut output.data, stage);
                assert_eq!(output.data, expected, "stage {stage} pattern {pattern}");
                assert_eq!(input.data, before);
                assert_eq!(input.pre, [0x1367; 2]);
                assert_eq!(input.post, [u64::MAX; 2]);
                assert_eq!(output.pre, [0x3579; 2]);
                assert_eq!(output.post, [0x468a; 2]);
                cases += 1;
            }
        }
        // A faulty two-lane neighbor load at stage0 could import this high sentinel.
        let mut x = Guarded {
            pre: [0x1234; 2],
            data: [0; N],
            post: [u64::MAX; 2],
        };
        x.data[N - 1] = 1 << 8;
        let mut y = [u64::MAX; N];
        label_route_stage(&x.data, &mut y, 0);
        assert_eq!(y[N - 1], 0);
        assert_eq!(y[N - 2], 0);
        assert_eq!(x.post, [u64::MAX; 2]);
        assert_eq!(cases, 1056);
    }
    #[test]
    fn packed_label_full_slots_match_original_coins_and_rng() {
        let base: [i32; N] = core::array::from_fn(|i| {
            [i32::MIN, i32::MAX, -1, 0, 1, 0x12345678][i % 6].wrapping_add(i as i32)
        });
        let mut cases = 0;
        for weight in 0..=128 {
            for stride in [1, 73, 255] {
                for mode in 0..2 {
                    let mut c = [false; N];
                    for i in 0..weight {
                        c[(i * stride) % N] = true;
                    }
                    let seed = [weight as u8, stride as u8, mode as u8];
                    let prefix: Vec<u8> = (0..4352)
                        .map(|i| ((i * 73 + weight * 7 + stride) % 256) as u8)
                        .collect();
                    let make = || {
                        if mode == 0 {
                            Xof::new(b"SCREENED_LABEL_SIMD-SLOTS", &[&seed])
                        } else {
                            Xof::from_scheduled(
                                crate::ct_stream_schedule::Reader::rarequeue_test_fixture(&prefix),
                            )
                        }
                    };
                    let mut r0 = make();
                    let mut r1 = make();
                    for rng in [&mut r0, &mut r1] {
                        rng.consume_attempt_prefix(|b| {
                            assert_eq!(b.len() >= 2080, mode == 1);
                            0
                        });
                    }
                    let mut a0 = Box::new([[0x123456789abcdef0u64; WORDS]; FIRST_ROWS]);
                    let mut b0 = Box::new([[0x0fedcba987654321u64; WORDS]; SECOND_ROWS]);
                    let mut a1 = a0.clone();
                    let mut b1 = b0.clone();
                    let old = Positions::label_original_packed_coins(
                        &c,
                        &mut r0,
                        &mut a0,
                        &mut b0,
                        Some(&base),
                    );
                    let new =
                        Positions::new_packed_coins(&c, &mut r1, &mut a1, &mut b1, Some(&base));
                    assert_eq!(old.records, new.records);
                    for slot in 0..128 {
                        let (oi, oa, ou) = old.get(slot);
                        let (ni, na, nu) = new.get(slot);
                        assert_eq!((oi, oa, *ou), (ni, na, *nu));
                        assert_eq!(old.base(slot), new.base(slot));
                    }
                    assert_eq!(a0, a1);
                    assert_eq!(b0, b1);
                    r0.batch_test_same_stream(&r1);
                    assert_eq!(r0.batch_test_consumed_pub(), 2080);
                    assert_eq!(r0.bytes::<256>(), r1.bytes::<256>());
                    r0.batch_test_same_stream(&r1);
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 774);
    }
}
