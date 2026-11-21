//! Fixed-address compaction of original challenge-indexed transport draws.
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

/// Slot records in a caller-owned buffer of the erased signing scratch (no
/// allocation per attempt).
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

    /// Route only position labels, then assign independent 384-bit uniforms
    /// in public slot order. Original conditional joint law, different tape map.
    #[cfg(test)]
    fn screened_label_original_packed_coins(
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
        // erased owner. The coins are therefore not independent; the paper assumes the
        // comparison with independent coins (Assumption F.1).
        let mut shared_words = [0u64; 4];
        let mut shared_tail = crate::ct_erase::StackByteGuard::new(&mut shared_words);
        rng.fill(&mut shared_tail);
        // One common low 256-bit tail, independent high 128 bits per slot.
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
            let _label = if let Some(row) = base {
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
            let _mask = u64::MAX; // Inactive slots use these independent coins only for dummy tests.
            if !copied_coins {
                let mut block_words = [0u64; 2];
                let mut block = crate::ct_erase::StackByteGuard::new(&mut block_words);
                rng.fill(&mut block);
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
        base: &[i32; N],
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
                | ((base[j] as u32 as u64) << 16))
                & mask;
            rank += active;
        }
        // Public eight-stage shift network; the final stage only needs the
        // first 128 outputs. All addresses depend on j and stride, never c.
        for stage in 0..8 {
            let (input, output) = if stage & 1 == 0 {
                (&*a, &mut *b)
            } else {
                (&*b, &mut *a)
            };
            screened_label_route_stage(input, output, stage);
        }
        // Eight stages leave labels in a; b's storage can now be reused.
        // Coins as in the paper, Appendix D.4, for the 80 positions that this parameter set
        // prepares (Appendix H.1): each has its own independent high 128 bits, and all
        // share one low 256-bit tail, kept in an erased owner. The coins are therefore
        // not independent; the paper assumes the comparison with independent coins
        // (Appendix H.1, Assumption F.3).
        let mut shared_words = [0u64; 4];
        let mut shared_tail = crate::ct_erase::StackByteGuard::new(&mut shared_words);
        rng.fill(&mut shared_tail);
        // One common low 256-bit tail, independent high 128 bits per slot.
        let copied_coins=rng.consume_attempt_prefix(|bytes|{
            if bytes.len()<80*16{return 0;}
            // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs`
            // asserts little-endian AArch64 on macOS). The check above gives `bytes` at
            // least 80 * 16 bytes; the loop runs 80 times and reads 16 bytes through `src` each
            // time. `shared_tail` views four `u64`, the 32 bytes read once through `tail`. `next`
            // has 128 records of 64 bytes, and the loop writes bytes 8 to 63 of each of the first
            // 80. The three regions are distinct borrows. Loads and stores are unaligned forms, the
            // stack is not used, and every register written is declared as an output.
            unsafe{core::arch::asm!(
                "ldp q0,q1,[{tail}]",
                "ext v0.16b,v0.16b,v0.16b,#8", "ext v1.16b,v1.16b,v1.16b,#8",
                "mov {count},#80", "2:",
                "ldr q2,[{src}]", "ext v2.16b,v2.16b,v2.16b,#8",
                "stur q1,[{dst},#8]", "stur q0,[{dst},#24]", "stur q2,[{dst},#40]",
                "str xzr,[{dst},#56]", "add {src},{src},#16", "add {dst},{dst},#64",
                "subs {count},{count},#1", "b.ne 2b",
                "movi v0.2d,#0", "movi v1.2d,#0", "movi v2.2d,#0",
                tail=in(reg) shared_tail.as_ptr(),src=inout(reg) bytes.as_ptr()=>_,dst=inout(reg) next.as_mut_ptr()=>_,count=out(reg) _,out("v0") _,out("v1") _,out("v2") _,options(nostack));}
            80*16
        })!=0;
        for slot in 0..80 {
            // Keep the added correlation payload inside its erased owners
            // and explicitly cleared asm temporaries across coin fills.
            // SAFETY: `slot < 80`. `records.as_flattened()` has `FIRST_ROWS * WORDS = 256`
            // words, so the 8-byte load at word `slot` is in bounds; `base` refers to `N = 256`
            // `i32`, of which the first is read (4 bytes); the 8-byte store goes to word 0 of
            // `next[slot]`, a checked index. Base AArch64 instructions only; the stack is not
            // used and the three scratch registers are declared as outputs.
            unsafe {
                core::arch::asm!(
                "ldr {value}, [{src}]", "ldr {base:w}, [{row}]",
                "asr {mask}, {value}, #63", "bic {base}, {base}, {mask}",
                "orr {value}, {value}, {base}, lsl #16", "str {value}, [{dst}]",
                "mov {value}, xzr", "mov {base}, xzr", "mov {mask}, xzr",
                src=in(reg) records.as_flattened().as_ptr().add(slot),
                dst=in(reg) next[slot].as_mut_ptr(),row=in(reg) base.as_ptr(),
                value=out(reg) _,base=out(reg) _,mask=out(reg) _,options(nostack));
            }
            if !copied_coins {
                let mut block_words = [0u64; 2];
                let mut block = crate::ct_erase::StackByteGuard::new(&mut block_words);
                rng.fill(&mut block);
                // Keep private coin bytes inside the explicit erased owners
                // and these three explicitly cleared vector registers.
                // Every slot has its own coins; no slot is masked.
                // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs`
                // asserts little-endian AArch64 on macOS). `shared_tail` views four `u64`
                // (32 bytes, read by the `ldp`), `block` views two (16 bytes, read by the `ldr`),
                // and the three 16-byte stores cover bytes 8 to 55 of the 64-byte record
                // `next[slot]`, a checked index. The three are distinct objects. Loads and stores
                // are unaligned forms, the stack is not used, and v0 to v2 are declared as outputs.
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
        for row in &mut next[80..] {
            row.fill(0);
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
        Self::new_packed_coins(c, rng, records, next, base)
    }
    #[cfg(test)]
    pub(crate) fn base_word(&self, slot: usize) -> &u64 {
        &self.records[slot][0]
    }
    #[cfg(test)]
    pub(crate) fn base(&self, slot: usize) -> i32 {
        (self.records[slot][0] >> 16) as u32 as i32
    }
    #[cfg(test)]
    #[inline(always)]
    fn metadata(record: &Record) -> (u64, u64) {
        let index;
        let active;
        // The full label also carries a secret correlation. Expose only its
        // index and active bit to Rust, clearing the full-word temporary.
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
        let (index, active) = Self::metadata(record);
        let mut u = Zeroizing::new(Fx::ZERO);
        u.0[..6].copy_from_slice(&record[1..7]);
        (index, active, u)
    }
}

// Two adjacent labels, not two words of one full record. Only public
// pointers/counts enter GPRs; all loaded private labels stay in v0..v3.
#[inline(always)]
fn screened_label_route_stage(input: &[u64], output: &mut [u64], stage: usize) {
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
    // SAFETY: NEON is in the baseline of every target this crate builds for (`build.rs` asserts
    // little-endian AArch64 on macOS). The assertion above gives both slices at least `N =
    // 256` words and `stage < 8`, so `stride <= 128`. The bulk loop reads words `0..2 * bulk`
    // through `src` and `stride..stride + 2 * bulk` through `neighbor`, with `stride + 2 * bulk <=
    // N` because `2 * bulk <= both <= N - stride`. The fringe step runs only for `stride == 1`,
    // where it reads words 254 and 255 through `src` and the single word 255 through `neighbor`
    // (`ldr d1`). The tail loop reads through `src` only, up to word `limit <= N`. Exactly `limit`
    // words are written through `dst`. `input` and `output` cannot overlap (a shared and an
    // exclusive borrow). The stack is not used and every register written is declared as an output.
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

#[cfg(test)]
mod screened_label_simd_tests {
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
                screened_label_route_stage(&input.data, &mut output.data, stage);
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
        screened_label_route_stage(&x.data, &mut y, 0);
        assert_eq!(y[N - 1], 0);
        assert_eq!(y[N - 2], 0);
        assert_eq!(x.post, [u64::MAX; 2]);
        assert_eq!(cases, 1056);
        println!("label routing stages: cases=1056 stages=8 payload_patterns=132 canary_bytes=64 fringe=1 suffix=128");
    }
    #[test]
    fn packed_label_full_slots_match_original_coins_and_rng() {
        let base: [i32; N] = core::array::from_fn(|i| {
            [i32::MIN, i32::MAX, -1, 0, 1, 0x12345678][i % 6].wrapping_add(i as i32)
        });
        let mut cases = 0;
        for weight in 0..=72 {
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
                    let old = Positions::screened_label_original_packed_coins(
                        &c,
                        &mut r0,
                        &mut a0,
                        &mut b0,
                        Some(&base),
                    );
                    let new = Positions::new_packed_coins(&c, &mut r1, &mut a1, &mut b1, &base);
                    assert_eq!(old.records[..80], new.records[..80]);
                    assert!(new.records[80..].iter().all(|r| r.iter().all(|&v| v == 0)));
                    for slot in 0..80 {
                        let (oi, oa, ou) = old.get(slot);
                        let (ni, na, nu) = new.get(slot);
                        assert_eq!((oi, oa, *ou), (ni, na, *nu));
                        assert_eq!(old.base(slot), new.base(slot));
                    }
                    assert_eq!(a0, a1);
                    assert_eq!(b0[..80], b1[..80]);
                    assert_eq!(r0.batch_test_consumed_pub(), 2080);
                    assert_eq!(r1.batch_test_consumed_pub(), 1312);
                    let _unused = r1.bytes::<768>();
                    r0.batch_test_same_stream(&r1);
                    assert_eq!(r0.bytes::<256>(), r1.bytes::<256>());
                    r0.batch_test_same_stream(&r1);
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 438);
        println!("label routing slots: cases=438 weights=73 patterns=3 rng_modes=2 slots=80 coin_bytes=1312 continuation=256");
    }
}
