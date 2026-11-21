//! Fixed-address compaction of original challenge-indexed transport draws.
use crate::{
    challenge::{weight, Challenge},
    ct::opaque_mask,
    params::N,
};

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
    pub(crate) fn record_slice(&self) -> &[Record] {
        self.records
    }

    // Keep the explicit lane order and index schedule of the kernel and its oracle.
    #[allow(clippy::needless_range_loop)]
    pub(crate) fn new_iid384_with_fill(
        c: &Challenge,
        mut fill: impl FnMut(&mut [u8]),
        records: &'a mut [Record; FIRST_ROWS],
        next: &'a mut [Record; SECOND_ROWS],
        base: Option<&[i32; N]>,
    ) -> Self {
        const _: () = {
            assert!(WORDS == 8);
            assert!(N == 256);
            assert!(SECOND_ROWS == 128);
        };
        assert!(weight(c) <= 128);
        let a = &mut records.as_flattened_mut()[..N];
        let b = &mut next.as_flattened_mut()[..N];
        let mut rank = 0u64;
        for j in 0..N {
            let active = u64::from(c[j]);
            // This binding is consumed only by an alternate selector.
            #[allow(unused_variables)]
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
            // This binding is consumed only by an alternate selector.
            #[allow(unused_variables)]
            let bit = (stride as u64) << 8;
            let (input, output) = if stage & 1 == 0 {
                (&*a, &mut *b)
            } else {
                (&*b, &mut *a)
            };
            // This binding is consumed only by an alternate selector.
            #[allow(unused_variables)]
            let limit = if stage == 7 { 128 } else { N };
            #[cfg(target_endian = "little")]
            label_route_stage(input, output, stage);
        }
        // Labels remain in records; fill directly into their owner.
        // No second 8192-byte record array and no persistent entropy copy.
        for slot in 0..128 {
            // This binding is consumed only by an alternate selector.
            #[allow(unused_variables)]
            let mut label = records.as_flattened()[slot];
            let inactive = opaque_mask((label >> 63).wrapping_sub(1));
            label |= ((base.map_or(0, |row| row[0]) as u32 as u64) << 16) & inactive;
            next[slot][0] = label;
            let ptr = next[slot][1..7].as_mut_ptr().cast::<u8>();
            // Six initialized contiguous u64 words have no intervening padding.
            // SAFETY: The checked [1..7] subslice supplies six initialized contiguous u64 values,
            // exactly 48 bytes. u8 needs only byte alignment and accepts every bit pattern; the
            // exclusive byte reborrow lasts only for fill.
            fill(unsafe { core::slice::from_raw_parts_mut(ptr, 48) });
            for limb in 1..7 {
                next[slot][limb] = u64::from_le(next[slot][limb]);
            }
            next[slot][7] = 0;
        }
        Self { records: &next[..] }
    }
}

// Two adjacent labels, not two words of one full record. Only public
// pointers/counts enter GPRs; all loaded private labels stay in v0..v3.
#[cfg(target_endian = "little")]
#[inline(always)]
fn label_route_stage(input: &[u64], output: &mut [u64], stage: usize) {
    assert!(input.len() >= N && output.len() >= N && stage < 8);
    let stride = 1usize << stage;
    // This binding is consumed only by an alternate selector.
    #[allow(unused_variables)]
    let limit = if stage == 7 { 128 } else { N };
    let both = core::cmp::min(limit, N - stride);
    let bulk = both / 2;
    let fringe = both % 2;
    let tail = limit / 2 - bulk - fringe;
    // This binding is consumed only by an alternate selector.
    #[allow(unused_variables)]
    let bit = (stride as u64) << 8;
    // Both arrays are disjoint scratch owners. The stage0 fringe
    // has one valid neighbor: LDR D1 zeroes its high lane, never reads N.
    // SAFETY: The AArch64/little-endian cfg selects NEON. Assertions give input/output lengths>=N=256
    // and stage<8. stride=1<<stage and limit in {128,256} bound every pair; the lone fringe uses an
    // eight-byte neighbor load. Output is exclusive and disjoint, and every modified register/flag is
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

#[cfg(all(test, target_endian = "little"))]
mod label_route_tests {
    use super::*;
    #[repr(C, align(16))]
    struct Guarded {
        pre: [u64; 2],
        data: [u64; N],
        post: [u64; 2],
    }
    fn scalar_stage(input: &[u64; N], output: &mut [u64; N], stage: usize) {
        let stride = 1usize << stage;
        // This binding is consumed only by an alternate selector.
        #[allow(unused_variables)]
        let bit = (stride as u64) << 8;
        // This binding is consumed only by an alternate selector.
        #[allow(unused_variables)]
        let limit = if stage == 7 { 128 } else { N };
        for j in 0..limit {
            let keep = opaque_mask(0u64.wrapping_sub(u64::from(input[j] & bit == 0)));
            // This binding is consumed only by an alternate selector.
            #[allow(unused_variables)]
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
}
