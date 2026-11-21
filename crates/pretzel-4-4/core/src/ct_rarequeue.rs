//! Bounded lazy Gaussian sampler.
//! Six fixed fallback slots.
use crate::hashes::Xof;
use zeroize::Zeroizing;
const CAP: usize = 6;
const PREFIX_MASK: u64 = 0xffffffffff000000;
pub(crate) fn decode_counts(out: &mut [i32], stride: i32, bounds: usize, bad: u64) -> u64 {
    assert!(out.len() % 4 == 0);
    // SAFETY: `pretzel44_rq_decode` (ct_rq_decode.S) reads and writes `n` `i32` at `out`, four at a
    // time, and nothing else outside its own 512-byte stack frame, which it clears; the other
    // arguments are values. `out` is a live slice passed with its own length, asserted above to be
    // a multiple of 4 (zero is accepted). The routine uses NEON only, which is in the baseline of
    // the supported AArch64 targets.
    unsafe { pretzel44_rq_decode(out.as_mut_ptr(), out.len(), stride, bounds, bad) }
}
type Gather = unsafe extern "C" fn(*mut u64, *const u8, usize, *const u8);
type Residual = unsafe extern "C" fn(*mut u64, *const u8, usize, *const u8, *mut u64);
pub(crate) struct Parts<'a> {
    coarse: Gather,
    residual: Residual,
    cp: &'a [u8],
    rp: &'a [u8],
    k: u32,
    pairs: usize,
    bounds: usize,
}
impl<'a> Parts<'a> {
    pub(crate) fn new(
        id: u64,
        cp: &'a [u8],
        rp: &'a [u8],
        k: u32,
        pairs: usize,
        bounds: usize,
    ) -> Option<Self> {
        // The generated native scans have fixed public extents. Validate every
        // extent/shape before a safe Rust caller can reach their raw pointers.
        let expected = match id {
            257 => (400, 992, 6, 54, 155),
            258 => (6272, 10816, 10, 743, 2129),
            259 => (6864, 13648, 10, 944, 2711),
            _ => return None,
        };
        if (cp.len(), rp.len(), k, pairs, bounds) != expected {
            return None;
        }
        let (coarse, residual): (Gather, Residual) = match id {
            257 => (pretzel44_rq_coarse_lead, pretzel44_rq_residual_lead),
            258 => (pretzel44_rq_coarse_sec, pretzel44_rq_residual_sec),
            259 => (pretzel44_rq_coarse_err, pretzel44_rq_residual_err),
            _ => return None,
        };
        Some(Self {
            coarse,
            residual,
            cp,
            rp,
            k,
            pairs,
            bounds,
        })
    }
    fn indices(&self, draws: &[[u64; 4]; 16]) -> Zeroizing<[u8; 32]> {
        let mut indices = Zeroizing::new([0u8; 32]);
        for i in 0..16 {
            let c = draws[i][3] & ((1u64 << self.k) - 1);
            indices[i] = (c & 15) as u8;
            indices[i + 16] = (c >> 4) as u8;
        }
        indices
    }
    fn gather(&self, draws: &[[u64; 4]; 16], out: &mut [[u64; 2]; 16]) {
        let indices = self.indices(draws);
        // SAFETY: `self.coarse` is one of the three coarse gathers, and `Parts::new` accepts it
        // only together with a table of exactly the length it reads (400, 6272 or 6864 bytes). The
        // routine also reads the 32 bytes of `indices`, writes the 256 bytes of `out` (`[[u64; 2];
        // 16]`) and ignores the block count. It uses NEON only, saves and restores d8 to d15 on 64
        // bytes of stack and keeps no pointer. NEON is in the baseline of every target this crate
        // builds for.
        unsafe {
            (self.coarse)(
                out.as_mut_ptr().cast(),
                self.cp.as_ptr(),
                (1usize << self.k) / 16,
                indices.as_ptr(),
            );
        }
    }
    fn residual(&self, draws: &[[u64; 4]; 16], out: &mut [[u64; 2]; 16], hi: &mut [[u64; 2]; 16]) {
        let indices = self.indices(draws);
        // SAFETY: `self.residual` is one of the three residual gathers, and `Parts::new` accepts it
        // only together with a table of exactly the length it reads (992, 10816 or 13648 bytes).
        // The routine also reads the 32 bytes of `indices`, writes the 256 bytes of `out`, and
        // reads and rewrites the 256 bytes of `hi`; `out` and `hi` are distinct exclusive borrows
        // of `[[u64; 2]; 16]`. It ignores the block count, uses NEON only and keeps no pointer.
        // NEON is in the baseline of every target this crate builds for.
        unsafe {
            (self.residual)(
                out.as_mut_ptr().cast(),
                self.rp.as_ptr(),
                (1usize << self.k) / 16,
                indices.as_ptr(),
                hi.as_mut_ptr().cast(),
            );
        }
    }
}
pub(crate) fn full(parts: &Parts<'_>, draws: &[[u64; 4]; 16], out: &mut [[u64; 2]; 16]) {
    // The generic alias interface accepts arbitrary upper column bits. Native
    // queue helpers accept canonical columns, as produced by sample() below.
    let mut canonical = Zeroizing::new(*draws);
    for draw in canonical.iter_mut() {
        draw[3] &= (1u64 << parts.k) - 1;
    }
    let draws = &*canonical;
    let mut hi = Zeroizing::new([[0u64; 2]; 16]);
    let mut lo = Zeroizing::new([[0u64; 2]; 16]);
    let mut rejected = Zeroizing::new([0u64; 8]);
    parts.gather(draws, &mut hi);
    parts.residual(draws, &mut lo, &mut hi);
    // SAFETY: `pretzel44_rq_resolve` writes the 16 pairs of `out` and the first six of the eight
    // words of `rejected`. It reads the 16 rows of `draws`, the 16 pairs of `hi` and of `lo`, and
    // three words behind its last pointer, here a three-word temporary that lives until the end of
    // this statement. All are initialized arrays of exactly these shapes; the other arguments are
    // values.
    unsafe {
        pretzel44_rq_resolve(
            out.as_mut_ptr().cast(),
            rejected.as_mut_ptr(),
            draws.as_ptr().cast(),
            hi.as_ptr().cast(),
            lo.as_ptr().cast(),
            parts.k,
            parts.pairs,
            parts.bounds,
            [u64::MAX; 3].as_ptr(),
        );
    }
}
fn take_words<'a, const N: usize>(words: &mut &'a mut [u64]) -> &'a mut [u64; N] {
    let all = core::mem::take(words);
    let (first, rest) = all.split_at_mut(N);
    *words = rest;
    first.try_into().unwrap()
}
/// Reuses completed dither workspaces. Every byte remains owned by the erased
/// attempt lease. Public n is a multiple of four and at most 1024.
pub(crate) fn sample(
    parts: &Parts<'_>,
    z: &[u64; 3],
    rng: &mut Xof,
    out: &mut [i32],
    records: &mut [u32; crate::scratch::RECORD_WORDS],
    work: &mut [u32; 2048],
) -> u64 {
    assert!(out.len() <= 1024 && out.len() % 4 == 0);
    let expected_z = match parts.pairs {
        54 => [0x86f4393b022e8630, 0x620f23bee3d768f2, 0xe4abf9f55b110217],
        743 => [0xe75986ae4ce20a9c, 0x15d0cf9062038f57, 0x3eddac8009d40396],
        944 => [0x9338f89d76be63d7, 0xb0cab2a1b2bc727d, 0x568d10ae91e40248],
        _ => unreachable!("validated public table shape"),
    };
    assert_eq!(
        *z, expected_z,
        "rare queue requires the certified public normalizer"
    );
    let(_,mut words,_)=
 // SAFETY: work is an exclusively borrowed initialized [u32; 2048]. align_to_mut chooses the
 // aligned u64 middle region; integer types have no invalid bit patterns or element padding,
 // and the returned borrows are disjoint.
 unsafe{work.align_to_mut::<u64>()};
    let draws=
 // SAFETY: take_words::<64> splits off 64 initialized aligned u64 values from the exclusive
 // work view. [[u64; 4]; 16] has that exact size/alignment with no padding; split_at_mut
 // keeps this region disjoint from subsequent scratch views.
 unsafe{&mut *take_words::<64>(&mut words).as_mut_ptr().cast::<[[u64;4];16]>()};
    let queue=
 // SAFETY: take_words::<64> splits off 64 initialized aligned u64 values from the exclusive
 // work view. [[u64; 4]; 16] has that exact size/alignment with no padding; split_at_mut
 // keeps this region disjoint from subsequent scratch views.
 unsafe{&mut *take_words::<64>(&mut words).as_mut_ptr().cast::<[[u64;4];16]>()};
    let hi=
 // SAFETY: take_words::<32> splits off 32 initialized aligned u64 values from the exclusive
 // work view. [[u64; 2]; 16] has that exact size/alignment with no padding; split_at_mut
 // keeps this region disjoint from subsequent scratch views.
 unsafe{&mut *take_words::<32>(&mut words).as_mut_ptr().cast::<[[u64;2];16]>()};
    let lo=
 // SAFETY: take_words::<32> splits off 32 initialized aligned u64 values from the exclusive
 // work view. [[u64; 2]; 16] has that exact size/alignment with no padding; split_at_mut
 // keeps this region disjoint from subsequent scratch views.
 unsafe{&mut *take_words::<32>(&mut words).as_mut_ptr().cast::<[[u64;2];16]>()};
    let resolved=
 // SAFETY: take_words::<32> splits off 32 initialized aligned u64 values from the exclusive
 // work view. [[u64; 2]; 16] has that exact size/alignment with no padding; split_at_mut
 // keeps this region disjoint from subsequent scratch views.
 unsafe{&mut *take_words::<32>(&mut words).as_mut_ptr().cast::<[[u64;2];16]>()};
    let reject = take_words::<8>(&mut words);
    let aux = take_words::<24>(&mut words);
    let (records, rank) = records.split_at_mut(crate::scratch::RECORD_RANK);
    rank[0] = 0;
    queue.fill([0; 4]);
    let n = out.len();
    let total = n + CAP;
    let (range, threshold) = {
        let m = ((z[0] >> 24) + 1) << (parts.k + 11);
        (m, m.wrapping_neg() % m)
    };
    for offset in (0..total).step_by(16) {
        let count = (total - offset).min(16);
        draws.fill([0; 4]);
        let mut done = 0;
        rng.consume_attempt_prefix(|bytes| {
            let mut used = 0;
            while done < count && used + 8 <= bytes.len() {
                let w = u64::from_le_bytes(bytes[used..used + 8].try_into().unwrap());
                used += 8;
                {
                    let product = w as u128 * range as u128;
                    let a = (product >> 64) as u64;
                    if product as u64 >= threshold {
                        draws[done][0] = (a >> (parts.k + 11)) << 24;
                        draws[done][2] = (a >> parts.k) & 2047;
                        draws[done][3] = a & ((1u64 << parts.k) - 1);
                        done += 1;
                    }
                }
            }
            used
        });
        while done < count {
            rng.fill(
                // SAFETY: aux is a mutable u64 scratch slice with at least one word from take_words; the
                // eight-byte view stays within its initialized storage, and all byte writes leave valid
                // integers.
                unsafe { core::slice::from_raw_parts_mut(aux.as_mut_ptr().cast::<u8>(), 8) },
            );
            let w = aux[0];
            {
                let product = w as u128 * range as u128;
                let a = (product >> 64) as u64;
                if product as u64 >= threshold {
                    draws[done][0] = (a >> (parts.k + 11)) << 24;
                    draws[done][2] = (a >> parts.k) & 2047;
                    draws[done][3] = a & ((1u64 << parts.k) - 1);
                    done += 1;
                }
            }
        }
        parts.gather(draws, hi);
        // SAFETY: `pretzel44_rq_common` reads the 16 rows of `draws` and the 16 pairs of `hi`,
        // reads and updates rows 0 to 5 of `queue` and the first word of `rank` (which has
        // `RECORD_WORDS - RECORD_RANK = 2` words), and writes `count` words at `records + offset`.
        // `count <= 16`, the bound its 16-entry stack arrays need, and `offset + count <= n + CAP
        // <= 1030` because `n <= 1024` is asserted above, inside the `RECORD_RANK = 1032` words of
        // `records`. The scratch views are disjoint (`take_words` and `split_at_mut`).
        unsafe {
            pretzel44_rq_common(
                queue.as_mut_ptr().cast(),
                records.as_mut_ptr().add(offset),
                rank.as_mut_ptr(),
                draws.as_ptr().cast(),
                hi.as_ptr().cast(),
                parts.k,
                parts.pairs,
                parts.bounds,
                z[0] & PREFIX_MASK,
                count,
            );
        }
    }
    // Fixed amount of completion entropy, even when no proposal is rare.
    rng.fill(
        // SAFETY: aux is the 24 u64 words (192 bytes) taken by take_words::<24> above. The u8 view
        // covers its first 24*CAP bytes, which is 144 with CAP = 6 and must stay at most 192. It
        // preserves the exclusive borrow, and all byte patterns remain valid u64 values.
        unsafe { core::slice::from_raw_parts_mut(aux.as_mut_ptr().cast::<u8>(), 24 * CAP) },
    );
    for i in 0..CAP {
        queue[i][0] |= aux[3 * i] & 0xffffff;
        queue[i][1] = aux[3 * i + 1];
        queue[i][2] |= aux[3 * i + 2] << 11;
    }
    parts.gather(queue, hi);
    parts.residual(queue, lo, hi);
    // SAFETY: `pretzel44_rq_resolve` writes the 16 pairs of `resolved` and the first six of the
    // eight words of `reject`. It reads the 16 rows of `queue`, the 16 pairs of `hi` and of `lo`,
    // and the three words of `z`. The scratch views are disjoint (`take_words`).
    unsafe {
        pretzel44_rq_resolve(
            resolved.as_mut_ptr().cast(),
            reject.as_mut_ptr(),
            queue.as_ptr().cast(),
            hi.as_ptr().cast(),
            lo.as_ptr().cast(),
            parts.k,
            parts.pairs,
            parts.bounds,
            z.as_ptr(),
        );
    }
    records[total] = 0;
    records[total + 1] = 0;
    // SAFETY: `n` is a multiple of 4 and at most 1024 (asserted above). `pretzel44_rq_repair` then
    // reads and rewrites the first `n + 8 <= 1032 = RECORD_RANK` words of `records`, writes `n`
    // words to `out` (`n` `i32` viewed as `u32`, same size and alignment), and reads rows 0 to 5 of
    // `resolved` and the first six words of `reject`.
    unsafe {
        pretzel44_rq_repair(
            out.as_mut_ptr().cast(),
            records.as_mut_ptr(),
            resolved.as_ptr().cast(),
            reject.as_ptr(),
            n,
            rank[0],
        )
    }
}
// SAFETY: contract of the routines declared here, all rank-four assembly of this crate. None of
// them keeps a pointer or has global state; all use base AArch64 and NEON instructions only.
// `pretzel44_rq_decode` (`ct_rq_decode.S`) reads and writes `n` `i32` at `out`, four at a time, so
// `n` must be a multiple of 4; it clears a 512-byte stack frame of its own. The three coarse
// gathers (`ct_rq_coarse_*.S`) are straight-line code: each reads 32 bytes at `indices`, reads its
// table front to back (400 bytes for `lead`, 6272 for `sec`, 6864 for `err`), writes 256 bytes at
// `out` and ignores `blocks`. The three residual gathers (`ct_rq_residual_*.S`) do the same with
// tables of 992, 10816 and 13648 bytes, and also read and rewrite 256 bytes at `hi`. The three
// helpers (`ct_rq_helpers_mac.S`) are edited compiler output and that file is their source;
// `generators/helpers.c` is an earlier C form that does not reproduce it (capacity 3 where the
// assembly has 6). `pretzel44_rq_common` reads 16 rows of four `u64` at `draws` and 16
// pairs at `hi`, reads and updates rows 0 to 5 of `queue` and one `u32` at `rank`, and writes `len`
// `u32` at `records`; `len` must be at most 16. `pretzel44_rq_resolve` writes 16 pairs of `u64` at
// `out` and six `u64` at `reject`, and reads 16 rows of four at `draws`, 16 pairs at each of `hi`
// and `lo`, and three `u64` at `z`. `pretzel44_rq_repair`, for `n` a multiple of 4, reads and
// rewrites `n + 8` `u32` at `records`, writes `n` `u32` at `out`, and reads rows 0 to 5 of
// `resolved` and six `u64` at `reject`.
unsafe extern "C" {
    fn pretzel44_rq_decode(out: *mut i32, n: usize, stride: i32, bounds: usize, bad: u64) -> u64;
    fn pretzel44_rq_common(
        queue: *mut u64,
        records: *mut u32,
        rank: *mut u32,
        draws: *const u64,
        hi: *const u64,
        k: u32,
        pairs: usize,
        bounds: usize,
        h: u64,
        len: usize,
    );
    fn pretzel44_rq_resolve(
        out: *mut u64,
        reject: *mut u64,
        draws: *const u64,
        hi: *const u64,
        lo: *const u64,
        k: u32,
        pairs: usize,
        bounds: usize,
        z: *const u64,
    );
    pub(crate) fn pretzel44_rq_repair(
        out: *mut u32,
        records: *mut u32,
        resolved: *const u64,
        reject: *const u64,
        n: usize,
        rank: u32,
    ) -> u64;
    fn pretzel44_rq_coarse_lead(out: *mut u64, table: *const u8, blocks: usize, indices: *const u8);
    fn pretzel44_rq_coarse_sec(out: *mut u64, table: *const u8, blocks: usize, indices: *const u8);
    fn pretzel44_rq_coarse_err(out: *mut u64, table: *const u8, blocks: usize, indices: *const u8);
    fn pretzel44_rq_residual_lead(
        out: *mut u64,
        table: *const u8,
        blocks: usize,
        indices: *const u8,
        hi: *mut u64,
    );
    fn pretzel44_rq_residual_sec(
        out: *mut u64,
        table: *const u8,
        blocks: usize,
        indices: *const u8,
        hi: *mut u64,
    );
    fn pretzel44_rq_residual_err(
        out: *mut u64,
        table: *const u8,
        blocks: usize,
        indices: *const u8,
        hi: *mut u64,
    );
}
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_rq_decode\n.p2align 2\n_pretzel44_rq_decode:\n",
        include_str!("ct_rq_decode.S")
    ),
    options(raw)
);
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    ".set PRETZEL_NATIVE_SET, 44",
    include_str!("ct_rq_helpers_mac.S"),
    options(raw)
);
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_rq_coarse_lead\n.p2align 2\n_pretzel44_rq_coarse_lead:\n",
        include_str!("ct_rq_coarse_lead.S")
    ),
    options(raw)
);
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_rq_coarse_sec\n.p2align 2\n_pretzel44_rq_coarse_sec:\n",
        include_str!("ct_rq_coarse_sec.S")
    ),
    options(raw)
);
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_rq_coarse_err\n.p2align 2\n_pretzel44_rq_coarse_err:\n",
        include_str!("ct_rq_coarse_err.S")
    ),
    options(raw)
);
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_rq_residual_lead\n.p2align 2\n_pretzel44_rq_residual_lead:\n",
        include_str!("ct_rq_residual_lead.S")
    ),
    options(raw)
);
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_rq_residual_sec\n.p2align 2\n_pretzel44_rq_residual_sec:\n",
        include_str!("ct_rq_residual_sec.S")
    ),
    options(raw)
);
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_rq_residual_err\n.p2align 2\n_pretzel44_rq_residual_err:\n",
        include_str!("ct_rq_residual_err.S")
    ),
    options(raw)
);

#[cfg(test)]
include!("ct_rarequeue_tests.rs");

// The assembly wrapper calls the Rust body and, after the body returns, zeroes
// 2048 bytes of stack below its own frame. Measured in one release image of a
// downstream program (rustc 1.90.0, Apple clang 17.0.0, release profile):
// the frame of the body is 544 bytes, and the deepest chain of callees that do
// not erase their own frames, `Xof::fill` (400 bytes, two copies of a squeezed
// block) and `keccak_p` (192 bytes, spilled state lanes), reaches 1136 bytes
// below the wrapper's frame.
// The wipe covers that reach with 912 bytes to spare. Another compiler, profile
// or downstream program can change these figures, and nothing in this repository
// checks them; `ct_rq_wrapper_mac.S` lists the figures of both parameter sets.
#[inline(always)]
pub(crate) fn sample_erased(
    cdt: &crate::gauss::Cdt,
    rng: &mut Xof,
    out: &mut [i32],
    records: &mut [u32; crate::scratch::RECORD_WORDS],
    work: &mut [u32; 2048],
) -> u64 {
    // SAFETY: the wrapper passes its six arguments unchanged to `pretzel44_rq_sample_body`, defined
    // below, and accesses none of their targets itself. They come from live references: `cdt`
    // shared, `rng`, `records` and `work` exclusive and distinct, and `out` with its own length.
    // That is the contract of the body.
    unsafe { pretzel44_rq_sample_wrapper(cdt, rng, out.as_mut_ptr(), out.len(), records, work) }
}
#[unsafe(no_mangle)]
#[inline(never)]
/// # Safety
/// cdt must point to a live Cdt; rng to an exclusively accessible initialized Xof; out to n
/// initialized writable i32 values; records and work to initialized writable scratch arrays
/// of their declared sizes. Mutable regions must be disjoint and correctly aligned.
unsafe extern "C" fn pretzel44_rq_sample_body(
    cdt: *const crate::gauss::Cdt,
    rng: *mut Xof,
    out: *mut i32,
    n: usize,
    records: *mut [u32; crate::scratch::RECORD_WORDS],
    work: *mut [u32; 2048],
) -> u64 {
    // SAFETY: The assembly wrapper forwards the Rust sample arguments unchanged. The caller
    // provides live, aligned pointees and disjoint exclusive scratch/output regions; these are
    // the extents used to reconstruct references and the output slice.
    unsafe {
        (&*cdt).sample_rare_body(
            &mut *rng,
            core::slice::from_raw_parts_mut(out, n),
            &mut *records,
            &mut *work,
        )
    }
}
// The wrapper hands both pointers to pretzel44_rq_sample_body unchanged and never reads their targets.
// SAFETY: contract of the assembly wrapper (`ct_rq_wrapper_*.S`). It pushes a frame record, calls
// `pretzel44_rq_sample_body` with the six arguments unchanged, then stores zero over 2048 bytes of
// stack below its frame, clears caller-saved registers and the flags, and returns the body's
// result. It accesses none of the pointer targets itself and keeps no pointer. Base AArch64 and
// NEON instructions only.
#[allow(improper_ctypes)]
unsafe extern "C" {
    fn pretzel44_rq_sample_wrapper(
        cdt: *const crate::gauss::Cdt,
        rng: *mut Xof,
        out: *mut i32,
        n: usize,
        records: *mut [u32; crate::scratch::RECORD_WORDS],
        work: *mut [u32; 2048],
    ) -> u64;
}
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(
    ".set PRETZEL_NATIVE_SET, 44",
    include_str!("ct_rq_wrapper_mac.S"),
    options(raw)
);

#[cfg(all(target_arch = "aarch64", test))]
mod full_output_tests {
    #[test]
    fn every_leading_count_and_abort_flag_obeys_full_output_bound() {
        for bad in [0u64, u64::MAX] {
            let mut counts: Vec<i32> = (0..4096u32)
                .chain([u32::MAX, 0x80000000, 155, 154])
                .map(|x| x as i32)
                .collect();
            let original = counts.clone();
            assert_eq!(super::decode_counts(&mut counts, 2, 155, bad), bad);
            for (&raw, &value) in original.iter().zip(&counts) {
                let i = raw as u32;
                let expected = if i < 155 {
                    ((i + 1) / 2) as i32 * 2 * if i & 1 == 1 { 1 } else { -1 }
                } else {
                    0
                };
                assert_eq!(value, expected);
                assert!(value.unsigned_abs() <= 154);
            }
        }
    }
}
