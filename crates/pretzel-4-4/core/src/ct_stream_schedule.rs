//! Fixed public pairing of the six attempt SHAKE streams.
//! Each prefix and continuation state belongs to its named stream. Nothing
//! survives an attempt except the immutable per-key absorption prefixes.
use crate::ct_erase::{ErasedWords, Words};
use crate::hashes::Xof;
use crate::params::*;
use crate::shake2::Sponge;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const RATE: usize = 136;

pub(crate) const STREAMS: usize = 6;

// Dyadic Gaussian and 64-bit transport draws have exact public byte counts.
// Unused salt blocks balance an odd total or a dominant stream. This is
// still the same salt stream, and its unused suffix is erased.

const BLOCKS: [usize; STREAMS] = {
    let mut blocks = [1, 96, 237, 384, 91, 46];
    {
        blocks[1] = 70;
        blocks[2] = 216;
        blocks[3] = 280;
    }
    {
        blocks[1] = 53;
        blocks[2] = 206;
        blocks[3] = 206;
    }
    {
        blocks[4] = 46;
    }
    {
        blocks[5] = 0;
    }
    {
        blocks[1] = 28;
        blocks[2] = 74;
        blocks[3] = 116;
    }
    {
        blocks[1] = 17;
        blocks[2] = 65;
        blocks[3] = 66;
    }
    {
        blocks[2] = 20;
        blocks[3] = 20;
    }
    {
        blocks[4] = (32usize + 128 * 16).div_ceil(RATE);
    }
    let mut total = 0;
    let mut largest = 0;
    let mut i = 0;
    while i < STREAMS {
        total += blocks[i];
        if blocks[i] > largest {
            largest = blocks[i];
        }
        i += 1;
    }
    blocks[0] += if 2 * largest > total {
        2 * largest - total
    } else {
        total & 1
    };
    blocks
};
const DOMAINS: [&[u8]; 6] = [
    DOM_SALT,
    DOM_MASK_LEAD,
    DOM_MASK_SEC,
    DOM_MASK_ERR,
    DOM_TRANSPORT,
    DOM_DUMMY,
];
// (first stream, second stream, blocks, first offset, second offset).
// The segments are (0, 3, 1), (2, 3, 19), (1, 4, 16) and (1, 2, 1) in streams
// and blocks: the error stream (3) is always the second lane, and stream 2 is
// the first lane of the second segment and the second lane of the last. The
// salt block is generated first, beside the first error block.

// Compile-time pairing of public stream lengths. After the salt block, pair
// the two largest remaining streams while preserving max <= total/2.
// Each positive segment either empties a stream or makes a third stream
// exactly half the remaining total; that stream empties on the next segment.
// Thus 32 slots suffice for six streams; zero suffix slots are skipped.

const SCHEDULE: [(usize, usize, usize, usize, usize); 32] = {
    let mut schedule = [(0, 0, 0, 0, 0); 32];
    schedule[0] = (0, 3, 1, 0, 0);
    let mut used = [0; STREAMS];
    used[0] = 1;
    used[3] = 1;
    let mut total = 0;
    let mut i = 0;
    while i < STREAMS {
        total += BLOCKS[i] - used[i];
        i += 1;
    }
    assert!(total % 2 == 0);
    let mut index = 1;
    while total > 0 {
        let mut a = 0;
        let mut i = 1;
        while i < STREAMS {
            if BLOCKS[i] - used[i] > BLOCKS[a] - used[a] {
                a = i;
            }
            i += 1;
        }
        let mut b = if a == 0 { 1 } else { 0 };
        let mut i = 0;
        while i < STREAMS {
            if i != a && BLOCKS[i] - used[i] > BLOCKS[b] - used[b] {
                b = i;
            }
            i += 1;
        }
        assert!(BLOCKS[a] - used[a] <= total / 2);
        let mut third = 0;
        let mut i = 0;
        while i < STREAMS {
            if i != a && i != b && BLOCKS[i] - used[i] > third {
                third = BLOCKS[i] - used[i];
            }
            i += 1;
        }
        let cap = total / 2 - third;
        let count = if BLOCKS[b] - used[b] < cap {
            BLOCKS[b] - used[b]
        } else {
            cap
        };
        assert!(count > 0 && index < schedule.len());
        if a > b {
            let t = a;
            a = b;
            b = t;
        }
        schedule[index] = (a, b, count, used[a], used[b]);
        used[a] += count;
        used[b] += count;
        total -= 2 * count;
        index += 1;
    }
    schedule
};
const _: () = assert!(SCHEDULE[0].0 == 0 && SCHEDULE[0].2 == 1 && SCHEDULE[0].3 == 0);
const _: () = {
    let mut i = 0;
    let mut used = [0; STREAMS];
    while i < SCHEDULE.len() {
        let (a, b, count, start_a, start_b) = SCHEDULE[i];
        if count == 0 {
            i += 1;
            continue;
        }
        assert!(a < b && count > 0 && start_a + count <= BLOCKS[a] && start_b + count <= BLOCKS[b]);
        assert!(start_a == used[a] && start_b == used[b]);
        used[a] += count;
        used[b] += count;
        i += 1;
    }
    let mut i = 0;
    while i < STREAMS {
        assert!(used[i] == BLOCKS[i]);
        i += 1;
    }
};

// Round constants of Keccak-f[1600], as given in FIPS 202, Section 3.2.5.
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(concat!(
    ".text\n.arch armv8.4-a+sha3\n.globl _pretzel44_ct_shake_segment\n.p2align 2\n_pretzel44_ct_shake_segment:\n",
    include_str!("ct_stream_schedule.S")), options(raw));
// SAFETY: contract of the assembly routine defined just above (ct_stream_schedule.S). It reads and
// writes exactly 50 words at `pair`, reads 24 words at `rc` (the pointer is reset for every block)
// and, for each of `blocks` blocks, writes 136 bytes at `first` and 136 bytes at `second`. `blocks`
// must be at least 1. It uses the SHA-3 instructions, assembled under `.arch armv8.4-a+sha3`, so
// the caller must have checked FEAT_SHA3 at run time. It saves and restores d8 to d15 in a 64-byte
// frame that it clears, needs no alignment, keeps no pointer and has no global state.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn pretzel44_ct_shake_segment(
        pair: *mut u64,
        rc: *const u64,
        first: *mut u8,
        second: *mut u8,
        blocks: usize,
    );
}

// The slice lengths, segment identities and CPU feature are public. The
// slices have distinct ownership and cannot alias the initialized pair.
fn segment(pair: &mut [u64; 50], first: &mut [u8], second: &mut [u8]) {
    assert_eq!(first.len(), second.len());
    assert_eq!(first.len() % RATE, 0);
    assert!(!first.is_empty());
    #[cfg(target_arch = "aarch64")]
    if crate::shake2::available() {
        // SAFETY: The assertions require equal, nonempty output lengths divisible by RATE=136.
        // available() checks SHA3; pair has 50 initialized u64 words and RC 24 constants.
        // ct_stream_schedule.S writes first.len()/RATE complete blocks to disjoint exclusive
        // outputs.
        unsafe {
            pretzel44_ct_shake_segment(
                pair.as_mut_ptr(),
                RC.as_ptr(),
                first.as_mut_ptr(),
                second.as_mut_ptr(),
                first.len() / RATE,
            );
        }
        return;
    }
    segment_scalar(pair, first, second);
}

fn segment_scalar(pair: &mut [u64; 50], first: &mut [u8], second: &mut [u8]) {
    for (a, b) in first
        .chunks_exact_mut(RATE)
        .zip(second.chunks_exact_mut(RATE))
    {
        for (lane, output) in [a, b].into_iter().enumerate() {
            let mut state = Zeroizing::new(core::array::from_fn(|i| pair[2 * i + lane]));
            // Explicit portable oracle, independent of the paired round code.
            keccak::keccak_p(&mut state, 24);
            for (i, word) in output.chunks_exact_mut(8).enumerate() {
                word.copy_from_slice(&state[i].to_le_bytes());
            }
            for i in 0..25 {
                pair[2 * i + lane] = state[i];
            }
        }
    }
}

/// Six secret-keyed tape prefixes.
pub(crate) struct Prefixes([Sponge; STREAMS]);
impl Prefixes {
    pub(crate) fn new(key: &[u8; 32], pk: &[u8]) -> Self {
        let tape = |domain: &[u8]| {
            let mut s = Sponge::new();
            s.absorb(domain);
            for part in [PROFILE_ID, crate::randomness::CT_TAPE_DOMAIN, &key[..], pk] {
                s.part(part);
            }
            s
        };
        Self([
            tape(DOMAINS[0]),
            tape(DOMAINS[1]),
            tape(DOMAINS[2]),
            tape(DOMAINS[3]),
            tape(DOMAINS[4]),
            tape(DOMAINS[5]),
        ])
    }

    pub(crate) fn expand(
        &self,
        mu: &[u8; 64],
        retry: &[u8; 4],
        entropy: &[u8; 32],
    ) -> [Xof; STREAMS] {
        self.readers(mu, retry, entropy, segment)
            .map(Xof::from_scheduled)
    }

    /// `expand` with the six prefixes written into storage taken from the
    /// signing scratch pool (allocated once per signing call, erased and
    /// returned by `AttemptRandomness::recycle`). Same bytes as `expand`.
    pub(crate) fn expand_pooled(
        &self,
        mu: &[u8; 64],
        retry: &[u8; 4],
        entropy: &[u8; 32],
        pool: &mut PrefixPool,
    ) -> [Xof; STREAMS] {
        let storage = core::array::from_fn(|i| pool.take(i));
        self.readers_in(mu, retry, entropy, segment, storage)
            .map(Xof::from_scheduled)
    }

    fn readers(
        &self,
        mu: &[u8; 64],
        retry: &[u8; 4],
        entropy: &[u8; 32],
        generate: fn(&mut [u64; 50], &mut [u8], &mut [u8]),
    ) -> [Reader; STREAMS] {
        self.readers_in(mu, retry, entropy, generate, BLOCKS.map(Words::new))
    }

    fn readers_in(
        &self,
        mu: &[u8; 64],
        retry: &[u8; 4],
        entropy: &[u8; 32],
        generate: fn(&mut [u64; 50], &mut [u8], &mut [u8]),
        storage: [Words<ROW>; STREAMS],
    ) -> [Reader; STREAMS] {
        let mut states = self.0.clone();
        let mut pair = Zeroizing::new([0u64; 50]);
        finalize_tape_suffix(&mut states[..6], mu, retry, entropy, &mut pair);
        let mut readers = storage.map(Reader::with_prefix);
        for i in 0..STREAMS {
            assert_eq!(readers[i].prefix.len(), BLOCKS[i]);
        }

        for (_index, (a, b, count, start_a, start_b)) in SCHEDULE.into_iter().enumerate() {
            if count == 0 {
                continue;
            }
            // All deployed pairs have a < b (checked on the constant schedule
            // where it is defined). split_at_mut proves disjointness.
            debug_assert!(a < b);
            for j in 0..25 {
                pair[2 * j] = states[a].state[j];
                pair[2 * j + 1] = states[b].state[j];
            }
            let (left, right) = readers.split_at_mut(b);
            let first = &mut left[a].prefix_bytes_mut()[start_a * RATE..(start_a + count) * RATE];
            let second = &mut right[0].prefix_bytes_mut()[start_b * RATE..(start_b + count) * RATE];
            generate(&mut pair, first, second);
            for j in 0..25 {
                states[a].state[j] = pair[2 * j];
                states[b].state[j] = pair[2 * j + 1];
            }
        }
        for i in 0..STREAMS {
            readers[i].state.copy_from_slice(&*states[i].state);
        }
        readers
    }
}

/// Prefix storage of the active streams, owned by the signing scratch: six
/// allocations per signing call instead of per attempt. Storage handed to a
/// reader comes back through `recycle` erased (wide word path); after an
/// unwinding attempt the reader's destructor erased and freed it, and the
/// next `take` allocates a fresh owner.
pub(crate) struct PrefixPool([ErasedWords<ROW>; STREAMS]);
impl PrefixPool {
    pub(crate) fn new() -> Self {
        Self(BLOCKS.map(ErasedWords::new))
    }
    fn take(&mut self, i: usize) -> Words<ROW> {
        let w = core::mem::replace(&mut self.0[i], ErasedWords::empty());
        if w.len() == BLOCKS[i] {
            w.into_words()
        } else {
            Words::new(BLOCKS[i])
        }
    }
    pub(crate) fn recycle(&mut self, i: usize, w: Words<ROW>) {
        let w = w.into_erased();
        if w.len() == BLOCKS[i] {
            self.0[i] = w;
        }
    }
    // Every resident owner is already erased across its whole capacity.
    // A writable prefix is exclusively held by a Words owner outside pool.
    pub(crate) fn erase(&mut self) {}
    #[cfg(test)]
    pub(crate) fn is_erased(&self) -> bool {
        self.0
            .iter()
            .all(|w| w.iter().all(|row| row.iter().all(|&x| x == 0)))
    }
}

// One rate block per word row. Word storage makes the erasure a wide
// fixed-count store loop (`ct_erase_words`) instead of one volatile byte
// store per tape byte; the bytes of every row are the little-endian rate
// bytes exactly as before, so the byte view below is the same prefix.
const ROW: usize = RATE / 8;
const _: () = assert!(ROW * 8 == RATE);

#[derive(Clone)]
pub(crate) struct Reader {
    prefix: Words<ROW>,
    state: [u64; 25],
    cursor: usize,
    squeeze_pos: usize,
}
impl Reader {
    #[cfg(test)]
    pub(crate) fn rarequeue_test_fixture(bytes: &[u8]) -> Self {
        let mut reader = Self::empty(bytes.len().div_ceil(RATE));
        reader.prefix_bytes_mut()[..bytes.len()].copy_from_slice(bytes);
        reader
    }
    #[cfg_attr(not(test), allow(dead_code))]
    fn empty(blocks: usize) -> Self {
        Self::with_prefix(Words::new(blocks))
    }
    fn with_prefix(prefix: Words<ROW>) -> Self {
        Self {
            prefix,
            state: [0; 25],
            cursor: 0,
            squeeze_pos: RATE,
        }
    }
    /// Move the prefix storage out; the reader keeps an empty owner and must
    /// not be read afterwards. The caller erases the storage and pools it.
    pub(crate) fn take_prefix(&mut self) -> Words<ROW> {
        self.cursor = 0;
        core::mem::replace(&mut self.prefix, Words::empty())
    }

    fn prefix_bytes(&self) -> &[u8] {
        let rows: &[[u64; ROW]] = &self.prefix;
        // SAFETY: rows is an initialized, exclusively owned array of plain u64
        // without padding; every byte is a valid u8 and the length is exact.
        unsafe { core::slice::from_raw_parts(rows.as_ptr().cast::<u8>(), rows.len() * RATE) }
    }

    fn prefix_bytes_mut(&mut self) -> &mut [u8] {
        let rows: &mut [[u64; ROW]] = &mut self.prefix;
        // SAFETY: as above; the mutable byte view is the only live view.
        unsafe {
            core::slice::from_raw_parts_mut(rows.as_mut_ptr().cast::<u8>(), rows.len() * RATE)
        }
    }

    #[inline(always)]
    pub(crate) fn consume_prefix(&mut self, visit: impl FnOnce(&[u8]) -> usize) -> usize {
        let available = &self.prefix_bytes()[self.cursor..];
        let used = visit(available);
        assert!(used <= available.len());
        self.cursor += used;
        used
    }

    pub(crate) fn read(&mut self, mut out: &mut [u8]) {
        let n = out.len().min(self.prefix.len() * RATE - self.cursor);
        // Source/destination are disjoint by the mutable Reader/output loans.
        // Exact n bytes only; the local native copy has no stack or calls.
        #[cfg(target_arch = "aarch64")]
        // SAFETY: cursor starts at zero and advances only by consumed prefix bytes;
        // n=min(out.len(), prefix_bytes().len()-cursor) stays in the prefix. The reader and output
        // borrows are disjoint, and cursor+n stays in the initialized prefix;
        // ct_scheduled_copy.S copies exactly n bytes on AArch64.
        unsafe {
            pretzel44_scheduled_copy(
                out.as_mut_ptr(),
                self.prefix_bytes().as_ptr().add(self.cursor),
                n,
            );
        }
        self.cursor += n;
        out = &mut out[n..];
        while !out.is_empty() {
            if self.squeeze_pos == RATE {
                crate::shake2::sponge_permute(&mut self.state);
                self.squeeze_pos = 0;
            }
            let n = out.len().min(RATE - self.squeeze_pos);
            for (j, byte) in out[..n].iter_mut().enumerate() {
                let i = self.squeeze_pos + j;
                *byte = (self.state[i / 8] >> (8 * (i % 8))) as u8;
            }
            self.squeeze_pos += n;
            out = &mut out[n..];
        }
    }
}
impl Zeroize for Reader {
    fn zeroize(&mut self) {
        self.prefix.erase();
        self.state.zeroize();
        self.cursor.zeroize();
        self.squeeze_pos.zeroize();
    }
}
// The prefix owner erases its whole allocation in its own destructor (wide
// path); the remaining fields are erased here, so nothing is erased twice.
impl Drop for Reader {
    fn drop(&mut self) {
        self.state.zeroize();
        self.cursor.zeroize();
        self.squeeze_pos.zeroize();
    }
}
impl ZeroizeOnDrop for Reader {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn six_stream_pool_recycles_and_continues_exactly() {
        assert_eq!(STREAMS, 6);
        let key = [7; 32];
        let pk = [9; PK_BYTES];
        let mu = [11; 64];
        let entropy = [13; 32];
        let prefixes = Prefixes::new(&key, &pk);
        let mut pool = PrefixPool::new();
        for retry in [0u32, 1, u32::MAX] {
            let retry = retry.to_le_bytes();
            let storage = core::array::from_fn(|i| pool.take(i));
            let mut readers = prefixes.readers_in(&mu, &retry, &entropy, segment_scalar, storage);
            for i in 0..STREAMS {
                let mut expected = Xof::new(
                    DOMAINS[i],
                    &[
                        PROFILE_ID,
                        crate::randomness::CT_TAPE_DOMAIN,
                        &key,
                        &pk,
                        &mu,
                        &retry,
                        &entropy,
                    ],
                );
                // Includes the zero-prefix dummy stream and two continuation blocks.
                let n = BLOCKS[i] * RATE + 2 * RATE + 1;
                let mut actual = vec![0; n];
                let mut reference = vec![0; n];
                readers[i].read(&mut actual);
                expected.fill(&mut reference);
                assert_eq!(actual, reference, "stream={i}");
                pool.recycle(i, readers[i].take_prefix());
            }
            assert!(pool.is_erased());
        }
    }

    #[test]
    fn schedule_has_37_paired_blocks() {
        assert_eq!(BLOCKS, [1, 17, 20, 20, 16, 0]);
        assert_eq!(SCHEDULE.iter().map(|x| x.2).sum::<usize>(), 37);
    }

    #[test]
    fn scheduled_native_segments_match_portable_states_bytes_and_bounds() {
        let mut random = Xof::new(b"LILT-CT-SCHEDULED-PERMUTATION-TEST", &[]);
        for blocks in [1, 2, 17, 38, 46, 53, 96, 203] {
            for case in 0..8 {
                let initial = core::array::from_fn(|_| match case {
                    0 => 0,
                    1 => u64::MAX,
                    _ => random.u64(),
                });
                let mut actual = initial;
                let mut expected = initial;
                let len = blocks * RATE;
                let mut a = vec![0xa5; len + 32];
                let mut b = vec![0x5a; len + 32];
                let mut aa = vec![0; len];
                let mut bb = vec![0; len];
                // Every byte alignment modulo sixteen, with two independent
                // offsets and sentinels on both sides of each output range.
                let offset_a = case * 2 + 1;
                let offset_b = 16 - case * 2;
                segment(
                    &mut actual,
                    &mut a[offset_a..offset_a + len],
                    &mut b[offset_b..offset_b + len],
                );
                segment_scalar(&mut expected, &mut aa, &mut bb);
                assert_eq!(actual, expected);
                assert_eq!(&a[offset_a..offset_a + len], aa);
                assert_eq!(&b[offset_b..offset_b + len], bb);
                assert!(a[..offset_a]
                    .iter()
                    .chain(a[offset_a + len..].iter())
                    .all(|&x| x == 0xa5));
                assert!(b[..offset_b]
                    .iter()
                    .chain(b[offset_b + len..].iter())
                    .all(|&x| x == 0x5a));
            }
        }
    }

    #[test]
    fn scheduled_streams_match_standard_shake_through_lane_changes_and_exhaustion() {
        let key = [0x5a; 32];
        for pk_len in (0..=RATE).chain([2 * RATE - 1, 2 * RATE, 2 * RATE + 1, PK_BYTES]) {
            let pk: Vec<u8> = (0..pk_len).map(|i| (i * 7 + 3) as u8).collect();
            let prefixes = Prefixes::new(&key, &pk);
            for retry in [0u32, u32::MAX] {
                let mu = [retry as u8; 64];
                let entropy = [pk_len as u8; 32];
                let retry = retry.to_le_bytes();
                let mut actual = prefixes.readers(&mu, &retry, &entropy, segment);
                let tape = DOMAINS.map(|domain| {
                    Xof::new(
                        domain,
                        &[
                            PROFILE_ID,
                            crate::randomness::CT_TAPE_DOMAIN,
                            &key,
                            &pk,
                            &mu,
                            &retry,
                            &entropy,
                        ],
                    )
                });
                let [t0, t1, t2, t3, t4, t5] = tape;
                let mut expected = [t0, t1, t2, t3, t4, t5];
                // Read the error stream first. Each iteration
                // interleaves all six streams, including empty reads and
                // positions immediately around each public prefetch boundary.
                let mut done = [0; STREAMS];
                for checkpoint in 0..9 {
                    for i in [3, 0, 5, 2, 4, 1] {
                        let boundary = BLOCKS[i] * RATE;
                        let target = [
                            0,
                            1,
                            RATE - 1,
                            RATE,
                            boundary.saturating_sub(1),
                            boundary,
                            boundary + 1,
                            boundary + RATE,
                            boundary + 4096,
                        ][checkpoint];
                        // Salt's prefetch is one block, so RATE precedes
                        // boundary-1; never rewind the reference stream.
                        let target = target.max(done[i]);
                        let mut got = vec![0; target - done[i]];
                        let mut want = vec![0; got.len()];
                        actual[i].read(&mut got);
                        expected[i].fill(&mut want);
                        assert_eq!(
                            got, want,
                            "pk={pk_len}, stream={i}, checkpoint={checkpoint}"
                        );
                        done[i] = target;
                    }
                }
            }
        }
    }
}

// Framing is exactly the concatenation of three part() calls.
// Construct private bytes directly through an erasing borrow; no extra
// unguarded private byte array is moved into this owner.
fn finalize_tape_suffix(
    states: &mut [Sponge],
    mu: &[u8; 64],
    retry: &[u8; 4],
    entropy: &[u8; 32],
    pair: &mut [u64; 50],
) {
    let mut backing = [0u64; 16];
    let mut tail = crate::ct_erase::StackByteGuard::new(&mut backing);
    tail[0..8].copy_from_slice(&64u64.to_le_bytes());
    tail[8..72].copy_from_slice(mu);
    tail[72..80].copy_from_slice(&4u64.to_le_bytes());
    tail[80..84].copy_from_slice(retry);
    tail[84..92].copy_from_slice(&32u64.to_le_bytes());
    tail[92..124].copy_from_slice(entropy);
    crate::shake2::finalize_attempt_suffix_paired(states, &tail[..124], pair);
}
#[cfg(test)]
mod coalesced_suffix_tests {
    use super::*;
    #[test]
    fn all_positions_and_mixed_streams_match_original_framing() {
        for position in 0..136 {
            for trial in 0..8 {
                let prefix: Vec<u8> = (0..136)
                    .map(|j| (j * 79 + trial * 13 + position) as u8)
                    .collect();
                let mut actual: [Sponge; 6] = core::array::from_fn(|i| {
                    let mut s = Sponge::new();
                    s.absorb(
                        &prefix[..if trial < 7 {
                            if i < trial {
                                position % 12
                            } else {
                                12 + position % 124
                            }
                        } else {
                            (position + 31 * i) % 136
                        }],
                    );
                    s
                });
                let mut expected = actual.clone();
                let mu = core::array::from_fn(|i| (i * 17 + position + trial) as u8);
                let retry = (position as u32).wrapping_mul(0x17398abc).to_le_bytes();
                let entropy = core::array::from_fn(|i| (i * 93 + position + trial * 17) as u8);
                for s in &mut expected {
                    for part in [&mu[..], &retry[..], &entropy[..]] {
                        s.part(part);
                    }
                    s.pad();
                }
                let mut pair = [0u64; 50];
                finalize_tape_suffix(&mut actual, &mu, &retry, &entropy, &mut pair);
                for (a, b) in actual.iter().zip(&expected) {
                    assert_eq!(*a.state, *b.state);
                    assert_eq!(a.audit_absorb_position(), b.audit_absorb_position());
                }
            }
        }
    }
}

// Only scheduled-prefix reads use this private copy primitive.
// SAFETY: contract of the assembly routine defined just below (ct_scheduled_copy.S). It reads `len`
// bytes at `src` and writes `len` bytes at `dst`, 16 bytes at a time and then byte by byte; the two
// ranges must not overlap. Any length and alignment are accepted. It is a leaf routine with no
// stack use, changes only x0 to x3, v0 and the flags, keeps no pointer and has no global state. It
// uses base and NEON register instructions only.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn pretzel44_scheduled_copy(dst: *mut u8, src: *const u8, len: usize);
}
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    concat!(
        ".text\n.globl _pretzel44_scheduled_copy\n.p2align 2\n_pretzel44_scheduled_copy:\n",
        include_str!("ct_scheduled_copy.S")
    ),
    options(raw)
);
