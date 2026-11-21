//! Paired SHAKE256 permutation and public transcript expansion.
#[cfg(test)]
use crate::hashes::Xof;
use zeroize::Zeroizing;

#[path = "ct_transcript.rs"]
mod transcript;
pub(crate) use transcript::FastSponge;

#[path = "public_common_prefix.rs"]
pub(crate) mod common_prefix;

const RATE: usize = 136;
#[path = "keccak2_arm.rs"]
mod arm;

pub(crate) fn available() -> bool {
    {
        std::arch::is_aarch64_feature_detected!("sha3")
    }
}

fn permute_scalar(pair: &mut [u64; 50]) {
    for lane in 0..2 {
        let mut s = Zeroizing::new(core::array::from_fn(|j| pair[2 * j + lane]));
        keccak::f1600(&mut s);
        for j in 0..25 {
            pair[2 * j + lane] = s[j];
        }
    }
}

fn permute(pair: &mut [u64; 50]) {
    if available() {
        // Fixed initialized 400-byte input, supported public CPU feature,
        // exactly 24 rounds; the assembly has no data-dependent addressing.
        // SAFETY: The AArch64 gate of build.rs and available() check establish FEAT_SHA3. pair exclusively borrows
        // 50 initialized u64 words, exactly the 400-byte state read/written by
        // keccak2_arm.rs::permute; RC has 24 initialized words.
        unsafe { arm::permute(pair) };
        return;
    }
    permute_scalar(pair);
}

/// Absorbing state, with the same SHAKE256 padding and framing as hashes::Xof.
/// Only lengths determine the absorption schedule. The state erases on drop.
#[derive(Clone)]
pub(crate) struct Sponge {
    pub(crate) state: Zeroizing<[u64; 25]>,
    pos: usize,
}
impl Sponge {
    pub(crate) fn new() -> Self {
        Self {
            state: Zeroizing::new([0; 25]),
            pos: 0,
        }
    }

    pub(crate) fn absorb(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let count = bytes.len().min(RATE - self.pos);
            #[cfg(target_endian = "little")]
            // Initialized disjoint input/state, with public offset+count <= RATE.
            // SAFETY: Under AArch64/little-endian cfg,
            // crates/pretzel-4-4/core/src/ct_sponge_xor.S reads count bytes and updates state
            // bytes pos..pos+count. count<=RATE-pos and the input slice provide those extents; the
            // exclusive 25-word initialized state has 200 bytes, RATE=136, and is disjoint from input.
            unsafe {
                pretzel55_ct_sponge_xor(self.state.as_mut_ptr(), self.pos, bytes.as_ptr(), count);
            }
            self.pos += count;
            bytes = &bytes[count..];
            if self.pos == RATE {
                sponge_permute(&mut self.state);
                self.pos = 0;
            }
        }
    }

    pub(crate) fn part(&mut self, bytes: &[u8]) {
        self.absorb(&(bytes.len() as u64).to_le_bytes());
        self.absorb(bytes);
    }

    pub(crate) fn pad(&mut self) {
        debug_assert!(self.pos < RATE);
        self.state[self.pos / 8] ^= 0x1f_u64 << (8 * (self.pos % 8));
        self.state[(RATE - 1) / 8] ^= 0x80_u64 << (8 * ((RATE - 1) % 8));
    }
}

/// Public-only SHAKE256 continuation using the two-lane permutation.
/// Both lanes contain the same state; the first is exposed. There is no
/// prefetch cutoff, so arbitrary public inputs retain exact continuation.
/// This reader does not change the representation of a signing Xof.
pub(crate) struct PublicReader {
    state: Zeroizing<[u64; 25]>,
    pos: usize,
}

impl PublicReader {
    pub(crate) fn from_absorbed(mut sponge: Sponge) -> Self {
        sponge.pad();
        Self {
            state: sponge.state,
            pos: RATE,
        }
    }

    #[inline(always)]
    fn rate_bytes(&self) -> &[u8] {
        #[cfg(target_endian = "little")]
        // State is initialized contiguous u64 storage. A shared byte view has
        // alignment 1, remains within 136 of 200 bytes and does not outlive self.
        // SAFETY: Under target_endian=little, the initialized [u64;25] state is contiguous 200-byte
        // storage. RATE=136 fits inside it; u8 has alignment one and all bit patterns valid. The
        // shared byte view cannot outlive self.
        unsafe {
            core::slice::from_raw_parts(self.state.as_ptr().cast::<u8>(), RATE)
        }
    }

    fn refill(&mut self) {
        sponge_permute(&mut self.state);
        self.pos = 0;
    }

    pub(crate) fn read(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.pos == RATE {
                self.refill();
            }
            let n = (RATE - self.pos).min(out.len());
            out[..n].copy_from_slice(&self.rate_bytes()[self.pos..self.pos + n]);
            self.pos += n;
            out = &mut out[n..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_permutations_match_independent_states() {
        let mut random = Xof::new(b"LILT-SHAKE2-PERMUTE-TEST", &[]);
        for k in 0..1000 {
            let mut a: [u64; 50] = core::array::from_fn(|_| match k {
                0 => 0,
                1 => u64::MAX,
                _ => random.u64(),
            });
            let mut b = a;
            let mut portable = a;
            for _ in 0..3 {
                permute(&mut a);
                permute_scalar(&mut b);
                // Bypass the crate's hardware dispatch as a second oracle,
                // so both sides cannot share the same ARM round routine.
                for lane in 0..2 {
                    let mut state = core::array::from_fn(|j| portable[2 * j + lane]);
                    keccak::keccak_p(&mut state, 24);
                    for j in 0..25 {
                        portable[2 * j + lane] = state[j];
                    }
                }
                assert_eq!(a, b);
                assert_eq!(a, portable);
            }
        }
    }
}

#[cfg(test)]
mod native_pair_controls {
    use super::*;
    #[test]
    fn full_native_permutation_matches_independent_scalar_lanes() {
        if !available() {
            return;
        }
        let mut seed = 0x813548bf87512u64;
        for case in 0..128 {
            let mut input = core::array::from_fn(|i| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                match case {
                    0 => 0,
                    1 => u64::MAX,
                    2 => 1u64 << (i % 64),
                    _ => seed,
                }
            });
            let mut expected = input;
            permute_scalar(&mut expected);
            unsafe {
                arm::permute(&mut input);
            }
            assert_eq!(input, expected);
        }
    }
}

pub(crate) fn sponge_permute(state: &mut [u64; 25]) {
    if available() {
        // The fixed native permutation reads/writes exactly 25 initialized words.
        // SAFETY: The AArch64 gate of build.rs and available() establish FEAT_SHA3.
        // crates/pretzel-4-4/core/src/ct_sponge_permute.S reads/writes exactly 25 initialized
        // u64 state words and reads KECCAK_RC's 24 words; state is exclusively borrowed and disjoint
        // from the constants.
        unsafe {
            pretzel55_ct_sponge_permute(state.as_mut_ptr(), KECCAK_RC.as_ptr());
        }
        return;
    }
    keccak::f1600(state);
}
// SAFETY: contract of the two assembly routines defined just below (rank-four files under this
// crate's symbol names). `pretzel55_ct_sponge_xor` (`ct_sponge_xor.S`) reads `count` bytes at
// `input` and reads and writes the `count` bytes at byte offset `offset` of `state`; the caller
// must keep `offset + count` inside the 200-byte state. It uses base instructions, no stack and x0
// to x8 only. `pretzel55_ct_sponge_permute` (`ct_sponge_permute.S`) reads and writes exactly 25
// words at `state` and reads 24 words at `rc`. It uses the SHA-3 instructions (EOR3, RAX1, XAR,
// BCAX), assembled under `.arch armv8.4-a+sha3` whatever the compiler flags are, so the caller must
// have checked FEAT_SHA3 at run time. It saves and restores d8 to d15 in a 64-byte frame that it
// clears. Neither routine needs an alignment, keeps a pointer or has global state.
unsafe extern "C" {
    fn pretzel55_ct_sponge_permute(state: *mut u64, rc: *const u64);
    fn pretzel55_ct_sponge_xor(state: *mut u64, offset: usize, input: *const u8, count: usize);
}
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(concat!(
    ".text\n.globl _pretzel55_ct_sponge_xor\n.p2align 2\n_pretzel55_ct_sponge_xor:\n",include_str!("../../pretzel-4-4/core/src/ct_sponge_xor.S"),
    ".arch armv8.4-a+sha3\n.globl _pretzel55_ct_sponge_permute\n.p2align 2\n_pretzel55_ct_sponge_permute:\n",include_str!("../../pretzel-4-4/core/src/ct_sponge_permute.S")),options(raw));

// Round constants of Keccak-f[1600], as given in FIPS 202, Section 3.2.5.
// Keccak-f1600 round constants shared by the native permutation variants.
pub(crate) const KECCAK_RC: [u64; 24] = [
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

#[cfg(test)]
mod native_sponge_tests {
    use super::*;
    #[test]
    fn single_state_native_matches_portable_with_guards() {
        let mut seed = 0xa7153b68e9231705u64;
        for case in 0..128 {
            let mut guarded = [0x912378aff321867bu64; 29];
            for x in &mut guarded[2..27] {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *x = match case {
                    0 => 0,
                    1 => u64::MAX,
                    _ => seed,
                };
            }
            let before = guarded;
            let state: &mut [u64; 25] = (&mut guarded[2..27]).try_into().unwrap();
            let mut want = *state;
            keccak::f1600(&mut want);
            sponge_permute(state);
            assert_eq!(*state, want);
            assert_eq!(&guarded[..2], &before[..2]);
            assert_eq!(&guarded[27..], &before[27..]);
        }
    }
    #[cfg(target_endian = "little")]
    #[test]
    fn single_state_xor_all_offsets_lengths_and_guards() {
        for offset in 0..=RATE {
            for count in 0..=RATE - offset {
                let mut storage = core::array::from_fn::<_, 29, _>(|i| {
                    (i as u64).wrapping_mul(0x713529bd02347f19)
                });
                let before = storage;
                let mut want = storage;
                let input: Vec<u8> = (0..count + 2)
                    .map(|i| (i * 79 + count + offset) as u8)
                    .collect();
                for (i, &b) in input[1..count + 1].iter().enumerate() {
                    let pos = offset + i;
                    want[2 + pos / 8] ^= (b as u64) << (8 * (pos % 8));
                }
                unsafe {
                    pretzel55_ct_sponge_xor(
                        storage.as_mut_ptr().add(2),
                        offset,
                        input.as_ptr().add(1),
                        count,
                    );
                }
                assert_eq!(storage, want);
                assert_eq!(&storage[..2], &before[..2]);
                assert_eq!(&storage[27..], &before[27..]);
            }
        }
    }
}

// Public same-wire matrix streams; no private mask-prefetch changes.
#[path = "shake2_matrix.rs"]
pub(crate) mod matrix;

/// Two independently framed streams, mapped into disjoint fixed tape regions.
/// Lane A supplies the proposal prefix. Lane B supplies its suffix then transport.
/// Lengths, split point and all output addresses are public.
pub(crate) fn expand_attempt_balanced(
    domain: &[u8],
    left: &[&[u8]],
    right: &[&[u8]],
    proposal: &mut [u8],
    transport: &mut [u8],
) {
    assert!(proposal.len() >= transport.len());
    let total = proposal
        .len()
        .checked_add(transport.len())
        .expect("public tape size");
    let split = total.div_ceil(2);
    let (first, second) = proposal.split_at_mut(split);
    let mut a = Sponge::new();
    a.absorb(domain);
    for part in left {
        a.part(part);
    }
    a.pad();
    let mut b = Sponge::new();
    b.absorb(domain);
    for part in right {
        b.part(part);
    }
    b.pad();
    let mut pair = Zeroizing::new([0u64; 50]);
    for i in 0..25 {
        pair[2 * i] = a.state[i];
        pair[2 * i + 1] = b.state[i];
    }
    // Fixed production shape only. All other public sizes keep the reference path.
    if first.len() == 8544 && second.len() == 2400 && transport.len() == 6144 && available() {
        // SAFETY: The AArch64 gate of build.rs and available() establish FEAT_SHA3. The length checks produce exact
        // 8544/2400/6144-byte mutable arrays; split_at_mut separates the proposal lanes and transport
        // is separately borrowed. pair is a distinct initialized [u64;50], meeting
        // sign_prefix_shake.rs::squeeze's contract.
        unsafe {
            sign_prefix_shake::squeeze(
                &mut pair,
                first.try_into().unwrap(),
                second.try_into().unwrap(),
                transport.try_into().unwrap(),
            );
        }
        return;
    }
    let blocks = split.div_ceil(RATE);
    for block in 0..blocks {
        permute(&mut pair);
        let at = block * RATE;
        store_balanced_segment(&pair, 0, at, 0, first);
        store_balanced_segment(&pair, 1, at, 0, second);
        store_balanced_segment(&pair, 1, at, second.len(), transport);
    }
}
#[inline(always)]
fn store_balanced_segment(
    pair: &[u64; 50],
    lane: usize,
    block_start: usize,
    segment_start: usize,
    out: &mut [u8],
) {
    let start = block_start.max(segment_start);
    let end = (block_start + RATE).min(segment_start + out.len());
    if start >= end {
        return;
    }
    // All production region boundaries are word multiples. This public fast path
    // keeps the copies exactly eight bytes; the generic tail remains tested.
    if (start | end) & 7 == 0 {
        let first = (start - block_start) / 8;
        for (j, chunk) in out[start - segment_start..end - segment_start]
            .chunks_exact_mut(8)
            .enumerate()
        {
            chunk.copy_from_slice(&pair[2 * (first + j) + lane].to_le_bytes());
        }
        return;
    }
    let mut cursor = start;
    while cursor < end {
        let offset = cursor - block_start;
        let bytes = pair[2 * (offset / 8) + lane].to_le_bytes();
        let within = offset % 8;
        let n = (8 - within).min(end - cursor);
        out[cursor - segment_start..cursor - segment_start + n]
            .copy_from_slice(&bytes[within..within + n]);
        cursor += n;
    }
}
#[cfg(test)]
mod balanced_attempt_pair_tests {
    use super::*;
    #[test]
    fn all_boundaries_match_independent_framed_streams() {
        for n in [
            0, 1, 7, 8, 9, 135, 136, 137, 271, 272, 273, 2400, 5120, 6144, 6544, 8544, 10944, 16384,
        ] {
            for m in [0, 1, 7, 8, 135, 136, 137, 6144] {
                if m > n {
                    continue;
                }
                let key = [0x53; 32];
                let seed = [0x97; 64];
                let message = vec![0x21; (n + m) % 281];
                let retry = 17u32.to_le_bytes();
                let left: &[&[u8]] = &[b"balanced-A", &key, &message, &retry, &seed];
                let right: &[&[u8]] = &[b"balanced-B", &key, &message, &retry, &seed];
                let mut a = vec![0; n];
                let mut b = vec![0; m];
                expand_attempt_balanced(b"balanced-attempt-test", left, right, &mut a, &mut b);
                let split = (n + m).div_ceil(2);
                let mut ar = vec![0; n];
                let mut br = vec![0; m];
                Xof::new(b"balanced-attempt-test", left).fill(&mut ar[..split]);
                let mut second = Xof::new(b"balanced-attempt-test", right);
                second.fill(&mut ar[split..]);
                second.fill(&mut br);
                assert_eq!(a, ar, "proposal lengths {} {}", n, m);
                assert_eq!(b, br, "transport lengths {} {}", n, m);
            }
        }
    }
}

#[path = "sign_prefix_shake.rs"]
mod sign_prefix_shake;
#[cfg(test)]
#[path = "sign_prefix_shake_tests.rs"]
mod sign_prefix_shake_tests;

impl Sponge {
    /// The verifier's adjacent rho and label framing form one 48-byte prefix.
    pub(crate) fn verify_rho_labels(&mut self, rho: &[u8; 32], labels: &[u8]) {
        let mut frame = [0u8; 48];
        frame[..8].copy_from_slice(&32u64.to_le_bytes());
        frame[8..40].copy_from_slice(rho);
        frame[40..].copy_from_slice(&(labels.len() as u64).to_le_bytes());
        self.absorb(&frame);
        self.public_absorb(labels);
    }

    /// Public continuation only.
    pub(crate) fn public_part(&mut self, bytes: &[u8]) {
        self.absorb(&(bytes.len() as u64).to_le_bytes());
        self.public_absorb(bytes);
    }
    fn public_absorb(&mut self, mut bytes: &[u8]) {
        if self.pos != 0 {
            let count = bytes.len().min(RATE - self.pos);
            self.absorb(&bytes[..count]);
            bytes = &bytes[count..];
        }
        #[cfg(target_endian = "little")]
        if self.pos == 0 && bytes.len() >= RATE && available() {
            let blocks = bytes.len() / RATE;
            // Safe: nonzero count, initialized 25-word exclusive state, disjoint
            // input covers blocks*136 bytes, public SHA3 support checked above.
            // SAFETY: The AArch64/little-endian cfg and available() establish FEAT_SHA3.
            // bytes.len()>=RATE=136 gives a nonzero blocks count and blocks*RATE<=bytes.len().
            // public_sponge_blocks.S consumes those complete input blocks, the exclusive initialized
            // 25-word state, and 24 KECCAK_RC words without overlapping borrows.
            unsafe {
                pretzel55_public_sponge_blocks(
                    self.state.as_mut_ptr(),
                    bytes.as_ptr(),
                    blocks,
                    KECCAK_RC.as_ptr(),
                );
            }
            bytes = &bytes[blocks * RATE..];
        }
        self.absorb(bytes);
    }
}
// SAFETY: contract of the assembly routine defined just below (the rank-four
// `public_sponge_blocks.S` under this crate's symbol name). It reads and writes exactly 25 words at
// `state`, reads `136 * blocks` bytes at `input` and 24 words at `rc` (the constant pointer is
// reset for every block). `blocks` must be at least 1. It uses the SHA-3 instructions, assembled
// under `.arch armv8.4-a+sha3`, so the caller must have checked FEAT_SHA3 at run time. It saves and
// restores d8 to d15 in a 64-byte frame, needs no alignment, keeps no pointer and has no global
// state.
unsafe extern "C" {
    fn pretzel55_public_sponge_blocks(
        state: *mut u64,
        input: *const u8,
        blocks: usize,
        rc: *const u64,
    );
}
#[cfg(target_vendor = "apple")]
core::arch::global_asm!(concat!(".text\n.arch armv8.4-a+sha3\n.globl _pretzel55_public_sponge_blocks\n.p2align 2\n_pretzel55_public_sponge_blocks:\n",include_str!("../../pretzel-4-4/core/src/public_sponge_blocks.S")),options(raw));
#[cfg(test)]
mod public_blocks_tests {
    use super::*;
    #[test]
    fn public_blocks_every_position_and_boundary() {
        let mut rng = 0xabcd9876u64;
        for pos in 0..RATE {
            for length in [0, 1, 7, 8, 135, 136, 137, 271, 272, 273, 1280, 4096] {
                let mut input = vec![0; length];
                for b in &mut input {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    *b = rng as u8;
                }
                let mut original = Sponge::new();
                original.absorb(&vec![0x98; pos]);
                let mut actual = original.clone();
                original.part(&input);
                actual.public_part(&input);
                assert_eq!(&*original.state, &*actual.state);
                assert_eq!(original.pos, actual.pos);
                let mut a = PublicReader::from_absorbed(original);
                let mut b = PublicReader::from_absorbed(actual);
                let mut x = [0; 300];
                let mut y = [0; 300];
                a.read(&mut x);
                b.read(&mut y);
                assert_eq!(x, y);
            }
        }
    }
    #[cfg(target_endian = "little")]
    #[test]
    fn public_native_blocks_against_scalar_keccak() {
        if !available() {
            return;
        }
        let mut rng = 0x1234abcd9876u64;
        for blocks in 1..=32 {
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let initial = core::array::from_fn::<_, 25, _>(|_| next());
            let input: Vec<u8> = (0..blocks * RATE).map(|_| next() as u8).collect();
            let mut expected = initial;
            for block in input.chunks_exact(RATE) {
                for (i, word) in block.chunks_exact(8).enumerate() {
                    expected[i] ^= u64::from_le_bytes(word.try_into().unwrap());
                }
                keccak::f1600(&mut expected);
            }
            // Canaries exercise the exact 200-byte state boundary.
            let mut guarded = [0xfeedfacecafebeefu64; 27];
            guarded[1..26].copy_from_slice(&initial);
            unsafe {
                pretzel55_public_sponge_blocks(
                    guarded[1..26].as_mut_ptr(),
                    input.as_ptr(),
                    blocks,
                    KECCAK_RC.as_ptr(),
                );
            }
            assert_eq!(&guarded[1..26], &expected);
            assert_eq!(guarded[0], 0xfeedfacecafebeef);
            assert_eq!(guarded[26], 0xfeedfacecafebeef);
        }
    }
}

#[cfg(test)]
mod public_verify_framing_tests {
    use super::*;

    #[test]
    fn public_framing_matches_separate_parts_at_all_rate_positions() {
        for pos in 0..RATE {
            for length in [
                0, 1, 7, 8, 87, 88, 89, 135, 136, 137, 271, 272, 273, 1024, 1280, 4096,
            ] {
                let rho = core::array::from_fn(|i| (i * 31 + pos) as u8);
                let labels: Vec<u8> = (0..length).map(|i| (i * 17 + pos) as u8).collect();
                let mut old = Sponge::new();
                old.absorb(&vec![0xa7; pos]);
                let mut new = old.clone();
                old.part(&rho);
                old.public_part(&labels);
                new.verify_rho_labels(&rho, &labels);
                assert_eq!(&*old.state, &*new.state);
                assert_eq!(old.pos, new.pos);
                let mut old = PublicReader::from_absorbed(old);
                let mut new = PublicReader::from_absorbed(new);
                let mut expected = [0; 300];
                let mut actual = [0; 300];
                old.read(&mut expected);
                new.read(&mut actual);
                assert_eq!(actual, expected);
            }
        }
    }
}
