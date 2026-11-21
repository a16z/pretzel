//! Bounded two-stream SHAKE256 prefetch for stateless mask generation.
//!
//! Both streams keep their original framed transcript and byte sequence.
//! Exactly PREFETCH_BLOCKS blocks are generated per lane before sampling;
//! the Xof buffers expose them in 136-byte chunks.
//! Any further bytes use ordinary single-state Keccak. Samplers and their
//! left-to-right abort order are not affected. No cross-signature state exists.
use crate::hashes::Xof;
use crate::params::{DOM_MASK_ERR, DOM_MASK_SEC, PROFILE_ID};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[path = "ct_transcript.rs"]
mod transcript;

pub(crate) use transcript::FastSponge;

#[path = "public_common_prefix.rs"]
pub(crate) mod common_prefix;

const RATE: usize = 136;

// Public, fixed per-attempt amount. Exhaustion uses the exact scalar stream.

const PREFETCH_BLOCKS: usize = 384;
const PREFETCH_BYTES: usize = PREFETCH_BLOCKS * RATE;

#[cfg(target_arch = "aarch64")]
#[path = "keccak2_arm.rs"]
mod arm;

pub(crate) fn available() -> bool {
    #[cfg(test)]
    if FORCE_NO_SHA3.with(|flag| flag.get()) {
        return false;
    }
    #[cfg(target_arch = "aarch64")]
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
    #[cfg(target_arch = "aarch64")]
    if available() {
        // Fixed initialized 400-byte input, supported public CPU feature,
        // exactly 24 rounds; the assembly has no data-dependent addressing.
        // SAFETY: available() checks FEAT_SHA3; pair is an exclusive initialized [u64; 50],
        // satisfying arm::permute in keccak2_arm.rs.
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
            #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
            // Initialized disjoint input/state, with public offset+count <= RATE.
            // SAFETY: count=min(bytes.len(), RATE-pos) bounds input and rate writes. The exclusive
            // 25-u64 state is disjoint from bytes; ct_sponge_xor.S accesses exactly that interval on
            // little-endian AArch64.
            unsafe {
                pretzel44_ct_sponge_xor(self.state.as_mut_ptr(), self.pos, bytes.as_ptr(), count);
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
        // SAFETY: state is an initialized [u64; 25], covering 200 bytes without element padding.
        // RATE=136 selects only its prefix; u8 alignment is one and the shared byte view is tied to
        // self.
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

pub(crate) struct Prefixes([Sponge; 2]);
impl Prefixes {
    pub(crate) fn new(key: &[u8; 32], pk: &[u8]) -> Self {
        Self([DOM_MASK_SEC, DOM_MASK_ERR].map(|domain| {
            let mut s = Sponge::new();
            s.absorb(domain);
            s.part(PROFILE_ID);
            s.part(crate::randomness::CT_TAPE_DOMAIN);
            s.part(key);
            s.part(pk);
            s
        }))
    }

    pub(crate) fn expand(&self, mu: &[u8; 64], retry: &[u8; 4], entropy: &[u8; 32]) -> (Xof, Xof) {
        let [a, b] = self.readers(mu, retry, entropy, permute);
        (Xof::from_prefetched(a), Xof::from_prefetched(b))
    }

    fn readers(
        &self,
        mu: &[u8; 64],
        retry: &[u8; 4],
        entropy: &[u8; 32],
        permutation: fn(&mut [u64; 50]),
    ) -> [Reader; 2] {
        let [mut a, mut b] = [Reader::empty(), Reader::empty()];
        let final_states = self.prefetch(
            mu,
            retry,
            entropy,
            [&mut a.prefix, &mut b.prefix],
            permutation,
        );
        a.state.copy_from_slice(&final_states[0]);
        b.state.copy_from_slice(&final_states[1]);
        [a, b]
    }

    fn prefetch(
        &self,
        mu: &[u8; 64],
        retry: &[u8; 4],
        entropy: &[u8; 32],
        prefixes: [&mut [u8; PREFETCH_BYTES]; 2],
        permutation: fn(&mut [u64; 50]),
    ) -> Zeroizing<[[u64; 25]; 2]> {
        let mut states = self.0.clone();
        for s in &mut states {
            for part in [&mu[..], &retry[..], &entropy[..]] {
                s.part(part);
            }
            s.pad();
        }
        let mut pair = Zeroizing::new(core::array::from_fn(|i| states[i % 2].state[i / 2]));
        for block in 0..PREFETCH_BLOCKS {
            permutation(&mut pair);
            for lane in 0..2 {
                for j in 0..RATE / 8 {
                    let offset = block * RATE + 8 * j;
                    prefixes[lane][offset..offset + 8]
                        .copy_from_slice(&pair[2 * j + lane].to_le_bytes());
                }
            }
        }
        Zeroizing::new(core::array::from_fn(|lane| {
            core::array::from_fn(|j| pair[2 * j + lane])
        }))
    }
}

/// Owns one prefetched prefix and the state immediately after that prefix.
/// No shared ownership or synchronization between readers. Consuming or
/// dropping either reader cannot alter the other stream.
#[derive(Clone)]
pub(crate) struct Reader {
    state: [u64; 25],
    prefix: Box<[u8; PREFETCH_BYTES]>,
    prefix_pos: usize,
    squeeze_pos: usize,
}
impl Reader {
    fn empty() -> Self {
        Self {
            state: [0; 25],
            prefix: Box::new([0; PREFETCH_BYTES]),
            prefix_pos: 0,
            squeeze_pos: RATE,
        }
    }

    pub(crate) fn read(&mut self, mut out: &mut [u8]) {
        let n = out.len().min(PREFETCH_BYTES - self.prefix_pos);
        out[..n].copy_from_slice(&self.prefix[self.prefix_pos..self.prefix_pos + n]);
        self.prefix_pos += n;
        out = &mut out[n..];
        while !out.is_empty() {
            if self.squeeze_pos == RATE {
                keccak::f1600(&mut self.state);
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
        self.state.zeroize();
        self.prefix.as_mut().zeroize();
        self.prefix_pos.zeroize();
        self.squeeze_pos.zeroize();
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for Reader {}

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

    #[test]
    fn framed_streams_match_sha3_across_absorb_prefetch_and_squeeze_boundaries() {
        let key = [0x5a; 32];
        let mu = [0xa5; 64];
        let entropy = [0x31; 32];
        // Cover every final padding position for both different-length
        // domains, including the combined 0x9f suffix in the last rate byte.
        for pk_len in (0..=RATE).chain([
            RATE + 1,
            2 * RATE - 1,
            2 * RATE,
            2 * RATE + 1,
            crate::params::PK_BYTES,
        ]) {
            let pk: Vec<u8> = (0..pk_len).map(|i| (i * 7) as u8).collect();
            let p = Prefixes::new(&key, &pk);
            for retry in [0u32, 511, u32::MAX] {
                for permutation in [permute as fn(&mut [u64; 50]), permute_scalar] {
                    let retry = retry.to_le_bytes();
                    let mut readers = p.readers(&mu, &retry, &entropy, permutation);
                    for (lane, domain) in [DOM_MASK_SEC, DOM_MASK_ERR].into_iter().enumerate() {
                        let mut reference = Xof::new(
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
                        );
                        // The first lane crosses into scalar continuation before
                        // the second is read at all; each stream is independent.
                        for n in [0, 1, 2, 135, 136, 137, PREFETCH_BYTES - 1, 1, 4096] {
                            let mut got = vec![0; n];
                            let mut expected = vec![0; n];
                            readers[lane].read(&mut got);
                            reference.fill(&mut expected);
                            assert_eq!(got, expected, "pk_len={pk_len}, lane={lane}, n={n}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn reader_erases_the_complete_owned_state_and_prefetch() {
        let p = Prefixes::new(&[3; 32], b"erasure-test");
        let [mut r, _] = p.readers(&[4; 64], &[5; 4], &[6; 32], permute);
        assert!(r.prefix.iter().any(|&x| x != 0));
        r.read(&mut [0; 7]);
        // Call the exact routine used by Drop while the allocation is alive.
        r.zeroize();
        assert_eq!(r.state, [0; 25]);
        assert!(r.prefix.iter().all(|&x| x == 0));
        assert_eq!((r.prefix_pos, r.squeeze_pos), (0, 0));
    }
}

#[cfg(all(target_arch = "aarch64", test))]
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
    #[cfg(target_arch = "aarch64")]
    if available() {
        // The fixed native permutation reads/writes exactly 25 initialized words.
        // SAFETY: available() checks FEAT_SHA3. state is an exclusive initialized 25-u64 array and
        // SPONGE_RC contains 24 constants; ct_sponge_permute.S reads/writes those exact extents.
        unsafe {
            pretzel44_ct_sponge_permute(state.as_mut_ptr(), SPONGE_RC.as_ptr());
        }
        return;
    }
    keccak::f1600(state);
}
// SAFETY: contract of the two assembly routines defined just below. `pretzel44_ct_sponge_xor`
// (ct_sponge_xor.S) reads `count` bytes at `input` and reads and writes the `count` bytes at byte
// offset `offset` of `state`; the caller must keep `offset + count` inside the 200-byte state. It
// uses base instructions, no stack and x0 to x8 only. `pretzel44_ct_sponge_permute`
// (ct_sponge_permute.S) reads and writes exactly 25 words at `state` and reads 24 words at `rc`. It
// uses the SHA-3 instructions (EOR3, RAX1, XAR, BCAX), assembled under `.arch armv8.4-a+sha3`
// whatever the compiler flags are, so the caller must have checked FEAT_SHA3 at run time. It saves
// and restores d8 to d15 in a 64-byte frame that it clears. Neither routine needs an alignment,
// keeps a pointer or has global state.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn pretzel44_ct_sponge_permute(state: *mut u64, rc: *const u64);
    fn pretzel44_ct_sponge_xor(state: *mut u64, offset: usize, input: *const u8, count: usize);
}
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(concat!(
    ".text\n.globl _pretzel44_ct_sponge_xor\n.p2align 2\n_pretzel44_ct_sponge_xor:\n",include_str!("ct_sponge_xor.S"),
    ".arch armv8.4-a+sha3\n.globl _pretzel44_ct_sponge_permute\n.p2align 2\n_pretzel44_ct_sponge_permute:\n",include_str!("ct_sponge_permute.S")),options(raw));

// Round constants of Keccak-f[1600], as given in FIPS 202, Section 3.2.5.
const SPONGE_RC: [u64; 24] = [
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
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
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
                    pretzel44_ct_sponge_xor(
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

#[cfg(test)]
impl Sponge {
    pub(crate) fn audit_absorb_position(&self) -> usize {
        self.pos
    }
}

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(concat!(".text\n.arch armv8.4-a+sha3\n.globl _pretzel44_ct_absorb_pair\n.p2align 2\n_pretzel44_ct_absorb_pair:\n",include_str!("ct_absorb_pair.S")),options(raw));
// SAFETY: contract of the assembly routine defined just above (ct_absorb_pair.S). It reads and
// writes exactly 50 words at `pair` (two interleaved Keccak states) and reads 24 words at `rc`. It
// uses the SHA-3 instructions, assembled under `.arch armv8.4-a+sha3`, so the caller must have
// checked FEAT_SHA3 at run time. It saves and restores d8 to d15 in a 64-byte frame that it clears,
// needs no alignment, keeps no pointer and has no global state.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn pretzel44_ct_absorb_pair(pair: *mut u64, rc: *const u64);
}

fn xor_rate_without_permuting(state: &mut [u64; 25], pos: usize, bytes: &[u8]) {
    assert!(pos <= RATE && bytes.len() <= RATE - pos);
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    // SAFETY: The assertion bounds pos+bytes.len() by RATE. The exclusive 25-u64 state and
    // input borrow are disjoint; ct_sponge_xor.S reads exactly bytes.len() input bytes and
    // writes that bounded state interval.
    unsafe {
        pretzel44_ct_sponge_xor(state.as_mut_ptr(), pos, bytes.as_ptr(), bytes.len());
    }
}

// Only public cached positions decide crossings, pairing, addresses and loops.
// Each stream still receives exactly its original full-block permutation.
pub(crate) fn finalize_attempt_suffix_paired(
    states: &mut [Sponge],
    tail: &[u8],
    pair: &mut [u64; 50],
) {
    assert_eq!(states.len(), 6);
    assert_eq!(tail.len(), 124);
    let mut cut = [0usize; 6];
    let mut ready = [0usize; 6];
    let mut count = 0;
    for (i, s) in states.iter_mut().enumerate() {
        assert!(s.pos < RATE);
        let k = (RATE - s.pos).min(tail.len());
        cut[i] = k;
        xor_rate_without_permuting(&mut s.state, s.pos, &tail[..k]);
        s.pos += k;
        if s.pos == RATE {
            ready[count] = i;
            count += 1;
        }
    }
    for ids in ready[..count].chunks(2) {
        #[cfg(target_arch = "aarch64")]
        if ids.len() == 2 && available() {
            let a = ids[0];
            let b = ids[1];
            for j in 0..25 {
                pair[2 * j] = states[a].state[j];
                pair[2 * j + 1] = states[b].state[j];
            }
            // SAFETY: The branch checks available() for FEAT_SHA3. pair is an initialized exclusive
            // 50-u64 owner filled from the two states; SPONGE_RC contains 24 constants, matching
            // ct_absorb_pair.S.
            unsafe {
                pretzel44_ct_absorb_pair(pair.as_mut_ptr(), SPONGE_RC.as_ptr());
            }
            for j in 0..25 {
                states[a].state[j] = pair[2 * j];
                states[b].state[j] = pair[2 * j + 1];
            }
            continue;
        }
        for &i in ids {
            sponge_permute(&mut states[i].state);
        }
    }
    for &i in &ready[..count] {
        states[i].pos = 0;
    }
    for (i, s) in states.iter_mut().enumerate() {
        s.absorb(&tail[cut[i]..]);
        s.pad();
    }
}

#[cfg(all(target_arch = "aarch64", test))]
mod paired_absorption_native_tests {
    use super::*;
    #[test]
    fn pure_pair_matches_independent_portable_lanes_and_guards() {
        if !available() {
            return;
        }
        let mut rng = 0x136af751c93eab71u64;
        for trial in 0..256 {
            let mut guarded = [0xa513fe389f276cd1u64; 54];
            for x in &mut guarded[2..52] {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                *x = match trial {
                    0 => 0,
                    1 => u64::MAX,
                    _ => rng,
                };
            }
            let before = guarded;
            let mut want = [[0u64; 25]; 2];
            for lane in 0..2 {
                for j in 0..25 {
                    want[lane][j] = guarded[2 + 2 * j + lane];
                }
                keccak::keccak_p(&mut want[lane], 24);
            }
            unsafe {
                pretzel44_ct_absorb_pair(guarded.as_mut_ptr().add(2), SPONGE_RC.as_ptr());
            }
            for lane in 0..2 {
                for j in 0..25 {
                    assert_eq!(guarded[2 + 2 * j + lane], want[lane][j]);
                }
            }
            assert_eq!(&guarded[..2], &before[..2]);
            assert_eq!(&guarded[52..], &before[52..]);
        }
    }
}

// Public same-wire matrix streams; no private mask-prefetch changes.
#[path = "shake2_matrix.rs"]
pub(crate) mod matrix;

impl Sponge {
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
        #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
        if self.pos == 0 && bytes.len() >= RATE && available() {
            let blocks = bytes.len() / RATE;
            // Safe: nonzero count, initialized 25-word exclusive state, disjoint
            // input covers blocks*136 bytes, public SHA3 support checked above.
            // SAFETY: The surrounding available() check admits FEAT_SHA3 and bytes.len()>=RATE ensures
            // blocks>0. bytes covers blocks*136 bytes, state has 25 initialized exclusive u64 words,
            // and SPONGE_RC has 24 constants, matching public_sponge_blocks.S.
            unsafe {
                pretzel44_public_sponge_blocks(
                    self.state.as_mut_ptr(),
                    bytes.as_ptr(),
                    blocks,
                    SPONGE_RC.as_ptr(),
                );
            }
            bytes = &bytes[blocks * RATE..];
        }
        self.absorb(bytes);
    }
}
// SAFETY: contract of the assembly routine defined just below (public_sponge_blocks.S). It reads
// and writes exactly 25 words at `state`, reads `136 * blocks` bytes at `input` and 24 words at
// `rc` (the constant pointer is reset for every block). `blocks` must be at least 1. It uses the
// SHA-3 instructions, assembled under `.arch armv8.4-a+sha3`, so the caller must have checked
// FEAT_SHA3 at run time. It saves and restores d8 to d15 in a 64-byte frame, needs no alignment,
// keeps no pointer and has no global state.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn pretzel44_public_sponge_blocks(
        state: *mut u64,
        input: *const u8,
        blocks: usize,
        rc: *const u64,
    );
}
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(concat!(".text\n.arch armv8.4-a+sha3\n.globl _pretzel44_public_sponge_blocks\n.p2align 2\n_pretzel44_public_sponge_blocks:\n",include_str!("public_sponge_blocks.S")),options(raw));
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
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
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
                pretzel44_public_sponge_blocks(
                    guarded[1..26].as_mut_ptr(),
                    input.as_ptr(),
                    blocks,
                    SPONGE_RC.as_ptr(),
                );
            }
            assert_eq!(&guarded[1..26], &expected);
            assert_eq!(guarded[0], 0xfeedfacecafebeef);
            assert_eq!(guarded[26], 0xfeedfacecafebeef);
        }
    }
}

#[cfg(test)]
std::thread_local! {
    static FORCE_NO_SHA3: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) fn with_sha3_disabled(f: impl FnOnce()) {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            FORCE_NO_SHA3.with(|flag| flag.set(self.0));
        }
    }
    let _reset = Reset(FORCE_NO_SHA3.with(|flag| flag.replace(true)));
    f();
}
