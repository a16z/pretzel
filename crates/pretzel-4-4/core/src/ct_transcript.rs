//! Exact SHAKE256 transcript continuation, including private failed-attempt
//! challenge inputs. Branches/addresses depend only on public lengths and CPU
//! features. A continuation stays in one erased owner after private absorption.
//! Native helpers clear their touched registers; this is not whole-process
//! register/stack erasure or an early declassification of their inputs.
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const RATE: usize = 136;

// Public framed input only. This cursor is never used by private continuations.
// Prefix framing has five borrowed slices; static dither framing has seven.
#[cfg(test)]
struct PublicPrefixCursor<'a, const PARTS: usize = 5> {
    parts: [&'a [u8]; PARTS],
    segment: usize,
    offset: usize,
}
#[cfg(test)]
impl<'a, const PARTS: usize> PublicPrefixCursor<'a, PARTS> {
    fn new(parts: [&'a [u8]; PARTS]) -> Self {
        Self {
            parts,
            segment: 0,
            offset: 0,
        }
    }
    fn skip_empty(&mut self) {
        while self.segment < self.parts.len() && self.offset == self.parts[self.segment].len() {
            self.segment += 1;
            self.offset = 0;
        }
    }
    fn fill(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;
        while written < out.len() {
            self.skip_empty();
            if self.segment == self.parts.len() {
                break;
            }
            let part = self.parts[self.segment];
            let count = (part.len() - self.offset).min(out.len() - written);
            out[written..written + count].copy_from_slice(&part[self.offset..self.offset + count]);
            self.offset += count;
            written += count;
        }
        written
    }
    // Called only for a complete eight-byte word in a common full rate block.
    fn next_word(&mut self) -> u64 {
        self.skip_empty();
        assert!(
            self.segment < self.parts.len(),
            "public prefix word exhausted"
        );
        let part = self.parts[self.segment];
        if part.len() - self.offset >= 8 {
            let word = u64::from_le_bytes(part[self.offset..self.offset + 8].try_into().unwrap());
            self.offset += 8;
            word
        } else {
            let mut boundary = Zeroizing::new([0u8; 8]);
            assert_eq!(
                self.fill(&mut boundary[..]),
                8,
                "public prefix partial word"
            );
            u64::from_le_bytes(*boundary)
        }
    }
}

// Exactly 51 initialized words, including the public position. No padding or
// separate digest-wrapper partial-block buffer is left outside the owner.
#[repr(C)]
pub(crate) struct FastSponge {
    pair: [u64; 50],
    pos: usize,
}
impl FastSponge {
    /// Duplicate a borrowed public lane directly into the continuation owner.
    pub(crate) fn from_public_pair(pair: &[u64; 50], lane: usize, pos: usize) -> Self {
        assert!(lane < 2 && pos < RATE);
        Self {
            pair: core::array::from_fn(|i| pair[2 * (i / 2) + lane]),
            pos,
        }
    }

    // Only immutable public state crosses this boundary.
    pub(crate) fn from_common_public_state(state: &[u64; 25], pos: usize) -> Self {
        assert!(pos < RATE);
        Self {
            pair: core::array::from_fn(|i| state[i / 2]),
            pos,
        }
    }
    /// Public-only construction: independent framed streams in the two lanes.
    /// Return ordinary duplicated-lane owners before any private continuation.
    #[cfg(test)]
    pub(crate) fn public_prefix_pair(domains: [&[u8]; 2], profile: &[u8], pk: &[u8]) -> [Self; 2] {
        let profile_len = (profile.len() as u64).to_le_bytes();
        let pk_len = (pk.len() as u64).to_le_bytes();
        let mut streams = domains
            .map(|domain| PublicPrefixCursor::new([domain, &profile_len, profile, &pk_len, pk]));
        let lengths = domains.map(|d| {
            d.len()
                .checked_add(16)
                .and_then(|n| n.checked_add(profile.len()))
                .and_then(|n| n.checked_add(pk.len()))
                .expect("public prefix length overflow")
        });
        let blocks = lengths[0].min(lengths[1]) / RATE;
        let mut pair = Zeroizing::new([0u64; 50]);
        for _ in 0..blocks {
            for lane in 0..2 {
                for word in 0..RATE / 8 {
                    pair[2 * word + lane] ^= streams[lane].next_word();
                }
            }
            permute_private(&mut pair);
        }
        let mut owners = core::array::from_fn(|lane| Self {
            pair: core::array::from_fn(|i| pair[2 * (i / 2) + lane]),
            pos: 0,
        });
        // Independent tails preserve unequal positions, even unequal full-block counts.
        for lane in 0..2 {
            let mut tail = Zeroizing::new([0u8; RATE]);
            loop {
                let n = streams[lane].fill(&mut tail[..]);
                if n == 0 {
                    break;
                }
                owners[lane].absorb(&tail[..n]);
            }
        }
        owners
    }

    // Called only on the immutable PUBLIC cached prefix, never a continuation.
    pub(crate) fn public_prefix_snapshot(&self) -> super::Sponge {
        super::Sponge {
            state: Zeroizing::new(core::array::from_fn(|i| self.pair[2 * i])),
            pos: self.pos,
        }
    }
    pub(crate) fn new() -> Self {
        Self {
            pair: [0; 50],
            pos: 0,
        }
    }

    pub(crate) fn absorb(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            let count = input.len().min(RATE - self.pos);
            xor_rate(&mut self.pair, self.pos, &input[..count]);
            self.pos += count;
            input = &input[count..];
            if self.pos == RATE {
                permute_private(&mut self.pair);
                self.pos = 0;
            }
        }
    }
    pub(crate) fn part(&mut self, input: &[u8]) {
        self.absorb(&(input.len() as u64).to_le_bytes());
        self.absorb(input);
    }

    /// The source is an immutable *public* prefix. Its local copy becomes a
    /// private continuation when parts are absorbed; it is never cloned again.
    pub(crate) fn hash<const N: usize>(&self, parts: &[&[u8]]) -> [u8; N] {
        let mut continuation = Self::new();
        continuation.pair.copy_from_slice(&self.pair);
        continuation.pos = self.pos;
        for part in parts {
            continuation.part(part);
        }
        // Keep the original return staging buffer owned until its copied
        // result reaches the caller. Both it and the continuation then erase
        // on normal return or unwind, including failed signing attempts.
        let mut out = Zeroizing::new([0u8; N]);
        continuation.finalize_into(&mut out[..]);
        *out
    }

    // One-shot finalization used only on the local continuation. Padding is
    // XORed through the same native helper, avoiding scalar secret-state loads.
    fn finalize_into(&mut self, out: &mut [u8]) {
        xor_rate(&mut self.pair, self.pos, &[0x1f]);
        xor_rate(&mut self.pair, RATE - 1, &[0x80]);
        for block in out.chunks_mut(RATE) {
            permute_private(&mut self.pair);
            extract_rate(&self.pair, 0, block);
        }
    }
}
impl Zeroize for FastSponge {
    fn zeroize(&mut self) {
        // SAFETY: exclusive initialized plain-word repr(C) object; usize and
        // u64 have equal size on the supported 64-bit accelerated targets.
        #[cfg(target_pointer_width = "64")]
        // SAFETY: On the target_pointer_width=64 path, the aligned owner consists of 50 u64 state
        // words plus one usize, exactly 51 words. The mutable self borrow is exclusive and all-zero
        // is valid for those integer fields; ct_erase_words.S only stores zeros.
        unsafe {
            crate::ct_erase::erase_struct_words(self as *mut Self as *mut u64, 51);
        }
    }
}
impl Drop for FastSponge {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for FastSponge {}
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<FastSponge>() == 51 * 8);

fn xor_rate(pair: &mut [u64; 50], offset: usize, input: &[u8]) {
    assert!(offset <= RATE && input.len() <= RATE - offset);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: The assertion bounds offset+input.len() by RATE=136. ct_transcript_xor.S reads
    // exactly that input and updates the corresponding interleaved words within initialized
    // pair[50]. The mutable pair borrow excludes input aliasing; its words are aligned, scalar
    // input loads permit byte alignment, and the aarch64 cfg admits the instructions.
    unsafe {
        pretzel44_ct_transcript_xor(pair.as_mut_ptr(), offset, input.as_ptr(), input.len());
    }
}
fn extract_rate(pair: &[u64; 50], offset: usize, out: &mut [u8]) {
    assert!(offset <= RATE && out.len() <= RATE - offset);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: The assertion bounds offset+out.len() by RATE=136. ct_transcript_extract.S reads
    // the corresponding first-lane words within initialized pair[50] and writes exactly
    // out.len() bytes. The output borrow is exclusive and disjoint from pair; scalar output
    // stores permit byte alignment and the aarch64 cfg admits the instructions.
    unsafe {
        pretzel44_ct_transcript_extract(pair.as_ptr(), offset, out.as_mut_ptr(), out.len());
    }
}
fn permute_private(pair: &mut [u64; 50]) {
    #[cfg(target_arch = "aarch64")]
    if super::available() {
        // SAFETY: public CPU feature checked, full initialized interleaved
        // state, canonical 24-word constants; leaf has one fixed round loop.
        // SAFETY: ct_transcript_permute.S reads and writes exactly 50 initialized u64 state words
        // and reads the 24 aligned RC words, with disjoint state and constants. The mutable borrow
        // is exclusive; native vector loads permit u64 alignment and super::available() checks SHA3
        // before this aarch64-only call.
        unsafe {
            pretzel44_ct_transcript_permute(pair.as_mut_ptr(), RC.as_ptr());
        }
        return;
    }
    for lane in 0..2 {
        let mut state = Zeroizing::new(core::array::from_fn(|i| pair[2 * i + lane]));
        keccak::keccak_p(&mut state, 24);
        for i in 0..25 {
            pair[2 * i + lane] = state[i];
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(concat!(
    ".text\n.globl _pretzel44_ct_transcript_xor\n.p2align 2\n_pretzel44_ct_transcript_xor:\n",include_str!("ct_transcript_xor.S"),
    ".globl _pretzel44_ct_transcript_extract\n.p2align 2\n_pretzel44_ct_transcript_extract:\n",include_str!("ct_transcript_extract.S"),
    ".arch armv8.4-a+sha3\n.globl _pretzel44_ct_transcript_permute\n.p2align 2\n_pretzel44_ct_transcript_permute:\n",include_str!("ct_transcript_permute.S")),options(raw));
// SAFETY: contract of the three assembly routines defined just above. `pair` is 50 words, two
// Keccak states interleaved word by word. `pretzel44_ct_transcript_xor` reads `count` bytes at
// `input` and reads and writes whole 16-byte word pairs of `pair` for the rate bytes `offset` to
// `offset + count`; `pretzel44_ct_transcript_extract` reads the first lane of the same words and
// writes `count` bytes at `out`. For both the caller must keep `offset + count` at most 136; they
// use base instructions, no stack and x0 to x8 only. `pretzel44_ct_transcript_permute` reads and
// writes exactly 50 words at `pair` and reads 24 words at `rc`; it uses the SHA-3 instructions,
// assembled under `.arch armv8.4-a+sha3`, so the caller must have checked FEAT_SHA3 at run time,
// and it saves and restores d8 to d15 in a 64-byte frame that it clears. None needs an alignment,
// keeps a pointer or has global state.
#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn pretzel44_ct_transcript_xor(pair: *mut u64, offset: usize, input: *const u8, count: usize);
    fn pretzel44_ct_transcript_extract(pair: *const u64, offset: usize, out: *mut u8, count: usize);
    fn pretzel44_ct_transcript_permute(pair: *mut u64, rc: *const u64);
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };

    #[test]
    fn partial_words_match_independent_byte_oracle_and_preserve_guards() {
        for offset in 0..=RATE {
            for count in 0..=RATE - offset {
                let input: Vec<u8> = (0..count + 9)
                    .map(|i| (i * 73 + offset + count) as u8)
                    .collect();
                // Unequal lanes verify that XOR preserves both preimages,
                // rather than copying the first lane over the second.
                let mut storage = core::array::from_fn::<_, 54, _>(|i| {
                    (i as u64).wrapping_mul(0x812c_fa96_483e_057b)
                });
                let original = storage;
                let pair: &mut [u64; 50] = (&mut storage[2..52]).try_into().unwrap();
                let mut want = *pair;
                for (i, &b) in input[1..count + 1].iter().enumerate() {
                    let pos = offset + i;
                    let v = (b as u64) << (8 * (pos % 8));
                    want[2 * (pos / 8)] ^= v;
                    want[2 * (pos / 8) + 1] ^= v;
                }
                xor_rate(pair, offset, &input[1..count + 1]);
                assert_eq!(*pair, want);
                let mut out = vec![0xa5; count + 2];
                extract_rate(pair, offset, &mut out[1..count + 1]);
                for (i, &b) in out[1..count + 1].iter().enumerate() {
                    let pos = offset + i;
                    assert_eq!(b, (want[2 * (pos / 8)] >> (8 * (pos % 8))) as u8);
                }
                assert_eq!((out[0], out[count + 1]), (0xa5, 0xa5));
                assert_eq!(&storage[..2], &original[..2]);
                assert_eq!(&storage[52..], &original[52..]);
            }
        }
    }

    #[test]
    fn private_permutation_matches_independent_scalar_lanes() {
        let mut seed = 0x5811_ac79_8934_efd3u64;
        for case in 0..128 {
            let mut pair = core::array::from_fn(|i| {
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
            let mut want = pair;
            for lane in 0..2 {
                let mut state = core::array::from_fn(|i| want[2 * i + lane]);
                keccak::keccak_p(&mut state, 24);
                for i in 0..25 {
                    want[2 * i + lane] = state[i];
                }
            }
            permute_private(&mut pair);
            assert_eq!(pair, want);
        }
    }

    #[test]
    fn every_padding_position_and_chunk_boundary_matches_original_shake() {
        for len in (0..=2 * RATE).chain([3 * RATE - 1, 3 * RATE, 3 * RATE + 1, 1024, 8193, 65537]) {
            let input: Vec<u8> = (0..len).map(|i| (i * 29 + len) as u8).collect();
            let mut hash = Shake256::default();
            hash.update(&input);
            let mut reference = hash.finalize_xof();
            let mut want = [0u8; 4097];
            reference.read(&mut want);
            for chunk in [1, 2, 7, 8, 9, 15, 16, 17, 135, 136, 137, 1024, 8192] {
                let mut sponge = FastSponge::new();
                for part in input.chunks(chunk) {
                    sponge.absorb(part);
                    sponge.absorb(&[]);
                }
                let mut got = [0u8; 4097];
                sponge.finalize_into(&mut got);
                assert_eq!(got, want, "len={len}, chunk={chunk}");
            }
        }
    }

    #[test]
    fn framed_private_continuations_preserve_prefix_and_all_output_sizes() {
        for len in 0..=RATE {
            let prefix: Vec<u8> = (0..len).map(|i| (i * 31 + len) as u8).collect();
            let mut sponge = FastSponge::new();
            sponge.absorb(&prefix);
            let prefix_pair = sponge.pair;
            let prefix_pos = sponge.pos;
            for n in [0usize, 1, 7, 8, 135, 136, 137, 1024, 8193] {
                let private = vec![n as u8; n];
                let parts: &[&[u8]] = &[b"", b"context", &private];
                let mut hash = Shake256::default();
                hash.update(&prefix);
                for part in parts {
                    hash.update(&(part.len() as u64).to_le_bytes());
                    hash.update(part);
                }
                let mut reference = hash.finalize_xof();
                let mut want = [0u8; 4097];
                reference.read(&mut want);
                assert_eq!(sponge.hash::<0>(parts), []);
                assert_eq!(&sponge.hash::<1>(parts), &want[..1]);
                assert_eq!(&sponge.hash::<32>(parts), &want[..32]);
                assert_eq!(&sponge.hash::<64>(parts), &want[..64]);
                assert_eq!(&sponge.hash::<135>(parts), &want[..135]);
                assert_eq!(&sponge.hash::<136>(parts), &want[..136]);
                assert_eq!(&sponge.hash::<137>(parts), &want[..137]);
                assert_eq!(sponge.hash::<4097>(parts), want);
                assert_eq!(sponge.pair, prefix_pair);
                assert_eq!(sponge.pos, prefix_pos);
            }
        }
    }

    #[test]
    fn real_owner_drop_erases_full_extent_on_return_and_unwind() {
        use core::mem::ManuallyDrop;
        #[repr(C)]
        struct Guarded {
            before: [u64; 2],
            sponge: ManuallyDrop<FastSponge>,
            after: [u64; 2],
        }
        // The test keeps the allocation alive after invoking the real Drop,
        // so its initialized plain-word bytes can be observed without reuse.
        struct InPlaceOwner(*mut FastSponge);
        impl Drop for InPlaceOwner {
            fn drop(&mut self) {
                unsafe {
                    core::ptr::drop_in_place(self.0);
                }
            }
        }
        for panic in [false, true] {
            let mut storage = Guarded {
                before: [0xa5; 2],
                sponge: ManuallyDrop::new(FastSponge::new()),
                after: [0x5a; 2],
            };
            let ptr = (&mut *storage.sponge) as *mut FastSponge;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _owner = InPlaceOwner(ptr);
                // SAFETY: the in-place guard owns the live object until exit;
                // no other live state reference exists during these calls.
                unsafe {
                    (*ptr).absorb(&[0x6d; 1025]);
                }
                if panic {
                    panic!("private transcript unwind control");
                }
            }));
            assert_eq!(result.is_err(), panic);
            // Drop erases but does not deallocate or invalidate plain byte
            // storage. ManuallyDrop prevents a second destructor invocation.
            let bytes = unsafe {
                core::slice::from_raw_parts(ptr.cast::<u8>(), core::mem::size_of::<FastSponge>())
            };
            assert!(bytes.iter().all(|&b| b == 0));
            assert_eq!(storage.before, [0xa5; 2]);
            assert_eq!(storage.after, [0x5a; 2]);
        }
    }
}

// Public-input only: a consuming, once-padded continuation.
impl FastSponge {
    pub(crate) fn into_public_reader(mut self) -> PublicSqueezeReader {
        xor_rate(&mut self.pair, self.pos, &[0x1f]);
        xor_rate(&mut self.pair, RATE - 1, &[0x80]);
        PublicSqueezeReader {
            sponge: self,
            pos: RATE,
            #[cfg(test)]
            operations: [0; 3],
        }
    }
}
pub(crate) struct PublicSqueezeReader {
    sponge: FastSponge,
    pos: usize,
    // Output permutation calls, extraction calls, extracted bytes; not cycles.
    #[cfg(test)]
    operations: [usize; 3],
}
impl PublicSqueezeReader {
    pub(crate) fn fill_public(&mut self, out: &mut [u8]) {
        self.fill_with(out, permute_private);
    }
    fn fill_with(&mut self, mut out: &mut [u8], permute: fn(&mut [u64; 50])) {
        while !out.is_empty() {
            if self.pos == RATE {
                permute(&mut self.sponge.pair);
                self.pos = 0;
                #[cfg(test)]
                {
                    self.operations[0] += 1;
                }
            }
            let n = out.len().min(RATE - self.pos);
            extract_rate(&self.sponge.pair, self.pos, &mut out[..n]);
            self.pos += n;
            #[cfg(test)]
            {
                self.operations[1] += 1;
                self.operations[2] += n;
            }
            out = &mut out[n..];
        }
    }
    #[cfg(test)]
    pub(crate) fn test_operations(&self) -> [usize; 3] {
        self.operations
    }
}
impl Drop for PublicSqueezeReader {
    fn drop(&mut self) {
        self.pos.zeroize();
        #[cfg(test)]
        self.operations.zeroize();
        // Automatic field destruction invokes the FastSponge Drop.
    }
}

#[cfg(test)]
mod public_reader_tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    fn scalar(pair: &mut [u64; 50]) {
        for lane in 0..2 {
            let mut state = Zeroizing::new(core::array::from_fn(|i| pair[2 * i + lane]));
            keccak::keccak_p(&mut state, 24);
            for i in 0..25 {
                pair[2 * i + lane] = state[i];
            }
        }
    }
    #[test]
    fn public_reader_padding_splits_and_scalar_dispatch_match_shake() {
        for len in 0..=2 * RATE {
            let input: Vec<u8> = (0..len).map(|i| (i * 37 + len) as u8).collect();
            let mut h = Shake256::default();
            h.update(&input);
            let mut want = [0u8; 4097];
            h.finalize_xof().read(&mut want);
            for chunk in [1, 2, 3, 7, 8, 135, 136, 137, 1024, 4097] {
                for forced_scalar in [false, true] {
                    let mut sponge = FastSponge::new();
                    sponge.absorb(&input);
                    let mut reader = sponge.into_public_reader();
                    let mut got = [0u8; 4097];
                    reader.fill_public(&mut []);
                    assert_eq!(reader.test_operations(), [0; 3]);
                    for out in got.chunks_mut(chunk) {
                        if forced_scalar {
                            reader.fill_with(out, scalar);
                        } else {
                            reader.fill_public(out);
                        }
                    }
                    assert_eq!(got, want, "len={len} chunk={chunk} scalar={forced_scalar}");
                    assert_eq!(reader.test_operations()[0], (got.len() + RATE - 1) / RATE);
                    assert_eq!(reader.test_operations()[2], got.len());
                    let before = reader.test_operations();
                    reader.fill_public(&mut []);
                    assert_eq!(reader.test_operations(), before);
                }
            }
        }
    }
    #[test]
    fn public_reader_drop_erases_owned_sponge_on_return_and_unwind() {
        use core::mem::ManuallyDrop;
        #[repr(C)]
        struct Guarded {
            before: [u64; 2],
            reader: ManuallyDrop<PublicSqueezeReader>,
            after: [u64; 2],
        }
        struct Owner(*mut PublicSqueezeReader);
        impl Drop for Owner {
            fn drop(&mut self) {
                unsafe {
                    core::ptr::drop_in_place(self.0);
                }
            }
        }
        for panic in [false, true] {
            let mut sponge = FastSponge::new();
            sponge.absorb(&[0x71; 1771]);
            let mut storage = Guarded {
                before: [0xa5; 2],
                reader: ManuallyDrop::new(sponge.into_public_reader()),
                after: [0x5a; 2],
            };
            let ptr = (&mut *storage.reader) as *mut PublicSqueezeReader;
            // Capture plain byte addresses before invoking the real destructor.
            let state = unsafe { core::ptr::addr_of!((*ptr).sponge).cast::<u8>() };
            let pos = unsafe { core::ptr::addr_of!((*ptr).pos) };
            let counters = unsafe { core::ptr::addr_of!((*ptr).operations) };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _owner = Owner(ptr);
                let mut out = Zeroizing::new([0u8; 137]);
                unsafe {
                    (*ptr).fill_public(&mut out[..]);
                }
                if panic {
                    panic!("public reader cleanup control");
                }
            }));
            assert_eq!(result.is_err(), panic);
            assert!(unsafe {
                core::slice::from_raw_parts(state, core::mem::size_of::<FastSponge>())
            }
            .iter()
            .all(|&b| b == 0));
            assert_eq!(unsafe { pos.read() }, 0);
            assert_eq!(unsafe { counters.read() }, [0; 3]);
            assert_eq!(storage.before, [0xa5; 2]);
            assert_eq!(storage.after, [0x5a; 2]);
        }
    }
}

#[cfg(test)]
mod paired_public_prefix_tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    fn old(domain: &[u8], profile: &[u8], pk: &[u8]) -> FastSponge {
        let mut s = FastSponge::new();
        s.absorb(domain);
        s.part(profile);
        s.part(pk);
        s
    }
    fn check(domains: [&[u8]; 2], profile: &[u8], pk: &[u8]) {
        let actual = FastSponge::public_prefix_pair(domains, profile, pk);
        for lane in 0..2 {
            let expected = old(domains[lane], profile, pk);
            assert_eq!(actual[lane].pair, expected.pair);
            assert_eq!(actual[lane].pos, expected.pos);
            for length in [0, 1, 7, 8, 135, 136, 137, 273] {
                let continuation = vec![0xa7; length];
                let parts: [&[u8]; 3] = [b"", &continuation, b"tail"];
                assert_eq!(
                    actual[lane].hash::<321>(&parts),
                    expected.hash::<321>(&parts)
                );
                let mut oracle = Shake256::default();
                oracle.update(domains[lane]);
                for p in [profile, pk].into_iter().chain(parts) {
                    oracle.update(&(p.len() as u64).to_le_bytes());
                    oracle.update(p);
                }
                let mut output = [0; 321];
                oracle.finalize_xof().read(&mut output);
                assert_eq!(actual[lane].hash::<321>(&parts), output);
            }
        }
    }
    #[test]
    fn paired_prefix_exact_states_and_continuations_at_rate_boundaries() {
        for n in [
            0, 1, 7, 8, 15, 16, 119, 120, 121, 135, 136, 137, 255, 256, 271, 272, 273, 1728,
        ] {
            let pk: Vec<u8> = (0..n).map(|i| (i * 73 + 19) as u8).collect();
            check(
                [crate::params::DOM_MSG, crate::params::DOM_CHAL],
                crate::params::PROFILE_ID,
                &pk,
            );
        }
    }
    #[test]
    fn paired_prefix_unequal_domains_profiles_and_full_block_counts() {
        for a in [0, 1, 135, 136, 137, 409] {
            for b in [0, 12, 13, 136, 273] {
                let d0 = vec![0x38; a];
                let d1 = vec![0xd1; b];
                check([&d0, &d1], b"profile", &[0x19; 277]);
            }
        }
    }
    #[test]
    fn public_word_cursor_all_segment_residues_and_exhaustion() {
        // All five segment lengths modulo eight, including empty chains.
        for shape in 0usize..32768 {
            let lengths: [usize; 5] = core::array::from_fn(|i| (shape >> (3 * i)) & 7);
            let buffers: [Vec<u8>; 5] = core::array::from_fn(|i| {
                (0..lengths[i]).map(|j| (i * 53 + j * 17) as u8).collect()
            });
            let parts: [&[u8]; 5] = core::array::from_fn(|i| buffers[i].as_slice());
            let expected: Vec<u8> = buffers.iter().flatten().copied().collect();
            let mut cursor = PublicPrefixCursor::new(parts);
            let mut actual = Vec::new();
            for _ in 0..expected.len() / 8 {
                actual.extend_from_slice(&cursor.next_word().to_le_bytes());
            }
            let mut tail = Zeroizing::new([0u8; 7]);
            let n = cursor.fill(&mut tail[..]);
            actual.extend_from_slice(&tail[..n]);
            assert_eq!(actual, expected);
            assert_eq!(cursor.fill(&mut tail[..]), 0);
        }
        // Invalid complete-word requests must fail, including the boundary-scratch path.
        for n in 0..8 {
            let bytes = vec![0x5a; n];
            let result = std::panic::catch_unwind(|| {
                let mut cursor = PublicPrefixCursor::new([&[], &bytes, &[], &[], &[]]);
                cursor.next_word();
            });
            assert!(result.is_err());
        }
        // Long contiguous words, odd offsets, repeated reads and exact exhaustion.
        for offset in 0..8 {
            let bytes: Vec<u8> = (0..4096).map(|i| i as u8).collect();
            let parts: [&[u8]; 5] = [
                &[],
                &bytes[offset..offset + 1],
                &[],
                &bytes[offset + 1..],
                &[],
            ];
            let mut cursor = PublicPrefixCursor::new(parts);
            let expected = &bytes[offset..];
            for word in expected.chunks_exact(8) {
                assert_eq!(cursor.next_word().to_le_bytes().as_slice(), word);
            }
            let mut tail = Zeroizing::new([0u8; 8]);
            let n = cursor.fill(&mut tail[..]);
            assert_eq!(&tail[..n], expected.chunks_exact(8).remainder());
        }
    }
    #[test]
    fn public_word_prefix_boundary_fields_unequal_blocks_and_sha3() {
        for domain_len in 0..8 {
            for profile_len in 0..8 {
                let d0 = vec![0x31; domain_len];
                let d1 = vec![0x72; domain_len + 409];
                let profile = vec![0xe3; profile_len];
                for pk_len in [0, 7, 8, 135, 136, 137, 1728] {
                    let pk: Vec<u8> = (0..pk_len).map(|i| (i * 29 + 7) as u8).collect();
                    check([&d0, &d1], &profile, &pk);
                }
            }
        }
    }
}

// Packed public profile only. This does not handle private inputs or
// alter FastSponge's representation, private continuations, or destructor.
#[cfg(test)]
impl FastSponge {
    pub(crate) fn public_dither_prefix_pair<R>(
        dither_parts: [&[u8]; 7],
        domains: [&[u8]; 2],
        profile: &[u8],
        pk: &[u8],
        consume: impl FnOnce(&mut dyn FnMut(&mut [u8])) -> R,
    ) -> (R, [Self; 2]) {
        Self::public_dither_prefix_pair_with(
            dither_parts,
            domains,
            profile,
            pk,
            consume,
            permute_private,
        )
    }
    fn public_dither_prefix_pair_with<R>(
        dither_parts: [&[u8]; 7],
        domains: [&[u8]; 2],
        profile: &[u8],
        pk: &[u8],
        consume: impl FnOnce(&mut dyn FnMut(&mut [u8])) -> R,
        mut permute: impl FnMut(&mut [u64; 50]),
    ) -> (R, [Self; 2]) {
        // Seven slices: domain, profile length/profile, core length/core,
        // seed length/seed. Never reinterpret these as a five-part key frame.
        assert_eq!(dither_parts.iter().map(|p| p.len()).sum::<usize>(), 1782);
        assert_eq!(profile.len(), 14);
        assert_eq!(pk.len(), 1728);
        assert_eq!(domains.map(|d| d.len()), [13, 14]);
        let profile_len = (profile.len() as u64).to_le_bytes();
        let pk_len = (pk.len() as u64).to_le_bytes();
        let mut dither = PublicPrefixCursor::new(dither_parts);
        let mut message = PublicPrefixCursor::new([domains[0], &profile_len, profile, &pk_len, pk]);
        let mut challenge =
            PublicPrefixCursor::new([domains[1], &profile_len, profile, &pk_len, pk]);
        let mut pair = Zeroizing::new([0u64; 50]);
        for _ in 0..13 {
            for w in 0..RATE / 8 {
                pair[2 * w] ^= dither.next_word();
                pair[2 * w + 1] ^= message.next_word();
            }
            permute(&mut pair);
        }
        let mut message_owner = Self {
            pair: core::array::from_fn(|i| pair[2 * (i / 2) + 1]),
            pos: 0,
        };
        let mut tail = Zeroizing::new([0u8; RATE]);
        let n = message.fill(&mut tail[..]);
        assert_eq!(n, 3);
        message_owner.absorb(&tail[..n]); // Unfinished position3, never padded.
        tail.zeroize();
        let n = dither.fill(&mut tail[..]);
        assert_eq!(n, 14);
        for (i, &b) in tail[..n].iter().enumerate() {
            pair[2 * (i / 8)] ^= (b as u64) << (8 * (i % 8));
        }
        pair[2] ^= 0x1fu64 << (8 * (14 % 8));
        pair[2 * (135 / 8)] ^= 0x80u64 << (8 * (135 % 8));
        // Padding does not permute. First refill performs the first squeeze.
        for w in 0..25 {
            pair[2 * w + 1] = 0;
        }
        let mut challenge_owner = None;
        let mut challenge_blocks = 0;
        let mut pos = RATE;
        let mut fetched = 0;
        let mut fill = |mut out: &mut [u8]| {
            assert!(out.len() <= 3072 - fetched, "public dither cutoff");
            fetched += out.len();
            while !out.is_empty() {
                if pos == RATE {
                    if challenge_blocks < 13 {
                        for w in 0..RATE / 8 {
                            pair[2 * w + 1] ^= challenge.next_word();
                        }
                    }
                    permute(&mut pair);
                    pos = 0;
                    if challenge_blocks < 13 {
                        challenge_blocks += 1;
                        if challenge_blocks == 13 {
                            let mut owner = Self {
                                pair: core::array::from_fn(|i| pair[2 * (i / 2) + 1]),
                                pos: 0,
                            };
                            tail.zeroize();
                            let n = challenge.fill(&mut tail[..]);
                            assert_eq!(n, 4);
                            owner.absorb(&tail[..n]); // Unfinished position4.
                            challenge_owner = Some(owner);
                        }
                    }
                }
                let n = out.len().min(RATE - pos);
                // The extractor reads lane0 only; lane1 may be unrelated.
                extract_rate(&pair, pos, &mut out[..n]);
                pos += n;
                out = &mut out[n..];
            }
        };
        let result = consume(&mut fill);
        // The only production consumer needs >=1024 words (16 rate blocks).
        // A too-short internal consumer is a programming error, never an oracle.
        let challenge_owner =
            challenge_owner.expect("public dither consumer shorter than prefix schedule");
        (result, [message_owner, challenge_owner])
    }
}

#[cfg(test)]
mod three_public_schedule_tests {
    use super::*;
    use sha3::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256,
    };
    const PROFILE: &[u8] = b"pretzel-pk13v1";
    const DOMAINS: [&[u8]; 2] = [b"LILT-AC-3:msg", b"LILT-AC-3:chal"];
    fn run<R>(
        pk: &[u8],
        consume: impl FnOnce(&mut dyn FnMut(&mut [u8])) -> R,
    ) -> (R, [FastSponge; 2], usize) {
        let profile_len = 14u64.to_le_bytes();
        let core_len = 1696u64.to_le_bytes();
        let seed_len = 32u64.to_le_bytes();
        let mut calls = 0;
        let (result, owners) = FastSponge::public_dither_prefix_pair_with(
            [
                b"LILT-DITH-KEY-v1",
                &profile_len,
                PROFILE,
                &core_len,
                &pk[..1696],
                &seed_len,
                &pk[1696..],
            ],
            DOMAINS,
            PROFILE,
            pk,
            consume,
            |pair| {
                calls += 1;
                permute_private(pair);
            },
        );
        (result, owners, calls)
    }
    fn check_owners(pk: &[u8], owners: &[FastSponge; 2]) {
        let old = FastSponge::public_prefix_pair(DOMAINS, PROFILE, pk);
        for lane in 0..2 {
            assert_eq!(owners[lane].pair, old[lane].pair);
            assert_eq!(owners[lane].pos, 3 + lane);
            for n in [0, 1, 135, 136, 137, 511] {
                let suffix = vec![0x39; n];
                let parts: [&[u8]; 3] = [b"", &suffix, b"tail"];
                let mut oracle = Shake256::default();
                oracle.update(DOMAINS[lane]);
                for part in [PROFILE, pk].into_iter().chain(parts) {
                    oracle.update(&(part.len() as u64).to_le_bytes());
                    oracle.update(part);
                }
                let mut expected = [0u8; 321];
                oracle.finalize_xof().read(&mut expected);
                assert_eq!(owners[lane].hash::<321>(&parts), expected);
                assert_eq!(
                    owners[lane].hash::<321>(&parts),
                    old[lane].hash::<321>(&parts)
                );
            }
        }
    }
    #[test]
    fn three_public_schedule_real_bytes_unfinished_prefixes_and_first_block() {
        for case in 0..8 {
            let pk: Vec<u8> = (0..1728).map(|i| (i * 73 + case * 19) as u8).collect();
            let mut oracle = Shake256::default();
            oracle.update(b"LILT-DITH-KEY-v1");
            for part in [PROFILE, &pk[..1696], &pk[1696..]] {
                oracle.update(&(part.len() as u64).to_le_bytes());
                oracle.update(part);
            }
            let mut expected = [0u8; 3072];
            oracle.finalize_xof().read(&mut expected);
            let (_, owners, calls) = run(&pk, |fill| {
                let mut actual = [0u8; 3072];
                // Deliberately split the first block and cross rate boundaries.
                let mut at = 0;
                for n in [1, 135, 137, 271, 2528] {
                    fill(&mut actual[at..at + n]);
                    at += n;
                }
                assert_eq!(at, 3072);
                assert_eq!(actual, expected);
            });
            assert_eq!(calls, 36);
            check_owners(&pk, &owners);
        }
    }
    #[test]
    fn three_public_schedule_all_cutoffs_save_exactly_thirteen_calls() {
        let pk = [0x2du8; 1728];
        // Production acceptance needs at least 1024 words. Exercise every possible
        // last acceptance and exact physical refill extent, without early extra reads.
        for last in 1023..1536 {
            let words = last + 1;
            let physical = ((2 * words + 135) / 136 * 136).min(3072);
            let (_, owners, calls) = run(&pk, |fill| {
                let mut block = [0u8; 136];
                let mut fetched = 0;
                while fetched < physical {
                    let n = (3072 - fetched).min(136);
                    fill(&mut block[..n]);
                    fetched += n;
                }
                assert_eq!(fetched, physical);
            });
            let old_calls = 13 + (physical + 135) / 136 + 13;
            assert_eq!(calls + 13, old_calls);
            assert_eq!(owners[0].pos, 3);
            assert_eq!(owners[1].pos, 4);
        }
        // Exhaustion consumes the same maximum23 squeeze blocks, no24th block.
        let (_, _, calls) = run(&pk, |fill| {
            let mut out = [0u8; 3072];
            fill(&mut out);
        });
        assert_eq!(calls, 36);
    }
}
