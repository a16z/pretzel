// Tests of the signer's word eraser against the eraser of `ct_erase.rs`.
use super::erase_struct_words;
const CANARY: u64 = 0x5a5a_c3c3_0f0f_a5a5;

fn check(offset: usize, words: usize) {
    #[repr(C, align(64))]
    struct Frame([u64; 9000]);
    let mut actual = Box::new(Frame([CANARY; 9000]));
    let mut reference = Box::new(Frame([CANARY; 9000]));
    assert!(offset + words < 9000);
    for (i, (a, b)) in actual.0.iter_mut().zip(&mut reference.0).enumerate() {
        *a = CANARY ^ i as u64;
        *b = *a;
    }
    // SAFETY: `offset + words < 9000` is asserted above, so both ranges lie inside the two
    // exclusive, 64-byte-aligned arrays of 9000 words.
    unsafe {
        erase_struct_words(actual.0.as_mut_ptr().add(offset), words);
        crate::ct_erase::erase_struct_words(reference.0.as_mut_ptr().add(offset), words);
    }
    assert_eq!(actual.0, reference.0);
    for (i, &value) in actual.0.iter().enumerate() {
        let expected = if (offset..offset + words).contains(&i) {
            0
        } else {
            CANARY ^ i as u64
        };
        assert_eq!(value, expected, "offset {offset} words {words} index {i}");
    }
}

#[test]
fn every_alignment_and_length_matches_shared_eraser_with_canaries() {
    for offset in 0..16 {
        for words in 0..300 {
            check(offset, words);
        }
        for words in [1023, 1024, 1025, 4206, 6950, 8192, 8960] {
            check(offset, words);
        }
    }
}

#[test]
fn large_signer_extents_match_shared_eraser() {
    for words in [
        33648 / 8,
        core::mem::size_of::<crate::scratch::Buffers>() / 8,
        2816 * 4 / 8,
        // The extent, in words, that the signer's stack-range wipe uses with the feature
        // `stack-wipe`; written out so that the eraser is tested at this length in both
        // configurations.
        8192,
    ] {
        check(1, words);
        check(8, words);
    }
}

#[test]
fn empty_extent_accepts_an_aligned_dangling_pointer() {
    let ptr = core::ptr::NonNull::<u64>::dangling().as_ptr();
    // Neither implementation may access memory for an empty extent.
    // SAFETY: the count is zero and the pointer is aligned; no memory is accessed.
    unsafe {
        erase_struct_words(ptr, 0);
        crate::ct_erase::erase_struct_words(ptr, 0);
    }
}
