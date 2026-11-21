//! Public fixture checks at OsEntropy::fill, including partial failures and next64.
use pretzel_4_4::{EntropySource, OsEntropy};
// SAFETY: the five symbols are defined in `tests/native/entropy.c`, which
// `scripts/run_kat_replay.py` compiles and links into this program; the
// signatures match the C definitions.
unsafe extern "C" {
    fn pretzel_test_tape_reset(seed: u64, fail_at: u64, partial: i32);
    fn pretzel_test_tape_end();
    fn pretzel_test_tape_calls() -> u64;
    fn pretzel_test_tape_bytes() -> u64;
    fn pretzel_test_tape_suffix(out: *mut u8);
}
fn oracle(seed: u64, count: usize) -> Vec<u8> {
    let mut state = seed;
    let mut bytes = Vec::new();
    while bytes.len() < count {
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        bytes.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    bytes.truncate(count);
    bytes
}
fn main() {
    let mut cases = 0;
    for size in [0usize, 1, 7, 8, 31, 32, 257, 1024] {
        for fail in [false, true] {
            for partial in [false, true] {
                let seed = 0x505245545a454c00;
                // SAFETY: the call passes three integers and resets the tape of
                // this thread, which `entropy.c` keeps in thread-local storage.
                unsafe { pretzel_test_tape_reset(seed, u64::from(fail), i32::from(partial)); }
                let mut output = vec![0xa5; size];
                let result = OsEntropy.fill(&mut output);
                let failed = fail && size != 0;
                assert_eq!(result.is_err(), failed);
                let consumed = if failed { if partial { size / 2 } else { 0 } } else { size };
                let expected = oracle(seed, consumed + 64);
                assert_eq!(&output[..consumed], &expected[..consumed]);
                assert!(output[consumed..].iter().all(|byte| *byte == 0xa5));
                let mut next64 = [0u8; 64];
                // SAFETY: `next64` is 64 writable bytes and
                // `pretzel_test_tape_suffix` writes exactly 64; the other calls
                // take no pointer and touch only the tape of this thread.
                let (calls, bytes) = unsafe {
                    pretzel_test_tape_suffix(next64.as_mut_ptr());
                    let counts = (pretzel_test_tape_calls(), pretzel_test_tape_bytes());
                    pretzel_test_tape_end();
                    counts
                };
                assert_eq!(next64.as_slice(), &expected[consumed..]);
                assert_eq!(calls, u64::from(size != 0));
                assert_eq!(bytes, if failed { 0 } else { size as u64 });
                println!("size={size};fail={fail};partial={partial};calls={calls};bytes={bytes};next64={next64:?}");
                cases += 1;
            }
        }
    }
    // Inactive conformance state must still reach the real OS entropy backend.
    OsEntropy.fill(&mut [0u8; 32]).expect("inactive fixture delegates to OS entropy");
    assert_eq!(cases, 32);
    println!("entropy contract: {cases} passed");
}
