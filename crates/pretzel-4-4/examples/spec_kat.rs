//! Public deterministic KAT executable. Link only with the test entropy
//! wrapper; never use these seeds or this binary for application keys.
use pretzel_4_4::*;
use std::{fmt::Write, fs, path::PathBuf};
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
fn start(seed: u64) {
    // SAFETY: the separately linked fixture wrapper owns this thread's tape.
    unsafe { pretzel_test_tape_reset(seed, 0, 0); }
}
fn tape(seed: u64, count: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::new();
    while out.len() < count {
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        out.extend_from_slice(&(z ^ (z >> 31)).to_le_bytes());
    }
    out.truncate(count); out
}
fn finish(seed: u64) -> Vec<u8> {
    let mut suffix = [0; 64];
    // SAFETY: suffix points to 64 writable bytes; the fixture is thread-local.
    let (calls, bytes) = unsafe {
        let counts = (pretzel_test_tape_calls(), pretzel_test_tape_bytes());
        pretzel_test_tape_suffix(suffix.as_mut_ptr()); pretzel_test_tape_end(); counts
    };
    assert!(calls > 0, "entropy wrapper did not run");
    assert_eq!(bytes, 32 * calls, "unexpected entropy request size");
    let bytes = usize::try_from(bytes).unwrap();
    let mut all = tape(seed, bytes + 64);
    assert_eq!(&all[bytes..], suffix, "fixture tape reconstruction differs");
    all.truncate(bytes); all
}
fn field(out: &mut String, name: &str, value: &[u8]) {
    write!(out, "{name} = ").unwrap();
    for byte in value { write!(out, "{byte:02x}").unwrap(); }
    out.push('\n');
}
fn main() {
    let path = PathBuf::from(std::env::args().nth(1).expect("output KAT path"));
    let ctx = Ctx::new();
    let mut output = String::from("# Pretzel Appendix D KAT v1\n# PUBLIC TEST SEEDS ONLY\n# key_seed is the accepted CBD candidate; keygen_randomness is the complete input tape.\n# signing_randomness contains every attempted 32-byte entropy block in order.\n");
    for case in 0..3u64 {
        let key_seed = 0x505245545a454c00u64 + case;
        start(key_seed);
        let pair = keygen(&ctx).expect("deterministic key generation");
        let key_tape = finish(key_seed);
        // seed_a, prf, one or more CBD candidates, then the first dither candidate seed.
        assert!(key_tape.len() >= 128);
        assert_eq!(&pair.pk[14..46], &key_tape[..32]);
        let sk = PreparedSk::new(&pair.sk).unwrap();
        let message = vec![case as u8; [0, 32, 4096][case as usize]];
        let context = vec![0x80 | case as u8; [0, 1, 255][case as usize]];
        let sign_seed = 0x434f4e464f524d00u64 + case * 16 + case;
        start(sign_seed);
        let (signature, attempts) = sign_prepared_with_context_and_stats(&ctx, &sk, &context, &message)
            .expect("deterministic signing");
        let sign_tape = finish(sign_seed);
        assert_eq!(sign_tape.len(), 32 * attempts as usize);
        assert_eq!(pair.pk.len(), PUBLIC_KEY_BYTES);
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        verify_with_context(&ctx, &pair.pk, &context, &message, &signature).unwrap();
        assert!(verify_with_context(&ctx, &pair.pk, &context, &[message.as_slice(), b"wrong"].concat(), &signature).is_err());
        writeln!(output, "\n[Pretzel-(4,4) vector {case}]").unwrap();
        field(&mut output, "parameter_id", &pair.pk[..14]);
        field(&mut output, "keygen_tape_seed_le64", &key_seed.to_le_bytes());
        field(&mut output, "key_seed", &key_tape[key_tape.len()-64..key_tape.len()-32]);
        field(&mut output, "keygen_randomness", &key_tape);
        field(&mut output, "message", &message);
        field(&mut output, "context", &context);
        field(&mut output, "signing_tape_seed_le64", &sign_seed.to_le_bytes());
        field(&mut output, "signing_randomness", &sign_tape);
        field(&mut output, "public_key", &pair.pk);
        field(&mut output, "signature", &signature);
    }
    fs::write(path, output).unwrap();
}
