//! Driver of the key-generation stack-depth check (`stack_depth_ci.py`).
//!
//! Generates one key pair, then CALLS more, and checks that every key signs
//! and that its signature verifies. The checker observes the key-generation
//! calls of this process under the debugger. The driver reads no clock and
//! prints nothing.
use scheme::{Ctx, PreparedPk, PreparedSk, SigningScratch};
use std::hint::black_box;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
compile_error!("This driver requires Apple silicon macOS");

fn sign(ctx: &Ctx, sk: &PreparedSk, scratch: &mut SigningScratch, msg: &[u8])
    -> Result<(Vec<u8>, u32), scheme::Error>
{
    scheme::scheme::prepared_signer::sign_prepared_with_scratch(ctx, sk, scratch, b"", msg)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 2, "CALLS");
    let calls: usize = args[1].parse().unwrap();
    assert!(calls > 0 && calls <= 100_000);
    let ctx = Ctx::new();
    // Errors, including TimingProtectionUnavailable, terminate the process.
    let pair = scheme::keygen(&ctx).expect("keygen guard failed; no timing protection fallback");
    let sk = PreparedSk::new(&pair.sk).expect("secret key preparation failed");
    let pk = PreparedPk::new(&pair.pk).expect("public key preparation failed");
    let mut scratch = SigningScratch::new();
    let msg = [43u8; 32];
    let verifier = scheme::scheme::verifier::PreparedVerifier::new(&ctx).unwrap();
    let verify = |pk: &PreparedPk, message: &[u8], sig: &[u8]| {
        verifier.verify(pk, b"", message, sig)
    };
    let verify_raw = |raw: &[u8], message: &[u8], sig: &[u8]| {
        verifier.verify_serialized_complete(raw, b"", message, sig)
    };
    let (fixture, _) = sign(&ctx, &sk, &mut scratch, &msg).expect("sign guard failed");
    assert_eq!(fixture.len(), 1908);
    verify(&pk, &msg, &fixture).unwrap();
    verify_raw(&pair.pk, &msg, &fixture).unwrap();
    assert!(verify(&pk, &[44u8; 32], &fixture).is_err());
    assert!(verify_raw(&pair.pk, &[44u8; 32], &fixture).is_err());
    for _ in 0..calls {
        let result = black_box(scheme::keygen(black_box(&ctx)));
        // The checker injects one entropy failure and expects it to end the process here.
        let new_pair = result.expect("keygen failed; campaign invalid");
        // Every returned key must sign, and its signature must verify.
        let new_sk = PreparedSk::new(&new_pair.sk).unwrap();
        let (sig, _) = sign(&ctx, &new_sk, &mut scratch, &msg).unwrap();
        verify_raw(&new_pair.pk, &msg, &sig).unwrap();
    }
}
