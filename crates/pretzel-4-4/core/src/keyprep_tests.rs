// Written for native execution only.
mod keyprep_equivalence {
 use super::*;
 struct Tape(Xof);
 impl Tape { fn new(i: u64, domain: &[u8]) -> Self { Self(Xof::new(domain, &[&i.to_le_bytes()])) } }
 impl EntropySource for Tape {
  fn fill(&mut self, out: &mut [u8]) -> Result<(), crate::EntropyError> { self.0.fill(out); Ok(()) }
 }
 #[test]
 fn keyprep_256_deterministic_keys_sign_verify_and_reject_malformed() {
  #[cfg(all(any(target_os = "linux", target_os = "macos"), target_arch = "aarch64"))]
  let _guard = crate::timing_state::Guard::enter().unwrap();
  let ctx = Ctx::new();
  let mut scratch_a = SigningScratch::new();
  for i in 0..256u64 {
   let pair = keygen_with_entropy(&ctx, &mut Tape::new(i,b"keyprep-l1-keys")).unwrap();
   let a = PreparedSk::new(&pair.sk).unwrap();
   assert_eq!(a.public_key(), pair.pk.as_slice());
   let msg = i.to_le_bytes();
   let sa = prepared_signer::sign_rice_prepared_using_scratch(&ctx, &a, b"keyprep", &msg, &mut Tape::new(i,b"keyprep-l1-sign"), &mut scratch_a).unwrap();
   rice_verify::PreparedRice.verify(&a.ppk, b"keyprep", &msg, &sa.0).unwrap();
   let mut bad = Zeroizing::new(pair.sk.to_vec());
   // Fixed final byte of digest, code 3 in a packed trit, and bad envelope.
   for offset in [0, 14 + 32, 14 + 32 + (ELL + M)*N/4 + 63] {
    bad.copy_from_slice(&pair.sk); if offset == 14+32 { bad[offset] |= 3; } else { bad[offset] ^= 1; }
    assert!(PreparedSk::new(&bad).is_err());
   }
  }
 }
}
