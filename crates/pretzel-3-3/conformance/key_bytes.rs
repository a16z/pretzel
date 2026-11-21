//! Fixed public test seeds only. Prints serialized secret keys for equivalence.
use pretzel_3_3::scheme::{keygen_with_entropy, Ctx, PreparedPk, PreparedSk};
use pretzel_3_3::{EntropyError, EntropySource};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake256, Shake256Reader};

struct Tape {
    reader: Shake256Reader,
    calls: Vec<usize>,
}
impl Tape {
    fn new(seed: u64) -> Self {
        let mut state = Shake256::default();
        state.update(b"PRETZEL33-IMPORT-PUBLIC-KEY-BYTES-v1");
        state.update(&seed.to_le_bytes());
        Self {
            reader: state.finalize_xof(),
            calls: Vec::new(),
        }
    }
}
impl EntropySource for Tape {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EntropyError> {
        self.calls.push(out.len());
        self.reader.read(out);
        Ok(())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    let ctx = Ctx::new();
    println!("PRETZEL33-IMPORT-PUBLIC-KEY-BYTES-v1 seeds=0..16");
    for seed in 0u64..16 {
        let mut tape = Tape::new(seed);
        let pair = keygen_with_entropy(&ctx, &mut tape).expect("fixed-seed keygen");
        assert_eq!(pair.pk.len(), 1326);
        assert_eq!(pair.sk.len(), 526);
        let prepared = PreparedSk::new(pair.sk.as_ref()).expect("secret-key import");
        assert_eq!(prepared.public_key(), pair.pk.as_slice());
        let _public = PreparedPk::new(&pair.pk).expect("public-key import");
        let mut continuation = [0u8; 64];
        tape.reader.read(&mut continuation);
        println!("pk {seed} {}", hex(&pair.pk));
        println!("sk {seed} {}", hex(pair.sk.as_ref()));
        println!("entropy {seed} {:?} {}", tape.calls, hex(&continuation));
    }
}
