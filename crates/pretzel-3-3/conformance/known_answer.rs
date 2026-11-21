//! Prints the rank-three known-answer replay on public test seeds
//! (`write_known_answer_replay` in `known_answer_replay.rs`). The expected output is
//! `known-answer.txt`: 169093 bytes with SHA-256
//! 6f6ed860caf01c76fd7bbe7d4362016ee67a04bf233f7663d7def2a30ac613a0,
//! compared byte for byte by `scripts/run_native_checks.py golden`.
use std::io::Write;
fn main() {
    let mut out = std::io::stdout().lock();
    pretzel_3_3::scheme::prepared_signer::write_known_answer_replay(&mut out);
    out.flush().expect("stdout");
}
