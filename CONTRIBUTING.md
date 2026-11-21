# Contributing to Pretzel

Use a focused pull request for fixes, small improvements, and documentation.
For changes to the signature or key formats, the hash domains, the samplers,
the public API, or the handling of secret data, describe the proposed design,
invariants, and validation plan before implementation.

## Setup and checks

Install Rust through rustup. [rust-toolchain.toml](rust-toolchain.toml) selects
Rust 1.90.0 with rustfmt and Clippy. Builds and tests need Apple silicon with
macOS 15.2 or later and Xcode Command Line Tools. Python 3 runs the repository
scripts without third-party packages. Run commands from the repository root.

The three crates, the backend `crates/pretzel-4-4/core` and the three sampler
crates under `crates/pretzel-5-5/samplers` are members of one workspace, with
one lockfile and one `target` directory at the repository root; each command
names a manifest:

```sh
export MACOSX_DEPLOYMENT_TARGET=15.2
export RUSTFLAGS='-C target-feature=+sha3,+dotprod'

for crate in pretzel-4-4 pretzel-3-3 pretzel-5-5; do
  cargo fmt --manifest-path "crates/$crate/Cargo.toml" --all
  cargo fmt --manifest-path "crates/$crate/Cargo.toml" --all -- --check
done

for manifest in \
  crates/pretzel-4-4/Cargo.toml \
  crates/pretzel-4-4/core/Cargo.toml \
  crates/pretzel-3-3/Cargo.toml \
  crates/pretzel-5-5/Cargo.toml; do
  cargo clippy --locked --release --manifest-path "$manifest" --all-targets -- -D warnings
  cargo clippy --locked --release --manifest-path "$manifest" --all-targets --features stack-wipe -- -D warnings
done

cargo test --locked --release --manifest-path crates/pretzel-4-4/Cargo.toml -- --test-threads=1
cargo test --locked --release --manifest-path crates/pretzel-5-5/Cargo.toml -- --test-threads=1
cargo test --locked --release --manifest-path crates/pretzel-5-5/samplers/proposal/Cargo.toml --lib -- --test-threads=1
python3 crates/pretzel-3-3/scripts/run_native_checks.py self-test
```

The known-answer replay of `crates/pretzel-4-4` also runs on a local Mac. Its
script refuses to start while `RUSTFLAGS` is set, so run it in a shell that
has not exported the variable, with a fresh or empty directory:

```sh
env -u RUSTFLAGS python3 crates/pretzel-4-4/scripts/run_kat_replay.py --output DIR
```

The checks below are pure Python (3.11 or newer) and run on any host:

```sh
python3 crates/pretzel-4-4/kat/gen_spec_tables.py --check
python3 crates/pretzel-4-4/core/generators/gen_public_tables.py --check
python3 crates/pretzel-4-4/core/generators/gen_assembly.py --check
python3 crates/pretzel-4-4/core/generators/check_sampler_bounds.py --check
python3 -B crates/pretzel-3-3/certificates/rank3-spread/certify_r3.py --self-test
python3 -B crates/pretzel-3-3/certificates/rank3-spread/certify_r3.py --check
python3 -B crates/pretzel-4-4/certificates/check_reference_tables.py --self-test
python3 -B crates/pretzel-4-4/certificates/check_reference_tables.py
python3 -B crates/pretzel-5-5/certificates/rank5-dither/certify.py --check
python3 -B crates/pretzel-4-4/certificates/rank4-spread/certify_r4_spread.py --self-test
python3 -B crates/pretzel-4-4/certificates/rank4-spread/certify_r4_spread.py --check
```

The library tests and known-answer replays of `crates/pretzel-3-3` and the
stack-depth check of `crates/pretzel-5-5` run only in CI; the workflow also
holds the commands of the known-answer replay of `crates/pretzel-5-5`. CI
also checks spelling (`typos`, allowlist in `_typos.toml`), the dependency policy of
`deny.toml` (`cargo deny`) and the documentation build with warnings denied;
see the exact commands in [the Rust workflow](.github/workflows/rust.yml). A
change that adds, removes or renames a test of `crates/pretzel-3-3` updates
`crates/pretzel-3-3/conformance/unit-tests.json` in the same pull request. A
change to `dither_setup.rs`, `dither_frame.rs`,
`public_common_prefix.rs` or `keygen_dither_check.rs` of `crates/pretzel-3-3`,
or to a cap that the certificate reads, regenerates
`crates/pretzel-3-3/certificates/rank3-spread/certificate_r3.json` (the
certificate command without `--check`) in the same pull request. The
certificates of `crates/pretzel-4-4` and `crates/pretzel-5-5` record
whole-file hashes of the sources they read; the README beside each lists
those files, and a change to one of them, comments included, regenerates
the certificate in the same pull request.

## Code conventions

Comments state invariants and reasons, not history.
Permanent tests assert the current contract against independent ground truth or
properties, and a superseded implementation is not kept as an oracle.
Malformed verifier inputs are validated before arithmetic, indexing or allocation
that could panic.
Unsafe code documents the feature, length and alignment invariants that make it
valid.

## Pull requests

Explain the problem, resulting behavior, and validation. State whether the
change can alter a signature, a key, or the instructions executed on secret
data, and how that was checked.
