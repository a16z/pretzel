# Pretzel

Pretzel is a lattice signature scheme in the Fiat-Shamir with aborts line,
built on module lattices. This repository holds research implementations of
its three parameter sets. The scheme is specified in the paper
[*Pretzel: Compact Lattice Signatures from Module-LWE and Module-SIS*](paper/pretzel.pdf).

> **Status:** research code. It has not been audited. It builds and is tested
> on Apple silicon with macOS 15.2 or later only.

## Parameter sets

| Parameter set | Crate | Signature | Public key | ML-DSA counterpart (signature, public key) |
|---|---|---|---|---|
| Pretzel-(3,3) | [`crates/pretzel-3-3`](crates/pretzel-3-3) | 1160 bytes | 1326 bytes | ML-DSA-44: 2420, 1312 bytes |
| Pretzel-(4,4) | [`crates/pretzel-4-4`](crates/pretzel-4-4) | 1361 bytes | 1742 bytes | ML-DSA-65: 3309, 1952 bytes |
| Pretzel-(5,5) | [`crates/pretzel-5-5`](crates/pretzel-5-5) | 1908 bytes | 2158 bytes | ML-DSA-87: 4627, 2592 bytes |

Each crate provides key generation, signing and verification for one
parameter set; its README describes the entry points.

## Build and test

Requirements: Apple silicon, macOS 15.2 or later, Xcode Command Line Tools,
and Rust through rustup ([rust-toolchain.toml](rust-toolchain.toml) selects
Rust 1.90.0). Run the commands from the repository root.

```sh
export MACOSX_DEPLOYMENT_TARGET=15.2

cargo build --locked --release --manifest-path crates/pretzel-4-4/Cargo.toml --lib
cargo build --locked --release --manifest-path crates/pretzel-3-3/Cargo.toml --lib
cargo build --locked --release --manifest-path crates/pretzel-5-5/Cargo.toml --lib

export RUSTFLAGS='-C target-feature=+sha3,+dotprod'

cargo test --locked --release --manifest-path crates/pretzel-4-4/Cargo.toml -- --test-threads=1
cargo test --locked --release --manifest-path crates/pretzel-5-5/Cargo.toml -- --test-threads=1
cargo test --locked --release --manifest-path crates/pretzel-5-5/samplers/proposal/Cargo.toml --lib -- --test-threads=1
```

The library tests and known-answer replays of Pretzel-(3,3) and the
stack-depth check of Pretzel-(5,5) run in GitHub Actions only.

| Topic | Where |
|---|---|
| Platform requirements, repository layout, checks that run only in CI | [docs/platform.md](docs/platform.md) |
| What CI checks, and the number of tests | [docs/ci.md](docs/ci.md) |

## Cargo features

Both features exist in each of the three crates and are off by default.

| Feature | Effect |
|---|---|
| `stack-wipe` | Zeroes a fixed range of stack after the import of a stored secret key, after signing and, at Pretzel-(4,4) and Pretzel-(5,5), after key generation. |
| `conformance` | Used only by the known-answer programs, which run on public test entropy. Never enable it in an application. |

## Comparison with ML-DSA

Mean thread CPU time of Pretzel divided by that of ML-DSA from AWS-LC, in one
run on Apple silicon with the default build; below 1, Pretzel took less time.

| Operation | Pretzel-(3,3) / ML-DSA-44 | Pretzel-(4,4) / ML-DSA-65 | Pretzel-(5,5) / ML-DSA-87 |
|---|---|---|---|
| Sign (prepared secret key) | 0.9097 | 0.9329 | 0.9397 |
| Prepared verify | 0.8519 | 0.9107 | 0.8324 |
| Verify with preparation | 0.7413 | 0.5821 | 0.4955 |
| Prepare public key | 0.6705 | 0.5046 | 0.4314 |
| Key generation | 1.4845 | 1.3342 | 0.9852 |

To reproduce: `python3 -B bench/mldsa-comparison/compare.py`. The method, the
95% intervals, the figures with `stack-wipe` and what the ML-DSA rows call
are in [bench/mldsa-comparison/README.md](bench/mldsa-comparison/README.md).

## Security

Report a vulnerability privately as [SECURITY.md](SECURITY.md) describes.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Code adapted from other projects is
listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md); the benchmark
adapters under `bench/mldsa-comparison/adapters` and the patch beside them are
under Apache-2.0 only, as that page says. The paper in [`paper/`](paper/) is
licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); the
text of that licence is in [paper/LICENSE-CC-BY-4.0](paper/LICENSE-CC-BY-4.0).
