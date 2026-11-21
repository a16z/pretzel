# Platform, layout and checks that run only in CI

## Supported platform

Apple silicon running macOS 15.2 or later, with Xcode Command Line Tools.

- The crates use the SHA3 and dot-product instructions of the processor.
  The SHA3 instructions are detected at run time. The dot-product instruction
  is not: the build scripts of the crates stop the build unless the target
  enables the `dotprod` feature, with an error that names the flag to set.
  The Rust target for Apple silicon enables it without any flag, and every
  Apple silicon Mac has the instruction. CI also checks its hosts for
  both before the tests, and builds the tests with
  `-C target-feature=+sha3,+dotprod`.
- Key generation, secret-key preparation and signing run with the
  data-independent timing (DIT) mode of the processor enabled, through an
  interface that macOS provides from version 15.2. When DIT cannot be enabled
  these operations return `TimingProtectionUnavailable` before any secret
  work.
- A build for another target stops with an error whose text begins
  `unsupported target:`.

No other platform is supported. The sources hold no build path for another
operating system or processor.

## Layout

```
crates/pretzel-3-3      Pretzel-(3,3)
crates/pretzel-4-4      Pretzel-(4,4); the library is in src/, its backend in core/
crates/pretzel-5-5      Pretzel-(5,5); samplers/ holds three path crates used only by it
bench/mldsa-comparison  timing of the three crates against ML-DSA (not part of the crates)
paper/                  the paper that specifies the scheme (pretzel.pdf) and its licence
docs/                   platform, CI
licenses/               licence texts of adapted third-party code (THIRD-PARTY-NOTICES.md)
.github/workflows/      the CI workflow (rust.yml) and the hand-started comparison with ML-DSA
```

The three crates, the backend `crates/pretzel-4-4/core` and the three sampler
crates are members of one Cargo workspace, with one lockfile, one set of
profiles and one `target` directory at the repository root. The diagnostics
tests in `crates/pretzel-4-4/tests/diagnostics` are a separate package with
their own lockfile, and the stack-depth check of Pretzel-(5,5) builds a
generated package with `crates/pretzel-5-5/scripts/stack_depth_Cargo.lock`.
`crates/pretzel-3-3` and `crates/pretzel-5-5`
compile source files of `crates/pretzel-4-4` through relative paths, so the three
directories must keep their positions relative to each other.

## Checks that run only in CI

Three further checks run only in GitHub Actions on `macos-15`, because their
scripts refuse any other host:

- the Pretzel-(3,3) library tests, run against the list of test names in
  `crates/pretzel-3-3/conformance/unit-tests.json`
  (`python3 crates/pretzel-3-3/scripts/run_native_checks.py tests`);
- the Pretzel-(3,3) known-answer replays (the same script with `golden` and
  `keys`);
- the stack-depth check of Pretzel-(5,5) key generation
  (`crates/pretzel-5-5/scripts/stack_depth_ci.py`).

CI runs the backend tests of Pretzel-(4,4) with one `cargo test` command on
`crates/pretzel-4-4/core/Cargo.toml` (see [ci.md](ci.md)). CI wraps each test
command in `crates/pretzel-4-4/scripts/run_counted_tests.py`, which fails when
no test ran. [The workflow](../.github/workflows/rust.yml) is the authority on
every command.
