# Pretzel-(5,5)

The `pretzel-5-5` crate implements the rank-five parameter set: 1908-byte
signatures and 2158-byte public keys. It is research code, not audited.

## Entry points

The crate root exports the whole interface; `src/api.rs` holds it with the
contract of each item.

- Sizes: `SIGNATURE_BYTES` (1908), `PUBLIC_KEY_BYTES` (2158) and
  `SECRET_KEY_BYTES` (782). Serialized keys include a 14-byte format tag.
- Types: `Ctx` (public tables, built once), `Keypair`, `PreparedPk`,
  `PreparedSk`, `SigningScratch`, `SecretKey`, `Error`, and the entropy
  interface `EntropySource`, `EntropyError`, `OsEntropy`.
- Key generation: `keygen` and `keygen_with_entropy`.
- Signing from a serialized secret key: `sign`, `sign_with_context`,
  `sign_with_stats`.
- Signing with a `PreparedSk`: `sign_prepared`, `sign_prepared_with_context`,
  `sign_prepared_with_stats`, `sign_prepared_with_context_and_stats`, and
  `sign_prepared_with_scratch` with a caller-owned `SigningScratch`.
- Verification: `verify` and `verify_with_context` with a serialized public
  key, `verify_prepared` and `verify_prepared_with_context` with a
  `PreparedPk`.

The names and the order of arguments are those of the Pretzel-(4,4) crate.
These entries forward to `scheme::prepared_signer::sign_with_context_and_stats`,
`scheme::prepared_signer::sign_prepared_with_scratch` and
`scheme::verifier::PreparedVerifier`. The modules below the crate root are
hidden from the documentation and are not an interface. The signer does not
verify its output before returning it.

The crate has two Cargo features, both off by default. `conformance`
builds the known-answer replay binary and its public test entropy hooks; it
must not be enabled in an application. `stack-wipe` zeroes a fixed range of
stack after key generation, after the import of a stored secret key and after
signing; see "Stack-range wipes" below.

`samplers/` holds three path crates used only by this crate
(`samplers/proposal`, `samplers/transport-decision` and
`samplers/transport-locator`). Their tables are checked in as they are; this
repository has no generator for them. `samplers/proposal` holds the code the
signer reaches through `conditional_initial::generate` and stores no fixture
file: its tests rebuild their record sets, and
[`samplers/generators`](samplers/generators/README.md) describes the rules
and holds a second, independent computation of the same sets.
`samplers/transport-decision/src/decision-fixtures.bin` is checked in as it
is. Several
source files are read from `../pretzel-4-4/core/src` through relative
paths.

## Key generation

Each key candidate is expanded from a 64-byte key seed, and the SHAKE256
input is the key-seed domain, then the length-prefixed parameter-set
identifier, then the length-prefixed seed (107 bytes). Pretzel-(3,3) and
Pretzel-(4,4) hash a 32-byte seed with no identifier (53 bytes), so the three
crates do not share one key-derivation layout. The test
`profile_key_and_prefix_known_answers` in `src/public_known_answer_tests.rs`
pins the first 64 output bytes for one seed.

After fixing the public core, key generation makes one 32-byte entropy request,
which is its last. The value determines the candidate dither seeds, visited in
increasing order modulo $2^{256}$. Key generation returns the first candidate
whose bounded expansion succeeds, reading at most 1664 words to obtain 1280
coefficients, and fails if none of 2048 candidates expands. It never generates
or tests public rows, and a failed setup never resamples the secret core.

The [row certificate](certificates/rank5-dither/README.md) bounds the
probability that the reference row of the paper fails, and the probability
that the bounded expansion of one candidate fails.

`tests/vectors/keygen-vectors.bin` records public keys, secret keys and entropy
requests for 64 public seeds. The fixture holds one more 32-byte entropy request
per seed than key generation makes; the test in `src/keygen_fixture_tests.rs`
requires the same keys and the same requests up to that last one.

## Build and test

Apple silicon, macOS 15.2 or later, Xcode Command Line Tools, Rust 1.90.0.
From the repository root:

```sh
export MACOSX_DEPLOYMENT_TARGET=15.2
cargo build --locked --release --manifest-path crates/pretzel-5-5/Cargo.toml --lib
export RUSTFLAGS='-C target-feature=+sha3,+dotprod'
cargo test --locked --release --manifest-path crates/pretzel-5-5/Cargo.toml -- --test-threads=1
cargo test --locked --release --manifest-path crates/pretzel-5-5/samplers/proposal/Cargo.toml --lib -- --test-threads=1
```

The first test command runs the 301 library tests and the 2 tests in `tests/`;
none is ignored. CI also runs the tests of the three sampler crates.

The native code is compiled with `xcrun clang` and archived with `xcrun ar`;
`CC` and `AR` accept paths of other executables.

## Known-answer replay

From this directory, with `RUSTFLAGS` unset:

```sh
cargo build --locked --release --features conformance --bin conformance_replay
../../target/release/conformance_replay > first.jsonl 2> first.stderr
../../target/release/conformance_replay > second.jsonl 2> second.stderr
cmp first.jsonl second.jsonl
wc -c first.jsonl
shasum -a 256 first.jsonl
```

Both outputs must have 927340 bytes and SHA-256
`94d211afde9ce23531d22611e9e4b70cb32915b35b97dd04ed00f91637b497cb`, and both
error streams must be empty. The replay uses public test entropy only and
includes error, unwinding, recovery and verification cases. The
tests of `src/signature_vector_tests.rs` check the fixed signatures, attempt counts and entropy
continuations of `src/signature_vectors.bin`.

## Generated files

`src/interval-key256-table.h` is regenerated byte for byte by
[the table generator of `crates/pretzel-4-4`](../pretzel-4-4/core/generators/README.md).

## Secret data and timing protection

Both key-generation entries enter the data-independent timing (DIT) guard
before any entropy or secret work and keep it through the destruction of
their secret owners and, with the feature `stack-wipe`, the stack wipe. `PreparedSk::new` enters the guard
before parsing; when DIT cannot be enabled it returns
`TimingProtectionUnavailable` before validating the key format. Signing from
a serialized key holds one guard across preparation, signing and the
destruction of scratch and prepared key. Prepared keys, serialized secret
keys and scratch are destroyed under their own guards. If entering a guard
fails at destruction time, the destructors still erase, with value-independent
stores over fixed or public extents, and DIT is not claimed for that cleanup.
Callbacks and signal handlers must preserve DIT while a guard is live.

The tests `erasure_runs_when_dit_entry_fails_capability_failure_class`,
`prepared_key_drop_and_caller_scratch_failure_cover_all_entry_modes` and
`panicking_parent_keeps_children_guarded_once_on_all_entry_modes` cover
cleanup when the guard cannot be entered, the destructor tree and unwinding.

### Stack-range wipes: the Cargo feature `stack-wipe`

By default the crate does not zero the stack that its entry points leave
behind: the wipes of this section are off. The only stack zeroed in every
build is the area that some assembly wrappers clear below the routine they
call. Its named secret storage is
erased as described above: the prepared key, the signing scratch and the
temporaries that are held in erasing owners. The frames that key generation, the key import and signing
leave on the stack when they return are not erased, so copies of
secret-derived values that the compiler placed in those frames stay until
something overwrites them.

The feature `stack-wipe` is off by default. It adds a wipe of a fixed range
of stack to three operations. Each wipe zeroes the range directly below one
function before that function returns: on success, on an error and on
unwinding, while the timing guard is still held. When the timing guard cannot
be entered, the function returns `TimingProtectionUnavailable` before any
secret work and without a wipe. A wipe writes only a local of its own, so no
output byte changes. Its routine has a stack frame slightly larger than its
extent, so an operation needs that much stack below the function that holds
the wipe.

| Operation | Function that holds the wipe | Bytes zeroed below it |
|---|---|---|
| Key generation | `keygen_with_entropy` | 131072 |
| Import of a stored secret key | `PreparedSk::new`, also inside `sign`, `sign_with_context` and `sign_with_stats` | 393216 |
| Signing with a prepared key | `sign_prepared_with_scratch`, which every signing entry reaches | 65536 |

Signing from a serialized key runs the wipe of the import and then the wipe
of the signer.

The extents are measured, not bounded. They were chosen from stack depths
measured on particular builds, and another compiler, build profile or caller
can change the depth. Depths measured on one macOS runner, in bytes below the
function that holds the wipe, for calls that return:

| Operation | Optimized program that links the crate | Optimized unit-test build of the library |
|---|---|---|
| Key generation | 67112 | 71456 |
| Key import | 183208 | 356096 |
| Signing with a prepared key | 27648 | 28704 |

The unit-test build of the same source was about twice as deep as the program
for the key import. For key generation only, the CI job
`level5-keygen-depth` also computes a bound from the call graph of the image
it builds; [SECRET-PATH.md](SECRET-PATH.md) states what that job checks and
what it does not. No check bounds the depth of the import or of signing.

A wipe does not erase:

- registers;
- the frame of the function that holds it, and the frames of its callers;
- anything deeper than its extent below that function.

When the import panics, two more things are not erased. The panic handler
runs below the frames of the import before the wipe does, and it may write
deeper than the extent; such words stay. After the wipe the unwinder
continues directly below `PreparedSk::new` and leaves its own state in the
top of the wiped range. That state can include saved register contents;
whether those hold secret-derived values at that point is not established.
The tests reach a panic inside the import only by injection.

Tests. With the feature, `key_import_erases_the_stack_below_its_entry` in
`tests/api.rs` fills the stack with a pattern, imports valid keys and five
invalid encodings of each, and requires every word from 4096 to 393216 bytes
below the calling frame to be zero afterwards and the pattern beyond the
extent to be intact. Without the feature this test is not compiled. No test
of this crate paints the stack around signing.

The timing lifetime tests of the library record a completion event for the
wipes of key generation and of the import (the wipe of the signer records
none), and they run in both configurations. With the feature they require
the event exactly once, with DIT on: after an import that unwinds, rejects
the key or succeeds
(`real_constructor_unwind_and_post_parse_rejection_retire_temporaries`,
`hash_consistent_malformed_shell_key_observes_constructor_temporaries`) and
once in a successful key generation
(`public_keygen_and_callback_cover_every_draw_private_work_and_cleanup`).
Without the feature the same tests require that no such event is recorded.
The event says that a wipe ran, not which bytes it erased.

With the feature and in the optimized build,
`real_constructor_unwind_and_post_parse_rejection_retire_temporaries` also
paints the stack around an import that unwinds and around a reference in
which the same wipe is held above a function that fills a local and panics.
Depths are taken below an address recorded when the wipe completes. It
requires, in both, nothing non-zero within the extent deeper than 32768 bytes
below that address, and the deepest non-zero word within 256 bytes of the
same depth in both. Whether words deeper than the extent were changed is
printed, not required. The CI job `level5-import-scrub` runs these tests with
the feature.

These are observations of optimized test builds, not bounds on the stack
depth of the import or of signing.

Not covered: process termination, aborting panics, forgotten allocations,
copies made by the compiler in registers or on the stack (by default) or
outside the wiped stack extents (with the feature `stack-wipe`), and the
instructions actually emitted. The crate does not claim that the whole
signer runs in constant time.

## License

`MIT OR Apache-2.0`; see [THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md)
for the adapted Keccak code.
