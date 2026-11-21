# Pretzel-(4,4)

The `pretzel-4-4` crate implements the rank-four parameter set: 1361-byte
signatures, 1742-byte public keys and 654-byte secret keys. It is research
code, not audited.

## Entry points

The library is `src/lib.rs`; its public items are in `src/api.rs`.

- `Ctx`, `Keypair`, `keygen`, `keygen_with_entropy`: key generation.
  `KeygenCtx` with `keygen_only` and `keygen_only_with_entropy` is a context
  for key generation alone. Only this crate has it; key generation does not
  read the context it is given.
- `sign`, `sign_with_context`, `sign_with_stats`: signing from a serialized
  secret key. `PreparedSk` with `sign_prepared`, `sign_prepared_with_context`,
  `sign_prepared_with_stats`, `sign_prepared_with_context_and_stats` and
  `sign_prepared_with_scratch` (caller-owned `SigningScratch`) sign
  repeatedly with one key.
- `verify`, `verify_with_context`; `PreparedPk` with `verify_prepared` and
  `verify_prepared_with_context`.
- `SecretKey`, `Error`, and the entropy types `EntropySource`, `EntropyError`
  and `OsEntropy`.
- The sizes `SIGNATURE_BYTES`, `PUBLIC_KEY_BYTES` and `SECRET_KEY_BYTES`
  (also `params::SIG_BYTES`, `params::PK_BYTES`, `params::SK_BYTES`). The key
  sizes include the 14-byte tag at the start of each key.

The arithmetic, samplers, codecs and native code are in the path crate
`core` (`pretzel-4-4-core`), which `crates/pretzel-3-3` and
`crates/pretzel-5-5` also read through relative paths.

The crate has two Cargo features, both off by default. `conformance` links a
public test entropy hook for the known-answer replay and must never be
enabled in an application. `stack-wipe` zeroes a fixed range of stack after
key generation, after the import of a stored secret key and after signing;
see "Stack-range wipes" below.

## Key generation

Key generation draws its seeds in 32-byte entropy requests; the last request is
the first candidate dither seed. It then selects the first of the candidate
seeds, in increasing order, whose bounded dither expansion succeeds. No public
row is generated or tested during key generation.

The [spread certificate](certificates/rank4-spread/README.md) bounds the
probability that a row fails, under a condition on the public matrix that is
not checked per key.

## Build and test

Apple silicon, macOS 15.2 or later, Xcode Command Line Tools, Rust 1.90.0.
From the repository root:

```sh
export MACOSX_DEPLOYMENT_TARGET=15.2
cargo build --locked --release --manifest-path crates/pretzel-4-4/Cargo.toml --lib
RUSTFLAGS='-C target-feature=+sha3,+dotprod' \
  cargo test --locked --release --manifest-path crates/pretzel-4-4/Cargo.toml -- --test-threads=1
```

CI runs these commands in both configurations: as written, and with
`--features stack-wipe` before the `--`. The crate has six tests in `tests/`
by default and eight with the feature. Two of them, `spec-domains` and `dit`,
each start a nested release build of `core` in a temporary target directory
and run backend tests there; the backend command below runs those tests too.

The library of `core` has 315 tests in both configurations, and CI runs all
of them. The command:

```sh
RUSTFLAGS='-C target-feature=+sha3,+dotprod' \
  cargo test --locked --release --manifest-path crates/pretzel-4-4/core/Cargo.toml \
  --lib -- --test-threads=1
```

The native code is compiled with `xcrun clang` and archived with `xcrun ar`;
`CC` and `AR` accept paths of other executables.

## Known-answer replay

```sh
python3 crates/pretzel-4-4/scripts/run_kat_replay.py --output DIR
```

`DIR` must be a fresh or empty directory and `RUSTFLAGS` must be unset. The
script builds the library with the `conformance` feature, links three
executables with the public test entropy tape of
`tests/native/entropy.c`, and checks:

1. the entropy contract (`tests/native/entropy_contract.rs`);
2. the 140 files that `tests/native/conformance.rs` writes for four
   public test keys and eight signing cases each, against the SHA-256 list
   `tests/native/fixture-inventory.json`, and its summary record;
3. `kat/pretzel-kat.txt`, written twice by `examples/spec_kat.rs` and compared
   byte for byte.

See [tests/native](tests/native/README.md).

## Generated files

`kat/gen_spec_tables.py --check` regenerates `kat/spec_domains_table.tex`, the
table of hash domain strings that the test `spec-domains` compares with the
source. [core/generators](core/generators/README.md)
regenerates 43 table files and one assembly file byte for byte.

## Secret data and timing protection

Key generation, secret-key preparation and signing enter a guard that enables
the data-independent timing (DIT) mode of the processor before any secret
work, and restore the caller's state on every returning or unwinding exit.
When the mode cannot be enabled they return `TimingProtectionUnavailable`.
Signing from a serialized key holds one guard across preparation, signing and
the destruction of the prepared key. Callbacks and signal handlers must
preserve DIT while a guard is live.

`PreparedSk::new` allocates its secret fields together; moving the owner
copies only a pointer and public fields. Secret owners and signing scratch are
erased under a guard when they are destroyed. If entering the guard fails at
destruction time, the destructors still erase, with value-independent stores
over fixed or public extents, and DIT is not claimed for that cleanup:
skipping the erasure would leave secrets in memory. The storage of an already
erased signing scratch is freed after its guard has been left.

The test `erasure_runs_when_dit_entry_fails_capability_failure_class` injects
both ways in which entering the guard can fail, with the caller's DIT state
initially off and on, and checks that the prepared key and the scratch are
erased and that the caller's state is restored.
`prepared_key_drop_and_caller_scratch_failure_cover_all_entry_modes` and
`panicking_parent_keeps_children_guarded_once_on_all_entry_modes` cover the
destructor tree and unwinding.

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
| Key generation | `keygen_with_entropy` of both key-generation entry families | 262144 |
| Import of a stored secret key | `PreparedSk::new`, also inside `sign`, `sign_with_context` and `sign_with_stats` | 393216 |
| Signing with a prepared key | the function that calls the retry loop | 73728 |

Signing from a serialized key runs the wipe of the import and then the wipe
of the signer.

The extents are measured, not bounded. They were chosen from stack depths
measured on particular builds, and another compiler, build profile or caller
can change the depth. Depths measured on one macOS runner, in bytes below the
function that holds the wipe, for calls that return:

| Operation | Optimized program that links the crate | Optimized unit-test build of the library |
|---|---|---|
| Key generation | 54224 | 55632 |
| Key import | 146712 | 287376 |
| Signing with a prepared key | 32768 | 44800 |

The unit-test build of the same source was about twice as deep as the program
for the key import. No check in this crate bounds the stack depth of an
operation against its extent.

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

Tests. With the feature, two tests in `tests/api.rs` fill the stack with a
pattern and read it back: `prepared_signing_erases_the_stack_below_its_entry`
signs through `sign_prepared_with_scratch` and `sign_prepared_with_stats` and
requires every word from 1024 to 73728 bytes below the calling frame to be
zero and the pattern beyond the extent to be intact;
`key_import_erases_the_stack_below_its_entry` imports valid keys and five
invalid encodings of each (an empty key, a truncated key, a changed format
tag, a secret coefficient code that is not allowed, a changed public-key
hash) and requires the same from 4096 to 393216 bytes. Without the feature
these two tests are not compiled.

The timing lifetime tests of the backend record a completion event for every
wipe, and they run in both configurations. With the feature they require the
event exactly once, with DIT on: after the cleanup of the attempt when
signing fails or unwinds
(`prepared_key_drop_and_caller_scratch_failure_cover_all_entry_modes`,
`real_sign_unwind_erases_leases_scratch_and_prepared_key`, which imports the
key inside the observed call and so requires two events), after every
destructor of an import that unwinds or rejects the key
(`real_constructor_unwind_and_post_parse_rejection_retire_temporaries`,
`hash_consistent_malformed_shell_key_observes_constructor_temporaries`), and
as the last event of key generation on every exit
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
printed, not required.

These are observations of optimized test builds, not bounds on the stack
depth of any operation.

Not covered: process termination, aborting panics, forgotten allocations,
copies made by the compiler in registers or on the stack (by default) or
outside the wiped stack extents (with the feature `stack-wipe`), and the
instructions actually emitted. The crate does not claim that the whole
signer runs in constant time.

## License

`MIT OR Apache-2.0`. The Keccak code adapted from other projects keeps its
notices; see [THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md) and
[the licence texts](../../licenses/keccak/).
