# Pretzel-(3,3)

This crate implements the rank-three parameter set: 1160-byte signatures,
1326-byte public keys and 526-byte secret keys. It is research code, not
audited. The Cargo package is named `pretzel-3-3`.

## Entry points

The crate root exports the interface for the self-identifying formats;
`src/api.rs` holds it with the contract of each item.

- Sizes: `SIGNATURE_BYTES` (1160), `PUBLIC_KEY_BYTES` (1326) and
  `SECRET_KEY_BYTES` (526). Serialized keys include a 14-byte format tag.
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
These entries forward to
`scheme::prepared_signer::sign_prepared_with_context_and_stats`,
`scheme::prepared_signer::sign_prepared_with_scratch` and
`scheme::verifier::PreparedVerifier`. The modules below the crate root are
hidden from the documentation and are not an interface, with one exception:
`scheme::fixed_profile_key::TypedPublicKey` accepts the 1312-byte public-key
body without the 14-byte format tag, for a protocol that selects Pretzel-(3,3)
externally. It rebuilds the tag and builds the same `PreparedPk` as the
1326-byte format, so hash inputs are unchanged. This crate has no
`tests/dit.rs`: its DIT lifetime checks are the library tests of
`src/dit_lifetime_tests.rs`.

The crate has two Cargo features, both off by default. `conformance` builds
the two known-answer executables of `conformance/`, which take explicit
`EntropySource` tapes through the ordinary entry points; it must not be
enabled in an application. `stack-wipe` zeroes a fixed range of stack after
the import of a stored secret key and after signing; see "Stack-range wipes"
below.

Several source files are read from `../pretzel-4-4/core/src` through
relative paths, including the native C and assembly code.

## Key generation

After fixing the public core, key generation makes one 32-byte entropy request,
the first candidate dither seed, which is its last request. It selects the
first of at most 2048 candidates, visited in increasing order modulo $2^{256}$,
whose bounded expansion succeeds. Exhausted expansion skips a candidate; any
other error aborts. No public row is generated or tested.

The [spread certificate](certificates/rank3-spread/README.md) bounds the
probability that a row fails, under a condition on the public matrix that is
not checked per key.

## Build and test

Apple silicon, macOS 15.2 or later, Xcode Command Line Tools (`xcrun`),
Rust 1.90.0. From the repository root:

```sh
export MACOSX_DEPLOYMENT_TARGET=15.2
cargo build --locked --release --manifest-path crates/pretzel-3-3/Cargo.toml --lib
python3 crates/pretzel-3-3/scripts/run_native_checks.py self-test
```

`self-test` is pure Python. The other modes of the script run only in GitHub
Actions on Apple silicon and are the test commands of this crate:

```sh
RUSTFLAGS='-C target-feature=+sha3,+dotprod' python3 crates/pretzel-3-3/scripts/run_native_checks.py tests
python3 crates/pretzel-3-3/scripts/run_native_checks.py golden --output "$RUNNER_TEMP/level3-replay"
python3 crates/pretzel-3-3/scripts/run_native_checks.py keys --output "$RUNNER_TEMP/level3-replay"
```

`tests` builds the library tests, compares the list of tests in the
executable with `conformance/unit-tests.json`, runs every test, and requires
each listed result: 282 passed, 0 ignored, 0 excluded. A test that is added,
missing or reported differently fails the check. The script builds the
library tests only;
a separate step of the workflow runs `tests/api.rs`, the tests of the
crate-root interface: one by default and three with the feature `stack-wipe`.
CI runs every command of this section in both configurations; the script
takes `--features stack-wipe`, and the list of library tests is the same in
both.

`golden` and `keys` are the known-answer replays; see
[conformance](conformance/README.md).

## Secret data and timing protection

Both key-generation entries enter the data-independent timing (DIT) guard
before drawing entropy and keep it through the cleanup of their secrets.
`PreparedSk::new` guards parsing and allocation, and its secret fields are
destroyed under a fresh guard. Nested guards restore the caller's state on
return, error and unwinding. When DIT cannot be enabled, guard entry returns
`TimingProtectionUnavailable`, and key generation then draws no entropy.
Destructors still erase when entering a guard for cleanup fails. Callbacks and
signal handlers must preserve DIT while an operation is active.

### Stack-range wipes: the Cargo feature `stack-wipe`

By default the crate does not zero the stack that its entry points leave
behind: the wipes of this section are off. The only stack zeroed in every
build is the area that some assembly wrappers clear below the routine they
call. Its named secret storage is
erased as described above: the prepared key, the signing scratch and the
temporaries that are held in erasing owners. The frames that the key import and signing
leave on the stack when they return are not erased, so copies of
secret-derived values that the compiler placed in those frames stay until
something overwrites them.

The feature `stack-wipe` is off by default. It adds a wipe of a fixed range
of stack to two operations. Each wipe zeroes the range directly below one
function before that function returns: on success, on an error and on
unwinding, while the timing guard is still held. When the timing guard cannot
be entered, the function returns `TimingProtectionUnavailable` before any
secret work and without a wipe. A wipe writes only a local of its own, so no
output byte changes. Its routine has a stack frame slightly larger than its
extent, so an operation needs that much stack below the function that holds
the wipe.

| Operation | Function that holds the wipe | Bytes zeroed below it |
|---|---|---|
| Key generation | none: this crate has no wipe in key generation | |
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
| Key import | 109832 | 219088 |
| Signing with a prepared key | 29440 | 37600 |

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

The library tests record a completion event for every wipe, and they run in
both configurations. With the feature they require the event exactly once,
with DIT on: `direct_four_signer_owner_extent_and_entropy_exits` when a
signature is returned, when the entropy source returns an error and when it
panics and the signer unwinds; `secret_key_preparation_unwind_stays_guarded`,
`secret_key_preparation_bad_key_and_unsupported_restore_both_states`,
`prepared_secret_moves_preserve_allocation_and_guarded_drop` and
`caller_guard_survives_nested_preparation_and_cleanup` for an import that
unwinds, rejects the key or succeeds. Without the feature the same tests
require that no such event is recorded. In both configurations they require
no event when the timing guard cannot be entered. The event says that a wipe
ran, not which bytes it erased.

With the feature and in the optimized build,
`secret_key_preparation_unwind_stays_guarded` also paints the stack around an
import that unwinds and around a reference in which the same wipe is held
above a function that fills a local and panics. Depths are taken below an
address recorded when the wipe completes. It requires, in both, nothing
non-zero within the extent deeper than 32768 bytes below that address. The
depth of the deepest non-zero word in the import and in the reference is
printed and not required to agree: with the present extent as well as with
a smaller one, the import left words 4680 bytes deeper than the reference
(28327 against 23647 bytes). Those words are written after the wipe; what
writes them has not been identified, and it is an open item. Whether
words deeper than the extent were changed is also printed, not required.

These are observations of optimized test builds, not bounds on the stack
depth of any operation.

[SECRET-PATH.md](SECRET-PATH.md) describes how key generation packs the
secret polynomials. The crate has no stack wipe at its key-generation
entry in either configuration. It does not claim that the whole signer runs in
constant time or that copies made by the compiler in registers or outside the
erased stack extent are erased.

## License

`MIT OR Apache-2.0`; see [THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md)
for the adapted Keccak code.
