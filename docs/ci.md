# What CI checks

[The workflow](../.github/workflows/rust.yml) runs on every change:

- the tests in the tree, in two configurations of the three crates: the
  default build, and the build with the Cargo feature `stack-wipe` (table
  below);
- the known-answer replays of the three parameter sets, compared with the
  recorded bytes or hashes. Each output is written twice, except the 140
  files of the Pretzel-(4,4) inventory, which are written once;
- formatting, Clippy with warnings denied (in both configurations), the
  documentation build with warnings denied, and spelling. Formatting, Clippy
  and the documentation build cover the Cargo targets of the three crates
  and of the backend, with Clippy in the default features and with
  `stack-wipe`. They do not cover:
  - the code behind the feature `conformance` of each crate, and
    the three replay programs that need it (`rank3_golden`,
    `rank3_key_bytes`, `conformance_replay`): Clippy and the documentation
    build never enable that feature;
  - the programs that scripts compile outside a Cargo target
    (`tests/native/conformance.rs`, `tests/native/entropy_contract.rs` and
    `examples/spec_kat.rs` of `crates/pretzel-4-4`, and
    `crates/pretzel-5-5/scripts/stack_depth_driver.rs`), which get neither
    the formatting check nor Clippy;
  - the files that the build scripts take in with `include!`
    (`native-build.rs` and `native-tools.rs` in `crates/pretzel-4-4/core`),
    which the formatting check does not reach;
  - the diagnostics package, which is in none of the three loops, and the
    test targets of the three sampler crates, which are not in the Clippy
    loop;
- the dependency policy: licences, advisories and sources (`deny.toml`);
- that the files with a generator are reproduced byte for byte: the hash
  domain table of Pretzel-(4,4), 43 table files of `crates/pretzel-4-4/core`
  and `crates/pretzel-5-5`, and one assembly file (the
  [generators README](../crates/pretzel-4-4/core/generators/README.md) lists
  them and the files without a generator). No file of `crates/pretzel-3-3`
  is among them;
- that the largest values the sampler tables of Pretzel-(4,4) can produce,
  recomputed from the tables, are the figures that the sources state
  (`crates/pretzel-4-4/core/generators/check_sampler_bounds.py`);
- with the feature `stack-wipe`: the stack depth of Pretzel-(5,5) key
  generation against the extent that key generation then erases;
- with the feature `stack-wipe`: the stack that the key import erases, at the
  three parameter sets, and the stack that signing with a prepared key
  erases, at Pretzel-(3,3) and Pretzel-(4,4) only, each observed on a painted
  stack (an observation of the test builds, not a bound on the depth of
  either). No test paints the stack around signing at Pretzel-(5,5), or
  around key generation at any parameter set;
- in the default configuration: that the tests which record a stack wipe
  record none;
- the [rank-three spread certificate](../crates/pretzel-3-3/certificates/rank3-spread/README.md):
  its self-test, and a recomputation of its bounds from the constants in the
  sources;
- the reference tables of Pretzel-(4,4) and Pretzel-(5,5)
  (`reference_tables.rs` under `crates/pretzel-4-4/certificates` and
  `crates/pretzel-5-5/certificates`): every entry is recomputed from the base
  and the weights in the sources;
- the [row certificate of Pretzel-(5,5)](../crates/pretzel-5-5/certificates/rank5-dither/README.md):
  a recomputation of its bounds from the constants in the sources;
- the [rank-four spread certificate](../crates/pretzel-4-4/certificates/rank4-spread/README.md):
  its self-test, and a recomputation of its bounds from the constants in the
  sources;
- the self-test of the script that compares the crates with ML-DSA
  (`bench/mldsa-comparison/compare.py --self-test`, pure Python). CI does
  not build or run the comparison itself.

Tests, counted as `#[test]` functions compiled for each CI configuration.
The stack-painting tests exist only with the feature `stack-wipe`:

| Test image | Tests, default | Tests, `stack-wipe` |
|---|---|---|
| `crates/pretzel-3-3`, library | 282 | 282 |
| `crates/pretzel-3-3/tests/api.rs` | 1 | 3 |
| `crates/pretzel-4-4`, `tests/` | 6 | 8 |
| `crates/pretzel-4-4/core` (the backend), library | 315 | 315 |
| `crates/pretzel-4-4/tests/diagnostics` | 4 | one configuration |
| `crates/pretzel-5-5`, library | 301 | 301 |
| `crates/pretzel-5-5`, `tests/` | 2 | 3 |
| `crates/pretzel-5-5/samplers/proposal` | 18 | one configuration |
| `crates/pretzel-5-5/samplers/transport-decision` and `transport-locator` | 9 | one configuration |
| Total | 938 | 943, counting the three one-configuration rows |

- Pretzel-(3,3): CI compares the tests of the library with the list
  `crates/pretzel-3-3/conformance/unit-tests.json` and requires exactly 282
  passed, none ignored and none excluded, in both configurations. A separate
  step runs `crates/pretzel-3-3/tests/api.rs`, the tests of the crate-root
  interface.
- Pretzel-(4,4): CI runs the tests of the crate and every backend test (315)
  in both configurations, and the four tests of the diagnostics package once.
- Pretzel-(5,5): CI runs every test of the crate in both configurations (301
  in the library; 2 in `tests/` by default and 3 with the feature) and the
  tests of the three sampler crates, once.
- In each of the three crates a CI step lists the tests of `tests/api.rs` and
  requires the stack-painting tests to be present, run and passed with the
  feature, and absent without it.
- No test in the tree carries an `#[ignore]` attribute, and no test is
  excluded from the CI run.

Only the Pretzel-(3,3) library counts and the presence of the stack-painting
tests are enforced by a check. The other counts are read from the sources,
and nothing fails when they change.
