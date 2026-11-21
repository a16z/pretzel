# Generators of tables and assembly

Run from the repository root with Python 3.11 or newer:

```sh
python3 crates/pretzel-4-4/core/generators/gen_public_tables.py --check
python3 crates/pretzel-4-4/core/generators/gen_assembly.py --check
```

Both commands run in the repository workflow. They use only the Python
standard library, read files of this repository and compare bytes. They invoke
no compiler and never overwrite a checked-in file; `--output-dir DIR` writes
the generated files under `DIR` for inspection.

A third program checks figures and writes no file:

```sh
python3 crates/pretzel-4-4/core/generators/check_sampler_bounds.py --check
```

It recomputes, from the reconstructed 192-bit sampler tables, the largest values that the
sampler can produce (108, 739 and 937) or hold in an aborted attempt (744 and 946), and the
bound 189281598 that `../src/aux32_initial.rs` derives from them, and compares them with the
figures in `aux32_initial.rs` and `params.rs`. Its docstring states the rule it applies and
what it does not establish.

## What is regenerated

`gen_public_tables.py` reproduces 43 complete files, including whitespace:

- both `collapsed_bounds_*.bin` files, all six
  `reservoir_{main,mid,suffix}_*.bin` files and all 31 `warm_tree_*.bin` files
  of `../src`;
- `aux32_static_tables.rs` and `auxiliary_static_tables.rs` of `../src` (no
  crate compiles the second any more; the generator still writes and checks
  it);
- `interval-key256-table.h` of `../src` and of `crates/pretzel-5-5/src`.

The Gaussian boundaries are reconstructed at 240 and 320 decimal digits from
`params.rs` and `fixed.rs` (`crates/pretzel-4-4/scripts/spec_sampler.py`), and the
two results must agree. The integer construction removes common tie atoms,
balances odd pairs, applies a last-in-first-out Walker alias construction,
then serializes thresholds and metadata. The main gather uses consecutive
64-row planes without endpoint flags; the middle and suffix gathers use
Gray-code blocks of sixteen and omit zero planes. The warm tree splits
endpoints at bit 128 and keeps the high planes that the error law needs. The
comparison is of bytes; it is not an arithmetic certificate of the tables.

Key coefficients use directed Q1024 arithmetic and projection to Q256, with
theta taken from each crate's `params.rs`. The C callers specify 38 rows
(rank four) and 36 rows (Pretzel-(5,5)); Pretzel-(5,5) specifies $L^2 = 2^{37}$ in
`interval-transport.c`, rank four $2^{36}$.

`gen_assembly.py` reproduces one file, `ct_alias_sixteen_runs.S`, from the
hand-written assembly template `ct_alias_sixteen_compact.S`. The template is
assembled by nothing: it is only the generator's input. The symbol
`pretzel44_ct_alias_sixteen_compact` is assembled from the generated file
`ct_alias_sixteen_runs.S`.

## Compiler output kept as source

`ct_rq_helpers_mac.S` began as compiler output and was then edited. The
checked-in assembly is the source. `helpers.c` is an earlier C form of the
same routines; it is compiled by nothing and does not reproduce the assembly.
A build of `helpers.c` on a macOS runner with the compiler version the file
names and the command in its header, also with the capacity constant
`RQ_CAP` set to 6, differed from the checked-in file in 276 lines after
normalization of labels. Known differences:

- `helpers.c` defines `RQ_CAP` as 3; the assembly uses 6 (`movi.4s v8, #6`,
  `cmp w5, #6`), which is also the constant `CAP` of `ct_rarequeue.rs`.
- `pretzel44_rq_resolve` in `helpers.c` fills three words of `reject` (a
  literal 3, not `RQ_CAP`); the assembly stores six.
- About 180 lines of the assembly are instructions that clear registers and
  stack words (`mov x1, xzr`, `stp xzr, xzr, ...`); the C file has no
  counterpart.
- The sampler loop of the assembly contains a 24-bit patch that the C file
  does not express.
- The assembly selects its symbol names with `.if PRETZEL_NATIVE_SET == 33`,
  so that `crates/pretzel-3-3` can assemble the same file under its own
  prefix.

No check ties the C file to the assembly.

Two more files hold edited compiler output and are their own source:

- `ct_recycle_prefix.S`.
- `transport-tables.S`: its routine `pretzel44_interval_coarse_keep_tables`
  is compiler output for the C function `pretzel44_interval_coarse_step` of
  `interval-transport.c` (it still carries the compiler's block and spill
  comments). The C function is also built and
  called. No check keeps the two in step.

## Files without a generator

The following checked-in files have no generator in this repository that
reproduces their bytes. The files themselves are the source.

- `ct_alias_fixtures.txt`, the expected values of the alias tests.
- `ct_alias_generated.rs` (the plane-mask patterns of the alias scan).
- The other unrolled, straight-line gather routines: `ct_rq_coarse_lead.S`,
  `ct_rq_coarse_sec.S`, `ct_rq_coarse_err.S`, `ct_rq_residual_lead.S`,
  `ct_rq_residual_sec.S`, `ct_rq_residual_err.S`, `reservoir-tables.S` and
  `warm-gathers.S`. The table bytes they read (`reservoir_*.bin`,
  `warm_tree_*.bin`) are regenerated, as listed above; the routines are not.
- The hand-written assembly and C files of `../src` that are not named in
  this document.
- `params_tables.rs`, `cap_piecewise_tables.rs`, the descriptor files
  `reservoir_tables.rs` and `warm_tail_tables.rs`, and the transport constants
  in `interval-centered7-prepare.h` and `interval-geometric-prepare.c`. Tests
  compare `aux32_static_tables.rs` with its runtime constructor.
- `keygen_cdt_static_data.rs`. A test beside it compares it with the runtime
  construction.
- `direct_ntt_vectors.rs` and `spectral_b_vectors.rs`, which tests read.
- In `crates/pretzel-3-3/src`: `interval-key256-table.h`,
  `reservoir_tables.rs`, `warm_tail_tables.rs`, `params_tables.rs`, and its
  copy of `ct_alias_sixteen_runs.S`. No check in this directory reads a file
  of `crates/pretzel-3-3`.
- The reference tables of the row-quality statements,
  `crates/pretzel-4-4/certificates/rank4-spread/reference_tables.rs` and
  `crates/pretzel-5-5/certificates/rank5-dither/reference_tables.rs`. They
  are certificate input data; no crate compiles them.
  `crates/pretzel-4-4/certificates/check_reference_tables.py` recomputes
  every entry from the base and the weights in `params.rs`, and CI runs it.
- The tables and binary planes of `crates/pretzel-5-5/samplers`, and its one
  stored fixture, `decision-fixtures.bin` of the transport-decision sampler.
  The record sets of the proposal sampler are not stored: its tests generate
  them, and
  `crates/pretzel-5-5/samplers/generators/gen_proposal_fixtures.py` checks them.
- The known-answer files and the codec fixtures that tests read.
- `crates/pretzel-4-4/tests/data/keygen-main-rank4.bin`, the key-generation fixture of
  Pretzel-(4,4). Its entropy record holds one more 32-byte request per seed than key
  generation makes; the test in `core/src/key_setup.rs` compares the record without it.

The checks above cover exactly the files listed under "What is regenerated".
