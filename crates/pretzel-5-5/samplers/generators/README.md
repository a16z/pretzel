# Generator of the proposal sampler's fixture sets

Run from the repository root with Python 3.11 or newer:

```sh
python3 crates/pretzel-5-5/samplers/generators/gen_proposal_fixtures.py --check
```

The command uses only the Python standard library, reads the tables of
`../proposal/src` and compares hashes. It invokes no compiler and writes
nothing. `--output-dir DIR` writes the six generated files under `DIR`, which
must be outside the repository; `--self-test` checks the hash expansion and
the hand-built cases described below. `--check` takes about one second.

When a test reports that the hash of its set differs from the constant, it
first prints one line per record, `SET record INDEX` followed by the first
eight hexadecimal digits of the SHA-256 of that record.
`--record-hashes SET` prints the same lines for the model's records; the
first line that differs names the record.

## What is generated

Six sets of records for the functions of `samplers/proposal` that the signer
calls. A record is the input of one call followed by what the function
returns. The sets are not stored in the repository. Two programs compute them:

- `gen_proposal_fixtures.py` builds the inputs by the rules below and computes
  the outputs with an integer model of the sampler. The model is an
  independent restatement of the sampler, written from the Rust source; it
  shares no code with it and uses integers of arbitrary size where the sampler
  uses vector instructions.
- The test of each function in `samplers/proposal/src` builds the same inputs
  by the same rules, calls the function, and hashes the same bytes.

Both compare the SHA-256 of the whole set with the constant in the table.
Agreement of the Rust tests and of `--check` on one constant is the check: the
sampler and the model then return the same outputs on every record. A wrong
constant, a changed table, a changed rule or a changed sampler makes one of
the two fail.

| set | function | records | bytes | SHA-256 |
|---|---|---|---|---|
| `coretail-main` | `coretail_main::core16` | 5112 | 40896 | `d0b247d20b7a5af394470c75576d825bafbaa81673ef41d2d71a3961199608f4` |
| `coretail-middle` | `coretail_middle::middle16` | 29288 | 497896 | `f1818ab0abbe22c2450957caf39eea8d86805437b085de05401d40d0495ecec5` |
| `coretail-final` | `coretail_final::final8` | 30 | 2430 | `9a1dc9cf2ca1040109f777893fe1dffb614b3f269eb8653af13d37097f04d98c` |
| `coretail-major` | `coretail_major::sample` | 198 | 2813382 | `854abe1af9fe8f170935b81a6c0d93fc8894b0b56ba0f637b0b4a1a72bdeec92` |
| `leading-alias32` | `leading_alias32::sample` | 803 | 2313443 | `2df04288385c029cfee00112fd1bcd86aef7cce5de44b013daef46504a127a40` |
| `coretail-composite` | `conditional_initial::generate` | 218 | 4841562 | `520ad041d762fc6a24cef7af0a6fa0868f97cd9b106e00f01ace9eb24ce5887c` |

The tests also assert what a hash does not show by itself: the sixteen lanes
of `core16` agree, a window of eight records of `final8` reports the OR of
their failure flags, workspaces and entropy buffers are zero after every call,
and the rows that abort are exactly the rows listed below.

## Shared definitions

**Seeded bytes.** `expand(label, seed, n)` is SHA-256 in counter mode: block
$i$ is the SHA-256 of the ASCII label, one zero byte, the seed as a 32-bit
little-endian word and $i$ as a 32-bit little-endian word; the result is the
first $n$ bytes of block 0, block 1 and so on. The Rust tests use their own
SHA-256 (`samplers/proposal/src/fixture_gen.rs`, compiled for tests only and
checked against the standard test vectors); the generator uses `hashlib`.

**Boundary set.** For a cut $t$ and a largest value $T$, $B(t, T)$ is the
increasing list of the distinct values among $0$, $t-1$, $t$, $t+1$, $T$ that
lie in $[0, T]$. A column that is its own alias always returns itself; for
such a column $t$ is taken as $T$.

**Bits** of a byte string are numbered from the most significant bit of the
first byte. Multi-byte values in records are little-endian unless stated.

## The sets

### `coretail-main`

Record: family, column, sign, coin (16 bits, little-endian); then ready (one
byte) and the value (`i16`).

For family 0 and 1, for column 0 to 255, for the coin in $B(t, 65535)$ with
$t$ the 16-bit cut of the column, for sign 0 and 1. The same record is placed
in all sixteen lanes of one call.

### `coretail-middle`

Record: family, main column, sign, main coin (6 bytes, big-endian), tail
column, tail coin (4 bytes, big-endian); then ready and the value (`i16`).

For column $c$ from 0 to 255, for family 0 and 1:

1. main coin in $B$ of the 48-bit cut of $c$, tail column $(c + 13) \bmod 256$,
   tail coin in $B$ of the 32-bit cut of that tail column, sign 0 and 1;
2. main column 255 with main coin 0 (which escapes to the tail), tail column
   $c$, tail coin in $B$ of the 32-bit cut of $c$, sign 0 and 1.

Calls take sixteen consecutive records; the last call wraps to the first
records.

### `coretail-final`

Record: the 14 metadata bytes of `coretail-middle`, the 64-byte record of
coin bits; then the failure flag (one byte) and the unsigned value (`i16`,
zero on failure).

Thirty hand-built cases, fifteen for each family, in this order:

1. Four ties: column 1, main coin equal to the first 48 bits of its 320-bit
   cut, and tail column, tail coin and record equal to the 69 bytes of
   `expand("coretail-final", 4 * family + i, 69)` for $i$ from 0 to 3. The
   record decides between the column and its alias.
2. Three edges: column 1, and the 320 bits formed by the main coin and the
   start of the record equal to the cut minus one, the cut, and the cut plus
   one; all other bytes zero.
3. Seven chains. Every coin is zero, so each level takes its column; column
   255 continues to the next level. The record holds only the column bytes of
   levels two and later, each at the bit position the earlier levels leave
   the cursor at (a level whose cut has $z$ leading zero bits consumes
   $z + 1$ bits beyond the coin bits held in the metadata). The columns are
   (255, 254), (255, 255), (255, 255, 254), (255, 255, 255),
   (255, 255, 255, 254), (255, 255, 255, 255), and last
   (255, 255, 255, 255, 129) for family 0 or (255, 255, 255, 255, 255, 187)
   for family 1. The values are 509, 510, 764, 765, 1019, 1020 and the
   largest value of the family, 1149 or 1462.
4. One overflow: column 255 with the 320-bit word equal to its cut with the
   last set bit cleared, then tail column 1 with the tail coin and the rest of
   the record equal to the cut of that column for as long as the record
   lasts. The cursor passes the end of the record and the call fails.

Each case is run alone, in lane $k \bmod 8$ for case $k$, to obtain its own
flag and value, and again in windows of eight.

### `coretail-major`

Record: 9088 entropy bytes; then the abort flag and 2560 values (`i16`).

Row $r$ from 0 to 197 is `expand("coretail-major", r, 9088)`, changed in 39
rows:

- Rows 35, 36, 37: all 2560 columns are set to 0 (which resolves at once),
  then lane $39j$ for $j$ below 63, 64 and 65 receives column $1 + j$ and a
  16-bit coin equal to the cut of that column. The first queue holds 64
  lanes: row 37 aborts.
- Rows 39, 40, 41: the same with 7, 8 and 9 lanes, whose next 32 coin bits
  (bytes $8000 + 9j$ to $8003 + 9j$) also equal the cut, so that every lane
  reaches the last stage. The second queue holds 8 lanes: row 41 aborts.
- Rows 43 and 44: as rows 39 and 40, with the 7 and 8 lanes at $1280 + 39j$,
  in family 1.
- Rows 55 and 69: one lane carries the overflow case of `coretail-final` for
  family 0 (row 55) and family 1 (row 69), embedded as described below with
  sign 0. Both rows abort.
- Rows 70 to 97: row $70 + k$ carries case $k$ of the 28 cases of
  `coretail-final` that do not fail (the thirty in their order, without the
  two overflows), with sign $(k + f) \bmod 2$ for a case of family $f$.
- Row 98: case 26 again (the chain of family 1 that ends at 1020), with
  sign 0; row 96 carries it negated.

A case is embedded in the first lane of its family, lane $n = 0$ or
$n = 1280$: byte $n$ receives its column, bit 0 of byte $2560 + n/8$ its
sign, bytes $2880 + 2n$ and $2881 + 2n$ the first 16 coin bits, bytes 8000 to
8008 the next 32 coin bits, the tail column and the tail coin, and bytes 8576
to 8639 its record. For family 1 the columns of lanes 0 to 1279 are set to 0,
so that the lane is the first one queued. All other bytes stay seeded.

Abort rows: 37, 41, 55, 69. No seeded row aborts.

The rows that set every column to 0 (35 to 37, 39 to 41, 43 and 44) have no
seeded lane around the forced ones: the number of queued lanes must be exact,
and a seeded tape queues lanes of its own that the rule cannot count without
running the sampler. The embedded cases keep their seeded surroundings.

Results of the last stage that reach an output of a row that does not abort,
counted with the model. The first column is the set that was stored in the
repository before this generator; `coretail-composite` has the same counts,
because its major part is the same input.

| | stored set | generated set |
|---|---|---|
| results | 35, in 22 rows | 58, in 32 rows |
| family 0, family 1 | 17, 18 | 29, 29 |
| levels reached | 1 to 6 | 1 to 6 |
| least and greatest value | $-1149$, $1462$ | $-1149$, $1462$ |
| magnitudes of 255 or more | 509, 510, 764, 765, 1019, 1020, 1149, 1462 | the same |
| negative results of magnitude 255 or more | 7 | 7 |
| combinations of family, level and sign | 13 | 20, the 13 among them |

One embedded case does not reach the last stage: the chain (255, 254) of
family 1 is resolved to 509 by the middle stage. `--self-test` asserts the
right column.

### `leading-alias32`

Record: 1856 entropy bytes; then the abort flag and 256 values (`i32`).

- Rows 0 to 23: `expand("leading-alias32", r, 1856)`.
- Row 24: all bytes 0. Row 25: all bytes 255.
- Rows 26 to 793: for column 0 to 127, for sign 0 and 1, for $\delta$ in
  $-1, 0, 1$: lane 0 holds the column and the sign, and its 320 coin bits
  (the 32-bit coin, then the first 36-byte block) equal the 320-bit cut of the
  column plus $\delta$ modulo $2^{320}$; all other bytes are zero.
- Rows 794 to 802: 0, 1, 2, 15, 16, 17, 31, 255 and 256 queued lanes. For a
  count of at most 31 the lanes are $37 (j \bmod 7) + 3 \lfloor j / 7 \rfloor$
  for $j$ below the count, otherwise lanes 0 to count minus one. The $i$-th
  lane in increasing order holds column $1 + (i \bmod 127)$, sign $i \bmod 2$
  and a 32-bit coin equal to the cut of its column; the sixteen 36-byte blocks
  are `expand("leading-alias32-queue", 0, 576)`. The queue holds 16 lanes.

Abort rows: 799, 800, 801, 802.

### `coretail-composite`

Record: 10944 entropy bytes, the leading part (1856) then the major part
(9088); then the abort flag and 2816 values (`i32`).

- Rows 0 to 197: `expand("coretail-composite", r, 1856)`, then the input of
  row $r$ of `coretail-major`.
- Rows 198 to 213: the input of rows 0 to 15 of `leading-alias32`, then the
  input of row 0 of `coretail-major`.
- Rows 214 to 217: the input of rows 799 to 802 of `leading-alias32`, then
  the input of row 0 of `coretail-major`.

Abort rows: 37, 41, 55, 69 (major part) and 214 to 217 (leading part).

## Files without a generator

The tables and binary planes of the three sampler crates are checked in as
they are; no generator in this repository reproduces them. The generated sets
depend on them: the input rules read the cuts, and the model reads every
table the signer path reads, which is every table of `samplers/proposal`.

`samplers/proposal` stores no fixture file: the six sets above are all the
record sets its tests use. `samplers/transport-decision/src/decision-fixtures.bin`
has no generator.
