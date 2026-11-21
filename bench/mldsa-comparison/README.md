# Pretzel against ML-DSA

This directory times the three Pretzel crates of this repository against
ML-DSA at the parameter sets they are compared with (Pretzel-(3,3) with
ML-DSA-44, Pretzel-(4,4) with ML-DSA-65, Pretzel-(5,5) with ML-DSA-87). The
ML-DSA implementation is the one of [AWS-LC](https://github.com/aws/aws-lc)
at commit `a3d1e685552f05a9ad04a2946962c03e97bdecac`, which contains the
mldsa-native code with its AArch64 arithmetic.

It is a benchmark, not part of the crates: no crate depends on it, and the
workflow that tests the crates does not build it; that workflow runs only
the pure-Python self-test of the script.

## The command

From the repository root, on Apple silicon with macOS 15.2 or later:

```sh
python3 -B bench/mldsa-comparison/compare.py
```

This one command

1. fetches AWS-LC by the commit hash above into `target/mldsa-comparison/`,
   checks the SHA-256 of `crypto/fipsmodule/ml_dsa/mldsa/sign.c`, applies
   [aws-lc-prepared-adapters.patch](aws-lc-prepared-adapters.patch) with
   `git apply`, checks the SHA-256 of the patched file, and builds
   `libcrypto` with CMake (release build, static library);
2. builds [mldsa_driver.c](mldsa_driver.c) against that library, and runs it
   once with `--validate`: the prepared-key entry points and the unmodified
   AWS-LC functions must give the same signature bytes for the same
   randomness, accept it, and reject a changed message, and the unmodified
   verification must reject a signature with one changed byte;
3. builds [pretzel_driver.rs](pretzel_driver.rs) against the Pretzel crate
   of this checkout, in release mode with the profile of the root manifest,
   three times: with the crate's Cargo feature `stack-wipe`, the same a
   second time (the null control), and with the crate's default features;
4. runs the executables alternated and prints the tables of each parameter
   set.

The command above times both builds of Pretzel. To time one of them only:

```sh
python3 -B bench/mldsa-comparison/compare.py --build stack-wipe
python3 -B bench/mldsa-comparison/compare.py --build default
```

Each of these two builds the chosen driver twice (the second build is the
null control) and runs it with the ML-DSA executable. `--build both` is the
default.

Other options: `--level 3`, `--level 4` or `--level 5` for one parameter
set (the default is all three), `--rounds N` (default 100), `--budget-seconds S`
(default 4200, per parameter set), `--no-null-control`, `--work DIR` and
`--output DIR`. No new round starts once the budget of a parameter set is
used, so a run can end with fewer rounds than requested; the table then says
how many were run. `--work DIR` (default `target/mldsa-comparison`) is where
AWS-LC is fetched and everything is built. The script deletes `DIR/aws-lc`,
`DIR/aws-lc-build` and the driver directories
`DIR/levelN-pretzel-stack-wipe`, `DIR/levelN-pretzel-stack-wipe-again`,
`DIR/levelN-pretzel-default` and `DIR/levelN-pretzel-default-again` before
it builds them again. `--self-test` runs
the pure-Python checks of the script and builds nothing; it needs Python
3.11 or newer. The tables and the
build logs are written to `target/mldsa-comparison/results/`
(`RESULT-level4.txt`, `RESULT-level4.json` with every per-process value, and
one log per build step). Both result files name the features of every
Pretzel executable. A per-process value is the mean, the median or the
least thread CPU time of the calls of one process, its wall time per call,
or its signing attempts per call; the times of single calls are not kept.

Requirements: Apple silicon with macOS 15.2 or later; the Xcode Command
Line Tools; CMake; git; Rust through rustup with the toolchain of
[rust-toolchain.toml](../../rust-toolchain.toml) installed; Python 3; and
network access to fetch AWS-LC and the registry packages of the lockfile.
With 100 rounds, expect a few minutes for the AWS-LC build and a few
minutes of measurement per parameter set.

The script runs on any Apple silicon Mac. In GitHub Actions, the workflow
[mldsa-comparison.yml](../../.github/workflows/mldsa-comparison.yml) runs the
same command on `macos-15` runners, one job per parameter set, and uploads the
results as artifacts. It is started by hand (`workflow_dispatch`) and is not
one of the checks that run on every change.

## What is measured

Two builds of Pretzel are timed in the same jobs, against the same ML-DSA
executable:

- with the default features: the Cargo feature `stack-wipe` is off, and none
  of the stack ranges of that feature is zeroed. This is the build that the
  timing tables of the paper report;
- with the Cargo feature `stack-wipe`: the ranges of stack that key
  generation, the import of a secret key and signing use are zeroed before
  these operations return (the extents, and what a wipe does not cover, are
  in the README of each crate).

Of the five rows, signing runs a wipe at the three parameter sets and key
generation runs one at Pretzel-(4,4) and Pretzel-(5,5); Pretzel-(3,3) has no
wipe in key generation. The import of the secret key is outside the timed
intervals, and the three rows that use only the public key run no wipe.

One process per executable, operation and round. A process makes a fresh
key pair from operating-system entropy, checks one signature both ways,
makes 64 unmeasured calls, and then reads the thread CPU time
(`CLOCK_THREAD_CPUTIME_ID`) around every measured call. The message has 32
bytes and the context is empty. In every round the executables run one after
the other for each operation, and the order rotates from round to round.

| Row | Pretzel | ML-DSA (AWS-LC) | Calls per process |
|---|---|---|---|
| Key generation | `keygen` | `EVP_PKEY_pqdsa_new_raw_private_key` on a fresh 32-byte seed, and the export of both keys | 1000 |
| Prepare public key | `PreparedPk::new` and the release of the prepared key | `verify_new` and `verify_free` of the adapters | 2000 |
| Sign (prepared secret key) | `sign_prepared_with_scratch` | `prepared_sign` of the adapters | 2000 |
| Prepared verify | `verify_prepared` | `verify_prepared` of the adapters | 4000 |
| Verify with preparation | `verify` on the serialized public key | the unmodified `ml_dsa_NN_verify` of AWS-LC on the serialized public key | 2000 |

Signing on both sides draws fresh randomness in every call. Each signature
made in a timed call is verified outside the timed interval, and each
generated key is used and verified outside it. No check runs inside a timed
interval.

### What a timed call does on each side

"By reading" below means: read in the source, not measured. For Pretzel the
reading covers the function that the driver calls and the types it returns,
not the functions called from it. For AWS-LC it covers the adapters of this
directory and the lines of AWS-LC at the pinned commit that they depend on.
Where this section says "not examined", nobody has listed what the call
allocates or erases.

Key generation.

- Pretzel: `keygen`. It draws its randomness from the operating system
  inside the call and returns the key pair. It runs with data-independent
  timing enabled. With `stack-wipe` it zeroes 262144 bytes of stack at
  Pretzel-(4,4) and 131072 bytes at Pretzel-(5,5) before it returns, and
  nothing at Pretzel-(3,3). What else it allocates or erases: not examined.
- ML-DSA: 32 bytes from `getentropy`,
  `EVP_PKEY_pqdsa_new_raw_private_key` on that seed, the export of the
  public and the secret key into buffers of the caller, `EVP_PKEY_free`, and
  the erasure of the 32-byte seed. What AWS-LC allocates and erases inside
  these functions: not examined.

Prepare public key.

- Pretzel: `PreparedPk::new` on the serialized public key, and the release
  of the result. By reading: one heap allocation for the matrix (6144, 10240
  and 15360 bytes at Pretzel-(3,3), (4,4) and (5,5)), zeroed once and then
  filled; one heap allocation for a second array (3072, 4096 and 5120
  bytes), not zeroed, filled; and, at Pretzel-(3,3) and Pretzel-(4,4) only,
  one heap allocation for a copy of the key body (1312 and 1728 bytes). That
  is three allocations at Pretzel-(3,3) and Pretzel-(4,4), and two at
  Pretzel-(5,5). The release frees them and does not erase them. It erases
  two hash states of 408 bytes each that the prepared key holds, and at
  Pretzel-(5,5) three more hash states of 200 bytes each.
- ML-DSA: `verify_new` and `verify_free` of the adapters. One `malloc` of
  the prepared public key, the whole object set to zero once
  (`OPENSSL_cleanse`), then filled (the expansion of the matrix, the
  unpacking and transform of the public vector, one hash of the key), and
  one `free`. The adapter erases nothing, and the prepared object is not
  erased. The unmodified AWS-LC functions that fill it erase their own
  temporaries on the stack (the sampling buffers of the matrix expansion
  and the hash states), as they do in every row. The object has 20607,
  36991 and 65663 bytes at ML-DSA-44, ML-DSA-65 and ML-DSA-87 on the
  `macos-15` runners; the
  driver prints this size when it runs with `--validate`, and the log of
  that step is among the results. The adapters do not use `OPENSSL_zalloc`
  and `OPENSSL_free` of AWS-LC for this object because, by reading,
  `OPENSSL_free` erases every block that it releases. The zeroing is not
  needed for the result; it is the work that `OPENSSL_zalloc` would do.

Sign (prepared secret key).

- Pretzel: `sign_prepared_with_scratch`, with a prepared secret key and a
  workspace that the caller made outside the timed interval. It draws fresh
  randomness inside the call and runs with data-independent timing enabled.
  With `stack-wipe` it zeroes 73728 bytes of stack at Pretzel-(3,3) and
  Pretzel-(4,4), and 65536 bytes at Pretzel-(5,5), before it returns. What
  else it allocates or erases: not examined here; the README of each crate
  says what signing erases.
- ML-DSA: `prepared_sign` of the adapters, with a prepared secret key made
  outside the timed interval. It draws 32 random bytes inside the call and
  calls the unmodified signing-attempt function of AWS-LC until a signature
  is accepted. By reading: the adapter makes no heap allocation and erases
  its own temporaries, which are small buffers on the stack. What the
  unmodified signing-attempt function allocates and erases: not examined.

Prepared verify.

- Pretzel: `verify_prepared`, with a prepared public key made outside the
  timed interval. What it allocates or erases: not examined.
- ML-DSA: `verify_prepared` of the adapters, with a prepared public key made
  outside the timed interval. By reading: no heap allocation; its
  temporaries are on the stack and each is erased before the call returns
  (the macro `MLD_FREE` of mldsa-native), as in the function of AWS-LC that
  the adapter restates.

Verify with preparation.

- Pretzel: `verify` on the serialized public key. By reading: the work of
  "Prepare public key" above (`PreparedPk::new`), the prepared
  verification, and the release described above; at Pretzel-(3,3) the
  release also erases any hash state of 200 bytes that the verification
  set up.
- ML-DSA: the unmodified `ml_dsa_NN_verify` of AWS-LC on the serialized
  public key, with an empty context. By reading: no heap allocation; the
  expanded public matrix (16384, 30720 and 57344 bytes at ML-DSA-44,
  ML-DSA-65 and ML-DSA-87) and the temporaries are on the stack, and each
  is erased before the call returns (`MLD_FREE`).

The two rows with public-key preparation are like for like at the interface
and in the kind of work, not in the amount of work. "Prepare public key":
both sides allocate on the heap, zero once, fill and free, and neither
erases the prepared matrix; the functions of AWS-LC that fill the matrix
erase their sampling buffers and hash states on the stack; ML-DSA makes one
allocation and zeroes all of it
(21 to 66 thousand bytes), Pretzel makes three allocations (two at
Pretzel-(5,5)), zeroes one of them (6 to 15 thousand bytes) and erases its
small hash states. "Verify with preparation": each library's own
verification from the serialized key; the unmodified function of AWS-LC
allocates nothing and erases its public matrix on its stack, and Pretzel
allocates on the heap; in the function read and in its release it erases
only the small hash states (the functions it calls and the prepared
verification were not examined). This README
does not claim that the two sides do the same amount of memory work in
these rows.

What each side is built with:

- Pretzel: the crate in release mode with the profile of the root manifest,
  once with the feature `stack-wipe` and once with its default features.
  The feature is enabled on the dependency line of the manifest that the
  script writes for the driver (`features = ["stack-wipe"]`), and no other
  feature is enabled in either build. In both builds key generation and
  signing run with the data-independent timing (DIT) mode of the processor
  enabled, as the crates do by default.
- ML-DSA: AWS-LC configured by CMake with `-DCMAKE_BUILD_TYPE=Release`,
  `-DBUILD_TESTING=OFF`, `-DBUILD_LIBSSL=OFF`, `-DDISABLE_GO=ON`,
  `-DDISABLE_PERL=ON`, `-DBUILD_SHARED_LIBS=OFF` and
  `-DGENERATE_RUST_BINDINGS=OFF`, with the C compiler of the Xcode Command
  Line Tools; the driver is compiled with `-O3`. The adapters zeroize the
  prepared secret key when it is released, which happens outside the timed
  intervals; they do not erase the prepared public key; and they release
  their temporaries through the macro `MLD_FREE` of mldsa-native, which
  erases them.

Data-independent timing is not the same on the two sides. Pretzel's key
generation and signing run with the DIT mode of the processor enabled.
AWS-LC has a build option of its own for this,
`ENABLE_DATA_INDEPENDENT_TIMING`, which is off by default, and the script
does not pass it. Without the option, the macro `SET_DIT_AUTO_RESET`, with
which the functions of AWS-LC and the adapters would enable the DIT mode,
compiles to nothing, so no ML-DSA row runs with the library enabling it.
The file `aws-CMakeCache.txt` among the results records the option of a
run. The consequence: in the rows "Key generation" and "Sign (prepared
secret key)" Pretzel does its secret work under DIT and ML-DSA does not.
One run of the comparison with the option on for AWS-LC showed no
measurable difference on any row; that run is not the one of the table
below and is not in this repository.

The first table of a parameter set gives the mean thread CPU time per call
in microseconds, one column per build of Pretzel and one for ML-DSA:
`stack-wipe us`, `default us` and `ML-DSA us` (the second build of the null
control has no column). The second table gives the ratios:

| Column | Ratio |
|---|---|
| `stack-wipe / ML-DSA` | Pretzel with `stack-wipe` divided by ML-DSA |
| `default / ML-DSA` | Pretzel with default features divided by ML-DSA |
| `stack-wipe / default` | Pretzel with `stack-wipe` divided by Pretzel with default features: the cost of the wipes |
| `null control` | the second build of the first Pretzel driver divided by its first build |

With `--build stack-wipe` or `--build default` the columns of the other
build and the column `stack-wipe / default` are absent. A ratio is the
geometric mean, over the rounds, of the per-round ratio of the two process
means, with a normal 95% interval on the logarithms. The null control is the
same statistic for two builds of the same driver (with `stack-wipe`, unless
only the default build is timed); its
distance from 1 shows what one run cannot resolve. The means are what the
tables report. Signing time is skewed on both sides, because both schemes
repeat until a candidate is accepted, so a ratio of medians can differ from
the ratio of means; the per-process medians are in the JSON file.

The figures move by a few percent between machines, and between runs on
the same machine or runner class. One run is one sample: repeat it, and
compare runs, before reading a difference of that size. The only figures
that this repository records, outside the paper, are those of the table
below.

## Figures of one run

One run of the comparison with both builds. Each cell is a ratio of mean
thread CPU times with its 95% interval: below 1, the build named first took
less time. The column `stack-wipe` / default is the cost of the wipes.

| Parameter set | Row | default / ML-DSA | `stack-wipe` / ML-DSA | `stack-wipe` / default | Wipe in the timed call with `stack-wipe` |
|---|---|---|---|---|---|
| Pretzel-(3,3) against ML-DSA-44 | Sign (prepared secret key) | 0.9097 [0.9060, 0.9135] | 0.9472 [0.9431, 0.9512] | 1.0412 [1.0362, 1.0462] | yes, 73728 bytes |
| Pretzel-(3,3) against ML-DSA-44 | Verify with preparation | 0.7413 [0.7383, 0.7442] | 0.7406 [0.7378, 0.7435] | 0.9992 [0.9948, 1.0035] | no |
| Pretzel-(3,3) against ML-DSA-44 | Prepare public key | 0.6705 [0.6677, 0.6733] | 0.6724 [0.6692, 0.6757] | 1.0029 [0.9976, 1.0083] | no |
| Pretzel-(3,3) against ML-DSA-44 | Prepared verify | 0.8519 [0.8481, 0.8557] | 0.8509 [0.8475, 0.8543] | 0.9988 [0.9939, 1.0038] | no |
| Pretzel-(3,3) against ML-DSA-44 | Key generation | 1.4845 [1.4788, 1.4902] | 1.4765 [1.4711, 1.4819] | 0.9946 [0.9903, 0.9989] | no |
| Pretzel-(4,4) against ML-DSA-65 | Sign (prepared secret key) | 0.9329 [0.9288, 0.9371] | 0.9499 [0.9461, 0.9537] | 1.0182 [1.0135, 1.0229] | yes, 73728 bytes |
| Pretzel-(4,4) against ML-DSA-65 | Verify with preparation | 0.5821 [0.5799, 0.5843] | 0.5830 [0.5809, 0.5852] | 1.0016 [0.9970, 1.0063] | no |
| Pretzel-(4,4) against ML-DSA-65 | Prepare public key | 0.5046 [0.5025, 0.5068] | 0.5056 [0.5035, 0.5077] | 1.0020 [0.9973, 1.0066] | no |
| Pretzel-(4,4) against ML-DSA-65 | Prepared verify | 0.9107 [0.9071, 0.9144] | 0.9086 [0.9052, 0.9121] | 0.9977 [0.9931, 1.0023] | no |
| Pretzel-(4,4) against ML-DSA-65 | Key generation | 1.3342 [1.3287, 1.3397] | 1.4770 [1.4716, 1.4825] | 1.1071 [1.1022, 1.1120] | yes, 262144 bytes |
| Pretzel-(5,5) against ML-DSA-87 | Sign (prepared secret key) | 0.9397 [0.9355, 0.9440] | 0.9444 [0.9402, 0.9485] | 1.0049 [1.0002, 1.0097] | yes, 65536 bytes |
| Pretzel-(5,5) against ML-DSA-87 | Verify with preparation | 0.4955 [0.4938, 0.4972] | 0.4952 [0.4931, 0.4973] | 0.9993 [0.9943, 1.0043] | no |
| Pretzel-(5,5) against ML-DSA-87 | Prepare public key | 0.4314 [0.4300, 0.4327] | 0.4310 [0.4296, 0.4323] | 0.9990 [0.9952, 1.0029] | no |
| Pretzel-(5,5) against ML-DSA-87 | Prepared verify | 0.8324 [0.8293, 0.8356] | 0.8349 [0.8310, 0.8388] | 1.0030 [0.9980, 1.0079] | no |
| Pretzel-(5,5) against ML-DSA-87 | Key generation | 0.9852 [0.9812, 0.9891] | 1.0282 [1.0239, 1.0325] | 1.0437 [1.0392, 1.0482] | yes, 131072 bytes |

What the table says:

- The default build is the one that the timing tables of the paper report.
  The table is a run of its own and does not reproduce the figures of the
  PDF. The tables of the paper were measured before the ML-DSA rows "Prepare
  public key" and "Verify with preparation" were timed as described above.
- With `stack-wipe`, the timed call runs a wipe in five of the fifteen rows:
  signing at the three parameter sets, and key generation at Pretzel-(4,4)
  and Pretzel-(5,5). The last column gives the bytes zeroed. The other ten
  rows run no wipe; their ratio `stack-wipe` / default lies between 0.9946
  and 1.0030, which shows what the run resolves.
- The feature does not wipe after key generation at Pretzel-(3,3): with
  `stack-wipe` enabled, the stack that key generation used at that parameter
  set is not zeroed. That row is the same operation in both builds.
- In this run signing took less time than ML-DSA at the three parameter
  sets in both builds. Key generation took more time than ML-DSA at
  Pretzel-(3,3) and Pretzel-(4,4) in both builds; at Pretzel-(5,5) it took
  less time in the default build and more with `stack-wipe`.

What the run was:

- The table was produced by this script in its default mode
  (`python3 -B bench/mldsa-comparison/compare.py`, both builds), three
  sessions pooled.
- GitHub-hosted `macos-15` runners with virtual Apple M2 Pro processors,
  on 2026-11-21: three sessions per parameter set, each a separate job of
  100 rounds.
- Each cell pools the three sessions with equal weight: the geometric mean
  of the three session ratios, with an interval from the standard errors
  within the sessions. The script itself reports one session and pools
  nothing.
- Mean thread CPU time per call, with the calls per process, the 64
  unmeasured calls, the release profile and the AWS-LC commit given above.

The commands of this script for the two builds, and for both in one run:

```sh
python3 -B bench/mldsa-comparison/compare.py --build default
python3 -B bench/mldsa-comparison/compare.py --build stack-wipe
python3 -B bench/mldsa-comparison/compare.py
```

The figures move by a few percent between machines and between runs, so a
run of these commands gives figures of its own, not those of the table.

## The prepared-key entry points are ours, not AWS-LC's

At the pinned commit, the ML-DSA signing and verification functions of
AWS-LC (`ml_dsa_NN_sign`, `ml_dsa_NN_verify`) take the serialized key and
expand it in every call. Pretzel's rows for a prepared key need ML-DSA rows
in which the key is expanded once, so this directory adds them:

- [adapters/](adapters) holds twelve files, four per ML-DSA parameter set.
  `aws_prepared_adapter_NN.{h,inc}` define
  `pretzel_mldsaNN_prepared_{new,free,sign,sign_seed}`: a
  prepared secret key that keeps the expanded matrix and the transformed
  secret vectors. `aws_prepared_verify_adapter_NN.{h,inc}` define
  `pretzel_mldsaNN_verify_{new,free,prepared,object_bytes}`: a prepared
  public key that keeps the expanded matrix, the transformed public vector
  and the hash of the public key, and the size of that object. The rows
  "Prepare public key" and "Prepared verify" use them. The row "Verify with
  preparation" does not: it calls the unmodified `ml_dsa_NN_verify`.
- [aws-lc-prepared-adapters.patch](aws-lc-prepared-adapters.patch) adds
  fifteen lines to `crypto/fipsmodule/ml_dsa/mldsa/sign.c` of AWS-LC: a
  conditional include of the two `.inc` files for each parameter set, so that
  they are compiled inside that file and can call its internal functions.
  Nothing in that file is removed or changed, and no other file of AWS-LC is
  touched.

These functions are **not part of AWS-LC, are not an AWS-LC API, and are
not endorsed by the AWS-LC or mldsa-native projects**. They exist for this
measurement only, work only with AWS-LC at the pinned commit, and are not
meant for any other use.

What they take from upstream:

- The signing adapter restates the body of mldsa-native's signing function
  (the pure-mode path), with the unpacking of the secret key moved into the
  prepared object. Its loop calls the unmodified signing-attempt function
  (`mld_attempt_signature_generation`) at most
  `mld_get_max_signing_attempts()` times.
- The verification adapter restates the body of mldsa-native's
  `mld_sign_verify_internal` (the pure-mode path), with the unpacking and
  transform of the public key moved into the prepared object.
- Both follow the entry-point pattern of AWS-LC's
  `crypto/fipsmodule/ml_dsa/ml_dsa.c` (the self-test and service-indicator
  calls).

No arithmetic is changed: the expanded matrix and the transformed key
material are computed once and kept in a caller-owned object. The driver
checks in every process, before it times anything, that the prepared signer
and the unmodified AWS-LC signer produce the same bytes for the same
randomness, that the prepared verifier and the unmodified verification
accept that signature and reject a changed message, and that the unmodified
verification rejects the signature with one changed byte.

AWS-LC is fetched when the command runs. This repository contains no AWS-LC
source file, and distributes no build of it.

## Licences

The twelve adapter files and the patch are licensed under Apache-2.0 only
(`SPDX-License-Identifier: Apache-2.0`), because they contain or restate
upstream text:

- mldsa-native: `Copyright (c) The mldsa-native project authors`,
  `SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT`;
- AWS-LC: `Copyright Amazon.com, Inc. or its affiliates. All Rights
  Reserved.`, `SPDX-License-Identifier: Apache-2.0 OR ISC`.

Apache-2.0 is the one licence common to both upstream grants and to this
repository's `MIT OR Apache-2.0`. Each of those files carries the upstream
notices and a statement of what was changed; the entry in
[THIRD-PARTY-NOTICES.md](../../THIRD-PARTY-NOTICES.md) repeats them. The
other files of this directory (the script, the two drivers and this README)
are under the licence of the repository, `MIT OR Apache-2.0`.
