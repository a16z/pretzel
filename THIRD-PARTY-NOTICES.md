# Third-party notices

Pretzel is licensed under either of the Apache License, Version 2.0
([LICENSE-APACHE](LICENSE-APACHE)) or the MIT license
([LICENSE-MIT](LICENSE-MIT)), at your option. The files listed on this page
contain code adapted from other projects; their notices follow.

## Keccak-f[1600] for ARMv8.4-A SHA3 instructions

The files listed below contain a Keccak-f[1600] round body adapted from the
RustCrypto `keccak` crate, version 0.1.6, file `src/armv8.rs`
(<https://github.com/RustCrypto/sponges>, tag `keccak-v0.1.6`).

    Copyright (c) 2018-2022 RustCrypto Developers

The `keccak` crate is licensed under either of the Apache License, Version 2.0
or the MIT license, at the user's option. Both texts, as distributed with that
crate, are in [licenses/keccak/LICENSE-APACHE](licenses/keccak/LICENSE-APACHE)
and [licenses/keccak/LICENSE-MIT](licenses/keccak/LICENSE-MIT).

That file states that it is adapted from the Keccak-f1600 implementation in
XKCP/K12, `lib/ARMv8Asha3/KeccakP-1600-ARMv8Asha3.S`
(<https://github.com/XKCP/K12>, commit
`df6a21e6d1f34c1aa36e8d702540899c97dba5a0`). The header of that file reads:

    Implementation by Gilles Van Assche, hereby denoted as "the implementer".
    Core subroutine is based on one by Andy Polyakov, available
    at https://github.com/dot-asm/cryptogams. Used with permission.

    To the extent possible under law, the implementer has waived all copyright
    and related or neighboring rights to the source code in this file.
    http://creativecommons.org/publicdomain/zero/1.0/

Changes made here: loads, stores and pointer strides (two interleaved states),
the outer absorb and squeeze scheduling, register save and restore, and the
erasure of working registers. The 24-round body is unchanged.

Files:

- `crates/pretzel-4-4/core/src/keccak2_arm.rs`
- `crates/pretzel-4-4/core/src/ct_absorb_pair.S`
- `crates/pretzel-4-4/core/src/ct_sponge_permute.S`
- `crates/pretzel-4-4/core/src/ct_stream_schedule.S`
- `crates/pretzel-4-4/core/src/ct_transcript_permute.S`
- `crates/pretzel-4-4/core/src/public_sponge_blocks.S`
- `crates/pretzel-3-3/src/keccak2_arm.rs`
- `crates/pretzel-3-3/src/public_pair_flat_arm.rs`
- `crates/pretzel-5-5/src/sign_prefix_shake.rs`
- `crates/pretzel-5-5/src/keccak2_arm.rs`

## ML-DSA prepared-key benchmark adapters for AWS-LC

The files listed below are benchmark adapters for the ML-DSA implementation
of AWS-LC (<https://github.com/aws/aws-lc>, commit
`a3d1e685552f05a9ad04a2946962c03e97bdecac`), which contains code of the
mldsa-native project (<https://github.com/pq-code-package/mldsa-native>). They
are not part of AWS-LC and are not an AWS-LC API: the prepared-key entry
points they define belong to this repository. No crate uses them; they are
compiled only by the comparison in `bench/mldsa-comparison`, which fetches
AWS-LC at that commit when it runs. This repository contains no AWS-LC source
file and distributes no build of AWS-LC.

The adapters are compiled inside the file
`crypto/fipsmodule/ml_dsa/mldsa/sign.c` of AWS-LC and call its internal
functions. The verification adapters restate the body of its function
`mld_sign_verify_internal`, and the signing adapters restate the body of its
signing function, each with the key unpacking moved into the prepared object;
the signing adapters call its function `mld_attempt_signature_generation` for
every attempt.
The context lines of the patch are text of that file. Its header reads:

    Copyright (c) The mldsa-native project authors
    SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT

The adapters also follow the entry-point pattern of
`crypto/fipsmodule/ml_dsa/ml_dsa.c` of AWS-LC (the self-test and
service-indicator calls). Its header reads:

    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0 OR ISC

The `NOTICE` file of AWS-LC reads:

    AWS-LC
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

The files listed below are licensed under the Apache License, Version 2.0
only ([LICENSE-APACHE](LICENSE-APACHE)), the one licence common to both
upstream grants and to this repository's own.

Changes made here: the expanded matrix and the transformed key material are
computed once and kept in a caller-owned object, behind new entry points
(`pretzel_mldsaNN_prepared_*` and `pretzel_mldsaNN_verify_*`). No arithmetic
is changed. The patch adds fifteen lines to `sign.c`, the conditional includes
of the adapter files, and removes or changes none.

Files:

- `bench/mldsa-comparison/aws-lc-prepared-adapters.patch`
- `bench/mldsa-comparison/adapters/aws_prepared_adapter_44.h`
- `bench/mldsa-comparison/adapters/aws_prepared_adapter_44.inc`
- `bench/mldsa-comparison/adapters/aws_prepared_verify_adapter_44.h`
- `bench/mldsa-comparison/adapters/aws_prepared_verify_adapter_44.inc`
- `bench/mldsa-comparison/adapters/aws_prepared_adapter_65.h`
- `bench/mldsa-comparison/adapters/aws_prepared_adapter_65.inc`
- `bench/mldsa-comparison/adapters/aws_prepared_verify_adapter_65.h`
- `bench/mldsa-comparison/adapters/aws_prepared_verify_adapter_65.inc`
- `bench/mldsa-comparison/adapters/aws_prepared_adapter_87.h`
- `bench/mldsa-comparison/adapters/aws_prepared_adapter_87.inc`
- `bench/mldsa-comparison/adapters/aws_prepared_verify_adapter_87.h`
- `bench/mldsa-comparison/adapters/aws_prepared_verify_adapter_87.inc`
