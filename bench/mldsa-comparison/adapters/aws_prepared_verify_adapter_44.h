/*
 * Benchmark adapter for AWS-LC (https://github.com/aws/aws-lc) at commit
 * a3d1e685552f05a9ad04a2946962c03e97bdecac. Not part of AWS-LC and not an
 * AWS-LC API: the prepared-key entry points declared below
 * (pretzel_mldsa44_verify_*) belong to this repository.
 * They are implemented in aws_prepared_verify_adapter_44.inc, which is compiled
 * inside AWS-LC's crypto/fipsmodule/ml_dsa/mldsa/sign.c through the
 * include added by aws-lc-prepared-adapters.patch.
 *
 * This header uses the export macro and the base header of AWS-LC. The
 * implementation restates or calls code of that source file:
 *   Copyright (c) The mldsa-native project authors
 *   SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * and follows the entry-point pattern of AWS-LC's
 * crypto/fipsmodule/ml_dsa/ml_dsa.c:
 *   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *   SPDX-License-Identifier: Apache-2.0 OR ISC
 *
 * Changes: the expanded matrix and the transformed key material are computed
 * once and kept in a caller-owned object; no arithmetic is changed. The
 * object holds public data only: it comes from malloc of the C library, is
 * set to zero once, and is released with free without being erased.
 *
 * Copyright (c) 2026 a16z
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PRETZEL_AWS_PREPARED_VERIFY_ADAPTER_44_H
#define PRETZEL_AWS_PREPARED_VERIFY_ADAPTER_44_H
#include <stddef.h>
#include <stdint.h>
#include <openssl/base.h>
/* The bytes that pretzel_mldsa44_verify_new allocates and sets to zero. */
OPENSSL_EXPORT size_t pretzel_mldsa44_verify_object_bytes(void);
OPENSSL_EXPORT void *pretzel_mldsa44_verify_new(const uint8_t *pk, size_t pk_len);
OPENSSL_EXPORT void pretzel_mldsa44_verify_free(void *prepared);
OPENSSL_EXPORT int pretzel_mldsa44_verify_prepared(const void *prepared,
    const uint8_t *sig, size_t sig_len, const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len);
#endif
