/*
 * Benchmark adapter for AWS-LC (https://github.com/aws/aws-lc) at commit
 * a3d1e685552f05a9ad04a2946962c03e97bdecac. Not part of AWS-LC and not an
 * AWS-LC API: the prepared-key entry points defined below
 * (pretzel_mldsa87_prepared_*) belong to this repository.
 * This file is compiled inside AWS-LC's
 * crypto/fipsmodule/ml_dsa/mldsa/sign.c through the include added by
 * aws-lc-prepared-adapters.patch; that file is otherwise unchanged.
 *
 * This file restates the body of the signing function of that source file
 * (the pure-mode path, with the key unpacking moved into the prepared
 * object) and calls its internal functions, among them its unmodified
 * signing-attempt function mld_attempt_signature_generation:
 *   Copyright (c) The mldsa-native project authors
 *   SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * It follows the entry-point pattern of AWS-LC's
 * crypto/fipsmodule/ml_dsa/ml_dsa.c (the self-test and service-indicator
 * calls):
 *   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *   SPDX-License-Identifier: Apache-2.0 OR ISC
 *
 * Changes: the expanded matrix and the transformed key material are computed
 * once and kept in a caller-owned object, which signing only reads; no
 * arithmetic is changed, and every call uses the unmodified signing-attempt
 * function and its cleanup. The functions of AWS-LC are unchanged. This
 * file is included only when sign.c is compiled for ML-DSA-87, before that
 * file undefines its macros.
 *
 * Copyright (c) 2026 a16z
 * SPDX-License-Identifier: Apache-2.0
 */
#include "aws_prepared_adapter_87.h"
#include <openssl/mem.h>
#include "crypto/fipsmodule/service_indicator/internal.h"

#if MLD_CONFIG_PARAMETER_SET != 87 || defined(MLD_CONFIG_REDUCE_RAM) || \
    defined(MLD_CONFIG_CONTEXT_PARAMETER) || defined(MLD_CONFIG_CUSTOM_ALLOC_FREE) || \
    defined(MLD_CONFIG_SIGN_HOOK_RESUME) || defined(MLD_CONFIG_SIGN_HOOK_ATTEMPT) || \
    defined(MLD_CONFIG_SIGN_HOOK_FINISH)
#error Prepared benchmark requires the pinned eager, context-free AWS-LC build
#endif

typedef struct {
  void *allocation;
  mld_polymat matrix;
  mld_sk_s1hat s1hat;
  mld_sk_s2hat s2hat;
  mld_sk_t0hat t0hat;
  uint8_t tr[MLDSA_TRBYTES];
  uint8_t key[MLDSA_SEEDBYTES];
} pretzel_prepared87;

#define PRETZEL_PREPARED87_ALLOC_BYTES (sizeof(pretzel_prepared87) + MLD_DEFAULT_ALIGN - 1)

void *pretzel_mldsa87_prepared_new(const uint8_t *sk, size_t sk_len) {
  SET_DIT_AUTO_RESET;
  boringssl_ensure_ml_dsa_self_test();
  if (sk == NULL || sk_len != MLDSA_CRYPTO_SECRETKEYBYTES) {
    return NULL;
  }
  /* Validate imported packed keys outside the signing timer using the
   * existing upstream routine; it also checks the stored tr and t0. */
  MLD_ALIGN uint8_t public_key[MLDSA_CRYPTO_PUBLICKEYBYTES];
  if (mld_sign_pk_from_sk(public_key, sk, unused) != 0) {
    mld_zeroize(public_key, sizeof(public_key));
    return NULL;
  }
  mld_zeroize(public_key, sizeof(public_key));
  void *allocation = OPENSSL_zalloc(PRETZEL_PREPARED87_ALLOC_BYTES);
  if (allocation == NULL) {
    return NULL;
  }
  uintptr_t aligned = ((uintptr_t)allocation + MLD_DEFAULT_ALIGN - 1) &
                      ~((uintptr_t)MLD_DEFAULT_ALIGN - 1);
  pretzel_prepared87 *p = (pretzel_prepared87 *)aligned;
  p->allocation = allocation;
  MLD_ALIGN uint8_t rho[MLDSA_SEEDBYTES];
  mld_unpack_sk(rho, p->tr, p->key, &p->t0hat, &p->s1hat, &p->s2hat, sk);
  MLD_CT_TESTING_DECLASSIFY(rho, sizeof(rho));
  mld_polyvec_matrix_expand(&p->matrix, rho);
  mld_zeroize(rho, sizeof(rho));
  return p;
}

void pretzel_mldsa87_prepared_free(void *prepared) {
  if (prepared != NULL) {
    pretzel_prepared87 *p = (pretzel_prepared87 *)prepared;
    void *allocation = p->allocation;
    mld_zeroize(allocation, PRETZEL_PREPARED87_ALLOC_BYTES);
    OPENSSL_free(allocation);
  }
}

static int pretzel_prepared87_core(const pretzel_prepared87 *p,
    uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len, const uint8_t rnd[MLDSA_RNDBYTES]) {
  int ret = MLD_ERR_INVALID_ARG;
  MLD_ALLOC(pre, uint8_t, MLD_DOMAIN_SEPARATION_MAX_BYTES, unused);
  MLD_ALLOC(mu, uint8_t, MLDSA_CRHBYTES, unused);
  MLD_ALLOC(rhoprime, uint8_t, MLDSA_CRHBYTES, unused);
  if (p == NULL || (message == NULL && message_len != 0) ||
      (ctx == NULL && ctx_len != 0)) {
    goto cleanup;
  }
  size_t pre_len = mld_prepare_domain_separation_prefix(pre, NULL, 0, ctx,
                                                       ctx_len, MLD_PREHASH_NONE);
  if (pre_len == 0) { goto cleanup; }
  mld_H(mu, MLDSA_CRHBYTES, p->tr, MLDSA_TRBYTES, pre, pre_len,
        message, message_len);
  mld_H(rhoprime, MLDSA_CRHBYTES, p->key, MLDSA_SEEDBYTES,
        rnd, MLDSA_RNDBYTES, mu, MLDSA_CRHBYTES);
  const uint16_t max_attempts = mld_get_max_signing_attempts();
  ret = MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED;
  for (uint16_t attempt = 0; attempt < max_attempts; attempt++) {
    uint16_t kappa = (uint16_t)(attempt * MLDSA_L);
    /* The upstream helper's mat parameter accommodates lazy builds; its
     * eager path only reads the matrix, as its contract states. This adapter
     * rejects the lazy configuration above, so the const cast is read-only. */
    ret = mld_attempt_signature_generation(sig, mu, rhoprime, kappa,
        (mld_polymat *)&p->matrix, &p->s1hat, &p->s2hat, &p->t0hat, unused);
    if (ret != MLD_ERR_FAIL) { goto cleanup; }
  }
  ret = MLD_ERR_SIGN_ATTEMPTS_EXHAUSTED;
cleanup:
  if (ret != 0) { mld_zeroize(sig, MLDSA_CRYPTO_BYTES); }
  MLD_FREE(rhoprime, uint8_t, MLDSA_CRHBYTES, unused);
  MLD_FREE(mu, uint8_t, MLDSA_CRHBYTES, unused);
  MLD_FREE(pre, uint8_t, MLD_DOMAIN_SEPARATION_MAX_BYTES, unused);
  return ret;
}

int pretzel_mldsa87_prepared_sign_seed(const void *prepared,
    uint8_t sig[4627], const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len, const uint8_t rnd[32]) {
  SET_DIT_AUTO_RESET;
  boringssl_ensure_ml_dsa_self_test();
  FIPS_service_indicator_lock_state();
  int ret = pretzel_prepared87_core((const pretzel_prepared87 *)prepared,
      sig, message, message_len, ctx, ctx_len, rnd);
  FIPS_service_indicator_unlock_state();
  if (ret == 0) { FIPS_service_indicator_update_state(); }
  return ret == 0;
}

int pretzel_mldsa87_prepared_sign(const void *prepared,
    uint8_t sig[4627], const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len) {
  SET_DIT_AUTO_RESET;
  boringssl_ensure_ml_dsa_self_test();
  FIPS_service_indicator_lock_state();
  if (prepared == NULL || ctx_len > 255 ||
      (ctx == NULL && ctx_len != 0) || (message == NULL && message_len != 0)) {
    mld_zeroize(sig, MLDSA_CRYPTO_BYTES);
    FIPS_service_indicator_unlock_state();
    return 0;
  }
  MLD_ALIGN uint8_t rnd[MLDSA_RNDBYTES];
  int ret = mld_randombytes(rnd, sizeof(rnd));
  if (ret == 0) {
    MLD_CT_TESTING_SECRET(rnd, sizeof(rnd));
    ret = pretzel_prepared87_core((const pretzel_prepared87 *)prepared,
        sig, message, message_len, ctx, ctx_len, rnd);
  } else {
    mld_zeroize(sig, MLDSA_CRYPTO_BYTES);
  }
  mld_zeroize(rnd, sizeof(rnd));
  FIPS_service_indicator_unlock_state();
  if (ret == 0) { FIPS_service_indicator_update_state(); }
  return ret == 0;
}

#undef PRETZEL_PREPARED87_ALLOC_BYTES
