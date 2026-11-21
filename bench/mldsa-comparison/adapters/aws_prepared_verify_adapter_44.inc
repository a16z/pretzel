/*
 * Benchmark adapter for AWS-LC (https://github.com/aws/aws-lc) at commit
 * a3d1e685552f05a9ad04a2946962c03e97bdecac. Not part of AWS-LC and not an
 * AWS-LC API: the prepared-key entry points defined below
 * (pretzel_mldsa44_verify_*) belong to this repository.
 * This file is compiled inside AWS-LC's
 * crypto/fipsmodule/ml_dsa/mldsa/sign.c through the include added by
 * aws-lc-prepared-adapters.patch; that file is otherwise unchanged.
 *
 * This file restates the body of mld_sign_verify_internal of that source
 * file (the pure-mode path, with the public-key preprocessing moved into
 * the prepared object) and calls its internal functions:
 *   Copyright (c) The mldsa-native project authors
 *   SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * It follows the entry-point pattern of AWS-LC's
 * crypto/fipsmodule/ml_dsa/ml_dsa.c (the self-test and service-indicator
 * calls):
 *   Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *   SPDX-License-Identifier: Apache-2.0 OR ISC
 *
 * Changes: the expanded matrix and the transformed key material are computed
 * once and kept in a caller-owned object; no arithmetic is changed. Only the
 * preprocessing of the public key moves into the prepared object. This file
 * is included only when sign.c is compiled for ML-DSA-44, beside the signing
 * adapter.
 *
 * The prepared object holds public data only. pretzel_mldsa44_verify_new
 * takes it from malloc of the C library, sets the whole object to zero once
 * and fills it; pretzel_mldsa44_verify_free releases it with free of the C
 * library and erases nothing. OPENSSL_zalloc and OPENSSL_free of AWS-LC are
 * not used for it, because OPENSSL_free erases every block that it releases.
 *
 * Copyright (c) 2026 a16z
 * SPDX-License-Identifier: Apache-2.0
 */
#include "aws_prepared_verify_adapter_44.h"
#include <stdlib.h>
#include <openssl/mem.h>
#include "crypto/fipsmodule/service_indicator/internal.h"

#if MLD_CONFIG_PARAMETER_SET != 44 || defined(MLD_CONFIG_REDUCE_RAM) || \
    defined(MLD_CONFIG_CONTEXT_PARAMETER) || defined(MLD_CONFIG_CUSTOM_ALLOC_FREE)
#error Prepared benchmark requires the pinned eager, context-free AWS-LC build
#endif

typedef struct {
  void *allocation;
  mld_polymat matrix;
  mld_polyveck t1hat;
  uint8_t tr[MLDSA_TRBYTES];
} pretzel_verify44;

#define PRETZEL_VERIFY44_ALLOC_BYTES (sizeof(pretzel_verify44) + MLD_DEFAULT_ALIGN - 1)

size_t pretzel_mldsa44_verify_object_bytes(void) { return PRETZEL_VERIFY44_ALLOC_BYTES; }

void *pretzel_mldsa44_verify_new(const uint8_t *pk, size_t pk_len) {
  SET_DIT_AUTO_RESET;
  boringssl_ensure_ml_dsa_self_test();
  if (pk == NULL || pk_len != MLDSA_CRYPTO_PUBLICKEYBYTES) { return NULL; }
  /* Every fixed-width public-key encoding is canonical: rho is unrestricted
   * and each packed t1 coefficient occupies exactly ten bits. */
  void *allocation = malloc(PRETZEL_VERIFY44_ALLOC_BYTES);
  if (allocation == NULL) { return NULL; }
  /* OPENSSL_cleanse is a memset to zero that the compiler cannot remove or
   * merge with the allocation. */
  OPENSSL_cleanse(allocation, PRETZEL_VERIFY44_ALLOC_BYTES);
  uintptr_t aligned = ((uintptr_t)allocation + MLD_DEFAULT_ALIGN - 1) &
                      ~((uintptr_t)MLD_DEFAULT_ALIGN - 1);
  pretzel_verify44 *p = (pretzel_verify44 *)aligned;
  p->allocation = allocation;
  mld_polyvec_matrix_expand(&p->matrix, pk);
  for (unsigned int i = 0; i < MLDSA_K; i++) {
    mld_unpack_pk_t1(&p->t1hat.vec[i], pk, i);
    mld_poly_shiftl(&p->t1hat.vec[i]);
    mld_poly_ntt(&p->t1hat.vec[i]);
  }
  mld_H(p->tr, MLDSA_TRBYTES, pk, MLDSA_CRYPTO_PUBLICKEYBYTES, NULL, 0, NULL, 0);
  return p;
}

void pretzel_mldsa44_verify_free(void *prepared) {
  if (prepared != NULL) { free(((pretzel_verify44 *)prepared)->allocation); }
}

static int pretzel_verify44_core(const pretzel_verify44 *p,
    const uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t *message,
    size_t message_len, const uint8_t *ctx, size_t ctx_len) {
  int ret = MLD_ERR_INVALID_ARG;
  MLD_ALLOC(pre, uint8_t, MLD_DOMAIN_SEPARATION_MAX_BYTES, unused);
  MLD_ALLOC(buf, uint8_t, (MLDSA_K * MLDSA_POLYW1_PACKEDBYTES), unused);
  MLD_ALLOC(mu, uint8_t, MLDSA_CRHBYTES, unused);
  MLD_ALLOC(c, uint8_t, MLDSA_CTILDEBYTES, unused);
  MLD_ALLOC(c2, uint8_t, MLDSA_CTILDEBYTES, unused);
  MLD_ALLOC(z, mld_polyvecl, 1, unused);
  MLD_ALLOC(cp, mld_poly, 1, unused);
  MLD_ALLOC(w1, mld_poly, 1, unused);
  MLD_ALLOC(tmp, mld_poly, 1, unused);
  /* Default stack allocation is enforced above. No allocator can fail. */
  size_t pre_len = mld_prepare_domain_separation_prefix(pre, NULL, 0, ctx,
                                                       ctx_len, MLD_PREHASH_NONE);
  if (pre_len == 0) { goto cleanup; }
  mld_memcpy(c, sig, MLDSA_CTILDEBYTES);
  mld_polyvecl_unpack_z(z, sig + MLDSA_SIG_Z_OFFSET);
  if (mld_polyvecl_chknorm(z, MLDSA_GAMMA1 - MLDSA_BETA)) {
    ret = MLD_ERR_INVALID_SIGNATURE;
    goto cleanup;
  }
  mld_H(mu, MLDSA_CRHBYTES, p->tr, MLDSA_TRBYTES, pre, pre_len,
        message, message_len);
  mld_polyvecl_ntt(z);
  mld_poly_challenge(cp, c);
  mld_poly_ntt(cp);
  for (unsigned int i = 0; i < MLDSA_K; i++) {
    /* The eager helper's contract assigns only w1; its interface leaves mat
     * non-const to match the lazy implementation, which is rejected above. */
    mld_polyvec_matrix_pointwise_montgomery_row(w1, (mld_polymat *)&p->matrix, z, i);
    /* Exactly the precomputed result of unpack/shiftl/ntt in the upstream body. */
    *tmp = p->t1hat.vec[i];
    mld_poly_pointwise_montgomery(tmp, cp);
    mld_poly_sub(w1, tmp);
    mld_poly_reduce(w1);
    mld_poly_invntt_tomont(w1);
    mld_poly_caddq(w1);
    if (mld_sig_unpack_hints(tmp, sig, i) != 0) {
      ret = MLD_ERR_INVALID_SIGNATURE;
      goto cleanup;
    }
    mld_poly_use_hint(w1, tmp);
    mld_polyw1_pack(buf + i * MLDSA_POLYW1_PACKEDBYTES, w1);
  }
  mld_H(c2, MLDSA_CTILDEBYTES, mu, MLDSA_CRHBYTES, buf,
        MLDSA_K * MLDSA_POLYW1_PACKEDBYTES, NULL, 0);
  int cmp = mld_ct_memcmp(c, c2, MLDSA_CTILDEBYTES);
  MLD_CT_TESTING_DECLASSIFY(&cmp, sizeof(cmp));
  ret = cmp == 0 ? 0 : MLD_ERR_INVALID_SIGNATURE;
cleanup:
  MLD_FREE(tmp, mld_poly, 1, unused);
  MLD_FREE(w1, mld_poly, 1, unused);
  MLD_FREE(cp, mld_poly, 1, unused);
  MLD_FREE(z, mld_polyvecl, 1, unused);
  MLD_FREE(c2, uint8_t, MLDSA_CTILDEBYTES, unused);
  MLD_FREE(c, uint8_t, MLDSA_CTILDEBYTES, unused);
  MLD_FREE(mu, uint8_t, MLDSA_CRHBYTES, unused);
  MLD_FREE(buf, uint8_t, (MLDSA_K * MLDSA_POLYW1_PACKEDBYTES), unused);
  MLD_FREE(pre, uint8_t, MLD_DOMAIN_SEPARATION_MAX_BYTES, unused);
  return ret;
}

int pretzel_mldsa44_verify_prepared(const void *prepared,
    const uint8_t *sig, size_t sig_len, const uint8_t *message, size_t message_len,
    const uint8_t *ctx, size_t ctx_len) {
  SET_DIT_AUTO_RESET;
  boringssl_ensure_ml_dsa_self_test();
  FIPS_service_indicator_lock_state();
  int ret = MLD_ERR_INVALID_ARG;
  if (prepared != NULL && sig != NULL && sig_len == MLDSA_CRYPTO_BYTES &&
      ctx_len <= 255 && (ctx != NULL || ctx_len == 0) &&
      (message != NULL || message_len == 0)) {
    ret = pretzel_verify44_core((const pretzel_verify44 *)prepared, sig,
                                message, message_len, ctx, ctx_len);
  }
  FIPS_service_indicator_unlock_state();
  if (ret == 0) { FIPS_service_indicator_update_state(); }
  return ret == 0;
}

#undef PRETZEL_VERIFY44_ALLOC_BYTES
