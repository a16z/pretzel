/* ML-DSA side of the comparison: AWS-LC at the pinned commit, built with the
 * prepared-key adapters of adapters/ (see README.md beside this file).
 *
 * Arguments: OPERATION CALLS WARMUP, or --validate. The process makes a fresh
 * key pair with operating-system entropy, checks that the prepared-key entry
 * points and the unmodified AWS-LC functions agree (the same signature bytes
 * for the same randomness, acceptance, and rejection of a changed message),
 * checks that the unmodified ml_dsa_NN_verify rejects a signature with one
 * changed byte, then times CALLS calls of one operation after WARMUP
 * unmeasured calls and prints one line. Thread CPU time is read around every
 * call. No check runs inside a timed interval.
 *
 *   keygen                    EVP_PKEY_pqdsa_new_raw_private_key from a fresh seed
 *                             and the export of both keys (unmodified AWS-LC)
 *   prepare_pk                verify_new and verify_free of the adapters: one
 *                             malloc, the object set to zero once, filled, one
 *                             free; the prepared object is not erased
 *   sign                      prepared_sign of the adapters, prepared secret key
 *   verify                    verify_prepared of the adapters, prepared public key
 *   verify_with_preparation   the unmodified ml_dsa_NN_verify of AWS-LC on the
 *                             serialized public key (not the adapters)
 *
 * The header crypto/fipsmodule/ml_dsa/ml_dsa.h is an internal header of
 * AWS-LC; it declares the unmodified functions used by the timed call of
 * verify_with_preparation and by the checks. */
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif
#include "crypto/fipsmodule/ml_dsa/ml_dsa.h"
#if LEVEL == 44
#include "aws_prepared_adapter_44.h"
#include "aws_prepared_verify_adapter_44.h"
#define PK_BYTES 1312
#define SK_BYTES 2560
#define SIG_BYTES 2420
#define NID_VALUE NID_MLDSA44
#elif LEVEL == 65
#include "aws_prepared_adapter_65.h"
#include "aws_prepared_verify_adapter_65.h"
#define PK_BYTES 1952
#define SK_BYTES 4032
#define SIG_BYTES 3309
#define NID_VALUE NID_MLDSA65
#elif LEVEL == 87
#include "aws_prepared_adapter_87.h"
#include "aws_prepared_verify_adapter_87.h"
#define PK_BYTES 2592
#define SK_BYTES 4896
#define SIG_BYTES 4627
#define NID_VALUE NID_MLDSA87
#else
#error Unsupported ML-DSA level
#endif
#define ADAPTER_(level, name) pretzel_mldsa##level##_##name
#define ADAPTER(level, name) ADAPTER_(level, name)
#define API(name) ADAPTER(LEVEL, name)
#define STOCK_(level, name) ml_dsa_##level##_##name
#define STOCK(level, name) STOCK_(level, name)
#define MESSAGE_BYTES 32
static void require(int ok, const char *reason) {
  if (!ok) { fprintf(stderr, "ML-DSA-%d: %s\n", LEVEL, reason); exit(1); }
}
static unsigned number(const char *arg) {
  char *end = NULL;
  unsigned long n = strtoul(arg, &end, 10);
  require(*arg >= '0' && *arg <= '9' && !*end && n <= 100000, "invalid count");
  return (unsigned)n;
}
static uint64_t cpu_ns(void) {
  struct timespec t;
  require(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t) == 0, "thread clock");
  return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static uint64_t wall_ns(void) {
  uint64_t t = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
  require(t != 0, "uptime clock");
  return t;
}
static int compare_u64(const void *left, const void *right) {
  uint64_t a = *(const uint64_t *)left, b = *(const uint64_t *)right;
  return a < b ? -1 : (a > b ? 1 : 0);
}
static void keypair(uint8_t *pk, uint8_t *sk) {
  uint8_t seed[32];
  require(getentropy(seed, sizeof(seed)) == 0, "OS entropy");
  EVP_PKEY *owner = EVP_PKEY_pqdsa_new_raw_private_key(NID_VALUE, seed, sizeof(seed));
  require(owner != NULL, "key generation");
  size_t length = PK_BYTES;
  require(EVP_PKEY_get_raw_public_key(owner, pk, &length) && length == PK_BYTES, "public key export");
  length = SK_BYTES;
  require(EVP_PKEY_get_raw_private_key(owner, sk, &length) && length == SK_BYTES, "secret key export");
  EVP_PKEY_free(owner);
  OPENSSL_cleanse(seed, sizeof(seed));
}
/* The timed call of verify_with_preparation: the unmodified AWS-LC function. */
static int stock_verify(const uint8_t *pk, const uint8_t *sig, const uint8_t *msg, size_t message_bytes) {
  return STOCK(LEVEL, verify)(pk, sig, SIG_BYTES, msg, message_bytes, NULL, 0) == ML_DSA_SUCCESS;
}
/* Untimed check: a second prepared public key, made and released here, verifies. */
static int second_object_verify(const uint8_t *pk, const uint8_t *sig, const uint8_t *msg, size_t message_bytes) {
  void *p = API(verify_new)(pk, PK_BYTES);
  if (!p) return 0;
  int ok = API(verify_prepared)(p, sig, SIG_BYTES, msg, message_bytes, NULL, 0);
  API(verify_free)(p);
  return ok;
}
int main(int argc, char **argv) {
  int validate = argc == 2 && !strcmp(argv[1], "--validate");
  require(validate || argc == 4, "OPERATION CALLS WARMUP or --validate");
  const char *operations[] = {"sign", "verify", "verify_with_preparation", "prepare_pk", "keygen"};
  unsigned op = 0;
  while (op < 5 && strcmp(validate ? "sign" : argv[1], operations[op])) ++op;
  require(op < 5, "operation");
  const size_t message_bytes = MESSAGE_BYTES;
  uint8_t pk[PK_BYTES], sk[SK_BYTES], sig[SIG_BYTES], stock[SIG_BYTES];
  uint8_t msg[MESSAGE_BYTES];
  memset(msg, 43, message_bytes);
  keypair(pk, sk);
  void *signer = API(prepared_new)(sk, SK_BYTES), *verifier = API(verify_new)(pk, PK_BYTES);
  require(signer && verifier, "key preparation");
  /* Fixed public validation randomness, never used by timed signing. */
  uint8_t rnd[32] = {0}, prefix[2] = {0, 0};
  size_t size = 0;
  require(API(prepared_sign_seed)(signer, sig, msg, message_bytes, NULL, 0, rnd), "prepared signing with fixed randomness");
  require(STOCK(LEVEL, sign_internal)(sk, stock, &size, msg, message_bytes, prefix, 2, rnd) == ML_DSA_SUCCESS && size == SIG_BYTES, "unmodified AWS-LC signing with fixed randomness");
  require(!memcmp(sig, stock, SIG_BYTES), "the prepared signer and the unmodified AWS-LC signer gave different signatures");
  require(STOCK(LEVEL, verify)(pk, sig, SIG_BYTES, msg, message_bytes, NULL, 0) == ML_DSA_SUCCESS, "unmodified AWS-LC verification");
  require(API(verify_prepared)(verifier, sig, SIG_BYTES, msg, message_bytes, NULL, 0) && second_object_verify(pk, sig, msg, message_bytes), "prepared verification");
  require(STOCK(LEVEL, sign)(sk, stock, &size, msg, message_bytes, NULL, 0) == ML_DSA_SUCCESS && size == SIG_BYTES, "unmodified AWS-LC signing from the serialized key");
  require(STOCK(LEVEL, verify)(pk, stock, size, msg, message_bytes, NULL, 0) == ML_DSA_SUCCESS, "unmodified AWS-LC verification of its own signature");
  msg[31] ^= 1;
  require(STOCK(LEVEL, verify)(pk, sig, SIG_BYTES, msg, message_bytes, NULL, 0) != ML_DSA_SUCCESS, "unmodified AWS-LC accepted a changed message");
  require(!API(verify_prepared)(verifier, sig, SIG_BYTES, msg, message_bytes, NULL, 0) && !second_object_verify(pk, sig, msg, message_bytes), "the prepared verifier accepted a changed message");
  require(!stock_verify(pk, sig, msg, message_bytes), "unmodified AWS-LC verification from the serialized key accepted a changed message");
  msg[31] ^= 1;
  memcpy(stock, sig, SIG_BYTES);
  stock[0] ^= 1;
  require(stock_verify(pk, sig, msg, message_bytes), "unmodified AWS-LC verification from the serialized key");
  require(!stock_verify(pk, stock, msg, message_bytes), "unmodified AWS-LC accepted a signature with a changed first byte");
  stock[0] ^= 1;
  stock[SIG_BYTES / 2] ^= 0x10;
  require(!stock_verify(pk, stock, msg, message_bytes), "unmodified AWS-LC accepted a signature with a changed byte in its body");
  if (validate) {
    API(prepared_free)(signer); API(verify_free)(verifier);
    OPENSSL_cleanse(sk, sizeof(sk));
    printf("prepared public key object: %zu bytes\n", API(verify_object_bytes)());
    puts("The prepared-key entry points and the unmodified AWS-LC functions agree: the same signature bytes, "
         "acceptance, and rejection of a changed message; the unmodified ml_dsa_NN_verify rejects a signature "
         "with one changed byte. Nothing was timed.");
    return 0;
  }
  unsigned calls = number(argv[2]), warmup = number(argv[3]);
  require(calls > 0 && warmup <= 1024, "counts");
  uint64_t *cpu = calloc(calls, sizeof(uint64_t));
  require(cpu != NULL, "sample allocation");
  uint64_t wall_total = 0;
  uint8_t next_pk[PK_BYTES], next_sk[SK_BYTES];
  for (unsigned round = 0; round < calls + warmup; ++round) {
    int ok = 1;
    uint64_t c = cpu_ns(), w = wall_ns();
    switch (op) {
      case 0: ok = API(prepared_sign)(signer, sig, msg, message_bytes, NULL, 0); break;
      case 1: ok = API(verify_prepared)(verifier, sig, SIG_BYTES, msg, message_bytes, NULL, 0); break;
      case 2: ok = stock_verify(pk, sig, msg, message_bytes); break;
      case 4: keypair(next_pk, next_sk); break;
      case 3: { void *p = API(verify_new)(pk, PK_BYTES); ok = p != NULL; API(verify_free)(p); break; }
    }
    w = wall_ns() - w;
    c = cpu_ns() - c;
    require(ok, "measured operation failed");
    if (op == 4) {
      void *owner = API(prepared_new)(next_sk, SK_BYTES);
      require(owner != NULL, "generated secret key preparation");
      require(API(prepared_sign)(owner, stock, msg, message_bytes, NULL, 0), "generated key sign");
      API(prepared_free)(owner);
      require(STOCK(LEVEL, verify)(next_pk, stock, SIG_BYTES, msg, message_bytes, NULL, 0) == ML_DSA_SUCCESS, "unmodified AWS-LC verification with the generated key");
      OPENSSL_cleanse(next_sk, sizeof(next_sk));
    } else if (op == 0) {
      require(STOCK(LEVEL, verify)(pk, sig, SIG_BYTES, msg, message_bytes, NULL, 0) == ML_DSA_SUCCESS, "unmodified AWS-LC verification of the measured signature");
    }
    if (round >= warmup) { cpu[round - warmup] = c; wall_total += w; }
  }
  uint64_t cpu_total = 0;
  for (unsigned round = 0; round < calls; ++round) cpu_total += cpu[round];
  qsort(cpu, calls, sizeof(uint64_t), compare_u64);
  /* Fields: operation, calls, CPU ns total, wall ns total, median CPU ns, least CPU ns,
   * signing attempts (not counted on this side: 0). */
  printf("bench\t%s\t%u\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t0\n",
         operations[op], calls, cpu_total, wall_total, cpu[calls / 2], cpu[0]);
  API(prepared_free)(signer);
  API(verify_free)(verifier);
  OPENSSL_cleanse(sk, sizeof(sk));
  free(cpu);
  return 0;
}
