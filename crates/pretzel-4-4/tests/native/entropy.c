/* Public test entropy tape. It defines pretzel_test_logical_entropy, the hook that the library
 * calls when it is built with the feature `conformance`. Never link this object into an
 * application. */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
static _Thread_local struct {
    uint64_t state, word, calls, bytes, fail_at;
    unsigned remaining;
    int active, partial;
} tape;

void pretzel_test_tape_reset(uint64_t seed, uint64_t fail_at, int partial) {
    tape = (__typeof__(tape)){.state=seed, .fail_at=fail_at,
                             .active=1, .partial=partial};
}
void pretzel_test_tape_end(void) { tape.active=0; }
uint64_t pretzel_test_tape_calls(void) { return tape.calls; }
uint64_t pretzel_test_tape_bytes(void) { return tape.bytes; }
static unsigned char next(void) {
    if (!tape.remaining) {
        uint64_t z = (tape.state += UINT64_C(0x9e3779b97f4a7c15));
        z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
        tape.word = z ^ (z >> 31);
        tape.remaining=8;
    }
    unsigned char b=(unsigned char)tape.word;
    tape.word >>= 8; --tape.remaining;
    return b;
}
void pretzel_test_tape_suffix(unsigned char *out) {
    for (size_t i=0;i<64;i++) out[i]=next();
}
/* 1 delegates inactive requests to the real OS. Empty fills consume nothing. */
int pretzel_test_logical_entropy(unsigned char *out, size_t len) {
    if (!tape.active) return 1;
    if (len == 0) return 0;
    ++tape.calls;
    if (tape.fail_at && tape.calls == tape.fail_at) {
        if (tape.partial) for (size_t i=0;i<len/2;i++) out[i]=next();
        errno=EIO;
        return -1;
    }
    for (size_t i=0;i<len;i++) out[i]=next();
    tape.bytes+=len;
    return 0;
}
