# Secret data in key generation, Pretzel-(5,5)

This note states what the source guarantees about the secret coefficients
between sampling and the returned secret key, and what the CI job
`level5-keygen-depth` checks about the stack scrub of key generation, which
exists only with the Cargo feature `stack-wipe` (off by default). The
first two sections are statements about the Rust source, not a review of the
emitted machine code.

## Owners

| Data | Owner and erasure |
| --- | --- |
| Secret and error coefficients | `s0: Zeroizing<[Poly; ELL]>` and `e: Zeroizing<[Poly; M]>` in `scheme.rs`; erased when they leave scope, on return, error and unwinding. |
| Packed coefficients | `packed: Zeroizing<[u8; TRIT_BYTES]>` (640 bytes) in the caller, initialized with zeros before `encode::keygen_pack_trits` borrows it. The packer writes each byte into this owner and returns nothing. |
| Serialized secret key | `sk: Zeroizing<Vec<u8>>`, allocated with its exact public length, so appending never reallocates. The tagged key is a second `Zeroizing` vector; the first is erased when it is dropped. |
| Returned secret key | wrapped in `GuardedDrop`, whose destructor erases the vector with the timing guard held, also on unwinding. |
| Seeds and PRF key | `Zeroizing` buffers; the matrix seed is also public-key data. |

Every fallible step of key generation (entropy requests, dither setup) happens
before packing, so no error return exists while the packed owner is live. On
an unwinding panic the owners are erased in reverse order of creation. An
abort or process termination runs no destructor.

## Fixed work

`keygen_pack_trits` maps each coefficient of $\{-1,0,1\}$ to two bits with
`((u & 3) ^ (u >> 31))`, giving $2,0,1$, and stores four coefficients per byte
at shifts $0,2,4,6$. Its loops run over public counts (10 polynomials, 64
groups of four coefficients); input and output addresses depend only on the
counters, and there is no table lookup, branch or assertion on a coefficient.
The test `every_four_trits_and_poly_boundary_matches_flat_packer` checks all 81
combinations of four coefficients and every polynomial boundary, starting from
a destination filled with nonzero bytes.

## Stack scrub

By default key generation does not scrub the stack it leaves behind: the
frames it leaves on return are not erased, and this section does not apply.

With the Cargo feature `stack-wipe`, the key-generation entry creates
`StackScrub<KEYGEN_SCRUB_WORDS>` after the timing guard and before the
private body. `KEYGEN_SCRUB_WORDS` is 16384 words, 131072 bytes. The scrub
runs on return, error and unwinding. Frames of the caller and registers are
outside it.

The CI job `level5-keygen-depth` (`scripts/stack_depth_ci.py`) checks, on the
release image it builds with that feature, that key generation stays inside
that extent with a margin of 32768 bytes:

1. A static bound. `scripts/stack_depth_static.py` computes the deepest chain
   of frames from the call graph of the image. It fails on recursion, on an
   unresolved indirect call and on an unresolved stack adjustment. Every
   system routine is charged a fixed allowance of 4096 bytes. Thread-local
   accesses and the one-time initialization closure are resolved from the
   image's own descriptors and tables. The bound plus the margin must not
   exceed 131072 bytes.
2. An observation of the whole body under the debugger for 4096 deterministic
   seeds, one run with operating-system entropy, one injected entropy failure
   and one forced retry of the secret sampling. Each case must leave the
   scrubbed extent erased, and the deepest observed use plus the margin must
   not exceed 131072 bytes. An observed depth is a lower bound on the worst
   case; it does not replace the static bound.
3. An observation of the system routines on 31 of the seeds and the same three
   special cases. Each observed routine must use at most 2048 bytes, half of
   its allowance. Routines that were not observed keep their allowance and are
   listed by name in the report.

All three steps must run on the same executable, identified by its SHA-256.

The check covers the image that the job builds (the release profile with the
feature `stack-wipe`), with operating-system entropy, valid inputs and no
panic hook installed. It is a statement about that image, not about other
builds of the crate. Outside it: custom `EntropySource`
implementations, which run their own code on the stack, and panics, where the
scrub still runs on unwinding but the depth is not bounded. The allowances for
system routines are assumptions supported by measurement, not a proof about
the system library.

## Limits

Scalar temporaries, registers and copies that the compiler places on the stack
are not erased by the source in the default build; with the feature
`stack-wipe`, those outside the scrubbed extent are not erased. The
properties in the first two sections are claims about the source; the emitted
instructions are not certified.
