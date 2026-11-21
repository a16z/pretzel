# Packing of the secret polynomials in key generation, Pretzel-(3,3)

This note states what the source guarantees about the secret coefficients
between sampling and the returned secret key. It is a statement about the Rust
source. It is not a review of the emitted machine code.

## Owners

| Data | Owner and erasure |
| --- | --- |
| Secret and error coefficients | `s0: Zeroizing<[Poly; ELL]>` and `e: Zeroizing<[Poly; M]>` in `scheme.rs`; erased when they leave scope, on return, error and unwinding. |
| Product $A_0 s_0$ | one `acc: Zeroizing<Poly>` per row of the public key, in `scheme.rs`. `ring::add_pointwise_assign` adds each pointwise product into it in place, so no product or partial sum is returned or moved, and the owner is erased at the end of each row; $b = A_0 s_0 + e$ is copied out. The transforms `neon::ntt` (on the copy of $s_0$) and `neon::intt` (on `acc`) each work on a 512-byte copy of their argument in their own stack frame and do not erase it. |
| Packed coefficients | `packed: Zeroizing<[u8; TRIT_BYTES]>` (384 bytes) in the caller, initialized with zeros before `encode::keygen_pack_trits` borrows it. The packer writes each byte into this owner and returns nothing. |
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
at shifts $0,2,4,6$. Its loops run over public counts (6 polynomials, 64 groups
of four coefficients); input and output addresses depend only on the counters,
and there is no table lookup, branch or assertion on a coefficient. The test
`every_four_trits_and_poly_boundary_matches_old_packer` checks all 81
combinations of four coefficients and every polynomial boundary, starting from
a destination filled with nonzero bytes.

## Limits

Scalar temporaries, registers and copies that the compiler places on the stack
have no owner of their own and are not erased by the source. This crate has no
stack scrub at its key-generation entry, with or without the Cargo feature
`stack-wipe`. The properties above are claims about
the source; the emitted instructions are not certified.
