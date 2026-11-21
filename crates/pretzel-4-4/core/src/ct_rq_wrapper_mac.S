// Wrapper of the rare-queue sampler. The Rust contract is in
// `ct_rarequeue.rs`. Pretzel-(3,3) includes this file under its own symbol
// names.
//
// After the body returns, the wrapper zeroes the 2048 bytes of stack directly
// below its own 16-byte frame record: it lowers the stack pointer by 2048,
// stores zero vectors upward from it in 64 fixed steps of 32 bytes, and raises
// the stack pointer again. Nothing is written below the stack pointer, the
// stack pointer stays 16-byte aligned, and the code is straight-line.
//
// Measured stack use below that frame record, in one release image of a
// downstream program per parameter set (rustc 1.90.0, Apple clang 17.0.0,
// release profile):
//   Pretzel-(4,4): frame of the body 544 bytes; deepest chain of callees that
//     do not erase their own frames `Xof::fill` 400 and `keccak_p` 192; reach
//     1136 bytes.
//   Pretzel-(3,3): frame of the body 240 bytes; chain `sample_with_word_limit`
//     480, `Xof::fill` 400 and `keccak_p` 192; reach 1312 bytes.
// The frame of `Xof::fill` holds two copies of a 136-byte squeezed block and
// the frame of `keccak_p` holds spilled state lanes. The extent of 2048 bytes
// leaves 736 bytes beyond the larger measured reach. Another compiler, profile
// or downstream program can change every figure, and nothing in this repository
// checks them.
.text
.if PRETZEL_NATIVE_SET == 33
.globl _pretzel33_rq_sample_wrapper
.else
.globl _pretzel44_rq_sample_wrapper
.endif
.p2align 2
.if PRETZEL_NATIVE_SET == 33
_pretzel33_rq_sample_wrapper:
.else
_pretzel44_rq_sample_wrapper:
.endif
stp x29, x30, [sp, #-16]!
mov x29, sp
.if PRETZEL_NATIVE_SET == 33
bl _pretzel33_rq_sample_body
.else
bl _pretzel44_rq_sample_body
.endif
sub sp, sp, #2048
mov x16, sp
movi v0.16b, #0
.rept 64
stp q0, q0, [x16], #32
.endr
add sp, sp, #2048
ldp x29, x30, [sp]
stp xzr, xzr, [sp]
add sp, sp, #16
mov x1, xzr
mov x2, xzr
mov x3, xzr
mov x4, xzr
mov x5, xzr
mov x6, xzr
mov x7, xzr
mov x8, xzr
mov x9, xzr
mov x10, xzr
mov x11, xzr
mov x12, xzr
mov x13, xzr
mov x14, xzr
mov x15, xzr
mov x16, xzr
mov x17, xzr
movi v0.16b, #0
movi v1.16b, #0
movi v2.16b, #0
movi v3.16b, #0
movi v4.16b, #0
movi v5.16b, #0
movi v6.16b, #0
movi v7.16b, #0
movi v16.16b, #0
movi v17.16b, #0
movi v18.16b, #0
movi v19.16b, #0
movi v20.16b, #0
movi v21.16b, #0
movi v22.16b, #0
movi v23.16b, #0
movi v24.16b, #0
movi v25.16b, #0
movi v26.16b, #0
movi v27.16b, #0
movi v28.16b, #0
movi v29.16b, #0
movi v30.16b, #0
movi v31.16b, #0
ins v8.d[1], xzr
ins v9.d[1], xzr
ins v10.d[1], xzr
ins v11.d[1], xzr
ins v12.d[1], xzr
ins v13.d[1], xzr
ins v14.d[1], xzr
ins v15.d[1], xzr
msr nzcv, xzr
ret
