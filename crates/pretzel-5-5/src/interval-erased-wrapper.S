// Erasing wrapper for the interval preparation of a secret key.
// pretzel55_interval_prepare_key keeps its three arguments and calls
// pretzel55_interval_prepare_key_impl (interval-transport.c). After the call it
// stores zero over 4096 bytes of stack below its own frame, clears x1 to x17,
// v0 to v7, v16 to v31, the upper halves of v8 to v15 and the flags, erases its
// own 16-byte frame and returns. x0 is not cleared.
// Assembled by build.rs for macOS on AArch64.
#define SYM(x) _##x
.text
.p2align 2
.global SYM(pretzel55_interval_prepare_key)
SYM(pretzel55_interval_prepare_key):
sub sp, sp, #16
str x30, [sp, #8]
str xzr, [sp]
bl SYM(pretzel55_interval_prepare_key_impl)
sub sp, sp, #4096
mov x16, sp
mov x17, #256
1:
stp xzr, xzr, [x16], #16
subs x17, x17, #1
b.ne 1b
add sp, sp, #4096
mov x1, #0
mov x2, #0
mov x3, #0
mov x4, #0
mov x5, #0
mov x6, #0
mov x7, #0
mov x8, #0
mov x9, #0
mov x10, #0
mov x11, #0
mov x12, #0
mov x13, #0
mov x14, #0
mov x15, #0
mov x16, #0
mov x17, #0
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
mov v8.d[1], xzr
mov v9.d[1], xzr
mov v10.d[1], xzr
mov v11.d[1], xzr
mov v12.d[1], xzr
mov v13.d[1], xzr
mov v14.d[1], xzr
mov v15.d[1], xzr
msr nzcv, xzr
ldr x30, [sp, #8]
stp xzr, xzr, [sp]
add sp, sp, #16
ret
