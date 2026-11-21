// Wrappers of the transport routines: each calls `X_impl` and then stores zero over a fixed range
// of stack below its own frame. The Rust contract is in `ct_interval_transport.rs`.
#define SYM(x) _##x
.text
.p2align 2
.global SYM(pretzel44_interval_prepare_slots)
SYM(pretzel44_interval_prepare_slots):
sub sp, sp, #16
str x30, [sp, #8]
str xzr, [sp]
bl SYM(pretzel44_interval_prepare_slots_impl)
sub sp, sp, #2048
mov x16, sp
mov x17, #128
1:
stp xzr, xzr, [x16], #16
subs x17, x17, #1
b.ne 1b
add sp, sp, #2048
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
.p2align 2
.global SYM(pretzel44_interval_coarse_step)
SYM(pretzel44_interval_coarse_step):
sub sp, sp, #16
str x30, [sp, #8]
ldr x9, [sp, #16]
str x9, [sp]
bl SYM(pretzel44_interval_coarse_step_impl)
sub sp, sp, #64
mov x16, sp
mov x17, #4
1:
stp xzr, xzr, [x16], #16
subs x17, x17, #1
b.ne 1b
add sp, sp, #64
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
mov x0, #0
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
.p2align 2
.global SYM(pretzel44_interval_finish_deferred)
SYM(pretzel44_interval_finish_deferred):
sub sp, sp, #16
str x30, [sp, #8]
str xzr, [sp]
bl SYM(pretzel44_interval_finish_deferred_impl)
sub sp, sp, #256
mov x16, sp
mov x17, #16
1:
stp xzr, xzr, [x16], #16
subs x17, x17, #1
b.ne 1b
add sp, sp, #256
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
.p2align 2
.global SYM(pretzel44_interval_prepare_key)
SYM(pretzel44_interval_prepare_key):
sub sp, sp, #16
str x30, [sp, #8]
str xzr, [sp]
bl SYM(pretzel44_interval_prepare_key_impl)
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

#ifdef PRETZEL_NATIVE_TRANSPORT_BATCH
.text
.p2align 2
.global SYM(pretzel44_interval_batch)
SYM(pretzel44_interval_batch):
sub sp, sp, #16
str x30, [sp, #8]
str xzr, [sp]
bl SYM(pretzel44_interval_batch_impl)
sub sp, sp, #512
mov x16, sp
mov x17, #32
1:
stp xzr, xzr, [x16], #16
subs x17, x17, #1
b.ne 1b
add sp, sp, #512
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

#endif
