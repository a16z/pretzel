#define SYM(x) _##x
// AArch64 wrapper; verify emitted helper and gather frames fit the reserved region.
.text
.p2align 2
.global SYM(pretzel44_warm_tail192)
SYM(pretzel44_warm_tail192):
.cfi_startproc
sub sp,sp,#1088
.cfi_def_cfa_offset 1088
add x16,sp,#1056
stp x29,x30,[x16,#16]
.cfi_offset x29,-16
.cfi_offset x30,-8
stp xzr,xzr,[x16]
add x29,x16,#16
// The lower 1056-byte region is reserved for a 992-byte helper plus 64-byte gather.
add sp,sp,#1056
.cfi_def_cfa_offset 32
bl SYM(pretzel44_warm_tail192_impl)
sub sp,sp,#1056
.cfi_def_cfa_offset 1088
mov x16,sp
mov x17,#66
1:
stp xzr,xzr,[x16],#16
subs x17,x17,#1
b.ne 1b
add sp,sp,#1056
.cfi_def_cfa_offset 32
ldp x29,x30,[sp,#16]
.cfi_restore x29
.cfi_restore x30
stp xzr,xzr,[sp]
stp xzr,xzr,[sp,#16]
mov x0,#0
mov x1,#0
mov x2,#0
mov x3,#0
mov x4,#0
mov x5,#0
mov x6,#0
mov x7,#0
mov x8,#0
mov x9,#0
mov x10,#0
mov x11,#0
mov x12,#0
mov x13,#0
mov x14,#0
mov x15,#0
mov x16,#0
mov x17,#0
movi v0.16b,#0
movi v1.16b,#0
movi v2.16b,#0
movi v3.16b,#0
movi v4.16b,#0
movi v5.16b,#0
movi v6.16b,#0
movi v7.16b,#0
movi v16.16b,#0
movi v17.16b,#0
movi v18.16b,#0
movi v19.16b,#0
movi v20.16b,#0
movi v21.16b,#0
movi v22.16b,#0
movi v23.16b,#0
movi v24.16b,#0
movi v25.16b,#0
movi v26.16b,#0
movi v27.16b,#0
movi v28.16b,#0
movi v29.16b,#0
movi v30.16b,#0
movi v31.16b,#0
mov v8.d[1],xzr
mov v9.d[1],xzr
mov v10.d[1],xzr
mov v11.d[1],xzr
mov v12.d[1],xzr
mov v13.d[1],xzr
mov v14.d[1],xzr
mov v15.d[1],xzr
msr nzcv,xzr
add sp,sp,#32
.cfi_def_cfa_offset 0
ret
.cfi_endproc
