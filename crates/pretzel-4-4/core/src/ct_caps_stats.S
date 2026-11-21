// x0 output [weight sum, square sum, infinity failure], x1 input i32s,
// x2 public length divisible by four, x3 six i64 Horner coefficients,
// x4 fixed 32-word correction table, x5 shift, x6 infinity cap.
// Only caller-saved x0..14, v0..7, v16..27; no stack or calls. Public
// extent branches only. Arithmetic on invalid inputs wraps as in Rust;
// their infinity failure remains set and prevents acceptance.
ld1 {v0.4s,v1.4s,v2.4s,v3.4s}, [x4], #64
ld1 {v4.4s,v5.4s,v6.4s,v7.4s}, [x4]
ld1 {v16.2d,v17.2d,v18.2d}, [x3]
dup v19.4s, w6
movi v20.2d, #0
movi v21.2d, #0
movi v22.4s, #0
mov w3, #0x0100
movk w3, #0x0302, lsl #16
cbz x2, 2f
.p2align 4
1:
ld1 {v23.4s}, [x1], #16
abs v23.4s, v23.4s
cmhi v26.4s, v23.4s, v19.4s
orr v22.16b, v22.16b, v26.16b
umull v26.2d, v23.2s, v23.2s
umull2 v27.2d, v23.4s, v23.4s
add v21.2d, v21.2d, v26.2d
add v21.2d, v21.2d, v27.2d

// Word a/16, selected solely inside SIMD registers. The high comparison
// makes the correction zero for every a >= 512, just like lookup4.
ushr v24.4s, v23.4s, #4
movi v27.4s, #15
and v24.16b, v24.16b, v27.16b
movi v27.16b, #4
mul v24.4s, v24.4s, v27.4s
dup v27.4s, w3
add v24.4s, v24.4s, v27.4s
tbl v25.16b, {v0.16b,v1.16b,v2.16b,v3.16b}, v24.16b
tbl v26.16b, {v4.16b,v5.16b,v6.16b,v7.16b}, v24.16b
ushr v24.4s, v23.4s, #8
cmeq v27.4s, v24.4s, #0
and v25.16b, v25.16b, v27.16b
movi v27.4s, #1
cmeq v27.4s, v24.4s, v27.4s
and v26.16b, v26.16b, v27.16b
orr v25.16b, v25.16b, v26.16b
movi v27.4s, #15
and v24.16b, v23.16b, v27.16b
shl v24.4s, v24.4s, #1
neg v24.4s, v24.4s
ushl v25.4s, v25.4s, v24.4s
movi v27.4s, #3
and v25.16b, v25.16b, v27.16b

// Four independent scalar Horner chains expose multiplication parallelism.
umov w7, v23.s[0]
umov w8, v23.s[1]
umov w9, v23.s[2]
umov w10, v23.s[3]
umov x6, v16.d[0]
mov x11, x6
mov x12, x6
mov x13, x6
mov x14, x6
umov x6, v16.d[1]
madd x11, x11, x7, x6
madd x12, x12, x8, x6
madd x13, x13, x9, x6
madd x14, x14, x10, x6
umov x6, v17.d[0]
madd x11, x11, x7, x6
madd x12, x12, x8, x6
madd x13, x13, x9, x6
madd x14, x14, x10, x6
umov x6, v17.d[1]
madd x11, x11, x7, x6
madd x12, x12, x8, x6
madd x13, x13, x9, x6
madd x14, x14, x10, x6
umov x6, v18.d[0]
madd x11, x11, x7, x6
madd x12, x12, x8, x6
madd x13, x13, x9, x6
madd x14, x14, x10, x6
umov x6, v18.d[1]
madd x11, x11, x7, x6
madd x12, x12, x8, x6
madd x13, x13, x9, x6
madd x14, x14, x10, x6
asr x11, x11, x5
asr x12, x12, x5
asr x13, x13, x5
asr x14, x14, x5
mov v24.d[0], x11
mov v24.d[1], x12
mov v26.d[0], x13
mov v26.d[1], x14
uxtl v27.2d, v25.2s
add v24.2d, v24.2d, v27.2d
uxtl2 v27.2d, v25.4s
add v26.2d, v26.2d, v27.2d
add v20.2d, v20.2d, v24.2d
add v20.2d, v20.2d, v26.2d
subs x2, x2, #4
b.ne 1b
2:
addp d20, v20.2d
addp d21, v21.2d
umaxv s22, v22.4s
fmov x7, d20
fmov x8, d21
fmov w6, s22
sxtw x6, w6
stp x7, x8, [x0]
str x6, [x0, #16]

// Erase all registers touched by the leaf, including private intermediates.
mov x0, #0
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
msr nzcv, xzr
ret
