.arch_extension dotprod
// Exact routed dot: x0 prior indices, x1 prior signs, x2/3 Gram byte planes,
// x4 Gram high nibbles, x5 public ceil(recorded/16), x6 index, x7 borrowed label.
// Only incoming d8..d15 are saved. Frame and private temporaries are wiped.
sub sp, sp, #64
stp d8, d9, [sp]
stp d10, d11, [sp, #16]
stp d12, d13, [sp, #32]
stp d14, d15, [sp, #48]
dup v20.16b, w6
movi v21.16b, #128
movi v22.16b, #64
movi v23.16b, #1
movi v24.16b, #0
movi v25.16b, #0
movi v26.16b, #0
cbz x5, 4f
ld1 {v0.16b-v3.16b}, [x2], #64
ld1 {v4.16b-v7.16b}, [x2]
ld1 {v8.16b-v11.16b}, [x3], #64
ld1 {v12.16b-v15.16b}, [x3]
ld1 {v16.16b-v19.16b}, [x4]
2:
ld1 {v27.16b}, [x0], #16
uabd v27.16b, v20.16b, v27.16b
cmhi v28.16b, v27.16b, v21.16b
neg v29.16b, v27.16b
bit v27.16b, v29.16b, v28.16b
cmeq v29.16b, v27.16b, v21.16b
ld1 {v30.16b}, [x1], #16
eor v30.16b, v30.16b, v28.16b
sub v30.16b, v30.16b, v28.16b
bic v30.16b, v30.16b, v29.16b
tbl v31.16b, {v0.16b-v3.16b}, v27.16b
sub v29.16b, v27.16b, v22.16b
tbx v31.16b, {v4.16b-v7.16b}, v29.16b
tbl v28.16b, {v8.16b-v11.16b}, v27.16b
tbx v28.16b, {v12.16b-v15.16b}, v29.16b
ushr v29.16b, v27.16b, #1
tbl v29.16b, {v16.16b-v19.16b}, v29.16b
and v27.16b, v27.16b, v23.16b
shl v27.16b, v27.16b, #2
neg v27.16b, v27.16b
ushl v29.16b, v29.16b, v27.16b
shl v29.16b, v29.16b, #4
sshr v29.16b, v29.16b, #4
sdot v24.4s, v30.16b, v31.16b
ushr v31.16b, v31.16b, #7
sdot v25.4s, v30.16b, v31.16b
sdot v25.4s, v30.16b, v28.16b
ushr v28.16b, v28.16b, #7
sdot v26.4s, v30.16b, v28.16b
sdot v26.4s, v30.16b, v29.16b
subs w5, w5, #1
b.ne 2b
4:
shl v25.4s, v25.4s, #8
shl v26.4s, v26.4s, #16
add v24.4s, v24.4s, v25.4s
add v24.4s, v24.4s, v26.4s
addv s24, v24.4s
umov w9, v24.s[0]
ldr x8, [x7]
ubfx x8, x8, #16, #32
add w0, w9, w8
sxtw x0, w0
movi v0.16b, #0
movi v1.16b, #0
movi v2.16b, #0
movi v3.16b, #0
movi v4.16b, #0
movi v5.16b, #0
movi v6.16b, #0
movi v7.16b, #0
movi v8.16b, #0
movi v9.16b, #0
movi v10.16b, #0
movi v11.16b, #0
movi v12.16b, #0
movi v13.16b, #0
movi v14.16b, #0
movi v15.16b, #0
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
ldp d8, d9, [sp]
ldp d10, d11, [sp, #16]
ldp d12, d13, [sp, #32]
ldp d14, d15, [sp, #48]
stp xzr, xzr, [sp, #0]
stp xzr, xzr, [sp, #16]
stp xzr, xzr, [sp, #32]
stp xzr, xzr, [sp, #48]
add sp, sp, #64
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
msr NZCV, xzr
ret
