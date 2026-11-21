// Exact negative quartic; all A/B/C/D values are signed negative words.
// The FIX table supplies D; no lookup or input-dependent address.
sub sp, sp, #64
stp d8, d9, [sp]
stp d10, d11, [sp, #16]
stp d12, d13, [sp, #32]
stp d14, d15, [sp, #48]
ld1 {v0.4s,v1.4s,v2.4s,v3.4s}, [x3]
ld1 {v4.4s,v5.4s,v6.4s,v7.4s}, [x4]
ld1 {v8.4s,v9.4s,v10.4s,v11.4s}, [x5]
ld1 {v12.4s,v13.4s,v14.4s,v15.4s}, [x6], #64
ld1 {v16.4s,v17.4s,v18.4s,v19.4s}, [x6]
movi v27.4s, #0
movi v28.4s, #0
movi v29.4s, #0
dup v30.4s, w7
mov w8, #1
dup v0.4s, v0.s[0]
dup v4.4s, v4.s[0]
dup v8.4s, v8.s[0]
dup v12.4s, v12.s[0]
dup v31.4s, w8
cbz x2, 2f
.p2align 4
1:
ld1 {v20.4s}, [x1], #16
abs v20.4s, v20.4s
cmhi v26.4s, v20.4s, v30.4s
orr v29.16b, v29.16b, v26.16b
bic v20.16b, v20.16b, v26.16b
mul v21.4s, v20.4s, v20.4s
add v28.4s, v28.4s, v21.4s
mul v22.4s, v21.4s, v12.4s
add v22.4s, v22.4s, v8.4s
shl v23.4s, v21.4s, #9
sqdmulh v24.4s, v22.4s, v23.4s
add v24.4s, v24.4s, v4.4s
shl v23.4s, v21.4s, #8
sqdmulh v25.4s, v24.4s, v23.4s
add v25.4s, v25.4s, v0.4s
shl v23.4s, v21.4s, #3
sqdmulh v25.4s, v25.4s, v23.4s
sub v27.4s, v27.4s, v25.4s
subs x2, x2, #4
b.ne 1b
2:
addv s27, v27.4s
addv s28, v28.4s
umaxv s29, v29.4s
umov w3, v27.s[0]
umov w4, v28.s[0]
umov w5, v29.s[0]
sxtw x5, w5
stp x3, x4, [x0]
str x5, [x0, #16]

// Preserve the selected kernel retirement addresses.
.rept 11
nop
.endr

// Clear every working vector before restoring only incoming callee lanes.
.irp r,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
movi v\r\().16b, #0
.endr
ldp d8, d9, [sp]
ldp d10, d11, [sp, #16]
ldp d12, d13, [sp, #32]
ldp d14, d15, [sp, #48]
stp xzr, xzr, [sp]
stp xzr, xzr, [sp, #16]
stp xzr, xzr, [sp, #32]
stp xzr, xzr, [sp, #48]
add sp, sp, #64
.irp r,0,1,2,3,4,5,6,7,8
mov x\r, #0
.endr
msr nzcv, xzr
ret
