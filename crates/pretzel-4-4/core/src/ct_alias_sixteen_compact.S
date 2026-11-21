// Sixteen queries over a byte-plane alias table. x0 output (16 x [count, tie]),
// x1 public planes (region A: row bytes 0..15 = threshold limbs 0,1, 256 bytes per public
// block of 16 rows; region B: row bytes 16..29, 224 bytes per block), x2 positive
// public block count, x3 private indices at a public address (16 in-block bytes, then 16
// block bytes), x4 AoS draws (16 x 4 u64), x5 public log2(N), x6 public pair count,
// x7 public boundary count. Metadata: alias tag bits 0..14, phase 15..15+k, cap 16+k..17+2k, primary flip 18+2k, dropped pairs 19+2k..26+2k.
// Only public counters enter branches and addresses; private indices select bytes inside
// vector registers (1-register tbx), never memory.
sub sp, sp, #576
stp d8, d9, [sp, #0]
stp d10, d11, [sp, #16]
stp d12, d13, [sp, #32]
stp d14, d15, [sp, #48]
mov x12, #256
madd x8, x2, x12, x1
ld1 {v27.16b-v28.16b}, [x3]
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
mov w9, #0
mov x10, x2
2:
dup v29.16b, w9
cmeq v29.16b, v28.16b, v29.16b
orn v30.16b, v27.16b, v29.16b
ld1 {v16.16b-v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v20.16b-v23.16b}, [x1], #64
tbx v4.16b, {v20.16b}, v30.16b
tbx v5.16b, {v21.16b}, v30.16b
tbx v6.16b, {v22.16b}, v30.16b
tbx v7.16b, {v23.16b}, v30.16b
ld1 {v16.16b-v19.16b}, [x1], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v20.16b-v23.16b}, [x1], #64
tbx v12.16b, {v20.16b}, v30.16b
tbx v13.16b, {v21.16b}, v30.16b
tbx v14.16b, {v22.16b}, v30.16b
tbx v15.16b, {v23.16b}, v30.16b
add w9, w9, #1
subs x10, x10, #1
b.ne 2b
trn1 v16.16b, v0.16b, v1.16b
trn2 v17.16b, v0.16b, v1.16b
trn1 v18.16b, v2.16b, v3.16b
trn2 v19.16b, v2.16b, v3.16b
trn1 v20.16b, v4.16b, v5.16b
trn2 v21.16b, v4.16b, v5.16b
trn1 v22.16b, v6.16b, v7.16b
trn2 v23.16b, v6.16b, v7.16b
trn1 v24.16b, v8.16b, v9.16b
trn2 v25.16b, v8.16b, v9.16b
trn1 v26.16b, v10.16b, v11.16b
trn2 v27.16b, v10.16b, v11.16b
trn1 v28.16b, v12.16b, v13.16b
trn2 v29.16b, v12.16b, v13.16b
trn1 v30.16b, v14.16b, v15.16b
trn2 v31.16b, v14.16b, v15.16b
trn1 v0.8h, v16.8h, v18.8h
trn2 v2.8h, v16.8h, v18.8h
trn1 v1.8h, v17.8h, v19.8h
trn2 v3.8h, v17.8h, v19.8h
trn1 v4.8h, v20.8h, v22.8h
trn2 v6.8h, v20.8h, v22.8h
trn1 v5.8h, v21.8h, v23.8h
trn2 v7.8h, v21.8h, v23.8h
trn1 v8.8h, v24.8h, v26.8h
trn2 v10.8h, v24.8h, v26.8h
trn1 v9.8h, v25.8h, v27.8h
trn2 v11.8h, v25.8h, v27.8h
trn1 v12.8h, v28.8h, v30.8h
trn2 v14.8h, v28.8h, v30.8h
trn1 v13.8h, v29.8h, v31.8h
trn2 v15.8h, v29.8h, v31.8h
trn1 v16.4s, v0.4s, v4.4s
trn2 v20.4s, v0.4s, v4.4s
trn1 v17.4s, v1.4s, v5.4s
trn2 v21.4s, v1.4s, v5.4s
trn1 v18.4s, v2.4s, v6.4s
trn2 v22.4s, v2.4s, v6.4s
trn1 v19.4s, v3.4s, v7.4s
trn2 v23.4s, v3.4s, v7.4s
trn1 v24.4s, v8.4s, v12.4s
trn2 v28.4s, v8.4s, v12.4s
trn1 v25.4s, v9.4s, v13.4s
trn2 v29.4s, v9.4s, v13.4s
trn1 v26.4s, v10.4s, v14.4s
trn2 v30.4s, v10.4s, v14.4s
trn1 v27.4s, v11.4s, v15.4s
trn2 v31.4s, v11.4s, v15.4s
trn1 v0.2d, v16.2d, v24.2d
trn2 v8.2d, v16.2d, v24.2d
trn1 v1.2d, v17.2d, v25.2d
trn2 v9.2d, v17.2d, v25.2d
trn1 v2.2d, v18.2d, v26.2d
trn2 v10.2d, v18.2d, v26.2d
trn1 v3.2d, v19.2d, v27.2d
trn2 v11.2d, v19.2d, v27.2d
trn1 v4.2d, v20.2d, v28.2d
trn2 v12.2d, v20.2d, v28.2d
trn1 v5.2d, v21.2d, v29.2d
trn2 v13.2d, v21.2d, v29.2d
trn1 v6.2d, v22.2d, v30.2d
trn2 v14.2d, v22.2d, v30.2d
trn1 v7.2d, v23.2d, v31.2d
trn2 v15.2d, v23.2d, v31.2d
stp q0, q1, [sp, #64]
stp q2, q3, [sp, #96]
stp q4, q5, [sp, #128]
stp q6, q7, [sp, #160]
stp q8, q9, [sp, #192]
stp q10, q11, [sp, #224]
stp q12, q13, [sp, #256]
stp q14, q15, [sp, #288]
ld1 {v27.16b-v28.16b}, [x3]
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
mov w9, #0
mov x10, x2
3:
dup v29.16b, w9
cmeq v29.16b, v28.16b, v29.16b
orn v30.16b, v27.16b, v29.16b
ld1 {v16.16b-v19.16b}, [x8], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v20.16b-v23.16b}, [x8], #64
tbx v4.16b, {v20.16b}, v30.16b
tbx v5.16b, {v21.16b}, v30.16b
tbx v6.16b, {v22.16b}, v30.16b
tbx v7.16b, {v23.16b}, v30.16b
ld1 {v16.16b-v19.16b}, [x8], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v20.16b-v21.16b}, [x8], #32
tbx v12.16b, {v20.16b}, v30.16b
tbx v13.16b, {v21.16b}, v30.16b
add w9, w9, #1
subs x10, x10, #1
b.ne 3b
trn1 v16.16b, v0.16b, v1.16b
trn2 v17.16b, v0.16b, v1.16b
trn1 v18.16b, v2.16b, v3.16b
trn2 v19.16b, v2.16b, v3.16b
trn1 v20.16b, v4.16b, v5.16b
trn2 v21.16b, v4.16b, v5.16b
trn1 v22.16b, v6.16b, v7.16b
trn2 v23.16b, v6.16b, v7.16b
trn1 v24.16b, v8.16b, v9.16b
trn2 v25.16b, v8.16b, v9.16b
trn1 v26.16b, v10.16b, v11.16b
trn2 v27.16b, v10.16b, v11.16b
trn1 v28.16b, v12.16b, v13.16b
trn2 v29.16b, v12.16b, v13.16b
trn1 v30.16b, v14.16b, v15.16b
trn2 v31.16b, v14.16b, v15.16b
trn1 v0.8h, v16.8h, v18.8h
trn2 v2.8h, v16.8h, v18.8h
trn1 v1.8h, v17.8h, v19.8h
trn2 v3.8h, v17.8h, v19.8h
trn1 v4.8h, v20.8h, v22.8h
trn2 v6.8h, v20.8h, v22.8h
trn1 v5.8h, v21.8h, v23.8h
trn2 v7.8h, v21.8h, v23.8h
trn1 v8.8h, v24.8h, v26.8h
trn2 v10.8h, v24.8h, v26.8h
trn1 v9.8h, v25.8h, v27.8h
trn2 v11.8h, v25.8h, v27.8h
trn1 v12.8h, v28.8h, v30.8h
trn2 v14.8h, v28.8h, v30.8h
trn1 v13.8h, v29.8h, v31.8h
trn2 v15.8h, v29.8h, v31.8h
trn1 v16.4s, v0.4s, v4.4s
trn2 v20.4s, v0.4s, v4.4s
trn1 v17.4s, v1.4s, v5.4s
trn2 v21.4s, v1.4s, v5.4s
trn1 v18.4s, v2.4s, v6.4s
trn2 v22.4s, v2.4s, v6.4s
trn1 v19.4s, v3.4s, v7.4s
trn2 v23.4s, v3.4s, v7.4s
trn1 v24.4s, v8.4s, v12.4s
trn2 v28.4s, v8.4s, v12.4s
trn1 v25.4s, v9.4s, v13.4s
trn2 v29.4s, v9.4s, v13.4s
trn1 v26.4s, v10.4s, v14.4s
trn2 v30.4s, v10.4s, v14.4s
trn1 v27.4s, v11.4s, v15.4s
trn2 v31.4s, v11.4s, v15.4s
trn1 v0.2d, v16.2d, v24.2d
trn2 v8.2d, v16.2d, v24.2d
trn1 v1.2d, v17.2d, v25.2d
trn2 v9.2d, v17.2d, v25.2d
trn1 v2.2d, v18.2d, v26.2d
trn2 v10.2d, v18.2d, v26.2d
trn1 v3.2d, v19.2d, v27.2d
trn2 v11.2d, v19.2d, v27.2d
trn1 v4.2d, v20.2d, v28.2d
trn2 v12.2d, v20.2d, v28.2d
trn1 v5.2d, v21.2d, v29.2d
trn2 v13.2d, v21.2d, v29.2d
trn1 v6.2d, v22.2d, v30.2d
trn2 v14.2d, v22.2d, v30.2d
trn1 v7.2d, v23.2d, v31.2d
trn2 v15.2d, v23.2d, v31.2d
stp q0, q1, [sp, #320]
stp q2, q3, [sp, #352]
stp q4, q5, [sp, #384]
stp q6, q7, [sp, #416]
stp q8, q9, [sp, #448]
stp q10, q11, [sp, #480]
stp q12, q13, [sp, #512]
stp q14, q15, [sp, #544]
// Public decode constants.
mov x9, #1
lsl x9, x9, x5
lsl x10, x9, #1
sub x11, x10, #1
dup v0.2d, x11
neg x11, x5
dup v1.2d, x11
mov x11, #1
dup v2.2d, x11
mov x11, #4095
dup v3.2d, x11
add x11, x5, #16
neg x11, x11
dup v4.2d, x11
lsl x11, x10, #1
sub x11, x11, #1
dup v5.2d, x11
dup v6.2d, x10
mov x11, #0x5000
dup v7.2d, x11
dup v8.2d, x6
orr x11, x7, #0x4000
dup v9.2d, x11
mov x11, #0x7fff
dup v10.2d, x11
lsl x11, x5, #1
add x11, x11, #18
neg x11, x11
dup v11.2d, x11
sub x11, x9, #1
dup v12.2d, x11
lsl x11, x5, #1
add x11, x11, #19
neg x11, x11
dup v13.2d, x11
mov x11, #0xff
dup v14.2d, x11
// Resolve lanes 0, 1 from the transposed rows.
ldp q24, q25, [sp, #64]
ldp q26, q27, [sp, #320]
zip1 v16.2d, v24.2d, v25.2d
zip2 v17.2d, v24.2d, v25.2d
zip1 v18.2d, v26.2d, v27.2d
zip2 v19.2d, v26.2d, v27.2d
ld4 {v20.2d-v23.2d}, [x4], #64
// Exact three-limb subtraction and u < threshold mask.
sub v24.2d, v22.2d, v18.2d
cmhi v25.2d, v18.2d, v22.2d
sub v26.2d, v21.2d, v17.2d
cmhi v27.2d, v17.2d, v21.2d
cmeq v30.2d, v26.2d, #0
and v30.16b, v30.16b, v25.16b
orr v27.16b, v27.16b, v30.16b
add v26.2d, v26.2d, v25.2d
sub v28.2d, v20.2d, v16.2d
cmhi v29.2d, v16.2d, v20.2d
cmeq v30.2d, v28.2d, #0
and v30.16b, v30.16b, v27.16b
orr v29.16b, v29.16b, v30.16b
add v28.2d, v28.2d, v27.2d
// Primary tag from the public shape and the private row index v23 (v2 = 1, v7 = pair|tie,
// v8 = P, v9 = N|tie, v10 = 0x7fff, v11 = -(18+2k), v12 = n-1, v13 = -(19+2k), v14 = 0xff);
// pair base = 2i-1 + 2*(pairs dropped before row i); alias tag from metadata bits 0..14.
and v23.16b, v23.16b, v12.16b
shl v17.2d, v23.2d, #1
sub v17.2d, v17.2d, v2.2d
ushl v18.2d, v19.2d, v13.2d
and v18.16b, v18.16b, v14.16b
shl v18.2d, v18.2d, #1
add v17.2d, v17.2d, v18.2d
ushl v18.2d, v19.2d, v11.2d
shl v18.2d, v18.2d, #13
orr v17.16b, v17.16b, v18.16b
orr v17.16b, v17.16b, v7.16b
cmhi v18.2d, v23.2d, v8.2d
bsl v18.16b, v9.16b, v17.16b
cmeq v17.2d, v23.2d, #0
bic v18.16b, v18.16b, v17.16b
and v17.16b, v19.16b, v10.16b
mov v16.16b, v29.16b
bsl v16.16b, v18.16b, v17.16b
ushr v17.2d, v19.2d, #15
// Modular rank parity (v0 = 2n-1, v1 = -k, v2 = 1).
and v17.16b, v17.16b, v0.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
ushl v17.2d, v17.2d, v1.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
and v17.16b, v17.16b, v2.16b
// Keep the selected tag tie bit before reducing it to the count base (v3 = 4095).
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v2.16b
neg v30.2d, v30.2d
and v16.16b, v16.16b, v3.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference (v4 = -cap shift, v5 = 4n-1).
ushl v18.2d, v19.2d, v4.2d
and v18.16b, v18.16b, v5.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie (v6 = 2n).
cmhi v17.2d, v6.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 2, 3 from the transposed rows.
ldp q24, q25, [sp, #96]
ldp q26, q27, [sp, #352]
zip1 v16.2d, v24.2d, v25.2d
zip2 v17.2d, v24.2d, v25.2d
zip1 v18.2d, v26.2d, v27.2d
zip2 v19.2d, v26.2d, v27.2d
ld4 {v20.2d-v23.2d}, [x4], #64
// Exact three-limb subtraction and u < threshold mask.
sub v24.2d, v22.2d, v18.2d
cmhi v25.2d, v18.2d, v22.2d
sub v26.2d, v21.2d, v17.2d
cmhi v27.2d, v17.2d, v21.2d
cmeq v30.2d, v26.2d, #0
and v30.16b, v30.16b, v25.16b
orr v27.16b, v27.16b, v30.16b
add v26.2d, v26.2d, v25.2d
sub v28.2d, v20.2d, v16.2d
cmhi v29.2d, v16.2d, v20.2d
cmeq v30.2d, v28.2d, #0
and v30.16b, v30.16b, v27.16b
orr v29.16b, v29.16b, v30.16b
add v28.2d, v28.2d, v27.2d
// Primary tag from the public shape and the private row index v23 (v2 = 1, v7 = pair|tie,
// v8 = P, v9 = N|tie, v10 = 0x7fff, v11 = -(18+2k), v12 = n-1, v13 = -(19+2k), v14 = 0xff);
// pair base = 2i-1 + 2*(pairs dropped before row i); alias tag from metadata bits 0..14.
and v23.16b, v23.16b, v12.16b
shl v17.2d, v23.2d, #1
sub v17.2d, v17.2d, v2.2d
ushl v18.2d, v19.2d, v13.2d
and v18.16b, v18.16b, v14.16b
shl v18.2d, v18.2d, #1
add v17.2d, v17.2d, v18.2d
ushl v18.2d, v19.2d, v11.2d
shl v18.2d, v18.2d, #13
orr v17.16b, v17.16b, v18.16b
orr v17.16b, v17.16b, v7.16b
cmhi v18.2d, v23.2d, v8.2d
bsl v18.16b, v9.16b, v17.16b
cmeq v17.2d, v23.2d, #0
bic v18.16b, v18.16b, v17.16b
and v17.16b, v19.16b, v10.16b
mov v16.16b, v29.16b
bsl v16.16b, v18.16b, v17.16b
ushr v17.2d, v19.2d, #15
// Modular rank parity (v0 = 2n-1, v1 = -k, v2 = 1).
and v17.16b, v17.16b, v0.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
ushl v17.2d, v17.2d, v1.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
and v17.16b, v17.16b, v2.16b
// Keep the selected tag tie bit before reducing it to the count base (v3 = 4095).
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v2.16b
neg v30.2d, v30.2d
and v16.16b, v16.16b, v3.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference (v4 = -cap shift, v5 = 4n-1).
ushl v18.2d, v19.2d, v4.2d
and v18.16b, v18.16b, v5.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie (v6 = 2n).
cmhi v17.2d, v6.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 4, 5 from the transposed rows.
ldp q24, q25, [sp, #128]
ldp q26, q27, [sp, #384]
zip1 v16.2d, v24.2d, v25.2d
zip2 v17.2d, v24.2d, v25.2d
zip1 v18.2d, v26.2d, v27.2d
zip2 v19.2d, v26.2d, v27.2d
ld4 {v20.2d-v23.2d}, [x4], #64
// Exact three-limb subtraction and u < threshold mask.
sub v24.2d, v22.2d, v18.2d
cmhi v25.2d, v18.2d, v22.2d
sub v26.2d, v21.2d, v17.2d
cmhi v27.2d, v17.2d, v21.2d
cmeq v30.2d, v26.2d, #0
and v30.16b, v30.16b, v25.16b
orr v27.16b, v27.16b, v30.16b
add v26.2d, v26.2d, v25.2d
sub v28.2d, v20.2d, v16.2d
cmhi v29.2d, v16.2d, v20.2d
cmeq v30.2d, v28.2d, #0
and v30.16b, v30.16b, v27.16b
orr v29.16b, v29.16b, v30.16b
add v28.2d, v28.2d, v27.2d
// Primary tag from the public shape and the private row index v23 (v2 = 1, v7 = pair|tie,
// v8 = P, v9 = N|tie, v10 = 0x7fff, v11 = -(18+2k), v12 = n-1, v13 = -(19+2k), v14 = 0xff);
// pair base = 2i-1 + 2*(pairs dropped before row i); alias tag from metadata bits 0..14.
and v23.16b, v23.16b, v12.16b
shl v17.2d, v23.2d, #1
sub v17.2d, v17.2d, v2.2d
ushl v18.2d, v19.2d, v13.2d
and v18.16b, v18.16b, v14.16b
shl v18.2d, v18.2d, #1
add v17.2d, v17.2d, v18.2d
ushl v18.2d, v19.2d, v11.2d
shl v18.2d, v18.2d, #13
orr v17.16b, v17.16b, v18.16b
orr v17.16b, v17.16b, v7.16b
cmhi v18.2d, v23.2d, v8.2d
bsl v18.16b, v9.16b, v17.16b
cmeq v17.2d, v23.2d, #0
bic v18.16b, v18.16b, v17.16b
and v17.16b, v19.16b, v10.16b
mov v16.16b, v29.16b
bsl v16.16b, v18.16b, v17.16b
ushr v17.2d, v19.2d, #15
// Modular rank parity (v0 = 2n-1, v1 = -k, v2 = 1).
and v17.16b, v17.16b, v0.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
ushl v17.2d, v17.2d, v1.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
and v17.16b, v17.16b, v2.16b
// Keep the selected tag tie bit before reducing it to the count base (v3 = 4095).
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v2.16b
neg v30.2d, v30.2d
and v16.16b, v16.16b, v3.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference (v4 = -cap shift, v5 = 4n-1).
ushl v18.2d, v19.2d, v4.2d
and v18.16b, v18.16b, v5.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie (v6 = 2n).
cmhi v17.2d, v6.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 6, 7 from the transposed rows.
ldp q24, q25, [sp, #160]
ldp q26, q27, [sp, #416]
zip1 v16.2d, v24.2d, v25.2d
zip2 v17.2d, v24.2d, v25.2d
zip1 v18.2d, v26.2d, v27.2d
zip2 v19.2d, v26.2d, v27.2d
ld4 {v20.2d-v23.2d}, [x4], #64
// Exact three-limb subtraction and u < threshold mask.
sub v24.2d, v22.2d, v18.2d
cmhi v25.2d, v18.2d, v22.2d
sub v26.2d, v21.2d, v17.2d
cmhi v27.2d, v17.2d, v21.2d
cmeq v30.2d, v26.2d, #0
and v30.16b, v30.16b, v25.16b
orr v27.16b, v27.16b, v30.16b
add v26.2d, v26.2d, v25.2d
sub v28.2d, v20.2d, v16.2d
cmhi v29.2d, v16.2d, v20.2d
cmeq v30.2d, v28.2d, #0
and v30.16b, v30.16b, v27.16b
orr v29.16b, v29.16b, v30.16b
add v28.2d, v28.2d, v27.2d
// Primary tag from the public shape and the private row index v23 (v2 = 1, v7 = pair|tie,
// v8 = P, v9 = N|tie, v10 = 0x7fff, v11 = -(18+2k), v12 = n-1, v13 = -(19+2k), v14 = 0xff);
// pair base = 2i-1 + 2*(pairs dropped before row i); alias tag from metadata bits 0..14.
and v23.16b, v23.16b, v12.16b
shl v17.2d, v23.2d, #1
sub v17.2d, v17.2d, v2.2d
ushl v18.2d, v19.2d, v13.2d
and v18.16b, v18.16b, v14.16b
shl v18.2d, v18.2d, #1
add v17.2d, v17.2d, v18.2d
ushl v18.2d, v19.2d, v11.2d
shl v18.2d, v18.2d, #13
orr v17.16b, v17.16b, v18.16b
orr v17.16b, v17.16b, v7.16b
cmhi v18.2d, v23.2d, v8.2d
bsl v18.16b, v9.16b, v17.16b
cmeq v17.2d, v23.2d, #0
bic v18.16b, v18.16b, v17.16b
and v17.16b, v19.16b, v10.16b
mov v16.16b, v29.16b
bsl v16.16b, v18.16b, v17.16b
ushr v17.2d, v19.2d, #15
// Modular rank parity (v0 = 2n-1, v1 = -k, v2 = 1).
and v17.16b, v17.16b, v0.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
ushl v17.2d, v17.2d, v1.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
and v17.16b, v17.16b, v2.16b
// Keep the selected tag tie bit before reducing it to the count base (v3 = 4095).
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v2.16b
neg v30.2d, v30.2d
and v16.16b, v16.16b, v3.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference (v4 = -cap shift, v5 = 4n-1).
ushl v18.2d, v19.2d, v4.2d
and v18.16b, v18.16b, v5.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie (v6 = 2n).
cmhi v17.2d, v6.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 8, 9 from the transposed rows.
ldp q24, q25, [sp, #192]
ldp q26, q27, [sp, #448]
zip1 v16.2d, v24.2d, v25.2d
zip2 v17.2d, v24.2d, v25.2d
zip1 v18.2d, v26.2d, v27.2d
zip2 v19.2d, v26.2d, v27.2d
ld4 {v20.2d-v23.2d}, [x4], #64
// Exact three-limb subtraction and u < threshold mask.
sub v24.2d, v22.2d, v18.2d
cmhi v25.2d, v18.2d, v22.2d
sub v26.2d, v21.2d, v17.2d
cmhi v27.2d, v17.2d, v21.2d
cmeq v30.2d, v26.2d, #0
and v30.16b, v30.16b, v25.16b
orr v27.16b, v27.16b, v30.16b
add v26.2d, v26.2d, v25.2d
sub v28.2d, v20.2d, v16.2d
cmhi v29.2d, v16.2d, v20.2d
cmeq v30.2d, v28.2d, #0
and v30.16b, v30.16b, v27.16b
orr v29.16b, v29.16b, v30.16b
add v28.2d, v28.2d, v27.2d
// Primary tag from the public shape and the private row index v23 (v2 = 1, v7 = pair|tie,
// v8 = P, v9 = N|tie, v10 = 0x7fff, v11 = -(18+2k), v12 = n-1, v13 = -(19+2k), v14 = 0xff);
// pair base = 2i-1 + 2*(pairs dropped before row i); alias tag from metadata bits 0..14.
and v23.16b, v23.16b, v12.16b
shl v17.2d, v23.2d, #1
sub v17.2d, v17.2d, v2.2d
ushl v18.2d, v19.2d, v13.2d
and v18.16b, v18.16b, v14.16b
shl v18.2d, v18.2d, #1
add v17.2d, v17.2d, v18.2d
ushl v18.2d, v19.2d, v11.2d
shl v18.2d, v18.2d, #13
orr v17.16b, v17.16b, v18.16b
orr v17.16b, v17.16b, v7.16b
cmhi v18.2d, v23.2d, v8.2d
bsl v18.16b, v9.16b, v17.16b
cmeq v17.2d, v23.2d, #0
bic v18.16b, v18.16b, v17.16b
and v17.16b, v19.16b, v10.16b
mov v16.16b, v29.16b
bsl v16.16b, v18.16b, v17.16b
ushr v17.2d, v19.2d, #15
// Modular rank parity (v0 = 2n-1, v1 = -k, v2 = 1).
and v17.16b, v17.16b, v0.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
ushl v17.2d, v17.2d, v1.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
and v17.16b, v17.16b, v2.16b
// Keep the selected tag tie bit before reducing it to the count base (v3 = 4095).
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v2.16b
neg v30.2d, v30.2d
and v16.16b, v16.16b, v3.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference (v4 = -cap shift, v5 = 4n-1).
ushl v18.2d, v19.2d, v4.2d
and v18.16b, v18.16b, v5.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie (v6 = 2n).
cmhi v17.2d, v6.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 10, 11 from the transposed rows.
ldp q24, q25, [sp, #224]
ldp q26, q27, [sp, #480]
zip1 v16.2d, v24.2d, v25.2d
zip2 v17.2d, v24.2d, v25.2d
zip1 v18.2d, v26.2d, v27.2d
zip2 v19.2d, v26.2d, v27.2d
ld4 {v20.2d-v23.2d}, [x4], #64
// Exact three-limb subtraction and u < threshold mask.
sub v24.2d, v22.2d, v18.2d
cmhi v25.2d, v18.2d, v22.2d
sub v26.2d, v21.2d, v17.2d
cmhi v27.2d, v17.2d, v21.2d
cmeq v30.2d, v26.2d, #0
and v30.16b, v30.16b, v25.16b
orr v27.16b, v27.16b, v30.16b
add v26.2d, v26.2d, v25.2d
sub v28.2d, v20.2d, v16.2d
cmhi v29.2d, v16.2d, v20.2d
cmeq v30.2d, v28.2d, #0
and v30.16b, v30.16b, v27.16b
orr v29.16b, v29.16b, v30.16b
add v28.2d, v28.2d, v27.2d
// Primary tag from the public shape and the private row index v23 (v2 = 1, v7 = pair|tie,
// v8 = P, v9 = N|tie, v10 = 0x7fff, v11 = -(18+2k), v12 = n-1, v13 = -(19+2k), v14 = 0xff);
// pair base = 2i-1 + 2*(pairs dropped before row i); alias tag from metadata bits 0..14.
and v23.16b, v23.16b, v12.16b
shl v17.2d, v23.2d, #1
sub v17.2d, v17.2d, v2.2d
ushl v18.2d, v19.2d, v13.2d
and v18.16b, v18.16b, v14.16b
shl v18.2d, v18.2d, #1
add v17.2d, v17.2d, v18.2d
ushl v18.2d, v19.2d, v11.2d
shl v18.2d, v18.2d, #13
orr v17.16b, v17.16b, v18.16b
orr v17.16b, v17.16b, v7.16b
cmhi v18.2d, v23.2d, v8.2d
bsl v18.16b, v9.16b, v17.16b
cmeq v17.2d, v23.2d, #0
bic v18.16b, v18.16b, v17.16b
and v17.16b, v19.16b, v10.16b
mov v16.16b, v29.16b
bsl v16.16b, v18.16b, v17.16b
ushr v17.2d, v19.2d, #15
// Modular rank parity (v0 = 2n-1, v1 = -k, v2 = 1).
and v17.16b, v17.16b, v0.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
ushl v17.2d, v17.2d, v1.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
and v17.16b, v17.16b, v2.16b
// Keep the selected tag tie bit before reducing it to the count base (v3 = 4095).
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v2.16b
neg v30.2d, v30.2d
and v16.16b, v16.16b, v3.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference (v4 = -cap shift, v5 = 4n-1).
ushl v18.2d, v19.2d, v4.2d
and v18.16b, v18.16b, v5.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie (v6 = 2n).
cmhi v17.2d, v6.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 12, 13 from the transposed rows.
ldp q24, q25, [sp, #256]
ldp q26, q27, [sp, #512]
zip1 v16.2d, v24.2d, v25.2d
zip2 v17.2d, v24.2d, v25.2d
zip1 v18.2d, v26.2d, v27.2d
zip2 v19.2d, v26.2d, v27.2d
ld4 {v20.2d-v23.2d}, [x4], #64
// Exact three-limb subtraction and u < threshold mask.
sub v24.2d, v22.2d, v18.2d
cmhi v25.2d, v18.2d, v22.2d
sub v26.2d, v21.2d, v17.2d
cmhi v27.2d, v17.2d, v21.2d
cmeq v30.2d, v26.2d, #0
and v30.16b, v30.16b, v25.16b
orr v27.16b, v27.16b, v30.16b
add v26.2d, v26.2d, v25.2d
sub v28.2d, v20.2d, v16.2d
cmhi v29.2d, v16.2d, v20.2d
cmeq v30.2d, v28.2d, #0
and v30.16b, v30.16b, v27.16b
orr v29.16b, v29.16b, v30.16b
add v28.2d, v28.2d, v27.2d
// Primary tag from the public shape and the private row index v23 (v2 = 1, v7 = pair|tie,
// v8 = P, v9 = N|tie, v10 = 0x7fff, v11 = -(18+2k), v12 = n-1, v13 = -(19+2k), v14 = 0xff);
// pair base = 2i-1 + 2*(pairs dropped before row i); alias tag from metadata bits 0..14.
and v23.16b, v23.16b, v12.16b
shl v17.2d, v23.2d, #1
sub v17.2d, v17.2d, v2.2d
ushl v18.2d, v19.2d, v13.2d
and v18.16b, v18.16b, v14.16b
shl v18.2d, v18.2d, #1
add v17.2d, v17.2d, v18.2d
ushl v18.2d, v19.2d, v11.2d
shl v18.2d, v18.2d, #13
orr v17.16b, v17.16b, v18.16b
orr v17.16b, v17.16b, v7.16b
cmhi v18.2d, v23.2d, v8.2d
bsl v18.16b, v9.16b, v17.16b
cmeq v17.2d, v23.2d, #0
bic v18.16b, v18.16b, v17.16b
and v17.16b, v19.16b, v10.16b
mov v16.16b, v29.16b
bsl v16.16b, v18.16b, v17.16b
ushr v17.2d, v19.2d, #15
// Modular rank parity (v0 = 2n-1, v1 = -k, v2 = 1).
and v17.16b, v17.16b, v0.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
ushl v17.2d, v17.2d, v1.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
and v17.16b, v17.16b, v2.16b
// Keep the selected tag tie bit before reducing it to the count base (v3 = 4095).
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v2.16b
neg v30.2d, v30.2d
and v16.16b, v16.16b, v3.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference (v4 = -cap shift, v5 = 4n-1).
ushl v18.2d, v19.2d, v4.2d
and v18.16b, v18.16b, v5.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie (v6 = 2n).
cmhi v17.2d, v6.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 14, 15 from the transposed rows.
ldp q24, q25, [sp, #288]
ldp q26, q27, [sp, #544]
zip1 v16.2d, v24.2d, v25.2d
zip2 v17.2d, v24.2d, v25.2d
zip1 v18.2d, v26.2d, v27.2d
zip2 v19.2d, v26.2d, v27.2d
ld4 {v20.2d-v23.2d}, [x4], #64
// Exact three-limb subtraction and u < threshold mask.
sub v24.2d, v22.2d, v18.2d
cmhi v25.2d, v18.2d, v22.2d
sub v26.2d, v21.2d, v17.2d
cmhi v27.2d, v17.2d, v21.2d
cmeq v30.2d, v26.2d, #0
and v30.16b, v30.16b, v25.16b
orr v27.16b, v27.16b, v30.16b
add v26.2d, v26.2d, v25.2d
sub v28.2d, v20.2d, v16.2d
cmhi v29.2d, v16.2d, v20.2d
cmeq v30.2d, v28.2d, #0
and v30.16b, v30.16b, v27.16b
orr v29.16b, v29.16b, v30.16b
add v28.2d, v28.2d, v27.2d
// Primary tag from the public shape and the private row index v23 (v2 = 1, v7 = pair|tie,
// v8 = P, v9 = N|tie, v10 = 0x7fff, v11 = -(18+2k), v12 = n-1, v13 = -(19+2k), v14 = 0xff);
// pair base = 2i-1 + 2*(pairs dropped before row i); alias tag from metadata bits 0..14.
and v23.16b, v23.16b, v12.16b
shl v17.2d, v23.2d, #1
sub v17.2d, v17.2d, v2.2d
ushl v18.2d, v19.2d, v13.2d
and v18.16b, v18.16b, v14.16b
shl v18.2d, v18.2d, #1
add v17.2d, v17.2d, v18.2d
ushl v18.2d, v19.2d, v11.2d
shl v18.2d, v18.2d, #13
orr v17.16b, v17.16b, v18.16b
orr v17.16b, v17.16b, v7.16b
cmhi v18.2d, v23.2d, v8.2d
bsl v18.16b, v9.16b, v17.16b
cmeq v17.2d, v23.2d, #0
bic v18.16b, v18.16b, v17.16b
and v17.16b, v19.16b, v10.16b
mov v16.16b, v29.16b
bsl v16.16b, v18.16b, v17.16b
ushr v17.2d, v19.2d, #15
// Modular rank parity (v0 = 2n-1, v1 = -k, v2 = 1).
and v17.16b, v17.16b, v0.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
ushl v17.2d, v17.2d, v1.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
and v17.16b, v17.16b, v2.16b
// Keep the selected tag tie bit before reducing it to the count base (v3 = 4095).
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v2.16b
neg v30.2d, v30.2d
and v16.16b, v16.16b, v3.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference (v4 = -cap shift, v5 = 4n-1).
ushl v18.2d, v19.2d, v4.2d
and v18.16b, v18.16b, v5.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie (v6 = 2n).
cmhi v17.2d, v6.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
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
ldp d8, d9, [sp, #0]
ldp d10, d11, [sp, #16]
ldp d12, d13, [sp, #32]
ldp d14, d15, [sp, #48]
stp q0, q1, [sp, #0]
stp q0, q1, [sp, #32]
stp q0, q1, [sp, #64]
stp q0, q1, [sp, #96]
stp q0, q1, [sp, #128]
stp q0, q1, [sp, #160]
stp q0, q1, [sp, #192]
stp q0, q1, [sp, #224]
stp q0, q1, [sp, #256]
stp q0, q1, [sp, #288]
stp q0, q1, [sp, #320]
stp q0, q1, [sp, #352]
stp q0, q1, [sp, #384]
stp q0, q1, [sp, #416]
stp q0, q1, [sp, #448]
stp q0, q1, [sp, #480]
stp q0, q1, [sp, #512]
stp q0, q1, [sp, #544]
add sp, sp, #576
ret
