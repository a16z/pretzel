// x0: caller-owned state[8][4]; x1: public [table pointer, block count] descriptors.
// x2: nonzero public depth; x3: four AoS 192-bit draws.
// Every table is immutable and nonempty. Input/output/frame ranges are disjoint.
sub sp, sp, #160
stp d8, d9, [sp, #96]
stp d10, d11, [sp, #112]
stp d12, d13, [sp, #128]
stp d14, d15, [sp, #144]
ld3 {v0.2d-v2.2d}, [x3], #48
ld3 {v3.2d-v5.2d}, [x3]
movi v6.16b, #0
movi v7.16b, #0
movi v8.16b, #0
movi v9.16b, #0
movi v10.16b, #0
movi v11.16b, #0
movi v12.16b, #0
movi v13.16b, #0
movi v14.16b, #0
mov x16, #-1
stp x16, x16, [sp, #0]
stp x16, x16, [sp, #16]
stp x16, x16, [sp, #32]
stp x16, x16, [sp, #48]
stp x16, x16, [sp, #64]
stp x16, x16, [sp, #80]
2:
ldp x4, x5, [x1]
ushr v23.4s, v14.4s, #4
movi v24.4s, #15
and v22.16b, v14.16b, v24.16b
movi v24.16b, #4
mul v22.4s, v22.4s, v24.4s
mov w9, #0x0100
movk w9, #0x0302, lsl #16
dup v24.4s, w9
add v22.4s, v22.4s, v24.4s
movi v15.16b, #0
movi v16.16b, #0
movi v17.16b, #0
movi v18.16b, #0
movi v19.16b, #0
movi v20.16b, #0
movi v21.16b, #0
mov w6, #0
3:
dup v24.4s, w6
cmeq v28.4s, v23.4s, v24.4s
orn v29.16b, v22.16b, v28.16b
ld1 {v24.16b-v27.16b}, [x4], #64
tbx v15.16b, {v24.16b-v27.16b}, v29.16b
ld1 {v24.16b-v27.16b}, [x4], #64
tbx v16.16b, {v24.16b-v27.16b}, v29.16b
ld1 {v24.16b-v27.16b}, [x4], #64
tbx v17.16b, {v24.16b-v27.16b}, v29.16b
ld1 {v24.16b-v27.16b}, [x4], #64
tbx v18.16b, {v24.16b-v27.16b}, v29.16b
ld1 {v24.16b-v27.16b}, [x4], #64
tbx v19.16b, {v24.16b-v27.16b}, v29.16b
ld1 {v24.16b-v27.16b}, [x4], #64
tbx v20.16b, {v24.16b-v27.16b}, v29.16b
ld1 {v24.16b-v27.16b}, [x4], #64
tbx v21.16b, {v24.16b-v27.16b}, v29.16b
add w6, w6, #1
subs x5, x5, #1
b.ne 3b
zip1 v24.4s, v15.4s, v16.4s
zip2 v16.4s, v15.4s, v16.4s
mov v15.16b, v24.16b
zip1 v24.4s, v17.4s, v18.4s
zip2 v18.4s, v17.4s, v18.4s
mov v17.16b, v24.16b
zip1 v24.4s, v19.4s, v20.4s
zip2 v20.4s, v19.4s, v20.4s
mov v19.16b, v24.16b
cmhi v24.2d, v15.2d, v0.2d
cmeq v26.2d, v15.2d, v0.2d
cmhi v27.2d, v17.2d, v1.2d
and v27.16b, v27.16b, v26.16b
orr v24.16b, v24.16b, v27.16b
cmeq v27.2d, v17.2d, v1.2d
and v26.16b, v26.16b, v27.16b
cmhi v27.2d, v19.2d, v2.2d
and v27.16b, v27.16b, v26.16b
orr v24.16b, v24.16b, v27.16b
cmhi v25.2d, v16.2d, v3.2d
cmeq v26.2d, v16.2d, v3.2d
cmhi v27.2d, v18.2d, v4.2d
and v27.16b, v27.16b, v26.16b
orr v25.16b, v25.16b, v27.16b
cmeq v27.2d, v18.2d, v4.2d
and v26.16b, v26.16b, v27.16b
cmhi v27.2d, v20.2d, v5.2d
and v27.16b, v27.16b, v26.16b
orr v25.16b, v25.16b, v27.16b
sshr v28.4s, v21.4s, #31
sxtl v29.2d, v28.2s
sxtl2 v30.2d, v28.4s
bic v26.16b, v29.16b, v24.16b
bic v27.16b, v30.16b, v25.16b
and v24.16b, v24.16b, v29.16b
and v25.16b, v25.16b, v30.16b
bit v6.16b, v15.16b, v26.16b
bit v7.16b, v17.16b, v26.16b
bit v8.16b, v19.16b, v26.16b
bit v9.16b, v16.16b, v27.16b
bit v10.16b, v18.16b, v27.16b
bit v11.16b, v20.16b, v27.16b
ldp q22, q23, [sp, #0]
bit v22.16b, v15.16b, v24.16b
bit v23.16b, v16.16b, v25.16b
stp q22, q23, [sp, #0]
ldp q22, q23, [sp, #32]
bit v22.16b, v17.16b, v24.16b
bit v23.16b, v18.16b, v25.16b
stp q22, q23, [sp, #32]
ldp q22, q23, [sp, #64]
bit v22.16b, v19.16b, v24.16b
bit v23.16b, v20.16b, v25.16b
stp q22, q23, [sp, #64]
xtn v22.2s, v26.2d
xtn2 v22.4s, v27.2d
bit v13.16b, v21.16b, v22.16b
orr v12.16b, v12.16b, v22.16b
movi v23.4s, #1
and v22.16b, v22.16b, v23.16b
shl v14.4s, v14.4s, #1
add v14.4s, v14.4s, v22.4s
add x1, x1, #16
subs x2, x2, #1
b.ne 2b
stp q6, q9, [x0, #0]
stp q7, q10, [x0, #32]
stp q8, q11, [x0, #64]
ldp q0, q1, [sp, #0]
stp q0, q1, [x0, #96]
ldp q2, q3, [sp, #32]
stp q2, q3, [x0, #128]
ldp q4, q5, [sp, #64]
stp q4, q5, [x0, #160]
uxtl v0.2d, v13.2s
uxtl2 v1.2d, v13.4s
stp q0, q1, [x0, #192]
sxtl v2.2d, v12.2s
sxtl2 v3.2d, v12.4s
stp q2, q3, [x0, #224]
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
ldp d8, d9, [sp, #96]
ldp d10, d11, [sp, #112]
ldp d12, d13, [sp, #128]
ldp d14, d15, [sp, #144]
stp xzr, xzr, [sp, #0]
stp xzr, xzr, [sp, #16]
stp xzr, xzr, [sp, #32]
stp xzr, xzr, [sp, #48]
stp xzr, xzr, [sp, #64]
stp xzr, xzr, [sp, #80]
stp xzr, xzr, [sp, #96]
stp xzr, xzr, [sp, #112]
stp xzr, xzr, [sp, #128]
stp xzr, xzr, [sp, #144]
add sp, sp, #160
ret
