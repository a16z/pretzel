// Eight queries. x0 output, x1 public table, x2 positive public blocks,
// x3 masked private indices at a public address, x4 AoS draws, x5 public log2(N).
// Arrays and frame are disjoint; only public counters enter branches/addresses.
sub sp, sp, #64
stp d8, d9, [sp, #0]
stp d10, d11, [sp, #16]
stp d12, d13, [sp, #32]
stp d14, d15, [sp, #48]
ld1 {v20.4s-v21.4s}, [x3]
ushr v22.4s, v20.4s, #4
ushr v23.4s, v21.4s, #4
movi v24.4s, #15
and v20.16b, v20.16b, v24.16b
and v21.16b, v21.16b, v24.16b
movi v24.16b, #4
mul v20.4s, v20.4s, v24.4s
mul v21.4s, v21.4s, v24.4s
mov w6, #0x0100
movk w6, #0x0302, lsl #16
dup v24.4s, w6
add v20.4s, v20.4s, v24.4s
add v21.4s, v21.4s, v24.4s
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
mov w6, #0
2:
dup v24.4s, w6
cmeq v28.4s, v22.4s, v24.4s
cmeq v29.4s, v23.4s, v24.4s
orn v30.16b, v20.16b, v28.16b
orn v31.16b, v21.16b, v29.16b
ld1 {v24.16b-v27.16b}, [x1], #64
tbx v0.16b, {v24.16b-v27.16b}, v30.16b
tbx v1.16b, {v24.16b-v27.16b}, v31.16b
ld1 {v24.16b-v27.16b}, [x1], #64
tbx v2.16b, {v24.16b-v27.16b}, v30.16b
tbx v3.16b, {v24.16b-v27.16b}, v31.16b
ld1 {v24.16b-v27.16b}, [x1], #64
tbx v4.16b, {v24.16b-v27.16b}, v30.16b
tbx v5.16b, {v24.16b-v27.16b}, v31.16b
ld1 {v24.16b-v27.16b}, [x1], #64
tbx v6.16b, {v24.16b-v27.16b}, v30.16b
tbx v7.16b, {v24.16b-v27.16b}, v31.16b
ld1 {v24.16b-v27.16b}, [x1], #64
tbx v8.16b, {v24.16b-v27.16b}, v30.16b
tbx v9.16b, {v24.16b-v27.16b}, v31.16b
ld1 {v24.16b-v27.16b}, [x1], #64
tbx v10.16b, {v24.16b-v27.16b}, v30.16b
tbx v11.16b, {v24.16b-v27.16b}, v31.16b
ld1 {v24.16b-v27.16b}, [x1], #64
tbx v12.16b, {v24.16b-v27.16b}, v30.16b
tbx v13.16b, {v24.16b-v27.16b}, v31.16b
ld1 {v24.16b-v27.16b}, [x1], #64
tbx v14.16b, {v24.16b-v27.16b}, v30.16b
tbx v15.16b, {v24.16b-v27.16b}, v31.16b
add w6, w6, #1
subs x2, x2, #1
b.ne 2b
mov x6, #1
lsl x6, x6, x5
lsl x7, x6, #1
// Resolve lanes 0, 1; gathered columns remain in v0-v15.
zip1 v16.4s, v0.4s, v2.4s
zip1 v17.4s, v4.4s, v6.4s
zip1 v18.4s, v8.4s, v10.4s
zip1 v19.4s, v12.4s, v14.4s
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
// Selected tag and modular rank parity.
ushr v17.2d, v19.2d, #15
mov v16.16b, v29.16b
bsl v16.16b, v19.16b, v17.16b
ushr v17.2d, v19.2d, #30
sub x8, x7, #1
dup v18.2d, x8
and v17.16b, v17.16b, v18.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
neg x8, x5
dup v23.2d, x8
ushl v17.2d, v17.2d, v23.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
mov x8, #1
dup v23.2d, x8
and v17.16b, v17.16b, v23.16b
// Keep the selected tag tie bit before reducing it to the count base.
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v23.16b
neg v30.2d, v30.2d
mov x8, #4095
dup v18.2d, x8
and v16.16b, v16.16b, v18.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference.
add x8, x5, #31
neg x8, x8
dup v23.2d, x8
ushl v18.2d, v19.2d, v23.2d
lsl x8, x7, #1
sub x8, x8, #1
dup v23.2d, x8
and v18.16b, v18.16b, v23.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie.
dup v23.2d, x7
cmhi v17.2d, v23.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 2, 3; gathered columns remain in v0-v15.
zip2 v16.4s, v0.4s, v2.4s
zip2 v17.4s, v4.4s, v6.4s
zip2 v18.4s, v8.4s, v10.4s
zip2 v19.4s, v12.4s, v14.4s
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
// Selected tag and modular rank parity.
ushr v17.2d, v19.2d, #15
mov v16.16b, v29.16b
bsl v16.16b, v19.16b, v17.16b
ushr v17.2d, v19.2d, #30
sub x8, x7, #1
dup v18.2d, x8
and v17.16b, v17.16b, v18.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
neg x8, x5
dup v23.2d, x8
ushl v17.2d, v17.2d, v23.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
mov x8, #1
dup v23.2d, x8
and v17.16b, v17.16b, v23.16b
// Keep the selected tag tie bit before reducing it to the count base.
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v23.16b
neg v30.2d, v30.2d
mov x8, #4095
dup v18.2d, x8
and v16.16b, v16.16b, v18.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference.
add x8, x5, #31
neg x8, x8
dup v23.2d, x8
ushl v18.2d, v19.2d, v23.2d
lsl x8, x7, #1
sub x8, x8, #1
dup v23.2d, x8
and v18.16b, v18.16b, v23.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie.
dup v23.2d, x7
cmhi v17.2d, v23.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 4, 5; gathered columns remain in v0-v15.
zip1 v16.4s, v1.4s, v3.4s
zip1 v17.4s, v5.4s, v7.4s
zip1 v18.4s, v9.4s, v11.4s
zip1 v19.4s, v13.4s, v15.4s
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
// Selected tag and modular rank parity.
ushr v17.2d, v19.2d, #15
mov v16.16b, v29.16b
bsl v16.16b, v19.16b, v17.16b
ushr v17.2d, v19.2d, #30
sub x8, x7, #1
dup v18.2d, x8
and v17.16b, v17.16b, v18.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
neg x8, x5
dup v23.2d, x8
ushl v17.2d, v17.2d, v23.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
mov x8, #1
dup v23.2d, x8
and v17.16b, v17.16b, v23.16b
// Keep the selected tag tie bit before reducing it to the count base.
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v23.16b
neg v30.2d, v30.2d
mov x8, #4095
dup v18.2d, x8
and v16.16b, v16.16b, v18.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference.
add x8, x5, #31
neg x8, x8
dup v23.2d, x8
ushl v18.2d, v19.2d, v23.2d
lsl x8, x7, #1
sub x8, x8, #1
dup v23.2d, x8
and v18.16b, v18.16b, v23.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie.
dup v23.2d, x7
cmhi v17.2d, v23.2d, v22.2d
orr v20.16b, v20.16b, v21.16b
cmeq v20.2d, v20.2d, #0
and v17.16b, v17.16b, v20.16b
bsl v29.16b, v17.16b, v18.16b
and v17.16b, v29.16b, v30.16b
st2 {v16.2d-v17.2d}, [x0], #32
// Resolve lanes 6, 7; gathered columns remain in v0-v15.
zip2 v16.4s, v1.4s, v3.4s
zip2 v17.4s, v5.4s, v7.4s
zip2 v18.4s, v9.4s, v11.4s
zip2 v19.4s, v13.4s, v15.4s
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
// Selected tag and modular rank parity.
ushr v17.2d, v19.2d, #15
mov v16.16b, v29.16b
bsl v16.16b, v19.16b, v17.16b
ushr v17.2d, v19.2d, #30
sub x8, x7, #1
dup v18.2d, x8
and v17.16b, v17.16b, v18.16b
bic v17.16b, v17.16b, v29.16b
add v17.2d, v22.2d, v17.2d
neg x8, x5
dup v23.2d, x8
ushl v17.2d, v17.2d, v23.2d
ushr v18.2d, v16.2d, #13
eor v17.16b, v17.16b, v18.16b
ushr v23.2d, v16.2d, #12
and v17.16b, v17.16b, v23.16b
mov x8, #1
dup v23.2d, x8
and v17.16b, v17.16b, v23.16b
// Keep the selected tag tie bit before reducing it to the count base.
ushr v30.2d, v16.2d, #14
and v30.16b, v30.16b, v23.16b
neg v30.2d, v30.2d
mov x8, #4095
dup v18.2d, x8
and v16.16b, v16.16b, v18.16b
add v16.2d, v16.2d, v17.2d
// Alias capped prefix is compared to the complete nonnegative difference.
add x8, x5, #31
neg x8, x8
dup v23.2d, x8
ushl v18.2d, v19.2d, v23.2d
lsl x8, x7, #1
sub x8, x8, #1
dup v23.2d, x8
and v18.16b, v18.16b, v23.16b
cmhi v18.2d, v18.2d, v24.2d
orr v27.16b, v26.16b, v28.16b
cmeq v27.2d, v27.2d, #0
and v18.16b, v18.16b, v27.16b
// Primary prefix and final masked tie.
dup v23.2d, x7
cmhi v17.2d, v23.2d, v22.2d
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
stp xzr, xzr, [sp, #0]
stp xzr, xzr, [sp, #16]
stp xzr, xzr, [sp, #32]
stp xzr, xzr, [sp, #48]
add sp, sp, #64
ret
