// Fixed 256-output scatter through register lookup. x0 updates, x1 signs[128], x2 bool challenge[256].
// No frame, untouched v8..v15. Challenge weight <=128; signs of inactive slots are zero.
ld1 {v0.16b-v3.16b}, [x1], #64
ld1 {v4.16b-v7.16b}, [x1]
movi v16.16b, #0
movi v17.16b, #64
mov w9, #0
mov x3, #16
1:
ld1 {v18.16b}, [x2], #16
mov v19.16b, v18.16b
ext v20.16b, v16.16b, v19.16b, #15
add v19.16b, v19.16b, v20.16b
ext v20.16b, v16.16b, v19.16b, #14
add v19.16b, v19.16b, v20.16b
ext v20.16b, v16.16b, v19.16b, #12
add v19.16b, v19.16b, v20.16b
ext v20.16b, v16.16b, v19.16b, #8
add v19.16b, v19.16b, v20.16b
sub v21.16b, v19.16b, v18.16b
dup v20.16b, w9
add v21.16b, v21.16b, v20.16b
umov w8, v19.b[15]
add w9, w9, w8
tbl v22.16b, {v0.16b-v3.16b}, v21.16b
sub v21.16b, v21.16b, v17.16b
tbx v22.16b, {v4.16b-v7.16b}, v21.16b
neg v18.16b, v18.16b
and v22.16b, v22.16b, v18.16b
sxtl v23.8h, v22.8b
sxtl2 v24.8h, v22.16b
sxtl v25.4s, v23.4h
sxtl2 v26.4s, v23.8h
sxtl v27.4s, v24.4h
sxtl2 v28.4s, v24.8h
ld1 {v29.4s}, [x0]
add v29.4s, v29.4s, v25.4s
st1 {v29.4s}, [x0], #16
ld1 {v29.4s}, [x0]
add v29.4s, v29.4s, v26.4s
st1 {v29.4s}, [x0], #16
ld1 {v29.4s}, [x0]
add v29.4s, v29.4s, v27.4s
st1 {v29.4s}, [x0], #16
ld1 {v29.4s}, [x0]
add v29.4s, v29.4s, v28.4s
st1 {v29.4s}, [x0], #16
subs x3, x3, #1
b.ne 1b
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
mov x8, xzr
mov x9, xzr
msr NZCV, xzr
ret
