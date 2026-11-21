// Residual gather of the sec table of the rare-queue sampler. Straight-line code with no
// generator in this repository. It reads 32 index bytes, reads its 10816-byte table front to
// back and writes 256 bytes; it also reads and rewrites 256 bytes at `hi`. The Rust contract is in `ct_rarequeue.rs`.
// Residual x4 points to coarse rows for low24 patch.
sub sp, sp, #64
stp d8, d9, [sp, #0]
stp d10, d11, [sp, #16]
stp d12, d13, [sp, #32]
stp d14, d15, [sp, #48]
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
shl v29.16b, v28.16b, #4
orr v27.16b, v27.16b, v29.16b
movi v31.16b, #127
and v27.16b, v27.16b, v31.16b
ushr v28.16b, v28.16b, #3
movi v31.16b, #128
movi v24.16b, #16
movi v25.16b, #48
movi v26.16b, #112
movi v29.16b, #0
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v8.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
movi v29.16b, #1
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
movi v29.16b, #2
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
movi v29.16b, #3
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v7.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v9.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v10.16b, {v16.16b}, v30.16b
tbx v11.16b, {v17.16b}, v30.16b
tbx v12.16b, {v18.16b}, v30.16b
tbx v13.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b}, [x1], #32
tbx v14.16b, {v16.16b}, v30.16b
tbx v15.16b, {v17.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v6.16b, {v18.16b}, v30.16b
tbx v9.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v10.16b, {v16.16b}, v30.16b
tbx v11.16b, {v17.16b}, v30.16b
tbx v12.16b, {v18.16b}, v30.16b
tbx v13.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b}, [x1], #32
tbx v14.16b, {v16.16b}, v30.16b
tbx v15.16b, {v17.16b}, v30.16b
movi v29.16b, #4
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v5.16b, {v17.16b}, v30.16b
tbx v9.16b, {v18.16b}, v30.16b
tbx v10.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v11.16b, {v16.16b}, v30.16b
tbx v12.16b, {v17.16b}, v30.16b
tbx v13.16b, {v18.16b}, v30.16b
tbx v14.16b, {v19.16b}, v30.16b
ld1 {v16.16b}, [x1], #16
tbx v15.16b, {v16.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v4.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v3.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
tbx v9.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v10.16b, {v16.16b}, v30.16b
tbx v11.16b, {v17.16b}, v30.16b
tbx v12.16b, {v18.16b}, v30.16b
tbx v13.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b}, [x1], #32
tbx v14.16b, {v16.16b}, v30.16b
tbx v15.16b, {v17.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v9.16b, {v18.16b}, v30.16b
tbx v10.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v11.16b, {v16.16b}, v30.16b
tbx v12.16b, {v17.16b}, v30.16b
tbx v13.16b, {v18.16b}, v30.16b
tbx v14.16b, {v19.16b}, v30.16b
ld1 {v16.16b}, [x1], #16
tbx v15.16b, {v16.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v0.16b, {v16.16b}, v30.16b
tbx v9.16b, {v17.16b}, v30.16b
tbx v10.16b, {v18.16b}, v30.16b
tbx v11.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v12.16b, {v16.16b}, v30.16b
tbx v13.16b, {v17.16b}, v30.16b
tbx v14.16b, {v18.16b}, v30.16b
tbx v15.16b, {v19.16b}, v30.16b
movi v29.16b, #5
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
tbx v15.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b, v17.16b}, [x1], #32
tbx v13.16b, {v16.16b}, v30.16b
tbx v14.16b, {v17.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
ld1 {v16.16b}, [x1], #16
tbx v13.16b, {v16.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b, v19.16b}, [x1], #64
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
tbx v12.16b, {v19.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
tbx v11.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b}, [x1], #32
tbx v9.16b, {v16.16b}, v30.16b
tbx v10.16b, {v17.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b}, [x1], #16
tbx v9.16b, {v16.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
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
stp q0, q1, [x0, #0]
stp q2, q3, [x0, #32]
stp q4, q5, [x0, #64]
stp q6, q7, [x0, #96]
stp q8, q9, [x0, #128]
stp q10, q11, [x0, #160]
stp q12, q13, [x0, #192]
stp q14, q15, [x0, #224]
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
shl v29.16b, v28.16b, #4
orr v27.16b, v27.16b, v29.16b
movi v31.16b, #127
and v27.16b, v27.16b, v31.16b
ushr v28.16b, v28.16b, #3
movi v31.16b, #128
movi v24.16b, #16
movi v25.16b, #48
movi v26.16b, #112
movi v29.16b, #0
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
movi v29.16b, #1
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
movi v29.16b, #2
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
movi v29.16b, #3
cmeq v29.16b, v28.16b, v29.16b
bic v29.16b, v31.16b, v29.16b
orr v30.16b, v27.16b, v29.16b
ld1 {v16.16b, v17.16b, v18.16b}, [x1], #48
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
tbx v2.16b, {v18.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b, v17.16b}, [x1], #32
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
eor v30.16b, v30.16b, v25.16b
ld1 {v16.16b, v17.16b}, [x1], #32
tbx v0.16b, {v16.16b}, v30.16b
tbx v1.16b, {v17.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
ld1 {v16.16b}, [x1], #16
tbx v0.16b, {v16.16b}, v30.16b
eor v30.16b, v30.16b, v26.16b
ld1 {v16.16b}, [x1], #16
tbx v0.16b, {v16.16b}, v30.16b
eor v30.16b, v30.16b, v24.16b
eor v30.16b, v30.16b, v25.16b
eor v30.16b, v30.16b, v24.16b
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
ldr q16, [x4, #0]
orr v0.16b, v0.16b, v16.16b
str q0, [x4, #0]
ldr q16, [x4, #16]
orr v1.16b, v1.16b, v16.16b
str q1, [x4, #16]
ldr q16, [x4, #32]
orr v2.16b, v2.16b, v16.16b
str q2, [x4, #32]
ldr q16, [x4, #48]
orr v3.16b, v3.16b, v16.16b
str q3, [x4, #48]
ldr q16, [x4, #64]
orr v4.16b, v4.16b, v16.16b
str q4, [x4, #64]
ldr q16, [x4, #80]
orr v5.16b, v5.16b, v16.16b
str q5, [x4, #80]
ldr q16, [x4, #96]
orr v6.16b, v6.16b, v16.16b
str q6, [x4, #96]
ldr q16, [x4, #112]
orr v7.16b, v7.16b, v16.16b
str q7, [x4, #112]
ldr q16, [x4, #128]
orr v8.16b, v8.16b, v16.16b
str q8, [x4, #128]
ldr q16, [x4, #144]
orr v9.16b, v9.16b, v16.16b
str q9, [x4, #144]
ldr q16, [x4, #160]
orr v10.16b, v10.16b, v16.16b
str q10, [x4, #160]
ldr q16, [x4, #176]
orr v11.16b, v11.16b, v16.16b
str q11, [x4, #176]
ldr q16, [x4, #192]
orr v12.16b, v12.16b, v16.16b
str q12, [x4, #192]
ldr q16, [x4, #208]
orr v13.16b, v13.16b, v16.16b
str q13, [x4, #208]
ldr q16, [x4, #224]
orr v14.16b, v14.16b, v16.16b
str q14, [x4, #224]
ldr q16, [x4, #240]
orr v15.16b, v15.16b, v16.16b
str q15, [x4, #240]
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
add sp, sp, #64
mov x0, xzr
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
msr nzcv, xzr
ret
