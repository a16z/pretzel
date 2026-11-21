// Adapted from RustCrypto keccak 0.1.6; MIT OR Apache-2.0. See THIRD-PARTY-NOTICES.md.
// Public full-block SHAKE absorb. x0=state, x1=bytes, x2=positive block count,
// x3=round constants. Reads exactly 136*x2 input bytes. No private callers.
// Round body and state save/restore are copied from ct_sponge_permute.S.
sub sp, sp, #64
stp d8, d9, [sp, #0]
stp d10, d11, [sp, #16]
stp d12, d13, [sp, #32]
stp d14, d15, [sp, #48]
ldp d0, d1, [x0, #0]
ldp d2, d3, [x0, #16]
ldp d4, d5, [x0, #32]
ldp d6, d7, [x0, #48]
ldp d8, d9, [x0, #64]
ldp d10, d11, [x0, #80]
ldp d12, d13, [x0, #96]
ldp d14, d15, [x0, #112]
ldp d16, d17, [x0, #128]
ldp d18, d19, [x0, #144]
ldp d20, d21, [x0, #160]
ldp d22, d23, [x0, #176]
ldr d24, [x0, #192]
mov x4, x1
mov x5, x2
mov x6, x3
2:
ldr d25, [x4], #8
eor.16b v0, v0, v25
ldr d25, [x4], #8
eor.16b v1, v1, v25
ldr d25, [x4], #8
eor.16b v2, v2, v25
ldr d25, [x4], #8
eor.16b v3, v3, v25
ldr d25, [x4], #8
eor.16b v4, v4, v25
ldr d25, [x4], #8
eor.16b v5, v5, v25
ldr d25, [x4], #8
eor.16b v6, v6, v25
ldr d25, [x4], #8
eor.16b v7, v7, v25
ldr d25, [x4], #8
eor.16b v8, v8, v25
ldr d25, [x4], #8
eor.16b v9, v9, v25
ldr d25, [x4], #8
eor.16b v10, v10, v25
ldr d25, [x4], #8
eor.16b v11, v11, v25
ldr d25, [x4], #8
eor.16b v12, v12, v25
ldr d25, [x4], #8
eor.16b v13, v13, v25
ldr d25, [x4], #8
eor.16b v14, v14, v25
ldr d25, [x4], #8
eor.16b v15, v15, v25
ldr d25, [x4], #8
eor.16b v16, v16, v25
mov x1, x6
mov x8, #24
1:
sub x8, x8, #1
        // Theta Calculations
        eor3.16b   v25, v20, v15, v10
        eor3.16b   v26, v21, v16, v11
        eor3.16b   v27, v22, v17, v12
        eor3.16b   v28, v23, v18, v13
        eor3.16b   v29, v24, v19, v14
        eor3.16b   v25, v25,  v5,  v0
        eor3.16b   v26, v26,  v6,  v1
        eor3.16b   v27, v27,  v7,  v2
        eor3.16b   v28, v28,  v8,  v3
        eor3.16b   v29, v29,  v9,  v4
        rax1.2d    v30, v25, v27
        rax1.2d    v31, v26, v28
        rax1.2d    v27, v27, v29
        rax1.2d    v28, v28, v25
        rax1.2d    v29, v29, v26

        // Rho and Phi
        eor.16b     v0,  v0, v29
        xar.2d     v25,  v1, v30, #64 -  1
        xar.2d      v1,  v6, v30, #64 - 44
        xar.2d      v6,  v9, v28, #64 - 20
        xar.2d      v9, v22, v31, #64 - 61
        xar.2d     v22, v14, v28, #64 - 39
        xar.2d     v14, v20, v29, #64 - 18
        xar.2d     v26,  v2, v31, #64 - 62
        xar.2d      v2, v12, v31, #64 - 43
        xar.2d     v12, v13, v27, #64 - 25
        xar.2d     v13, v19, v28, #64 -  8
        xar.2d     v19, v23, v27, #64 - 56
        xar.2d     v23, v15, v29, #64 - 41
        xar.2d     v15,  v4, v28, #64 - 27
        xar.2d     v28, v24, v28, #64 - 14
        xar.2d     v24, v21, v30, #64 -  2
        xar.2d      v8,  v8, v27, #64 - 55
        xar.2d      v4, v16, v30, #64 - 45
        xar.2d     v16,  v5, v29, #64 - 36
        xar.2d      v5,  v3, v27, #64 - 28
        xar.2d     v27, v18, v27, #64 - 21
        xar.2d      v3, v17, v31, #64 - 15
        xar.2d     v30, v11, v30, #64 - 10
        xar.2d     v31,  v7, v31, #64 -  6
        xar.2d     v29, v10, v29, #64 -  3

        // Chi and Iota
        bcax.16b   v20, v26, v22,  v8
        bcax.16b   v21,  v8, v23, v22
        bcax.16b   v22, v22, v24, v23
        bcax.16b   v23, v23, v26, v24
        bcax.16b   v24, v24,  v8, v26

        ld1r.2d    {v26}, [x1], #8

        bcax.16b   v17, v30, v19,  v3
        bcax.16b   v18,  v3, v15, v19
        bcax.16b   v19, v19, v16, v15
        bcax.16b   v15, v15, v30, v16
        bcax.16b   v16, v16,  v3, v30

        bcax.16b   v10, v25, v12, v31
        bcax.16b   v11, v31, v13, v12
        bcax.16b   v12, v12, v14, v13
        bcax.16b   v13, v13, v25, v14
        bcax.16b   v14, v14, v31, v25

        bcax.16b    v7, v29,  v9,  v4
        bcax.16b    v8,  v4,  v5,  v9
        bcax.16b    v9,  v9,  v6,  v5
        bcax.16b    v5,  v5, v29,  v6
        bcax.16b    v6,  v6,  v4, v29

        bcax.16b    v3, v27,  v0, v28
        bcax.16b    v4, v28,  v1,  v0
        bcax.16b    v0,  v0,  v2,  v1
        bcax.16b    v1,  v1, v27,  v2
        bcax.16b    v2,  v2, v28, v27

        eor.16b v0,v0,v26


cbnz x8, 1b
subs x5, x5, #1
b.ne 2b
// Write exactly the 25 low lanes, preserving the original 200-byte owner.
stp d0, d1, [x0, #0]
stp d2, d3, [x0, #16]
stp d4, d5, [x0, #32]
stp d6, d7, [x0, #48]
stp d8, d9, [x0, #64]
stp d10, d11, [x0, #80]
stp d12, d13, [x0, #96]
stp d14, d15, [x0, #112]
stp d16, d17, [x0, #128]
stp d18, d19, [x0, #144]
stp d20, d21, [x0, #160]
stp d22, d23, [x0, #176]
str d24, [x0, #192]

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
mov x0, xzr
mov x1, xzr
mov x8, xzr
mov x2, xzr
mov x3, xzr
mov x4, xzr
mov x5, xzr
mov x6, xzr
msr nzcv, xzr
ret
