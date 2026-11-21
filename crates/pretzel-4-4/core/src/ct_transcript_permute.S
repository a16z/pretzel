// Adapted from RustCrypto keccak 0.1.6; MIT OR Apache-2.0. See THIRD-PARTY-NOTICES.md.
// Private SHAKE permutation: x0 points to 50 interleaved u64 lanes,
// x1 to the canonical 24 public round constants. Fixed 24 rounds.
// The 64-byte frame saves only incoming ABI-preserved d8..d15 values.
sub sp, sp, #64
stp d8, d9, [sp, #0]
stp d10, d11, [sp, #16]
stp d12, d13, [sp, #32]
stp d14, d15, [sp, #48]
ld1.2d {v0-v3}, [x0], #64
ld1.2d {v4-v7}, [x0], #64
ld1.2d {v8-v11}, [x0], #64
ld1.2d {v12-v15}, [x0], #64
ld1.2d {v16-v19}, [x0], #64
ld1.2d {v20-v23}, [x0], #64
ld1.2d {v24}, [x0]
sub x0, x0, #384
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
        // Write state
        st1.2d	{ v0- v3}, [x0], #64
        st1.2d	{ v4- v7}, [x0], #64
        st1.2d	{ v8-v11}, [x0], #64
        st1.2d	{v12-v15}, [x0], #64
        st1.2d	{v16-v19}, [x0], #64
        st1.2d	{v20-v23}, [x0], #64
        st1.2d	{v24},     [x0]

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
msr nzcv, xzr
ret
