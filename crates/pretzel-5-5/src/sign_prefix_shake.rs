//! SHAKE prefix generation for the high-precision signer.
//! Fixed 8544-byte lane A and 2400+6144-byte lane B squeeze.
//! The 24-round schedule is copied verbatim from keccak2_arm.rs
//! (RustCrypto keccak 0.1.6, MIT OR Apache-2.0), with public outer scheduling.
//! All output addresses depend only on the fixed public block number.
use crate::shake2::KECCAK_RC as RC;

/// Caller supplies an initialized interleaved pair after absorption
/// and padding. All four mutable regions are disjoint, by their Rust borrows.
/// SHA3 support is checked by the caller before this target-feature function.
/// There are exactly 63 permutations, 8544 output bytes per lane, and a single
/// final 400-byte state writeback into the Zeroizing owner.
#[target_feature(enable = "sha3")]
#[inline(never)]
/// # Safety
/// Requires FEAT_SHA3 (the caller checks shake2::available()). The typed mutable borrows must remain
/// disjoint: 50 initialized u64 state words, 8544 first bytes, 2400 second bytes and 6144 transport
/// bytes. The 63 fixed rate blocks use RC's 24 initialized round constants.
pub(super) unsafe fn squeeze(
    pair: &mut [u64; 50],
    first: &mut [u8; 8544],
    second: &mut [u8; 2400],
    transport: &mut [u8; 6144],
) {
    // SAFETY: The caller supplies the function safety contract. Requires FEAT_SHA3 (the caller checks
    // shake2::available()). The typed mutable borrows must remain disjoint: 50 initialized u64 state
    // words, 8544 first bytes, 2400 second bytes and 6144 transport bytes. The 63 fixed rate blocks
    // use RC's 24 initialized round constants.
    unsafe {
        core::arch::asm!(r#"
        // Read state
        ld1.2d {{ v0- v3}}, [x0], #64
        ld1.2d {{ v4- v7}}, [x0], #64
        ld1.2d {{ v8-v11}}, [x0], #64
        ld1.2d {{v12-v15}}, [x0], #64
        ld1.2d {{v16-v19}}, [x0], #64
        ld1.2d {{v20-v23}}, [x0], #64
        ld1.2d {{v24}},     [x0]
        sub x0, x0, #384


20:
mov x1, x6
mov x8, #24
30:
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

        ld1r.2d    {{v26}}, [x1], #8

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


cbnz w8, 30b
cmp x5, #62
b.eq 60f
cmp x5, #17
b.eq 50f
uzp1.2d v25, v0, v1
uzp2.2d v26, v0, v1
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v2, v3
uzp2.2d v26, v2, v3
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v4, v5
uzp2.2d v26, v4, v5
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v6, v7
uzp2.2d v26, v6, v7
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v8, v9
uzp2.2d v26, v8, v9
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v10, v11
uzp2.2d v26, v10, v11
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v12, v13
uzp2.2d v26, v12, v13
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v14, v15
uzp2.2d v26, v14, v15
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
st1 {{v16.d}}[0], [x2], #8
st1 {{v16.d}}[1], [x3], #8
b 70f
50:
st1 {{v0.d}}[0], [x2], #8
st1 {{v0.d}}[1], [x3], #8
st1 {{v1.d}}[0], [x2], #8
st1 {{v1.d}}[1], [x3], #8
st1 {{v2.d}}[0], [x2], #8
st1 {{v2.d}}[1], [x3], #8
st1 {{v3.d}}[0], [x2], #8
st1 {{v3.d}}[1], [x3], #8
st1 {{v4.d}}[0], [x2], #8
st1 {{v4.d}}[1], [x3], #8
st1 {{v5.d}}[0], [x2], #8
st1 {{v5.d}}[1], [x3], #8
st1 {{v6.d}}[0], [x2], #8
st1 {{v6.d}}[1], [x3], #8
st1 {{v7.d}}[0], [x2], #8
st1 {{v7.d}}[1], [x3], #8
st1 {{v8.d}}[0], [x2], #8
st1 {{v8.d}}[1], [x3], #8
st1 {{v9.d}}[0], [x2], #8
st1 {{v9.d}}[1], [x3], #8
st1 {{v10.d}}[0], [x2], #8
st1 {{v10.d}}[1], [x3], #8
mov x3, x4
st1 {{v11.d}}[0], [x2], #8
st1 {{v11.d}}[1], [x3], #8
st1 {{v12.d}}[0], [x2], #8
st1 {{v12.d}}[1], [x3], #8
st1 {{v13.d}}[0], [x2], #8
st1 {{v13.d}}[1], [x3], #8
st1 {{v14.d}}[0], [x2], #8
st1 {{v14.d}}[1], [x3], #8
st1 {{v15.d}}[0], [x2], #8
st1 {{v15.d}}[1], [x3], #8
st1 {{v16.d}}[0], [x2], #8
st1 {{v16.d}}[1], [x3], #8
b 70f
60:
uzp1.2d v25, v0, v1
uzp2.2d v26, v0, v1
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v2, v3
uzp2.2d v26, v2, v3
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v4, v5
uzp2.2d v26, v4, v5
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v6, v7
uzp2.2d v26, v6, v7
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v8, v9
uzp2.2d v26, v8, v9
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v10, v11
uzp2.2d v26, v10, v11
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
uzp1.2d v25, v12, v13
uzp2.2d v26, v12, v13
st1.2d {{v25}}, [x2], #16
st1.2d {{v26}}, [x3], #16
70:
add x5, x5, #1
cmp x5, #63
b.ne 20b
        // Write state
        st1.2d	{{ v0- v3}}, [x0], #64
        st1.2d	{{ v4- v7}}, [x0], #64
        st1.2d	{{ v8-v11}}, [x0], #64
        st1.2d	{{v12-v15}}, [x0], #64
        st1.2d	{{v16-v19}}, [x0], #64
        st1.2d	{{v20-v23}}, [x0], #64
        st1.2d	{{v24}},     [x0]

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
mov x1, xzr
mov x2, xzr
mov x3, xzr
mov x4, xzr
mov x5, xzr
mov x6, xzr
mov x7, xzr
mov x8, xzr
mov x9, xzr
"#,
            inout("x0") pair.as_mut_ptr() => _,
            inout("x1") RC.as_ptr() => _,
            inout("x2") first.as_mut_ptr() => _,
            inout("x3") second.as_mut_ptr() => _,
            inout("x4") transport.as_mut_ptr() => _,
            inout("x5") 0usize => _,
            inout("x6") RC.as_ptr() => _,
            clobber_abi("C"),
            options(nostack)
        );
    }
}
