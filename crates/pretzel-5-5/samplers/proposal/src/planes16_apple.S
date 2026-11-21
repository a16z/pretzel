// Public loops: public stage planes, columns/16 blocks. Private indices only feed TBX.
.p2align 2
_pretzel55_proposal_planes16:
    ld1 {v1.16b, v2.16b}, [x3]
    mov x8, x1
    mov x9, x4
1:
    movi v0.16b, #0
    mov x10, x8
    mov x11, x2
    mov w12, #0
2:
    dup v3.16b, w12
    cmeq v3.16b, v2.16b, v3.16b
    orn v4.16b, v1.16b, v3.16b
    ldr q5, [x10]
    tbx v0.16b, {v5.16b}, v4.16b
    add x10, x10, #704
    add w12, w12, #1
    subs x11, x11, #1
    b.ne 2b
    str q0, [x0], #16
    add x8, x8, #16
    subs x9, x9, #1
    b.ne 1b
    movi v0.16b, #0
    movi v1.16b, #0
    movi v2.16b, #0
    movi v3.16b, #0
    movi v4.16b, #0
    movi v5.16b, #0
    mov x8, xzr
    mov x9, xzr
    mov x10, xzr
    mov x11, xzr
    mov x12, xzr
    ret
