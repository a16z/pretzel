// x0: pair[50], x1: public rate offset, x2: input, x3: public byte count.
// Caller guarantees offset+count <= 136 and disjoint initialized slices.
// Duplicate every XOR into both lanes; consume aligned whole words when able.
1:
cbz x3, 9f
tst x1, #7
b.eq 3f
2:
lsr x4, x1, #3
add x4, x0, x4, lsl #4
and x5, x1, #7
lsl x5, x5, #3
ldrb w6, [x2], #1
lsl x6, x6, x5
ldp x7, x8, [x4]
eor x7, x7, x6
eor x8, x8, x6
stp x7, x8, [x4]
add x1, x1, #1
sub x3, x3, #1
b 1b
3:
cmp x3, #8
b.lo 2b
lsr x4, x1, #3
add x4, x0, x4, lsl #4
4:
ldr x6, [x2], #8
ldp x7, x8, [x4]
eor x7, x7, x6
eor x8, x8, x6
stp x7, x8, [x4], #16
add x1, x1, #8
sub x3, x3, #8
cmp x3, #8
b.hs 4b
b 1b
9:
mov x0, xzr
mov x1, xzr
mov x2, xzr
mov x3, xzr
mov x4, xzr
mov x5, xzr
mov x6, xzr
mov x7, xzr
mov x8, xzr
msr nzcv, xzr
ret
