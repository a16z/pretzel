// Edited compiler output that refines the Rust prefix parser; this file is its source.
// ABI: z, draws, draw_count, bytes, byte_count, pool, done; returns consumed bytes.
// Frame holds only incoming ABI registers and is wiped after restoration.
// Not straight-line. Branches on public quantities: the draw count and the bytes left (the
// bytes left also move with the number of words consumed). Branches on draw words: the first
// word against z[0], the range comparisons and subtractions of the recycling loop, the pool
// refill, and the three-word comparison with z that accepts a candidate or draws again.
// These are the decisions of rejection sampling. This file does not claim constant time.
sub sp, sp, #48
stp x21, x25, [sp]
stp x26, x27, [sp, #16]
stp x28, x30, [sp, #32]
ldr x11, [x0]
adds x12, x11, #0x1
cset w13, hs
ldr x14, [x6]
cmp x14, x2
b.hs 908f
mov x8, x2
mov x7, #0x0
mvn x21, x11
ldp x16, x17, [x0, #0x8]
ldp x10, x25, [x5]
mov x0, #0x0
900:
ldr q0, [x5]
add x26, x1, x14, lsl #5
mov x27, x10
901:
sub x9, x4, x0
cmp x9, #0x8
b.lo 909f
add x9, x0, #0x8
cmn x0, #0x9
cmp x9, x4
ldr x28, [x3, x0]
str x28, [x26]
cmp x28, x11
b.ls 907f
mov x0, #0x0
subs x28, x28, x12
ngc x30, x13
mov x15, x21
cmp x11, x21
ngcs xzr, x0
b.lo 905f
902:
cbz x25, 904f
903:
extr x30, x30, x28, #0x3f
lsr x10, x27, #1
bfi x27, x28, #1, #63
mov x28, x27
extr x0, x0, x15, #0x3f
sub x25, x25, #0x1
mov x27, x10
lsl x15, x15, #1
cmp x11, x15
ngcs xzr, x0
b.lo 905f
b 902b
904:
sub x10, x4, x9
cmp x10, #0x8
b.lo 912f
add x10, x9, #0x8
cmn x9, #0x9
cmp x10, x4
ldr x27, [x3, x9]
mov w25, #0x40
mov x9, x10
b 903b
905:
cmp x11, x28
ngcs xzr, x30
b.hs 906f
subs x28, x28, x12
sbc x30, x30, x13
subs x15, x15, x12
sbc x0, x0, x13
cmp x11, x15
ngcs xzr, x0
b.lo 905b
b 902b
906:
str x28, [x26]
907:
sub x15, x4, x9
cmp x15, #0x8
b.lo 909f
add x15, x9, #0x8
cmn x9, #0x9
subs x0, x4, x15
ldr x30, [x3, x9]
str x30, [x26, #0x8]
cmp x0, #0x8
b.lo 909f
add x0, x9, #0x10
cmp x0, x15
cmp x0, x4
ldr x9, [x3, x15]
str x9, [x26, #0x10]
subs x15, x17, x9
sbcs x15, x16, x30
sbcs x15, x11, x28
csetm x9, lo
cbnz x9, 901b
stp x10, x25, [x5]
add x14, x14, #0x1
str x14, [x6]
mov x7, x0
cmp x14, x8
b.ne 900b
b 911f
908:
mov x0, #0x0
b 911f
909:
str q0, [x5]
910:
mov x0, x7
911:
ldp x21, x25, [sp]
ldp x26, x27, [sp, #16]
ldp x28, x30, [sp, #32]
stp xzr, xzr, [sp]
stp xzr, xzr, [sp, #16]
stp xzr, xzr, [sp, #32]
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
movi v0.16b, #0
msr NZCV, xzr
add sp, sp, #48
ret 
912:
str q0, [x5]
b 910b
