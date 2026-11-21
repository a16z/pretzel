// x0 = eight-byte aligned pointer, x1 = word count.
// Writes zero to exactly the same x1 words as pretzel55_ct_erase_words. No loads
// of the buffer, no stack, no SIMD/callee-saved/x18 use; addresses and extent
// are public. DC ZVA is used only on 64-byte blocks lying wholly inside the
// extent, and only when DCZID_EL0 permits it (DZP clear) with a 64-byte block;
// otherwise the plain store loop runs. Scratch registers are cleared.
mrs x3, dczid_el0
tbnz x3, #4, 20f
and x3, x3, #15
cmp x3, #4
b.ne 20f
add x4, x0, x1, lsl #3
1:
tst x0, #63
b.eq 2f
cmp x0, x4
b.hs 9f
str xzr, [x0], #8
b 1b
2:
sub x5, x4, x0
cmp x5, #64
b.lo 4f
3:
dc zva, x0
add x0, x0, #64
sub x5, x5, #64
cmp x5, #64
b.hs 3b
4:
cmp x0, x4
b.hs 9f
str xzr, [x0], #8
b 4b
20:
lsr x2, x1, #3
cbz x2, 22f
21:
stp xzr, xzr, [x0, #0]
stp xzr, xzr, [x0, #16]
stp xzr, xzr, [x0, #32]
stp xzr, xzr, [x0, #48]
add x0, x0, #64
subs x2, x2, #1
b.ne 21b
22:
and x1, x1, #7
lsr x2, x1, #1
cbz x2, 24f
23:
stp xzr, xzr, [x0], #16
subs x2, x2, #1
b.ne 23b
24:
tbz x1, #0, 9f
str xzr, [x0]
9:
mov x0, #0
mov x1, #0
mov x2, #0
mov x3, #0
mov x4, #0
mov x5, #0
ret
