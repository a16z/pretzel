// Little-endian AArch64 normal-memory exact interval XOR.
// x0 initialized state[25], x1 public offset, x2 disjoint input, x3 count.
// Caller proves offset+count<=136. No read/write is rounded beyond count.
add x0,x0,x1
cmp x3,#8
b.lo 2f
1:
ldr x6,[x2],#8
ldr x7,[x0]
eor x7,x7,x6
str x7,[x0],#8
sub x3,x3,#8
cmp x3,#8
b.hs 1b
2:
tbz x3,#2,3f
ldr w6,[x2],#4
ldr w7,[x0]
eor w7,w7,w6
str w7,[x0],#4
3:
tbz x3,#1,4f
ldrh w6,[x2],#2
ldrh w7,[x0]
eor w7,w7,w6
strh w7,[x0],#2
4:
tbz x3,#0,9f
ldrb w6,[x2]
ldrb w7,[x0]
eor w7,w7,w6
strb w7,[x0]
9:
mov x0,xzr
mov x1,xzr
mov x2,xzr
mov x3,xzr
mov x4,xzr
mov x5,xzr
mov x6,xzr
mov x7,xzr
mov x8,xzr
msr nzcv,xzr
ret
