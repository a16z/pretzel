// Public pointer, public byte count. No private loads, SIMD, stack or x18.
// Align with exact byte stores, then 64-byte groups and exact public tails.
cbz x1,9f
1:
and x2,x0,#7
cbz x2,2f
strb wzr,[x0],#1
subs x1,x1,#1
b.eq 9f
b 1b
2:
cmp x1,#64
b.lo 4f
3:
stp xzr,xzr,[x0,#0]
stp xzr,xzr,[x0,#16]
stp xzr,xzr,[x0,#32]
stp xzr,xzr,[x0,#48]
add x0,x0,#64
sub x1,x1,#64
cmp x1,#64
b.hs 3b
4:
cmp x1,#16
b.lo 6f
5:
stp xzr,xzr,[x0],#16
sub x1,x1,#16
cmp x1,#16
b.hs 5b
6:
tbz x1,#3,7f
str xzr,[x0],#8
sub x1,x1,#8
7:
cbz x1,9f
8:
strb wzr,[x0],#1
subs x1,x1,#1
b.ne 8b
9:
mov x0,#0
mov x1,#0
mov x2,#0
ret
