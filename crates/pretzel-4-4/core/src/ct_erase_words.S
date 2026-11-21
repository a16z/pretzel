// Exact public-extent erasure. Samezero stores, no private loads, no stack,
// no SIMD/callee/x18 use. Unroll full chunks, then original word-pair tail.
lsr x2,x1,#3
cbz x2,2f
1:
stp xzr,xzr,[x0,#0]
stp xzr,xzr,[x0,#16]
stp xzr,xzr,[x0,#32]
stp xzr,xzr,[x0,#48]
add x0,x0,#64
subs x2,x2,#1
b.ne 1b
2:
and x1,x1,#7
lsr x2,x1,#1
cbz x2,4f
3:
stp xzr,xzr,[x0],#16
subs x2,x2,#1
b.ne 3b
4:
tbz x1,#0,5f
str xzr,[x0]
5:
mov x0,#0
mov x1,#0
mov x2,#0
ret
