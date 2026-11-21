// Nonoverlapping initialized input/output, arbitrary byte length. Void ABI.
// No stack, no calls, no platform/callee-saved register writes.
cmp x2,#16
b.lo 2f
1:
ldr q0,[x1],#16
str q0,[x0],#16
sub x2,x2,#16
cmp x2,#16
b.hs 1b
2:
cbz x2,4f
3:
ldrb w3,[x1],#1
strb w3,[x0],#1
subs x2,x2,#1
b.ne 3b
4:
movi v0.16b,#0
mov x0,xzr
mov x1,xzr
mov x2,xzr
mov x3,xzr
msr nzcv,xzr
ret
