// x0: output counts, x1: public multiple-of-four length, w2: stride,
// w3: public number of values, x4: complete attempt abort mask.
// No calls, fixed-address loop, no private branch.
// Zeroes the 512 bytes of stack below the stack pointer at entry. After a tail
// call they are the top 512 bytes of what the caller's released frame and its
// callees used; after an ordinary call the caller's frame is still live above
// them and they are what deeper calls left. In the release images measured
// (rustc 1.90.0, Apple clang 17.0.0, release profile) the body of the rare-queue
// sampler reaches this routine as follows. Pretzel-(4,4): one site is an
// ordinary call with the 544-byte frame of the body live, so the range zeroed
// lies 544 to 1056 bytes below the frame record of the sampler's wrapper; the
// other site is a tail call, and the frame of the body is 32 bytes larger than
// this wipe. Pretzel-(3,3): the range zeroed on the rare-queue path lies 240 to
// 752 bytes below that frame record. So this wipe does not by itself cover the
// frame of the body or the frames below it; the wrapper of the body
// (`ct_rq_wrapper_mac.S`) zeroes 2048 bytes and does not rely on it. Nothing in
// this repository checks these figures.
sub sp, sp, #512
stp xzr, xzr, [sp, #0]
stp xzr, xzr, [sp, #16]
stp xzr, xzr, [sp, #32]
stp xzr, xzr, [sp, #48]
stp xzr, xzr, [sp, #64]
stp xzr, xzr, [sp, #80]
stp xzr, xzr, [sp, #96]
stp xzr, xzr, [sp, #112]
stp xzr, xzr, [sp, #128]
stp xzr, xzr, [sp, #144]
stp xzr, xzr, [sp, #160]
stp xzr, xzr, [sp, #176]
stp xzr, xzr, [sp, #192]
stp xzr, xzr, [sp, #208]
stp xzr, xzr, [sp, #224]
stp xzr, xzr, [sp, #240]
stp xzr, xzr, [sp, #256]
stp xzr, xzr, [sp, #272]
stp xzr, xzr, [sp, #288]
stp xzr, xzr, [sp, #304]
stp xzr, xzr, [sp, #320]
stp xzr, xzr, [sp, #336]
stp xzr, xzr, [sp, #352]
stp xzr, xzr, [sp, #368]
stp xzr, xzr, [sp, #384]
stp xzr, xzr, [sp, #400]
stp xzr, xzr, [sp, #416]
stp xzr, xzr, [sp, #432]
stp xzr, xzr, [sp, #448]
stp xzr, xzr, [sp, #464]
stp xzr, xzr, [sp, #480]
stp xzr, xzr, [sp, #496]
cbz x1, 2f
dup v4.4s, w2
dup v5.4s, w3
movi v6.4s, #1
1:
ldr q0, [x0]
add v1.4s, v0.4s, v6.4s
ushr v1.4s, v1.4s, #1
and v2.16b, v0.16b, v6.16b
shl v2.4s, v2.4s, #1
sub v2.4s, v2.4s, v6.4s
cmhi v3.4s, v5.4s, v0.4s
mul v1.4s, v1.4s, v4.4s
mul v1.4s, v1.4s, v2.4s
and v1.16b, v1.16b, v3.16b
str q1, [x0], #16
subs x1, x1, #4
b.ne 1b
2:
mov x0, x4
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
movi v1.16b, #0
movi v2.16b, #0
movi v3.16b, #0
movi v4.16b, #0
movi v5.16b, #0
movi v6.16b, #0
movi v7.16b, #0
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
msr nzcv, xzr
add sp, sp, #512
ret
