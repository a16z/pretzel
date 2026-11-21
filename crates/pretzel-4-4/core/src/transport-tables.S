// Batch loop and routed dot product of the transport (hand-written), followed by
// `pretzel44_interval_coarse_keep_tables`, which is edited compiler output for the C function
// `pretzel44_interval_coarse_step` of `interval-transport.c`.
// See `../generators/README.md`, "Compiler output kept as source".
#define SYM(x) _##x
.text

.p2align 2
.globl SYM(pretzel44_interval_batch_impl)
SYM(pretzel44_interval_batch_impl):
sub sp,sp,#272
stp x19,x20,[sp,#48]
stp x21,x22,[sp,#64]
stp x23,x24,[sp,#80]
stp x25,x26,[sp,#96]
stp x27,x28,[sp,#112]
stp x29,x30,[sp,#128]
stp q8,q9,[sp,#144]
stp q10,q11,[sp,#176]
stp q12,q13,[sp,#208]
stp q14,q15,[sp,#240]
mov x19,x0
mov x20,#0
ldr x21,[x19]
ldp x22,x23,[x19,#56]
ldp x24,x25,[x19,#72]
ldp x26,x27,[x19,#88]
ldr x9,[x19,#32]
ld1 {v0.16b-v3.16b},[x9],#64
ld1 {v4.16b-v7.16b},[x9]
ldr x9,[x19,#40]
ld1 {v8.16b-v11.16b},[x9],#64
ld1 {v12.16b-v15.16b},[x9]
ldr x9,[x19,#48]
ld1 {v16.16b-v19.16b},[x9]
Lpretzel_table_batch_loop:
mov x0,x22
mov x1,x23
add x5,x20,#15
lsr x5,x5,#4
ldr x6,[x21]
and x6,x6,#255
mov x7,x21
bl SYM(pretzel44_ct_routed_dot_keep_tables)
mov x3,x0
add x0,sp,#16
ldr x1,[x19,#24]
mov x2,x26
ldr x9,[x19,#8]
ldr x4,[x9,x20,lsl #3]
add x5,x21,#8
mov x6,x24
mov x7,x25
ldr x9,[x21]
asr x9,x9,#63
str x9,[sp]
bl SYM(pretzel44_interval_coarse_keep_tables)
ldr x9,[sp,#32]
ldr x12,[sp]
and x9,x9,x12
orr x27,x27,x9
ldr x11,[x19,#16]
ldr x9,[x21,#8]
ldr x10,[x11,#0]
subs xzr,x9,x10
ldr x9,[x21,#16]
ldr x10,[x11,#8]
sbcs xzr,x9,x10
ldr x9,[x21,#24]
ldr x10,[x11,#16]
sbcs xzr,x9,x10
ldr x9,[x21,#32]
ldr x10,[x11,#24]
sbcs xzr,x9,x10
ldr x9,[x21,#40]
ldr x10,[x11,#32]
sbcs xzr,x9,x10
ldr x9,[x21,#48]
ldr x10,[x11,#40]
sbcs xzr,x9,x10
ldr x9,[x21,#56]
ldr x10,[x11,#48]
sbcs xzr,x9,x10
csetm x11,hs
bic x11,x11,x12
orr x27,x27,x11
ldp x9,x10,[sp,#16]
and x10,x10,#1
orr x9,x9,x10
bic x9,x9,x27
and x9,x9,x12
strb w9,[x23,x20]
ldrb w10,[x21]
strb w10,[x22,x20]
add x20,x20,#1
add x21,x21,#64
cmp x20,#128
b.ne Lpretzel_table_batch_loop
mov x0,x27
ldp q8,q9,[sp,#144]
ldp q10,q11,[sp,#176]
ldp q12,q13,[sp,#208]
ldp q14,q15,[sp,#240]
ldp x19,x20,[sp,#48]
ldp x21,x22,[sp,#64]
ldp x23,x24,[sp,#80]
ldp x25,x26,[sp,#96]
ldp x27,x28,[sp,#112]
ldp x29,x30,[sp,#128]
movi v0.16b,#0
movi v1.16b,#0
movi v2.16b,#0
movi v3.16b,#0
movi v4.16b,#0
movi v5.16b,#0
movi v6.16b,#0
movi v7.16b,#0
movi v16.16b,#0
movi v17.16b,#0
movi v18.16b,#0
movi v19.16b,#0
movi v20.16b,#0
movi v21.16b,#0
movi v22.16b,#0
movi v23.16b,#0
movi v24.16b,#0
movi v25.16b,#0
movi v26.16b,#0
movi v27.16b,#0
movi v28.16b,#0
movi v29.16b,#0
movi v30.16b,#0
movi v31.16b,#0
mov x9,sp
mov x10,#17
Lpretzel_table_batch_erase:
stp xzr,xzr,[x9],#16
subs x10,x10,#1
b.ne Lpretzel_table_batch_erase
add sp,sp,#272
ret
.p2align 2
.globl SYM(pretzel44_ct_routed_dot_keep_tables)
SYM(pretzel44_ct_routed_dot_keep_tables):
dup v20.16b, w6
movi v21.16b, #128
movi v22.16b, #64
movi v23.16b, #1
movi v24.16b, #0
movi v25.16b, #0
movi v26.16b, #0
cbz x5, 4f
2:
ld1 {v27.16b}, [x0], #16
uabd v27.16b, v20.16b, v27.16b
cmhi v28.16b, v27.16b, v21.16b
neg v29.16b, v27.16b
bit v27.16b, v29.16b, v28.16b
cmeq v29.16b, v27.16b, v21.16b
ld1 {v30.16b}, [x1], #16
eor v30.16b, v30.16b, v28.16b
sub v30.16b, v30.16b, v28.16b
bic v30.16b, v30.16b, v29.16b
tbl v31.16b, {v0.16b-v3.16b}, v27.16b
sub v29.16b, v27.16b, v22.16b
tbx v31.16b, {v4.16b-v7.16b}, v29.16b
tbl v28.16b, {v8.16b-v11.16b}, v27.16b
tbx v28.16b, {v12.16b-v15.16b}, v29.16b
ushr v29.16b, v27.16b, #1
tbl v29.16b, {v16.16b-v19.16b}, v29.16b
and v27.16b, v27.16b, v23.16b
shl v27.16b, v27.16b, #2
neg v27.16b, v27.16b
ushl v29.16b, v29.16b, v27.16b
shl v29.16b, v29.16b, #4
sshr v29.16b, v29.16b, #4
sdot v24.4s, v30.16b, v31.16b
ushr v31.16b, v31.16b, #7
sdot v25.4s, v30.16b, v31.16b
sdot v25.4s, v30.16b, v28.16b
ushr v28.16b, v28.16b, #7
sdot v26.4s, v30.16b, v28.16b
sdot v26.4s, v30.16b, v29.16b
subs w5, w5, #1
b.ne 2b
4:
shl v25.4s, v25.4s, #8
shl v26.4s, v26.4s, #16
add v24.4s, v24.4s, v25.4s
add v24.4s, v24.4s, v26.4s
addv s24, v24.4s
umov w9, v24.s[0]
ldr x8, [x7]
ubfx x8, x8, #16, #32
add w0, w9, w8
sxtw x0, w0
ret

.p2align 2
.globl _pretzel44_interval_coarse_keep_tables
_pretzel44_interval_coarse_keep_tables:
	.cfi_startproc
; %bb.0:
	stp	x22, x21, [sp, #-48]!           ; 16-byte Folded Spill
	stp	x20, x19, [sp, #16]             ; 16-byte Folded Spill
	stp	x29, x30, [sp, #32]             ; 16-byte Folded Spill
	.cfi_def_cfa_offset 48
	.cfi_offset w30, -8
	.cfi_offset w29, -16
	.cfi_offset w19, -24
	.cfi_offset w20, -32
	.cfi_offset w21, -40
	.cfi_offset w22, -48
	mov	x20, x3
	mov	x8, x2
	mov	x19, x0
	cmp	x3, #0
	cneg	x2, x3, mi
	neg	x9, x8
	cmp	x2, x8
	csel	x11, x8, x2, hi
	ldr	x10, [sp, #48]
	ccmp	x9, x3, #4, hs
	mul	x9, x11, x11
	lsl	x9, x9, #26
	mov	x14, #0x1c00000000000000
	sub	x9, x9, x14
	lsl	x9, x9, #1
	ldp	x11, x12, [x1, #40]
	mul	x14, x11, x9
	smulh	x11, x11, x9
	extr	x11, x11, x14, #62
	add	x11, x11, x12
	ldp	x12, x13, [x1, #56]
	mul	x14, x11, x9
	smulh	x11, x11, x9
	extr	x11, x11, x14, #62
	add	x11, x11, x12
	mul	x14, x11, x9
	smulh	x11, x11, x9
	extr	x11, x11, x14, #62
	add	x11, x11, x13
	ldp	x12, x13, [x1, #72]
	mul	x14, x11, x9
	smulh	x11, x11, x9
	extr	x11, x11, x14, #62
	add	x11, x11, x12
	mul	x14, x11, x9
	smulh	x11, x11, x9
	extr	x11, x11, x14, #62
	add	x11, x11, x13
	ldr	x12, [x1, #88]
	mul	x14, x11, x9
	smulh	x9, x11, x9
	extr	x9, x9, x14, #62
	add	x9, x9, x12
	csel	x9, x9, xzr, eq
	ldr	x11, [x5, #40]
	mov	w12, #76
	movk	w12, #1, lsl #16
	mul	x13, x11, x12
	umulh	x11, x11, x12
	extr	x11, x11, x13, #18
	mov	x12, #32
	movk	x12, #4096, lsl #16
	movk	x12, #49152, lsl #48
	add	x9, x9, x11
	add	x11, x9, x12
	mov	w12, #65
	movk	w12, #8192, lsl #16
	cmp	x11, x12
	cset	w11, lo
	and	x10, x11, x10
	fmov	d22, x20
	mov.d	v22[1], x4
	ldp	q23, q20, [x5]
	ldr	q21, [x5, #32]
	ldr	x11, [x7]
	cmp	x11, #0
	cset	w11, eq
	and	x11, x10, x11
	neg	x11, x11
	; InlineAsm Start
	; InlineAsm End
	dup.2d	v24, x11
	ldp	q25, q26, [x6]
	bit.16b	v25, v22, v24
	bit.16b	v26, v23, v24
	stp	q25, q26, [x6]
	ldp	q25, q26, [x6, #32]
	bit.16b	v25, v20, v24
	bsl.16b	v24, v21, v26
	stp	q25, q24, [x6, #32]
	ldr	x11, [x7]
	cmp	x11, #1
	cset	w11, eq
	and	x11, x10, x11
	neg	x11, x11
	; InlineAsm Start
	; InlineAsm End
	dup.2d	v24, x11
	ldp	q25, q26, [x6, #64]
	bit.16b	v25, v22, v24
	bit.16b	v26, v23, v24
	stp	q25, q26, [x6, #64]
	ldp	q25, q26, [x6, #96]
	bit.16b	v25, v20, v24
	bsl.16b	v24, v21, v26
	stp	q25, q24, [x6, #96]
	ldr	x11, [x7]
	cmp	x11, #2
	cset	w11, eq
	and	x11, x10, x11
	neg	x11, x11
	; InlineAsm Start
	; InlineAsm End
	dup.2d	v24, x11
	ldp	q25, q26, [x6, #128]
	bit.16b	v25, v22, v24
	bit.16b	v26, v23, v24
	stp	q25, q26, [x6, #128]
	ldp	q25, q26, [x6, #160]
	bit.16b	v25, v20, v24
	bsl.16b	v24, v21, v26
	stp	q25, q24, [x6, #160]
	ldr	x11, [x7]
	cmp	x11, #3
	cset	w11, eq
	and	x11, x10, x11
	neg	x11, x11
	; InlineAsm Start
	; InlineAsm End
	dup.2d	v24, x11
	ldp	q25, q26, [x6, #192]
	bit.16b	v25, v22, v24
	bit.16b	v26, v23, v24
	stp	q25, q26, [x6, #192]
	ldp	q25, q26, [x6, #224]
	bit.16b	v25, v20, v24
	bsl.16b	v24, v21, v26
	stp	q25, q24, [x6, #224]
	ldr	x11, [x7]
	cmp	x11, #4
	cset	w11, eq
	and	x11, x10, x11
	neg	x11, x11
	; InlineAsm Start
	; InlineAsm End
	dup.2d	v24, x11
	ldp	q25, q26, [x6, #256]
	bit.16b	v25, v22, v24
	bit.16b	v26, v23, v24
	stp	q25, q26, [x6, #256]
	ldp	q25, q26, [x6, #288]
	bit.16b	v25, v20, v24
	bsl.16b	v24, v21, v26
	stp	q25, q24, [x6, #288]
	ldr	x11, [x7]
	cmp	x11, #5
	cset	w11, eq
	and	x11, x10, x11
	neg	x11, x11
	; InlineAsm Start
	; InlineAsm End
	dup.2d	v24, x11
	ldp	q25, q26, [x6, #320]
	bif.16b	v22, v25, v24
	bif.16b	v23, v26, v24
	stp	q22, q23, [x6, #320]
	ldp	q22, q23, [x6, #352]
	bif.16b	v20, v22, v24
	bif.16b	v21, v23, v24
	stp	q20, q21, [x6, #352]
	mov	x11, #33
	movk	x11, #4096, lsl #16
	movk	x11, #16384, lsl #48
	cmp	x9, x11
	cset	w21, lt
	ldr	x9, [x7]
	add	x9, x9, x10
	str	x9, [x7]
	mov	x0, x4
	mov	x1, x8
	bl	_pretzel44_interval_union64
	mov	w8, #1
	sub	w8, w8, w0
	and	x8, x8, x21
	neg	x8, x8
	neg	x9, x0
	eor	x10, x8, x9
	and	x10, x10, x20, asr #63
	eor	x11, x10, x8
	eor	x10, x10, x9
	stp	x11, x10, [x19]
	orr	x8, x8, x9
	mvn	x8, x8
	str	x8, [x19, #16]
	ldp	x29, x30, [sp, #32]             ; 16-byte Folded Reload
	ldp	x20, x19, [sp, #16]             ; 16-byte Folded Reload
	ldp	x22, x21, [sp], #48             ; 16-byte Folded Reload
	ret
.cfi_endproc

