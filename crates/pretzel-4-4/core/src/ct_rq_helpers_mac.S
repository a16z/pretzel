	.section	__TEXT,__text,regular,pure_instructions
	.build_version macos, 15, 5	sdk_version 15, 5
	.section	__TEXT,__literal16,16byte_literals
	.p2align	4, 0x0                          ; -- Begin function pretzel44_rq_common
Lpretzel_rqhelper_mac_lCPI0_0:
	.long	1                               ; 0x1
	.long	2                               ; 0x2
	.long	3                               ; 0x3
	.long	4                               ; 0x4
Lpretzel_rqhelper_mac_lCPI0_1:
	.long	5                               ; 0x5
	.long	6                               ; 0x6
	.long	7                               ; 0x7
	.long	8                               ; 0x8
Lpretzel_rqhelper_mac_lCPI0_2:
	.long	9                               ; 0x9
	.long	10                              ; 0xa
	.long	11                              ; 0xb
	.long	12                              ; 0xc
Lpretzel_rqhelper_mac_lCPI0_3:
	.long	13                              ; 0xd
	.long	14                              ; 0xe
	.long	15                              ; 0xf
	.long	16                              ; 0x10
Lpretzel_rqhelper_mac_lCPI0_4:
	.byte	0                               ; 0x0
	.byte	1                               ; 0x1
	.byte	2                               ; 0x2
	.byte	3                               ; 0x3
	.byte	4                               ; 0x4
	.byte	5                               ; 0x5
	.byte	6                               ; 0x6
	.byte	7                               ; 0x7
	.byte	8                               ; 0x8
	.byte	9                               ; 0x9
	.byte	10                              ; 0xa
	.byte	11                              ; 0xb
	.byte	12                              ; 0xc
	.byte	13                              ; 0xd
	.byte	14                              ; 0xe
	.byte	15                              ; 0xf
Lpretzel_rqhelper_mac_lCPI0_5:
	.byte	192                             ; 0xc0
	.byte	193                             ; 0xc1
	.byte	194                             ; 0xc2
	.byte	195                             ; 0xc3
	.byte	196                             ; 0xc4
	.byte	197                             ; 0xc5
	.byte	198                             ; 0xc6
	.byte	199                             ; 0xc7
	.byte	200                             ; 0xc8
	.byte	201                             ; 0xc9
	.byte	202                             ; 0xca
	.byte	203                             ; 0xcb
	.byte	204                             ; 0xcc
	.byte	205                             ; 0xcd
	.byte	206                             ; 0xce
	.byte	207                             ; 0xcf
	.section	__TEXT,__literal8,8byte_literals
	.p2align	3, 0x0
Lpretzel_rqhelper_mac_lCPI0_6:
	.long	4294901761                      ; 0xffff0001
	.long	4294967280                      ; 0xfffffff0
	.section	__TEXT,__text,regular,pure_instructions
.if PRETZEL_NATIVE_SET == 33
	.globl	_pretzel33_rq_common
.else
	.globl	_pretzel44_rq_common
.endif
	.p2align	2
.if PRETZEL_NATIVE_SET == 33
_pretzel33_rq_common:                        ; @pretzel33_rq_common
.else
_pretzel44_rq_common:                        ; @pretzel44_rq_common
.endif
; %bb.0:
	sub	sp, sp, #400
	stp	d15, d14, [sp, #320]            ; 16-byte Folded Spill
	stp	d13, d12, [sp, #336]            ; 16-byte Folded Spill
	stp	d11, d10, [sp, #352]            ; 16-byte Folded Spill
	stp	d9, d8, [sp, #368]              ; 16-byte Folded Spill
	stp	x28, x27, [sp, #384]            ; 16-byte Folded Spill
                                        ; kill: def $w5 killed $w5 def $x5
	mov	x9, #0                          ; =0x0
	ldr	x8, [sp, #408]
	movi.2d	v0, #0000000000000000
	stp	q0, q0, [sp, #32]
	stp	q0, q0, [sp]
	lsl	w10, w5, #1
	add	w11, w10, #19
	dup.2d	v4, x11
	mov	w11, #2                         ; =0x2
	lsl	x11, x11, x5
	mov	w12, w5
	sub	x11, x11, #1
	add	w10, w10, #18
	dup.2d	v7, x10
	dup.2d	v0, x6
	dup.2d	v1, x7
	dup.2d	v2, x11
	dup.2d	v20, x12
	add	x10, sp, #400
	ld1r.2d	{ v3 }, [x10]
	neg.2d	v4, v4
	mov	w10, #1                         ; =0x1
	dup.2d	v5, x10
	mov	w10, #510                       ; =0x1fe
	dup.2d	v6, x10
	neg.2d	v7, v7
	movi.2d	v16, #0xffffffffffffffff
	mov	w10, #8192                      ; =0x2000
	dup.2d	v17, x10
	mov	w10, #20480                     ; =0x5000
	dup.2d	v18, x10
	mov	w10, #4095                      ; =0xfff
	dup.2d	v19, x10
	neg.2d	v20, v20
	movi.2d	v21, #0xffffffffff000000
	mov	w10, #16777216                  ; =0x1000000
	dup.2d	v22, x10
	add	x10, sp, #64
	mov	x11, x3
Lpretzel_rqhelper_mac_LBB0_1:                                 ; =>This Inner Loop Header: Depth=1
	add	x12, x4, x9
	ld2.2d	{ v23, v24 }, [x12]
	ushl.2d	v25, v24, v4
	ld4.2d	{ v26, v27, v28, v29 }, [x11], #64
	cmhi.2d	v30, v23, v26
	ushl.2d	v31, v24, v7
	add.2d	v8, v29, v29
	add.2d	v25, v25, v25
	and.16b	v25, v25, v6
	add.2d	v8, v8, v16
	add.2d	v25, v8, v25
	shl.2d	v31, v31, #13
	and.16b	v31, v31, v17
	orr.16b	v31, v31, v18
	orr.16b	v25, v31, v25
	cmhi.2d	v31, v29, v0
	bit.16b	v25, v1, v31
	cmeq.2d	v31, v29, #0
	bic.16b	v25, v25, v31
	bif.16b	v25, v24, v30
	ushr.2d	v31, v24, #15
	and.16b	v31, v31, v2
	bic.16b	v30, v31, v30
	and.16b	v31, v25, v19
	add.2d	v30, v28, v30
	ushl.2d	v30, v30, v20
	ushr.2d	v8, v25, #13
	eor.16b	v30, v8, v30
	ushr.2d	v25, v25, #12
	and.16b	v25, v25, v5
	and.16b	v25, v25, v30
	add.2d	v30, v25, v31
	cmeq.2d	v25, v26, #0
	cmeq.2d	v8, v26, v23
	orr.16b	v25, v25, v8
	cmeq.2d	v8, v23, v21
	add.2d	v23, v23, v22
	cmeq.2d	v23, v26, v23
	bic.16b	v23, v23, v8
	cmeq.2d	v24, v26, v3
	orr.16b	v24, v24, v25
	orr.16b	v31, v24, v23
	add	x12, x10, x9
	st2.2d	{ v30, v31 }, [x12]
	add	x9, x9, #32
	cmp	x9, #256
	b.ne	Lpretzel_rqhelper_mac_LBB0_1
; %bb.2:
	cbz	x8, Lpretzel_rqhelper_mac_LBB0_5
; %bb.3:
	add	x9, sp, #64
	add	x9, x9, #8
	mov	x10, sp
Lpretzel_rqhelper_mac_LBB0_4:                                 ; =>This Inner Loop Header: Depth=1
	ldr	w11, [x9]
	sbfx	w12, w11, #0, #1
	and	w11, w11, #0x1
	ldr	w13, [x2]
	add	w11, w11, w13
	and	w12, w12, w11
	str	w11, [x2]
	ldur	w11, [x9, #-8]
	orr	w11, w11, w12, lsl #12
	str	w11, [x1], #4
	str	w12, [x10], #4
	add	x9, x9, #16
	subs	x8, x8, #1
	b.ne	Lpretzel_rqhelper_mac_LBB0_4
Lpretzel_rqhelper_mac_LBB0_5:
	add	x8, x3, #384
	ld4.2d	{ v20, v21, v22, v23 }, [x8]
	add	x8, x3, #448
	ld4.2d	{ v24, v25, v26, v27 }, [x8]
	add	x8, x3, #256
	ld4.2d	{ v0, v1, v2, v3 }, [x8]
	add	x8, x3, #320
	ld4.2d	{ v28, v29, v30, v31 }, [x8]
	add	x8, x3, #128
	ld4.2d	{ v8, v9, v10, v11 }, [x8]
	sli.2d	v26, v27, #16
	add	x8, x3, #192
	ld4.2d	{ v12, v13, v14, v15 }, [x8]
	sli.2d	v22, v23, #16
	uzp1.4s	v7, v22, v26
	sli.2d	v30, v31, #16
	sli.2d	v2, v3, #16
	uzp1.4s	v6, v2, v30
	ld4.2d	{ v16, v17, v18, v19 }, [x3], #64
	mov.16b	v1, v28
	mov.16b	v2, v20
	sli.2d	v14, v15, #16
	sli.2d	v10, v11, #16
	uzp1.4s	v5, v10, v14
	mov.16b	v3, v24
	ld4.2d	{ v20, v21, v22, v23 }, [x3]
	sli.2d	v18, v19, #16
	sli.2d	v22, v23, #16
	uzp1.4s	v4, v18, v22
	mov.16b	v17, v20
	mov.16b	v18, v8
	mov.16b	v19, v12
	ldp	q23, q22, [sp, #32]
	ldp	q26, q24, [sp]
	movi.4s	v20, #1
	cmeq.4s	v21, v26, v20
Lpretzel_rqhelper_mac_Lloh0:
	adrp	x8, Lpretzel_rqhelper_mac_lCPI0_0@PAGE
Lpretzel_rqhelper_mac_Lloh1:
	ldr	q29, [x8, Lpretzel_rqhelper_mac_lCPI0_0@PAGEOFF]
	and.16b	v21, v21, v29
	cmeq.4s	v25, v24, v20
Lpretzel_rqhelper_mac_Lloh2:
	adrp	x8, Lpretzel_rqhelper_mac_lCPI0_1@PAGE
Lpretzel_rqhelper_mac_Lloh3:
	ldr	q27, [x8, Lpretzel_rqhelper_mac_lCPI0_1@PAGEOFF]
	and.16b	v30, v25, v27
	cmeq.4s	v25, v23, v20
Lpretzel_rqhelper_mac_Lloh4:
	adrp	x8, Lpretzel_rqhelper_mac_lCPI0_2@PAGE
Lpretzel_rqhelper_mac_Lloh5:
	ldr	q28, [x8, Lpretzel_rqhelper_mac_lCPI0_2@PAGEOFF]
	and.16b	v31, v25, v28
	cmeq.4s	v20, v22, v20
Lpretzel_rqhelper_mac_Lloh6:
	adrp	x8, Lpretzel_rqhelper_mac_lCPI0_3@PAGE
Lpretzel_rqhelper_mac_Lloh7:
	ldr	q25, [x8, Lpretzel_rqhelper_mac_lCPI0_3@PAGEOFF]
	and.16b	v20, v20, v25
	orr.16b	v21, v30, v21
	orr.16b	v20, v31, v20
	orr.16b	v20, v21, v20
	umaxv.4s	s20, v20
	fmov	w8, s20
	sub	w8, w8, #1
	lsl	w9, w8, #3
	dup.16b	v21, w9
Lpretzel_rqhelper_mac_Lloh8:
	adrp	x9, Lpretzel_rqhelper_mac_lCPI0_4@PAGE
Lpretzel_rqhelper_mac_Lloh9:
	ldr	q20, [x9, Lpretzel_rqhelper_mac_lCPI0_4@PAGEOFF]
	movi.4s	v30, #2
	cmeq.4s	v31, v26, v30
	and.16b	v31, v31, v29
	cmeq.4s	v8, v24, v30
	and.16b	v8, v8, v27
	orr.16b	v31, v8, v31
	cmeq.4s	v8, v23, v30
	and.16b	v8, v8, v28
	cmeq.4s	v30, v22, v30
	and.16b	v30, v30, v25
	orr.16b	v30, v8, v30
	orr.16b	v30, v31, v30
	umaxv.4s	s30, v30
	fmov	w9, s30
	movi.4s	v30, #3
	cmeq.4s	v31, v26, v30
	and.16b	v31, v31, v29
	cmeq.4s	v8, v24, v30
	and.16b	v8, v8, v27
	orr.16b	v31, v8, v31
	cmeq.4s	v8, v23, v30
	and.16b	v8, v8, v28
	cmeq.4s	v30, v22, v30
	and.16b	v30, v30, v25
	orr.16b	v30, v8, v30
	orr.16b	v30, v31, v30
	umaxv.4s	s30, v30
	fmov	w10, s30
	movi.4s	v30, #4
	cmeq.4s	v31, v26, v30
	and.16b	v31, v31, v29
	cmeq.4s	v8, v24, v30
	and.16b	v8, v8, v27
	orr.16b	v31, v8, v31
	cmeq.4s	v8, v23, v30
	and.16b	v8, v8, v28
	cmeq.4s	v30, v22, v30
	and.16b	v30, v30, v25
	orr.16b	v30, v8, v30
	orr.16b	v30, v31, v30
	umaxv.4s	s30, v30
	fmov	w11, s30
	movi.4s	v30, #5
	cmeq.4s	v31, v26, v30
	and.16b	v31, v31, v29
	cmeq.4s	v8, v24, v30
	and.16b	v8, v8, v27
	orr.16b	v31, v8, v31
	cmeq.4s	v8, v23, v30
	and.16b	v8, v8, v28
	cmeq.4s	v30, v22, v30
	and.16b	v30, v30, v25
	orr.16b	v8, v8, v30
	add.16b	v30, v21, v20
	tbl.16b	v30, { v16, v17, v18, v19 }, v30
	sub	w9, w9, #1
	lsl	w12, w9, #3
	orr.16b	v8, v31, v8
	dup.16b	v31, w12
	umaxv.4s	s8, v8
	fmov	w12, s8
	movi.4s	v8, #6
	cmeq.4s	v26, v26, v8
	and.16b	v29, v26, v29
	add.16b	v26, v31, v20
	tbl.16b	v26, { v16, v17, v18, v19 }, v26
	sub	w10, w10, #1
	lsl	w13, w10, #3
	cmeq.4s	v24, v24, v8
	and.16b	v24, v24, v27
	dup.16b	v27, w13
	cmeq.4s	v23, v23, v8
	and.16b	v28, v23, v28
	add.16b	v23, v27, v20
	tbl.16b	v23, { v16, v17, v18, v19 }, v23
	sub	w11, w11, #1
	lsl	w13, w11, #3
	cmeq.4s	v22, v22, v8
	dup.16b	v8, w13
	and.16b	v25, v22, v25
	add.16b	v22, v8, v20
	tbl.16b	v22, { v16, v17, v18, v19 }, v22
	sub	w12, w12, #1
	lsl	w13, w12, #3
	orr.16b	v24, v24, v29
	dup.16b	v29, w13
	orr.16b	v25, v28, v25
	orr.16b	v24, v24, v25
	umaxv.4s	s24, v24
	fmov	w13, s24
	sub	w13, w13, #1
	lsl	w14, w13, #3
	add.16b	v24, v29, v20
	tbl.16b	v24, { v16, v17, v18, v19 }, v24
	dup.16b	v25, w14
	add.16b	v28, v25, v20
	tbl.16b	v16, { v16, v17, v18, v19 }, v28
	lsl	w8, w8, #2
	dup.16b	v17, w8
	add.16b	v17, v17, v20
	tbl.16b	v28, { v4, v5, v6, v7 }, v17
	dup.2s	v17, v28[0]
	mov.h	v28[1], wzr
Lpretzel_rqhelper_mac_Lloh10:
	adrp	x8, Lpretzel_rqhelper_mac_lCPI0_6@PAGE
Lpretzel_rqhelper_mac_Lloh11:
	ldr	d18, [x8, Lpretzel_rqhelper_mac_lCPI0_6@PAGEOFF]
	ushl.2s	v17, v17, v18
	mov.s	v28[1], v17[1]
Lpretzel_rqhelper_mac_Lloh12:
	adrp	x8, Lpretzel_rqhelper_mac_lCPI0_5@PAGE
Lpretzel_rqhelper_mac_Lloh13:
	ldr	q19, [x8, Lpretzel_rqhelper_mac_lCPI0_5@PAGEOFF]
	lsl	w8, w9, #2
	lsl	w9, w10, #2
	lsl	w10, w11, #2
	lsl	w11, w12, #2
	lsl	w12, w13, #2
	add.16b	v17, v21, v19
	tbl.16b	v17, { v0, v1, v2, v3 }, v17
	add.16b	v21, v31, v19
	add.16b	v31, v27, v19
	add.16b	v8, v8, v19
	add.16b	v29, v29, v19
	add.16b	v9, v25, v19
	dup.16b	v19, w8
	add.16b	v10, v19, v20
	tbl.16b	v27, { v0, v1, v2, v3 }, v21
	tbl.16b	v25, { v0, v1, v2, v3 }, v31
	tbl.16b	v21, { v0, v1, v2, v3 }, v8
	tbl.16b	v19, { v0, v1, v2, v3 }, v29
	tbl.16b	v0, { v0, v1, v2, v3 }, v9
	dup.16b	v1, w9
	dup.16b	v2, w10
	add.16b	v1, v1, v20
	add.16b	v2, v2, v20
	dup.16b	v3, w11
	dup.16b	v29, w12
	add.16b	v3, v3, v20
	add.16b	v20, v29, v20
	tbl.16b	v29, { v4, v5, v6, v7 }, v10
	tbl.16b	v1, { v4, v5, v6, v7 }, v1
	tbl.16b	v2, { v4, v5, v6, v7 }, v2
	tbl.16b	v3, { v4, v5, v6, v7 }, v3
	tbl.16b	v4, { v4, v5, v6, v7 }, v20
	ldr	q5, [x0, #16]
	ushll.2d	v6, v28, #0
	orr.16b	v5, v5, v6
	dup.2s	v6, v29[0]
	str	q5, [x0, #16]
	mov.h	v29[1], wzr
	ushl.2s	v5, v6, v18
	mov.s	v29[1], v5[1]
	ldr	q5, [x0, #48]
	ushll.2d	v6, v29, #0
	orr.16b	v5, v5, v6
	str	q5, [x0, #48]
	dup.2s	v5, v1[0]
	mov.h	v1[1], wzr
	ushl.2s	v5, v5, v18
	mov.s	v1[1], v5[1]
	ldr	q5, [x0, #80]
	ushll.2d	v1, v1, #0
	orr.16b	v1, v5, v1
	dup.2s	v5, v2[0]
	mov.h	v2[1], wzr
	str	q1, [x0, #80]
	ushl.2s	v1, v5, v18
	mov.s	v2[1], v1[1]
	ldr	q1, [x0, #112]
	ushll.2d	v2, v2, #0
	orr.16b	v1, v1, v2
	str	q1, [x0, #112]
	dup.2s	v1, v3[0]
	mov.h	v3[1], wzr
	ushl.2s	v1, v1, v18
	mov.s	v3[1], v1[1]
	ldr	q1, [x0, #144]
	ushll.2d	v2, v3, #0
	orr.16b	v1, v1, v2
	str	q1, [x0, #144]
	dup.2s	v1, v4[0]
	ushl.2s	v1, v1, v18
	mov.h	v4[1], wzr
	mov.s	v4[1], v1[1]
	ldr	q1, [x0, #176]
	ushll.2d	v2, v4, #0
	orr.16b	v1, v1, v2
	str	q1, [x0, #176]
	orr.16b	v1, v17, v30
	fmov	x8, d1
	orr.16b	v1, v27, v26
	fmov	x9, d1
	orr.16b	v1, v25, v23
	fmov	x10, d1
	orr.16b	v1, v21, v22
	fmov	x11, d1
	orr.16b	v1, v19, v24
	fmov	x12, d1
	orr.16b	v0, v0, v16
	fmov	x13, d0
	ldr	x14, [x0]
	orr	x8, x14, x8
	str	x8, [x0]
	ldr	x8, [x0, #32]
	orr	x8, x8, x9
	str	x8, [x0, #32]
	ldr	x8, [x0, #64]
	orr	x8, x8, x10
	str	x8, [x0, #64]
	ldr	x8, [x0, #96]
	orr	x8, x8, x11
	str	x8, [x0, #96]
	ldr	x8, [x0, #128]
	orr	x8, x8, x12
	str	x8, [x0, #128]
	ldr	x8, [x0, #160]
	orr	x8, x8, x13
	str	x8, [x0, #160]
	movi v0.16b, #0
	movi v1.16b, #0
	movi v2.16b, #0
	movi v3.16b, #0
	movi v4.16b, #0
	movi v5.16b, #0
	movi v6.16b, #0
	movi v7.16b, #0
	movi v8.16b, #0
	movi v9.16b, #0
	movi v10.16b, #0
	movi v11.16b, #0
	movi v12.16b, #0
	movi v13.16b, #0
	movi v14.16b, #0
	movi v15.16b, #0
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
	mov x0, xzr
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
	ldp	x28, x27, [sp, #384]            ; 16-byte Folded Reload
	ldp	d9, d8, [sp, #368]              ; 16-byte Folded Reload
	ldp	d11, d10, [sp, #352]            ; 16-byte Folded Reload
	ldp	d13, d12, [sp, #336]            ; 16-byte Folded Reload
	ldp	d15, d14, [sp, #320]            ; 16-byte Folded Reload
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
	add sp, sp, #400
	msr nzcv, xzr
	ret
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh12, Lpretzel_rqhelper_mac_Lloh13
	.loh AdrpAdrp	Lpretzel_rqhelper_mac_Lloh10, Lpretzel_rqhelper_mac_Lloh12
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh10, Lpretzel_rqhelper_mac_Lloh11
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh8, Lpretzel_rqhelper_mac_Lloh9
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh6, Lpretzel_rqhelper_mac_Lloh7
	.loh AdrpAdrp	Lpretzel_rqhelper_mac_Lloh4, Lpretzel_rqhelper_mac_Lloh6
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh4, Lpretzel_rqhelper_mac_Lloh5
	.loh AdrpAdrp	Lpretzel_rqhelper_mac_Lloh2, Lpretzel_rqhelper_mac_Lloh4
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh2, Lpretzel_rqhelper_mac_Lloh3
	.loh AdrpAdrp	Lpretzel_rqhelper_mac_Lloh0, Lpretzel_rqhelper_mac_Lloh2
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh0, Lpretzel_rqhelper_mac_Lloh1
                                        ; -- End function
	.section	__TEXT,__literal8,8byte_literals
	.p2align	3, 0x0                          ; -- Begin function pretzel44_rq_resolve
Lpretzel_rqhelper_mac_lCPI1_0:
	.long	18                              ; 0x12
	.long	19                              ; 0x13
	.section	__TEXT,__literal16,16byte_literals
	.p2align	4, 0x0
Lpretzel_rqhelper_mac_lCPI1_1:
	.quad	13                              ; 0xd
	.quad	1                               ; 0x1
Lpretzel_rqhelper_mac_lCPI1_2:
	.quad	8192                            ; 0x2000
	.quad	510                             ; 0x1fe
	.section	__TEXT,__text,regular,pure_instructions
.if PRETZEL_NATIVE_SET == 33
	.globl	_pretzel33_rq_resolve
.else
	.globl	_pretzel44_rq_resolve
.endif
	.p2align	2
.if PRETZEL_NATIVE_SET == 33
_pretzel33_rq_resolve:                       ; @pretzel33_rq_resolve
.else
_pretzel44_rq_resolve:                       ; @pretzel44_rq_resolve
.endif
; %bb.0:
	stp	d15, d14, [sp, #-144]!          ; 16-byte Folded Spill
	stp	d13, d12, [sp, #16]             ; 16-byte Folded Spill
	stp	d11, d10, [sp, #32]             ; 16-byte Folded Spill
	stp	d9, d8, [sp, #48]               ; 16-byte Folded Spill
	stp	x28, x27, [sp, #64]             ; 16-byte Folded Spill
	stp	x26, x25, [sp, #80]             ; 16-byte Folded Spill
	stp	x24, x23, [sp, #96]             ; 16-byte Folded Spill
	stp	x22, x21, [sp, #112]            ; 16-byte Folded Spill
	stp	x20, x19, [sp, #128]            ; 16-byte Folded Spill
                                        ; kill: def $w5 killed $w5 def $x5
	ldr	x8, [sp, #144]
	lsl	w9, w5, #1
	dup.2s	v0, w9
Lpretzel_rqhelper_mac_Lloh14:
	adrp	x9, Lpretzel_rqhelper_mac_lCPI1_0@PAGE
Lpretzel_rqhelper_mac_Lloh15:
	ldr	d1, [x9, Lpretzel_rqhelper_mac_lCPI1_0@PAGEOFF]
	add.2s	v0, v0, v1
	ushll.2d	v1, v0, #0
	orr	x10, x7, #0x4000
	mov	w9, w5
	mov	w11, #2                         ; =0x2
	lsl	x11, x11, x5
	sub	x13, x11, #1
	add	w12, w5, #16
	mov	w14, #4                         ; =0x4
	lsl	x14, x14, x5
	sub	x14, x14, #1
	add	x17, x0, #256
	add	x5, x3, #256
	add	x15, x4, #256
	add	x16, x2, #512
	cmp	x15, x0
	ccmp	x17, x4, #0, hi
	cset	w15, hi
	cmp	x16, x0
	ccmp	x17, x2, #0, hi
	cset	w16, hi
	cmp	x17, x3
	ccmp	x5, x0, #0, hi
	b.hi	Lpretzel_rqhelper_mac_LBB1_5
; %bb.1:
	tbnz	w15, #0, Lpretzel_rqhelper_mac_LBB1_5
; %bb.2:
	cbnz	w16, Lpretzel_rqhelper_mac_LBB1_5
; %bb.3:
	mov	x15, #0                         ; =0x0
	dup.2d	v0, x6
	dup.2d	v7, v1[1]
	dup.2d	v17, v1[0]
	dup.2d	v1, x10
	dup.2d	v2, x13
	dup.2d	v21, x12
	dup.2d	v3, x14
	dup.2d	v4, x11
	dup.2d	v22, x9
	mov	w9, #1                          ; =0x1
	dup.2d	v5, x9
	mov	w9, #510                        ; =0x1fe
	dup.2d	v6, x9
	neg.2d	v7, v7
	movi.2d	v16, #0xffffffffffffffff
	neg.2d	v17, v17
	mov	w9, #8192                       ; =0x2000
	dup.2d	v18, x9
	mov	w9, #20480                      ; =0x5000
	dup.2d	v19, x9
	mov	w9, #4095                       ; =0xfff
	dup.2d	v20, x9
	neg.2d	v21, v21
	neg.2d	v22, v22
	mov	w9, #16384                      ; =0x4000
	dup.2d	v23, x9
	mov	x9, x2
Lpretzel_rqhelper_mac_LBB1_4:                                 ; =>This Inner Loop Header: Depth=1
	add	x10, x3, x15
	ld2.2d	{ v24, v25 }, [x10]
	add	x10, x4, x15
	ld2.2d	{ v26, v27 }, [x10]
	ld4.2d	{ v28, v29, v30, v31 }, [x9], #64
	cmhi.2d	v8, v24, v28
	cmeq.2d	v9, v28, v24
	cmhi.2d	v10, v26, v29
	cmeq.2d	v11, v29, v26
	cmhi.2d	v12, v27, v30
	and.16b	v11, v11, v12
	orr.16b	v10, v10, v11
	add.2d	v11, v31, v31
	ushl.2d	v13, v25, v7
	add.2d	v13, v13, v13
	and.16b	v9, v9, v10
	and.16b	v13, v13, v6
	add.2d	v11, v11, v16
	add.2d	v11, v11, v13
	ushl.2d	v13, v25, v17
	shl.2d	v13, v13, #13
	orr.16b	v8, v8, v9
	and.16b	v9, v13, v18
	orr.16b	v9, v9, v19
	orr.16b	v9, v9, v11
	cmhi.2d	v11, v31, v0
	bit.16b	v9, v1, v11
	xtn.2s	v11, v8
	cmeq.2d	v13, v31, #0
	ushr.2d	v14, v25, #15
	and.16b	v14, v14, v2
	bic.16b	v14, v14, v8
	sub.2d	v15, v30, v27
	bic.16b	v9, v9, v13
	sub.2d	v26, v26, v12
	and.16b	v27, v10, v5
	sub.2d	v10, v28, v24
	ushl.2d	v12, v25, v21
	and.16b	v12, v12, v3
	mov.16b	v24, v8
	bsl.16b	v24, v9, v25
	cmeq.2d	v25, v10, v27
	cmeq.2d	v26, v29, v26
	cmhi.2d	v27, v12, v15
	and.16b	v26, v27, v26
	and.16b	v25, v26, v25
	xtn.2s	v25, v25
	orr.16b	v26, v29, v28
	cmeq.2d	v26, v26, #0
	cmhi.2d	v27, v4, v30
	and.16b	v26, v26, v27
	add.2d	v27, v14, v30
	and.16b	v28, v24, v20
	ushl.2d	v27, v27, v22
	ushr.2d	v29, v24, #13
	eor.16b	v27, v27, v29
	ushr.2d	v29, v24, #12
	and.16b	v29, v29, v5
	and.16b	v27, v29, v27
	bic.8b	v25, v25, v11
	and.16b	v26, v26, v8
	xtn.2s	v26, v26
	orr.8b	v25, v26, v25
	cmtst.2d	v24, v24, v23
	add.2d	v26, v27, v28
	xtn.2s	v24, v24
	and.8b	v24, v24, v25
	ushll.2d	v24, v24, #0
	shl.2d	v24, v24, #63
	cmlt.2d	v27, v24, #0
	add	x10, x0, x15
	st2.2d	{ v26, v27 }, [x10]
	add	x15, x15, #32
	cmp	x15, #256
	b.ne	Lpretzel_rqhelper_mac_LBB1_4
	b	Lpretzel_rqhelper_mac_LBB1_7
Lpretzel_rqhelper_mac_LBB1_5:
	add	x15, x3, #8
	add	x16, x0, #8
	add	x17, x4, #8
	add	x0, x2, #16
	neg.2d	v0, v1
Lpretzel_rqhelper_mac_Lloh16:
	adrp	x3, Lpretzel_rqhelper_mac_lCPI1_1@PAGE
Lpretzel_rqhelper_mac_Lloh17:
	ldr	q1, [x3, Lpretzel_rqhelper_mac_lCPI1_1@PAGEOFF]
	mov	w3, #16                         ; =0x10
Lpretzel_rqhelper_mac_Lloh18:
	adrp	x4, Lpretzel_rqhelper_mac_lCPI1_2@PAGE
Lpretzel_rqhelper_mac_Lloh19:
	ldr	q2, [x4, Lpretzel_rqhelper_mac_lCPI1_2@PAGEOFF]
	mov	w4, #20480                      ; =0x5000
Lpretzel_rqhelper_mac_LBB1_6:                                 ; =>This Inner Loop Header: Depth=1
	ldp	x7, x19, [x17, #-8]
	ldp	x21, x20, [x0, #-16]
	cmp	x20, x7
	cset	w22, eq
	ldp	x5, x23, [x0], #32
	subs	x19, x5, x19
	csel	w22, wzr, w22, hs
	cinc	x24, x7, lo
	cmp	x20, x7
	ldp	x7, x25, [x15, #-8]
	dup.2d	v3, x25
	csinc	w22, w22, wzr, hs
	ushl.2d	v3, v3, v0
	ushl.2d	v3, v3, v1
	and.16b	v3, v3, v2
	mov.d	x26, v3[1]
	subs	x7, x21, x7
	csel	w27, wzr, w22, ne
	add	x26, x26, x23, lsl #1
	sub	x26, x26, #1
	fmov	x28, d3
	orr	x28, x28, x4
	csinc	w27, w27, wzr, hs
	orr	x26, x28, x26
	cmp	x23, x6
	csel	x26, x10, x26, hi
	lsr	x28, x25, x12
	cmp	x23, #0
	csel	x23, xzr, x26, eq
	and	x26, x28, x14
	cmp	x20, x24
	ccmp	x7, x22, #0, eq
	ccmp	x19, x26, #2, eq
	orr	x7, x20, x21
	cset	w19, lo
	cmp	x7, #0
	ccmp	x5, x11, #2, eq
	cset	w7, lo
	cmp	w27, #0
	csel	w7, w7, w19, ne
	csel	x19, x23, x25, ne
	and	x20, x13, x25, lsr #15
	csel	x20, xzr, x20, ne
	add	x5, x20, x5
	lsr	x5, x5, x9
	eor	w5, w5, w19, lsr #13
	and	x20, x19, #0xfff
	and	w5, w5, w19, lsr #12
	and	x5, x5, #0x1
	add	x5, x5, x20
	and	w7, w7, w19, lsr #14
	sbfx	x7, x7, #0, #1
	stp	x5, x7, [x16, #-8]
	add	x15, x15, #16
	add	x16, x16, #16
	add	x17, x17, #16
	subs	x3, x3, #1
	b.ne	Lpretzel_rqhelper_mac_LBB1_6
Lpretzel_rqhelper_mac_LBB1_7:
	ldp	x10, x9, [x8]
	ldp	x12, x11, [x2]
	cmp	x9, x11
	cset	w13, eq
	ldr	x14, [x8, #16]
	ldr	x15, [x2, #16]
	cmp	x14, x15
	csel	w13, wzr, w13, hs
	cmp	x9, x11
	csinc	w9, w13, wzr, hs
	cmp	x10, x12
	csel	w9, wzr, w9, ne
	csinc	w9, w9, wzr, hs
	str	x9, [x1]
	ldp	x10, x9, [x8]
	ldp	x12, x11, [x2, #32]
	cmp	x9, x11
	cset	w13, eq
	ldr	x14, [x8, #16]
	ldr	x15, [x2, #48]
	cmp	x14, x15
	csel	w13, wzr, w13, hs
	cmp	x9, x11
	csinc	w9, w13, wzr, hs
	cmp	x10, x12
	csel	w9, wzr, w9, ne
	csinc	w9, w9, wzr, hs
	str	x9, [x1, #8]
	ldp	x10, x9, [x8]
	ldp	x12, x11, [x2, #64]
	cmp	x9, x11
	cset	w13, eq
	ldr	x14, [x8, #16]
	ldr	x15, [x2, #80]
	cmp	x14, x15
	csel	w13, wzr, w13, hs
	cmp	x9, x11
	csinc	w9, w13, wzr, hs
	cmp	x10, x12
	csel	w9, wzr, w9, ne
	csinc	w9, w9, wzr, hs
	str	x9, [x1, #16]
	ldp	x10, x9, [x8]
	ldp	x12, x11, [x2, #96]
	cmp	x9, x11
	cset	w13, eq
	ldr	x14, [x8, #16]
	ldr	x15, [x2, #112]
	cmp	x14, x15
	csel	w13, wzr, w13, hs
	cmp	x9, x11
	csinc	w9, w13, wzr, hs
	cmp	x10, x12
	csel	w9, wzr, w9, ne
	csinc	w9, w9, wzr, hs
	str	x9, [x1, #24]
	ldp	x10, x9, [x8]
	ldp	x12, x11, [x2, #128]
	cmp	x9, x11
	cset	w13, eq
	ldr	x14, [x8, #16]
	ldr	x15, [x2, #144]
	cmp	x14, x15
	csel	w13, wzr, w13, hs
	cmp	x9, x11
	csinc	w9, w13, wzr, hs
	cmp	x10, x12
	csel	w9, wzr, w9, ne
	csinc	w9, w9, wzr, hs
	str	x9, [x1, #32]
	ldp	x10, x9, [x8]
	ldp	x12, x11, [x2, #160]
	cmp	x9, x11
	cset	w13, eq
	ldr	x8, [x8, #16]
	ldr	x14, [x2, #176]
	cmp	x8, x14
	csel	w8, wzr, w13, hs
	cmp	x9, x11
	csinc	w8, w8, wzr, hs
	cmp	x10, x12
	csel	w8, wzr, w8, ne
	csinc	w8, w8, wzr, hs
	str	x8, [x1, #40]
	movi v0.16b, #0
	movi v1.16b, #0
	movi v2.16b, #0
	movi v3.16b, #0
	movi v4.16b, #0
	movi v5.16b, #0
	movi v6.16b, #0
	movi v7.16b, #0
	movi v8.16b, #0
	movi v9.16b, #0
	movi v10.16b, #0
	movi v11.16b, #0
	movi v12.16b, #0
	movi v13.16b, #0
	movi v14.16b, #0
	movi v15.16b, #0
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
	mov x0, xzr
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
	ldp	x20, x19, [sp, #128]            ; 16-byte Folded Reload
	ldp	x22, x21, [sp, #112]            ; 16-byte Folded Reload
	ldp	x24, x23, [sp, #96]             ; 16-byte Folded Reload
	ldp	x26, x25, [sp, #80]             ; 16-byte Folded Reload
	ldp	x28, x27, [sp, #64]             ; 16-byte Folded Reload
	ldp	d9, d8, [sp, #48]               ; 16-byte Folded Reload
	ldp	d11, d10, [sp, #32]             ; 16-byte Folded Reload
	ldp	d13, d12, [sp, #16]             ; 16-byte Folded Reload
	ldp d15, d14, [sp]
	stp xzr, xzr, [sp, #0]
	stp xzr, xzr, [sp, #16]
	stp xzr, xzr, [sp, #32]
	stp xzr, xzr, [sp, #48]
	stp xzr, xzr, [sp, #64]
	stp xzr, xzr, [sp, #80]
	stp xzr, xzr, [sp, #96]
	stp xzr, xzr, [sp, #112]
	stp xzr, xzr, [sp, #128]
	add sp, sp, #144
	msr nzcv, xzr
	ret
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh14, Lpretzel_rqhelper_mac_Lloh15
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh18, Lpretzel_rqhelper_mac_Lloh19
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh16, Lpretzel_rqhelper_mac_Lloh17
                                        ; -- End function
	.section	__TEXT,__literal16,16byte_literals
	.p2align	4, 0x0                          ; -- Begin function pretzel44_rq_repair
Lpretzel_rqhelper_mac_lCPI2_0:
	.long	0                               ; 0x0
	.long	65536                           ; 0x10000
	.long	131072                          ; 0x20000
	.long	196608                          ; 0x30000
Lpretzel_rqhelper_mac_lCPI2_1:
	.long	0                               ; 0x0
	.long	1                               ; 0x1
	.long	2                               ; 0x2
	.long	3                               ; 0x3
	.section	__TEXT,__text,regular,pure_instructions
.if PRETZEL_NATIVE_SET == 33
	.globl	_pretzel33_rq_repair
.else
	.globl	_pretzel44_rq_repair
.endif
	.p2align	2
.if PRETZEL_NATIVE_SET == 33
_pretzel33_rq_repair:                        ; @pretzel33_rq_repair
.else
_pretzel44_rq_repair:                        ; @pretzel44_rq_repair
.endif
; %bb.0:
	movi.2d	v0, #0000000000000000
	add	w8, w4, #9
	ands	x8, x8, #0xfffffffc
	b.eq	Lpretzel_rqhelper_mac_LBB2_3
; %bb.1:
	mov	w9, #0                          ; =0x0
	mov	x10, #0                         ; =0x0
	add	x11, x2, #16
	add	x12, x2, #24
	add	x13, x2, #32
	add	x14, x2, #40
	ldr	s1, [x2, #8]
	ld1.s	{ v1 }[1], [x12]
	add	x12, x2, #48
	ld1.s	{ v1 }[2], [x14]
	add	x14, x2, #56
	ld1.s	{ v1 }[3], [x14]
	shl.4s	v1, v1, #12
	movi.4s	v2, #16, lsl #8
	ldr	s3, [x2]
	ld1.s	{ v3 }[1], [x11]
	ld1.s	{ v3 }[2], [x13]
	ld1.s	{ v3 }[3], [x12]
	and.16b	v1, v1, v2
	ldp	q4, q2, [x3]
	uzp1.4s	v2, v4, v2
	shl.4s	v2, v2, #13
	orr.16b	v2, v3, v2
	orr.16b	v1, v1, v2
	ldr	w11, [x2, #64]
	ldr	w12, [x2, #72]
	ubfiz	w12, w12, #12, #1
	orr	w11, w12, w11
	ldr	w12, [x3, #32]
	orr	w11, w11, w12, lsl #13
	ldr	w12, [x2, #80]
	ldr	w13, [x2, #88]
	ubfiz	w13, w13, #12, #1
	orr	w12, w13, w12
	ldr	w13, [x3, #40]
	orr	w12, w12, w13, lsl #13
	movi.2d	v2, #0000000000000000
	mov.s	v2[0], w11
	mov.s	v2[1], w12
	movi.4s	v3, #5
	movi.16b	v4, #4
	mov	w11, #256                       ; =0x100
	movk	w11, #770, lsl #16
	dup.4s	v5, w11
	movi.4s	v6, #15, msl #8
	movi.4s	v7, #1
	movi.4s	v16, #31, msl #8
Lpretzel_rqhelper_mac_Lloh20:
	adrp	x11, Lpretzel_rqhelper_mac_lCPI2_0@PAGE
Lpretzel_rqhelper_mac_Lloh21:
	ldr	q17, [x11, Lpretzel_rqhelper_mac_lCPI2_0@PAGEOFF]
	mov	x11, x1
Lpretzel_rqhelper_mac_LBB2_2:                                 ; =>This Inner Loop Header: Depth=1
	ldr	q18, [x11]
	movi.2d	v19, #0xffffffffffffffff
	usra.4s	v19, v18, #12
	cmhi.4s	v20, v19, v3
	mov.16b	v21, v5
	mla.4s	v21, v19, v4
	orr.16b	v19, v21, v20
	tbl.16b	v19, { v1, v2 }, v19
	cmhi.4s	v20, v18, v6
	bic.16b	v18, v18, v20
	and.16b	v19, v19, v20
	and.16b	v18, v18, v6
	orr.16b	v18, v19, v18
	ushr.4s	v19, v18, #13
	and.16b	v19, v19, v7
	ext.16b	v20, v0, v19, #12
	add.4s	v20, v20, v19
	ext.16b	v21, v0, v20, #8
	add.4s	v20, v21, v20
	sub	w12, w10, w9
	dup.4s	v21, w12
	add.4s	v21, v21, v19
	sub.4s	v21, v21, v20
	mov.s	w12, v20[3]
	shl.4s	v20, v21, #16
	add	w9, w12, w9
	and.16b	v18, v18, v16
	orr.16b	v18, v20, v18
	add.4s	v18, v18, v17
	orr.4s	v18, #128, lsl #24
	cmeq.4s	v19, v19, #0
	and.16b	v18, v18, v19
	str	q18, [x11], #16
	add	x10, x10, #4
	cmp	x10, x8
	b.lo	Lpretzel_rqhelper_mac_LBB2_2
Lpretzel_rqhelper_mac_LBB2_3:
	cbz	x4, Lpretzel_rqhelper_mac_LBB2_6
; %bb.4:
	mov	x8, #0                          ; =0x0
	mov	w9, #4095                       ; =0xfff
	cmp	w5, #7
	csel	w9, w9, wzr, lo
	dup.4s	v1, w9
	add	x9, x1, #12
	movi.2d	v0, #0000000000000000
Lpretzel_rqhelper_mac_Lloh22:
	adrp	x10, Lpretzel_rqhelper_mac_lCPI2_1@PAGE
Lpretzel_rqhelper_mac_Lloh23:
	ldr	q2, [x10, Lpretzel_rqhelper_mac_lCPI2_1@PAGEOFF]
	movi.4s	v3, #1
Lpretzel_rqhelper_mac_LBB2_5:                                 ; =>This Inner Loop Header: Depth=1
	add	w10, w8, #8, lsl #12            ; =32768
	dup.4s	v4, w10
	orr.16b	v4, v4, v2
	ldur	q5, [x9, #-12]
	ushr.4s	v6, v5, #16
	cmeq.4s	v6, v6, v4
	and.16b	v5, v5, v6
	ldur	q6, [x9, #-8]
	ushr.4s	v7, v6, #16
	cmeq.4s	v7, v7, v4
	and.16b	v6, v6, v7
	orr.16b	v5, v6, v5
	ldur	q6, [x9, #-4]
	ushr.4s	v7, v6, #16
	cmeq.4s	v7, v7, v4
	and.16b	v6, v6, v7
	ldr	q7, [x9]
	ushr.4s	v16, v7, #16
	cmeq.4s	v16, v16, v4
	and.16b	v7, v7, v16
	orr.16b	v6, v7, v6
	orr.16b	v5, v6, v5
	ldur	q6, [x9, #4]
	ushr.4s	v7, v6, #16
	cmeq.4s	v7, v7, v4
	and.16b	v6, v6, v7
	ldur	q7, [x9, #8]
	ushr.4s	v16, v7, #16
	cmeq.4s	v16, v16, v4
	and.16b	v7, v7, v16
	orr.16b	v6, v7, v6
	ldur	q7, [x9, #12]
	ushr.4s	v16, v7, #16
	cmeq.4s	v4, v16, v4
	and.16b	v4, v7, v4
	orr.16b	v4, v4, v6
	orr.16b	v4, v4, v5
	ushr.4s	v5, v4, #12
	and.16b	v5, v5, v3
	orr.16b	v0, v5, v0
	and.16b	v4, v4, v1
	str	q4, [x0], #16
	add	x8, x8, #4
	add	x9, x9, #16
	cmp	x8, x4
	b.lo	Lpretzel_rqhelper_mac_LBB2_5
Lpretzel_rqhelper_mac_LBB2_6:
	cmp	w5, #6
	umaxv.4s	s0, v0
	fmov	w8, s0
	ccmp	w8, #0, #0, ls
	cset	w8, ne
	sbfx x0, x8, #0, #1
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
	msr nzcv, xzr
	ret
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh20, Lpretzel_rqhelper_mac_Lloh21
	.loh AdrpLdr	Lpretzel_rqhelper_mac_Lloh22, Lpretzel_rqhelper_mac_Lloh23
                                        ; -- End function
.subsections_via_symbols
