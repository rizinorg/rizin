// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>

static ut64 pic18_regadr(Pic18ILContext *ctx, const char *v) {
	bool f = false;
	ut64 adr = ht_su_find((HtSU *)ctx->mm, v, &f);
	if (f) {
		return adr;
	}
	rz_warn_if_reached();
	return UT64_MAX;
}

static RzILOpPure *varg_mm(Pic18ILContext *ctx, const char *v);
static RzILOpEffect *setg_mm(Pic18ILContext *ctx, const char *v, RzILOpPure *x);

static RzILOpPure *varg_mm_uhl(Pic18ILContext *ctx, const char *u, const char *h, const char *l) {
	return APPEND(varg_mm(ctx, u), APPEND(varg_mm(ctx, h), varg_mm(ctx, l)));
}
static RzILOpEffect *setg_mm_uhl(Pic18ILContext *ctx, const char *u, const char *h, const char *l, RzILOpPure *x) {
	return SEQ4(
		SETL("__x", x),
		setg_mm(ctx, u, UNSIGNED(8, SHIFTR0(VARL("__x"), U8(16)))),
		setg_mm(ctx, h, UNSIGNED(8, SHIFTR0(VARL("__x"), U8(8)))),
		setg_mm(ctx, l, UNSIGNED(8, VARL("__x"))));
}
static RzILOpPure *varg_mm_hl(Pic18ILContext *ctx, const char *v) {
	char h[8];
	char l[8];
	rz_strf(h, "%sh", v);
	rz_strf(l, "%sl", v);
	return APPEND(varg_mm(ctx, h), varg_mm(ctx, l));
}
static RzILOpEffect *setg_mm_hl(Pic18ILContext *ctx, const char *v, RzILOpPure *x) {
	char h[8];
	char l[8];
	rz_strf(h, "%sh", v);
	rz_strf(l, "%sl", v);
	return SEQ3(
		SETL("__x", x),
		setg_mm(ctx, h, UNSIGNED(8, SHIFTR0(VARL("__x"), U8(8)))),
		setg_mm(ctx, l, UNSIGNED(8, VARL("__x"))));
}

/**
 * \see https://ww1.microchip.com/downloads/en/DeviceDoc/39500a.pdf
 * 7.7.6 Indirect Addressing, INDF, and FSR Registers
 * Each FSR register has an INDF register plus four addresses associated with it. The same INDFn,
 * and FSRnH:FSRnL registers are used, but depending on the INDFn address selected, the
 * FSRnH:FSRnL registers may be modified.
 * When a data access is done to the one of the five INDFn locations, the address selected will configure the FSRn register to:
 *   • Do nothing to FSRn after an indirect access (no change) - INDFn
 *   • Auto-decrement FSRn after an indirect access (post-decrement) - POSTDECn
 *   • Auto-increment FSRn after an indirect access (post-increment) - POSTINCn
 *   • Auto-increment FSRn before an indirect access (pre-increment) - PREINCn
 *   • Use the value in the WREG register as an offset to FSRn. Do not modify the value of the
 *     WREG or the FSRn register after an indirect access (no change) - PLUSWn
 */
static RzILOpPure *varg_mm(Pic18ILContext *ctx, const char *v) {
	if (RZ_STR_ISEMPTY(v)) {
		return NULL;
	}
	if (rz_str_startswith(v, "indf")) {
		char fsr[8];
		long n = strtol(v + 4, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		return LOAD(UNSIGNED(24, varg_mm(ctx, fsr)));
	}
	if (rz_str_startswith(v, "postdec")) {
		char fsr[8];
		long n = strtol(v + 7, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		rz_warn_if_fail(ctx->eff.tag == ILOpEff_None);
		ctx->eff.tag = ILOpEff_PostDec;
		strcat(ctx->eff.fsr, fsr);
		return LOAD(UNSIGNED(24, varg_mm(ctx, fsr)));
	}
	if (rz_str_startswith(v, "postinc")) {
		char fsr[8];
		long n = strtol(v + 7, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		rz_warn_if_fail(ctx->eff.tag == ILOpEff_None);
		ctx->eff.tag = ILOpEff_PostInc;
		strcat(ctx->eff.fsr, fsr);
		return LOAD(UNSIGNED(24, varg_mm(ctx, fsr)));
	}
	if (rz_str_startswith(v, "predec")) {
		char fsr[8];
		long n = strtol(v + 6, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		rz_warn_if_fail(ctx->eff.tag == ILOpEff_None);
		ctx->eff.tag = ILOpEff_PreInc;
		strcat(ctx->eff.fsr, fsr);
		return LOAD(UNSIGNED(24, varg_mm(ctx, fsr)));
	}
	if (rz_str_startswith(v, "plusw")) {
		char fsr[8];
		long n = strtol(v + 5, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		return LOAD(UNSIGNED(24, ADD(varg_mm(ctx, fsr), UNSIGNED(16, varg_mm(ctx, "wreg")))));
	}

	bool f = false;
	ut64 adr = ht_su_find((HtSU *)ctx->mm, v, &f);
	if (f) {
		return LOAD(UN(24, adr));
	}
	ut8 b = pic18_status(v);
	if (b != 0xff) {
		return bit_get(varg_mm(ctx, "status"), b);
	}
	if (RZ_STR_EQ(v, "tblptr")) {
		return varg_mm_uhl(ctx, "tblptru", "tblptrh", "tblptrl");
	}
	if (RZ_STR_EQ(v, "tos")) {
		return varg_mm_uhl(ctx, "tosu", "tosh", "tosl");
	}
	if (rz_str_startswith(v, "fsr")) {
		return varg_mm_hl(ctx, v);
	}
	return VARG(v);
}

static RzILOpEffect *setg_mm(Pic18ILContext *ctx, const char *v, RzILOpPure *x) {
	if (RZ_STR_ISEMPTY(v)) {
		return NULL;
	}
	if (rz_str_startswith(v, "indf")) {
		char fsr[8];
		long n = strtol(v + 4, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		return STORE(UNSIGNED(24, varg_mm(ctx, fsr)), x);
	}
	if (rz_str_startswith(v, "postdec")) {
		char fsr[8];
		long n = strtol(v + 7, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		rz_warn_if_fail(ctx->eff.tag == ILOpEff_None);
		ctx->eff.tag = ILOpEff_PostDec;
		strcat(ctx->eff.fsr, fsr);
		return STORE(UNSIGNED(24, varg_mm(ctx, fsr)), x);
	}
	if (rz_str_startswith(v, "postinc")) {
		char fsr[8];
		long n = strtol(v + 7, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		rz_warn_if_fail(ctx->eff.tag == ILOpEff_None);
		ctx->eff.tag = ILOpEff_PostInc;
		strcat(ctx->eff.fsr, fsr);
		return STORE(UNSIGNED(24, varg_mm(ctx, fsr)), x);
	}
	if (rz_str_startswith(v, "predec")) {
		char fsr[8];
		long n = strtol(v + 6, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		rz_warn_if_fail(ctx->eff.tag == ILOpEff_None);
		ctx->eff.tag = ILOpEff_PreInc;
		strcat(ctx->eff.fsr, fsr);
		return STORE(UNSIGNED(24, varg_mm(ctx, fsr)), x);
	}
	if (rz_str_startswith(v, "plusw")) {
		char fsr[8];
		long n = strtol(v + 5, NULL, 0);
		rz_strf(fsr, "fsr%ld", n);
		return STORE(UNSIGNED(24, ADD(varg_mm(ctx, fsr), UNSIGNED(16, varg_mm(ctx, "wreg")))), x);
	}
	bool f = false;
	ut64 adr = ht_su_find((HtSU *)ctx->mm, v, &f);
	if (f) {
		return STORE(UN(24, adr), x);
	}
	ut8 b = pic18_status(v);
	if (b != 0xff) {
		return setg_mm(ctx, "status", bit_set1(varg_mm(ctx, "status"), b, x));
	}
	if (RZ_STR_EQ(v, "tblptr")) {
		return setg_mm_uhl(ctx, "tblptru", "tblptrh", "tblptrl", x);
	}
	if (RZ_STR_EQ(v, "tos")) {
		return setg_mm_uhl(ctx, "tosu", "tosh", "tosl", x);
	}
	if (rz_str_startswith(v, "fsr")) {
		return setg_mm_hl(ctx, v, x);
	}
	return SETG(v, x);
}

#undef VARG
#undef SETG
#define VARG(x)    varg_mm(ctx, x)
#define SETG(v, x) setg_mm(ctx, v, x)

#define K  (ctx->op->k)
#define D  (ctx->op->d)
#define F  (ctx->op->f)
#define B  (ctx->op->b)
#define N  (ctx->op->n)
#define PC (ctx->op->addr)

#define RW   "wreg"
#define VRW  (VARG(RW))
#define RF   pic18_regname(F)
#define VRF  (VARG(pic18_regname(F)))
#define RWF  (D ? pic18_regname(F) : RW)
#define VRWF (VARG(RWF))

#define VPC  (UN(24, PC))
#define RC   "c"
#define VRC  VARG(RC)
#define RN   "n"
#define VRN  VARG(RN)
#define ROV  "ov"
#define VROV VARG(ROV)
#define RZ   "z"
#define VRZ  VARG(RZ)
#define RS   "s"
#define VRS  VARG(RS)

/**
 * The `d` bit selects the destination for the operation.
 * If `d` is 1; the result is stored back in the File Register `f`.
 * If `d` is 0; the result is stored in the WREG Register.
 *
 * The `a` bit selects which bank is accessed for the operation.
 * If `a` is 1; the bank specified by the BSR Register is used.
 * If `a` is 0; the access bank is used.
 */
static RzILOpEffect *set_dest(Pic18ILContext *ctx, RzILOpPure *x) {
	const char *fsr = ctx->op->d ? pic18_regname(F) : RW;
	if (ctx->op->a) {
		ut64 adr = pic18_regadr(ctx, fsr);
		if (adr != UT64_MAX) {
			return STORE(
				ADD(MUL(UNSIGNED(24, LOGAND(VARG("bsr"), U8(0x0f))), UN(24, 0x100)), UN(24, adr)),
				x);
		}
		return NULL;
	}
	return SETG(fsr, x);
}

/**
 * bit 4: N: Negative bit
 * This bit is used for signed arithmetic (2’s complement). It indicates whether the result was negative, (ALU MSb = 1).
 * 1 = Result was negative
 * 0 = Result was positive
 *
 * bit 3: OV: Overflow bit
 * This bit is used for signed arithmetic (2’s complement). It indicates an overflow of the 7-bit magnitude, which causes the sign bit (bit7) to change state.
 * 1 = Overflow occurred for signed arithmetic (in this arithmetic operation)
 * 0 = No overflow occurred
 *
 * bit 2: Z: Zero bit
 * 1 = The result of an arithmetic or logic operation is zero
 * 0 = The result of an arithmetic or logic operation is not zero
 *
 * bit 1: DC: Digit carry/borrow bit
 * For ADDWF, ADDLW, SUBLW, and SUBWF instructions
 * 1 = A carry-out from the 4th low order bit of the result occurred
 * 0 = No carry-out from the 4th low order bit of the result
 * Note: For borrow, the polarity is reversed. A subtraction is executed by adding the 2’s complement of the second operand. For rotate (RRF, RLF) instructions, this bit is loaded
 * with either the bit4 or bit3 of the source register.
 *
 * bit 0: C: Carry/borrow bit
 * For ADDWF, ADDLW, SUBLW, and SUBWF instructions
 * 1 = A carry-out from the most significant bit of the result occurred
 * 0 = No carry-out from the most significant bit of the result occurred
 * Note: For borrow, the polarity is reversed. A subtraction is executed by adding the 2’s complement of the second operand. For rotate (RRF, RLF) instructions, this bit is loaded
 * with either the high or low order bit of the source register.
 */

static RzILOpEffect *status_add(Pic18ILContext *ctx, RzILOpPure *a, RzILOpPure *b, RzILOpPure *res, RzILOpPure *curry) {
	return SEQ5(
		SETG("c", CHECK_CARRY(a, b, res)),
		SETG("dc", CHECK_DIGIT_CARRY(DUP(a), DUP(b), DUP(res))),
		SETG("z", IS_ZERO(DUP(res))),
		SETG("ov", CHECK_OVERFLOW(DUP(a), DUP(b), DUP(res))),
		SETG("n", MSB(DUP(res))));
}

static RzILOpEffect *status_sub(Pic18ILContext *ctx, RzILOpPure *a, RzILOpPure *b, RzILOpPure *res, RzILOpPure *curry) {
	return SEQ5(
		SETG("c", CHECK_BORROW(a, b, res)),
		SETG("dc", CHECK_DIGIT_BORROW(DUP(a), DUP(b), DUP(res))),
		SETG("z", IS_ZERO(DUP(res))),
		SETG("ov", CHECK_OVERFLOW(DUP(a), DUP(b), DUP(res))),
		SETG("n", MSB(DUP(res))));
}

static RzILOpEffect *status_res(Pic18ILContext *ctx, RzILOpPure *res) {
	return SEQ2(
		SETG("z", IS_ZERO(res)),
		SETG("n", MSB(DUP(res))));
}

static RzILOpEffect *set_dest_status(Pic18ILContext *ctx, RzILOpPure *x) {
	return SEQ3(
		SETL("__res", x),
		status_res(ctx, VARL("__res")),
		set_dest(ctx, VARL("__res")));
}

static RzILOpPure *complement_1(RzILOpPure *x) {
	return NEG(x);
}

static RzILOpPure *complement_2(RzILOpPure *x) {
	return ADD(U8(1), NEG(x));
}

static RzILOpPure *decimal_adjust(Pic18ILContext *ctx, RzILOpPure *x) {
	return LET(
		"_x03", UNSIGNED(4, x),
		LET(
			"_x47", UNSIGNED(4, SHIFTR0(DUP(x), U8(4))),
			APPEND(
				ITE(OR(UGT(VARL("_x47"), UN(4, 9)), VARG("c")),
					ADD(VARL("_x47"), UN(4, 6)),
					VARL("_x47")),
				ITE(OR(UGT(VARL("_x03"), UN(4, 9)), VARG("dc")),
					ADD(VARL("_x03"), UN(4, 6)),
					VARL("_x03")))));
}

static RzILOpEffect *op_add(Pic18ILContext *ctx, const char *dst,
	RzILOpPure *a, RzILOpPure *b, RzILOpPure *curry) {
	if (dst) {
		return SEQ3(
			SETL("__res", ADD(a, curry ? ADD(b, curry) : b)),
			status_add(ctx, DUP(a), DUP(b), VARL("__res"), curry ? DUP(curry) : NULL),
			SETG(dst, VARL("__res")));
	}
	return SEQ3(
		SETL("__res", ADD(a, curry ? ADD(b, curry) : b)),
		status_add(ctx, DUP(a), DUP(b), VARL("__res"), curry ? DUP(curry) : NULL),
		set_dest(ctx, VARL("__res")));
}

static RzILOpEffect *op_sub(Pic18ILContext *ctx, const char *dst,
	RzILOpPure *a, RzILOpPure *b, RzILOpPure *curry) {
	if (dst) {
		return SEQ3(
			SETL("__res", SUB(a, curry ? ADD(b, curry) : b)),
			status_sub(ctx, DUP(a), DUP(b), VARL("__res"), curry ? DUP(curry) : NULL),
			SETG(dst, VARL("__res")));
	}
	return SEQ3(
		SETL("__res", SUB(a, curry ? ADD(b, curry) : b)),
		status_sub(ctx, DUP(a), DUP(b), VARL("__res"), curry ? DUP(curry) : NULL),
		set_dest(ctx, VARL("__res")));
}

static RzILOpEffect *op_branch(Pic18ILContext *ctx, RzILOpPure *condition) {
	st8 n = (st8)((ut8)ctx->op->n);
	RzILOpEffect *jmp = JMP(UN(24, PC + 2 + 2 * n));
	return condition ? BRANCH(condition, jmp, NOP())
			 : jmp;
}

static RzILOpEffect *load_shadows_opt(Pic18ILContext *ctx) {
	return ctx->op->s ? SEQ3(
				    SETG("ws", VRW),
				    SETG("ss", VRS),
				    SETG("bsrs", VARG("bsr")))
			  : NOP();
}

static RzILOpEffect *op_call(Pic18ILContext *ctx) {
	return SEQ3(
		SETG("tos", UN(24, PC + 4)),
		JMP(UN(24, K << 1)),
		load_shadows_opt(ctx));
}

static RzILOpEffect *op_and(Pic18ILContext *ctx, const char *dst,
	RzILOpPure *a, RzILOpPure *b) {
	return SEQ3(
		SETL("__res", LOGAND(a, b)),
		status_res(ctx, VARL("__res")),
		SETG(dst, VARL("__res")));
}

static RzILOpEffect *op_skip_if(Pic18ILContext *ctx, RzILOpPure *condition) {
	return BRANCH(condition, SETG("_skip", U8(1)), NOP());
}

static RzILOpEffect *set_prod16(Pic18ILContext *ctx, RzILOpPure *res) {
	return SEQ3(
		SETL("__res", res),
		SETG("prodh", UNSIGNED(8, SHIFTR0(VARL("__res"), U8(8)))),
		SETG("prodl", UNSIGNED(8, VARL("__res"))));
}

static RzILOpEffect *op_pop(Pic18ILContext *ctx) {
	return SEQ2(
		SETG("stkptr", SUB(VARG("stkptr"), U8(4))),
		SETG("tos", LOADW(24, UNSIGNED(24, ADD(VARG("_stack"), VARG("stkptr"))))));
}

static RzILOpEffect *op_pop_jmp(Pic18ILContext *ctx) {
	return SEQ3(
		SETL("_pc", VARG("tos")),
		op_pop(ctx),
		JMP(VARL("_pc")));
}

static RzILOpEffect *op_push(Pic18ILContext *ctx, RzILOpPure *x) {
	return SEQ3(
		SETG("stkptr", ADD(VARG("stkptr"), U8(4))),
		STOREW(ADD(VARG("_stack"), VARG("stkptr")), x),
		SETG("tos", DUP(x)));
}

static RzILOpEffect *op_lfsr(Pic18ILContext *ctx) {
	ut8 lo = (ut8)ctx->op->k;
	ut8 hi = (ut8)ctx->op->k >> 8;
	char regl[8];
	char regh[8];
	rz_strf(regl, "fsr%dl", ctx->op->f);
	rz_strf(regh, "fsr%dh", ctx->op->f);
	return SEQ2(
		SETG(regl, U8(lo)),
		SETG(regh, U8(hi)));
}

static RzILOpEffect *pic18_il_op(Pic18ILContext *ctx) {
	switch (ctx->op->code) {
	case PIC18_OPCODE_ADDLW: return op_add(ctx, RW, VRW, U8(K), NULL);
	case PIC18_OPCODE_ADDWF: return op_add(ctx, NULL, VRW, VRF, NULL);
	case PIC18_OPCODE_ADDWFC: return op_add(ctx, NULL, VRW, VRF, VRC);
	case PIC18_OPCODE_ANDLW: return op_and(ctx, RW, VRW, U8(K));
	case PIC18_OPCODE_ANDWF: return op_and(ctx, NULL, VRW, VRF);
	case PIC18_OPCODE_BC: return op_branch(ctx, VRC);
	case PIC18_OPCODE_BN: return op_branch(ctx, VRN);
	case PIC18_OPCODE_BOV: return op_branch(ctx, VROV);
	case PIC18_OPCODE_BZ: return op_branch(ctx, VRZ);
	case PIC18_OPCODE_BNC: return op_branch(ctx, INV(VRC));
	case PIC18_OPCODE_BNN: return op_branch(ctx, INV(VRN));
	case PIC18_OPCODE_BNOV: return op_branch(ctx, INV(VROV));
	case PIC18_OPCODE_BNZ: return op_branch(ctx, INV(VRZ));
	case PIC18_OPCODE_BRA: return op_branch(ctx, NULL);

	case PIC18_OPCODE_BCF: return regbit_set(RF, B, 0);
	case PIC18_OPCODE_BSF: return regbit_set(RF, B, 1);
	case PIC18_OPCODE_BTG: return regbit_set1(RF, B, INV(bit_get(VRF, B)));
	case PIC18_OPCODE_BTFSC: return op_skip_if(ctx, BITN(VRF, B));
	case PIC18_OPCODE_BTFSS: return op_skip_if(ctx, bit_get(VRF, B));

	case PIC18_OPCODE_CALL: return op_call(ctx);
	case PIC18_OPCODE_CLRF: return SEQ2(SETG(RF, U8(0)), SETG("z", IL_TRUE));
	case PIC18_OPCODE_CLRWDT:
		return NOP();
		//		return SEQ4(
		//			SETG("wdt", U8(0)),
		//			SETG("wdtps", IL_FALSE),
		//			SETG("to", IL_TRUE),
		//			SETG("pd", IL_TRUE));
	case PIC18_OPCODE_SLEEP:
		return NOP();
		//		return SEQ4(
		//			SETG("wdt", U8(0)),
		//			SETG("wdtps", IL_FALSE),
		//			SETG("to", IL_TRUE),
		//			SETG("pd", IL_FALSE));
	case PIC18_OPCODE_COMF: return set_dest_status(ctx, complement_1(VRF));
	case PIC18_OPCODE_CPFSEQ: return op_skip_if(ctx, EQ(VRW, VRF));
	case PIC18_OPCODE_CPFSGT: return op_skip_if(ctx, UGT(VRF, VRW));
	case PIC18_OPCODE_CPFSLT: return op_skip_if(ctx, ULT(VRF, VRW));
	case PIC18_OPCODE_DAW:
		return SEQ3(
			SETL("__res", decimal_adjust(ctx, VRW)),
			SETG("c", IL_FALSE), // TODO: status C
			SETG(RW, VARL("__res")));
	case PIC18_OPCODE_DECF:
		return SEQ3(
			SETL("__res", SUB(VRF, U8(1))),
			status_sub(ctx, VRF, U8(1), VARL("__res"), NULL),
			set_dest(ctx, VARL("__res")));
	case PIC18_OPCODE_DECFSZ:
		return SEQ3(
			SETL("__res", SUB(VRF, U8(1))),
			set_dest(ctx, VARL("__res")),
			op_skip_if(ctx, IS_ZERO(VARL("__res"))));
	case PIC18_OPCODE_DCFSNZ:
		return SEQ3(
			SETL("__res", SUB(VRF, U8(1))),
			set_dest(ctx, VARL("__res")),
			op_skip_if(ctx, NON_ZERO(VARL("__res"))));
	case PIC18_OPCODE_GOTO: return JMP(UN(24, (ut32)K << 1));
	case PIC18_OPCODE_INCF:
		return SEQ3(
			SETL("__res", ADD(VRF, U8(1))),
			status_add(ctx, VRF, U8(1), VARL("__res"), NULL),
			set_dest(ctx, VARL("__res")));
	case PIC18_OPCODE_INCFSZ:
		return SEQ3(
			SETL("__res", ADD(VRF, U8(1))),
			set_dest(ctx, VARL("__res")),
			op_skip_if(ctx, IS_ZERO(VARL("__res"))));
	case PIC18_OPCODE_INFSNZ:
		return SEQ3(
			SETL("__res", ADD(VRF, U8(1))),
			set_dest(ctx, VARL("__res")),
			op_skip_if(ctx, NON_ZERO(VARL("__res"))));
	case PIC18_OPCODE_IORWF:
		return set_dest_status(ctx, LOGOR(VRW, VRF));
	case PIC18_OPCODE_IORLW:
		return SEQ2(
			SETG(RW, LOGOR(VRW, U8(K))),
			status_res(ctx, VRW));
	case PIC18_OPCODE_LFSR: return op_lfsr(ctx);
	case PIC18_OPCODE_MOVF:
		return set_dest_status(ctx, VRF);
	case PIC18_OPCODE_MOVFF:
		return SETG(pic18_regname(ctx->op->d), VARG(pic18_regname(ctx->op->s)));
	case PIC18_OPCODE_MOVLB:
		return SETG("bsr", LOGOR(U8(K), LOGAND(VARG("bsr"), U8(0xf0))));
	case PIC18_OPCODE_MOVLW:
		return SETG(RW, U8(K));
	case PIC18_OPCODE_MOVWF:
		return SETG(RF, VRW);
	case PIC18_OPCODE_MULLW:
		return set_prod16(ctx, MUL(UNSIGNED(16, VRW), U16(K)));
	case PIC18_OPCODE_MULWF:
		return set_prod16(ctx, MUL(UNSIGNED(16, VRW), UNSIGNED(16, VRF)));
	case PIC18_OPCODE_NOP: return NOP();
	case PIC18_OPCODE_NEGF: return SETG(RF, complement_2(VRF));
	case PIC18_OPCODE_POP: return op_pop(ctx);
	case PIC18_OPCODE_PUSH: return op_push(ctx, UN(24, PC));
	case PIC18_OPCODE_RCALL:
		return SEQ2(
			op_push(ctx, UN(24, PC + 2)),
			JMP(UN(24, PC + 2 + 2 * N)));
	case PIC18_OPCODE_RESET: return NOP();
	case PIC18_OPCODE_RETFIE:
		return SEQ3(
			BRANCH(
				IS_ZERO(VARG("ipen")),
				SETG("gie", IL_TRUE),
				SEQ2(
					SETL("_g", APPEND(VARG("gieh"), VARG("geil"))),
					BRANCH(
						EQ(VARG("_g"), UN(2, 0b11)),
						SETG("invalid", IL_TRUE),
						BRANCH(
							EQ(VARG("_g"), UN(2, 0b10)),
							SEQ2(SETG("giel", IL_TRUE),
								SETG("gieh", IL_TRUE)),
							NOP())))),
			load_shadows_opt(ctx),
			op_pop_jmp(ctx));
	case PIC18_OPCODE_RETLW:
		return SEQ2(
			SETG(RW, U8(K)),
			op_pop_jmp(ctx));
	case PIC18_OPCODE_RETURN:
		return SEQ2(
			load_shadows_opt(ctx),
			op_pop_jmp(ctx));
	case PIC18_OPCODE_RLNCF:
		return set_dest_status(ctx, LET("_x", VRF, LOGOR(SHIFTL0(VARLP("_x"), U8(7)), BOOL_TO_BV(MSB(VARLP("_x")), 8))));
	case PIC18_OPCODE_RRNCF:
		return set_dest_status(ctx, LET("_x", VRF, LOGOR(SHIFTR0(VARLP("_x"), U8(7)), BOOL_TO_BV(LSB(VARLP("_x")), 8))));
	case PIC18_OPCODE_RLCF:
		return SEQ3(
			SETL("_x", VRF),
			SETG("c", MSB(VARG("_x"))),
			set_dest_status(ctx, LOGOR(SHIFTL0(VARLP("_x"), U8(7)), BOOL_TO_BV(VRC, 8))));
	case PIC18_OPCODE_RRCF:
		return SEQ3(
			SETL("_x", VRF),
			SETG("c", LSB(VARG("_x"))),
			set_dest_status(ctx, LOGOR(SHIFTR0(VARLP("_x"), U8(7)), BOOL_TO_BV(VRC, 8))));
	case PIC18_OPCODE_SETF:
		return SETG(RF, U8(0xff));
	case PIC18_OPCODE_SUBFWB: return op_sub(ctx, NULL, VRW, VRF, VRC);
	case PIC18_OPCODE_SUBLW: return op_sub(ctx, RW, U8(K), VRW, NULL);
	case PIC18_OPCODE_SUBWF: return op_sub(ctx, NULL, VRF, VRW, NULL);
	case PIC18_OPCODE_SUBWFB: return op_sub(ctx, NULL, VRF, VRW, VRC);
	case PIC18_OPCODE_SWAPF:
		return set_dest(ctx, APPEND(UNSIGNED(4, VRF), UNSIGNED(4, SHIFTR0(VRF, U8(4)))));

	case PIC18_OPCODE_TBLRDs:
		return SETG("tablat", LOAD(VARG("tblptr")));
	case PIC18_OPCODE_TBLRDis:
		return SEQ2(
			SETG("tblptr", ADD(VARG("tblptr"), UN(24, 1))),
			SETG("tablat", LOAD(VARG("tblptr"))));
	case PIC18_OPCODE_TBLRDsd:
		return SEQ2(
			SETG("tablat", LOAD(VARG("tblptr"))),
			SETG("tblptr", SUB(VARG("tblptr"), UN(24, 1))));
	case PIC18_OPCODE_TBLRDsi:
		return SEQ2(
			SETG("tablat", LOAD(VARG("tblptr"))),
			SETG("tblptr", ADD(VARG("tblptr"), UN(24, 1))));
	case PIC18_OPCODE_TBLWTMs:
		return STORE(VARG("tblptr"), VARG("tablat"));
	case PIC18_OPCODE_TBLWTis:
		return SEQ2(
			SETG("tblptr", ADD(VARG("tblptr"), UN(24, 1))),
			STORE(VARG("tblptr"), VARG("tablat")));
	case PIC18_OPCODE_TBLWTMsd:
		return SEQ2(
			STORE(VARG("tblptr"), VARG("tablat")),
			SETG("tblptr", SUB(VARG("tblptr"), UN(24, 1))));
	case PIC18_OPCODE_TBLWTMsi:
		return SEQ2(
			STORE(VARG("tblptr"), VARG("tablat")),
			SETG("tblptr", ADD(VARG("tblptr"), UN(24, 1))));
	case PIC18_OPCODE_TSTFSZ:
		return op_skip_if(ctx, IS_ZERO(VRF));
	case PIC18_OPCODE_XORWF:
		return set_dest_status(ctx, LOGXOR(VRW, VRF));
	case PIC18_OPCODE_XORLW:
		return SEQ2(
			SETG(RW, LOGXOR(VRW, VRF)),
			status_res(ctx, VRW));
	case PIC18_OPCODE_INVALID: break;
	}
	return NULL;
}

static RzILOpEffect *pic18_il_op_finally(Pic18ILContext *ctx) {
	RzILOpEffect *op = pic18_il_op(ctx);
	switch (ctx->eff.tag) {
	case ILOpEff_None: break;
	case ILOpEff_PostDec:
		op = SEQ2(
			op,
			SETG(ctx->eff.fsr, SUB(VARG(ctx->eff.fsr), U16(1))));
		break;
	case ILOpEff_PostInc:
		op = SEQ2(
			op,
			SETG(ctx->eff.fsr, ADD(VARG(ctx->eff.fsr), U16(1))));
		break;
	case ILOpEff_PreInc:
		op = SEQ2(
			SETG(ctx->eff.fsr, ADD(VARG(ctx->eff.fsr), U16(1))),
			op);
		break;
	}
	return BRANCH(NON_ZERO(VARG("_skip")),
		SETG("_skip", U8(0)),
		op);
}

#undef K
#undef D
#undef F
#undef B
#undef N
#undef PC

#undef RW
#undef VRW
#undef RF
#undef VRF
#undef RWF
#undef VRWF
#undef VPC
#undef RC
#undef VRC
#undef RN
#undef VRN
#undef ROV
#undef VROV
#undef RZ
#undef VRZ
#undef RS
#undef VRS

static const char *pic18_reg_bindings[] = {
	"pc",
	"_sram",
	"_stack",
	"_skip",
	NULL
};

static RzAnalysisILConfig *pic18_il_config(
	RZ_NONNULL RzAnalysis *analysis) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(24, false, 24);
	cfg->reg_bindings = pic18_reg_bindings;
	return cfg;
}
