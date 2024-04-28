// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>

static ut64 pic18_regadr(const HtSU *mm, const char *v) {
	bool f = false;
	ut64 adr = ht_su_find((HtSU *)mm, v, &f);
	if (f) {
		return adr;
	}
	rz_warn_if_reached();
	return UT64_MAX;
}

static RzILOpPure *varg_mm(const HtSU *mm, const char *v) {
	bool f = false;
	ut64 adr = ht_su_find((HtSU *)mm, v, &f);
	if (f) {
		return LOAD(U16(adr));
	}
	ut8 b = pic18_status(v);
	if (b != 0xff) {
		return BITN(varg_mm(mm, "status"), b);
	}
	if (RZ_STR_EQ(v, "tblptr")) {
		return APPEND(varg_mm(mm, "tblptru"), APPEND(varg_mm(mm, "tblptrh"), varg_mm(mm, "tblptrl")));
	}
	return VARG(v);
}

static RzILOpEffect *setg_mm(const HtSU *mm, const char *v, RzILOpPure *x) {
	bool f = false;
	ut64 adr = ht_su_find((HtSU *)mm, v, &f);
	if (f) {
		return STORE(U16(adr), x);
	}
	ut8 b = pic18_status(v);
	if (b != 0xff) {
		return setg_mm(mm, "status", bit_set(varg_mm(mm, "status"), b, x));
	}
	if (RZ_STR_EQ(v, "tblptr")) {
		return SEQ4(
			SETL("__tblptr", x),
			setg_mm(mm, "tblptrl", UNSIGNED(8, VARL("__tblptr"))),
			setg_mm(mm, "tblptrh", UNSIGNED(8, SHIFTR0(VARL("__tblptr"), U8(8)))),
			setg_mm(mm, "tblptru", UNSIGNED(8, SHIFTR0(VARL("__tblptr"), U8(16)))));
	}
	return SETG(v, x);
}

#undef VARG
#undef SETG
#define VARG(x)    varg_mm(ctx->mm, x)
#define SETG(v, x) setg_mm(ctx->mm, v, x)

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

#define VPC  (U16(PC))
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
static RzILOpEffect *set_dest(const Pic18ILContext *ctx, RzILOpPure *x) {
	const char *regname = ctx->op->d ? pic18_regname(F) : RW;
	if (ctx->op->a) {
		ut64 adr = pic18_regadr(ctx->mm, regname);
		if (adr != UT64_MAX) {
			return STORE(ADD(MUL(UNSIGNED(16, LOGAND(VARG("bsr"), U8(0x0f))), U16(0x100)), U16(adr)),
				x);
		}
		return NULL;
	}
	return SETG(regname, x);
}

static RzILOpEffect *status_add(RzILOpPure *a, RzILOpPure *b, RzILOpPure *res, RzILOpPure *curry) {
	return NOP();
}

static RzILOpEffect *status_sub(RzILOpPure *a, RzILOpPure *b, RzILOpPure *res, RzILOpPure *curry) {
	return NOP();
}

static RzILOpEffect *status_res(const Pic18ILContext *ctx, RzILOpPure *res) {
	return NOP();
}

static RzILOpEffect *set_dest_status(const Pic18ILContext *ctx, RzILOpPure *x) {
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

static RzILOpPure *decimal_adjust(const Pic18ILContext *ctx, RzILOpPure *x) {
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

static RzILOpEffect *op_add(const Pic18ILContext *ctx, const char *dst,
	RzILOpPure *a, RzILOpPure *b, RzILOpPure *curry) {
	if (dst) {
		return SEQ3(
			SETL("_res", ADD(a, curry ? ADD(b, curry) : b)),
			status_add(DUP(a), DUP(b), VARL("_res"), curry ? DUP(curry) : NULL),
			SETG(dst, VARL("_res")));
	}
	return SEQ3(
		SETL("_res", ADD(a, curry ? ADD(b, curry) : b)),
		status_add(DUP(a), DUP(b), VARL("_res"), curry ? DUP(curry) : NULL),
		set_dest(ctx, VARL("_res")));
}

static RzILOpEffect *op_sub(const Pic18ILContext *ctx, const char *dst,
	RzILOpPure *a, RzILOpPure *b, RzILOpPure *curry) {
	if (dst) {
		return SEQ3(
			SETL("_res", SUB(a, curry ? ADD(b, curry) : b)),
			status_sub(DUP(a), DUP(b), VARL("_res"), curry ? DUP(curry) : NULL),
			SETG(dst, VARL("_res")));
	}
	return SEQ3(
		SETL("_res", SUB(a, curry ? ADD(b, curry) : b)),
		status_sub(DUP(a), DUP(b), VARL("_res"), curry ? DUP(curry) : NULL),
		set_dest(ctx, VARL("_res")));
}

static RzILOpEffect *op_branch(const Pic18ILContext *ctx, RzILOpPure *condition) {
	return condition ? BRANCH(condition, JMP(U16(PC + 2 + 2 * ctx->op->n)), NOP())
			 : JMP(U16(PC + 2 + 2 * ctx->op->n));
}

static RzILOpEffect *load_shadows_opt(const Pic18ILContext *ctx) {
	return BRANCH(NON_ZERO(VARG("s")),
		SEQ3(
			SETG("ws", VRW),
			SETG("ss", VRS),
			SETG("bsrs", VARG("bsr"))),
		NOP());
}

static RzILOpEffect *op_call(const Pic18ILContext *ctx) {
	return SEQ3(
		SETG("tos", U16(PC + 4)),
		JMP(U32(K << 1)),
		load_shadows_opt(ctx));
}

static RzILOpEffect *op_and(const Pic18ILContext *ctx, const char *dst,
	RzILOpPure *a, RzILOpPure *b) {
	return SEQ3(
		SETL("_res", LOGAND(a, b)),
		status_res(ctx, VARL("_res")),
		SETG(dst, VARL("_res")));
}

static RzILOpEffect *op_skip_if(const Pic18ILContext *ctx, RzILOpPure *condition) {
	return BRANCH(condition, JMP(U16(PC + INS_LEN * 2)), NOP());
}

static RzILOpEffect *set_prod16(const Pic18ILContext *ctx, RzILOpPure *res) {
	return SEQ3(
		SETL("_res", res),
		SETG("prodh", UNSIGNED(8, SHIFTR0(VARL("_res"), U8(8)))),
		SETG("prodl", UNSIGNED(8, VARL("_res"))));
}

static RzILOpEffect *op_pop(const Pic18ILContext *ctx) {
	return SEQ2(
		SETG("stkptr", SUB(VARG("stkptr"), U16(4))),
		SETG("tos", LOADW(32, ADD(VARG("_stack"), VARG("stkptr")))));
}

static RzILOpEffect *op_pop_jmp(const Pic18ILContext *ctx) {
	return SEQ3(
		SETL("_pc", VARG("tos")),
		op_pop(ctx),
		JMP(VARL("_pc")));
}

static RzILOpEffect *op_push(const Pic18ILContext *ctx, RzILOpPure *x) {
	return SEQ3(
		SETG("stkptr", ADD(VARG("stkptr"), U16(4))),
		STOREW(ADD(VARG("_stack"), VARG("stkptr")), x),
		SETG("tos", DUP(x)));
}

static RzILOpEffect *pic18_il(Pic18ILContext *ctx) {
	switch (ctx->op->code) {
	case PIC18_OPCODE_ADDLW: return op_add(ctx, RW, VRW, U16(K), NULL);
	case PIC18_OPCODE_ADDWF: return op_add(ctx, NULL, VRW, VRF, NULL);
	case PIC18_OPCODE_ADDWFC: return op_add(ctx, NULL, VRW, VRF, VRC);
	case PIC18_OPCODE_ANDLW: return op_and(ctx, RW, VRW, U16(K));
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
	case PIC18_OPCODE_BTFSC: return op_skip_if(ctx, INV(bit_get(VRF, B)));
	case PIC18_OPCODE_BTFSS: return op_skip_if(ctx, bit_get(VRF, B));

	case PIC18_OPCODE_CALL: return op_call(ctx);
	case PIC18_OPCODE_CLRF: return SEQ2(SETG(RF, U8(0)), SETG("z", IL_TRUE));
	case PIC18_OPCODE_CLRWDT:
		return SEQ4(
			SETG("wdt", U8(0)),
			SETG("wdt_prescaler_count", IL_FALSE),
			SETG("to", IL_TRUE),
			SETG("pd", IL_TRUE));
	case PIC18_OPCODE_COMF: return set_dest_status(ctx, complement_1(VRF));
	case PIC18_OPCODE_CPFSEQ: return op_skip_if(ctx, EQ(VRW, VRF));
	case PIC18_OPCODE_CPFSGT: return op_skip_if(ctx, SGT(VRW, VRF));
	case PIC18_OPCODE_CPFSLT: return op_skip_if(ctx, SLT(VRW, VRF));
	case PIC18_OPCODE_DAW:
		return SEQ3(
			SETL("_res", decimal_adjust(ctx, VRW)),
			SETG("c", IL_FALSE), // TODO: status C
			SETG(RW, VARL("_res")));
	case PIC18_OPCODE_DECF:
		return SEQ3(
			SETL("_res", SUB(VRF, U8(1))),
			status_sub(VRF, U8(1), VARL("_res"), NULL),
			set_dest(ctx, VARL("_res")));
	case PIC18_OPCODE_DECFSZ:
		return SEQ3(
			SETL("_res", SUB(VRF, U8(1))),
			set_dest(ctx, VARL("_res")),
			op_skip_if(ctx, IS_ZERO(VARL("_res"))));
	case PIC18_OPCODE_DCFSNZ:
		return SEQ3(
			SETL("_res", SUB(VRF, U8(1))),
			set_dest(ctx, VARL("_res")),
			op_skip_if(ctx, NON_ZERO(VARL("_res"))));
	case PIC18_OPCODE_GOTO: return JMP(U32((ut32)K << 1));
	case PIC18_OPCODE_INCF:
		return SEQ3(
			SETL("_res", ADD(VRF, U8(1))),
			status_add(VRF, U8(1), VARL("_res"), NULL),
			set_dest(ctx, VARL("_res")));
	case PIC18_OPCODE_INCFSZ:
		return SEQ3(
			SETL("_res", ADD(VRF, U8(1))),
			set_dest(ctx, VARL("_res")),
			op_skip_if(ctx, IS_ZERO(VARL("_res"))));
	case PIC18_OPCODE_INFSNZ:
		return SEQ3(
			SETL("_res", ADD(VRF, U8(1))),
			set_dest(ctx, VARL("_res")),
			op_skip_if(ctx, NON_ZERO(VARL("_res"))));
	case PIC18_OPCODE_IORWF:
		return set_dest_status(ctx, LOGOR(VRW, VRF));
	case PIC18_OPCODE_IORLW:
		return SEQ2(
			SETG(RW, LOGOR(VRW, U16(K))),
			status_res(ctx, VRW));
	case PIC18_OPCODE_LFSR: return SETG(RFSR(F), U16(K));
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
	case PIC18_OPCODE_PUSH: return op_push(ctx, U32(PC));
	case PIC18_OPCODE_RCALL:
		return SEQ2(
			op_push(ctx, U32(PC + 2)),
			JMP(U32(PC + 2 + 2 * N)));
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
	case PIC18_OPCODE_SLEEP:
		return SEQ4(
			SETG("wdt", U8(0)),
			SETG("wdt_prescaler_count", IL_FALSE),
			SETG("to", IL_TRUE),
			SETG("pd", IL_FALSE));
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
			SETG("tblptr", ADD(VARG("tblptr"), U32(1))),
			SETG("tablat", LOAD(VARG("tblptr"))));
	case PIC18_OPCODE_TBLRDsd:
		return SEQ2(
			SETG("tablat", LOAD(VARG("tblptr"))),
			SETG("tblptr", SUB(VARG("tblptr"), U32(1))));
	case PIC18_OPCODE_TBLRDsi:
		return SEQ2(
			SETG("tablat", LOAD(VARG("tblptr"))),
			SETG("tblptr", ADD(VARG("tblptr"), U32(1))));
	case PIC18_OPCODE_TBLWTMs:
		return STORE(VARG("tblptr"), VARG("tablat"));
	case PIC18_OPCODE_TBLWTis:
		return SEQ2(
			SETG("tblptr", ADD(VARG("tblptr"), U32(1))),
			STORE(VARG("tblptr"), VARG("tablat")));
	case PIC18_OPCODE_TBLWTMsd:
		return SEQ2(
			STORE(VARG("tblptr"), VARG("tablat")),
			SETG("tblptr", SUB(VARG("tblptr"), U32(1))));
	case PIC18_OPCODE_TBLWTMsi:
		return SEQ2(
			STORE(VARG("tblptr"), VARG("tablat")),
			SETG("tblptr", ADD(VARG("tblptr"), U32(1))));
	case PIC18_OPCODE_TSTFSZ:
		return op_skip_if(ctx, IS_ZERO(VRF));
	case PIC18_OPCODE_XORWF:
		return set_dest_status(ctx, XOR(VRW, VRF));
	case PIC18_OPCODE_XORLW:
		return SEQ2(
			SETG(RW, XOR(VRW, VRF)),
			status_res(ctx, VRW));
	case PIC18_OPCODE_INVALID: break;
	}
	return NULL;
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
	"_sram",
	"_stack"
};

static RzAnalysisILConfig *pic18_il_config(
	RZ_NONNULL RzAnalysis *analysis) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 16);
	cfg->reg_bindings = pic18_reg_bindings;
	return cfg;
}
