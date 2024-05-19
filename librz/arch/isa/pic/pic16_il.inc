// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2024 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opbuilder_begin.h>
#include <rz_analysis.h>
#include "pic16.h"
#include "pic_il.inc"

enum {
	INDF0,
	INDF1,
	PCL,
	STATUS,
	FSR0L,
	FSR0H,
	FSR1L,
	FSR1H,
	BSR,
	WREG,
	PCLATH,
	INTCON,
} GPRs;

static ut16 OPTION_REG = 1;

enum {
	RBIF,
	INTF,
	T0IF,
	BEIF,
	INTE,
	T0IE,
	PEIE,
	GIE
} INTCON_Register;

enum {
	C,
	DC,
	Z,
	PD,
	TO,
	RP0,
	RP1,
	IRP
} STAUTS_Register;

static const ut16 STKPTR = 0xfed;
static const ut16 TOSL = 0xfee;
static const ut16 TOSH = 0xfef;

typedef struct pic16_il_context_t {
	RzAnalysis *analysis;
	RzAnalysisOp *op;
	const Pic16Op *x;
} Pic16ILContext;

static RzILOpPure *register_i(ut16 i);
static RzILOpEffect *set_register_i(ut16 i, RzILOpPure *x);

#define K   (ctx->x->args.k)
#define D   (ctx->x->args.d)
#define F   (ctx->x->args.f)
#define B   (ctx->x->args.b)
#define N   (ctx->x->args.n)
#define PC  (ctx->x->addr)
#define VPC (U16(PC))

static RzILOpPure *val_fsrn(ut8 n) {
	rz_return_val_if_fail(n <= 1, NULL);
	return APPEND(register_i(2 * n + FSR0L + 1), register_i(2 * n + FSR0L));
}
static RzILOpEffect *set_fsrn(ut8 n, RzILOpPure *x) {
	rz_return_val_if_fail(n <= 1, NULL);
	return SEQ3(
		SETL("__x", x),
		set_register_i(2 * n + FSR0L + 1, UNSIGNED(8, SHIFTR0(VARL("__x"), U8(8)))),
		set_register_i(2 * n + FSR0L, UNSIGNED(8, VARL("__x"))));
}

static RzILOpPure *val_bank() {
	return VARG("_bank");
}
static RzILOpEffect *set_bank() {
	return SETG("_bank", LOGAND(register_i(BSR), U8(0x1f)));
}

static RzILOpPure *register_i(ut16 i) {
	rz_warn_if_fail(i < 0x80);
	if (i == INDF0 || i == INDF1) {
		return LOAD(val_fsrn(i - INDF0));
	}

	return LOAD(ADD(U16(i), UNSIGNED(16, MUL(val_bank(), U8(0x80)))));
}
static RzILOpEffect *set_register_i(ut16 i, RzILOpPure *x) {
	rz_warn_if_fail(i < 0x80);
	if (i == INDF0 || i == INDF1) {
		return STORE(val_fsrn(i - INDF0), x);
	}

	RzILOpEffect *eff = STORE(ADD(U16(i), UNSIGNED(16, MUL(val_bank(), U8(0x80)))), x);
	if (i == BSR) {
		return SEQ2(eff, set_bank());
	}
	return eff;
}
#define VARGi(i)       register_i(i)
#define SETGi(i, x)    set_register_i(i, x)
#define VARGb(i, b)    bit_get(register_i(i), b)
#define SETGb(i, b, x) set_register_i(i, bit_set1(register_i(i), b, x))

#define VRW      register_i(WREG)
#define SET_W(x) set_register_i(WREG, x)
#define VRF      register_i(F)
#define SET_F(x) set_register_i(F, x)

#define VTOS       APPEND(LOAD(U16(TOSH)), LOAD(U16(TOSL)))
#define SET_TOS(x) SEQ3(SETL("__tos", x), \
	STORE(U16(TOSH), UNSIGNED(8, SHIFTR0(VARL("__tos"), U8(8)))), \
	STORE(U16(TOSL), UNSIGNED(8, VARL("__tos"))))

static RzILOpPure *register_WF(Pic16ILContext *ctx) {
	rz_warn_if_fail(F < 0x80);
	return D ? VRW : VRF;
}
static RzILOpEffect *set_register_WF(Pic16ILContext *ctx, RzILOpPure *x) {
	rz_warn_if_fail(F < 0x80);
	return D ? SET_F(x) : SET_W(x);
}
#define VRWF      register_WF(ctx)
#define SET_WF(x) (set_register_WF(ctx, x))

typedef RzILOpEffect *(*pic16_il_handler)(Pic16ILContext *, ut16);

RzILOpEffect *reset() {
	return NOP();
}

RzILOpEffect *set_z(Pic16ILContext *ctx, RzILOpPure *x) {
	return SETGb(STATUS, Z, IS_ZERO(x));
}

#define SETZ(x) set_z(ctx, x)

// HELPER DEFINES & TYPEDEFS

#define IL_LIFTER(op)      pic16_##op##_il_lifter
#define IL_LIFTER_IMPL(op) static RzILOpEffect *pic16_##op##_il_lifter( \
	RZ_NONNULL Pic16ILContext *ctx, ut16 instr)

#define INS_LEN 2

/**
 * Handle C, DC & Z flags for the previous operation.
 * To be used after an arithmetic operation.
 * Order of operands must be preserved for subtraction
 * operations, i.e `add = false`
 *
 * \param x First operand
 * \param y Second operand
 * \param res Result of last performed operation that affected the flag.
 * \param add Was this an add operation?
 *
 * \return \c RzILOpEffect containing set of steps to set status flags.
 * */
RzILOpEffect *pic16_il_set_arithmetic_flags(Pic16ILContext *ctx,
	RZ_BORROW RzILOpPure *x, RZ_BORROW RzILOpPure *y, RZ_BORROW RzILOpPure *res, bool add) {
	// get carry flag
	RzILOpBool *cf = NULL;
	RzILOpBool *dcf = NULL;
	if (add) {
		cf = CHECK_CARRY(VARL("status_x"), VARL("status_y"), VARL("status_res"));
		dcf = CHECK_DIGIT_CARRY(VARL("status_x"), VARL("status_y"), VARL("status_res"));
	} else { // sub
		cf = CHECK_CARRY(VARL("status_x"), NEG(VARL("status_y")), VARL("status_res"));
		dcf = CHECK_DIGIT_CARRY(VARL("status_x"), NEG(VARL("status_y")), VARL("status_res"));
	}

	// get zero flag
	RzILOpBool *zf = IS_ZERO(VARL("status_res"));

	return SEQ8(
		SETL("status_x", x),
		SETL("status_y", y),
		SETL("status_res", res),
		SETL("_c", cf),
		SETL("_dc", dcf),
		SETL("_z", zf),
		SETL("_status", register_i(STATUS)),
		SETGi(STATUS,
			bit_set1(
				bit_set1(
					bit_set1(VARL("_status"), C, VARL("_c")),
					DC,
					VARL("_dc")),
				Z, VARL("_z"))));
}

#define SET_STATUS_ADD(ctx, x, y, r) pic16_il_set_arithmetic_flags(ctx, x, y, r, true)
#define SET_STATUS_SUB(ctx, x, y, r) pic16_il_set_arithmetic_flags(ctx, x, y, r, false)

/**
 * NOP
 * Operation: No Operation.
 * Operands: NONE
 * Status affected : NONE
 * */
IL_LIFTER_IMPL(NOP) {
	return NOP();
}

/**
 * ADDLW.
 * Operation: Add Literal To wreg
 * Operands: Literal (k)
 * Status affected : C, DC, Z
 * */
IL_LIFTER_IMPL(ADDLW) {
	return SEQ4(
		SETL("_w", VRW),
		SETL("_res", ADD(VARL("_w"), U8(K))),
		SET_W(VARL("_res")),
		SET_STATUS_ADD(ctx, VARL("_w"), U8(K), VARL("_res")));
}

/**
 * ADDWF
 * Operation: Add freg to wreg.
 * Operands: f, d
 * Status affected : C, DC, Z
 * */
IL_LIFTER_IMPL(ADDWF) {
	return SEQ5(
		SETL("_w", VRW),
		SETL("_f", VRF),
		SETL("_res", ADD(VARL("_w"), VARL("_f"))),
		SET_WF(VARL("_res")),
		SET_STATUS_ADD(ctx, VARL("_w"), VARL("_f"), VARL("_res")));
}

IL_LIFTER_IMPL(ANDLW) {
	return SEQ2(
		SET_W(LOGAND(VRW, U8(K))),
		SETZ(VRW));
}

/**
 * ANDWF
 * Operation: Take logical AND of freg and wreg.
 * Operands: f, d
 * Status affected : Z
 * */
IL_LIFTER_IMPL(ANDWF) {
	return SEQ2(
		SET_WF(LOGAND(VRW, VRF)),
		SETZ(VRWF));
}

IL_LIFTER_IMPL(BCF) {
	return SET_F(bit_set(VRF, B, 0));
}

IL_LIFTER_IMPL(BSF) {
	return SET_F(bit_set(VRF, B, 1));
}

IL_LIFTER_IMPL(BTFSC) {
	return BRANCH(bit_get(VRF, B), NOP(), JMP(U16(PC + INS_LEN * 2)));
}

IL_LIFTER_IMPL(BTFSS) {
	return BRANCH(bit_get(VRF, B), JMP(U16(PC + INS_LEN * 2)), NOP());
}

IL_LIFTER_IMPL(CALL) {
	return SEQ2(
		SET_TOS(U16(PC + INS_LEN)),
		JMP(LOGOR(U16(K), SHIFTL0(UNSIGNED(16, pure_slice(register_i(PCLATH), 3, 4)), U16(11)))));
}

IL_LIFTER_IMPL(CLRF) {
	return SEQ2(
		SET_F(U8(0)),
		SETGb(STATUS, Z, IL_TRUE));
}

IL_LIFTER_IMPL(CLRW) {
	return SEQ2(
		SET_W(U8(0)),
		SETGb(STATUS, Z, IL_TRUE));
}

IL_LIFTER_IMPL(CLRWDT) {
	return NOP();
}

IL_LIFTER_IMPL(COMF) {
	return SEQ2(
		SET_WF(NEG(VRF)),
		SETGb(STATUS, Z, IS_ZERO(VRWF)));
}

IL_LIFTER_IMPL(DECF) {
	return SEQ2(
		SET_WF(SUB(VRF, U8(1))),
		SETGb(STATUS, Z, IS_ZERO(VRWF)));
}

IL_LIFTER_IMPL(DECFSZ) {
	return SEQ2(
		SET_WF(SUB(VRF, U8(1))),
		BRANCH(IS_ZERO(VRWF),
			JMP(U16(PC + INS_LEN * 2)),
			NOP()));
}

IL_LIFTER_IMPL(GOTO) {
	return JMP(LOGOR(U16(K), SHIFTL0(UNSIGNED(16, pure_slice(register_i(PCLATH), 3, 5)), U16(11))));
}

IL_LIFTER_IMPL(INCF) {
	return SEQ2(
		SET_WF(ADD(VRF, U8(1))),
		SETGb(STATUS, Z, IS_ZERO(VRWF)));
}

IL_LIFTER_IMPL(INCFSZ) {
	return SEQ2(
		SET_WF(ADD(VRF, U8(1))),
		BRANCH(IS_ZERO(VRWF),
			JMP(U16(PC + INS_LEN * 2)),
			NOP()));
}

IL_LIFTER_IMPL(IORLW) {
	return SEQ2(
		SET_W(LOGOR(VRW, U8(K))),
		SETGb(STATUS, Z, IS_ZERO(VRW)));
}

IL_LIFTER_IMPL(IORWF) {
	return SEQ2(
		SET_WF(LOGOR(VRW, VRF)),
		SETGb(STATUS, Z, IS_ZERO(VRWF)));
}

IL_LIFTER_IMPL(MOVLW) {
	return SET_W(U8(K));
}

IL_LIFTER_IMPL(MOVF) {
	return SEQ2(SET_WF(VRF),
		SETGb(STATUS, Z, IS_ZERO(VRWF)));
}

IL_LIFTER_IMPL(MOVWF) {
	return SET_F(VRW);
}

IL_LIFTER_IMPL(OPTION) {
	return SETGi(OPTION_REG, VRW);
}

IL_LIFTER_IMPL(RETFIE) {
	return SEQ2(
		SET_TOS(VPC),
		SETGb(INTCON, GIE, IL_TRUE));
}

IL_LIFTER_IMPL(RETLW) {
	return SEQ2(
		SET_W(U8(K)),
		JMP(VTOS));
}

IL_LIFTER_IMPL(RETURN) {
	return JMP(VTOS);
}

IL_LIFTER_IMPL(RLF) {
	return SEQ3(
		SETL("_c", LOGAND(SHIFTR0(VRF, U8(7)), U8(1))),
		SET_WF(LOGOR(SHIFTL0(VRF, U8(1)), VARL("_c"))),
		SETGb(STATUS, C, NON_ZERO(VARL("_c"))));
}

IL_LIFTER_IMPL(RRF) {
	return SEQ3(
		SETL("_c", LOGAND(VRF, U8(1))),
		SET_WF(LOGOR(SHIFTR0(VRF, U8(1)), SHIFTL0(VARL("_c"), U8(7)))),
		SETGb(STATUS, C, NON_ZERO(VARL("_c"))));
}

IL_LIFTER_IMPL(SLEEP) {
	return NOP();
}

IL_LIFTER_IMPL(SUBLW) {
	return SEQ4(
		SETL("_w", VRW),
		SETL("_res", SUB(U8(K), VARL("_w"))),
		SET_W(VARL("_res")),
		SET_STATUS_SUB(ctx, U8(K), VARL("_w"), VARL("_res")));
}

IL_LIFTER_IMPL(SUBWF) {
	return SEQ5(
		SETL("_f", VRF),
		SETL("_w", VRW),
		SETL("_res", SUB(VARL("_f"), VARL("_w"))),
		SET_WF(VARL("_res")),
		SET_STATUS_SUB(ctx, VARL("_f"), VARL("_w"), VARL("_res")));
}

IL_LIFTER_IMPL(SWAPF) {
	return SET_WF(APPEND(UNSIGNED(4, VRF), UNSIGNED(4, SHIFTR0(VRF, U8(4)))));
}

IL_LIFTER_IMPL(TRIS) {
	// TODO: TRIS register f;
	return SETG("tris", VRW);
}

/**
 * XORLW.
 * Operation: Take logical XOR between literal and wreg
 * Operands: Literal (k)
 * Status affected : Z
 * */
IL_LIFTER_IMPL(XORLW) {
	return SEQ2(
		SET_W(LOGXOR(VRW, U8(K))),
		SETGb(STATUS, Z, IS_ZERO(VRW)));
}

/**
 * ANDWF
 * Operation: Take logical AND of freg and wreg.
 * Operands: f, d
 * Status affected : Z
 * */
IL_LIFTER_IMPL(XORWF) {
	return SEQ3(
		SETL("_res", LOGXOR(VRW, VRF)),
		SET_WF(VARL("_res")),
		SETZ(VARL("_res")));
}

IL_LIFTER_IMPL(RESET) {
	return SEQ2(
		reset(),
		JMP(U16(0)));
}
IL_LIFTER_IMPL(CALLW) {
	return SEQ2(
		SET_TOS(U16(PC + INS_LEN)),
		JMP(LOGOR(U16(K), UNSIGNED(16, VRW))));
}
IL_LIFTER_IMPL(BRW) {
	return JMP(ADD(UNSIGNED(16, VRW), SHIFTR0(U16(PC + INS_LEN), U16(1))));
}
IL_LIFTER_IMPL(MOVIW_1) {
	switch (ctx->x->instr & 0b11) {
	case 0x0: return SEQ3(
		set_fsrn(N, ADD(val_fsrn(N), U16(1))),
		SET_W(LOAD(val_fsrn(N))),
		SETZ(VRW));
	case 0x1: return SEQ3(
		set_fsrn(N, SUB(val_fsrn(N), U16(1))),
		SET_W(LOAD(val_fsrn(N))),
		SETZ(VRW));
	case 0x2: return SEQ3(
		SET_W(LOAD(val_fsrn(N))),
		set_fsrn(N, ADD(val_fsrn(N), U16(1))),
		SETZ(VRW));
	case 0x3: return SEQ3(
		SET_W(LOAD(val_fsrn(N))),
		set_fsrn(N, SUB(val_fsrn(N), U16(1))),
		SETZ(VRW));
	default: break;
	}
	return NULL;
}
IL_LIFTER_IMPL(MOVIW_2) {
	return SEQ2(
		SET_W(LOAD(ADD(val_fsrn(N), S16(K)))),
		SETZ(VRW));
}

IL_LIFTER_IMPL(MOVWI_1) {
	return STORE(val_fsrn(N), VRW);
}
IL_LIFTER_IMPL(MOVWI_2) {
	return STORE(ADD(val_fsrn(N), S16(K)), VRW);
}

IL_LIFTER_IMPL(MOVLB) {
	// imm5?
	return SETGi(BSR, U8(K));
}
IL_LIFTER_IMPL(MOVLP) {
	// imm7?
	return SETGi(PCLATH, U8(K));
}

IL_LIFTER_IMPL(LSLF) {
	return SEQ3(
		SETGb(STATUS, C, MSB(VRF)),
		SET_WF(SHIFTL0(VRF, U8(1))),
		SETZ(VRWF));
}
IL_LIFTER_IMPL(LSRF) {
	return SEQ3(
		SETGb(STATUS, C, LSB(VRF)),
		SET_WF(SHIFTR0(VRF, U8(1))),
		SETZ(VRWF));
}
IL_LIFTER_IMPL(ASRF) {
	return SEQ3(
		SETGb(STATUS, C, LSB(VRF)),
		SET_WF(SHIFTRA(VRF, U8(1))),
		SETZ(VRWF));
}
IL_LIFTER_IMPL(SUBWFB) {
	return SEQ3(
		SETL("_res", ADD(SUB(VRF, VRW), BOOL_TO_BV(VARGb(STATUS, C), 8))),
		SET_STATUS_SUB(ctx, VRF, VRW, VARL("_res")),
		SET_WF(VARL("_res")));
}
IL_LIFTER_IMPL(ADDWFC) {
	return SEQ3(
		SETL("_res", ADD(ADD(VRF, VRW), BOOL_TO_BV(VARGb(STATUS, C), 8))),
		SET_STATUS_ADD(ctx, VRF, VRW, VARL("_res")),
		SET_WF(VARL("_res")));
}
IL_LIFTER_IMPL(ADDFSR) {
	return set_fsrn(N, ADD(val_fsrn(N), S16(K)));
}
IL_LIFTER_IMPL(BRA) {
	return JMP(U16(PC + K));
}

#undef K
#undef D
#undef F
#undef B
#undef N
#undef PC
#undef VPC

#undef RW
#undef VRW
#undef RF
#undef VRF
#undef RWF
#undef VRWF

const char *pic16_reg_bindings[] = {
	"tris",
	"_bank",
	NULL,
};

/**
 * \brief Returns IL VM config for given PIC Mid-Range device type.
 *
 * \param analysis \c RzAnalysis instance.
 * \param device_type Device type in PIC16F family.
 *
 * \return valid ptr to RzAnalysisILConfig on success, NULL otherwise.
 * */
RzAnalysisILConfig *pic16_il_config(
	RZ_NONNULL RzAnalysis *analysis) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(16, false, 16);
	cfg->reg_bindings = pic16_reg_bindings;
	return cfg;
}