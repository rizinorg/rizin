// SPDX-FileCopyrightText: 2023 Siddharth Mishra <admin@brightprogrammer.in>
// SPDX-FileCopyrightText: 2024 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <stdlib.h>

#include "pic_midrange.h"

#include <rz_il/rz_il_opbuilder_begin.h>

#include <rz_analysis.h>
#include <rz_il.h>

/**
 * PIC Mid-Range Device Type.
 * Since each device has it's own set of supported instructions
 * and memory map (# of banks, register arrangement etc...),
 * we'll support analysis of each of these devices differently!
 * */
typedef enum pic16f_device_type_t {
	PIC16F882,
	PIC16F883,
	PIC16F884,
	PIC16F886,
	PIC16F887,
	PIC_MIDRANGE_SUPPORTED_DEVICE_NUM
} PicMidrangeDeviceType;

/**
 * This struct will store the CPU state of a PIC Mid-Range
 * device while being uplifted.
 *
 * Register are indexed using a value between 0x00-0x7f and a selected bank.
 * Instructions are indexed using a page selector (PCLATH)
 * Hence we need to maintain a state of CPU while being analyzed.
 *
 * This opens possibilities of storing more useful data to improve the process.
 * */
typedef struct pic_midrange_cpu_state_t {
	PicMidrangeDeviceType device_type;
	ut8 selected_bank; ///< for register indexing.
	ut8 selected_page; ///< for instruction indexing.
	bool skip;
} PicMidrangeCPUState;

typedef struct _pic_midrange_op_args_val {
	ut16 f;
	ut16 k;
	ut8 d;
	ut8 m;
	ut8 n;
	ut8 b;
} PicMidrangeOpArgsVal;

typedef struct pic_midrange_il_context_t {
	RzAnalysis *analysis;
	RzAnalysisOp *op;
	PicMidrangeCPUState cpu;
	PicMidrangeOpArgsVal args;
	ut64 addr;
	ut16 d;
} PicMidrangeILContext;

typedef RzILOpEffect *(*pic_midrange_il_handler)(PicMidrangeILContext *, ut16);

// HELPER DEFINES & TYPEDEFS

#define IL_LIFTER(op)      pic_midrange_##op##_il_lifter
#define IL_LIFTER_IMPL(op) static RzILOpEffect *pic_midrange_##op##_il_lifter( \
	RZ_NONNULL PicMidrangeILContext *ctx, ut16 instr)

// REGISTER DECLARATIONS & DEFINITIONS
#include "pic16f_memmaps/memmaps.h"

#define BANK_SIZE            ((ut32)0x80)
#define BANK_COMMON_MAP_LOW  cpu_state->selected_bank *BANK_SIZE + 0X70
#define BANK_COMMON_MAP_HIGH cpu_state->selected_bank *BANK_SIZE + 0X7F

#define K   (ctx->args.k)
#define D   (ctx->args.d)
#define F   (ctx->args.f)
#define B   (ctx->args.b)
#define N   (ctx->args.n)
#define PC  (ctx->addr)
#define VPC (U16(PC))

#define RW   "w"
#define VRW  (VARG(RW))
#define RF   pic_midrange_regname(F)
#define VRF  (VARG(pic_midrange_regname(F)))
#define RWF  (D ? pic_midrange_regname(F) : "w")
#define VRWF (VARG(RWF))

#define INS_LEN 2

// device to register schema map
PicMidrangeRegType *pic_midrange_device_reg_map[] = {
	[PIC16F882] = pic16f882_reg_map,
	[PIC16F883] = pic16f883_reg_map,
	//	[PIC16F884] = pic16f884_reg_map,
	[PIC16F886] = pic16f886_reg_map,
	//	[PIC16F887] = pic16f887_reg_map,
};

static RzILOpPure *SLICE(RzILOpPure *x, ut8 l, ut8 r) {
	return LOGAND(SHIFTR0(x, U16(l)), U16(~(-1 << (r - l + 1))));
}

#define SEXT(B, x, b) ((st##B)(x << (B - b)) >> (B - b))

static const char *RFSR(ut8 n) {
	static const char *FSR_names[] = {
		"fsr0", "fsr1", "fsr2"
	};
	if (n >= RZ_ARRAY_SIZE(FSR_names)) {
		return NULL;
	}
	return FSR_names[n];
}

#define VRFSR(n) VARG(RFSR(n))

#define BITN(x, n) IS_ZERO(UNSIGNED(1, SHIFTR0(x, U32(n))))
// overflow is not used in status register but just keeping this for future "maybe" use
#define CHECK_OVERFLOW(x, y, res)      AND(XOR(MSB(x), MSB(res)), XOR(MSB(y), MSB(DUP(res))))
#define CHECK_CARRY(x, y, res)         OR(AND(MSB(x), MSB(y)), AND(OR(MSB(DUP(x)), MSB(DUP(y))), INV(MSB(res))))
#define CHECK_BORROW(x, y, res)        OR(OR(AND(INV(MSB(x)), MSB(y)), AND(INV(MSB(DUP(x))), MSB(res))), AND(MSB(DUP(x)), AND(MSB(DUP(y)), MSB(DUP(res)))))
#define CHECK_DIGIT_CARRY(x, y, res)  OR(AND(BITN(x, 3), BITN(y, 3)), AND(OR(BITN(DUP(x), 3), BITN(DUP(y), 3)), INV(BITN(res, 3))))
#define CHECK_DIGIT_BORROW(x, y, res) OR( \
	OR(AND(INV(BITN(x, 3)), BITN(y, 3)), AND(INV(BITN(DUP(x), 3)), BITN(res, 3))), \
	AND(BITN(DUP(x), 3), AND(BITN(DUP(y), 3), BITN(DUP(res), 3))))

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
RzILOpEffect *pic_midrange_il_set_arithmetic_flags(
	RZ_BORROW RzILOpPure *x, RZ_BORROW RzILOpPure *y, RZ_BORROW RzILOpPure *res, bool add) {
	// get carry flag
	RzILOpBool *cf = NULL;
	RzILOpBool *dcf = NULL;
	if (add) {
		cf = CHECK_CARRY(x, y, res);
		dcf = CHECK_DIGIT_CARRY(x, y, res);
	} else { // sub
		cf = CHECK_BORROW(x, y, res);
		dcf = CHECK_DIGIT_BORROW(x, y, res);
	}

	// get zero flag
	RzILOpBool *zf = IS_ZERO(res);

	return SEQ3(SETG("c", cf),
		SETG("dc", dcf),
		SETG("z", zf));
}

#define SET_STATUS_ADD(x, y, r) pic_midrange_il_set_arithmetic_flags(x, y, r, true)
#define SET_STATUS_SUB(x, y, r) pic_midrange_il_set_arithmetic_flags(x, y, r, false)

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
	RzILOpEffect *add_op = SETG("w", ADD(VARG("w"), U16(K)));
	RzILOpEffect *set_status_op =
		SET_STATUS_ADD(VARL("_1"), U16(K), VARG("w"));
	return SEQ3(SETL("_1", VARG("w")),
		add_op,
		set_status_op);
}

/**
 * ADDWF
 * Operation: Add freg to wreg.
 * Operands: f, d
 * Status affected : C, DC, Z
 * */
IL_LIFTER_IMPL(ADDWF) {
	RzILOpEffect *add_op = SETG(RWF, ADD(VARG(RW), U16(K)));
	RzILOpEffect *set_status_op =
		SET_STATUS_ADD(VARL("_1"), U16(K), VARG(RWF));
	return SEQ3(SETL("_1", VARG(RW)),
		add_op,
		set_status_op);
}

IL_LIFTER_IMPL(ANDLW) {
	// TODO: set status Z
	return SETG(RW, LOGAND(VARG(RW), U16(K)));
}

/**
 * ANDWF
 * Operation: Take logical AND of freg and wreg.
 * Operands: f, d
 * Status affected : Z
 * */
IL_LIFTER_IMPL(ANDWF) {
	// TODO: set status Z
	return SETG(RWF, LOGAND(VARG(RW), U16(K)));
}

static RzILOpPure *bit_set(RzILOpPure *v, ut32 b, bool x) {
	if (x) {
		return LOGOR(v, U8(1 << b));
	}
	return LOGAND(v, U8(~(1 << b)));
}

static RzILOpPure *bit_set1(RzILOpPure *v, ut32 b, RzILOpBool *x) {
	return ITE(x, LOGOR(v, U8(1 << b)), LOGAND(DUP(v), U8(~(1 << b))));
}

static RzILOpPure *bit_get(RzILOpPure *v, ut32 b) {
	return NON_ZERO(LOGAND(v, U8(1 << b)));
}

#define regbit_set(reg, b, x)  SETG(reg, bit_set(VARG(reg), b, x))
#define regbit_set1(reg, b, x) SETG(reg, bit_set1(VARG(reg), b, x))

IL_LIFTER_IMPL(BCF) {
	return regbit_set(pic_midrange_regname(F), B, 0);
}

IL_LIFTER_IMPL(BSF) {
	return regbit_set(pic_midrange_regname(F), B, 1);
}

IL_LIFTER_IMPL(BTFSC) {
	return BRANCH(bit_get(VARG(pic_midrange_regname(F)), B), NOP(), JMP(U32(PC + INS_LEN * 2)));
}

IL_LIFTER_IMPL(BTFSS) {
	return BRANCH(bit_get(VARG(pic_midrange_regname(F)), B), JMP(U32(PC + INS_LEN * 2)), NOP());
}

IL_LIFTER_IMPL(CALL) {
	return SEQ2(
		SETG("tos", U16(PC + INS_LEN)),
		JMP(LOGOR(U16(K), SHIFTL0(SLICE(VARG("pclath"), 3, 4), U16(11)))));
}

IL_LIFTER_IMPL(CLRF) {
	return SEQ2(
		SETG(pic_midrange_regname(F), U16(0)),
		SETG("z", U16(1)));
}

IL_LIFTER_IMPL(CLR) {
	return SEQ2(
		SETG(RW, U16(0)),
		SETG("z", U16(1)));
}

IL_LIFTER_IMPL(CLRWDT) {
	return SEQ4(
		SETG("wdt", U16(0)),
		SETG("wdt_prescaler_count", U16(0)),
		SETG("to", U16(1)),
		SETG("pd", U16(1)));
}

IL_LIFTER_IMPL(COMF) {
	return SEQ2(
		SETG(RWF, NEG(VRF)),
		SETG("z", IS_ZERO(VARG(RWF))));
}

IL_LIFTER_IMPL(DECF) {
	return SEQ2(
		SETG(RWF, SUB(VRF, U16(1))),
		SETG("z", IS_ZERO(VARG(RWF))));
}

IL_LIFTER_IMPL(DECFSZ) {
	return SEQ2(
		SETG(RWF, SUB(VRF, U16(1))),
		BRANCH(IS_ZERO(VARG(RWF)),
			JMP(U16(PC + INS_LEN * 2)),
			NOP()));
}

IL_LIFTER_IMPL(GOTO) {
	return JMP(LOGOR(U16(K), SHIFTL0(SLICE(VARG("pclath"), 3, 4), U16(11))));
}

IL_LIFTER_IMPL(INCF) {
	return SEQ2(
		SETG(RWF, ADD(VRF, U16(1))),
		SETG("z", IS_ZERO(VARG(RWF))));
}

IL_LIFTER_IMPL(INCFSZ) {
	return SEQ2(
		SETG(RWF, ADD(VRF, U16(1))),
		BRANCH(IS_ZERO(VARG(RWF)),
			JMP(U16(PC + INS_LEN * 2)),
			NOP()));
}

IL_LIFTER_IMPL(IORLW) {
	return SEQ2(
		SETG(RW, LOGOR(VRW, U16(K))),
		SETG("z", IS_ZERO(VRW)));
}

IL_LIFTER_IMPL(IORWF) {
	return SEQ2(
		SETG(RWF, LOGOR(VRW, VRF)),
		SETG("z", IS_ZERO(VRWF)));
}

IL_LIFTER_IMPL(MOVLW) {
	return SETG(RW, U16(K));
}

IL_LIFTER_IMPL(MOVF) {
	return SEQ2(SETG(RWF, VRF),
		SETG("z", IS_ZERO(VRWF)));
}

IL_LIFTER_IMPL(MOVWF) {
	return SETG(RF, VRW);
}

IL_LIFTER_IMPL(OPTION) {
	return SETG("option", VRW);
}

IL_LIFTER_IMPL(RETFIE) {
	return SEQ2(
		SETG("tos", VPC),
		SETG("gie", U16(1)));
}

IL_LIFTER_IMPL(RETLW) {
	return SEQ2(
		SETG(RW, U16(K)),
		JMP(VARG("tos")));
}

IL_LIFTER_IMPL(RETURN) {
	return JMP(VARG("tos"));
}

IL_LIFTER_IMPL(RLF) {
	return SEQ3(
		SETG("_c", LOGAND(SHIFTR0(VRF, U8(7)), U8(1))),
		SETG(RWF, LOGOR(SHIFTL0(VRF, U8(1)), VARG("c"))),
		SETG("c", VARL("_v")));
}

IL_LIFTER_IMPL(RRF) {
	return SEQ3(
		SETG("_c", LOGAND(VRF, U8(1))),
		SETG(RWF, LOGOR(SHIFTR0(VRF, U8(1)), SHIFTL0(VARG("c"), U8(7)))),
		SETG("c", VARL("_v")));
}

IL_LIFTER_IMPL(SLEEP) {
	return SEQ4(
		SETG("wdt", U8(0)),
		SETG("wdt_prescaler_count", U8(0)),
		SETG("to", U8(1)),
		SETG("pd", U8(0)));
}

IL_LIFTER_IMPL(SUBLW) {
	return SEQ3(
		SETL("_w", VRW),
		SETG(RW, SUB(U8(K), VARL("_w"))),
		SET_STATUS_SUB(VARL("_w"), U8(K), VRW));
}

IL_LIFTER_IMPL(SUBWF) {
	return SEQ3(
		SETL("_res", SUB(VRF, VRW)),
		SET_STATUS_SUB(VRF, VRW, VARL("_res")),
		SETG(RWF, VARL("_res")));
}

IL_LIFTER_IMPL(SWAPF) {
	return SETG(RWF, APPEND(UNSIGNED(4, VRF), UNSIGNED(4, SHIFTR0(VRF, U8(4)))));
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
		SETG(RW, LOGXOR(VRW, U8(K))),
		SETG("z", IS_ZERO(VRW)));
}

/**
 * ANDWF
 * Operation: Take logical AND of freg and wreg.
 * Operands: f, d
 * Status affected : Z
 * */
IL_LIFTER_IMPL(XORWF) {
	return SEQ2(
		SETG(RWF, LOGXOR(VRW, VRF)),
		SETG("z", IS_ZERO(VRWF)));
}

// 14-bit enhanced PIC additional instructions

RzILOpEffect *reset() {
	return NOP();
}

RzILOpEffect *setZ(RzILOpPure *x) {
	return SETG("z", IS_ZERO(x));
}

IL_LIFTER_IMPL(RESET) {
	return SEQ2(
		reset(),
		JMP(U16(0)));
}
IL_LIFTER_IMPL(CALLW) {
	return SEQ2(
		SETG("tos", U16(PC + INS_LEN)),
		JMP(LOGOR(U16(K), UNSIGNED(16, VRW))));
}
IL_LIFTER_IMPL(BRW) {
	return JMP(ADD(UNSIGNED(16, VRW), SHIFTR0(U16(PC + INS_LEN), U16(1))));
}
IL_LIFTER_IMPL(MOVIW_1) {
	switch (ctx->d & 0b11) {
	case 0x0: return SEQ3(
		SETG(RFSR(N), ADD(VRFSR(N), U8(1))),
		SETG(RW, VRFSR(N)),
		setZ(VRW));
	case 0x1: return SEQ3(
		SETG(RFSR(N), SUB(VRFSR(N), U8(1))),
		SETG(RW, VRFSR(N)),
		setZ(VRW));
	case 0x2: return SEQ3(
		SETG(RW, VRFSR(N)),
		SETG(RFSR(N), ADD(VRFSR(N), U8(1))),
		setZ(VRW));
	case 0x3: return SEQ3(
		SETG(RW, VRFSR(N)),
		SETG(RFSR(N), SUB(VRFSR(N), U8(1))),
		setZ(VRW));
	default: break;
	}
	return NULL;
}
IL_LIFTER_IMPL(MOVIW_2) {
	return SEQ2(
		SETG(RW, LOAD(ADD(VRFSR(N), S8(SEXT(8, K, 6))))),
		setZ(VRW));
}

IL_LIFTER_IMPL(MOVWI_1) {
	return SETG(RFSR(N), VRW);
}
IL_LIFTER_IMPL(MOVWI_2) {
	return STORE(ADD(VRFSR(N), S8(SEXT(8, K, 6))), VRW);
}

IL_LIFTER_IMPL(MOVLB) {
	// imm5?
	return SETG("bsr", U8(K));
}
IL_LIFTER_IMPL(MOVLP) {
	// imm7?
	return SETG("pclath", U8(K));
}

IL_LIFTER_IMPL(LSLF) {
	return SEQ3(
		SETG("c", MSB(VRF)),
		SETG(RWF, SHIFTL0(VRF, U8(1))),
		setZ(VRWF));
}
IL_LIFTER_IMPL(LSRF) {
	return SEQ3(
		SETG("c", LSB(VRF)),
		SETG(RWF, SHIFTR0(VRF, U8(1))),
		setZ(VRWF));
}
IL_LIFTER_IMPL(ASRF) {
	return SEQ3(
		SETG("c", LSB(VRF)),
		SETG(RWF, SHIFTRA(VRF, U8(1))),
		setZ(VRWF));
}
IL_LIFTER_IMPL(SUBWFB) {
	return SEQ3(
		SETG("_res", ADD(SUB(VRF, VRW), VARG("c"))),
		SET_STATUS_SUB(VRF, VRW, VARL("_res")),
		SETG(RWF, VARL("_res")));
}
IL_LIFTER_IMPL(ADDWFC) {
	return SEQ3(
		SETG("_res", ADD(ADD(VRF, VRW), VARG("c"))),
		SET_STATUS_ADD(VRF, VRW, VARL("_res")),
		SETG(RWF, VARL("_res")));
}
IL_LIFTER_IMPL(ADDFSR) {
	return SETG(RFSR(N), ADD(VRFSR(N), S8(SEXT(8, K, 6))));
}
IL_LIFTER_IMPL(BRA) {
	return JMP(U16(PC + SEXT(16, K, 9)));
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

/**
 * Create new Mid-Range device CPU state.
 *
 * */
static bool rz_pic_midrange_cpu_state_setup(
	PicMidrangeCPUState *state,
	PicMidrangeDeviceType device_type) {
	rz_return_val_if_fail(state, NULL);
	if (device_type >= PIC_MIDRANGE_SUPPORTED_DEVICE_NUM) {
		RZ_LOG_ERROR("RzIL : Invalid PIC Mid-Range device type provided");
		return false;
	}

	state->device_type = device_type;
	state->selected_bank = 0; // initially bank is 0
	state->selected_page = 0; // initially page is 0
	return true;
}

/**
 * \brief Returns IL VM config for given PIC Mid-Range device type.
 *
 * \param analysis \c RzAnalysis instance.
 * \param device_type Device type in PIC16F family.
 *
 * \return valid ptr to RzAnalysisILConfig on success, NULL otherwise.
 * */
static RzAnalysisILConfig *pic_midrange_il_config(
	RZ_NONNULL RzAnalysis *analysis) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(16, false, 16);
	cfg->reg_bindings = pic_midrange_regnames;
	return cfg;
}