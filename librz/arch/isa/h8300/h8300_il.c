// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "h8300_disas.h"
#include <rz_il/rz_il_opbuilder_begin.h>

#define OPS_GET(I) (cmd->ops[(I)])
#define PC_VAL     U16(cmd->pc)

static const char *GPRs[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"
};

#define R16_OP_DECL(I) \
	H8300Operand *op = &OPS_GET(i); \
	if (op->typ != H8300_OP_R16 && op->typ != H8300_OP_RI16 && op->typ != H8300_OP_RINC && op->typ != H8300_OP_RDEC) { \
		RZ_LOG_ERROR("invalid op type r16/r+/-r\n"); \
		return NULL; \
	}

#define R8_OP_DECL(I) \
	H8300Operand *op = &OPS_GET(i); \
	if (op->typ != H8300_OP_R8) { \
		RZ_LOG_ERROR("invalid op type r8\n"); \
		return NULL; \
	}

static RzILOpPure *r8_op(H8300Cmd *cmd, ut8 i) {
	R8_OP_DECL(i);
	ut8 index = op->reg % 8;
	bool low = op->reg & 8;
	RzILOpPure *x = VARG(GPRs[index]);
	return low ? UNSIGNED(8, x) : UNSIGNED(8, SHIFTR0(x, U8(8)));
}

#define DEPOSIT16(V, S, L, F) UNSIGNED(16, DEPOSIT32(UNSIGNED(32, V), S, L, UNSIGNED(32, F)))
#define DEPOSIT8(V, S, L, F)  UNSIGNED(8, DEPOSIT32(UNSIGNED(32, V), S, L, UNSIGNED(32, F)))
#define EXTRACT1(V, S)        UNSIGNED(1, EXTRACT32(UNSIGNED(32, V), S, U32(1)))
#define EXTRACTb(V, S)        NON_ZERO(EXTRACT32(UNSIGNED(32, V), S, U32(1)))

static RzILOpEffect *r8_op_set(H8300Cmd *cmd, ut8 i, RzILOpPure *x) {
	R8_OP_DECL(i);
	ut8 index = op->reg % 8;
	bool low = op->reg & 8;
	return SETG(GPRs[index],
		DEPOSIT16(VARG(GPRs[index]), low ? U32(0) : U32(8), U32(8), x));
}

static RzILOpPure *r16_op(H8300Cmd *cmd, ut8 i) {
	R16_OP_DECL(i);
	ut8 index = op->reg % 8;
	return VARG(GPRs[index]);
}

static RzILOpEffect *r16_op_set(H8300Cmd *cmd, ut8 i, RzILOpPure *x) {
	R16_OP_DECL(i);
	ut8 index = op->reg % 8;
	return SETG(GPRs[index], x);
}

#define X_OP_GET_IMPL(E, T, X) \
	static RzILOpPure *X##_op(H8300Cmd *cmd, ut8 i) { \
		H8300Operand *op = &OPS_GET(i); \
		if (op->typ != E) { \
			RZ_LOG_ERROR("invalid op type " #E "\n"); \
			return NULL; \
		} \
		return T(op->imm); \
	}

X_OP_GET_IMPL(H8300_OP_IMM, U16, imm);
#define IMM_OP(I) imm_op(cmd, I)
X_OP_GET_IMPL(H8300_OP_IMM, U8, imm8);
#define IMM8_OP(I) imm8_op(cmd, I)
X_OP_GET_IMPL(H8300_OP_ABS, U16, abs);
#define ABS_OP(I) abs_op(cmd, I)
X_OP_GET_IMPL(H8300_OP_MI8, U16, mi8);
#define MI8_OP(I) mi8_op(cmd, I)

static RzILOpPure *rd16_op(H8300Cmd *cmd, ut8 i) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_RD16) {
		RZ_LOG_ERROR("invalid op type rd16\n");
		return NULL;
	}
	return ADD(VARG(GPRs[op->rd.reg]), S16(op->rd.disp));
}

static RzILOpPure *pc_rel_op(H8300Cmd *cmd, ut8 i) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_PCREL8) {
		RZ_LOG_ERROR("invalid op type pc relative\n");
		return NULL;
	}
	st32 dst = (st32)cmd->pc + op->disp;
	return U16((ut16)dst);
}

#define R8_OP(I)    r8_op(cmd, (I))
#define R8_X(I, X)  r8_op_set(cmd, (I), (X))
#define R16_OP(I)   r16_op(cmd, (I))
#define R16_X(I, X) r16_op_set(cmd, (I), (X))
#define RD16_OP(I)  rd16_op(cmd, (I))
#define PCREL_OP(I) pc_rel_op(cmd, (I))

typedef enum {
	CCR_C,
	CCR_V,
	CCR_Z,
	CCR_N,
	CCR_4,
	CCR_H,
	CCR_6,
	CCR_I,
} CCR_BIT;

#define B_TO_1(x)  BOOL_TO_BV(x, 1)
#define B_TO_8(x)  BOOL_TO_BV(x, 8)
#define B_TO_16(x) BOOL_TO_BV(x, 16)
#define B_TO_32(x) BOOL_TO_BV(x, 32)

static RzILOpBool *ccr_val(CCR_BIT bit) {
	return NON_ZERO(EXTRACT32(UNSIGNED(32, VARG("ccr")), U32(bit), U32(1)));
}

static RzILOpEffect *ccr_set(CCR_BIT bit, RzILOpBool *x) {
	return SETG("ccr", DEPOSIT8(VARG("ccr"), U32(bit), U32(1), B_TO_16(x)));
}

static RzILOpEffect *ccr_unary_NZ(ut8 N, RzILOpPure *x) {
	return SEQ2(
		ccr_set(CCR_N, SLT(x, UN(N, 0))),
		ccr_set(CCR_Z, IS_ZERO(DUP(x))));
}

static RzILOpEffect *ccr_unary_NZV(ut8 N, RzILOpPure *x, RzILOpBool *v) {
	return SEQ2(
		ccr_unary_NZ(N, x),
		ccr_set(CCR_V, v));
}

static RzILOpEffect *ccr_unary_NZVC(ut8 N, RzILOpPure *x, RzILOpBool *v, RzILOpBool *c) {
	return SEQ2(
		ccr_unary_NZV(N, x, v),
		ccr_unary_NZ(N, DUP(x)));
}

#define ccr_unary_NZV0(N, X) ccr_unary_NZV(N, X, IL_FALSE)

static RzILOpEffect *op_mov_b(H8300Cmd *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R8R8:
		return SEQ3(
			SETL("data_value", R8_OP(0)),
			R8_X(1, VARL("data_value")),
			ccr_unary_NZV0(8, VARL("data_value")));
	case H8300_INSN_FORMAT_ABSR8:
		return SEQ2(R8_X(1, LOAD(ABS_OP(0))), ccr_unary_NZV0(8, LOAD(ABS_OP(0))));
	case H8300_INSN_FORMAT_R8ABS:
		return SEQ2(STORE(ABS_OP(1), R8_OP(0)), ccr_unary_NZV0(8, R8_OP(0)));
	case H8300_INSN_FORMAT_IMMR8:
		return SEQ2(R8_X(1, IMM8_OP(0)), ccr_unary_NZV0(8, IMM8_OP(0)));
	case H8300_INSN_FORMAT_R8RI16:
		return SEQ2(STORE(R16_OP(1), R8_OP(0)), ccr_unary_NZV0(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RI16R8:
		return SEQ2(R8_X(1, LOAD(R16_OP(0))), ccr_unary_NZV0(8, LOAD(R16_OP(0))));
	case H8300_INSN_FORMAT_R8RD16:
		return SEQ2(STORE(RD16_OP(1), R8_OP(0)), ccr_unary_NZV0(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RD16R8:
		return SEQ2(R8_X(1, LOAD(RD16_OP(0))), ccr_unary_NZV0(8, LOAD(RD16_OP(0))));
	case H8300_INSN_FORMAT_R8RDEC:
		return SEQ3(
			R16_X(1, SUB(R16_OP(1), U16(1))),
			STORE(R16_OP(1), R8_OP(0)),
			ccr_unary_NZV0(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RINCR8:
		return SEQ3(
			R8_X(1, LOAD(R16_OP(0))),
			R16_X(0, ADD(U16(1), R16_OP(0))),
			ccr_unary_NZV0(8, LOAD(R16_OP(0))));
	default: NOT_IMPLEMENTED;
	}
}

static RzILOpEffect *op_mov_w(H8300Cmd *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R16R16:
		return SEQ3(
			SETL("data_value", R16_OP(0)),
			R16_X(1, VARL("data_value")),
			ccr_unary_NZV0(16, VARL("data_value")));
	case H8300_INSN_FORMAT_IMMR16:
		return SEQ2(R16_X(1, IMM_OP(0)), ccr_unary_NZV0(16, IMM_OP(0)));
	case H8300_INSN_FORMAT_RI16R16:
		return SEQ3(
			SETL("data_value", LOADW(16, R16_OP(0))),
			R16_X(1, VARL("data_value")),
			ccr_unary_NZV0(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16RI16:
		return SEQ2(STOREW(R16_OP(1), R16_OP(0)), ccr_unary_NZV0(16, R16_OP(0)));
	case H8300_INSN_FORMAT_ABSR16:
		return SEQ3(
			SETL("data_value", LOADW(16, ABS_OP(0))),
			R16_X(1, VARL("data_value")),
			ccr_unary_NZV0(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16ABS:
		return SEQ2(STOREW(ABS_OP(1), R16_OP(0)), ccr_unary_NZV0(16, R16_OP(0)));
	case H8300_INSN_FORMAT_R16RD16:
		return SEQ2(STOREW(RD16_OP(1), R16_OP(0)), ccr_unary_NZV0(16, R16_OP(0)));
	case H8300_INSN_FORMAT_RD16R16:
		return SEQ3(
			SETL("data_value", LOADW(16, RD16_OP(0))),
			R16_X(1, VARL("data_value")),
			ccr_unary_NZV0(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16RDEC:
		return SEQ3(
			R16_X(1, SUB(R16_OP(1), U16(1))),
			STOREW(R16_OP(1), R16_OP(0)),
			ccr_unary_NZV0(16, R16_OP(0)));
	case H8300_INSN_FORMAT_RINCR16:
		return SEQ4(
			R16_X(1, LOADW(16, R16_OP(0))),
			SETL("data_value", ADD(U16(1), R16_OP(0))),
			R16_X(0, ADD(U16(1), R16_OP(0))),
			ccr_unary_NZV0(16, VARL("data_value")));
	default:
		NOT_IMPLEMENTED;
	}
}

#define BEQ(X, Y)     INV(XOR(X, Y))
#define BNE(X, Y)     XOR(X, Y)
#define ADD3(X, Y, Z) ADD(X, ADD(Y, Z))
#define SUB3(X, Y, Z) SUB(X, ADD(Y, Z))

/**
 * \brief Conditional code ADD
 * I: Previous value remains unchanged.
 * H: Set to "1" when there is a carry from bit 3;
 *  otherwise cleared to "0."
 * N: Set to "1" when the result is negative;
 * 	otherwise cleared to "0."
 * Z: Set to "1" when the result is zero;
 * 	otherwise cleared to "0."
 * V: Set to "1" if an overflow occurs;
 * 	otherwise cleared to "0."
 * C: Set to "1" if there is a carry from bit 7;
 * 	otherwise cleared to "0."
 */
static RzILOpEffect *ccr_add_b(RzILOpPure *a, RzILOpPure *b, RzILOpBool *c) {
	RzILOpPure *low4 = ADD3(LOGAND(a, U8(0xf)), LOGAND(b, U8(0xf)), B_TO_8(c));
	RzILOpPure *H = NON_ZERO(LOGAND(low4, U8(0x10)));

	RzILOpPure *sum = ADD3(UNSIGNED(16, DUP(a)), UNSIGNED(16, DUP(b)), B_TO_16(DUP(c)));
	RzILOpPure *N = NON_ZERO(LOGAND(sum, U16(0x80)));
	RzILOpPure *Z = IS_ZERO(DUP(sum));
	RzILOpPure *C = NON_ZERO(LOGAND(DUP(sum), U16(0x100)));
	RzILOpPure *V = AND(BEQ(MSB(DUP(a)), MSB(DUP(b))), BNE(MSB(DUP(a)), DUP(N)));
	return SEQ5(
		ccr_set(CCR_H, H),
		ccr_set(CCR_N, N),
		ccr_set(CCR_Z, Z),
		ccr_set(CCR_C, C),
		ccr_set(CCR_V, V));
}

static RzILOpEffect *ccr_add_w(RzILOpPure *a, RzILOpPure *b) {
	RzILOpPure *low12 = ADD(LOGAND(a, U16(0xfff)), LOGAND(b, U16(0xfff)));
	RzILOpPure *H = NON_ZERO(LOGAND(low12, U16(0x1000)));

	RzILOpPure *sum = ADD(UNSIGNED(32, DUP(a)), UNSIGNED(32, DUP(b)));
	RzILOpPure *N = NON_ZERO(LOGAND(sum, U32(0x800)));
	RzILOpPure *Z = IS_ZERO(DUP(sum));
	RzILOpPure *C = NON_ZERO(LOGAND(DUP(sum), U32(0x10000)));
	RzILOpPure *V = AND(BEQ(MSB(DUP(a)), MSB(DUP(b))), BNE(MSB(DUP(a)), DUP(N)));
	return SEQ5(
		ccr_set(CCR_H, H),
		ccr_set(CCR_N, N),
		ccr_set(CCR_Z, Z),
		ccr_set(CCR_C, C),
		ccr_set(CCR_V, V));
}

static RzILOpEffect *op_add_b(H8300Cmd *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R8R8:
		return SEQ4(
			SETL("_0", R8_OP(0)),
			SETL("_1", R8_OP(1)),
			R8_X(1, ADD(VARL("_0"), VARL("_1"))),
			ccr_add_b(VARL("_0"), VARL("_1"), IL_FALSE));
	case H8300_INSN_FORMAT_IMMR8:
		return SEQ4(
			SETL("_0", IMM8_OP(0)),
			SETL("_1", R8_OP(1)),
			R8_X(1, ADD(VARL("_0"), VARL("_1"))),
			ccr_add_b(VARL("_0"), VARL("_1"), IL_FALSE));
	default: NOT_IMPLEMENTED;
	}
}

static RzILOpEffect *op_add_w(H8300Cmd *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R16R16:
		return SEQ4(
			SETL("_0", R16_OP(0)),
			SETL("_1", R16_OP(1)),
			R16_X(1, ADD(VARL("_0"), VARL("_1"))),
			ccr_add_w(VARL("_0"), VARL("_1")));
	default: NOT_IMPLEMENTED;
	}
}

static RzILOpEffect *op_adds(H8300Cmd *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_IMMR16:
		return R16_X(1, ADD(IMM_OP(0), R16_OP(1)));
	default: NOT_IMPLEMENTED;
	}
}

static RzILOpEffect *op_addx(H8300Cmd *cmd) {
	RzILOpBool *C = ccr_val(CCR_C);
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_IMMR8:
		return SEQ5(
			SETL("_c", C),
			SETL("_0", IMM8_OP(0)),
			SETL("_1", R8_OP(1)),
			R8_X(1, ADD3(VARL("_0"), VARL("_1"), B_TO_8(VARL("_c")))),
			ccr_add_b(VARL("_0"), VARL("_1"), VARL("_c")));
	case H8300_INSN_FORMAT_R8R8:
		return SEQ5(
			SETL("_c", C),
			SETL("_0", R8_OP(0)),
			SETL("_1", R8_OP(1)),
			R8_X(1, ADD3(VARL("_0"), VARL("_1"), B_TO_8(VARL("_c")))),
			ccr_add_b(VARL("_0"), VARL("_1"), VARL("_c")));
	default:
		rz_il_op_pure_free(C);
		NOT_IMPLEMENTED;
	}
}

static RzILOpEffect *ccr_cmp_b(RzILOpPure *a, RzILOpPure *b, RzILOpBool *c) {
	RzILOpPure *low4 = SUB3(LOGAND(a, U8(0xf)), LOGAND(b, U8(0xf)), B_TO_8(c));
	RzILOpPure *H = NON_ZERO(LOGAND(low4, U8(0x10)));

	RzILOpPure *res = SUB3(SIGNED(16, DUP(a)), SIGNED(16, DUP(b)), B_TO_16(DUP(c)));
	RzILOpPure *N = NON_ZERO(LOGAND(res, U16(0x80)));
	RzILOpPure *Z = ITE(IS_ZERO(DUP(res)), ccr_val(CCR_Z), IL_FALSE);
	RzILOpPure *C = SLT(DUP(res), S16(0));
	RzILOpPure *V = AND(BNE(MSB(DUP(a)), MSB(DUP(b))), BNE(MSB(DUP(a)), DUP(N)));
	return SEQ5(
		ccr_set(CCR_H, H),
		ccr_set(CCR_N, N),
		ccr_set(CCR_Z, Z),
		ccr_set(CCR_C, C),
		ccr_set(CCR_V, V));
}

static RzILOpEffect *ccr_cmp_w(RzILOpPure *a, RzILOpPure *b, RzILOpBool *c) {
	RzILOpPure *low12 = SUB3(LOGAND(a, U16(0xfff)), LOGAND(b, U16(0xfff)), B_TO_16(c));
	RzILOpPure *H = NON_ZERO(LOGAND(low12, U16(0x1000)));

	RzILOpPure *res = SUB3(SIGNED(32, DUP(a)), SIGNED(32, DUP(b)), B_TO_32(DUP(c)));
	RzILOpPure *N = NON_ZERO(LOGAND(res, U32(0x8000)));
	RzILOpPure *Z = IS_ZERO(DUP(res));
	RzILOpPure *C = SLT(DUP(res), S32(0));
	RzILOpPure *V = AND(BNE(MSB(DUP(a)), MSB(DUP(b))), BNE(MSB(DUP(a)), DUP(N)));
	return SEQ5(
		ccr_set(CCR_H, H),
		ccr_set(CCR_N, N),
		ccr_set(CCR_Z, Z),
		ccr_set(CCR_C, C),
		ccr_set(CCR_V, V));
}

static RzILOpEffect *ccr_sub_b(RzILOpPure *a, RzILOpPure *b, RzILOpBool *c) {
	RzILOpPure *low4 = SUB3(LOGAND(a, U8(0xf)), LOGAND(b, U8(0xf)), B_TO_8(c));
	RzILOpPure *H = NON_ZERO(LOGAND(low4, U8(0x10)));

	RzILOpPure *res = SUB3(SIGNED(16, DUP(a)), SIGNED(16, DUP(b)), B_TO_16(DUP(c)));
	RzILOpPure *N = NON_ZERO(LOGAND(res, U16(0x80)));
	RzILOpPure *Z = IS_ZERO(DUP(res));
	RzILOpPure *C = SLT(DUP(res), S16(0));
	RzILOpPure *V = AND(BNE(MSB(DUP(a)), MSB(DUP(b))), BNE(MSB(DUP(a)), DUP(N)));
	return SEQ5(
		ccr_set(CCR_H, H),
		ccr_set(CCR_N, N),
		ccr_set(CCR_Z, Z),
		ccr_set(CCR_C, C),
		ccr_set(CCR_V, V));
}

typedef RzILOpPure *(*op2)(RzILOpPure *a, RzILOpPure *b);
typedef RzILOpEffect *(*setter)(H8300Cmd *, ut8, RzILOpPure *);

static RzILOpEffect *op_logical2(H8300Cmd *cmd, RzILOpPure *a, RzILOpPure *b, op2 f, setter s) {
	return SEQ3(
		SETL("_res", f(a, b)),
		s(cmd, 1, VARL("_res")),
		ccr_unary_NZV0(8, VARL("_res")));
}

static RzILOpEffect *op_logical2_formats(H8300Cmd *cmd, op2 f) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_IMMR8:
		return op_logical2(cmd, IMM8_OP(0), R8_OP(1), f, r8_op_set);
	case H8300_INSN_FORMAT_R8R8:
		return op_logical2(cmd, R8_OP(0), R8_OP(1), f, r8_op_set);
	default: NOT_IMPLEMENTED;
	}
}

static RzILOpEffect *op_logical_i8ccr(H8300Cmd *cmd, op2 f) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_IMM:
		return SETG("ccr", f(IMM8_OP(0), VARG("ccr")));
	default: NOT_IMPLEMENTED;
	}
}

#define U2(X)             UN(2, X)
#define U4(X)             UN(4, X)
#define AND3(X, Y, Z)     AND(X, AND(Y, Z))
#define IN_RANGE(X, L, H) AND(UGE(X, L), ULE(X, H))
#define UNDEFINED8        U8(0)

static RzILOpEffect *op_daa(H8300Cmd *cmd) {
	RzILOpPure *ch = APPEND(BOOL_TO_BV(ccr_val(CCR_C), 1), BOOL_TO_BV(ccr_val(CCR_H), 1));
	RzILOpPure *un = UNSIGNED(4, SHIFTR0(R8_OP(0), U8(4)));
	RzILOpPure *ln = UNSIGNED(4, R8_OP(0));

	RzILOpPure *cnd_ch_00_00 = AND(ULE(VARL("un"), U4(0x9)), ULE(VARL("ln"), U4(0x9)));
	RzILOpPure *cnd_ch_00_06 = AND(ULE(VARL("un"), U4(0x8)), IN_RANGE(VARL("ln"), U4(0xa), U4(0xf)));
	RzILOpPure *ch_00 = ITE(
		cnd_ch_00_00,
		U8(0x00),
		ITE(
			cnd_ch_00_06,
			U8(0x06),
			ITE(
				AND(IN_RANGE(VARL("un"), U4(0xa), U4(0xf)), ULE(VARL("ln"), U4(0x9))),
				U8(0x60),
				ITE(
					AND(IN_RANGE(VARL("un"), U4(0x9), U4(0xf)), IN_RANGE(VARL("ln"), U4(0xa), U4(0xf))),
					U8(0x66),
					UNDEFINED8))));

	RzILOpPure *cnd_ch_01_06 = AND(ULE(VARL("un"), U4(0x9)), ULE(VARL("ln"), U4(0x3)));
	RzILOpPure *ch_01 = ITE(
		cnd_ch_01_06,
		U8(0x06),
		ITE(
			AND(IN_RANGE(VARL("un"), U4(0xa), U4(0xf)), ULE(VARL("ln"), U4(0x3))),
			U8(0x66),
			UNDEFINED8));

	RzILOpPure *ch_10 = ITE(
		AND(ULE(VARL("un"), U4(0x2)), ULE(VARL("ln"), U4(0x9))),
		U8(0x60),
		ITE(
			AND(ULE(VARL("un"), U4(0x2)), IN_RANGE(VARL("ln"), U4(0xa), U4(0xf))),
			U8(0x66),
			UNDEFINED8));

	RzILOpPure *ch_11 = ITE(
		AND(ULE(VARL("un"), U4(0x3)), ULE(VARL("ln"), U4(0x3))),
		U8(0x66),
		UNDEFINED8);

	RzILOpPure *added =
		ITE(
			EQ(VARL("ch"), UN(2, 0b00)),
			ch_00,
			ITE(
				EQ(VARL("ch"), UN(2, 0b01)),
				ch_01,
				ITE(
					EQ(VARL("ch"), UN(2, 0b10)),
					ch_10,
					ITE(
						EQ(VARL("ch"), UN(2, 0b11)),
						ch_11,
						UNDEFINED8))));

	RzILOpPure *result_c = INV(
		OR(
			AND(EQ(VARL("ch"), U2(0b00)), OR(DUP(cnd_ch_00_00), DUP(cnd_ch_00_06))),
			AND(EQ(VARL("ch"), U2(0b01)), DUP(cnd_ch_01_06))));

	return SEQ8(
		SETL("un", un),
		SETL("ln", ln),
		SETL("ch", ch),
		SETL("added", added),
		SETL("result", ADD(R8_OP(0), VARL("added"))),
		R8_X(0, VARL("result")),
		ccr_unary_NZ(8, VARL("result")),
		ccr_set(CCR_C, result_c));
}

static RzILOpEffect *op_das(H8300Cmd *cmd) {
	RzILOpPure *ch = APPEND(BOOL_TO_BV(ccr_val(CCR_C), 1), BOOL_TO_BV(ccr_val(CCR_H), 1));
	RzILOpPure *un = UNSIGNED(4, SHIFTR0(R8_OP(0), U8(4)));
	RzILOpPure *ln = UNSIGNED(4, R8_OP(0));

	RzILOpPure *ch_00 = ITE(
		AND(ULE(VARL("un"), U4(0x9)), ULE(VARL("ln"), U4(0x9))),
		U8(0x00),
		UNDEFINED8);

	RzILOpPure *ch_01 = ITE(
		AND(ULE(VARL("un"), U4(0x8)), IN_RANGE(VARL("ln"), U4(0x6), U4(0xf))),
		U8(0xfa),
		UNDEFINED8);

	RzILOpPure *ch_10 = ITE(
		AND(IN_RANGE(VARL("un"), U4(0x7), U4(0xf)), ULE(VARL("ln"), U4(0x9))),
		U8(0xa0),
		UNDEFINED8);

	RzILOpPure *ch_11 = ITE(
		AND(IN_RANGE(VARL("un"), U4(0x6), U4(0xf)), IN_RANGE(VARL("ln"), U4(0x6), U4(0xf))),
		U8(0x9a),
		UNDEFINED8);

	RzILOpPure *added =
		ITE(
			EQ(VARL("ch"), UN(2, 0b00)),
			ch_00,
			ITE(
				EQ(VARL("ch"), UN(2, 0b01)),
				ch_01,
				ITE(
					EQ(VARL("ch"), UN(2, 0b10)),
					ch_10,
					ITE(
						EQ(VARL("ch"), UN(2, 0b11)),
						ch_11,
						UNDEFINED8))));

	return SEQ7(
		SETL("un", un),
		SETL("ln", ln),
		SETL("ch", ch),
		SETL("added", added),
		SETL("result", ADD(R8_OP(0), VARL("added"))),
		R8_X(0, VARL("result")),
		ccr_unary_NZ(8, VARL("result")));
}

static RzILOpEffect *op_Bcc(H8300Cmd *cmd, RzILOpPure *cnd) {
	return BRANCH(cnd, JMP(PCREL_OP(0)), NOP());
}

static RzILOpEffect *aop(RzAnalysis *a, RzAnalysisOp *op, H8300Cmd *cmd) {
	switch (cmd->id) {
	case H8300_INSN_MOV_B: return op_mov_b(cmd);
	case H8300_INSN_MOV_W: return op_mov_w(cmd);
	case H8300_INSN_ADD_B: return op_add_b(cmd);
	case H8300_INSN_ADD_W: return op_add_w(cmd);
	case H8300_INSN_ADDS: return op_adds(cmd);
	case H8300_INSN_ADDX: return op_addx(cmd);
	case H8300_INSN_CMP_B:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
			return ccr_cmp_b(R8_OP(1), IMM8_OP(0), IL_FALSE);
		case H8300_INSN_FORMAT_R8R8:
			return ccr_cmp_b(R8_OP(1), R8_OP(0), IL_FALSE);
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_CMP_W:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R16R16:
			return ccr_cmp_w(R16_OP(1), R16_OP(0), IL_FALSE);
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_SUB_B:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R8R8:
			return SEQ4(
				SETL("_0", R8_OP(0)),
				SETL("_1", R8_OP(1)),
				R8_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_sub_b(VARL("_1"), VARL("_0"), IL_FALSE));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_SUB_W:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R16R16:
			return SEQ4(
				SETL("_0", R16_OP(0)),
				SETL("_1", R16_OP(1)),
				R16_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_cmp_w(VARL("_1"), VARL("_0"), IL_FALSE));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_SUBX:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R8R8:
			return SEQ5(
				SETL("_c", ccr_val(CCR_C)),
				SETL("_0", R8_OP(0)),
				SETL("_1", R8_OP(1)),
				R8_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_cmp_b(VARL("_1"), VARL("_0"), VARL("_c")));
		case H8300_INSN_FORMAT_IMMR8:
			return SEQ5(
				SETL("_c", ccr_val(CCR_C)),
				SETL("_0", IMM8_OP(0)),
				SETL("_1", R8_OP(1)),
				R8_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_cmp_b(VARL("_1"), VARL("_0"), VARL("_c")));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_SUBS:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR16:
			return R16_X(1, SUB(R16_OP(1), IMM_OP(0)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_OR: return op_logical2_formats(cmd, rz_il_op_new_log_or);
	case H8300_INSN_XOR: return op_logical2_formats(cmd, rz_il_op_new_log_xor);
	case H8300_INSN_AND: return op_logical2_formats(cmd, rz_il_op_new_log_and);
	case H8300_INSN_NOP:
	case H8300_INSN_SLEEP: return NOP();
	case H8300_INSN_STC: return R8_X(0, VARG("ccr"));
	case H8300_INSN_LDC:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMM:
			return SETG("ccr", IMM8_OP(0));
		case H8300_INSN_FORMAT_R8:
			return SETG("ccr", R8_OP(0));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_ORC: return op_logical_i8ccr(cmd, rz_il_op_new_log_or);
	case H8300_INSN_XORC: return op_logical_i8ccr(cmd, rz_il_op_new_log_xor);
	case H8300_INSN_ANDC: return op_logical_i8ccr(cmd, rz_il_op_new_log_and);
	case H8300_INSN_DEC:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R8:
			return SEQ3(
				SETL("_res", SUB(R8_OP(0), S8(1))),
				R8_X(0, VARL("_res")),
				ccr_unary_NZV(8, VARL("_res"), EQ(VARL("_res"), U8(0x80))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_INC:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R8:
			return SEQ3(
				SETL("_res", ADD(R8_OP(0), U8(1))),
				R8_X(0, VARL("_res")),
				ccr_unary_NZV(8, VARL("_res"), EQ(VARL("_res"), U8(0))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_DAA: return op_daa(cmd);
	case H8300_INSN_DAS: return op_das(cmd);
	case H8300_INSN_SHAL:
		return SEQ3(
			SETL("result", SHIFTL0(R8_OP(0), U8(1))),
			ccr_unary_NZVC(8, VARL("result"),
				XOR(MSB(VARL("result")), MSB(R8_OP(0))),
				MSB(R8_OP(0))),
			R8_X(0, VARL("result")));
	case H8300_INSN_SHAR:
		return SEQ3(
			SETL("result", SHIFTRA(R8_OP(0), U8(1))),
			ccr_unary_NZVC(8, VARL("result"),
				IL_FALSE,
				LSB(R8_OP(0))),
			R8_X(0, VARL("result")));
	case H8300_INSN_SHLL:
		return SEQ3(
			SETL("result", SHIFTL0(R8_OP(0), U8(1))),
			ccr_unary_NZVC(8, VARL("result"),
				IL_FALSE,
				MSB(R8_OP(0))),
			R8_X(0, VARL("result")));
	case H8300_INSN_SHLR:
		return SEQ3(
			SETL("result", SHIFTR0(R8_OP(0), U8(1))),
			ccr_unary_NZVC(8, VARL("result"),
				IL_FALSE,
				LSB(R8_OP(0))),
			R8_X(0, VARL("result")));
	case H8300_INSN_ROTL:
		return SEQ3(
			SETL("result", SHIFTL(MSB(R8_OP(0)), R8_OP(0), U8(1))),
			ccr_unary_NZVC(8, VARL("result"),
				IL_FALSE,
				MSB(R8_OP(0))),
			R8_X(0, VARL("result")));
	case H8300_INSN_ROTR:
		return SEQ3(
			SETL("result", SHIFTR(LSB(R8_OP(0)), R8_OP(0), U8(1))),
			ccr_unary_NZVC(8, VARL("result"),
				IL_FALSE,
				LSB(R8_OP(0))),
			R8_X(0, VARL("result")));
	case H8300_INSN_ROTXL:
		return SEQ3(
			SETL("result", SHIFTL(ccr_val(CCR_C), R8_OP(0), U8(1))),
			ccr_unary_NZVC(8, VARL("result"),
				IL_FALSE,
				MSB(R8_OP(0))),
			R8_X(0, VARL("result")));
	case H8300_INSN_ROTXR:
		return SEQ3(
			SETL("result", SHIFTR(ccr_val(CCR_C), R8_OP(0), U8(1))),
			ccr_unary_NZVC(8, VARL("result"),
				IL_FALSE,
				LSB(R8_OP(0))),
			R8_X(0, VARL("result")));
	case H8300_INSN_NEG:
		return SEQ3(
			SETL("result", NEG(R8_OP(0))),
			ccr_sub_b(S8(0), R8_OP(0), IL_FALSE),
			R8_X(0, VARL("result")));
	case H8300_INSN_NOT:
		return SEQ3(
			SETL("result", LOGNOT(R8_OP(0))),
			ccr_unary_NZV0(8, VARL("result")),
			R8_X(0, VARL("result")));

	case H8300_INSN_BRA:
		return JMP(PCREL_OP(0));
	case H8300_INSN_BRN:
		return NOP();
	case H8300_INSN_BHI:
		return op_Bcc(cmd, INV(OR(ccr_val(CCR_C), ccr_val(CCR_Z))));
	case H8300_INSN_BLS:
		return op_Bcc(cmd, OR(ccr_val(CCR_C), ccr_val(CCR_Z)));
	case H8300_INSN_BCC:
		return op_Bcc(cmd, INV(ccr_val(CCR_C)));
	case H8300_INSN_BCS:
		return op_Bcc(cmd, ccr_val(CCR_C));
	case H8300_INSN_BNE:
		return op_Bcc(cmd, INV(ccr_val(CCR_Z)));
	case H8300_INSN_BEQ:
		return op_Bcc(cmd, ccr_val(CCR_Z));
	case H8300_INSN_BVC:
		return op_Bcc(cmd, INV(ccr_val(CCR_V)));
	case H8300_INSN_BVS:
		return op_Bcc(cmd, ccr_val(CCR_V));
	case H8300_INSN_BPL: return op_Bcc(cmd, INV(ccr_val(CCR_Z)));
	case H8300_INSN_BMI: return op_Bcc(cmd, ccr_val(CCR_Z));
	case H8300_INSN_BGE:
		return op_Bcc(cmd, INV(XOR(ccr_val(CCR_N), ccr_val(CCR_V))));
	case H8300_INSN_BLT:
		return op_Bcc(cmd, XOR(ccr_val(CCR_N), ccr_val(CCR_V)));
	case H8300_INSN_BGT:
		return op_Bcc(cmd, INV(OR(ccr_val(CCR_Z), XOR(ccr_val(CCR_N), ccr_val(CCR_V)))));
	case H8300_INSN_BLE:
		return op_Bcc(cmd, OR(ccr_val(CCR_Z), XOR(ccr_val(CCR_N), ccr_val(CCR_V))));
	case H8300_INSN_MULXU:
		return R16_X(1, MUL(UNSIGNED(16, R8_OP(0)), LOGAND(R16_OP(1), U16(0x00ff))));
	case H8300_INSN_DIVXU:
		return SEQ4(
			SETL("quotient", UNSIGNED(8, DIV(R16_OP(1), UNSIGNED(16, R8_OP(0))))),
			SETL("remainder", UNSIGNED(8, MOD(R16_OP(1), UNSIGNED(16, R8_OP(0))))),
			ccr_unary_NZ(8, R8_OP(0)),
			R16_X(1, APPEND(VARL("remainder"), VARL("quotient"))));
	case H8300_INSN_EEPMOV:
		return SEQ2(
			SETL("i", U8(0)),
			REPEAT(
				ULT(VARL("i"), UNSIGNED(8, VARG("r4"))),
				SEQ2(
					STORE(ADD(VARG("r6"), UNSIGNED(16, VARL("i"))), LOAD(ADD(VARG("r6"), UNSIGNED(16, VARL("i"))))),
					SETL("i", ADD(VARL("i"), U8(1))))));
	case H8300_INSN_RTS:
		return SEQ3(
			SETL("@sp", LOADW(16, VARG("r7"))),
			SETG("r7", ADD(VARG("r7"), U16(2))),
			JMP(VARL("@sp")));
	case H8300_INSN_RTE:
		return SEQ5(
			SETL("_ccr", LOADW(16, VARG("r7"))),
			SETL("_pc", LOADW(16, ADD(VARG("r7"), U16(8)))),
			SETG("r7", ADD(VARG("r7"), U16(4))),
			SETG("ccr", UNSIGNED(8, SHIFTR0(VARL("_ccr"), U8(8)))),
			JMP(VARL("_pc")));
	case H8300_INSN_BSR:
		return SEQ3(
			SETG("r7", SUB(VARG("r7"), U16(2))),
			STOREW(VARG("r7"), PC_VAL),
			JMP(ADD(PC_VAL, PCREL_OP(0))));
	case H8300_INSN_JMP:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_RI16:
			return JMP(LOADW(16, R16_OP(0)));
		case H8300_INSN_FORMAT_ABS:
			return JMP(ABS_OP(0));
		case H8300_INSN_FORMAT_MI8:
			return JMP(LOADW(16, UNSIGNED(16, LOAD(MI8_OP(0)))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_JSR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_RI16:
			return SEQ3(
				SETG("r7", SUB(VARG("r7"), U16(2))),
				STOREW(VARG("r7"), PC_VAL),
				JMP(LOADW(16, R16_OP(0))));
		case H8300_INSN_FORMAT_ABS:
			return SEQ3(
				SETG("r7", SUB(VARG("r7"), U16(2))),
				STOREW(VARG("r7"), PC_VAL),
				JMP(ABS_OP(0)));
		case H8300_INSN_FORMAT_MI8:
			return SEQ3(
				SETG("r7", SUB(VARG("r7"), U16(2))),
				STOREW(VARG("r7"), PC_VAL),
				JMP(LOADW(16, UNSIGNED(16, LOAD(MI8_OP(0))))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BSET:
#define BIT_NO (OPS_GET(0).typ == H8300_OP_IMM ? UNSIGNED(32, IMM8_OP(0)) : UNSIGNED(32, LOGAND(R8_OP(0), U8(0x7))))
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), U32(1)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return STORE(R16_OP(1), DEPOSIT8(LOAD(R16_OP(1)), BIT_NO, U32(1), U32(1)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return STORE(ABS_OP(1), DEPOSIT8(LOAD(ABS_OP(1)), BIT_NO, U32(1), U32(1)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BNOT:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), LOGNOT(EXTRACT1(R8_OP(1), BIT_NO))));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return STORE(R16_OP(1), DEPOSIT8(LOAD(R16_OP(1)), BIT_NO, U32(1), LOGNOT(EXTRACT1(LOAD(R16_OP(1)), BIT_NO))));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return STORE(ABS_OP(1), DEPOSIT8(LOAD(ABS_OP(1)), BIT_NO, U32(1), LOGNOT(EXTRACT1(LOAD(ABS_OP(1)), BIT_NO))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BCLR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), U32(0)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return STORE(R16_OP(1), DEPOSIT8(LOAD(R16_OP(1)), BIT_NO, U32(1), U32(0)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return STORE(ABS_OP(1), DEPOSIT8(LOAD(ABS_OP(1)), BIT_NO, U32(1), U32(0)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BTST:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_Z, EXTRACTb(R8_OP(1), BIT_NO));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_Z, EXTRACTb(LOAD(R16_OP(1)), BIT_NO));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_Z, EXTRACTb(LOAD(ABS_OP(1)), BIT_NO));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BST:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), B_TO_1(ccr_val(CCR_C))));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return STORE(R16_OP(1), DEPOSIT8(LOAD(R16_OP(1)), BIT_NO, U32(1), B_TO_1(ccr_val(CCR_C))));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return STORE(ABS_OP(1), DEPOSIT8(LOAD(ABS_OP(1)), BIT_NO, U32(1), B_TO_1(ccr_val(CCR_C))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BIST:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), LOGNOT(B_TO_1(ccr_val(CCR_C)))));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return STORE(R16_OP(1), DEPOSIT8(LOAD(R16_OP(1)), BIT_NO, U32(1), LOGNOT(B_TO_1(ccr_val(CCR_C)))));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return STORE(ABS_OP(1), DEPOSIT8(LOAD(ABS_OP(1)), BIT_NO, U32(1), LOGNOT(B_TO_1(ccr_val(CCR_C)))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BOR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, OR(EXTRACTb(R8_OP(1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_C, OR(EXTRACTb(LOAD(R16_OP(1)), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, OR(EXTRACTb(LOAD(ABS_OP(1)), BIT_NO), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BIOR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, OR(INV(EXTRACTb(R8_OP(1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_C, OR(INV(EXTRACTb(LOAD(R16_OP(1)), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, OR(INV(EXTRACTb(LOAD(ABS_OP(1)), BIT_NO)), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BAND:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, AND(EXTRACTb(R8_OP(1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_C, AND(EXTRACTb(LOAD(R16_OP(1)), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, AND(EXTRACTb(LOAD(ABS_OP(1)), BIT_NO), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BIAND:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, AND(INV(EXTRACTb(R8_OP(1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_C, AND(INV(EXTRACTb(LOAD(R16_OP(1)), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, AND(INV(EXTRACTb(LOAD(ABS_OP(1)), BIT_NO)), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BLD:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, EXTRACTb(R8_OP(1), BIT_NO));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_C, EXTRACTb(LOAD(R16_OP(1)), BIT_NO));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, EXTRACTb(LOAD(ABS_OP(1)), BIT_NO));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BILD:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, INV(EXTRACTb(R8_OP(1), BIT_NO)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_C, INV(EXTRACTb(LOAD(R16_OP(1)), BIT_NO)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, INV(EXTRACTb(LOAD(ABS_OP(1)), BIT_NO)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BXOR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, XOR(EXTRACTb(R8_OP(1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_C, XOR(EXTRACTb(LOAD(R16_OP(1)), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, XOR(EXTRACTb(LOAD(ABS_OP(1)), BIT_NO), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BIXOR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, XOR(INV(EXTRACTb(R8_OP(1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI16:
		case H8300_INSN_FORMAT_R8RI16:
			return ccr_set(CCR_C, XOR(INV(EXTRACTb(LOAD(R16_OP(1)), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, XOR(INV(EXTRACTb(LOAD(ABS_OP(1)), BIT_NO)), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_POP: break;
	case H8300_INSN_PUSH: break;
	}

	NOT_IMPLEMENTED;
}

int h8300_analyze_op_il(RzAnalysis *a, RzAnalysisOp *op, H8300Cmd *cmd) {
	op->il_op = aop(a, op, cmd);
	return 0;
}

static const char *reg_bindings[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"pc", "ccr", NULL
};

RzAnalysisILConfig *h8300_il_config(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);

	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(16, a->big_endian, 16);
	if (!cfg) {
		return NULL;
	}
	cfg->reg_bindings = reg_bindings;

	return cfg;
}
