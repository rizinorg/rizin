// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "h8300_disas.h"
#include <rz_il/rz_il_opbuilder_begin.h>

#define OPS_GET(I) (cmd->ops[(I)])

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

static RzILOpPure *u16_op(H8300Cmd *cmd, ut8 i) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_IMM && op->typ != H8300_OP_ABS) {
		RZ_LOG_ERROR("invalid op type imm/abs!=%d\n", op->typ);
		return NULL;
	}
	return U16(op->imm);
}

static RzILOpPure *rd16_op(H8300Cmd *cmd, ut8 i) {
	H8300Operand *op = &OPS_GET(i);
	if (op->typ != H8300_OP_RD16) {
		RZ_LOG_ERROR("invalid op type rd16\n");
		return NULL;
	}
	return ADD(VARG(GPRs[op->rd.reg]), S16(op->rd.disp));
}

#define R8_OP(I)    r8_op(cmd, (I))
#define R8_X(I, X)  r8_op_set(cmd, (I), (X))
#define R16_OP(I)   r16_op(cmd, (I))
#define R16_X(I, X) r16_op_set(cmd, (I), (X))
#define U16_OP(I)   u16_op(cmd, (I))
#define U8_OP(I)    UNSIGNED(8, u16_op(cmd, (I)))
#define RD16_OP(I)  rd16_op(cmd, (I))

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

#define B_TO_8(x)  BOOL_TO_BV(x, 8)
#define B_TO_16(x) BOOL_TO_BV(x, 16)
#define B_TO_32(x) BOOL_TO_BV(x, 32)

static RzILOpBool *ccr_val(CCR_BIT bit) {
	return NON_ZERO(EXTRACT32(UNSIGNED(32, VARG("ccr")), U32(bit), U32(1)));
}

static RzILOpEffect *ccr_set(CCR_BIT bit, RzILOpBool *x) {
	return SETG("ccr", DEPOSIT8(VARG("ccr"), U32(bit), U32(1), B_TO_16(x)));
}

static RzILOpEffect *ccr_unary(ut8 N, RzILOpPure *x) {
	return SEQ3(
		ccr_set(CCR_N, SLT(x, UN(N, 0))),
		ccr_set(CCR_Z, IS_ZERO(DUP(x))),
		ccr_set(CCR_V, IL_FALSE));
}

static RzILOpEffect *op_mov_b(H8300Cmd *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R8R8:
		return SEQ3(
			SETL("data_value", R8_OP(0)),
			R8_X(1, VARL("data_value")),
			ccr_unary(8, VARL("data_value")));
	case H8300_INSN_FORMAT_ABSR8:
		return SEQ2(R8_X(1, LOAD(U16_OP(0))), ccr_unary(8, LOAD(U16_OP(0))));
	case H8300_INSN_FORMAT_R8ABS:
		return SEQ2(STORE(U16_OP(1), R8_OP(0)), ccr_unary(8, R8_OP(0)));
	case H8300_INSN_FORMAT_IMMR8:
		return SEQ2(R8_X(1, U8_OP(0)), ccr_unary(8, U8_OP(0)));
	case H8300_INSN_FORMAT_R8RI16:
		return SEQ2(STORE(R16_OP(1), R8_OP(0)), ccr_unary(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RI16R8:
		return SEQ2(R8_X(1, LOAD(R16_OP(0))), ccr_unary(8, LOAD(R16_OP(0))));
	case H8300_INSN_FORMAT_R8RD16:
		return SEQ2(STORE(RD16_OP(1), R8_OP(0)), ccr_unary(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RD16R8:
		return SEQ2(R8_X(1, LOAD(RD16_OP(0))), ccr_unary(8, LOAD(RD16_OP(0))));
	case H8300_INSN_FORMAT_R8RDEC:
		return SEQ3(
			R16_X(1, SUB(R16_OP(1), U16(1))),
			STORE(R16_OP(1), R8_OP(0)),
			ccr_unary(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RINCR8:
		return SEQ3(
			R8_X(1, LOAD(R16_OP(0))),
			R16_X(0, ADD(U16(1), R16_OP(0))),
			ccr_unary(8, LOAD(R16_OP(0))));
	default: NOT_IMPLEMENTED;
	}
}

static RzILOpEffect *op_mov_w(H8300Cmd *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R16R16:
		return SEQ3(
			SETL("data_value", R16_OP(0)),
			R16_X(1, VARL("data_value")),
			ccr_unary(16, VARL("data_value")));
	case H8300_INSN_FORMAT_IMMR16:
		return SEQ2(R16_X(1, U16_OP(0)), ccr_unary(16, U16_OP(0)));
	case H8300_INSN_FORMAT_RI16R16:
		return SEQ3(
			SETL("data_value", LOADW(16, R16_OP(0))),
			R16_X(1, VARL("data_value")),
			ccr_unary(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16RI16:
		return SEQ2(STOREW(R16_OP(1), R16_OP(0)), ccr_unary(16, R16_OP(0)));
	case H8300_INSN_FORMAT_ABSR16:
		return SEQ3(
			SETL("data_value", LOADW(16, U16_OP(0))),
			R16_X(1, VARL("data_value")),
			ccr_unary(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16ABS:
		return SEQ2(STOREW(U16_OP(1), R16_OP(0)), ccr_unary(16, R16_OP(0)));
	case H8300_INSN_FORMAT_R16RD16:
		return SEQ2(STOREW(RD16_OP(1), R16_OP(0)), ccr_unary(16, R16_OP(0)));
	case H8300_INSN_FORMAT_RD16R16:
		return SEQ3(
			SETL("data_value", LOADW(16, RD16_OP(0))),
			R16_X(1, VARL("data_value")),
			ccr_unary(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16RDEC:
		return SEQ3(
			R16_X(1, SUB(R16_OP(1), U16(1))),
			STOREW(R16_OP(1), R16_OP(0)),
			ccr_unary(16, R16_OP(0)));
	case H8300_INSN_FORMAT_RINCR16:
		return SEQ4(
			R16_X(1, LOADW(16, R16_OP(0))),
			SETL("data_value", ADD(U16(1), R16_OP(0))),
			R16_X(0, ADD(U16(1), R16_OP(0))),
			ccr_unary(16, VARL("data_value")));
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
			SETL("_0", U8_OP(0)),
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
		return R16_X(1, ADD(U16_OP(0), R16_OP(1)));
	default: NOT_IMPLEMENTED;
	}
}

static RzILOpEffect *op_addx(H8300Cmd *cmd) {
	RzILOpBool *C = ccr_val(CCR_C);
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_IMMR8:
		return SEQ5(
			SETL("_c", C),
			SETL("_0", U8_OP(0)),
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
		ccr_unary(8, VARL("_res")));
}

static RzILOpEffect *op_logical2_formats(H8300Cmd *cmd, op2 f) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_IMMR8:
		return op_logical2(cmd, U8_OP(0), R8_OP(1), f, r8_op_set);
	case H8300_INSN_FORMAT_R8R8:
		return op_logical2(cmd, R8_OP(0), R8_OP(1), f, r8_op_set);
	default: NOT_IMPLEMENTED;
	}
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
			return ccr_cmp_b(R8_OP(1), U8_OP(0), IL_FALSE);
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
				SETL("_0", U8_OP(0)),
				SETL("_1", R8_OP(1)),
				R8_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_cmp_b(VARL("_1"), VARL("_0"), VARL("_c")));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_SUBS:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR16:
			return R16_X(1, SUB(R16_OP(1), U16_OP(0)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_OR: return op_logical2_formats(cmd, rz_il_op_new_log_or);
	case H8300_INSN_XOR: return op_logical2_formats(cmd, rz_il_op_new_log_xor);
	case H8300_INSN_AND: return op_logical2_formats(cmd, rz_il_op_new_log_and);
	case H8300_INSN_NOP:
	case H8300_INSN_SLEEP: return NOP();
	case H8300_INSN_STC: return R8_X(0, VARG("ccr"));
	case H8300_INSN_LDC: break;
	case H8300_INSN_ORC: break;
	case H8300_INSN_XORC: break;
	case H8300_INSN_ANDC: break;
	case H8300_INSN_INC: break;
	case H8300_INSN_DAA: break;
	case H8300_INSN_SHL: break;
	case H8300_INSN_SHR: break;
	case H8300_INSN_ROTL: break;
	case H8300_INSN_ROTR: break;
	case H8300_INSN_NEG: break;
	case H8300_INSN_DEC: break;
	case H8300_INSN_DAS: break;
	case H8300_INSN_BRA: break;
	case H8300_INSN_BRN: break;
	case H8300_INSN_BHI: break;
	case H8300_INSN_BLS: break;
	case H8300_INSN_BCC: break;
	case H8300_INSN_BCS: break;
	case H8300_INSN_BNE: break;
	case H8300_INSN_BEQ: break;
	case H8300_INSN_BVC: break;
	case H8300_INSN_BVS: break;
	case H8300_INSN_BPL: break;
	case H8300_INSN_BMI: break;
	case H8300_INSN_BGE: break;
	case H8300_INSN_BLT: break;
	case H8300_INSN_BGT: break;
	case H8300_INSN_BLE: break;
	case H8300_INSN_MULXU: break;
	case H8300_INSN_DIVXU: break;
	case H8300_INSN_RTS: break;
	case H8300_INSN_BSR: break;
	case H8300_INSN_RTE: break;
	case H8300_INSN_JMP: break;
	case H8300_INSN_JSR: break;
	case H8300_INSN_BSET: break;
	case H8300_INSN_BNOT: break;
	case H8300_INSN_BCLR: break;
	case H8300_INSN_BTST: break;
	case H8300_INSN_BST: break;
	case H8300_INSN_BIST: break;
	case H8300_INSN_BIOR: break;
	case H8300_INSN_BXOR: break;
	case H8300_INSN_BAND: break;
	case H8300_INSN_BIAND: break;
	case H8300_INSN_BILD: break;
	case H8300_INSN_EEPMOV: break;
	case H8300_INSN_BOR: break;
	case H8300_INSN_BIXOR: break;
	case H8300_INSN_BLD: break;
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
