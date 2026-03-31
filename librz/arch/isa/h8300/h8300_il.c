// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "h8300_disas.h"
#include <rz_il/rz_il_opbuilder_begin.h>

#define INS_OPS(I)  (cmd->ops[(I)])
#define PC_VAL      UADDR(cmd->pc)
#define PC_NEXT_VAL UADDR(cmd->pc + cmd->size)

#define T_OP_DECL(T, I) \
	H8300Operand *op = &INS_OPS(i); \
	if (op->typ != T) { \
		RZ_LOG_ERROR("invalid op type " #T "\n"); \
		return NULL; \
	}

#define DEPOSIT16(V, S, L, F) UNSIGNED(16, DEPOSIT32(UNSIGNED(32, V), S, L, UNSIGNED(32, F)))
#define DEPOSIT8(V, S, L, F)  UNSIGNED(8, DEPOSIT32(UNSIGNED(32, V), S, L, UNSIGNED(32, F)))
#define EXTRACT1(V, S)        UNSIGNED(1, EXTRACT32(UNSIGNED(32, V), S, U32(1)))
#define EXTRACTb(V, S)        NON_ZERO(EXTRACT32(UNSIGNED(32, V), S, U32(1)))
#define UADDR(X)              UN(24, X)
#define AS_ADDR(X)            UNSIGNED(24, X)

static inline ut8 r16_index_from_r8_register(H8300Register reg) {
	return (reg - H8300_REG8_BEGIN) % 8 + H8300_REG16_BEGIN;
}

static inline RzILOpPure *r8_op_i(ut8 index) {
	rz_return_val_if_fail(index >= H8300_R0H && index <= H8300_R7L, NULL);
	ut8 i = r16_index_from_r8_register(index);
	bool low = index > H8300_R7H;
	RzILOpPure *x = VARG(h8300_get_register_name(i));
	return low ? UNSIGNED(8, x) : UNSIGNED(8, SHIFTR0(x, U8(8)));
}

static inline RzILOpEffect *r8_op_i_set(ut8 index, RzILOpPure *x) {
	rz_return_val_if_fail(index >= H8300_R0H && index <= H8300_R7L, NULL);
	ut8 i = r16_index_from_r8_register(index);
	bool low = index > H8300_R7H;
	return SETG(h8300_get_register_name(i),
		DEPOSIT16(VARG(h8300_get_register_name(i)), low ? U32(0) : U32(8), U32(8), x));
}

static inline RzILOpPure *r8_op(H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_R8, i);
	return r8_op_i(op->reg);
}

static inline RzILOpEffect *r8_op_set(H8300Instruction *cmd, ut8 i, RzILOpPure *x) {
	T_OP_DECL(H8300_OP_R8, i);
	return r8_op_i_set(op->reg, x);
}

static inline RzILOpPure *r16_op_i(ut8 index) {
	rz_return_val_if_fail(index >= H8300_R0 && index <= H8300_E7, NULL);
	return VARG(h8300_get_register_name(index));
}

static inline RzILOpEffect *r16_op_i_set(ut8 index, RzILOpPure *x) {
	rz_return_val_if_fail(index >= H8300_R0 && index <= H8300_E7, NULL);
	return SETG(h8300_get_register_name(index), x);
}

static inline RzILOpPure *r16_op(H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_R16, i);
	return r16_op_i(op->reg);
}

static inline RzILOpEffect *r16_op_set(H8300Instruction *cmd, ut8 i, RzILOpPure *x) {
	T_OP_DECL(H8300_OP_R16, i);
	return r16_op_i_set(op->reg, x);
}

static inline ut8 r16_index_from_r32_register(H8300Register reg) {
	return reg - H8300_REG32_BEGIN + H8300_REG16_BEGIN;
}

static inline RzILOpPure *r32_op_i(ut8 index) {
	rz_return_val_if_fail(index >= H8300_ER0 && index <= H8300_ER7, NULL);
	index = r16_index_from_r32_register(index);
	return APPEND(
		VARG(h8300_get_register_name(index + 8)),
		VARG(h8300_get_register_name(index)));
}

static inline RzILOpEffect *r32_op_i_set(ut8 index, RzILOpPure *x) {
	rz_return_val_if_fail(index >= H8300_ER0 && index <= H8300_ER7, NULL);
	index = r16_index_from_r32_register(index);
	return SEQ2(
		SETG(h8300_get_register_name(index + 8), UNSIGNED(16, SHIFTR0(x, U8(16)))),
		SETG(h8300_get_register_name(index), UNSIGNED(16, DUP(x))));
}

static inline RzILOpPure *r32_op(H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_R32, i);
	return r32_op_i(op->reg);
}

static inline RzILOpEffect *r32_op_set(H8300Instruction *cmd, ut8 i, RzILOpPure *x) {
	T_OP_DECL(H8300_OP_R32, i);
	return r32_op_i_set(op->reg, x);
}

static inline RzILOpPure *rpostinc_op(H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_RPOSTINC, i);
	return cmd->cpu_type == CPU_H8300H ? r32_op_i(op->reg) : r16_op_i(op->reg);
}

static inline RzILOpEffect *rpostinc_op_inc(H8300Instruction *cmd, ut8 i, ut8 x) {
	T_OP_DECL(H8300_OP_RPOSTINC, i);
	return cmd->cpu_type == CPU_H8300H
		? r32_op_i_set(op->reg, ADD(r32_op_i(op->reg), U32(x)))
		: r16_op_i_set(op->reg, ADD(r16_op_i(op->reg), U16(x)));
}

static inline RzILOpPure *rpredec_op(H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_RPREDEC, i);
	return cmd->cpu_type == CPU_H8300H ? r32_op_i(op->reg) : r16_op_i(op->reg);
}

static inline RzILOpEffect *rpredec_op_dec(H8300Instruction *cmd, ut8 i, ut8 x) {
	T_OP_DECL(H8300_OP_RPREDEC, i);
	return cmd->cpu_type == CPU_H8300H
		? r32_op_i_set(op->reg, SUB(r32_op_i(op->reg), U32(x)))
		: r16_op_i_set(op->reg, SUB(r16_op_i(op->reg), U16(x)));
}

static inline RzILOpPure *ri_op(ut8 N, H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_RI, i);
	return LOADW(N, AS_ADDR(INS_OPS(i).width == H8300Operand_32 ? r32_op_i(op->reg) : r16_op_i(op->reg)));
}

static inline RzILOpEffect *ri_op_set(H8300Instruction *cmd, ut8 i, RzILOpPure *x) {
	T_OP_DECL(H8300_OP_RI, i);
	return STOREW(AS_ADDR(INS_OPS(i).width == H8300Operand_32 ? r32_op_i(op->reg) : r16_op_i(op->reg)), x);
}

static inline RzILOpPure *rd_adr(H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_RD, i);
	switch (op->width) {
	case H8300Operand_16: {
		RzILOpPure *r = r16_op_i(op->rd.reg);
		return AS_ADDR(ADD(r, S16(op->rd.disp)));
	}
	case H8300Operand_32: {
		RzILOpPure *r = r32_op_i(op->rd.reg);
		return AS_ADDR(ADD(r, S32(op->rd.disp)));
	}
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

static inline RzILOpPure *rd_op(ut8 N, H8300Instruction *cmd, ut8 i) {
	RzILOpPure *adr = rd_adr(cmd, i);
	if (!adr) {
		return NULL;
	}
	return LOADW(N, adr);
}

static inline RzILOpEffect *rd_op_set(H8300Instruction *cmd, ut8 i, RzILOpPure *x) {
	RzILOpPure *adr = rd_adr(cmd, i);
	if (!adr) {
		return NULL;
	}
	return STOREW(adr, x);
}

static inline RzILOpPure *abs_op(ut8 N, H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_ABS, i);
	return LOADW(N, UADDR(op->imm));
}

static inline RzILOpEffect *abs_op_set(H8300Instruction *cmd, ut8 i, RzILOpPure *x) {
	T_OP_DECL(H8300_OP_ABS, i);
	return STOREW(UADDR(op->imm), x);
}

static inline RzILOpPure *pc_rel_op(H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_PCREL, i);
	st32 dst = (st32)cmd->pc + cmd->size + op->disp;
	return UADDR(dst);
}

static inline RzILOpPure *imm_op(ut8 N, H8300Instruction *cmd, ut8 i) {
	T_OP_DECL(H8300_OP_IMM, i);
	return UN(N, op->imm);
}

#define X_OP_GET_IMPL(E, T, X) \
	static RzILOpPure *X##_op(H8300Instruction *cmd, ut8 i) { \
		H8300Operand *op = &INS_OPS(i); \
		if (op->typ != E) { \
			RZ_LOG_ERROR("invalid op type " #E "\n"); \
			return NULL; \
		} \
		return T(op->imm); \
	}

X_OP_GET_IMPL(H8300_OP_MI8, UADDR, mi8);

#define IMM_OP(N, I) imm_op(N, cmd, I)
#define IMM8_OP(I)   imm_op(8, cmd, I)
#define IMM16_OP(I)  imm_op(16, cmd, I)
#define IMM32_OP(I)  imm_op(32, cmd, I)
#define MI8_OP(I)    mi8_op(cmd, I)
#define RD_OP(N, I)  rd_op(N, cmd, (I))
#define PCREL_OP(I)  pc_rel_op(cmd, (I))

#define R8_OP(I)      r8_op(cmd, (I))
#define R8_X(I, X)    r8_op_set(cmd, (I), (X))
#define R16_OP(I)     r16_op(cmd, (I))
#define R16_X(I, X)   r16_op_set(cmd, (I), (X))
#define R32_OP(I)     r32_op(cmd, (I))
#define R32_OP_I(I)   r32_op_i((INS_OPS(I).reg))
#define R32_X(I, X)   r32_op_set(cmd, (I), (X))
#define R32_I_X(I, X) r32_op_i_set((INS_OPS(I).reg), (X))

static inline RzILOpPure *rx_op_i(ut8 N, ut8 I) {
	switch (N) {
	case 8: return r8_op_i(I);
	case 16: return r16_op_i(I);
	case 32: return r32_op_i(I);
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *rx_op_i_set(ut8 N, ut8 I, RzILOpPure *x) {
	switch (N) {
	case 8: return r8_op_i_set(I, x);
	case 16: return r16_op_i_set(I, x);
	case 32: return r32_op_i_set(I, x);
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpPure *rx_op(H8300Instruction *cmd, ut8 N, ut8 I) {
	switch (N) {
	case 8: return R8_OP(I);
	case 16: return R16_OP(I);
	case 32: return R32_OP(I);
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *rx_op_set(H8300Instruction *cmd, ut8 N, ut8 I, RzILOpPure *x) {
	switch (N) {
	case 8: return r8_op_set(cmd, I, x);
	case 16: return r16_op_set(cmd, I, x);
	case 32: return r32_op_set(cmd, I, x);
	default: NOT_IMPLEMENTED;
	}
}

#define RX_OP(N, I)   rx_op(cmd, N, I)
#define RX_X(N, I, X) rx_op_set(cmd, N, I, X)

static inline ut8 sp_index_from_cpu_type(int cpu_type) {
	return cpu_type == CPU_H8300H ? H8300H_SP : H8300_SP;
}

static inline ut8 sp_width_from_cpu_type(int cpu_type) {
	return cpu_type == CPU_H8300H ? 32 : 16;
}

static inline RzILOpPure *sp_op(const H8300Instruction *cmd) {
	return cmd->cpu_type == CPU_H8300H ? r32_op_i(H8300H_SP) : r16_op_i(H8300_SP);
}

static inline RzILOpPure *sp_op_as_adr(const H8300Instruction *cmd) {
	return AS_ADDR(sp_op(cmd));
}

static inline RzILOpEffect *sp_set(const H8300Instruction *cmd, RzILOpPure *x) {
	return STOREW(sp_op_as_adr(cmd), x);
}

static inline RzILOpEffect *sp_dec(const H8300Instruction *cmd, ut8 x) {
	return rx_op_i_set(sp_width_from_cpu_type(cmd->cpu_type), sp_index_from_cpu_type(cmd->cpu_type),
		SUB(sp_op(cmd), UN(sp_width_from_cpu_type(cmd->cpu_type), x)));
}

static inline RzILOpEffect *sp_inc(const H8300Instruction *cmd, ut8 x) {
	return rx_op_i_set(sp_width_from_cpu_type(cmd->cpu_type), sp_index_from_cpu_type(cmd->cpu_type),
		ADD(sp_op(cmd), UN(sp_width_from_cpu_type(cmd->cpu_type), x)));
}

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

static inline RzILOpBool *ccr_val(CCR_BIT bit) {
	return NON_ZERO(EXTRACT32(UNSIGNED(32, VARG("ccr")), U32(bit), U32(1)));
}

static inline RzILOpEffect *ccr_set(CCR_BIT bit, RzILOpBool *x) {
	return SETG("ccr", DEPOSIT8(VARG("ccr"), U32(bit), U32(1), B_TO_16(x)));
}

static inline RzILOpEffect *ccr_NZV(ut8 N, RzILOpBool *n, RzILOpBool *z, RzILOpBool *v) {
	return SEQ3(
		ccr_set(CCR_N, n),
		ccr_set(CCR_Z, z),
		ccr_set(CCR_V, v));
}

static inline RzILOpEffect *ccr_xNZ(ut8 N, RzILOpPure *x) {
	return SEQ2(
		ccr_set(CCR_N, SLT(x, UN(N, 0))),
		ccr_set(CCR_Z, IS_ZERO(DUP(x))));
}

static inline RzILOpEffect *ccr_xNZV(ut8 N, RzILOpPure *x, RzILOpBool *v) {
	return SEQ2(
		ccr_xNZ(N, x),
		ccr_set(CCR_V, v));
}

static inline RzILOpEffect *ccr_xNZVC(ut8 N, RzILOpPure *x, RzILOpBool *v, RzILOpBool *c) {
	return SEQ2(
		ccr_xNZV(N, x, v),
		ccr_set(CCR_C, c));
}

#define ccr_xNZV0(N, X) ccr_xNZV(N, X, IL_FALSE)

static inline RzILOpEffect *op_mov_b(H8300Instruction *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R8R8:
		return SEQ3(
			SETL("data_value", R8_OP(0)),
			R8_X(1, VARL("data_value")),
			ccr_xNZV0(8, VARL("data_value")));
	case H8300_INSN_FORMAT_ABSR8:
		return SEQ2(R8_X(1, abs_op(8, cmd, 0)), ccr_xNZV0(8, abs_op(8, cmd, 0)));
	case H8300_INSN_FORMAT_ABSR16:
		return SEQ2(R16_X(1, abs_op(16, cmd, 0)), ccr_xNZV0(16, abs_op(16, cmd, 0)));
	case H8300_INSN_FORMAT_R8ABS:
		return SEQ2(abs_op_set(cmd, 1, R8_OP(0)), ccr_xNZV0(8, R8_OP(0)));
	case H8300_INSN_FORMAT_IMMR8:
		return SEQ2(R8_X(1, IMM8_OP(0)), ccr_xNZV0(8, IMM8_OP(0)));
	case H8300_INSN_FORMAT_R8RI:
		return SEQ2(ri_op_set(cmd, 1, R8_OP(0)), ccr_xNZV0(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RIR8:
		return SEQ2(R8_X(1, ri_op(8, cmd, 0)), ccr_xNZV0(8, ri_op(8, cmd, 0)));
	case H8300_INSN_FORMAT_R8RD:
		return SEQ2(rd_op_set(cmd, 1, R8_OP(0)), ccr_xNZV0(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RDR8:
		return SEQ2(R8_X(1, RD_OP(8, 0)), ccr_xNZV0(8, RD_OP(8, 0)));
	case H8300_INSN_FORMAT_R8RDEC:
		return SEQ3(
			rpredec_op_dec(cmd, 1, 1),
			STORE(AS_ADDR(rpredec_op(cmd, 1)), R8_OP(0)),
			ccr_xNZV0(8, R8_OP(0)));
	case H8300_INSN_FORMAT_RINCR8:
		return SEQ3(
			R8_X(1, LOAD(AS_ADDR(rpostinc_op(cmd, 0)))),
			rpostinc_op_inc(cmd, 0, 1),
			ccr_xNZV0(8, R8_OP(1)));
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *op_mov_w(H8300Instruction *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R16R16:
		return SEQ3(
			SETL("data_value", R16_OP(0)),
			R16_X(1, VARL("data_value")),
			ccr_xNZV0(16, VARL("data_value")));
	case H8300_INSN_FORMAT_IMMR16:
		return SEQ2(R16_X(1, IMM_OP(16, 0)), ccr_xNZV0(16, IMM_OP(16, 0)));
	case H8300_INSN_FORMAT_RIR16:
		return SEQ3(
			SETL("data_value", ri_op(16, cmd, 0)),
			R16_X(1, VARL("data_value")),
			ccr_xNZV0(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16RI:
		return SEQ2(ri_op_set(cmd, 1, R16_OP(0)), ccr_xNZV0(16, R16_OP(0)));
	case H8300_INSN_FORMAT_ABSR16:
		return SEQ3(
			SETL("data_value", abs_op(16, cmd, 0)),
			R16_X(1, VARL("data_value")),
			ccr_xNZV0(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16ABS:
		return SEQ2(abs_op_set(cmd, 1, R16_OP(0)), ccr_xNZV0(16, R16_OP(0)));
	case H8300_INSN_FORMAT_R16RD:
		return SEQ2(rd_op_set(cmd, 1, R16_OP(0)), ccr_xNZV0(16, R16_OP(0)));
	case H8300_INSN_FORMAT_RDR16:
		return SEQ3(
			SETL("data_value", RD_OP(16, 0)),
			R16_X(1, VARL("data_value")),
			ccr_xNZV0(16, VARL("data_value")));
	case H8300_INSN_FORMAT_R16RDEC:
		return SEQ3(
			rpredec_op_dec(cmd, 1, 2),
			STOREW(AS_ADDR(rpredec_op(cmd, 1)), R16_OP(0)),
			ccr_xNZV0(16, R16_OP(0)));
	case H8300_INSN_FORMAT_RINCR16:
		return SEQ4(
			SETL("data_value", LOADW(16, AS_ADDR(rpostinc_op(cmd, 0)))),
			R16_X(1, VARL("data_value")),
			rpostinc_op_inc(cmd, 0, 2),
			ccr_xNZV0(16, VARL("data_value")));
	default:
		NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *op_mov_l(H8300Instruction *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R32R32:
		return SEQ3(
			SETL("data_value", R32_OP(0)),
			R32_X(1, VARL("data_value")),
			ccr_xNZV0(32, VARL("data_value")));
	case H8300_INSN_FORMAT_IMMR32:
		return SEQ2(R32_X(1, IMM_OP(32, 0)), ccr_xNZV0(32, IMM_OP(32, 0)));
	case H8300_INSN_FORMAT_RIR32:
		return SEQ3(
			SETL("data_value", ri_op(32, cmd, 0)),
			R32_X(1, VARL("data_value")),
			ccr_xNZV0(32, VARL("data_value")));
	case H8300_INSN_FORMAT_R32RI:
		return SEQ2(ri_op_set(cmd, 1, R32_OP(0)), ccr_xNZV0(32, R32_OP(0)));
	case H8300_INSN_FORMAT_ABSR32:
		return SEQ3(
			SETL("data_value", abs_op(32, cmd, 0)),
			R32_X(1, VARL("data_value")),
			ccr_xNZV0(32, VARL("data_value")));
	case H8300_INSN_FORMAT_R32ABS:
		return SEQ2(abs_op_set(cmd, 1, R32_OP(0)), ccr_xNZV0(32, R32_OP(0)));
	case H8300_INSN_FORMAT_R32RD:
		return SEQ2(rd_op_set(cmd, 1, R32_OP(0)), ccr_xNZV0(32, R32_OP(0)));
	case H8300_INSN_FORMAT_RDR32:
		return SEQ3(
			SETL("data_value", RD_OP(32, 0)),
			R32_X(1, VARL("data_value")),
			ccr_xNZV0(32, VARL("data_value")));
	case H8300_INSN_FORMAT_R32RDEC:
		return SEQ3(
			rpredec_op_dec(cmd, 1, 4),
			STOREW(AS_ADDR(rpredec_op(cmd, 1)), R32_OP(0)),
			ccr_xNZV0(32, R32_OP(0)));
	case H8300_INSN_FORMAT_RINCR32:
		return SEQ4(
			SETL("data_value", LOADW(32, AS_ADDR(rpostinc_op(cmd, 0)))),
			R32_X(1, VARL("data_value")),
			rpostinc_op_inc(cmd, 0, 4),
			ccr_xNZV0(32, VARL("data_value")));
	default:
		NOT_IMPLEMENTED;
	}
}

#define BEQ(X, Y)     INV(XOR(X, Y))
#define BNE(X, Y)     XOR(X, Y)
#define ADD3(X, Y, Z) ADD(X, ADD(Y, Z))
#define SUB3(X, Y, Z) SUB(X, ADD(Y, Z))

static inline RzILOpEffect *ccr_add(RzILOpPure *a, RzILOpPure *b, RzILOpBool *c, ut8 n, ut8 carry_h, ut8 carry_c) {
	RzILOpPure *lown = ADD3(LOGAND(a, UN(n, (1ULL << (carry_h + 1)) - 1)),
		LOGAND(b, UN(n, (1ULL << (carry_h + 1)) - 1)), BOOL_TO_BV(c, n));
	RzILOpPure *H = NON_ZERO(LOGAND(lown, UN(n, 1ULL << (carry_h + 1))));

	RzILOpPure *sum = ADD3(UNSIGNED(n * 2, DUP(a)), UNSIGNED(n * 2, DUP(b)), BOOL_TO_BV(DUP(c), n * 2));
	RzILOpPure *N = NON_ZERO(LOGAND(sum, UN(n * 2, 1ULL << (n - 1))));
	RzILOpPure *Z = IS_ZERO(DUP(sum));
	RzILOpPure *C = NON_ZERO(LOGAND(DUP(sum), UN(n * 2, 1ULL << (carry_c + 1))));
	RzILOpPure *V = AND(BEQ(MSB(DUP(a)), MSB(DUP(b))), BNE(MSB(DUP(a)), DUP(N)));
	return SEQ5(
		ccr_set(CCR_H, H),
		ccr_set(CCR_N, N),
		ccr_set(CCR_Z, Z),
		ccr_set(CCR_C, C),
		ccr_set(CCR_V, V));
}

static inline RzILOpEffect *ccr_sub(RzILOpPure *a, RzILOpPure *b, RzILOpBool *c, ut8 n, ut8 carry_h, ut8 carry_c) {
	RzILOpPure *lown = SUB3(LOGAND(a, UN(n, (1ULL << (carry_h + 1)) - 1)),
		LOGAND(b, UN(n, (1ULL << (carry_h + 1)) - 1)), BOOL_TO_BV(c, n));
	RzILOpPure *H = NON_ZERO(LOGAND(lown, UN(n, 1ULL << (carry_h + 1))));

	RzILOpPure *res = SUB3(SIGNED(n * 2, DUP(a)), SIGNED(n * 2, DUP(b)), BOOL_TO_BV(DUP(c), n * 2));
	RzILOpPure *N = NON_ZERO(LOGAND(res, UN(n * 2, 1ULL << (n - 1))));
	RzILOpPure *Z = IS_ZERO(DUP(res));
	RzILOpPure *C = SLT(DUP(res), SN(n * 2, 0));
	RzILOpPure *V = AND(BNE(MSB(DUP(a)), MSB(DUP(b))), BNE(MSB(DUP(a)), DUP(N)));
	return SEQ5(
		ccr_set(CCR_H, H),
		ccr_set(CCR_N, N),
		ccr_set(CCR_Z, Z),
		ccr_set(CCR_C, C),
		ccr_set(CCR_V, V));
}

#define ccr_add_b(A, B, C) ccr_add(A, B, C, 8, 3, 7)
#define ccr_add_w(A, B, C) ccr_add(A, B, C, 16, 11, 15)
#define ccr_add_l(A, B, C) ccr_add(A, B, C, 32, 27, 31)
#define ccr_sub_b(A, B, C) ccr_sub(A, B, C, 8, 3, 7)
#define ccr_sub_w(A, B, C) ccr_sub(A, B, C, 16, 11, 15)
#define ccr_sub_l(A, B, C) ccr_sub(A, B, C, 32, 27, 31)

static inline RzILOpEffect *op_add_b(H8300Instruction *cmd) {
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

static inline RzILOpEffect *op_add_w(H8300Instruction *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R16R16:
		return SEQ4(
			SETL("_0", R16_OP(0)),
			SETL("_1", R16_OP(1)),
			R16_X(1, ADD(VARL("_0"), VARL("_1"))),
			ccr_add(VARL("_0"), VARL("_1"), IL_FALSE, 16, 11, 15));
	case H8300_INSN_FORMAT_IMMR16:
		return SEQ4(
			SETL("_0", IMM_OP(16, 0)),
			SETL("_1", R16_OP(1)),
			R16_X(1, ADD(VARL("_0"), VARL("_1"))),
			ccr_add(VARL("_0"), VARL("_1"), IL_FALSE, 16, 11, 15));
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *op_add_l(H8300Instruction *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R32R32:
		return SEQ4(
			SETL("_0", R32_OP(0)),
			SETL("_1", R32_OP(1)),
			R32_X(1, ADD(VARL("_0"), VARL("_1"))),
			ccr_add(VARL("_0"), VARL("_1"), IL_FALSE, 32, 27, 31));
	case H8300_INSN_FORMAT_IMMR32:
		return SEQ4(
			SETL("_0", IMM_OP(32, 0)),
			SETL("_1", R32_OP(1)),
			R32_X(1, ADD(VARL("_0"), VARL("_1"))),
			ccr_add(VARL("_0"), VARL("_1"), IL_FALSE, 32, 27, 31));
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *op_adds(H8300Instruction *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_IMMR16:
		return R16_X(1, ADD(IMM_OP(16, 0), R16_OP(1)));
	case H8300_INSN_FORMAT_IMMR32:
		return R32_X(1, ADD(IMM_OP(32, 0), R32_OP(1)));
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *op_addx(H8300Instruction *cmd) {
	RzILOpBool *C = ccr_val(CCR_C);
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_IMMR8:
		return SEQ5(
			SETL("_c", C),
			SETL("_0", IMM8_OP(0)),
			SETL("_1", R8_OP(1)),
			R8_X(1, ADD3(VARL("_0"), VARL("_1"), B_TO_8(VARL("_c")))),
			ccr_add_b(VARL("_0"), VARL("_1"), VARL("_c"))

		);
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

static inline RzILOpEffect *ccr_cmp(RzILOpPure *a, RzILOpPure *b, RzILOpBool *c, ut8 n, ut8 carry_h, ut8 carry_c) {
	RzILOpPure *lown = ADD3(LOGAND(a, UN(n, (1ULL << (carry_h + 1)) - 1)),
		LOGAND(b, UN(n, (1ULL << (carry_h + 1)) - 1)), BOOL_TO_BV(c, n));
	RzILOpPure *H = NON_ZERO(LOGAND(lown, UN(n, 1ULL << (carry_h + 1))));

	RzILOpPure *res = SUB3(SIGNED(n * 2, DUP(a)), SIGNED(n * 2, DUP(b)), BOOL_TO_BV(DUP(c), n * 2));
	RzILOpPure *N = NON_ZERO(LOGAND(res, UN(n * 2, 1ULL << (n - 1))));
	RzILOpPure *Z = IS_ZERO(DUP(res));
	RzILOpPure *C = ULT(DUP(a), DUP(b));
	RzILOpPure *V = AND(BNE(MSB(DUP(a)), MSB(DUP(b))), BNE(MSB(DUP(a)), DUP(N)));
	return SEQ5(
		ccr_set(CCR_H, H),
		ccr_set(CCR_N, N),
		ccr_set(CCR_Z, Z),
		ccr_set(CCR_C, C),
		ccr_set(CCR_V, V));
}

#define ccr_cmp_b(a, b) ccr_cmp(a, b, IL_FALSE, 8, 3, 7)
#define ccr_cmp_w(a, b) ccr_cmp(a, b, IL_FALSE, 16, 11, 15)
#define ccr_cmp_l(a, b) ccr_cmp(a, b, IL_FALSE, 32, 27, 31)

typedef RzILOpPure *(*op2)(RzILOpPure *a, RzILOpPure *b);
typedef RzILOpPure *(*op1)(RzILOpPure *a);
typedef RzILOpEffect *(*setter)(H8300Instruction *, ut8, RzILOpPure *);

static inline RzILOpEffect *op_logical2(H8300Instruction *cmd, RzILOpPure *a, RzILOpPure *b, op2 f, setter s, ut8 N) {
	return SEQ3(
		SETL("_res", f(a, b)),
		s(cmd, 1, VARL("_res")),
		ccr_xNZV0(N, VARL("_res")));
}

#define op_logical2_formats_IMPL(N) \
	static RzILOpEffect *op_logical2_formats_##N(H8300Instruction *cmd, op2 f) { \
		switch (cmd->fmt) { \
		case H8300_INSN_FORMAT_IMMR##N: \
			return op_logical2(cmd, IMM##N##_OP(0), R##N##_OP(1), f, r##N##_op_set, N); \
		case H8300_INSN_FORMAT_R##N##R##N: \
			return op_logical2(cmd, R##N##_OP(0), R##N##_OP(1), f, r##N##_op_set, N); \
		default: NOT_IMPLEMENTED; \
		} \
	}

op_logical2_formats_IMPL(8);
op_logical2_formats_IMPL(16);
op_logical2_formats_IMPL(32);

static inline RzILOpEffect *op_logical1(H8300Instruction *cmd, RzILOpPure *a, op1 f, RzILOpEffect *ccr_setter, ut8 N) {
	return SEQ3(
		SETL("_res", f(a)),
		ccr_setter,
		RX_X(N, 0, VARL("_res")));
}

static inline RzILOpEffect *op_neg(H8300Instruction *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R8:
		// TODO: fix ccr_sub
		return op_logical1(cmd, R8_OP(0), rz_il_op_new_neg, ccr_sub_b(S8(0), R8_OP(0), IL_FALSE), 8);
	case H8300_INSN_FORMAT_R16:
		return op_logical1(cmd, R16_OP(0), rz_il_op_new_neg, ccr_sub_w(S16(0), R16_OP(0), IL_FALSE), 16);
	case H8300_INSN_FORMAT_R32:
		return op_logical1(cmd, R32_OP(0), rz_il_op_new_neg, ccr_sub_l(S32(0), R32_OP(0), IL_FALSE), 32);
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *op_not(H8300Instruction *cmd) {
	switch (cmd->fmt) {
	case H8300_INSN_FORMAT_R8:
		return op_logical1(cmd, R8_OP(0), rz_il_op_new_log_not, ccr_xNZV0(8, VARL("_res")), 8);
	case H8300_INSN_FORMAT_R16:
		return op_logical1(cmd, R16_OP(0), rz_il_op_new_log_not, ccr_xNZV0(16, VARL("_res")), 16);
	case H8300_INSN_FORMAT_R32:
		return op_logical1(cmd, R32_OP(0), rz_il_op_new_log_not, ccr_xNZV0(32, VARL("_res")), 32);
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *op_logical_i8ccr(H8300Instruction *cmd, op2 f) {
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

static inline RzILOpEffect *op_daa(H8300Instruction *cmd) {
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
		ccr_xNZ(8, VARL("result")),
		ccr_set(CCR_C, result_c));
}

static inline RzILOpEffect *op_das(H8300Instruction *cmd) {
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
		ccr_xNZ(8, VARL("result")));
}

static inline RzILOpEffect *op_Bcc(H8300Instruction *cmd, RzILOpPure *cnd) {
	return BRANCH(cnd, JMP(PCREL_OP(0)), NOP());
}

static inline RzILOpEffect *op_divxu(H8300Instruction *cmd, ut8 N) {
	return SEQ4(
		SETL("quotient", UNSIGNED(N, DIV(RX_OP(N * 2, 1), UNSIGNED(N * 2, RX_OP(N, 0))))),
		SETL("remainder", UNSIGNED(N, MOD(RX_OP(N * 2, 1), UNSIGNED(N * 2, RX_OP(N, 0))))),
		ccr_xNZ(N, RX_OP(N, 0)),
		RX_X(N * 2, 1, APPEND(VARL("remainder"), VARL("quotient"))));
}

static inline RzILOpEffect *op_divxs(H8300Instruction *cmd, ut8 N) {
	return SEQ4(
		SETL("quotient", SIGNED(N, SDIV(RX_OP(N * 2, 1), SIGNED(N * 2, RX_OP(N, 0))))),
		SETL("remainder", SIGNED(N, SMOD(RX_OP(N * 2, 1), SIGNED(N * 2, RX_OP(N, 0))))),
		ccr_xNZ(N, RX_OP(N, 0)),
		RX_X(N * 2, 1, APPEND(VARL("remainder"), VARL("quotient"))));
}

static inline RzILOpEffect *op_mulxu(H8300Instruction *cmd, ut8 N) {
	return RX_X(N * 2, 1, MUL(UNSIGNED(N * 2, RX_OP(N, 0)), LOGAND(RX_OP(N * 2, 1), UN(N * 2, (1 << N) - 1))));
}

static inline RzILOpEffect *op_mulxs(H8300Instruction *cmd, ut8 N) {
	return RX_X(N * 2, 1, MUL(SIGNED(N * 2, RX_OP(N, 0)), LOGAND(RX_OP(N * 2, 1), UN(N * 2, (1 << N) - 1))));
}

static inline RzILOpEffect *op_eepmov(const H8300Instruction *cmd, ut8 N) {
	const H8300Register _4 = N == 8 ? H8300_R4L : H8300_R4;
	const H8300Register _5 = cmd->cpu_type == CPU_H8300H ? H8300_ER5 : H8300_R5;
	const H8300Register _6 = cmd->cpu_type == CPU_H8300H ? H8300_ER6 : H8300_R6;
	const ut8 _56sz = cmd->cpu_type == CPU_H8300H ? 32 : 16;
	return REPEAT(
		NE(rx_op_i(N, _4), UN(N, 0)),
		SEQ5(
			SETL("data_val", LOADW(N, AS_ADDR(rx_op_i(_56sz, _5)))),
			STOREW(AS_ADDR(rx_op_i(_56sz, _6)), VARL("data_val")),
			rx_op_i_set(_56sz, _5, ADD(rx_op_i(_56sz, _5), UN(_56sz, N / 8))),
			rx_op_i_set(_56sz, _6, ADD(rx_op_i(_56sz, _6), UN(_56sz, N / 8))),
			rx_op_i_set(N, _4, SUB(rx_op_i(N, _4), UN(N, 1)))));
}

static inline RzILOpEffect *op_extu(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("val", LOGAND(RX_OP(N, 0), UN(N, (1 << N / 2) - 1))),
		RX_X(N, 0, VARL("val")),
		ccr_NZV(N, IL_FALSE, IS_ZERO(VARL("val")), IL_FALSE));
}

static inline RzILOpEffect *op_exts(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("val", UNSIGNED(N, SEXTRACT32(UNSIGNED(32, RX_OP(N, 0)), U32(N / 2), U32(N / 2)))),
		RX_X(N, 0, VARL("val")),
		ccr_xNZV0(N, VARL("val")));
}

static inline RzILOpEffect *op_rotl(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("result", SHIFTL(MSB(RX_OP(N, 0)), RX_OP(N, 0), UN(N, 1))),
		ccr_xNZVC(N, VARL("result"),
			IL_FALSE,
			MSB(RX_OP(N, 0))),
		RX_X(N, 0, VARL("result")));
}

static inline RzILOpEffect *op_rotr(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("result", SHIFTR(LSB(RX_OP(N, 0)), RX_OP(N, 0), UN(N, 1))),
		ccr_xNZVC(N, VARL("result"),
			IL_FALSE,
			LSB(RX_OP(N, 0))),
		RX_X(N, 0, VARL("result")));
}

static inline RzILOpEffect *op_rotxl(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("result", SHIFTL(ccr_val(CCR_C), RX_OP(N, 0), UN(N, 1))),
		ccr_xNZVC(N, VARL("result"),
			IL_FALSE,
			MSB(RX_OP(N, 0))),
		RX_X(N, 0, VARL("result")));
}

static inline RzILOpEffect *op_rotxr(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("result", SHIFTR(ccr_val(CCR_C), RX_OP(N, 0), UN(N, 1))),
		ccr_xNZVC(N, VARL("result"),
			IL_FALSE,
			LSB(RX_OP(N, 0))),
		RX_X(N, 0, VARL("result")));
}

static inline RzILOpEffect *op_shal(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("result", SHIFTL0(RX_OP(N, 0), UN(N, 1))),
		ccr_xNZVC(N, VARL("result"),
			XOR(MSB(VARL("result")), MSB(RX_OP(N, 0))),
			MSB(RX_OP(N, 0))),
		RX_X(N, 0, VARL("result")));
}

static inline RzILOpEffect *op_shar(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("result", SHIFTRA(RX_OP(N, 0), UN(N, 1))),
		ccr_xNZVC(N, VARL("result"),
			IL_FALSE,
			LSB(RX_OP(N, 0))),
		RX_X(N, 0, VARL("result")));
}

static inline RzILOpEffect *op_shll(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("result", SHIFTL0(RX_OP(N, 0), UN(N, 1))),
		ccr_xNZVC(N, VARL("result"),
			IL_FALSE,
			MSB(RX_OP(N, 0))),
		RX_X(N, 0, VARL("result")));
}

static inline RzILOpEffect *op_shlr(H8300Instruction *cmd, ut8 N) {
	return SEQ3(
		SETL("result", SHIFTR0(RX_OP(N, 0), UN(N, 1))),
		ccr_xNZVC(N, VARL("result"),
			IL_FALSE,
			LSB(RX_OP(N, 0))),
		RX_X(N, 0, VARL("result")));
}

static inline RzILOpPure *vector_addr(H8300Instruction *cmd, ut8 x) {
	// TODO: This is a temporary solution, distinguish between normal and advanced mode
	switch (x) {
	case 0: return UADDR(0x20);
	case 1: return UADDR(0x24);
	case 2: return UADDR(0x28);
	case 3: return UADDR(0x2c);
	default: NOT_IMPLEMENTED;
	}
}

static inline RzILOpEffect *aop(RzAnalysis *a, RzAnalysisOp *op, H8300Instruction *cmd) {
	switch (cmd->id) {
	case H8300_INSN_MOV_B: return op_mov_b(cmd);
	case H8300_INSN_MOV_W: return op_mov_w(cmd);
	case H8300_INSN_MOV_L: return op_mov_l(cmd);
	case H8300_INSN_ADD_B: return op_add_b(cmd);
	case H8300_INSN_ADD_W: return op_add_w(cmd);
	case H8300_INSN_ADD_L: return op_add_l(cmd);
	case H8300_INSN_ADDS: return op_adds(cmd);
	case H8300_INSN_ADDX: return op_addx(cmd);
	case H8300_INSN_CMP_B:
	case H8300_INSN_CMP_W:
	case H8300_INSN_CMP_L:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
			return ccr_cmp_b(R8_OP(1), IMM8_OP(0));
		case H8300_INSN_FORMAT_R8R8:
			return ccr_cmp_b(R8_OP(1), R8_OP(0));
		case H8300_INSN_FORMAT_R16R16:
			return ccr_cmp_w(R16_OP(1), R16_OP(0));
		case H8300_INSN_FORMAT_IMMR16:
			return ccr_cmp_w(R16_OP(1), IMM_OP(16, 0));
		case H8300_INSN_FORMAT_R32R32:
			return ccr_cmp_l(R32_OP(1), R32_OP(0));
		case H8300_INSN_FORMAT_IMMR32:
			return ccr_cmp_l(R32_OP(1), IMM_OP(32, 0));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_SUB_B:
	case H8300_INSN_SUB_W:
	case H8300_INSN_SUB_L:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R8R8:
			return SEQ4(
				SETL("_0", R8_OP(0)),
				SETL("_1", R8_OP(1)),
				R8_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_sub_b(VARL("_1"), VARL("_0"), IL_FALSE));
		case H8300_INSN_FORMAT_R16R16:
			return SEQ4(
				SETL("_0", R16_OP(0)),
				SETL("_1", R16_OP(1)),
				R16_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_sub_w(VARL("_1"), VARL("_0"), IL_FALSE));
		case H8300_INSN_FORMAT_IMMR16:
			return SEQ4(
				SETL("_0", IMM16_OP(0)),
				SETL("_1", R16_OP(1)),
				R16_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_sub_w(VARL("_1"), VARL("_0"), IL_FALSE));
		case H8300_INSN_FORMAT_R32R32:
			return SEQ4(
				SETL("_0", R32_OP(0)),
				SETL("_1", R32_OP(1)),
				R32_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_sub_l(VARL("_1"), VARL("_0"), IL_FALSE));
		case H8300_INSN_FORMAT_IMMR32:
			return SEQ4(
				SETL("_0", IMM32_OP(0)),
				SETL("_1", R32_OP(1)),
				R32_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_sub_l(VARL("_1"), VARL("_0"), IL_FALSE));
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
				ccr_cmp(VARL("_1"), VARL("_0"), VARL("_c"), 8, 3, 7));
		case H8300_INSN_FORMAT_IMMR8:
			return SEQ5(
				SETL("_c", ccr_val(CCR_C)),
				SETL("_0", IMM8_OP(0)),
				SETL("_1", R8_OP(1)),
				R8_X(1, SUB(VARL("_1"), VARL("_0"))),
				ccr_cmp(VARL("_1"), VARL("_0"), VARL("_c"), 8, 3, 7));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_SUBS:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR16:
			return R16_X(1, SUB(R16_OP(1), IMM_OP(16, 0)));
		case H8300_INSN_FORMAT_IMMR32:
			return R32_X(1, SUB(R32_OP(1), IMM_OP(32, 0)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_OR_B: return op_logical2_formats_8(cmd, rz_il_op_new_log_or);
	case H8300_INSN_XOR_B: return op_logical2_formats_8(cmd, rz_il_op_new_log_xor);
	case H8300_INSN_AND_B: return op_logical2_formats_8(cmd, rz_il_op_new_log_and);
	case H8300_INSN_AND_W: return op_logical2_formats_16(cmd, rz_il_op_new_log_and);
	case H8300_INSN_XOR_W: return op_logical2_formats_16(cmd, rz_il_op_new_log_xor);
	case H8300_INSN_OR_W: return op_logical2_formats_16(cmd, rz_il_op_new_log_or);
	case H8300_INSN_AND_L: return op_logical2_formats_32(cmd, rz_il_op_new_log_and);
	case H8300_INSN_XOR_L: return op_logical2_formats_32(cmd, rz_il_op_new_log_xor);
	case H8300_INSN_OR_L: return op_logical2_formats_32(cmd, rz_il_op_new_log_or);
	case H8300_INSN_NOP:
	case H8300_INSN_SLEEP: return NOP();
	case H8300_INSN_STC_B: return R8_X(1, VARG("ccr"));
	case H8300_INSN_STC_W:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_RI:
			return ri_op_set(cmd, 1, UNSIGNED(16, VARG("ccr")));
		case H8300_INSN_FORMAT_RD:
			return rd_op_set(cmd, 1, UNSIGNED(16, VARG("ccr")));
		case H8300_INSN_FORMAT_RPREDEC:
			return SEQ2(
				rpredec_op_dec(cmd, 1, 2),
				STOREW(AS_ADDR(rpredec_op(cmd, 1)), UNSIGNED(16, VARG("ccr"))));
		case H8300_INSN_FORMAT_ABS:
			return abs_op_set(cmd, 1, UNSIGNED(16, VARG("ccr")));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_LDC_B:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMM:
			return SETG("ccr", IMM8_OP(0));
		case H8300_INSN_FORMAT_R8:
			return SETG("ccr", R8_OP(0));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_LDC_W:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_RI:
			return SETG("ccr", ri_op(8, cmd, 0));
		case H8300_INSN_FORMAT_RD:
			return SETG("ccr", rd_op(8, cmd, 0));
		case H8300_INSN_FORMAT_RPOSTINC:
			return SEQ2(SETG("ccr", LOAD(AS_ADDR(rpostinc_op(cmd, 0)))),
				rpostinc_op_inc(cmd, 0, 2));
		case H8300_INSN_FORMAT_ABS:
			return SETG("ccr", abs_op(8, cmd, 0));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_ORC: return op_logical_i8ccr(cmd, rz_il_op_new_log_or);
	case H8300_INSN_XORC: return op_logical_i8ccr(cmd, rz_il_op_new_log_xor);
	case H8300_INSN_ANDC: return op_logical_i8ccr(cmd, rz_il_op_new_log_and);
	case H8300_INSN_DEC_B:
	case H8300_INSN_DEC_W:
	case H8300_INSN_DEC_L:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R8:
			return SEQ4(
				SETL("_prev", R8_OP(0)),
				SETL("_res", SUB(R8_OP(0), S8(1))),
				R8_X(0, VARL("_res")),
				ccr_xNZV(8, VARL("_res"), EQ(VARL("_prev"), U8(0x80))));
		case H8300_INSN_FORMAT_IMMR16:
			return SEQ4(
				SETL("_prev", R16_OP(1)),
				SETL("_res", SUB(R16_OP(1), IMM16_OP(0))),
				R16_X(1, VARL("_res")),
				ccr_xNZV(16, VARL("_res"), SLE(VARL("_prev"), S16(0x8001))));
		case H8300_INSN_FORMAT_IMMR32:
			return SEQ4(
				SETL("_prev", R32_OP(1)),
				SETL("_res", SUB(R32_OP(1), IMM32_OP(0))),
				R32_X(1, VARL("_res")),
				ccr_xNZV(32, VARL("_res"), SLE(VARL("_prev"), S32(0x80000001))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_INC_B:
	case H8300_INSN_INC_L:
	case H8300_INSN_INC_W:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_R8:
			return SEQ4(
				SETL("_prev", R8_OP(0)),
				SETL("_res", ADD(R8_OP(0), S8(1))),
				R8_X(0, VARL("_res")),
				ccr_xNZV(8, VARL("_res"), EQ(VARL("_prev"), S8(0x7f))));
		case H8300_INSN_FORMAT_IMMR16:
			return SEQ4(
				SETL("_prev", R16_OP(1)),
				SETL("_res", ADD(R16_OP(1), IMM16_OP(0))),
				R16_X(1, VARL("_res")),
				ccr_xNZV(16, VARL("_res"), SGE(VARL("_prev"), S16(0x7ffe))));
		case H8300_INSN_FORMAT_IMMR32:
			return SEQ4(
				SETL("_prev", R32_OP(1)),
				SETL("_res", ADD(R32_OP(1), IMM32_OP(0))),
				R32_X(1, VARL("_res")),
				ccr_xNZV(32, VARL("_res"), SGE(VARL("_prev"), S32(0x7ffffffe))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_DAA: return op_daa(cmd);
	case H8300_INSN_DAS: return op_das(cmd);
	case H8300_INSN_SHAL_B: return op_shal(cmd, 8);
	case H8300_INSN_SHAL_W: return op_shal(cmd, 16);
	case H8300_INSN_SHAL_L: return op_shal(cmd, 32);

	case H8300_INSN_SHAR_B: return op_shar(cmd, 8);
	case H8300_INSN_SHAR_W: return op_shar(cmd, 16);
	case H8300_INSN_SHAR_L: return op_shar(cmd, 32);

	case H8300_INSN_SHLL_B: return op_shll(cmd, 8);
	case H8300_INSN_SHLL_W: return op_shll(cmd, 16);
	case H8300_INSN_SHLL_L: return op_shll(cmd, 32);

	case H8300_INSN_SHLR_B: return op_shlr(cmd, 8);
	case H8300_INSN_SHLR_W: return op_shlr(cmd, 16);
	case H8300_INSN_SHLR_L: return op_shlr(cmd, 32);

	case H8300_INSN_ROTL_B: return op_rotl(cmd, 8);
	case H8300_INSN_ROTL_W: return op_rotl(cmd, 16);
	case H8300_INSN_ROTL_L: return op_rotl(cmd, 32);

	case H8300_INSN_ROTR_B: return op_rotr(cmd, 8);
	case H8300_INSN_ROTR_W: return op_rotr(cmd, 16);
	case H8300_INSN_ROTR_L: return op_rotr(cmd, 32);

	case H8300_INSN_ROTXL_B: return op_rotxl(cmd, 8);
	case H8300_INSN_ROTXL_W: return op_rotxl(cmd, 16);
	case H8300_INSN_ROTXL_L: return op_rotxl(cmd, 32);

	case H8300_INSN_ROTXR_B: return op_rotxr(cmd, 8);
	case H8300_INSN_ROTXR_W: return op_rotxr(cmd, 16);
	case H8300_INSN_ROTXR_L: return op_rotxr(cmd, 32);

	case H8300_INSN_NEG_B:
	case H8300_INSN_NEG_W:
	case H8300_INSN_NEG_L: return op_neg(cmd);
	case H8300_INSN_NOT_B:
	case H8300_INSN_NOT_W:
	case H8300_INSN_NOT_L: return op_not(cmd);

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
	case H8300_INSN_DIVXU_B:
		return op_divxu(cmd, 8);
	case H8300_INSN_DIVXU_W:
		return op_divxu(cmd, 16);
	case H8300_INSN_DIVXS_B:
		return op_divxs(cmd, 8);
	case H8300_INSN_DIVXS_W:
		return op_divxs(cmd, 16);
	case H8300_INSN_MULXU_B: return op_mulxu(cmd, 8);
	case H8300_INSN_MULXS_B: return op_mulxs(cmd, 8);
	case H8300_INSN_MULXU_W: return op_mulxu(cmd, 16);
	case H8300_INSN_MULXS_W: return op_mulxs(cmd, 16);

	case H8300_INSN_EEPMOV_B: return op_eepmov(cmd, 8);
	case H8300_INSN_EEPMOV_W: return op_eepmov(cmd, 16);
	case H8300_INSN_EXTS_W: return op_exts(cmd, 16);
	case H8300_INSN_EXTS_L: return op_exts(cmd, 32);
	case H8300_INSN_EXTU_W: return op_extu(cmd, 16);
	case H8300_INSN_EXTU_L: return op_extu(cmd, 32);
	case H8300_INSN_RTS:
		return SEQ3(
			SETL("@sp", LOADW(32, sp_op_as_adr(cmd))),
			sp_inc(cmd, 4),
			JMP(UNSIGNED(24, VARL("@sp"))));
	case H8300_INSN_RTE:
		return SEQ4(
			SETL("ccr_pc", LOADW(32, sp_op_as_adr(cmd))),
			sp_inc(cmd, 4),
			SETG("ccr", UNSIGNED(8, SHIFTR0(VARL("ccr_pc"), U8(24)))),
			JMP(UNSIGNED(24, VARL("ccr_pc"))));
	case H8300_INSN_BSR:
		return SEQ3(
			sp_dec(cmd, 4),
			STOREW(sp_op_as_adr(cmd), PC_VAL),
			JMP(ADD(PC_VAL, PCREL_OP(0))));
	case H8300_INSN_JMP:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_RI:
			return JMP(ri_op(24, cmd, 0));
		case H8300_INSN_FORMAT_ABS:
			return JMP(UADDR(INS_OPS(0).imm));
		case H8300_INSN_FORMAT_MI8:
			return JMP(LOADW(24, MI8_OP(0)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_JSR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_RI:
			return SEQ3(
				sp_dec(cmd, 4),
				STOREW(sp_op_as_adr(cmd), UNSIGNED(32, PC_NEXT_VAL)),
				JMP(ri_op(24, cmd, 0)));
		case H8300_INSN_FORMAT_ABS:
			return SEQ3(
				sp_dec(cmd, 4),
				STOREW(sp_op_as_adr(cmd), UNSIGNED(32, PC_NEXT_VAL)),
				JMP(UADDR(INS_OPS(0).imm)));
		case H8300_INSN_FORMAT_MI8:
			return SEQ3(
				sp_dec(cmd, 4),
				STOREW(sp_op_as_adr(cmd), UNSIGNED(32, PC_NEXT_VAL)),
				JMP(LOADW(24, MI8_OP(0))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BSET:
#define BIT_NO (INS_OPS(0).typ == H8300_OP_IMM ? UNSIGNED(32, IMM8_OP(0)) : UNSIGNED(32, LOGAND(R8_OP(0), U8(0x7))))
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), U32(1)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ri_op_set(cmd, 1, DEPOSIT8(ri_op(8, cmd, 1), BIT_NO, U32(1), U32(1)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return abs_op_set(cmd, 1, DEPOSIT8(abs_op(8, cmd, 1), BIT_NO, U32(1), U32(1)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BNOT:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), LOGNOT(EXTRACT1(R8_OP(1), BIT_NO))));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ri_op_set(cmd, 1, DEPOSIT8(ri_op(8, cmd, 1), BIT_NO, U32(1), LOGNOT(EXTRACT1(ri_op(8, cmd, 1), BIT_NO))));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return abs_op_set(cmd, 1, DEPOSIT8(abs_op(8, cmd, 1), BIT_NO, U32(1), LOGNOT(EXTRACT1(abs_op(8, cmd, 1), BIT_NO))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BCLR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), U32(0)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ri_op_set(cmd, 1, DEPOSIT8(ri_op(8, cmd, 1), BIT_NO, U32(1), U32(0)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return abs_op_set(cmd, 1, DEPOSIT8(abs_op(8, cmd, 1), BIT_NO, U32(1), U32(0)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BTST:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_Z, EXTRACTb(R8_OP(1), BIT_NO));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_Z, EXTRACTb(ri_op(8, cmd, 1), BIT_NO));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_Z, EXTRACTb(abs_op(8, cmd, 1), BIT_NO));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BST:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), B_TO_1(ccr_val(CCR_C))));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ri_op_set(cmd, 1, DEPOSIT8(ri_op(8, cmd, 1), BIT_NO, U32(1), B_TO_1(ccr_val(CCR_C))));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return abs_op_set(cmd, 1, DEPOSIT8(abs_op(8, cmd, 1), BIT_NO, U32(1), B_TO_1(ccr_val(CCR_C))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BIST:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return R8_X(1, DEPOSIT8(R8_OP(1), BIT_NO, U32(1), LOGNOT(B_TO_1(ccr_val(CCR_C)))));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ri_op_set(cmd, 1, DEPOSIT8(ri_op(8, cmd, 1), BIT_NO, U32(1), LOGNOT(B_TO_1(ccr_val(CCR_C)))));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return abs_op_set(cmd, 1, DEPOSIT8(abs_op(8, cmd, 1), BIT_NO, U32(1), LOGNOT(B_TO_1(ccr_val(CCR_C)))));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BOR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, OR(EXTRACTb(R8_OP(1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_C, OR(EXTRACTb(ri_op(8, cmd, 1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, OR(EXTRACTb(abs_op(8, cmd, 1), BIT_NO), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BIOR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, OR(INV(EXTRACTb(R8_OP(1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_C, OR(INV(EXTRACTb(ri_op(8, cmd, 1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, OR(INV(EXTRACTb(abs_op(8, cmd, 1), BIT_NO)), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BAND:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, AND(EXTRACTb(R8_OP(1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_C, AND(EXTRACTb(ri_op(8, cmd, 1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, AND(EXTRACTb(abs_op(8, cmd, 1), BIT_NO), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BIAND:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, AND(INV(EXTRACTb(R8_OP(1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_C, AND(INV(EXTRACTb(ri_op(8, cmd, 1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, AND(INV(EXTRACTb(abs_op(8, cmd, 1), BIT_NO)), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BLD:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, EXTRACTb(R8_OP(1), BIT_NO));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_C, EXTRACTb(ri_op(8, cmd, 1), BIT_NO));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, EXTRACTb(abs_op(8, cmd, 1), BIT_NO));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BILD:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, INV(EXTRACTb(R8_OP(1), BIT_NO)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_C, INV(EXTRACTb(ri_op(8, cmd, 1), BIT_NO)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, INV(EXTRACTb(abs_op(8, cmd, 1), BIT_NO)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BXOR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, XOR(EXTRACTb(R8_OP(1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_C, XOR(EXTRACTb(ri_op(8, cmd, 1), BIT_NO), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, XOR(EXTRACTb(abs_op(8, cmd, 1), BIT_NO), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_BIXOR:
		switch (cmd->fmt) {
		case H8300_INSN_FORMAT_IMMR8:
		case H8300_INSN_FORMAT_R8R8:
			return ccr_set(CCR_C, XOR(INV(EXTRACTb(R8_OP(1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMRI:
		case H8300_INSN_FORMAT_R8RI:
			return ccr_set(CCR_C, XOR(INV(EXTRACTb(ri_op(8, cmd, 1), BIT_NO)), ccr_val(CCR_C)));
		case H8300_INSN_FORMAT_IMMABS:
		case H8300_INSN_FORMAT_R8ABS:
			return ccr_set(CCR_C, XOR(INV(EXTRACTb(abs_op(8, cmd, 1), BIT_NO)), ccr_val(CCR_C)));
		default: NOT_IMPLEMENTED;
		}
	case H8300_INSN_POP_W:
		return SEQ4(
			SETL("val", LOADW(16, sp_op_as_adr(cmd))),
			R16_X(0, VARL("val")),
			sp_inc(cmd, 2),
			ccr_xNZV0(16, VARL("val")));
	case H8300_INSN_POP_L:
		return SEQ4(
			SETL("val", LOADW(32, sp_op_as_adr(cmd))),
			R32_X(0, VARL("val")),
			sp_inc(cmd, 4),
			ccr_xNZV0(32, VARL("val")));
	case H8300_INSN_PUSH_W:
		return SEQ3(
			sp_dec(cmd, 2),
			STOREW(sp_op_as_adr(cmd), R16_OP(0)),
			ccr_xNZV0(16, R16_OP(0)));
	case H8300_INSN_PUSH_L:
		return SEQ3(
			sp_dec(cmd, 4),
			STOREW(sp_op_as_adr(cmd), R32_OP(0)),
			ccr_xNZV0(32, R32_OP(0)));
	case H8300_INSN_INVALID: return NOP();

	case H8300_INSN_TRAPA:
		return SEQ5(
			sp_dec(cmd, 4),
			sp_set(cmd, PC_NEXT_VAL),
			sp_dec(cmd, 2),
			sp_set(cmd, VARG("ccr")),
			JMP(vector_addr(cmd, INS_OPS(0).imm)));
	case H8300_INSN_MOVFPE:
		return SEQ2(
			R8_X(1, abs_op(8, cmd, 0)),
			ccr_xNZV0(8, abs_op(8, cmd, 0)));
	case H8300_INSN_MOVTPE:
		return SEQ2(
			abs_op_set(cmd, 1, R8_OP(0)),
			ccr_xNZV0(8, R8_OP(0)));
	}

	NOT_IMPLEMENTED;
}

int h8300_analyze_op_il(RzAnalysis *a, RzAnalysisOp *op, H8300Instruction *cmd) {
	op->il_op = aop(a, op, cmd);
	return 0;
}

static const char *reg_bindings[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"ccr", NULL
};

static const char *h8300h_reg_bindings[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
	"e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
	"ccr", NULL
};

RzAnalysisILConfig *h8300_il_config(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);

	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(24, a->big_endian, 24);
	if (!cfg) {
		return NULL;
	}
	cfg->reg_bindings = h8300_cpu_type(a->cpu) == CPU_H8300H ? h8300h_reg_bindings : reg_bindings;
	cfg->init_state = rz_analysis_il_init_state_new();
	if (!cfg->init_state) {
		rz_analysis_il_config_free(cfg);
		return NULL;
	}

	rz_analysis_il_init_state_set_var(cfg->init_state,
		"ccr", rz_il_value_new_bitv(rz_bv_new_from_ut64(8, 1 << CCR_I)));
	return cfg;
}
