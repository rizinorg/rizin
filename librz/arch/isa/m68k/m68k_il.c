// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "m68k/m68k_il.h"
#include "m68k/m68k_cs.h"

#ifdef CAPSTONE_M68K_H

#include <string.h>

#include <rz_il/rz_il_opbuilder_begin.h>
#include <rz_util/rz_assert.h>

#define M68K_MEM_IDX   0
#define M68K_ADDR_BITS 32

#define M68K_CCR_C                   0
#define M68K_CCR_V                   1
#define M68K_CCR_Z                   2
#define M68K_CCR_N                   3
#define M68K_CCR_X                   4
#define M68K_SR_M                    12
#define M68K_SR_S                    13
#define M68K_FPSR_CC_N               27
#define M68K_FPSR_CC_Z               26
#define M68K_FPSR_CC_I               25
#define M68K_FPSR_CC_NAN             24
#define M68K_FPSR_CC_MASK            ((1u << M68K_FPSR_CC_N) | (1u << M68K_FPSR_CC_Z) | (1u << M68K_FPSR_CC_I) | (1u << M68K_FPSR_CC_NAN))
#define M68K_FMOVEM_FP_REG_BITS_MASK 0x00ff0000u
#define M68K_FMOVEM_EXTENDED_BITS    96
#define M68K_FMOVEM_EXTENDED_BYTES   12

#ifndef M68K_BF_REG_FLAG
#define M68K_BF_REG_FLAG   0x80
#define M68K_BF_IS_REG(v)  ((v) & M68K_BF_REG_FLAG)
#define M68K_BF_REG_NUM(v) ((v) & 7)
#endif

typedef struct {
	csh handle;
	cs_mode mode;
	const cs_insn *insn;
	const cs_m68k *m68k;
	ut64 addr;
	ut64 next_addr;
} M68KILCtx;

typedef struct {
	RzILOpPure *addr;
	RzILOpEffect *pre;
	RzILOpEffect *post;
} M68KEA;

typedef struct {
	const cs_m68k_op *op;
	const char *addr_local;
	RzILOpEffect *post;
} M68KRWOperand;

typedef struct {
	const cs_m68k_op *op;
	bool memory;
	const char *addr_local;
	RzILOpEffect *post;
} M68KBitfieldTarget;

typedef enum {
	M68K_BIN_ADD,
	M68K_BIN_SUB,
	M68K_BIN_AND,
	M68K_BIN_OR,
	M68K_BIN_XOR
} M68KBinOp;

typedef enum {
	M68K_CACHE_OP_TOUCH,
	M68K_CACHE_OP_INVALIDATE,
	M68K_CACHE_OP_PUSH
} M68KCacheOp;

typedef enum {
	M68K_DEBUG_OP_DATA,
	M68K_DEBUG_OP_DEBUG
} M68KDebugOp;

typedef enum {
	M68K_SYSTEM_OP_RESET,
	M68K_SYSTEM_OP_STOP,
	M68K_SYSTEM_OP_LPSTOP,
	M68K_SYSTEM_OP_HALT,
	M68K_SYSTEM_OP_PULSE
} M68KSystemOp;

typedef enum {
	M68K_CP_OP_NOP,
	M68K_CP_OP_BRANCH,
	M68K_CP_OP_LOAD,
	M68K_CP_OP_STORE
} M68KCoprocessorOp;

typedef enum {
	M68K_TRAP_OP_TRAP,
	M68K_TRAP_OP_BKPT,
	M68K_TRAP_OP_TRAPCC,
	M68K_TRAP_OP_FTRAPCC,
	M68K_TRAP_OP_TRAPV,
	M68K_TRAP_OP_BGND,
	M68K_TRAP_OP_DIV_ZERO,
	M68K_TRAP_OP_CHK,
	M68K_TRAP_OP_ILLEGAL,
	M68K_TRAP_OP_PRIVILEGE,
	M68K_TRAP_OP_FORMAT
} M68KTrapOp;

typedef enum {
	M68K_VECTOR_ILLEGAL = 4,
	M68K_VECTOR_ZERO_DIVIDE = 5,
	M68K_VECTOR_CHK = 6,
	M68K_VECTOR_TRAPV_TRAPCC = 7,
	M68K_VECTOR_PRIVILEGE = 8,
	M68K_VECTOR_FORMAT_ERROR = 14
} M68KExceptionVector;

#define M68K_VECTOR_TRAP_BASE 32

typedef enum {
	M68K_FPU_STATE_SAVE,
	M68K_FPU_STATE_RESTORE
} M68KFPUStateOp;

typedef enum {
	M68K_MMU_OP_LOAD,
	M68K_MMU_OP_FLUSH,
	M68K_MMU_OP_TEST,
	M68K_MMU_OP_MOVE,
	M68K_MMU_OP_LOAD_PHYSICAL
} M68KMMUOp;

typedef struct {
	ut8 selector;
	ut16 sign_exp;
	ut64 mantissa;
} M68KFMovecrConst;

static RzILOpPure *fpu_fp80_to_ext96(RzILOpPure *fp80);
static RzILOpPure *fpu_ext96_to_fp80(RzILOpPure *ext96);
static void m68k_ea_fini(M68KEA *ea);

static RzILOpPure *u32(ut64 v) {
	return U32((ut32)v);
}

static RzILOpPure *s32(st64 v) {
	return S32((st32)v);
}

static RzILOpPure *cast_unsigned(ut32 bits, RzILOpPure *v) {
	return CAST(bits, IL_FALSE, v);
}

static RzILOpPure *cast_signed(ut32 bits, RzILOpPure *v) {
	return CAST(bits, MSB(DUP(v)), v);
}

static RzILOpPure *extend_to_32(RzILOpPure *v, bool sign_extend) {
	return sign_extend ? cast_signed(32, v) : cast_unsigned(32, v);
}

static RzILOpPure *append_addr_add(RzILOpPure *base, RzILOpPure *delta) {
	return ADD(cast_unsigned(32, base), cast_unsigned(32, delta));
}

static RzILOpPure *reg_value(M68KILCtx *ctx, m68k_reg reg) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		return NULL;
	}
	return VARG(name);
}

static RzILOpPure *read_reg_sized(M68KILCtx *ctx, m68k_reg reg, ut32 bits) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		return NULL;
	}
	if (rz_m68k_reg_is_areg(reg) || reg == M68K_REG_PC || reg == M68K_REG_USP || reg == M68K_REG_MSP || reg == M68K_REG_ISP) {
		return bits == 32 ? VARG(name) : cast_unsigned(bits, VARG(name));
	}
	if (reg == M68K_REG_CCR) {
		return bits == 8 ? cast_unsigned(8, VARG("sr")) : cast_unsigned(bits, VARG("sr"));
	}
	if (reg == M68K_REG_SR) {
		return bits == 16 ? VARG(name) : cast_unsigned(bits, VARG(name));
	}
	if (rz_m68k_reg_is_fpu(reg)) {
		return bits == 80 ? VARG(name) : cast_unsigned(bits, VARG(name));
	}
	if (rz_m68k_reg_name_is_mmu_root_pointer(name)) {
		return bits == 64 ? VARG(name) : cast_unsigned(bits, VARG(name));
	}
	return bits == 32 ? VARG(name) : cast_unsigned(bits, VARG(name));
}

static RzILOpEffect *seq_append(RzILOpEffect *a, RzILOpEffect *b) {
	if (!a) {
		return b;
	}
	if (!b) {
		return a;
	}
	RzILOpEffect *seq = SEQ2(a, b);
	if (!seq) {
		rz_warn_if_reached();
		rz_il_op_effect_free(a);
		rz_il_op_effect_free(b);
	}
	return seq;
}

static RzILOpEffect *set_ccr_from_value(RzILOpPure *new_ccr) {
	RzILOpPure *ccr8 = cast_unsigned(8, new_ccr);
	return SETG("sr", LOGOR(LOGAND(VARG("sr"), U16(0xff00)), cast_unsigned(16, ccr8)));
}

static RzILOpPure *ccr_bit(ut32 bit) {
	return NON_ZERO(LOGAND(cast_unsigned(8, VARG("sr")), U8(1u << bit)));
}

static RzILOpBool *fpsr_bit(ut32 bit) {
	return NON_ZERO(LOGAND(cast_unsigned(32, VARG("fpsr")), U32(1u << bit)));
}

static RzILOpEffect *set_fpsr_cc(RzILOpBool *n, RzILOpBool *z, RzILOpBool *i, RzILOpBool *nan) {
	RzILOpPure *cc = U32(0);
	cc = LOGOR(cc, SHIFTL0(BOOL_TO_BV(n, 32), U8(M68K_FPSR_CC_N)));
	cc = LOGOR(cc, SHIFTL0(BOOL_TO_BV(z, 32), U8(M68K_FPSR_CC_Z)));
	cc = LOGOR(cc, SHIFTL0(BOOL_TO_BV(i, 32), U8(M68K_FPSR_CC_I)));
	cc = LOGOR(cc, SHIFTL0(BOOL_TO_BV(nan, 32), U8(M68K_FPSR_CC_NAN)));
	return SETG("fpsr", LOGOR(LOGAND(cast_unsigned(32, VARG("fpsr")), U32(~M68K_FPSR_CC_MASK)), cc));
}

static RzILOpBool *sr_bit(ut32 bit) {
	return NON_ZERO(LOGAND(cast_unsigned(16, VARG("sr")), U16((ut16)(1u << bit))));
}

static RzILOpBool *supervisor_mode(void) {
	return sr_bit(M68K_SR_S);
}

static RzILOpPure *ccr_with_flag(RzILOpPure *ccr, ut32 bit, RzILOpBool *value) {
	RzILOpPure *cleared = LOGAND(ccr, U8((ut8) ~(1u << bit)));
	RzILOpPure *flag = SHIFTL0(BOOL_TO_BV(value, 8), U8(bit));
	return LOGOR(cleared, flag);
}

static RzILOpEffect *set_flags_nzvcx(RzILOpPure *value, ut32 bits, RzILOpBool *v, RzILOpBool *c, RzILOpBool *x) {
	RzILOpPure *val = cast_unsigned(bits, value);
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xe0));
	ccr = ccr_with_flag(ccr, M68K_CCR_N, MSB(DUP(val)));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, IS_ZERO(val));
	ccr = ccr_with_flag(ccr, M68K_CCR_V, v ? v : IL_FALSE);
	ccr = ccr_with_flag(ccr, M68K_CCR_C, c ? c : IL_FALSE);
	if (x) {
		ccr = ccr_with_flag(ccr, M68K_CCR_X, x);
	} else {
		ccr = LOGOR(ccr, LOGAND(cast_unsigned(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	}
	return set_ccr_from_value(ccr);
}

static RzILOpEffect *set_flags_nzvcx_extend(RzILOpPure *value, ut32 bits, RzILOpBool *v, RzILOpBool *c) {
	RzILOpPure *val = cast_unsigned(bits, value);
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xe0));
	ccr = ccr_with_flag(ccr, M68K_CCR_N, MSB(DUP(val)));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, AND(ccr_bit(M68K_CCR_Z), IS_ZERO(val)));
	ccr = ccr_with_flag(ccr, M68K_CCR_V, v);
	ccr = ccr_with_flag(ccr, M68K_CCR_C, c);
	ccr = ccr_with_flag(ccr, M68K_CCR_X, (RzILOpBool *)DUP(c));
	return set_ccr_from_value(ccr);
}

static RzILOpEffect *set_flags_div(RzILOpPure *quotient, ut32 bits, RzILOpBool *overflow) {
	RzILOpPure *quotient_sized = cast_unsigned(bits, quotient);
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xe0));
	RzILOpBool *no_overflow = INV((RzILOpBool *)DUP(overflow));
	ccr = ccr_with_flag(ccr, M68K_CCR_N, AND(no_overflow, MSB(DUP(quotient_sized))));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, AND(INV((RzILOpBool *)DUP(overflow)), IS_ZERO(quotient_sized)));
	ccr = ccr_with_flag(ccr, M68K_CCR_V, overflow);
	ccr = ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	ccr = LOGOR(ccr, LOGAND(cast_unsigned(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	return set_ccr_from_value(ccr);
}

static RzILOpBool *add_overflow(RzILOpPure *a, RzILOpPure *b, RzILOpPure *r) {
	RzILOpBool *same_sign = EQ(BOOL_TO_BV(MSB(DUP(a)), 1), BOOL_TO_BV(MSB(b), 1));
	RzILOpBool *diff_result = NE(BOOL_TO_BV(MSB(a), 1), BOOL_TO_BV(MSB(r), 1));
	return AND(same_sign, diff_result);
}

static RzILOpBool *sub_overflow(RzILOpPure *a, RzILOpPure *b, RzILOpPure *r) {
	RzILOpBool *diff_sign = NE(BOOL_TO_BV(MSB(DUP(a)), 1), BOOL_TO_BV(MSB(b), 1));
	RzILOpBool *diff_result = NE(BOOL_TO_BV(MSB(a), 1), BOOL_TO_BV(MSB(r), 1));
	return AND(diff_sign, diff_result);
}

static RzILOpBool *signed_out_of_range(RzILOpPure *value, ut32 bits) {
	st64 min = -(1LL << (bits - 1));
	st64 max = (1LL << (bits - 1)) - 1;
	return OR(SLT(DUP(value), S64(min)), SGT(value, S64(max)));
}

static RzILOpBool *addx_overflow(ut32 bits) {
	RzILOpPure *sum = ADD(ADD(cast_signed(64, VARL("dst")), cast_signed(64, VARL("src"))), cast_unsigned(64, VARL("x")));
	return signed_out_of_range(sum, bits);
}

static RzILOpBool *subx_overflow(ut32 bits) {
	RzILOpPure *diff = SUB(SUB(cast_signed(64, VARL("dst")), cast_signed(64, VARL("src"))), cast_unsigned(64, VARL("x")));
	return signed_out_of_range(diff, bits);
}

static RzILOpBool *negx_overflow(ut32 bits) {
	RzILOpPure *diff = SUB(SUB(S64(0), cast_signed(64, VARL("dst"))), cast_unsigned(64, VARL("borrow")));
	return signed_out_of_range(diff, bits);
}

static RzILOpPure *reg_write_value(M68KILCtx *ctx, m68k_reg reg, ut32 bits, RzILOpPure *value) {
	if (rz_m68k_reg_is_dreg(reg) && bits < 32) {
		ut32 mask = bits == 8 ? 0xffffff00u : 0xffff0000u;
		return LOGOR(LOGAND(reg_value(ctx, reg), U32(mask)), cast_unsigned(32, value));
	}
	if (rz_m68k_reg_is_areg(reg) && bits == 16) {
		return extend_to_32(value, true);
	}
	if (reg == M68K_REG_CCR) {
		return cast_unsigned(8, value);
	}
	if (reg == M68K_REG_SR) {
		return cast_unsigned(16, value);
	}
	if (rz_m68k_reg_is_fpu(reg)) {
		return cast_unsigned(80, value);
	}
	const char *name = cs_reg_name(ctx->handle, reg);
	if (rz_m68k_reg_name_is_mmu_root_pointer(name)) {
		if (bits == 64) {
			return cast_unsigned(64, value);
		}
		return LOGOR(LOGAND(reg_value(ctx, reg), U64(0xffffffff00000000ULL)), cast_unsigned(64, value));
	}
	return cast_unsigned(32, value);
}

static RzILOpEffect *write_reg_sized(M68KILCtx *ctx, m68k_reg reg, ut32 bits, RzILOpPure *value) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		rz_il_op_pure_free(value);
		return NULL;
	}
	if (reg == M68K_REG_PC) {
		return JMP(cast_unsigned(32, value));
	}
	if (reg == M68K_REG_CCR) {
		return set_ccr_from_value(value);
	}
	if (reg == M68K_REG_SR) {
		bool has_master_stack = ctx->mode == CS_MODE_M68K_020 || ctx->mode == CS_MODE_M68K_030 ||
			ctx->mode == CS_MODE_M68K_040 || ctx->mode == CS_MODE_M68K_060;
		ut16 master_mask = has_master_stack ? 1u << M68K_SR_M : 0;
		RzILOpEffect *save_old_sp = BRANCH(
			IS_ZERO(LOGAND(cast_unsigned(16, VARG("sr")), U16(1u << M68K_SR_S))),
			SETG("usp", cast_unsigned(32, VARG("a7"))),
			BRANCH(
				NON_ZERO(LOGAND(cast_unsigned(16, VARG("sr")), U16(master_mask))),
				SETG("msp", cast_unsigned(32, VARG("a7"))),
				SETG("isp", cast_unsigned(32, VARG("a7")))));
		RzILOpEffect *load_new_sp = BRANCH(
			IS_ZERO(LOGAND(VARL("sr_write_value"), U16(1u << M68K_SR_S))),
			SETG("a7", cast_unsigned(32, VARG("usp"))),
			BRANCH(
				NON_ZERO(LOGAND(VARL("sr_write_value"), U16(master_mask))),
				SETG("a7", cast_unsigned(32, VARG("msp"))),
				SETG("a7", cast_unsigned(32, VARG("isp")))));
		RzILOpPure *old_bank = ITE(
			IS_ZERO(LOGAND(cast_unsigned(16, VARG("sr")), U16(1u << M68K_SR_S))),
			U8(0),
			ITE(NON_ZERO(LOGAND(cast_unsigned(16, VARG("sr")), U16(master_mask))), U8(2), U8(1)));
		RzILOpPure *new_bank = ITE(
			IS_ZERO(LOGAND(VARL("sr_write_value"), U16(1u << M68K_SR_S))),
			U8(0),
			ITE(NON_ZERO(LOGAND(VARL("sr_write_value"), U16(master_mask))), U8(2), U8(1)));
		return SEQ3(
			SETL("sr_write_value", cast_unsigned(16, value)),
			BRANCH(NE(old_bank, new_bank), SEQ2(save_old_sp, load_new_sp), EMPTY()),
			SETG("sr", VARL("sr_write_value")));
	}
	return SETG(name, reg_write_value(ctx, reg, bits, value));
}

static bool m68k_mode_uses_later_movem_base_value(cs_mode mode) {
	if (mode == CS_MODE_M68K_020 || mode == CS_MODE_M68K_030 ||
		mode == CS_MODE_M68K_040 || mode == CS_MODE_M68K_060) {
		return true;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	return mode == CS_MODE_M68K_CPU32;
#else
	return false;
#endif
}

static bool m68k_mode_has_format_word(cs_mode mode) {
	return mode != CS_MODE_M68K_000;
}

static RzILOpBool *rte_format_valid(cs_mode mode) {
	switch (mode) {
	case CS_MODE_M68K_010:
		return OR(EQ(VARL("format"), U16(0)), EQ(VARL("format"), U16(8)));
	case CS_MODE_M68K_020:
	case CS_MODE_M68K_030:
		return OR(
			OR(EQ(VARL("format"), U16(0)), EQ(VARL("format"), U16(1))),
			OR(OR(EQ(VARL("format"), U16(2)), EQ(VARL("format"), U16(9))),
				OR(EQ(VARL("format"), U16(10)), EQ(VARL("format"), U16(11)))));
	case CS_MODE_M68K_040:
		return OR(
			OR(EQ(VARL("format"), U16(0)), EQ(VARL("format"), U16(1))),
			OR(OR(EQ(VARL("format"), U16(2)), EQ(VARL("format"), U16(3))),
				OR(EQ(VARL("format"), U16(4)), EQ(VARL("format"), U16(7)))));
	case CS_MODE_M68K_060:
		return OR(
			OR(EQ(VARL("format"), U16(0)), EQ(VARL("format"), U16(2))),
			OR(EQ(VARL("format"), U16(3)), EQ(VARL("format"), U16(4))));
	default:
		break;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	if (mode == CS_MODE_M68K_CPU32) {
		return OR(
			OR(EQ(VARL("format"), U16(0)), EQ(VARL("format"), U16(1))),
			OR(EQ(VARL("format"), U16(2)), EQ(VARL("format"), U16(12))));
	}
#endif
	return OR(
		OR(OR(EQ(VARL("format"), U16(0)), EQ(VARL("format"), U16(1))),
			OR(EQ(VARL("format"), U16(2)), EQ(VARL("format"), U16(3)))),
		OR(OR(EQ(VARL("format"), U16(4)), EQ(VARL("format"), U16(7))),
			OR(OR(EQ(VARL("format"), U16(8)), EQ(VARL("format"), U16(9))),
				OR(EQ(VARL("format"), U16(10)), EQ(VARL("format"), U16(11))))));
}

static RzILOpPure *rte_frame_size(cs_mode mode) {
	RzILOpPure *size = ITE(EQ(VARL("format"), U16(0)), U32(8),
		ITE(EQ(VARL("format"), U16(1)), U32(8),
			ITE(EQ(VARL("format"), U16(2)), U32(12),
				ITE(EQ(VARL("format"), U16(3)), U32(12),
					ITE(EQ(VARL("format"), U16(4)), U32(16),
						ITE(EQ(VARL("format"), U16(7)), U32(60),
							ITE(EQ(VARL("format"), U16(8)), U32(58),
								ITE(EQ(VARL("format"), U16(9)), U32(20),
									ITE(EQ(VARL("format"), U16(10)), U32(32), U32(92))))))))));
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	if (mode == CS_MODE_M68K_CPU32) {
		size = ITE(EQ(VARL("format"), U16(12)), U32(24), size);
	}
#else
	(void)mode;
#endif
	return size;
}

static RzILOpPure *read_mem_sized(ut32 bits, RzILOpPure *addr) {
	if (bits == 8) {
		return LOAD(addr);
	}
	return LOADW(bits, addr);
}

static RzILOpEffect *write_mem_sized(ut32 bits, RzILOpPure *addr, RzILOpPure *value) {
	if (bits == 8) {
		return STORE(addr, cast_unsigned(8, value));
	}
	return STOREW(addr, cast_unsigned(bits, value));
}

static RzILOpPure *index_value(M68KILCtx *ctx, const cs_m68k_op *op) {
	if (op->mem.index_reg == M68K_REG_INVALID) {
		return U32(0);
	}
	RzILOpPure *idx = read_reg_sized(ctx, op->mem.index_reg, op->mem.index_size ? 32 : 16);
	if (!idx) {
		return NULL;
	}
	idx = extend_to_32(idx, !op->mem.index_size);
	ut8 scale = op->mem.scale ? op->mem.scale : 1;
	if (scale > 1) {
		idx = MUL(idx, U32(scale));
	}
	return idx;
}

#if !defined(RZ_CAPSTONE_HAS_M68K_CPU32) && !defined(RZ_CAPSTONE_HAS_M68K_COLDFIRE)
// Older Capstone releases report raw PC-relative displacements. Recover the
// encoded extension word address so operands after other extension words lift
// to the expected address.
static bool insn_word_at(const M68KILCtx *ctx, ut32 offset, ut16 *word) {
	if (!ctx || !ctx->insn || !word ||
		offset + 1 >= ctx->insn->size ||
		offset + 1 >= sizeof(ctx->insn->bytes)) {
		return false;
	}
	*word = ((ut16)ctx->insn->bytes[offset] << 8) | ctx->insn->bytes[offset + 1];
	return true;
}

static ut32 mem_extension_bytes(const cs_m68k_op *op) {
	switch (op->address_mode) {
	case M68K_AM_REGI_ADDR_DISP:
	case M68K_AM_PCI_DISP:
	case M68K_AM_ABSOLUTE_DATA_SHORT:
		return 2;
	case M68K_AM_AREGI_INDEX_8_BIT_DISP:
	case M68K_AM_PCI_INDEX_8_BIT_DISP:
		return 2;
	case M68K_AM_ABSOLUTE_DATA_LONG:
		return 4;
	case M68K_AM_AREGI_INDEX_BASE_DISP:
	case M68K_AM_MEMI_PRE_INDEX:
	case M68K_AM_MEMI_POST_INDEX:
	case M68K_AM_PCI_INDEX_BASE_DISP:
	case M68K_AM_PC_MEMI_PRE_INDEX:
	case M68K_AM_PC_MEMI_POST_INDEX: {
		ut32 bytes = 2;
		if (op->mem.in_disp) {
			bytes += 2;
		}
		if (op->mem.out_disp) {
			bytes += 2;
		}
		return bytes;
	}
	default:
		return 0;
	}
}

static ut32 operand_extension_bytes(const M68KILCtx *ctx, const cs_m68k_op *op) {
	switch (op->type) {
	case M68K_OP_IMM:
		return rz_m68k_detail_op_bits(ctx->m68k, 16) > 16 ? 4 : 2;
	case M68K_OP_FP_SINGLE:
		return 4;
	case M68K_OP_FP_DOUBLE:
		return 8;
	case M68K_OP_BR_DISP:
		if (op->br_disp.disp_size == M68K_OP_BR_DISP_SIZE_LONG) {
			return 4;
		}
		if (op->br_disp.disp_size == M68K_OP_BR_DISP_SIZE_WORD) {
			return 2;
		}
		return 0;
	case M68K_OP_MEM:
		return mem_extension_bytes(op);
	default:
		return 0;
	}
}

static ut32 hidden_extension_bytes_before_ea(const M68KILCtx *ctx) {
	switch (ctx->insn->id) {
	case M68K_INS_BFCHG:
	case M68K_INS_BFCLR:
	case M68K_INS_BFEXTS:
	case M68K_INS_BFEXTU:
	case M68K_INS_BFFFO:
	case M68K_INS_BFINS:
	case M68K_INS_BFSET:
	case M68K_INS_BFTST:
	case M68K_INS_CHK2:
	case M68K_INS_CMP2:
	case M68K_INS_MOVES:
		return 2;
	default:
		break;
	}
	return ctx->insn->size >= 4 && (ctx->insn->bytes[0] & 0xf0) == 0xf0 ? 2 : 0;
}

static ut32 expected_pc_relative_extension_offset(const M68KILCtx *ctx, const cs_m68k_op *op) {
	ut32 offset = 2 + hidden_extension_bytes_before_ea(ctx);
	for (ut8 i = 0; i < ctx->m68k->op_count; i++) {
		const cs_m68k_op *cur = &ctx->m68k->operands[i];
		if (cur == op) {
			break;
		}
		offset += operand_extension_bytes(ctx, cur);
	}
	return offset;
}

static bool index_extension_word_matches(const cs_m68k_op *op, ut16 word, bool full) {
	if (((word & 0x0100) != 0) != full) {
		return false;
	}
	if (op->mem.index_reg == M68K_REG_INVALID) {
		return full && (word & 0x0040);
	}
	m68k_reg index_reg = ((word & 0x8000) ? M68K_REG_A0 : M68K_REG_D0) +
		((word >> 12) & 7);
	if (op->mem.index_reg != index_reg) {
		return false;
	}
	if (op->mem.index_size != ((word & 0x0800) ? 1 : 0)) {
		return false;
	}
	ut8 scale = 1 << ((word >> 9) & 3);
	return (op->mem.scale ? op->mem.scale : 1) == scale;
}

static bool pc_relative_extension_word_matches(const cs_m68k_op *op, ut16 word) {
	switch (op->address_mode) {
	case M68K_AM_PCI_DISP:
		return (st16)word == op->mem.disp;
	case M68K_AM_PCI_INDEX_8_BIT_DISP:
		return index_extension_word_matches(op, word, false) && (st8)(word & 0xff) == op->mem.disp;
	case M68K_AM_PCI_INDEX_BASE_DISP:
	case M68K_AM_PC_MEMI_PRE_INDEX:
	case M68K_AM_PC_MEMI_POST_INDEX:
		return index_extension_word_matches(op, word, true);
	default:
		return false;
	}
}

static ut32 pc_relative_extension_offset(const M68KILCtx *ctx, const cs_m68k_op *op) {
	ut32 expected = expected_pc_relative_extension_offset(ctx, op);
	ut16 word = 0;
	if (insn_word_at(ctx, expected, &word) && pc_relative_extension_word_matches(op, word)) {
		return expected;
	}

	ut32 fallback = expected;
	bool found = false;
	for (ut32 offset = 2; offset + 1 < ctx->insn->size; offset += 2) {
		if (!insn_word_at(ctx, offset, &word) || !pc_relative_extension_word_matches(op, word)) {
			continue;
		}
		if (offset >= expected) {
			return offset;
		}
		if (!found) {
			fallback = offset;
			found = true;
		}
	}
	return fallback;
}
#endif

static ut64 branch_disp_base(const M68KILCtx *ctx) {
	// M68K branch displacements are relative to the opcode-word successor,
	// not to the full instruction fallthrough address.
	return ctx->addr + 2;
}

static ut64 pc_relative_base(M68KILCtx *ctx, const cs_m68k_op *op) {
#if defined(RZ_CAPSTONE_HAS_M68K_CPU32) || defined(RZ_CAPSTONE_HAS_M68K_COLDFIRE)
	return branch_disp_base(ctx);
#else
	return ctx->addr + pc_relative_extension_offset(ctx, op);
#endif
}

static RzILOpPure *branch_disp_target(const M68KILCtx *ctx, const cs_m68k_op *op) {
	if (!op || op->type != M68K_OP_BR_DISP) {
		return NULL;
	}
	return u32(branch_disp_base(ctx) + op->br_disp.disp);
}

static RzILOpEffect *set_addr_reg_delta(M68KILCtx *ctx, m68k_reg reg, st32 delta) {
	if (!rz_m68k_reg_is_areg(reg)) {
		return NULL;
	}
	RzILOpPure *base = reg_value(ctx, reg);
	RzILOpPure *res = delta >= 0 ? ADD(base, U32((ut32)delta)) : SUB(base, U32((ut32)-delta));
	return write_reg_sized(ctx, reg, 32, res);
}

static M68KEA effective_addr(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits) {
	M68KEA ea = { 0 };
	RzILOpPure *base = NULL;
	RzILOpPure *idx = NULL;
	m68k_reg base_reg = rz_m68k_op_base_reg(op);
	ut32 bytes = rz_m68k_bits_access_bytes(bits);
	switch (op->address_mode) {
	case M68K_AM_REGI_ADDR:
		ea.addr = reg_value(ctx, base_reg);
		break;
	case M68K_AM_REGI_ADDR_POST_INC:
		ea.addr = reg_value(ctx, base_reg);
		ea.post = set_addr_reg_delta(ctx, base_reg, rz_m68k_reg_stack_access_bytes(base_reg, bits));
		break;
	case M68K_AM_REGI_ADDR_PRE_DEC:
		ea.pre = set_addr_reg_delta(ctx, base_reg, -(st32)rz_m68k_reg_stack_access_bytes(base_reg, bits));
		ea.addr = reg_value(ctx, base_reg);
		break;
	case M68K_AM_REGI_ADDR_DISP:
		ea.addr = append_addr_add(reg_value(ctx, base_reg), s32(op->mem.disp));
		break;
	case M68K_AM_AREGI_INDEX_8_BIT_DISP:
	case M68K_AM_AREGI_INDEX_BASE_DISP: {
		st64 disp = op->address_mode == M68K_AM_AREGI_INDEX_BASE_DISP ? op->mem.in_disp : op->mem.disp;
		base = base_reg != M68K_REG_INVALID ? reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(append_addr_add(base, s32(disp)), idx);
		break;
	}
	case M68K_AM_MEMI_PRE_INDEX:
		base = base_reg != M68K_REG_INVALID ? reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(read_mem_sized(32, ADD(ADD(base, idx), s32(op->mem.in_disp))), s32(op->mem.out_disp));
		break;
	case M68K_AM_MEMI_POST_INDEX:
		base = base_reg != M68K_REG_INVALID ? reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(ADD(read_mem_sized(32, ADD(base, s32(op->mem.in_disp))), idx), s32(op->mem.out_disp));
		break;
	case M68K_AM_PCI_DISP:
		ea.addr = u32((st64)(ut32)pc_relative_base(ctx, op) + op->mem.disp);
		break;
	case M68K_AM_PCI_INDEX_8_BIT_DISP:
	case M68K_AM_PCI_INDEX_BASE_DISP: {
		st64 disp = op->address_mode == M68K_AM_PCI_INDEX_BASE_DISP ? op->mem.in_disp : op->mem.disp;
		idx = index_value(ctx, op);
		ea.addr = ADD(u32((st64)(ut32)pc_relative_base(ctx, op) + disp), idx);
		break;
	}
	case M68K_AM_PC_MEMI_PRE_INDEX:
		idx = index_value(ctx, op);
		ea.addr = ADD(read_mem_sized(32, ADD(ADD(u32(pc_relative_base(ctx, op)), idx), s32(op->mem.in_disp))), s32(op->mem.out_disp));
		break;
	case M68K_AM_PC_MEMI_POST_INDEX:
		idx = index_value(ctx, op);
		ea.addr = ADD(ADD(read_mem_sized(32, ADD(u32(pc_relative_base(ctx, op)), s32(op->mem.in_disp))), idx), s32(op->mem.out_disp));
		break;
	case M68K_AM_ABSOLUTE_DATA_SHORT:
		ea.addr = u32(rz_m68k_op_absolute_address(op, true));
		break;
	case M68K_AM_ABSOLUTE_DATA_LONG:
		ea.addr = u32(rz_m68k_op_absolute_address(op, false));
		break;
	default:
		if (rz_m68k_op_is_mem_addr(op) && base_reg != M68K_REG_INVALID) {
			ea.addr = ADD(reg_value(ctx, base_reg), s32(op->mem.disp));
		} else if (rz_m68k_op_is_mem_addr(op)) {
			ea.addr = u32(rz_m68k_op_absolute_address(op, false));
		}
		break;
	}
	(void)bytes;
	return ea;
}

static RzILOpPure *read_operand(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits, RzILOpEffect **pre, RzILOpEffect **post) {
	if (pre) {
		*pre = NULL;
	}
	if (post) {
		*post = NULL;
	}
	if (rz_m68k_op_is_mem_addr(op)) {
		M68KEA ea = effective_addr(ctx, op, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return NULL;
		}
		if (pre) {
			*pre = ea.pre;
		}
		if (post) {
			*post = ea.post;
		}
		return read_mem_sized(bits, ea.addr);
	}
	switch (op->type) {
	case M68K_OP_REG:
		return read_reg_sized(ctx, op->reg, bits);
	case M68K_OP_IMM:
		return UN(bits, op->imm);
	case M68K_OP_BR_DISP:
		return branch_disp_target(ctx, op);
	case M68K_OP_FP_SINGLE:
		return F2BV(F32(op->simm));
	case M68K_OP_FP_DOUBLE:
		return F2BV(F64(op->dimm));
	default:
		return NULL;
	}
}

static RzILOpEffect *write_operand(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits, RzILOpPure *value, RzILOpEffect **pre, RzILOpEffect **post) {
	if (pre) {
		*pre = NULL;
	}
	if (post) {
		*post = NULL;
	}
	if (rz_m68k_op_is_mem_addr(op)) {
		M68KEA ea = effective_addr(ctx, op, bits);
		if (!ea.addr) {
			rz_il_op_pure_free(value);
			m68k_ea_fini(&ea);
			return NULL;
		}
		if (pre) {
			*pre = ea.pre;
		}
		if (post) {
			*post = ea.post;
		}
		return write_mem_sized(bits, ea.addr, value);
	}
	switch (op->type) {
	case M68K_OP_REG:
		return write_reg_sized(ctx, op->reg, bits, value);
	default:
		rz_il_op_pure_free(value);
		return NULL;
	}
}

static RzILOpEffect *m68k_label(const char *label) {
	if (!strcmp(label, "m68k_illegal")) {
		RzILOpEffect *seq = SETL("trap_op", U32((ut32)M68K_TRAP_OP_ILLEGAL));
		seq = seq_append(seq, SETL("trap_vector", U32((ut32)M68K_VECTOR_ILLEGAL)));
		return seq_append(seq, GOTO(label));
	}
	if (!strcmp(label, "m68k_privilege")) {
		RzILOpEffect *seq = SETL("trap_op", U32((ut32)M68K_TRAP_OP_PRIVILEGE));
		seq = seq_append(seq, SETL("trap_vector", U32((ut32)M68K_VECTOR_PRIVILEGE)));
		return seq_append(seq, GOTO(label));
	}
	return GOTO(label);
}

static RzILOpEffect *guard_supervisor(RzILOpEffect *effect) {
	return effect ? BRANCH(supervisor_mode(), effect, m68k_label("m68k_privilege")) : NULL;
}

static RzILOpEffect *m68k_invalid(void) {
	return NOP();
}

static RzILOpEffect *m68k_invalid_free(RzILOpEffect *seq) {
	rz_il_op_effect_free(seq);
	return m68k_invalid();
}

static bool rz_m68k_op_is_status_reg(const cs_m68k_op *op) {
	if (!op || op->type != M68K_OP_REG) {
		return false;
	}
	return op->reg == M68K_REG_CCR || op->reg == M68K_REG_SR;
}

static RzILOpEffect *write_status_reg_unchecked(M68KILCtx *ctx, m68k_reg reg, RzILOpPure *value) {
	ut32 bits = reg == M68K_REG_CCR ? 8 : 16;
	return write_reg_sized(ctx, reg, bits, value);
}

static RzILOpEffect *write_status_reg(M68KILCtx *ctx, m68k_reg reg, RzILOpPure *value) {
	RzILOpEffect *write = write_status_reg_unchecked(ctx, reg, value);
	if (!write) {
		return NULL;
	}
	return reg == M68K_REG_SR ? BRANCH(supervisor_mode(), write, m68k_label("m68k_privilege")) : write;
}

static RzILOpEffect *m68k_null_free(RzILOpEffect *seq) {
	rz_il_op_effect_free(seq);
	return NULL;
}

static RzILOpEffect *m68k_effect_free(RzILOpEffect *seq, RzILOpEffect *effect) {
	rz_il_op_effect_free(seq);
	return effect;
}

static void m68k_ea_fini(M68KEA *ea) {
	if (!ea) {
		return;
	}
	rz_il_op_pure_free(ea->addr);
	rz_il_op_effect_free(ea->pre);
	rz_il_op_effect_free(ea->post);
	*ea = (M68KEA){ 0 };
}

static void m68k_rw_operand_fini(M68KRWOperand *rw) {
	if (!rw) {
		return;
	}
	rz_il_op_effect_free(rw->post);
	*rw = (M68KRWOperand){ 0 };
}

static void m68k_bitfield_target_fini(M68KBitfieldTarget *target) {
	if (!target) {
		return;
	}
	rz_il_op_effect_free(target->post);
	*target = (M68KBitfieldTarget){ 0 };
}

static RzILOpEffect *m68k_exception(M68KTrapOp trap_op, M68KExceptionVector vector, const char *label) {
	RzILOpEffect *seq = SETL("trap_op", U32((ut32)trap_op));
	seq = seq_append(seq, SETL("trap_vector", U32((ut32)vector)));
	return seq_append(seq, m68k_label(label));
}

static RzILOpEffect *operand_to_local(M68KILCtx *ctx, const char *name, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq) {
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpPure *value = read_operand(ctx, op, bits, &pre, &post);
	if (!value) {
		return NULL;
	}
	*seq = seq_append(*seq, pre);
	*seq = seq_append(*seq, SETL(name, value));
	*seq = seq_append(*seq, post);
	return *seq;
}

static bool rw_operand_to_local(M68KILCtx *ctx, M68KRWOperand *rw, const char *value_local, const char *addr_local, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq) {
	rz_return_val_if_fail(rw && seq && op, false);
	*rw = (M68KRWOperand){
		.op = op,
		.addr_local = addr_local,
		.post = NULL,
	};
	if (rz_m68k_op_is_mem_addr(op)) {
		M68KEA ea = effective_addr(ctx, op, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return false;
		}
		*seq = seq_append(*seq, ea.pre);
		*seq = seq_append(*seq, SETL(addr_local, cast_unsigned(32, ea.addr)));
		*seq = seq_append(*seq, SETL(value_local, read_mem_sized(bits, VARL(addr_local))));
		rw->post = ea.post;
		return true;
	}
	switch (op->type) {
	case M68K_OP_REG: {
		RzILOpPure *value = read_reg_sized(ctx, op->reg, bits);
		if (!value) {
			return false;
		}
		*seq = seq_append(*seq, SETL(value_local, value));
		return true;
	}
	default:
		return false;
	}
}

static RzILOpEffect *write_rw_operand(M68KILCtx *ctx, const M68KRWOperand *rw, ut32 bits, RzILOpPure *value) {
	rz_return_val_if_fail(rw && rw->op, NULL);
	if (rz_m68k_op_is_mem_addr(rw->op)) {
		return write_mem_sized(bits, VARL(rw->addr_local), value);
	}
	switch (rw->op->type) {
	case M68K_OP_REG:
		return write_reg_sized(ctx, rw->op->reg, bits, value);
	default:
		rz_il_op_pure_free(value);
		return NULL;
	}
}

static RzILOpEffect *lift_move(M68KILCtx *ctx, bool address_dst) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	bool uses_usp = (src->type == M68K_OP_REG && src->reg == M68K_REG_USP) ||
		(dst->type == M68K_OP_REG && dst->reg == M68K_REG_USP);
	bool reads_sr = src->type == M68K_OP_REG && src->reg == M68K_REG_SR;
	bool reads_ccr = src->type == M68K_OP_REG && src->reg == M68K_REG_CCR;
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "src", src, bits, &seq)) {
		return m68k_invalid();
	}
	if (rz_m68k_op_is_status_reg(dst)) {
		RzILOpEffect *write = write_status_reg_unchecked(ctx, dst->reg, VARL("src"));
		if (!write) {
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, write);
		return dst->reg == M68K_REG_SR ? BRANCH(supervisor_mode(), seq, m68k_label("m68k_privilege")) : seq;
	}
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpEffect *write = write_operand(ctx, dst, bits, VARL("src"), &pre, &post);
	if (!write) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, pre);
	seq = seq_append(seq, write);
	seq = seq_append(seq, post);
	if (!address_dst && !uses_usp && !reads_sr && !reads_ccr) {
		seq = seq_append(seq, set_flags_nzvcx(VARL("src"), bits, IL_FALSE, IL_FALSE, NULL));
	}
	if (uses_usp || (reads_sr && ctx->mode != CS_MODE_M68K_000)) {
		return BRANCH(supervisor_mode(), seq, m68k_label("m68k_privilege"));
	}
	return seq;
}

static RzILOpEffect *lift_moveq(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || ctx->m68k->operands[1].type != M68K_OP_REG) {
		return m68k_invalid();
	}
	RzILOpPure *value = S32((st8)ctx->m68k->operands[0].imm);
	return SEQ3(
		SETL("res", DUP(value)),
		write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, value),
		set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_movec(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 ||
		ctx->m68k->operands[0].type != M68K_OP_REG ||
		ctx->m68k->operands[1].type != M68K_OP_REG) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	bool src_control = rz_m68k_op_is_control_reg(src);
	bool dst_control = rz_m68k_op_is_control_reg(dst);
	bool src_gpr = rz_m68k_op_is_gpr(src);
	bool dst_gpr = rz_m68k_op_is_gpr(dst);
	if (src_control == dst_control ||
		(!src_control && !src_gpr) ||
		(!dst_control && !dst_gpr)) {
		return m68k_invalid();
	}
	RzILOpPure *value = read_reg_sized(ctx, src->reg, 32);
	if (!value) {
		return m68k_invalid();
	}
	RzILOpEffect *write = write_reg_sized(ctx, dst->reg, 32, value);
	if (!write) {
		return m68k_invalid();
	}
	return BRANCH(supervisor_mode(), write, m68k_label("m68k_privilege"));
}

static RzILOpEffect *lift_moves(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	bool src_reg = rz_m68k_op_is_gpr(src);
	bool dst_reg = rz_m68k_op_is_gpr(dst);
	bool src_mem = rz_m68k_op_is_mem_addr(src);
	bool dst_mem = rz_m68k_op_is_mem_addr(dst);
	if (!((src_reg && dst_mem) || (src_mem && dst_reg))) {
		return m68k_invalid();
	}

	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	if (src_mem) {
		M68KEA ea = effective_addr(ctx, src, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return m68k_invalid();
		}
		RzILOpEffect *write = write_reg_sized(ctx, dst->reg, bits, VARL("src"));
		if (!write) {
			m68k_ea_fini(&ea);
			return m68k_invalid();
		}
		seq = seq_append(seq, ea.pre);
		seq = seq_append(seq, SETL("moves_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
		seq = seq_append(seq, SETL("moves_fc", read_reg_sized(ctx, M68K_REG_SFC, 32)));
		seq = seq_append(seq, SETL("moves_store", U32(0)));
		seq = seq_append(seq, SETL("moves_bits", U32(bits)));
		seq = seq_append(seq, SETL("src", read_mem_sized(bits, VARL("moves_addr"))));
		seq = seq_append(seq, ea.post);
		seq = seq_append(seq, write);
	} else {
		RzILOpPure *value = read_reg_sized(ctx, src->reg, bits);
		M68KEA ea = effective_addr(ctx, dst, bits);
		if (!value || !ea.addr) {
			rz_il_op_pure_free(value);
			m68k_ea_fini(&ea);
			return m68k_invalid();
		}
		seq = seq_append(seq, SETL("src", value));
		seq = seq_append(seq, ea.pre);
		seq = seq_append(seq, SETL("moves_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
		seq = seq_append(seq, SETL("moves_fc", read_reg_sized(ctx, M68K_REG_DFC, 32)));
		seq = seq_append(seq, SETL("moves_store", U32(1)));
		seq = seq_append(seq, SETL("moves_bits", U32(bits)));
		seq = seq_append(seq, write_mem_sized(bits, VARL("moves_addr"), VARL("src")));
		seq = seq_append(seq, ea.post);
	}
	return BRANCH(supervisor_mode(), seq, m68k_label("m68k_privilege"));
}

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static RzILOpPure *bit_at32(const char *local, ut32 bit) {
	return EXTRACT32(VARL(local), U32(bit), U32(1));
}

static RzILOpPure *reverse_bits32(const char *local) {
	RzILOpPure *res = U32(0);
	for (ut32 i = 0; i < 32; i++) {
		RzILOpPure *bit = bit_at32(local, i);
		if (i != 31) {
			bit = SHIFTL0(bit, U8(31 - i));
		}
		res = LOGOR(res, bit);
	}
	return res;
}

static RzILOpPure *reverse_bytes32(const char *local) {
	return LOGOR(
		LOGOR(
			SHIFTL0(LOGAND(VARL(local), U32(0xff)), U8(24)),
			SHIFTL0(LOGAND(VARL(local), U32(0xff00)), U8(8))),
		LOGOR(
			LOGAND(SHIFTR0(VARL(local), U8(8)), U32(0xff00)),
			SHIFTR0(VARL(local), U8(24))));
}

static RzILOpPure *ff1_result32(const char *local) {
	RzILOpPure *res = U32(32);
	for (ut32 bit = 0; bit < 32; bit++) {
		res = ITE(NON_ZERO(bit_at32(local, bit)), U32(31 - bit), res);
	}
	return res;
}

static RzILOpEffect *set_flags_ff1(RzILOpPure *source) {
	RzILOpPure *src = cast_unsigned(32, source);
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xe0));
	ccr = ccr_with_flag(ccr, M68K_CCR_N, MSB(DUP(src)));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, IS_ZERO(src));
	ccr = ccr_with_flag(ccr, M68K_CCR_V, IL_FALSE);
	ccr = ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	ccr = LOGOR(ccr, LOGAND(cast_unsigned(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	return set_ccr_from_value(ccr);
}

static RzILOpEffect *set_flags_rem(RzILOpPure *quotient, RzILOpBool *overflow) {
	RzILOpPure *quotient32 = cast_unsigned(32, quotient);
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xe0));
	RzILOpBool *no_overflow = INV((RzILOpBool *)DUP(overflow));
	ccr = ccr_with_flag(ccr, M68K_CCR_N, AND(no_overflow, MSB(DUP(quotient32))));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, AND(INV((RzILOpBool *)DUP(overflow)), IS_ZERO(quotient32)));
	ccr = ccr_with_flag(ccr, M68K_CCR_V, overflow);
	ccr = ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	ccr = LOGOR(ccr, LOGAND(cast_unsigned(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	return set_ccr_from_value(ccr);
}

static RzILOpEffect *lift_mov3q(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return m68k_invalid();
	}
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpPure *value = U32((ut32)ctx->m68k->operands[0].imm);
	RzILOpEffect *write = write_operand(ctx, dst, 32, VARL("res"), &pre, &post);
	if (!write && dst->type == M68K_OP_IMM) {
		write = write_mem_sized(32, u32((ut32)dst->imm), VARL("res"));
	}
	if (!write) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, pre);
	seq = seq_append(seq, SETL("res", value));
	seq = seq_append(seq, write);
	seq = seq_append(seq, post);
	return seq_append(seq, set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_movclr(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || ctx->m68k->operands[0].type != M68K_OP_REG || ctx->m68k->operands[1].type != M68K_OP_REG) {
		return m68k_invalid();
	}
	m68k_reg acc = ctx->m68k->operands[0].reg;
	m68k_reg dst = ctx->m68k->operands[1].reg;
	return SEQ3(
		SETL("src", read_reg_sized(ctx, acc, 32)),
		write_reg_sized(ctx, dst, 32, VARL("src")),
		write_reg_sized(ctx, acc, 32, U32(0)));
}

static RzILOpEffect *lift_mvs_mvz(M68KILCtx *ctx, bool sign_extend) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (bits != 8 && bits != 16) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "src", &ctx->m68k->operands[0], bits, &seq)) {
		return m68k_invalid();
	}
	seq = seq_append(seq, SETL("res", extend_to_32(VARL("src"), sign_extend)));
	seq = seq_append(seq, write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, VARL("res")));
	return seq_append(seq, set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_coldfire_debug_transfer(M68KILCtx *ctx, ut32 bits) {
	if (ctx->m68k->op_count < 1 || !rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0])) {
		return m68k_invalid();
	}
	const cs_m68k_op *op = &ctx->m68k->operands[0];
	if (op->type == M68K_OP_MEM && op->address_mode == M68K_AM_NONE) {
		return m68k_invalid();
	}
	M68KEA ea = effective_addr(ctx, op, bits);
	if (!ea.addr) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, SETL("debug_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
	seq = seq_append(seq, SETL("debug_data", read_mem_sized(bits, VARL("debug_addr"))));
	seq = seq_append(seq, ea.post);
	seq = seq_append(seq, SETL("debug_op", U32(ctx->insn->id == M68K_INS_WDEBUG ? M68K_DEBUG_OP_DEBUG : M68K_DEBUG_OP_DATA)));
	seq = seq_append(seq, SETL("debug_bits", U32(bits)));
	return seq_append(seq, m68k_label("m68k_debug"));
}

static bool coprocessor_number(M68KILCtx *ctx, ut32 *cp_num) {
	switch (ctx->insn->id) {
	case M68K_INS_CP0BCBUSY:
	case M68K_INS_CP0LD:
	case M68K_INS_CP0ST:
	case M68K_INS_CP0NOP:
		*cp_num = 0;
		return true;
	case M68K_INS_CP1BCBUSY:
	case M68K_INS_CP1LD:
	case M68K_INS_CP1ST:
	case M68K_INS_CP1NOP:
		*cp_num = 1;
		return true;
	default:
		return false;
	}
}

static bool coprocessor_operation(ut32 insn_id, M68KCoprocessorOp *op) {
	switch (insn_id) {
	case M68K_INS_CP0NOP:
	case M68K_INS_CP1NOP:
		*op = M68K_CP_OP_NOP;
		return true;
	case M68K_INS_CP0BCBUSY:
	case M68K_INS_CP1BCBUSY:
		*op = M68K_CP_OP_BRANCH;
		return true;
	case M68K_INS_CP0LD:
	case M68K_INS_CP1LD:
		*op = M68K_CP_OP_LOAD;
		return true;
	case M68K_INS_CP0ST:
	case M68K_INS_CP1ST:
		*op = M68K_CP_OP_STORE;
		return true;
	default:
		return false;
	}
}

static RzILOpEffect *append_coprocessor_common(M68KILCtx *ctx, RzILOpEffect *seq) {
	ut32 cp_num = 0;
	if (coprocessor_number(ctx, &cp_num)) {
		seq = seq_append(seq, SETL("cp_num", U32(cp_num)));
	}
	M68KCoprocessorOp cp_op = M68K_CP_OP_NOP;
	if (coprocessor_operation(ctx->insn->id, &cp_op)) {
		seq = seq_append(seq, SETL("cp_op", U32((ut32)cp_op)));
	}
	return seq;
}

static bool coprocessor_transfer_is_store(M68KILCtx *ctx) {
	switch (ctx->insn->id) {
	case M68K_INS_CP0ST:
	case M68K_INS_CP1ST:
		return true;
	default:
		return false;
	}
}

static RzILOpEffect *append_coprocessor_transfer_metadata(M68KILCtx *ctx, RzILOpEffect *seq, ut32 bits) {
	seq = append_coprocessor_common(ctx, seq);
	seq = seq_append(seq, SETL("cp_store", U32(coprocessor_transfer_is_store(ctx) ? 1 : 0)));
	seq = seq_append(seq, SETL("cp_bits", U32(bits)));
	if (ctx->m68k->op_count > 2 && ctx->m68k->operands[2].type == M68K_OP_IMM) {
		seq = seq_append(seq, SETL("cp_selector", U32((ut32)ctx->m68k->operands[2].imm)));
	}
	if (ctx->m68k->op_count > 3 && ctx->m68k->operands[3].type == M68K_OP_IMM) {
		seq = seq_append(seq, SETL("cp_extension", U32((ut32)ctx->m68k->operands[3].imm)));
	}
	return seq;
}

static RzILOpEffect *lift_coprocessor_load_transfer(M68KILCtx *ctx, ut32 bits) {
	if (ctx->m68k->op_count < 1) {
		return m68k_label("m68k_coprocessor");
	}

	const cs_m68k_op *src = &ctx->m68k->operands[0];
	RzILOpEffect *seq = NULL;
	if (src->type == M68K_OP_MEM && src->address_mode == M68K_AM_NONE) {
		return m68k_label("m68k_coprocessor");
	}
	if (rz_m68k_op_is_mem_addr(src)) {
		M68KEA ea = effective_addr(ctx, src, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, ea.pre);
		seq = seq_append(seq, SETL("cp_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
		seq = seq_append(seq, SETL("cp_data", read_mem_sized(bits, VARL("cp_addr"))));
		seq = seq_append(seq, ea.post);
	} else {
		RzILOpPure *value = read_operand(ctx, src, bits, NULL, NULL);
		if (!value) {
			return m68k_label("m68k_coprocessor");
		}
		seq = seq_append(seq, SETL("cp_data", value));
	}
	seq = append_coprocessor_transfer_metadata(ctx, seq, bits);
	return seq_append(seq, m68k_label("m68k_coprocessor"));
}

static RzILOpEffect *coprocessor_metadata_only_transfer(M68KILCtx *ctx, ut32 bits) {
	RzILOpEffect *seq = NULL;
	seq = append_coprocessor_transfer_metadata(ctx, seq, bits);
	return seq_append(seq, m68k_label("m68k_coprocessor"));
}

static RzILOpPure *coprocessor_external_data(ut32 bits) {
	return bits == 32 ? VARG("cp_external_data") : cast_unsigned(bits, VARG("cp_external_data"));
}

static RzILOpEffect *lift_coprocessor_store_transfer(M68KILCtx *ctx, ut32 bits) {
	if (ctx->m68k->op_count < 2) {
		return coprocessor_metadata_only_transfer(ctx, bits);
	}

	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if (dst->type == M68K_OP_MEM && dst->address_mode == M68K_AM_NONE) {
		return m68k_label("m68k_coprocessor");
	}

	RzILOpEffect *seq = SETL("cp_data", coprocessor_external_data(bits));
	if (rz_m68k_op_is_mem_addr(dst)) {
		M68KEA ea = effective_addr(ctx, dst, bits);
		if (!ea.addr) {
			return m68k_invalid();
		}
		seq = seq_append(seq, ea.pre);
		seq = seq_append(seq, SETL("cp_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
		seq = seq_append(seq, write_mem_sized(bits, VARL("cp_addr"), VARL("cp_data")));
		seq = seq_append(seq, ea.post);
	} else if (dst->type == M68K_OP_REG) {
		RzILOpEffect *write = write_reg_sized(ctx, dst->reg, bits, VARL("cp_data"));
		if (!write) {
			return coprocessor_metadata_only_transfer(ctx, bits);
		}
		seq = seq_append(seq, write);
	} else {
		return coprocessor_metadata_only_transfer(ctx, bits);
	}

	seq = append_coprocessor_transfer_metadata(ctx, seq, bits);
	return seq_append(seq, m68k_label("m68k_coprocessor"));
}

static RzILOpEffect *lift_coprocessor_transfer(M68KILCtx *ctx) {
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (coprocessor_transfer_is_store(ctx)) {
		return lift_coprocessor_store_transfer(ctx, bits);
	}
	return lift_coprocessor_load_transfer(ctx, bits);
}

static RzILOpEffect *lift_coprocessor_branch(M68KILCtx *ctx) {
	RzILOpEffect *seq = append_coprocessor_common(ctx, NULL);
	if (ctx->m68k->op_count > 0 && ctx->m68k->operands[0].type == M68K_OP_BR_DISP) {
		seq = seq_append(seq, SETL("cp_branch", read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL)));
	}
	return seq_append(seq, m68k_label("m68k_coprocessor"));
}

static RzILOpEffect *lift_coprocessor_nop(M68KILCtx *ctx) {
	RzILOpEffect *seq = append_coprocessor_common(ctx, NULL);
	if (ctx->m68k->op_count > 0 && ctx->m68k->operands[0].type == M68K_OP_IMM) {
		seq = seq_append(seq, SETL("cp_extension", U32((ut32)ctx->m68k->operands[0].imm)));
	}
	return seq_append(seq, m68k_label("m68k_coprocessor"));
}
#endif

static RzILOpEffect *append_fpu_state_metadata(M68KILCtx *ctx, RzILOpEffect *seq) {
	seq = seq_append(seq, SETL("fpu_state_op", U32(ctx->insn->id == M68K_INS_FRESTORE ? M68K_FPU_STATE_RESTORE : M68K_FPU_STATE_SAVE)));
	return seq;
}

static RzILOpEffect *lift_fpu_state_address_effects(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}

	const cs_m68k_op *op = &ctx->m68k->operands[0];
	if (op->type == M68K_OP_MEM && op->address_mode == M68K_AM_NONE) {
		return m68k_invalid();
	}
	if (!rz_m68k_op_is_mem_addr(op)) {
		return m68k_invalid();
	}

	if (op->address_mode == M68K_AM_REGI_ADDR_PRE_DEC) {
		m68k_reg base_reg = rz_m68k_op_base_reg(op);
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return m68k_invalid();
		}
		RzILOpEffect *seq = NULL;
		seq = seq_append(seq, SETL("fpu_state_base", cast_unsigned(M68K_ADDR_BITS, reg_value(ctx, base_reg))));
		seq = seq_append(seq, SETL("fpu_state_predec", U32(1)));
		seq = append_fpu_state_metadata(ctx, seq);
		return guard_supervisor(seq_append(seq, m68k_label("m68k_fpu")));
	}
	if (op->address_mode == M68K_AM_REGI_ADDR_POST_INC) {
		if (ctx->insn->id != M68K_INS_FRESTORE) {
			RzILOpEffect *seq = append_fpu_state_metadata(ctx, NULL);
			return guard_supervisor(seq_append(seq, m68k_label("m68k_fpu")));
		}
		m68k_reg base_reg = rz_m68k_op_base_reg(op);
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return m68k_invalid();
		}
		RzILOpEffect *seq = NULL;
		seq = seq_append(seq, SETL("fpu_state_addr", cast_unsigned(M68K_ADDR_BITS, reg_value(ctx, base_reg))));
		seq = seq_append(seq, SETL("fpu_state_base", cast_unsigned(M68K_ADDR_BITS, reg_value(ctx, base_reg))));
		seq = seq_append(seq, SETL("fpu_state_postinc", U32(1)));
		seq = append_fpu_state_metadata(ctx, seq);
		return guard_supervisor(seq_append(seq, m68k_label("m68k_fpu")));
	}

	M68KEA ea = effective_addr(ctx, op, 32);
	if (!ea.addr) {
		m68k_ea_fini(&ea);
		return m68k_invalid();
	}

	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, SETL("fpu_state_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
	seq = seq_append(seq, ea.post);
	seq = append_fpu_state_metadata(ctx, seq);
	return guard_supervisor(seq_append(seq, m68k_label("m68k_fpu")));
}

static RzILOpPure *callm_frame_addr(ut32 offset) {
	return offset ? ADD(VARL("callm_frame"), U32(offset)) : VARL("callm_frame");
}

static m68k_reg callm_reg_from_code(ut32 code) {
	static const m68k_reg regs[] = {
		M68K_REG_D0,
		M68K_REG_D1,
		M68K_REG_D2,
		M68K_REG_D3,
		M68K_REG_D4,
		M68K_REG_D5,
		M68K_REG_D6,
		M68K_REG_D7,
		M68K_REG_A0,
		M68K_REG_A1,
		M68K_REG_A2,
		M68K_REG_A3,
		M68K_REG_A4,
		M68K_REG_A5,
		M68K_REG_A6,
		M68K_REG_A7,
	};
	return code < RZ_ARRAY_SIZE(regs) ? regs[code] : M68K_REG_INVALID;
}

static RzILOpBool *callm_reg_code_is(ut32 code) {
	return EQ(VARL("callm_reg_code"), U32(code));
}

static RzILOpEffect *callm_store_selected_reg(M68KILCtx *ctx) {
	RzILOpEffect *effect = EMPTY();
	for (st32 code = 15; code >= 0; code--) {
		m68k_reg reg = callm_reg_from_code((ut32)code);
		RzILOpPure *value = read_reg_sized(ctx, reg, 32);
		RzILOpEffect *store = value ? write_mem_sized(32, callm_frame_addr(0x10), value) : NULL;
		if (!store) {
			return m68k_invalid();
		}
		effect = BRANCH(callm_reg_code_is((ut32)code), store, effect);
	}
	return effect;
}

static RzILOpEffect *callm_load_selected_reg(M68KILCtx *ctx) {
	RzILOpEffect *effect = EMPTY();
	for (st32 code = 14; code >= 0; code--) {
		m68k_reg reg = callm_reg_from_code((ut32)code);
		RzILOpEffect *write = write_reg_sized(ctx, reg, 32, VARL("callm_data"));
		if (!write) {
			return m68k_invalid();
		}
		effect = BRANCH(callm_reg_code_is((ut32)code), write, effect);
	}
	return effect;
}

static RzILOpEffect *lift_callm_type0(M68KILCtx *ctx) {
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, callm_store_selected_reg(ctx));
	seq = seq_append(seq, write_mem_sized(16, callm_frame_addr(0), VARL("callm_frame_info")));
	seq = seq_append(seq, SETL("callm_ccr_arg", LOGOR(SHIFTL0(cast_unsigned(16, cast_unsigned(8, VARG("sr"))), U8(8)), cast_unsigned(16, VARL("callm_count")))));
	seq = seq_append(seq, write_mem_sized(16, callm_frame_addr(2), VARL("callm_ccr_arg")));
	seq = seq_append(seq, write_mem_sized(32, callm_frame_addr(4), VARL("callm_addr")));
	seq = seq_append(seq, write_mem_sized(32, callm_frame_addr(8), reg_value(ctx, M68K_REG_A7)));
	seq = seq_append(seq, write_mem_sized(32, callm_frame_addr(0x0c), u32(ctx->next_addr)));
	seq = seq_append(seq, write_mem_sized(32, callm_frame_addr(0x14), U32(0)));
	seq = seq_append(seq, write_reg_sized(ctx, M68K_REG_A7, 32, VARL("callm_frame")));
	seq = seq_append(seq, callm_load_selected_reg(ctx));
	return seq_append(seq, JMP(ADD(VARL("callm_entry"), U32(2))));
}

static RzILOpEffect *lift_callm_address_effects(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 ||
		ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return m68k_label("m68k_callm");
	}

	const cs_m68k_op *target = &ctx->m68k->operands[1];
	if (!rz_m68k_op_is_mem_addr(target)) {
		return m68k_label("m68k_callm");
	}

	M68KEA ea = effective_addr(ctx, target, 32);
	if (!ea.addr) {
		return m68k_invalid();
	}

	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, SETL("callm_count", U32((ut32)(ctx->m68k->operands[0].imm & 0xff))));
	seq = seq_append(seq, SETL("callm_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
	seq = seq_append(seq, SETL("callm_frame_info", read_mem_sized(16, VARL("callm_addr"))));
	seq = seq_append(seq, SETL("callm_entry", read_mem_sized(32, ADD(VARL("callm_addr"), U32(4)))));
	seq = seq_append(seq, SETL("callm_data", read_mem_sized(32, ADD(VARL("callm_addr"), U32(8)))));
	seq = seq_append(seq, SETL("callm_entry_word", read_mem_sized(16, VARL("callm_entry"))));
	seq = seq_append(seq, SETL("callm_reg_code", cast_unsigned(32, SHIFTR0(VARL("callm_entry_word"), U8(12)))));
	seq = seq_append(seq, SETL("callm_frame", SUB(reg_value(ctx, M68K_REG_A7), U32(0x18))));
	seq = seq_append(seq, ea.post);
	return seq_append(seq, BRANCH(IS_ZERO(LOGAND(VARL("callm_frame_info"), U16(0xff00))), lift_callm_type0(ctx), m68k_label("m68k_callm")));
}

static ut32 pmove_address_bits(M68KILCtx *ctx) {
	for (ut8 i = 0; i < ctx->m68k->op_count; i++) {
		const cs_m68k_op *op = &ctx->m68k->operands[i];
		if (op->type != M68K_OP_REG) {
			continue;
		}
		const char *name = cs_reg_name(ctx->handle, op->reg);
		if (!name) {
			continue;
		}
		if (!strcmp(name, "srp") || !strcmp(name, "crp")) {
			return 64;
		}
		if (!strcmp(name, "mmusr")) {
			return 16;
		}
	}
	return 32;
}

static ut32 pmove_transfer_bits(M68KILCtx *ctx, m68k_reg reg) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		return 0;
	}
	if (!strcmp(name, "mmusr")) {
		return 16;
	}
	if (!strcmp(name, "srp") || !strcmp(name, "crp")) {
		return 64;
	}
	if (!strcmp(name, "tc") ||
		!strcmp(name, "itt0") || !strcmp(name, "itt1") ||
		!strcmp(name, "dtt0") || !strcmp(name, "dtt1") ||
		!strcmp(name, "tt0") || !strcmp(name, "tt1")) {
		return 32;
	}
	return 0;
}

static const cs_m68k_op *mmu_address_operand(M68KILCtx *ctx) {
	switch (ctx->insn->id) {
	case M68K_INS_PLOADR:
	case M68K_INS_PLOADW:
	case M68K_INS_PTESTR:
	case M68K_INS_PTESTW:
		if (ctx->m68k->op_count > 1) {
			return &ctx->m68k->operands[1];
		}
		return ctx->m68k->op_count ? &ctx->m68k->operands[0] : NULL;
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHN:
		return ctx->m68k->op_count ? &ctx->m68k->operands[ctx->m68k->op_count - 1] : NULL;
	case M68K_INS_PLPAR:
	case M68K_INS_PLPAW:
		return ctx->m68k->op_count ? &ctx->m68k->operands[0] : NULL;
	case M68K_INS_PMOVE:
	case M68K_INS_PMOVEFD:
		for (ut8 i = 0; i < ctx->m68k->op_count; i++) {
			if (ctx->m68k->operands[i].type == M68K_OP_MEM) {
				return &ctx->m68k->operands[i];
			}
		}
		return NULL;
	default:
		return NULL;
	}
}

static M68KMMUOp mmu_operation(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_PLOADR:
	case M68K_INS_PLOADW:
		return M68K_MMU_OP_LOAD;
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHN:
	case M68K_INS_PFLUSHA:
	case M68K_INS_PFLUSHAN:
		return M68K_MMU_OP_FLUSH;
	case M68K_INS_PTESTR:
	case M68K_INS_PTESTW:
		return M68K_MMU_OP_TEST;
	case M68K_INS_PMOVE:
	case M68K_INS_PMOVEFD:
		return M68K_MMU_OP_MOVE;
	case M68K_INS_PLPAR:
	case M68K_INS_PLPAW:
		return M68K_MMU_OP_LOAD_PHYSICAL;
	default:
		return M68K_MMU_OP_MOVE;
	}
}

static int mmu_read_write_access(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_PLOADR:
	case M68K_INS_PTESTR:
	case M68K_INS_PLPAR:
		return 0;
	case M68K_INS_PLOADW:
	case M68K_INS_PTESTW:
	case M68K_INS_PLPAW:
		return 1;
	default:
		return -1;
	}
}

static RzILOpPure *mmu_function_code_value(M68KILCtx *ctx, const cs_m68k_op *op) {
	if (op->type == M68K_OP_IMM) {
		return U32((ut32)op->imm);
	}
	if (op->type == M68K_OP_REG) {
		RzILOpPure *value = read_reg_sized(ctx, op->reg, 32);
		return value ? cast_unsigned(32, value) : NULL;
	}
	return NULL;
}

static RzILOpEffect *append_mmu_operand_metadata(M68KILCtx *ctx, RzILOpEffect *seq) {
	switch (ctx->insn->id) {
	case M68K_INS_PLOADR:
	case M68K_INS_PLOADW:
	case M68K_INS_PTESTR:
	case M68K_INS_PTESTW:
		if (ctx->m68k->op_count > 0) {
			RzILOpPure *fc = mmu_function_code_value(ctx, &ctx->m68k->operands[0]);
			if (fc) {
				seq = seq_append(seq, SETL("mmu_fc", fc));
			}
		}
		if ((ctx->insn->id == M68K_INS_PTESTR || ctx->insn->id == M68K_INS_PTESTW) &&
			ctx->m68k->op_count > 2 && ctx->m68k->operands[2].type == M68K_OP_IMM) {
			seq = seq_append(seq, SETL("mmu_level", U32((ut32)ctx->m68k->operands[2].imm)));
		}
		break;
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHN:
		if (ctx->m68k->op_count > 2) {
			RzILOpPure *fc = mmu_function_code_value(ctx, &ctx->m68k->operands[0]);
			if (fc) {
				seq = seq_append(seq, SETL("mmu_fc", fc));
			}
			if (ctx->m68k->operands[1].type == M68K_OP_IMM) {
				seq = seq_append(seq, SETL("mmu_mask", U32((ut32)ctx->m68k->operands[1].imm)));
			}
		}
		break;
	default:
		break;
	}
	return seq;
}

static RzILOpEffect *append_mmu_metadata(M68KILCtx *ctx, RzILOpEffect *seq) {
	seq = seq_append(seq, SETL("mmu_op", U32((ut32)mmu_operation(ctx->insn->id))));
	int rw = mmu_read_write_access(ctx->insn->id);
	if (rw >= 0) {
		seq = seq_append(seq, SETL("mmu_rw", U32((ut32)rw)));
	}
	switch (ctx->insn->id) {
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHN:
	case M68K_INS_PFLUSHA:
	case M68K_INS_PFLUSHAN:
		seq = seq_append(seq, SETL("mmu_flush_non_global", U32(ctx->insn->id == M68K_INS_PFLUSHN || ctx->insn->id == M68K_INS_PFLUSHAN ? 1 : 0)));
		break;
	case M68K_INS_PMOVEFD:
		seq = seq_append(seq, SETL("mmu_fd", U32(1)));
		break;
	default:
		break;
	}
	return append_mmu_operand_metadata(ctx, seq);
}

static RzILOpEffect *lift_mmu_address_effects(M68KILCtx *ctx, ut32 bits, bool append_unmodeled_mmu) {
	RzILOpEffect *seq = NULL;
	const cs_m68k_op *op = mmu_address_operand(ctx);
	if (op) {
		if (op->type == M68K_OP_MEM && !op->address_mode) {
			return m68k_invalid();
		}
		if (rz_m68k_op_is_gpr(op)) {
			RzILOpPure *addr = read_reg_sized(ctx, op->reg, M68K_ADDR_BITS);
			if (!addr) {
				return m68k_invalid();
			}
			seq = seq_append(seq, SETL("mmu_addr", cast_unsigned(M68K_ADDR_BITS, addr)));
		} else if (op->type == M68K_OP_IMM) {
			seq = seq_append(seq, SETL("mmu_addr", U32((ut32)op->imm)));
		} else if (!rz_m68k_op_is_mem_addr(op)) {
			if (op->type != M68K_OP_REG || append_unmodeled_mmu) {
				return m68k_label("m68k_mmu");
			}
			return NOP();
		} else {
			M68KEA ea = effective_addr(ctx, op, bits);
			if (!ea.addr) {
				m68k_ea_fini(&ea);
				return m68k_invalid();
			}
			seq = seq_append(seq, ea.pre);
			seq = seq_append(seq, SETL("mmu_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
			seq = seq_append(seq, ea.post);
		}
	}
	if (append_unmodeled_mmu) {
		seq = append_mmu_metadata(ctx, seq);
		return seq_append(seq, m68k_label("m68k_mmu"));
	}
	return seq ? seq : NOP();
}

static RzILOpEffect *lift_mmu_flush_all(M68KILCtx *ctx) {
	RzILOpEffect *seq = NULL;
	seq = append_mmu_metadata(ctx, seq);
	seq = seq_append(seq, SETL("mmu_flush_all", U32(1)));
	return seq_append(seq, m68k_label("m68k_mmu"));
}

static M68KCacheOp cache_operation(ut32 insn_id) {
	switch (insn_id) {
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_INS_INTOUCH:
		return M68K_CACHE_OP_TOUCH;
#endif
	case M68K_INS_CINVL:
	case M68K_INS_CINVP:
	case M68K_INS_CINVA:
		return M68K_CACHE_OP_INVALIDATE;
	case M68K_INS_CPUSHL:
	case M68K_INS_CPUSHP:
	case M68K_INS_CPUSHA:
		return M68K_CACHE_OP_PUSH;
	default:
		return M68K_CACHE_OP_TOUCH;
	}
}

static RzILOpEffect *append_cache_metadata(M68KILCtx *ctx, RzILOpEffect *seq, bool all_scope) {
	seq = seq_append(seq, SETL("cache_op", U32((ut32)cache_operation(ctx->insn->id))));
	if (ctx->m68k->op_count > 0 && ctx->m68k->operands[0].type == M68K_OP_IMM) {
		seq = seq_append(seq, SETL("cache_selector", U32((ut32)ctx->m68k->operands[0].imm)));
	}
	if (all_scope) {
		seq = seq_append(seq, SETL("cache_all", U32(1)));
	}
	return seq;
}

static const cs_m68k_op *cache_address_operand(M68KILCtx *ctx) {
	for (ut8 i = 0; i < ctx->m68k->op_count; i++) {
		const cs_m68k_op *op = &ctx->m68k->operands[i];
		if (rz_m68k_op_is_addr_reg(op)) {
			return op;
		}
		if (rz_m68k_op_is_mem_addr(op)) {
			return op;
		}
	}
	return NULL;
}

static RzILOpEffect *lift_cache_address_effects(M68KILCtx *ctx) {
	RzILOpEffect *seq = NULL;
	const cs_m68k_op *op = cache_address_operand(ctx);
	const bool needs_address = rz_m68k_insn_cache_requires_address(ctx->insn->id);
	if (!op) {
		if (needs_address) {
			return m68k_invalid();
		}
		seq = append_cache_metadata(ctx, seq, true);
		return seq_append(seq, m68k_label("m68k_cache"));
	}
	if (op->type == M68K_OP_MEM && !op->address_mode) {
		if (needs_address) {
			return m68k_invalid();
		}
		seq = append_cache_metadata(ctx, seq, true);
		return seq_append(seq, m68k_label("m68k_cache"));
	}
	if (rz_m68k_op_is_addr_reg(op)) {
		RzILOpPure *addr = read_reg_sized(ctx, op->reg, M68K_ADDR_BITS);
		if (!addr) {
			return m68k_invalid();
		}
		seq = seq_append(seq, SETL("cache_addr", cast_unsigned(M68K_ADDR_BITS, addr)));
		seq = append_cache_metadata(ctx, seq, false);
		return seq_append(seq, m68k_label("m68k_cache"));
	}
	if (!rz_m68k_op_is_mem_addr(op)) {
		return m68k_label(needs_address ? "m68k_illegal" : "m68k_cache");
	}

	M68KEA ea = effective_addr(ctx, op, 32);
	if (!ea.addr) {
		m68k_ea_fini(&ea);
		return m68k_invalid();
	}
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, SETL("cache_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
	seq = seq_append(seq, ea.post);
	seq = append_cache_metadata(ctx, seq, false);
	return seq_append(seq, m68k_label("m68k_cache"));
}

static RzILOpEffect *lift_pmove(M68KILCtx *ctx) {
	if (ctx->m68k->op_count != 2) {
		return lift_mmu_address_effects(ctx, pmove_address_bits(ctx), true);
	}

	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	const cs_m68k_op *mem = NULL;
	const cs_m68k_op *reg = NULL;
	bool mem_to_reg = false;

	if (src->type == M68K_OP_MEM && dst->type == M68K_OP_REG) {
		mem = src;
		reg = dst;
		mem_to_reg = true;
	} else if (src->type == M68K_OP_REG && dst->type == M68K_OP_MEM) {
		reg = src;
		mem = dst;
	} else if ((src->type == M68K_OP_REG || src->type == M68K_OP_IMM) && dst->type == M68K_OP_REG) {
		ut32 bits = pmove_transfer_bits(ctx, dst->reg);
		if (!bits) {
			return lift_mmu_address_effects(ctx, pmove_address_bits(ctx), true);
		}
		RzILOpPure *value = read_operand(ctx, src, bits, NULL, NULL);
		if (!value) {
			return m68k_invalid();
		}
		RzILOpEffect *write = write_reg_sized(ctx, dst->reg, bits, VARL("src"));
		if (!write) {
			rz_il_op_pure_free(value);
			return m68k_invalid();
		}
		return SEQ2(SETL("src", value), write);
	} else {
		return lift_mmu_address_effects(ctx, pmove_address_bits(ctx), true);
	}

	ut32 bits = pmove_transfer_bits(ctx, reg->reg);
	if (!bits) {
		return lift_mmu_address_effects(ctx, pmove_address_bits(ctx), true);
	}
	if (mem->type == M68K_OP_MEM && !mem->address_mode) {
		return m68k_invalid();
	}
	if (!rz_m68k_op_is_mem_addr(mem)) {
		return lift_mmu_address_effects(ctx, bits, true);
	}

	M68KEA ea = effective_addr(ctx, mem, bits);
	if (!ea.addr) {
		m68k_ea_fini(&ea);
		return m68k_invalid();
	}

	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, SETL("mmu_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
	if (mem_to_reg) {
		seq = seq_append(seq, SETL("src", read_mem_sized(bits, VARL("mmu_addr"))));
		seq = seq_append(seq, ea.post);
		RzILOpEffect *write = write_reg_sized(ctx, reg->reg, bits, VARL("src"));
		if (!write) {
			return m68k_invalid_free(seq);
		}
		return seq_append(seq, write);
	}

	RzILOpPure *value = read_reg_sized(ctx, reg->reg, bits);
	if (!value) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("src", value));
	seq = seq_append(seq, write_mem_sized(bits, VARL("mmu_addr"), VARL("src")));
	return seq_append(seq, ea.post);
}

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static RzILOpEffect *lift_coldfire_bitop_reg(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[0])) {
		return m68k_invalid();
	}
	m68k_reg reg = ctx->m68k->operands[0].reg;
	RzILOpEffect *seq = SEQ2(
		SETL("src", read_reg_sized(ctx, reg, 32)),
		SETL("res", ctx->insn->id == M68K_INS_BITREV ? reverse_bits32("src") : ctx->insn->id == M68K_INS_BYTEREV ? reverse_bytes32("src")
															 : ff1_result32("src")));
	seq = seq_append(seq, write_reg_sized(ctx, reg, 32, VARL("res")));
	if (ctx->insn->id == M68K_INS_FF1) {
		seq = seq_append(seq, set_flags_ff1(VARL("src")));
	}
	return seq;
}

static RzILOpEffect *lift_rem(M68KILCtx *ctx, bool sign) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg_pair(&ctx->m68k->operands[1])) {
		return m68k_invalid();
	}
	m68k_reg dw = ctx->m68k->operands[1].reg_pair.reg_0;
	m68k_reg dx = ctx->m68k->operands[1].reg_pair.reg_1;
	if (dw == dx) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "src", &ctx->m68k->operands[0], 32, &seq)) {
		return m68k_invalid_free(seq);
	}
	RzILOpPure *dst = read_reg_sized(ctx, dx, 32);
	if (!dst) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("dst", dst));

	RzILOpPure *dividend = sign ? cast_signed(64, VARL("dst")) : cast_unsigned(64, VARL("dst"));
	RzILOpPure *divisor = sign ? cast_signed(64, VARL("src")) : cast_unsigned(64, VARL("src"));
	RzILOpEffect *write_remainder = write_reg_sized(ctx, dw, 32, cast_unsigned(32, VARL("rem")));
	if (!write_remainder) {
		rz_il_op_pure_free(dividend);
		rz_il_op_pure_free(divisor);
		return m68k_invalid_free(seq);
	}
	RzILOpEffect *normal = SEQ4(
		SETL("quot", sign ? SDIV(dividend, divisor) : DIV(dividend, divisor)),
		SETL("rem", sign ? SMOD(cast_signed(64, VARL("dst")), cast_signed(64, VARL("src"))) : MOD(cast_unsigned(64, VARL("dst")), cast_unsigned(64, VARL("src")))),
		write_remainder,
		set_flags_rem(VARL("quot"), IL_FALSE));
	RzILOpBool *overflow = sign
		? AND(EQ(VARL("dst"), U32(0x80000000)), EQ(VARL("src"), U32(0xffffffff)))
		: UGT(DIV(cast_unsigned(64, VARL("dst")), cast_unsigned(64, VARL("src"))), U64(0x7fffffff));
	RzILOpEffect *do_divide = BRANCH(overflow, set_flags_rem(U32(0), IL_TRUE), normal);
	return seq_append(seq, BRANCH(IS_ZERO(VARL("src")), m68k_exception(M68K_TRAP_OP_DIV_ZERO, M68K_VECTOR_ZERO_DIVIDE, "m68k_trap"), do_divide));
}

static RzILOpEffect *lift_sats(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[0])) {
		return m68k_invalid();
	}
	m68k_reg reg = ctx->m68k->operands[0].reg;
	return SEQ4(
		SETL("src", read_reg_sized(ctx, reg, 32)),
		SETL("res", ITE(ccr_bit(M68K_CCR_V), ITE(MSB(VARL("src")), U32(0x7fffffffu), U32(0x80000000u)), VARL("src"))),
		write_reg_sized(ctx, reg, 32, VARL("res")),
		set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpPure *mac_read_reg_part(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits) {
	if (!rz_m68k_op_is_gpr(op)) {
		return NULL;
	}
	RzILOpPure *value = read_reg_sized(ctx, op->reg, 32);
	if (!value) {
		return NULL;
	}
	if (bits == 16) {
		value = (op->flags & M68K_OP_FLAG_REG_UPPER) ? SHIFTR0(value, U8(16)) : value;
		return cast_signed(32, cast_unsigned(16, value));
	}
	return value;
}

static RzILOpEffect *mac_memory_update(M68KILCtx *ctx, ut32 bits, RzILOpEffect *seq, const cs_m68k_op *mem, const cs_m68k_op *reg) {
	if (!mem || !rz_m68k_op_is_gpr(reg)) {
		return seq;
	}
	M68KEA ea = effective_addr(ctx, mem, bits);
	if (!ea.addr) {
		m68k_ea_fini(&ea);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, SETL("mem_addr", cast_unsigned(32, ea.addr)));
	seq = seq_append(seq, SETL("mem_load", read_mem_sized(bits, VARL("mem_addr"))));
	RzILOpEffect *write = write_reg_sized(ctx, reg->reg, bits, VARL("mem_load"));
	if (!write) {
		rz_il_op_effect_free(ea.post);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, write);
	return seq_append(seq, ea.post);
}

static RzILOpEffect *lift_mac_msac(M68KILCtx *ctx, bool subtract) {
	if (ctx->m68k->op_count < 3) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	const cs_m68k_op *src0 = &ctx->m68k->operands[0];
	const cs_m68k_op *src1 = &ctx->m68k->operands[1];
	const cs_m68k_op *acc_op = &ctx->m68k->operands[ctx->m68k->op_count - 1];
	if (!rz_m68k_op_is_acc_reg(acc_op)) {
		return m68k_invalid();
	}
	RzILOpPure *src0_value = mac_read_reg_part(ctx, src0, bits);
	RzILOpPure *src1_value = mac_read_reg_part(ctx, src1, bits);
	RzILOpPure *acc_value = read_reg_sized(ctx, acc_op->reg, 32);
	if (!src0_value || !src1_value || !acc_value) {
		rz_il_op_pure_free(src0_value);
		rz_il_op_pure_free(src1_value);
		rz_il_op_pure_free(acc_value);
		return m68k_invalid();
	}

	const cs_m68k_op *shift = NULL;
	const cs_m68k_op *mem = NULL;
	const cs_m68k_op *update_reg = NULL;
	for (ut8 i = 2; i + 1 < ctx->m68k->op_count; i++) {
		const cs_m68k_op *op = &ctx->m68k->operands[i];
		if (op->type == M68K_OP_SHIFT) {
			shift = op;
		} else if (op->type == M68K_OP_MEM) {
			mem = op;
			if (i + 1 < ctx->m68k->op_count - 1) {
				update_reg = &ctx->m68k->operands[i + 1];
			}
		}
	}

	RzILOpEffect *seq = SEQ4(
		SETL("src0", src0_value),
		SETL("src1", src1_value),
		SETL("acc", cast_signed(64, acc_value)),
		SETL("prod", MUL(cast_signed(64, VARL("src0")), cast_signed(64, VARL("src1")))));
	if (shift) {
		seq = seq_append(seq, SETL("prod", (shift->flags & M68K_OP_FLAG_SHIFT_LEFT) ? SHIFTL0(VARL("prod"), U8(1)) : SHIFTRA(VARL("prod"), U8(1))));
	}
	seq = seq_append(seq, SETL("res64", subtract ? SUB(VARL("acc"), VARL("prod")) : ADD(VARL("acc"), VARL("prod"))));
	seq = seq_append(seq, SETL("res", cast_unsigned(32, VARL("res64"))));
	RzILOpEffect *write_acc = write_reg_sized(ctx, acc_op->reg, 32, VARL("res"));
	if (!write_acc) {
		rz_il_op_effect_free(seq);
		return m68k_invalid();
	}
	seq = seq_append(seq, write_acc);
	return mac_memory_update(ctx, bits, seq, mem, update_reg);
}

static RzILOpEffect *mac_dual_acc_update(M68KILCtx *ctx, RzILOpEffect *seq, const cs_m68k_op *acc_op, bool subtract) {
	if (!rz_m68k_op_is_acc_reg(acc_op)) {
		return m68k_invalid_free(seq);
	}
	RzILOpPure *acc_value = read_reg_sized(ctx, acc_op->reg, 32);
	if (!acc_value) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("acc", cast_signed(64, acc_value)));
	seq = seq_append(seq, SETL("res64", subtract ? SUB(VARL("acc"), VARL("prod")) : ADD(VARL("acc"), VARL("prod"))));
	seq = seq_append(seq, SETL("res", cast_unsigned(32, VARL("res64"))));
	RzILOpEffect *write_acc = write_reg_sized(ctx, acc_op->reg, 32, VARL("res"));
	if (!write_acc) {
		return m68k_invalid_free(seq);
	}
	return seq_append(seq, write_acc);
}

static RzILOpEffect *lift_mac_dual_acc(M68KILCtx *ctx, bool subtract_first, bool subtract_second) {
	if (ctx->m68k->op_count < 4) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	const cs_m68k_op *src0 = &ctx->m68k->operands[0];
	const cs_m68k_op *src1 = &ctx->m68k->operands[1];
	const cs_m68k_op *acc0 = &ctx->m68k->operands[ctx->m68k->op_count - 2];
	const cs_m68k_op *acc1 = &ctx->m68k->operands[ctx->m68k->op_count - 1];
	if (!rz_m68k_op_is_acc_reg(acc0) || !rz_m68k_op_is_acc_reg(acc1)) {
		return m68k_invalid();
	}
	RzILOpPure *src0_value = mac_read_reg_part(ctx, src0, bits);
	RzILOpPure *src1_value = mac_read_reg_part(ctx, src1, bits);
	if (!src0_value || !src1_value) {
		rz_il_op_pure_free(src0_value);
		rz_il_op_pure_free(src1_value);
		return m68k_invalid();
	}

	const cs_m68k_op *shift = NULL;
	for (ut8 i = 2; i + 2 < ctx->m68k->op_count; i++) {
		const cs_m68k_op *op = &ctx->m68k->operands[i];
		if (op->type == M68K_OP_SHIFT) {
			shift = op;
		} else {
			rz_il_op_pure_free(src0_value);
			rz_il_op_pure_free(src1_value);
			return m68k_invalid();
		}
	}

	RzILOpEffect *seq = SEQ3(
		SETL("src0", src0_value),
		SETL("src1", src1_value),
		SETL("prod", MUL(cast_signed(64, VARL("src0")), cast_signed(64, VARL("src1")))));
	if (shift) {
		seq = seq_append(seq, SETL("prod", (shift->flags & M68K_OP_FLAG_SHIFT_LEFT) ? SHIFTL0(VARL("prod"), U8(1)) : SHIFTRA(VARL("prod"), U8(1))));
	}
	seq = mac_dual_acc_update(ctx, seq, acc0, subtract_first);
	if (!seq) {
		return m68k_invalid();
	}
	return mac_dual_acc_update(ctx, seq, acc1, subtract_second);
}
#endif

static RzILOpPure *div_quotient_expr(bool sign, const char *dividend_local, const char *divisor_local) {
	RzILOpPure *dividend = sign ? cast_signed(64, VARL(dividend_local)) : cast_unsigned(64, VARL(dividend_local));
	RzILOpPure *divisor = sign ? cast_signed(64, VARL(divisor_local)) : cast_unsigned(64, VARL(divisor_local));
	return sign ? SDIV(dividend, divisor) : DIV(dividend, divisor);
}

static RzILOpPure *div_remainder_expr(bool sign, const char *dividend_local, const char *divisor_local) {
	RzILOpPure *dividend = sign ? cast_signed(64, VARL(dividend_local)) : cast_unsigned(64, VARL(dividend_local));
	RzILOpPure *divisor = sign ? cast_signed(64, VARL(divisor_local)) : cast_unsigned(64, VARL(divisor_local));
	return sign ? SMOD(dividend, divisor) : MOD(dividend, divisor);
}

static RzILOpBool *div_quotient_overflows(bool sign, ut32 bits, RzILOpPure *quotient) {
	if (sign) {
		RzILOpPure *min = bits == 16 ? S64(-0x8000) : S64(-0x80000000LL);
		RzILOpPure *max = bits == 16 ? S64(0x7fff) : S64(0x7fffffff);
		return OR(SLT(DUP(quotient), min), SGT(quotient, max));
	}
	return UGT(quotient, bits == 16 ? U64(0xffff) : U64(0xffffffffULL));
}

static RzILOpEffect *lift_div_reg(M68KILCtx *ctx, bool sign, m68k_reg reg, ut32 bits, RzILOpEffect *seq) {
	RzILOpPure *dst = read_reg_sized(ctx, reg, 32);
	if (!dst) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("dst", dst));
	ut32 quotient_bits = bits == 16 ? 16 : 32;
	RzILOpEffect *write_result = NULL;
	if (bits == 16) {
		RzILOpPure *result = LOGOR(
			SHIFTL0(cast_unsigned(32, VARL("rem")), U8(16)),
			cast_unsigned(32, VARL("quot")));
		write_result = write_reg_sized(ctx, reg, 32, result);
	} else {
		write_result = write_reg_sized(ctx, reg, 32, cast_unsigned(32, VARL("quot")));
	}
	if (!write_result) {
		return m68k_invalid_free(seq);
	}
	RzILOpEffect *normal = bits == 16
		? SEQ4(
			  SETL("quot", div_quotient_expr(sign, "dst", "src")),
			  SETL("rem", div_remainder_expr(sign, "dst", "src")),
			  write_result,
			  set_flags_div(VARL("quot"), quotient_bits, IL_FALSE))
		: SEQ3(
			  SETL("quot", div_quotient_expr(sign, "dst", "src")),
			  write_result,
			  set_flags_div(VARL("quot"), quotient_bits, IL_FALSE));
	RzILOpBool *overflow = div_quotient_overflows(sign, quotient_bits, div_quotient_expr(sign, "dst", "src"));
	RzILOpEffect *do_divide = BRANCH(overflow, set_flags_div(UN(quotient_bits, 0), quotient_bits, IL_TRUE), normal);
	return seq_append(seq, BRANCH(IS_ZERO(VARL("src")), m68k_exception(M68K_TRAP_OP_DIV_ZERO, M68K_VECTOR_ZERO_DIVIDE, "m68k_trap"), do_divide));
}

static RzILOpEffect *lift_div_pair(M68KILCtx *ctx, bool sign, m68k_reg high_reg, m68k_reg low_reg, RzILOpEffect *seq) {
	if (!rz_m68k_reg_is_dreg(high_reg) || !rz_m68k_reg_is_dreg(low_reg) || high_reg == low_reg) {
		return m68k_invalid();
	}
	RzILOpEffect *write_high = write_reg_sized(ctx, high_reg, 32, cast_unsigned(32, VARL("rem")));
	RzILOpEffect *write_low = write_reg_sized(ctx, low_reg, 32, cast_unsigned(32, VARL("quot")));
	if (!write_high || !write_low) {
		return m68k_invalid();
	}
	seq = seq_append(seq, SETL("dst", APPEND(read_reg_sized(ctx, high_reg, 32), read_reg_sized(ctx, low_reg, 32))));
	RzILOpEffect *normal = SEQ5(
		SETL("quot", div_quotient_expr(sign, "dst", "src")),
		SETL("rem", div_remainder_expr(sign, "dst", "src")),
		write_low,
		write_high,
		set_flags_div(VARL("quot"), 32, IL_FALSE));
	RzILOpBool *overflow = div_quotient_overflows(sign, 32, div_quotient_expr(sign, "dst", "src"));
	RzILOpEffect *do_divide = BRANCH(overflow, set_flags_div(U32(0), 32, IL_TRUE), normal);
	return seq_append(seq, BRANCH(IS_ZERO(VARL("src")), m68k_exception(M68K_TRAP_OP_DIV_ZERO, M68K_VECTOR_ZERO_DIVIDE, "m68k_trap"), do_divide));
}

static RzILOpEffect *lift_div(M68KILCtx *ctx, bool sign) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	if (bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "src", &ctx->m68k->operands[0], bits, &seq)) {
		return m68k_invalid();
	}
	if (rz_m68k_op_is_data_reg(dst)) {
		return lift_div_reg(ctx, sign, dst->reg, bits, seq);
	}
	if (bits == 32 && dst->type == M68K_OP_REG_PAIR) {
		return lift_div_pair(ctx, sign, dst->reg_pair.reg_0, dst->reg_pair.reg_1, seq);
	}
	return m68k_invalid();
}

static RzILOpPure *movep_addr(ut32 offset) {
	return offset ? ADD(VARL("addr"), U32(offset)) : VARL("addr");
}

static RzILOpPure *movep_read_byte(ut32 offset, ut32 bits, ut32 shift) {
	RzILOpPure *byte = cast_unsigned(bits, read_mem_sized(8, movep_addr(offset)));
	return shift ? SHIFTL0(byte, U8(shift)) : byte;
}

static RzILOpEffect *movep_store_byte(ut32 offset, ut32 shift) {
	RzILOpPure *byte = shift ? SHIFTR0(VARL("src"), U8(shift)) : VARL("src");
	return write_mem_sized(8, movep_addr(offset), byte);
}

static RzILOpEffect *lift_movep(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	if (bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	bool mem_to_reg = rz_m68k_op_is_mem_addr(src) && rz_m68k_op_is_data_reg(dst);
	bool reg_to_mem = rz_m68k_op_is_data_reg(src) && rz_m68k_op_is_mem_addr(dst);
	if (!mem_to_reg && !reg_to_mem) {
		return m68k_invalid();
	}
	const cs_m68k_op *mem = mem_to_reg ? src : dst;
	M68KEA ea = effective_addr(ctx, mem, bits);
	if (!ea.addr) {
		return m68k_invalid();
	}

	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, SETL("addr", cast_unsigned(32, ea.addr)));
	if (mem_to_reg) {
		RzILOpPure *res = bits == 16
			? LOGOR(movep_read_byte(0, 16, 8), movep_read_byte(2, 16, 0))
			: LOGOR(LOGOR(movep_read_byte(0, 32, 24), movep_read_byte(2, 32, 16)), LOGOR(movep_read_byte(4, 32, 8), movep_read_byte(6, 32, 0)));
		seq = seq_append(seq, SETL("res", res));
		seq = seq_append(seq, write_reg_sized(ctx, dst->reg, bits, VARL("res")));
	} else {
		seq = seq_append(seq, SETL("src", read_reg_sized(ctx, src->reg, bits)));
		seq = seq_append(seq, bits == 16 ? SEQ2(movep_store_byte(0, 8), movep_store_byte(2, 0)) : SEQ4(movep_store_byte(0, 24), movep_store_byte(2, 16), movep_store_byte(4, 8), movep_store_byte(6, 0)));
	}
	seq = seq_append(seq, ea.post);
	return seq;
}

static m68k_reg movem_reg_for_bit(ut32 bit) {
	static const m68k_reg regs[] = {
		M68K_REG_D0, M68K_REG_D1, M68K_REG_D2, M68K_REG_D3,
		M68K_REG_D4, M68K_REG_D5, M68K_REG_D6, M68K_REG_D7,
		M68K_REG_A0, M68K_REG_A1, M68K_REG_A2, M68K_REG_A3,
		M68K_REG_A4, M68K_REG_A5, M68K_REG_A6, M68K_REG_A7
	};
	return bit < RZ_ARRAY_SIZE(regs) ? regs[bit] : M68K_REG_INVALID;
}

static ut32 movem_reg_count(ut32 reg_bits) {
	ut32 count = 0;
	for (ut32 i = 0; i < 16; i++) {
		if (reg_bits & (1u << i)) {
			count++;
		}
	}
	return count;
}

static RzILOpPure *movem_addr_at(ut32 offset) {
	return offset ? ADD(VARL("addr"), U32(offset)) : VARL("addr");
}

static RzILOpEffect *write_movem_reg(M68KILCtx *ctx, m68k_reg reg, ut32 bits, RzILOpPure *value) {
	if (bits == 16) {
		return write_reg_sized(ctx, reg, 32, cast_signed(32, value));
	}
	return write_reg_sized(ctx, reg, 32, value);
}

static RzILOpEffect *lift_movem(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	bool reg_to_mem = src->type == M68K_OP_REG_BITS && rz_m68k_op_is_mem_addr(dst);
	bool mem_to_reg = rz_m68k_op_is_mem_addr(src) && dst->type == M68K_OP_REG_BITS;
	if (!reg_to_mem && !mem_to_reg) {
		return m68k_invalid();
	}
	const cs_m68k_op *regs_op = reg_to_mem ? src : dst;
	const cs_m68k_op *mem = reg_to_mem ? dst : src;
	ut32 reg_bits = regs_op->register_bits;
	if (reg_bits & ~0xffffu) {
		return m68k_invalid();
	}
	ut32 count = movem_reg_count(reg_bits);
	if (!count) {
		return NOP();
	}

	ut32 bytes = rz_m68k_bits_access_bytes(bits);
	bool predec = mem->address_mode == M68K_AM_REGI_ADDR_PRE_DEC;
	bool postinc = mem->address_mode == M68K_AM_REGI_ADDR_POST_INC;
	m68k_reg base_reg = rz_m68k_op_base_reg(mem);
	RzILOpEffect *seq = NULL;
	if (predec || postinc) {
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return m68k_invalid();
		}
		seq = seq_append(seq, SETL("addr", cast_unsigned(32, reg_value(ctx, base_reg))));
	} else {
		M68KEA ea = effective_addr(ctx, mem, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return m68k_invalid();
		}
		seq = seq_append(seq, ea.pre);
		seq = seq_append(seq, SETL("addr", cast_unsigned(32, ea.addr)));
		seq = seq_append(seq, ea.post);
	}

	if (reg_to_mem && predec) {
		for (int i = 15; i >= 0; i--) {
			if (!(reg_bits & (1u << i))) {
				continue;
			}
			m68k_reg reg = movem_reg_for_bit((ut32)i);
			RzILOpPure *value = reg == base_reg && m68k_mode_uses_later_movem_base_value(ctx->mode)
				? cast_unsigned(bits, SUB(reg_value(ctx, base_reg), U32(bytes)))
				: read_reg_sized(ctx, reg, bits);
			if (!value) {
				return m68k_invalid_free(seq);
			}
			seq = seq_append(seq, SETL("addr", SUB(VARL("addr"), U32(bytes))));
			RzILOpEffect *write = write_mem_sized(bits, VARL("addr"), value);
			if (!write) {
				rz_il_op_pure_free(value);
				return m68k_invalid_free(seq);
			}
			seq = seq_append(seq, write);
		}
		return seq_append(seq, write_reg_sized(ctx, base_reg, 32, VARL("addr")));
	}

	ut32 offset = 0;
	for (ut32 i = 0; i < 16; i++) {
		if (!(reg_bits & (1u << i))) {
			continue;
		}
		m68k_reg reg = movem_reg_for_bit(i);
		RzILOpEffect *op = NULL;
		RzILOpPure *value = NULL;
		if (reg_to_mem) {
			value = read_reg_sized(ctx, reg, bits);
			if (!value) {
				return m68k_invalid_free(seq);
			}
			op = write_mem_sized(bits, movem_addr_at(offset), value);
		} else {
			value = read_mem_sized(bits, movem_addr_at(offset));
			op = write_movem_reg(ctx, reg, bits, value);
		}
		if (!op) {
			if (reg_to_mem) {
				rz_il_op_pure_free(value);
			}
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, op);
		offset += bytes;
	}
	if (postinc) {
		seq = seq_append(seq, write_reg_sized(ctx, base_reg, 32, ADD(VARL("addr"), U32(offset))));
	}
	return seq;
}

static RzILOpPure *move16_addr_at(const char *addr_local, ut32 offset) {
	return offset ? ADD(VARL(addr_local), U32(offset)) : VARL(addr_local);
}

static bool move16_operand_addr(M68KILCtx *ctx, const cs_m68k_op *op, const char *addr_local, RzILOpEffect **seq, m68k_reg *postinc_reg) {
	rz_return_val_if_fail(ctx && op && addr_local && seq && postinc_reg, false);
	*postinc_reg = M68K_REG_INVALID;
	if (op->type != M68K_OP_MEM) {
		return false;
	}
	if (op->address_mode == M68K_AM_REGI_ADDR_POST_INC) {
		m68k_reg base_reg = rz_m68k_op_base_reg(op);
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return false;
		}
		*seq = seq_append(*seq, SETL(addr_local, cast_unsigned(32, reg_value(ctx, base_reg))));
		*postinc_reg = base_reg;
		return true;
	}
	M68KEA ea = effective_addr(ctx, op, 32);
	if (!ea.addr) {
		return false;
	}
	*seq = seq_append(*seq, ea.pre);
	*seq = seq_append(*seq, SETL(addr_local, cast_unsigned(32, ea.addr)));
	*seq = seq_append(*seq, ea.post);
	return true;
}

static RzILOpEffect *lift_move16(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	RzILOpEffect *seq = NULL;
	m68k_reg src_postinc = M68K_REG_INVALID;
	m68k_reg dst_postinc = M68K_REG_INVALID;
	if (!move16_operand_addr(ctx, src, "src_addr", &seq, &src_postinc) ||
		!move16_operand_addr(ctx, dst, "dst_addr", &seq, &dst_postinc)) {
		return m68k_invalid();
	}

	seq = seq_append(seq, SETL("src_line", LOGAND(VARL("src_addr"), U32(~0xfu))));
	seq = seq_append(seq, SETL("dst_line", LOGAND(VARL("dst_addr"), U32(~0xfu))));
	seq = seq_append(seq, SETL("word0", read_mem_sized(32, move16_addr_at("src_line", 0))));
	seq = seq_append(seq, SETL("word1", read_mem_sized(32, move16_addr_at("src_line", 4))));
	seq = seq_append(seq, SETL("word2", read_mem_sized(32, move16_addr_at("src_line", 8))));
	seq = seq_append(seq, SETL("word3", read_mem_sized(32, move16_addr_at("src_line", 12))));
	seq = seq_append(seq, write_mem_sized(32, move16_addr_at("dst_line", 0), VARL("word0")));
	seq = seq_append(seq, write_mem_sized(32, move16_addr_at("dst_line", 4), VARL("word1")));
	seq = seq_append(seq, write_mem_sized(32, move16_addr_at("dst_line", 8), VARL("word2")));
	seq = seq_append(seq, write_mem_sized(32, move16_addr_at("dst_line", 12), VARL("word3")));
	if (src_postinc != M68K_REG_INVALID) {
		seq = seq_append(seq, write_reg_sized(ctx, src_postinc, 32, ADD(VARL("src_addr"), U32(16))));
	}
	if (dst_postinc != M68K_REG_INVALID && dst_postinc != src_postinc) {
		seq = seq_append(seq, write_reg_sized(ctx, dst_postinc, 32, ADD(VARL("dst_addr"), U32(16))));
	}
	return seq;
}

static RzILOpEffect *lift_lea(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0]) || ctx->m68k->operands[1].type != M68K_OP_REG) {
		return m68k_invalid();
	}
	M68KEA ea = effective_addr(ctx, &ctx->m68k->operands[0], 32);
	if (!ea.addr) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, ea.addr));
	seq = seq_append(seq, ea.post);
	return seq;
}

static RzILOpEffect *push32(M68KILCtx *ctx, RzILOpPure *value) {
	return SEQ3(
		SETL("push_value", value),
		set_addr_reg_delta(ctx, M68K_REG_A7, -4),
		write_mem_sized(32, reg_value(ctx, M68K_REG_A7), VARL("push_value")));
}

static RzILOpEffect *lift_pea(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || !rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0])) {
		return m68k_invalid();
	}
	M68KEA ea = effective_addr(ctx, &ctx->m68k->operands[0], 32);
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, push32(ctx, ea.addr));
	seq = seq_append(seq, ea.post);
	return seq;
}

static RzILOpPure *apply_binop(M68KBinOp binop, RzILOpPure *dst, RzILOpPure *src) {
	switch (binop) {
	case M68K_BIN_ADD:
		return ADD(dst, src);
	case M68K_BIN_SUB:
		return SUB(dst, src);
	case M68K_BIN_AND:
		return LOGAND(dst, src);
	case M68K_BIN_OR:
		return LOGOR(dst, src);
	case M68K_BIN_XOR:
		return LOGXOR(dst, src);
	default:
		return NULL;
	}
}

static RzILOpEffect *lift_binop(M68KILCtx *ctx, M68KBinOp binop, bool address_dst, bool compare_only) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 op_bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	ut32 bits = address_dst ? 32 : op_bits;
	RzILOpEffect *seq = NULL;
	if (address_dst && op_bits == 16) {
		if (!operand_to_local(ctx, "src_raw", src, op_bits, &seq)) {
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, SETL("src", extend_to_32(VARL("src_raw"), true)));
	} else if (!operand_to_local(ctx, "src", src, op_bits, &seq)) {
		return m68k_invalid_free(seq);
	}
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
		return m68k_invalid_free(seq);
	}
	RzILOpPure *res = apply_binop(binop, VARL("dst"), VARL("src"));
	if (!res) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("res", res));
	if (!compare_only) {
		RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, address_dst ? 32 : bits, VARL("res"));
		if (!write) {
			m68k_rw_operand_fini(&dst_rw);
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, write);
	}
	seq = seq_append(seq, dst_rw.post);
	if (!address_dst || compare_only) {
		RzILOpBool *v = NULL;
		RzILOpBool *c = NULL;
		RzILOpBool *x = NULL;
		if (binop == M68K_BIN_ADD) {
			v = add_overflow(VARL("dst"), VARL("src"), VARL("res"));
			c = ULT(VARL("res"), VARL("dst"));
			x = (RzILOpBool *)DUP(c);
		} else if (binop == M68K_BIN_SUB) {
			v = sub_overflow(VARL("dst"), VARL("src"), VARL("res"));
			c = ULT(VARL("dst"), VARL("src"));
			x = compare_only ? NULL : (RzILOpBool *)DUP(c);
		} else {
			v = IL_FALSE;
			c = IL_FALSE;
		}
		seq = seq_append(seq, set_flags_nzvcx(VARL("res"), bits, v, c, x));
	}
	return seq;
}

static RzILOpEffect *lift_status_binop(M68KILCtx *ctx, M68KBinOp binop) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if (!rz_m68k_op_is_status_reg(dst)) {
		return m68k_invalid();
	}
	ut32 bits = dst->reg == M68K_REG_CCR ? 8 : 16;
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "src", src, bits, &seq)) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("dst", read_reg_sized(ctx, dst->reg, bits)));
	RzILOpPure *res = apply_binop(binop, VARL("dst"), VARL("src"));
	if (!res) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("res", res));
	RzILOpEffect *write = write_status_reg(ctx, dst->reg, VARL("res"));
	if (!write) {
		return m68k_invalid_free(seq);
	}
	return seq_append(seq, write);
}

static RzILOpEffect *lift_addx_subx(M68KILCtx *ctx, bool subtract) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "src", src, bits, &seq)) {
		return m68k_invalid_free(seq);
	}
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
		return m68k_invalid_free(seq);
	}

	seq = seq_append(seq, SETL("x", BOOL_TO_BV(ccr_bit(M68K_CCR_X), bits)));
	seq = seq_append(seq, SETL("srcx", ADD(VARL("src"), VARL("x"))));
	RzILOpPure *res = subtract ? SUB(VARL("dst"), VARL("srcx")) : ADD(VARL("dst"), VARL("srcx"));
	seq = seq_append(seq, SETL("res", res));
	RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, write);
	seq = seq_append(seq, dst_rw.post);

	RzILOpPure *wide_dst = cast_unsigned(64, VARL("dst"));
	RzILOpPure *wide_src = cast_unsigned(64, VARL("src"));
	RzILOpPure *wide_x = cast_unsigned(64, VARL("x"));
	RzILOpBool *c = subtract
		? ULT(wide_dst, ADD(wide_src, wide_x))
		: UGT(ADD(ADD(wide_dst, wide_src), wide_x), U64(bits == 32 ? UT32_MAX : ((1ULL << bits) - 1)));
	RzILOpBool *v = subtract ? subx_overflow(bits) : addx_overflow(bits);
	return seq_append(seq, set_flags_nzvcx_extend(VARL("res"), bits, v, c));
}

static RzILOpPure *bcd_byte_to_decimal(const char *local) {
	RzILOpPure *high = cast_unsigned(32, SHIFTR0(LOGAND(VARL(local), U8(0xf0)), U8(4)));
	RzILOpPure *low = cast_unsigned(32, LOGAND(VARL(local), U8(0x0f)));
	return ADD(MUL(high, U32(10)), low);
}

static RzILOpPure *bcd_decimal_to_byte(const char *local) {
	RzILOpPure *high = SHIFTL0(DIV(cast_unsigned(32, VARL(local)), U32(10)), U8(4));
	RzILOpPure *low = MOD(cast_unsigned(32, VARL(local)), U32(10));
	return cast_unsigned(8, LOGOR(high, low));
}

static RzILOpEffect *set_flags_bcd(RzILOpPure *result, RzILOpBool *carry) {
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xea));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, AND(ccr_bit(M68K_CCR_Z), IS_ZERO(cast_unsigned(8, result))));
	ccr = ccr_with_flag(ccr, M68K_CCR_C, (RzILOpBool *)DUP(carry));
	ccr = ccr_with_flag(ccr, M68K_CCR_X, carry);
	return set_ccr_from_value(ccr);
}

static RzILOpEffect *lift_abcd_sbcd(M68KILCtx *ctx, bool subtract) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "src", &ctx->m68k->operands[0], 8, &seq)) {
		return m68k_invalid_free(seq);
	}
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[1], 8, &seq)) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("src_dec", bcd_byte_to_decimal("src")));
	seq = seq_append(seq, SETL("dst_dec", bcd_byte_to_decimal("dst")));
	seq = seq_append(seq, SETL("x", BOOL_TO_BV(ccr_bit(M68K_CCR_X), 32)));
	if (subtract) {
		seq = seq_append(seq, SETL("diff", SUB(SUB(cast_signed(32, VARL("dst_dec")), cast_signed(32, VARL("src_dec"))), cast_signed(32, VARL("x")))));
		seq = seq_append(seq, SETL("res_dec", ITE(SLT(VARL("diff"), S32(0)), ADD(VARL("diff"), S32(100)), VARL("diff"))));
	} else {
		seq = seq_append(seq, SETL("sum", ADD(ADD(VARL("dst_dec"), VARL("src_dec")), VARL("x"))));
		seq = seq_append(seq, SETL("res_dec", MOD(VARL("sum"), U32(100))));
	}
	seq = seq_append(seq, SETL("res", bcd_decimal_to_byte("res_dec")));
	RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, 8, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, write);
	seq = seq_append(seq, dst_rw.post);
	RzILOpBool *carry = subtract ? SLT(VARL("diff"), S32(0)) : UGT(VARL("sum"), U32(99));
	return seq_append(seq, set_flags_bcd(VARL("res"), carry));
}

static RzILOpEffect *lift_nbcd(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[0], 8, &seq)) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("dst_dec", bcd_byte_to_decimal("dst")));
	seq = seq_append(seq, SETL("x", BOOL_TO_BV(ccr_bit(M68K_CCR_X), 32)));
	seq = seq_append(seq, SETL("diff", SUB(S32(0), ADD(cast_signed(32, VARL("dst_dec")), cast_signed(32, VARL("x"))))));
	seq = seq_append(seq, SETL("borrow", BOOL_TO_BV(SLT(VARL("diff"), S32(0)), 32)));
	seq = seq_append(seq, SETL("res_dec", ITE(NON_ZERO(VARL("borrow")), ADD(VARL("diff"), S32(100)), VARL("diff"))));
	seq = seq_append(seq, SETL("res", bcd_decimal_to_byte("res_dec")));
	RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, 8, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, write);
	seq = seq_append(seq, dst_rw.post);
	return seq_append(seq, set_flags_bcd(VARL("res"), NON_ZERO(VARL("borrow"))));
}

static RzILOpPure *pack_adjustment(M68KILCtx *ctx) {
	if (ctx->m68k->op_count > 2 && ctx->m68k->operands[2].type == M68K_OP_IMM) {
		return U16((ut16)ctx->m68k->operands[2].imm);
	}
	return U16(0);
}

static RzILOpEffect *lift_pack_unpk(M68KILCtx *ctx, bool unpack) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	bool reg_to_reg = rz_m68k_op_is_data_reg(src) && rz_m68k_op_is_data_reg(dst);
	bool mem_to_mem = rz_m68k_op_is_predec_areg(src) && rz_m68k_op_is_predec_areg(dst);
	if (!reg_to_reg && !mem_to_mem) {
		return m68k_invalid();
	}

	RzILOpEffect *seq = NULL;
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpPure *src_value = read_operand(ctx, src, unpack ? 8 : 16, &pre, &post);
	if (!src_value) {
		return m68k_invalid();
	}
	seq = seq_append(seq, pre);
	seq = seq_append(seq, SETL("src", src_value));
	seq = seq_append(seq, post);
	seq = seq_append(seq, SETL("adjustment", pack_adjustment(ctx)));
	if (unpack) {
		RzILOpPure *high = SHIFTL0(cast_unsigned(16, LOGAND(VARL("src"), U8(0xf0))), U8(4));
		RzILOpPure *low = cast_unsigned(16, LOGAND(VARL("src"), U8(0x0f)));
		seq = seq_append(seq, SETL("expanded", LOGOR(high, low)));
		seq = seq_append(seq, SETL("res", ADD(VARL("expanded"), VARL("adjustment"))));
	} else {
		seq = seq_append(seq, SETL("adjusted", ADD(cast_unsigned(16, VARL("src")), VARL("adjustment"))));
		RzILOpPure *high = SHIFTR0(LOGAND(VARL("adjusted"), U16(0x0f00)), U8(4));
		RzILOpPure *low = LOGAND(VARL("adjusted"), U16(0x000f));
		seq = seq_append(seq, SETL("res", cast_unsigned(8, LOGOR(high, low))));
	}

	RzILOpEffect *write = write_operand(ctx, dst, unpack ? 16 : 8, VARL("res"), &pre, &post);
	if (!write) {
		rz_il_op_effect_free(pre);
		rz_il_op_effect_free(post);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, pre);
	seq = seq_append(seq, write);
	seq = seq_append(seq, post);
	return seq;
}

static RzILOpEffect *lift_unary_write_result(M68KILCtx *ctx, RzILOpPure *result, bool set_flags) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	const cs_m68k_op *dst = &ctx->m68k->operands[0];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpEffect *write = write_operand(ctx, dst, bits, VARL("res"), &pre, &post);
	if (!write) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, pre);
	seq = seq_append(seq, SETL("res", result));
	seq = seq_append(seq, write);
	seq = seq_append(seq, post);
	if (set_flags) {
		seq = seq_append(seq, set_flags_nzvcx(VARL("res"), bits, IL_FALSE, IL_FALSE, NULL));
	}
	return seq;
}

static RzILOpEffect *lift_tst(M68KILCtx *ctx) {
	RzILOpEffect *seq = NULL;
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (!operand_to_local(ctx, "dst", &ctx->m68k->operands[0], bits, &seq)) {
		return m68k_invalid();
	}
	return seq_append(seq, set_flags_nzvcx(VARL("dst"), bits, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_clr(M68KILCtx *ctx) {
	return lift_unary_write_result(ctx, UN(rz_m68k_detail_op_bits(ctx->m68k, 32), 0), true);
}

static RzILOpEffect *lift_not(M68KILCtx *ctx) {
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[0], bits, &seq)) {
		return m68k_invalid();
	}
	seq = seq_append(seq, SETL("res", LOGNOT(VARL("dst"))));
	RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	seq = seq_append(seq, write);
	seq = seq_append(seq, dst_rw.post);
	return seq_append(seq, set_flags_nzvcx(VARL("res"), bits, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_neg(M68KILCtx *ctx, bool with_extend) {
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[0], bits, &seq)) {
		return m68k_invalid();
	}
	if (with_extend) {
		seq = seq_append(seq, SETL("borrow", BOOL_TO_BV(ccr_bit(M68K_CCR_X), bits)));
		seq = seq_append(seq, SETL("res", SUB(SUB(UN(bits, 0), VARL("dst")), VARL("borrow"))));
	} else {
		seq = seq_append(seq, SETL("res", SUB(SUB(UN(bits, 0), VARL("dst")), UN(bits, 0))));
	}
	RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	seq = seq_append(seq, write);
	seq = seq_append(seq, dst_rw.post);
	RzILOpBool *c = with_extend ? OR(NON_ZERO(VARL("dst")), ccr_bit(M68K_CCR_X)) : NON_ZERO(VARL("dst"));
	RzILOpBool *v = with_extend ? negx_overflow(bits) : sub_overflow(UN(bits, 0), VARL("dst"), VARL("res"));
	return seq_append(seq, with_extend ? set_flags_nzvcx_extend(VARL("res"), bits, v, c) : set_flags_nzvcx(VARL("res"), bits, v, c, (RzILOpBool *)DUP(c)));
}

static RzILOpEffect *lift_swap(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[0])) {
		return m68k_invalid();
	}
	m68k_reg reg = ctx->m68k->operands[0].reg;
	RzILOpPure *v = reg_value(ctx, reg);
	RzILOpPure *res = LOGOR(SHIFTL0(cast_unsigned(32, v), U8(16)), SHIFTR0(cast_unsigned(32, DUP(v)), U8(16)));
	return SEQ3(
		SETL("res", DUP(res)),
		write_reg_sized(ctx, reg, 32, res),
		set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_exg(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || ctx->m68k->operands[0].type != M68K_OP_REG || ctx->m68k->operands[1].type != M68K_OP_REG) {
		return m68k_invalid();
	}
	m68k_reg a = ctx->m68k->operands[0].reg;
	m68k_reg b = ctx->m68k->operands[1].reg;
	return SEQ3(
		SETL("tmp", read_reg_sized(ctx, a, 32)),
		write_reg_sized(ctx, a, 32, read_reg_sized(ctx, b, 32)),
		write_reg_sized(ctx, b, 32, VARL("tmp")));
}

static RzILOpBool *cond_code(M68KILCtx *ctx, ut32 insn_id) {
	(void)ctx;
	switch (insn_id) {
	case M68K_INS_DBT:
	case M68K_INS_ST:
	case M68K_INS_TRAPT:
		return IL_TRUE;
	case M68K_INS_DBF:
	case M68K_INS_DBRA:
	case M68K_INS_SF:
	case M68K_INS_TRAPF:
		return IL_FALSE;
	case M68K_INS_BHI:
	case M68K_INS_DBHI:
	case M68K_INS_SHI:
	case M68K_INS_TRAPHI:
		return AND(INV(ccr_bit(M68K_CCR_C)), INV(ccr_bit(M68K_CCR_Z)));
	case M68K_INS_BLS:
	case M68K_INS_DBLS:
	case M68K_INS_SLS:
	case M68K_INS_TRAPLS:
		return OR(ccr_bit(M68K_CCR_C), ccr_bit(M68K_CCR_Z));
	case M68K_INS_BCC:
	case M68K_INS_BHS:
	case M68K_INS_DBCC:
	case M68K_INS_SCC:
	case M68K_INS_SHS:
	case M68K_INS_TRAPCC:
	case M68K_INS_TRAPHS:
		return INV(ccr_bit(M68K_CCR_C));
	case M68K_INS_BCS:
	case M68K_INS_BLO:
	case M68K_INS_DBCS:
	case M68K_INS_SCS:
	case M68K_INS_SLO:
	case M68K_INS_TRAPCS:
	case M68K_INS_TRAPLO:
		return ccr_bit(M68K_CCR_C);
	case M68K_INS_BNE:
	case M68K_INS_DBNE:
	case M68K_INS_SNE:
	case M68K_INS_TRAPNE:
		return INV(ccr_bit(M68K_CCR_Z));
	case M68K_INS_BEQ:
	case M68K_INS_DBEQ:
	case M68K_INS_SEQ:
	case M68K_INS_TRAPEQ:
		return ccr_bit(M68K_CCR_Z);
	case M68K_INS_BVC:
	case M68K_INS_DBVC:
	case M68K_INS_SVC:
	case M68K_INS_TRAPVC:
		return INV(ccr_bit(M68K_CCR_V));
	case M68K_INS_BVS:
	case M68K_INS_DBVS:
	case M68K_INS_SVS:
	case M68K_INS_TRAPVS:
		return ccr_bit(M68K_CCR_V);
	case M68K_INS_BPL:
	case M68K_INS_DBPL:
	case M68K_INS_SPL:
	case M68K_INS_TRAPPL:
		return INV(ccr_bit(M68K_CCR_N));
	case M68K_INS_BMI:
	case M68K_INS_DBMI:
	case M68K_INS_SMI:
	case M68K_INS_TRAPMI:
		return ccr_bit(M68K_CCR_N);
	case M68K_INS_BGE:
	case M68K_INS_DBGE:
	case M68K_INS_SGE:
	case M68K_INS_TRAPGE:
		return EQ(BOOL_TO_BV(ccr_bit(M68K_CCR_N), 1), BOOL_TO_BV(ccr_bit(M68K_CCR_V), 1));
	case M68K_INS_BLT:
	case M68K_INS_DBLT:
	case M68K_INS_SLT:
	case M68K_INS_TRAPLT:
		return NE(BOOL_TO_BV(ccr_bit(M68K_CCR_N), 1), BOOL_TO_BV(ccr_bit(M68K_CCR_V), 1));
	case M68K_INS_BGT:
	case M68K_INS_DBGT:
	case M68K_INS_SGT:
	case M68K_INS_TRAPGT:
		return AND(INV(ccr_bit(M68K_CCR_Z)), EQ(BOOL_TO_BV(ccr_bit(M68K_CCR_N), 1), BOOL_TO_BV(ccr_bit(M68K_CCR_V), 1)));
	case M68K_INS_BLE:
	case M68K_INS_DBLE:
	case M68K_INS_SLE:
	case M68K_INS_TRAPLE:
		return OR(ccr_bit(M68K_CCR_Z), NE(BOOL_TO_BV(ccr_bit(M68K_CCR_N), 1), BOOL_TO_BV(ccr_bit(M68K_CCR_V), 1)));
	default:
		return NULL;
	}
}

#define M68K_FPU_COND_CASE(offset, fb, fdb, fs, ftrap) \
	case M68K_INS_FB##fb: \
	case M68K_INS_FDB##fdb: \
	case M68K_INS_FS##fs: \
	case M68K_INS_FTRAP##ftrap: \
		return offset

static int fpu_cond_offset(ut32 insn_id) {
	switch (insn_id) {
		M68K_FPU_COND_CASE(0, F, F, F, F);
		M68K_FPU_COND_CASE(1, EQ, EQ, BEQ, EQ);
		M68K_FPU_COND_CASE(2, OGT, OGT, OGT, OGT);
		M68K_FPU_COND_CASE(3, OGE, OGE, OGE, OGE);
		M68K_FPU_COND_CASE(4, OLT, OLT, OLT, OLT);
		M68K_FPU_COND_CASE(5, OLE, OLE, OLE, OLE);
		M68K_FPU_COND_CASE(6, OGL, OGL, OGL, OGL);
		M68K_FPU_COND_CASE(7, OR, OR, OR, OR);
		M68K_FPU_COND_CASE(8, UN, UN, UN, UN);
		M68K_FPU_COND_CASE(9, UEQ, UEQ, UEQ, UEQ);
		M68K_FPU_COND_CASE(10, UGT, UGT, UGT, UGT);
		M68K_FPU_COND_CASE(11, UGE, UGE, UGE, UGE);
		M68K_FPU_COND_CASE(12, ULT, ULT, ULT, ULT);
		M68K_FPU_COND_CASE(13, ULE, ULE, ULE, ULE);
		M68K_FPU_COND_CASE(14, NE, NE, NE, NE);
		M68K_FPU_COND_CASE(15, T, T, T, T);
		M68K_FPU_COND_CASE(16, SF, SF, SF, SF);
		M68K_FPU_COND_CASE(17, SEQ, SEQ, SEQ, SEQ);
		M68K_FPU_COND_CASE(18, GT, GT, GT, GT);
		M68K_FPU_COND_CASE(19, GE, GE, GE, GE);
		M68K_FPU_COND_CASE(20, LT, LT, LT, LT);
		M68K_FPU_COND_CASE(21, LE, LE, LE, LE);
		M68K_FPU_COND_CASE(22, GL, GL, GL, GL);
		M68K_FPU_COND_CASE(23, GLE, GLE, GLE, GLE);
		M68K_FPU_COND_CASE(24, NGLE, NGLE, NGLE, NGLE);
		M68K_FPU_COND_CASE(25, NGL, NGL, NGL, NGL);
		M68K_FPU_COND_CASE(26, NLE, NLE, NLE, NLE);
		M68K_FPU_COND_CASE(27, NLT, NLT, NLT, NLT);
		M68K_FPU_COND_CASE(28, NGE, NGE, NGE, NGE);
		M68K_FPU_COND_CASE(29, NGT, NGT, NGT, NGT);
		M68K_FPU_COND_CASE(30, SNE, SNE, SNE, SNE);
		M68K_FPU_COND_CASE(31, ST, ST, ST, ST);
	default:
		break;
	}

	return -1;
}

#undef M68K_FPU_COND_CASE

static RzILOpBool *fpu_cond_ogt(void) {
	return AND(INV(fpsr_bit(M68K_FPSR_CC_NAN)),
		AND(INV(fpsr_bit(M68K_FPSR_CC_Z)), INV(fpsr_bit(M68K_FPSR_CC_N))));
}

static RzILOpBool *fpu_cond_oge(void) {
	return OR(fpsr_bit(M68K_FPSR_CC_Z),
		AND(INV(fpsr_bit(M68K_FPSR_CC_NAN)), INV(fpsr_bit(M68K_FPSR_CC_N))));
}

static RzILOpBool *fpu_cond_olt(void) {
	return AND(INV(fpsr_bit(M68K_FPSR_CC_NAN)),
		AND(INV(fpsr_bit(M68K_FPSR_CC_Z)), fpsr_bit(M68K_FPSR_CC_N)));
}

static RzILOpBool *fpu_cond_ole(void) {
	return OR(fpsr_bit(M68K_FPSR_CC_Z),
		AND(INV(fpsr_bit(M68K_FPSR_CC_NAN)), fpsr_bit(M68K_FPSR_CC_N)));
}

static RzILOpBool *fpu_cond_ogl(void) {
	return AND(INV(fpsr_bit(M68K_FPSR_CC_NAN)), INV(fpsr_bit(M68K_FPSR_CC_Z)));
}

static RzILOpBool *fpu_cond_ueq(void) {
	return OR(fpsr_bit(M68K_FPSR_CC_NAN), fpsr_bit(M68K_FPSR_CC_Z));
}

static RzILOpBool *fpu_cond_ugt(void) {
	return OR(fpsr_bit(M68K_FPSR_CC_NAN),
		AND(INV(fpsr_bit(M68K_FPSR_CC_Z)), INV(fpsr_bit(M68K_FPSR_CC_N))));
}

static RzILOpBool *fpu_cond_uge(void) {
	return OR(fpsr_bit(M68K_FPSR_CC_NAN),
		OR(fpsr_bit(M68K_FPSR_CC_Z), INV(fpsr_bit(M68K_FPSR_CC_N))));
}

static RzILOpBool *fpu_cond_ult(void) {
	return OR(fpsr_bit(M68K_FPSR_CC_NAN),
		AND(INV(fpsr_bit(M68K_FPSR_CC_Z)), fpsr_bit(M68K_FPSR_CC_N)));
}

static RzILOpBool *fpu_cond_ule(void) {
	return OR(fpsr_bit(M68K_FPSR_CC_NAN),
		OR(fpsr_bit(M68K_FPSR_CC_Z), fpsr_bit(M68K_FPSR_CC_N)));
}

static RzILOpBool *fpu_cond_code(ut32 insn_id) {
	switch (fpu_cond_offset(insn_id)) {
	case 0: // F
	case 16: // SF
		return IL_FALSE;
	case 1: // EQ
	case 17: // SEQ
		return fpsr_bit(M68K_FPSR_CC_Z);
	case 2: // OGT
	case 18: // GT
		return fpu_cond_ogt();
	case 3: // OGE
	case 19: // GE
		return fpu_cond_oge();
	case 4: // OLT
	case 20: // LT
		return fpu_cond_olt();
	case 5: // OLE
	case 21: // LE
		return fpu_cond_ole();
	case 6: // OGL
	case 22: // GL
		return fpu_cond_ogl();
	case 7: // OR
	case 23: // GLE
		return INV(fpsr_bit(M68K_FPSR_CC_NAN));
	case 8: // UN
	case 24: // NGLE
		return fpsr_bit(M68K_FPSR_CC_NAN);
	case 9: // UEQ
	case 25: // NGL
		return fpu_cond_ueq();
	case 10: // UGT
	case 26: // NLE
		return fpu_cond_ugt();
	case 11: // UGE
	case 27: // NLT
		return fpu_cond_uge();
	case 12: // ULT
	case 28: // NGE
		return fpu_cond_ult();
	case 13: // ULE
	case 29: // NGT
		return fpu_cond_ule();
	case 14: // NE
	case 30: // SNE
		return INV(fpsr_bit(M68K_FPSR_CC_Z));
	case 15: // T
	case 31: // ST
		return IL_TRUE;
	default:
		return NULL;
	}
}

static RzILOpEffect *lift_branch_cond(M68KILCtx *ctx, RzILOpBool *cond, bool call) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	RzILOpPure *target = read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL);
	if (!target) {
		return m68k_invalid();
	}
	RzILOpEffect *jmp = JMP(target);
	if (call) {
		jmp = SEQ2(push32(ctx, u32(ctx->next_addr)), jmp);
	}
	return BRANCH(cond, jmp, EMPTY());
}

static RzILOpEffect *lift_branch(M68KILCtx *ctx, bool unconditional, bool call) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	RzILOpPure *target = read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL);
	if (!target) {
		return m68k_invalid();
	}
	RzILOpEffect *jmp = JMP(target);
	if (call) {
		jmp = SEQ2(push32(ctx, u32(ctx->next_addr)), jmp);
	}
	if (unconditional) {
		return jmp;
	}
	RzILOpBool *cond = cond_code(ctx, ctx->insn->id);
	if (!cond) {
		return m68k_invalid();
	}
	return BRANCH(cond, jmp, EMPTY());
}

static RzILOpEffect *lift_jmp_jsr(M68KILCtx *ctx, bool call) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	RzILOpPure *target = NULL;
	RzILOpEffect *seq = NULL;
	if (rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0])) {
		M68KEA ea = effective_addr(ctx, &ctx->m68k->operands[0], 32);
		seq = seq_append(seq, ea.pre);
		target = ea.addr;
		seq = seq_append(seq, ea.post);
	} else {
		target = read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL);
	}
	if (!target) {
		return m68k_invalid();
	}
	if (call) {
		seq = seq_append(seq, SETL("target", target));
		seq = seq_append(seq, push32(ctx, u32(ctx->next_addr)));
		target = VARL("target");
	}
	seq = seq_append(seq, JMP(target));
	return seq;
}

static RzILOpEffect *lift_rts(M68KILCtx *ctx) {
	return SEQ3(
		SETL("target", read_mem_sized(32, reg_value(ctx, M68K_REG_A7))),
		set_addr_reg_delta(ctx, M68K_REG_A7, 4),
		JMP(VARL("target")));
}

static RzILOpEffect *lift_rtd(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return m68k_invalid();
	}
	st32 disp = (st16)ctx->m68k->operands[0].imm;
	return SEQ3(
		SETL("target", read_mem_sized(32, reg_value(ctx, M68K_REG_A7))),
		set_addr_reg_delta(ctx, M68K_REG_A7, 4 + disp),
		JMP(VARL("target")));
}

static RzILOpEffect *lift_rtr(M68KILCtx *ctx) {
	return SEQ5(
		SETL("ccr", read_mem_sized(16, reg_value(ctx, M68K_REG_A7))),
		set_addr_reg_delta(ctx, M68K_REG_A7, 2),
		SETL("target", read_mem_sized(32, reg_value(ctx, M68K_REG_A7))),
		set_addr_reg_delta(ctx, M68K_REG_A7, 4),
		SEQ2(set_ccr_from_value(VARL("ccr")), JMP(VARL("target"))));
}

static RzILOpEffect *lift_rte(M68KILCtx *ctx) {
	RzILOpEffect *effect = NULL;
	effect = seq_append(effect, SETL("frame", cast_unsigned(32, reg_value(ctx, M68K_REG_A7))));
	effect = seq_append(effect, SETL("new_sr", read_mem_sized(16, VARL("frame"))));
	effect = seq_append(effect, SETL("target", read_mem_sized(32, ADD(VARL("frame"), U32(2)))));
	RzILOpEffect *restore = NULL;
	if (m68k_mode_has_format_word(ctx->mode)) {
		effect = seq_append(effect, SETL("format", SHIFTR0(read_mem_sized(16, ADD(VARL("frame"), U32(6))), U8(12))));
		effect = seq_append(effect, SETL("frame_size", rte_frame_size(ctx->mode)));
		restore = seq_append(restore, write_reg_sized(ctx, M68K_REG_A7, 32, ADD(VARL("frame"), VARL("frame_size"))));
		restore = seq_append(restore, write_reg_sized(ctx, M68K_REG_SR, 16, VARL("new_sr")));
		restore = seq_append(restore, JMP(VARL("target")));
		effect = seq_append(effect, BRANCH(rte_format_valid(ctx->mode), restore, m68k_exception(M68K_TRAP_OP_FORMAT, M68K_VECTOR_FORMAT_ERROR, "m68k_trap")));
	} else {
		restore = seq_append(restore, write_reg_sized(ctx, M68K_REG_A7, 32, ADD(VARL("frame"), U32(6))));
		restore = seq_append(restore, write_reg_sized(ctx, M68K_REG_SR, 16, VARL("new_sr")));
		restore = seq_append(restore, JMP(VARL("target")));
		effect = seq_append(effect, restore);
	}
	return BRANCH(supervisor_mode(), effect, m68k_label("m68k_privilege"));
}

static RzILOpEffect *lift_rtm(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 ||
		!rz_m68k_op_is_gpr(&ctx->m68k->operands[0])) {
		return m68k_invalid();
	}

	m68k_reg module_reg = ctx->m68k->operands[0].reg;
	RzILOpEffect *restore = SEQ4(
		set_ccr_from_value(SHIFTR0(VARL("ccr_arg"), U8(8))),
		write_reg_sized(ctx, module_reg, 32, VARL("module_data")),
		write_reg_sized(ctx, M68K_REG_A7, 32, ADD(ADD(VARL("frame"), U32(0x18)), VARL("arg_count"))),
		JMP(VARL("target")));

	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, SETL("frame", cast_unsigned(32, reg_value(ctx, M68K_REG_A7))));
	seq = seq_append(seq, SETL("frame_info", read_mem_sized(16, VARL("frame"))));
	seq = seq_append(seq, SETL("ccr_arg", read_mem_sized(16, ADD(VARL("frame"), U32(2)))));
	seq = seq_append(seq, SETL("arg_count", cast_unsigned(32, cast_unsigned(8, VARL("ccr_arg")))));
	seq = seq_append(seq, SETL("target", read_mem_sized(32, ADD(VARL("frame"), U32(0x0c)))));
	seq = seq_append(seq, SETL("module_data", read_mem_sized(32, ADD(VARL("frame"), U32(0x10)))));
	return seq_append(seq, BRANCH(IS_ZERO(LOGAND(VARL("frame_info"), U16(0xff00))), restore, m68k_label("m68k_rtm")));
}

static RzILOpEffect *lift_stop(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return m68k_invalid();
	}
	ut16 new_sr = (ut16)ctx->m68k->operands[0].imm;
	RzILOpEffect *load_sr = write_reg_sized(ctx, M68K_REG_SR, 16, U16(new_sr));
	if (!load_sr) {
		return m68k_invalid();
	}
	RzILOpEffect *effect = SEQ4(
		SETL("system_op", U32(ctx->insn->id == M68K_INS_LPSTOP ? M68K_SYSTEM_OP_LPSTOP : M68K_SYSTEM_OP_STOP)),
		SETL("system_sr", U32(new_sr)),
		load_sr,
		m68k_label("m68k_system"));
	return BRANCH(supervisor_mode(), effect, m68k_label("m68k_privilege"));
}

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static RzILOpEffect *lift_strldsr(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return m68k_invalid();
	}

	ut16 new_sr = (ut16)ctx->m68k->operands[0].imm;
	if (!(new_sr & (1u << M68K_SR_S))) {
		return m68k_label("m68k_privilege");
	}

	RzILOpEffect *effect = SEQ2(
		push32(ctx, cast_unsigned(32, VARG("sr"))),
		write_reg_sized(ctx, M68K_REG_SR, 16, U16(new_sr)));
	return BRANCH(supervisor_mode(), effect, m68k_label("m68k_privilege"));
}
#endif

static RzILOpEffect *lift_privileged_system(M68KSystemOp op) {
	RzILOpEffect *effect = SEQ2(
		SETL("system_op", U32((ut32)op)),
		m68k_label("m68k_system"));
	return BRANCH(supervisor_mode(), effect, m68k_label("m68k_privilege"));
}

static RzILOpEffect *lift_link(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 ||
		!rz_m68k_op_is_addr_reg(&ctx->m68k->operands[0]) ||
		ctx->m68k->operands[1].type != M68K_OP_IMM) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	st32 disp = bits == 16
		? (st32)(st16)(ut16)ctx->m68k->operands[1].imm
		: (st32)ctx->m68k->operands[1].imm;
	m68k_reg areg = ctx->m68k->operands[0].reg;
	return SEQ4(
		push32(ctx, read_reg_sized(ctx, areg, 32)),
		write_reg_sized(ctx, areg, 32, reg_value(ctx, M68K_REG_A7)),
		SETL("new_sp", disp >= 0 ? ADD(reg_value(ctx, M68K_REG_A7), U32((ut32)disp)) : SUB(reg_value(ctx, M68K_REG_A7), U32((ut32)-disp))),
		write_reg_sized(ctx, M68K_REG_A7, 32, VARL("new_sp")));
}

static RzILOpEffect *lift_unlk(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || ctx->m68k->operands[0].type != M68K_OP_REG) {
		return m68k_invalid();
	}
	m68k_reg areg = ctx->m68k->operands[0].reg;
	return SEQ4(
		write_reg_sized(ctx, M68K_REG_A7, 32, read_reg_sized(ctx, areg, 32)),
		SETL("old", read_mem_sized(32, reg_value(ctx, M68K_REG_A7))),
		set_addr_reg_delta(ctx, M68K_REG_A7, 4),
		write_reg_sized(ctx, areg, 32, VARL("old")));
}

static RzILOpEffect *lift_scc_cond(M68KILCtx *ctx, RzILOpBool *cond) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	RzILOpPure *value = ITE(cond, U8(0xff), U8(0));
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpEffect *write = write_operand(ctx, &ctx->m68k->operands[0], 8, value, &pre, &post);
	if (!write) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, pre);
	seq = seq_append(seq, write);
	seq = seq_append(seq, post);
	return seq;
}

static RzILOpEffect *lift_scc(M68KILCtx *ctx) {
	RzILOpBool *cond = cond_code(ctx, ctx->insn->id);
	if (!cond) {
		return m68k_invalid();
	}
	return lift_scc_cond(ctx, cond);
}

static RzILOpEffect *lift_dbcc_cond(M68KILCtx *ctx, RzILOpBool *cond) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[0]) || ctx->m68k->operands[1].type != M68K_OP_BR_DISP) {
		return m68k_invalid();
	}
	m68k_reg reg = ctx->m68k->operands[0].reg;
	RzILOpPure *reg_value = read_reg_sized(ctx, reg, 32);
	if (!reg_value) {
		return m68k_invalid();
	}
	RzILOpPure *target = branch_disp_target(ctx, &ctx->m68k->operands[1]);
	if (!target) {
		rz_il_op_pure_free(reg_value);
		return m68k_invalid();
	}
	RzILOpEffect *seq = SETL("dec", SUB(cast_unsigned(16, reg_value), U16(1)));
	seq = seq_append(seq, write_reg_sized(ctx, reg, 16, VARL("dec")));
	seq = seq_append(seq, BRANCH(NE(VARL("dec"), U16(0xffff)), JMP(target), EMPTY()));
	return BRANCH(cond,
		EMPTY(),
		seq);
}

static RzILOpEffect *lift_dbcc(M68KILCtx *ctx) {
	RzILOpBool *cond = cond_code(ctx, ctx->insn->id);
	if (!cond) {
		return m68k_invalid();
	}
	return lift_dbcc_cond(ctx, cond);
}

static RzILOpPure *signed_zero_for_bits(ut32 bits) {
	return bits == 16 ? S16(0) : S32(0);
}

static RzILOpEffect *lift_chk(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	if (bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "bound", &ctx->m68k->operands[0], bits, &seq)) {
		return m68k_invalid();
	}
	RzILOpPure *dst = read_reg_sized(ctx, ctx->m68k->operands[1].reg, bits);
	if (!dst) {
		return m68k_invalid();
	}
	seq = seq_append(seq, SETL("dst", dst));

	RzILOpEffect *neg_trap = SEQ2(
		set_ccr_from_value(ccr_with_flag(cast_unsigned(8, VARG("sr")), M68K_CCR_N, IL_TRUE)),
		m68k_exception(M68K_TRAP_OP_CHK, M68K_VECTOR_CHK, "m68k_chk"));
	RzILOpEffect *high_trap = SEQ2(
		set_ccr_from_value(ccr_with_flag(cast_unsigned(8, VARG("sr")), M68K_CCR_N, IL_FALSE)),
		m68k_exception(M68K_TRAP_OP_CHK, M68K_VECTOR_CHK, "m68k_chk"));
	return seq_append(seq, BRANCH(SLT(VARL("dst"), signed_zero_for_bits(bits)), neg_trap, BRANCH(SGT(VARL("dst"), VARL("bound")), high_trap, EMPTY())));
}

static RzILOpPure *cmp2_extend_value(RzILOpPure *value, ut32 bits) {
	return bits == 32 ? value : cast_signed(32, value);
}

static RzILOpBool *cmp2_outside_bounds(void) {
	RzILOpBool *ordered = SLE(VARL("lower"), VARL("upper"));
	RzILOpBool *outside_ordered = OR(SLT(VARL("rn"), VARL("lower")), SGT(VARL("rn"), VARL("upper")));
	RzILOpBool *outside_wrapped = AND(SGT(VARL("rn"), VARL("upper")), SLT(VARL("rn"), VARL("lower")));
	return OR(AND(ordered, outside_ordered), AND(INV(SLE(VARL("lower"), VARL("upper"))), outside_wrapped));
}

static RzILOpEffect *set_flags_cmp2(void) {
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xfa));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, NON_ZERO(VARL("equal")));
	ccr = ccr_with_flag(ccr, M68K_CCR_C, NON_ZERO(VARL("outside")));
	return set_ccr_from_value(ccr);
}

static RzILOpEffect *lift_cmp2_chk2(M68KILCtx *ctx, bool trap) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0]) || !rz_m68k_op_is_gpr(&ctx->m68k->operands[1])) {
		return m68k_invalid();
	}
	const cs_m68k_op *bounds = &ctx->m68k->operands[0];
	const cs_m68k_op *reg = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (bits != 8 && bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	M68KEA ea = effective_addr(ctx, bounds, bits);
	if (!ea.addr) {
		return m68k_invalid();
	}
	RzILOpPure *rn = read_reg_sized(ctx, reg->reg, rz_m68k_reg_is_areg(reg->reg) ? 32 : bits);
	if (!rn) {
		return m68k_invalid();
	}
	if (rz_m68k_reg_is_dreg(reg->reg)) {
		rn = cmp2_extend_value(rn, bits);
	}
	RzILOpPure *addr = cast_unsigned(32, ea.addr);
	RzILOpPure *upper_addr = ADD(VARL("bounds_addr"), U32(rz_m68k_bits_access_bytes(bits)));
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, ea.pre);
	seq = seq_append(seq, SETL("bounds_addr", addr));
	seq = seq_append(seq, SETL("lower", cmp2_extend_value(read_mem_sized(bits, VARL("bounds_addr")), bits)));
	seq = seq_append(seq, SETL("upper", cmp2_extend_value(read_mem_sized(bits, upper_addr), bits)));
	seq = seq_append(seq, SETL("rn", rn));
	seq = seq_append(seq, SETL("outside", BOOL_TO_BV(cmp2_outside_bounds(), 1)));
	seq = seq_append(seq, SETL("equal", BOOL_TO_BV(OR(EQ(VARL("rn"), VARL("lower")), EQ(VARL("rn"), VARL("upper"))), 1)));
	seq = seq_append(seq, set_flags_cmp2());
	seq = seq_append(seq, ea.post);
	if (trap) {
		seq = seq_append(seq, BRANCH(NON_ZERO(VARL("outside")), m68k_exception(M68K_TRAP_OP_CHK, M68K_VECTOR_CHK, "m68k_chk"), EMPTY()));
	}
	return seq;
}

static RzILOpEffect *lift_cas(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 3 ||
		!rz_m68k_op_is_data_reg(&ctx->m68k->operands[0]) ||
		!rz_m68k_op_is_data_reg(&ctx->m68k->operands[1]) ||
		!rz_m68k_op_is_mem_addr(&ctx->m68k->operands[2])) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (bits != 8 && bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	RzILOpPure *cmp = read_reg_sized(ctx, ctx->m68k->operands[0].reg, bits);
	RzILOpPure *upd = read_reg_sized(ctx, ctx->m68k->operands[1].reg, bits);
	if (!cmp || !upd) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, SETL("cmp", cmp));
	seq = seq_append(seq, SETL("upd", upd));
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[2], bits, &seq)) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("res", SUB(VARL("dst"), VARL("cmp"))));
	RzILOpEffect *success = write_rw_operand(ctx, &dst_rw, bits, VARL("upd"));
	RzILOpEffect *failure = write_reg_sized(ctx, ctx->m68k->operands[0].reg, bits, VARL("dst"));
	if (!success || !failure) {
		m68k_rw_operand_fini(&dst_rw);
		rz_il_op_effect_free(success);
		rz_il_op_effect_free(failure);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, BRANCH(EQ(cast_unsigned(bits, VARL("cmp")), cast_unsigned(bits, VARL("dst"))), success, failure));
	seq = seq_append(seq, dst_rw.post);
	return seq_append(seq, set_flags_nzvcx(VARL("res"), bits, sub_overflow(VARL("dst"), VARL("cmp"), VARL("res")), ULT(VARL("dst"), VARL("cmp")), NULL));
}

static RzILOpEffect *lift_cas2(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 3 ||
		!rz_m68k_op_is_data_reg_pair(&ctx->m68k->operands[0]) ||
		!rz_m68k_op_is_data_reg_pair(&ctx->m68k->operands[1]) ||
		!rz_m68k_op_is_gpr_reg_pair(&ctx->m68k->operands[2])) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (bits != 16 && bits != 32) {
		return m68k_invalid();
	}

	const cs_m68k_op *cmp = &ctx->m68k->operands[0];
	const cs_m68k_op *upd = &ctx->m68k->operands[1];
	const cs_m68k_op *addr = &ctx->m68k->operands[2];
	RzILOpPure *addr0 = read_reg_sized(ctx, addr->reg_pair.reg_0, 32);
	RzILOpPure *addr1 = read_reg_sized(ctx, addr->reg_pair.reg_1, 32);
	RzILOpPure *cmp0 = read_reg_sized(ctx, cmp->reg_pair.reg_0, bits);
	RzILOpPure *cmp1 = read_reg_sized(ctx, cmp->reg_pair.reg_1, bits);
	RzILOpPure *upd0 = read_reg_sized(ctx, upd->reg_pair.reg_0, bits);
	RzILOpPure *upd1 = read_reg_sized(ctx, upd->reg_pair.reg_1, bits);
	if (!addr0 || !addr1 || !cmp0 || !cmp1 || !upd0 || !upd1) {
		return m68k_invalid();
	}

	RzILOpEffect *success = SEQ2(
		write_mem_sized(bits, VARL("addr0"), VARL("upd0")),
		write_mem_sized(bits, VARL("addr1"), VARL("upd1")));
	RzILOpEffect *fail_second = write_reg_sized(ctx, cmp->reg_pair.reg_1, bits, VARL("dst1"));
	RzILOpEffect *fail_first = write_reg_sized(ctx, cmp->reg_pair.reg_0, bits, VARL("dst0"));
	if (!success || !fail_second || !fail_first) {
		rz_il_op_effect_free(success);
		rz_il_op_effect_free(fail_second);
		rz_il_op_effect_free(fail_first);
		return m68k_invalid();
	}
	RzILOpEffect *failure = SEQ2(fail_second, fail_first);

	RzILOpEffect *seq = SEQ9(
		SETL("addr0", addr0),
		SETL("addr1", addr1),
		SETL("cmp0", cmp0),
		SETL("cmp1", cmp1),
		SETL("upd0", upd0),
		SETL("upd1", upd1),
		SETL("dst0", read_mem_sized(bits, VARL("addr0"))),
		SETL("dst1", read_mem_sized(bits, VARL("addr1"))),
		SETL("first_eq", BOOL_TO_BV(EQ(VARL("cmp0"), VARL("dst0")), 1)));
	seq = seq_append(seq, SETL("second_eq", BOOL_TO_BV(EQ(VARL("cmp1"), VARL("dst1")), 1)));
	seq = seq_append(seq, SETL("res0", SUB(VARL("dst0"), VARL("cmp0"))));
	seq = seq_append(seq, SETL("res1", SUB(VARL("dst1"), VARL("cmp1"))));
	seq = seq_append(seq, SETL("flag_cmp", ITE(NON_ZERO(VARL("first_eq")), VARL("cmp1"), VARL("cmp0"))));
	seq = seq_append(seq, SETL("flag_dst", ITE(NON_ZERO(VARL("first_eq")), VARL("dst1"), VARL("dst0"))));
	seq = seq_append(seq, SETL("res", ITE(NON_ZERO(VARL("first_eq")), VARL("res1"), VARL("res0"))));
	seq = seq_append(seq, BRANCH(AND(NON_ZERO(VARL("first_eq")), NON_ZERO(VARL("second_eq"))), success, failure));
	return seq_append(seq, set_flags_nzvcx(VARL("res"), bits, sub_overflow(VARL("flag_dst"), VARL("flag_cmp"), VARL("res")), ULT(VARL("flag_dst"), VARL("flag_cmp")), NULL));
}

#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
static RzILOpPure *tbl_extend_entry(RzILOpPure *value, ut32 bits, bool sign) {
	return sign ? cast_signed(64, value) : cast_unsigned(64, value);
}

static RzILOpPure *tbl_rounded_delta(void) {
	RzILOpPure *adjusted = ITE(
		MSB(VARL("prod")),
		SUB(VARL("prod"), S64(0x80)),
		ADD(VARL("prod"), S64(0x80)));
	return SDIV(adjusted, S64(0x100));
}

static RzILOpPure *tbl_unrounded_result(ut32 bits, bool sign) {
	ut32 result_bits = bits == 32 ? 32 : bits + 8;
	RzILOpPure *sized = cast_unsigned(result_bits, VARL("fixed"));
	return sign ? cast_signed(32, sized) : cast_unsigned(32, sized);
}

static RzILOpPure *tbl_immediate_base(M68KILCtx *ctx, ut32 bits) {
	return u32(ctx->addr + 4 + (bits == 8 ? 1 : 0));
}

static RzILOpEffect *lift_tbl(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	m68k_reg dst_reg = ctx->m68k->operands[1].reg;
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (bits != 8 && bits != 16 && bits != 32) {
		return m68k_invalid();
	}

	bool sign = rz_m68k_tbl_insn_is_signed(ctx->insn->id);
	bool unrounded = rz_m68k_tbl_insn_is_unrounded(ctx->insn->id);
	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, SETL("x", read_reg_sized(ctx, dst_reg, 16)));
	seq = seq_append(seq, SETL("frac", cast_unsigned(64, LOGAND(VARL("x"), U16(0xff)))));

	if (rz_m68k_op_is_data_reg_pair(src)) {
		seq = seq_append(seq, SETL("entry0", tbl_extend_entry(read_reg_sized(ctx, src->reg_pair.reg_0, bits), bits, sign)));
		seq = seq_append(seq, SETL("entry1", tbl_extend_entry(read_reg_sized(ctx, src->reg_pair.reg_1, bits), bits, sign)));
	} else if (rz_m68k_op_is_mem_addr(src)) {
		M68KEA ea = effective_addr(ctx, src, bits);
		if (!ea.addr) {
			return m68k_invalid();
		}
		ut32 bytes = rz_m68k_bits_access_bytes(bits);
		seq = seq_append(seq, ea.pre);
		seq = seq_append(seq, SETL("base", cast_unsigned(32, ea.addr)));
		seq = seq_append(seq, SETL("index", cast_unsigned(32, SHIFTR0(LOGAND(VARL("x"), U16(0xff00)), U8(8)))));
		seq = seq_append(seq, SETL("entry_addr", ADD(VARL("base"), MUL(VARL("index"), U32(bytes)))));
		seq = seq_append(seq, SETL("entry0", tbl_extend_entry(read_mem_sized(bits, VARL("entry_addr")), bits, sign)));
		seq = seq_append(seq, SETL("entry1", tbl_extend_entry(read_mem_sized(bits, ADD(VARL("entry_addr"), U32(bytes))), bits, sign)));
		seq = seq_append(seq, ea.post);
	} else if (src->type == M68K_OP_IMM) {
		ut32 bytes = rz_m68k_bits_access_bytes(bits);
		seq = seq_append(seq, SETL("base", tbl_immediate_base(ctx, bits)));
		seq = seq_append(seq, SETL("index", cast_unsigned(32, SHIFTR0(LOGAND(VARL("x"), U16(0xff00)), U8(8)))));
		seq = seq_append(seq, SETL("entry_addr", ADD(VARL("base"), MUL(VARL("index"), U32(bytes)))));
		seq = seq_append(seq, SETL("entry0", tbl_extend_entry(read_mem_sized(bits, VARL("entry_addr")), bits, sign)));
		seq = seq_append(seq, SETL("entry1", tbl_extend_entry(read_mem_sized(bits, ADD(VARL("entry_addr"), U32(bytes))), bits, sign)));
	} else {
		return m68k_invalid_free(seq);
	}

	seq = seq_append(seq, SETL("diff", SUB(VARL("entry1"), VARL("entry0"))));
	seq = seq_append(seq, SETL("prod", MUL(VARL("diff"), VARL("frac"))));
	if (unrounded) {
		seq = seq_append(seq, SETL("fixed", ADD(SHIFTL0(VARL("entry0"), U8(8)), VARL("prod"))));
		seq = seq_append(seq, SETL("res", tbl_unrounded_result(bits, sign)));
		seq = seq_append(seq, write_reg_sized(ctx, dst_reg, 32, VARL("res")));
		return seq_append(seq, set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
	}

	seq = seq_append(seq, SETL("res", cast_unsigned(bits, ADD(VARL("entry0"), tbl_rounded_delta()))));
	seq = seq_append(seq, write_reg_sized(ctx, dst_reg, bits, VARL("res")));
	return seq_append(seq, set_flags_nzvcx(VARL("res"), bits, IL_FALSE, IL_FALSE, NULL));
}
#endif

static RzILOpEffect *lift_ext(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1 || ctx->m68k->operands[0].type != M68K_OP_REG) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	ut32 src_bits = ctx->insn->id == M68K_INS_EXTB ? 8 : (bits == 32 ? 16 : 8);
	m68k_reg reg = ctx->m68k->operands[0].reg;
	RzILOpPure *src = cast_unsigned(src_bits, read_reg_sized(ctx, reg, 32));
	RzILOpPure *res = cast_signed(bits, src);
	return SEQ3(
		SETL("res", DUP(res)),
		write_reg_sized(ctx, reg, bits, res),
		set_flags_nzvcx(VARL("res"), bits, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_tas(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[0], 8, &seq)) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("res", LOGOR(VARL("dst"), U8(0x80))));
	RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, 8, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, write);
	seq = seq_append(seq, dst_rw.post);
	return seq_append(seq, set_flags_nzvcx(VARL("dst"), 8, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_shift(M68KILCtx *ctx, bool left, bool arithmetic) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	const cs_m68k_op *dst = NULL;
	if (ctx->m68k->op_count == 1) {
		dst = &ctx->m68k->operands[0];
		seq = seq_append(seq, SETL("count", U8(1)));
	} else {
		dst = &ctx->m68k->operands[1];
		if (!operand_to_local(ctx, "count", &ctx->m68k->operands[0], bits, &seq)) {
			return m68k_invalid_free(seq);
		}
	}
	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
		return m68k_invalid_free(seq);
	}
	RzILOpPure *count = cast_unsigned(8, VARL("count"));
	seq = seq_append(seq, SETL("count8", LOGAND(count, U8(0x3f))));
	RzILOpPure *res = left ? SHIFTL0(VARL("dst"), VARL("count8")) : (arithmetic ? SHIFTRA(VARL("dst"), VARL("count8")) : SHIFTR0(VARL("dst"), VARL("count8")));
	seq = seq_append(seq, SETL("res", res));
	RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, write);
	seq = seq_append(seq, dst_rw.post);
	RzILOpBool *shifted_out = NULL;
	if (left) {
		shifted_out = NON_ZERO(LOGAND(SHIFTR0(VARL("dst"), SUB(U8(bits), VARL("count8"))), UN(bits, 1)));
	} else {
		RzILOpBool *right_shifted_out = NON_ZERO(LOGAND(SHIFTR0(VARL("dst"), SUB(VARL("count8"), U8(1))), UN(bits, 1)));
		if (arithmetic) {
			RzILOpBool *past_width = UGE(VARL("count8"), U8(bits));
			RzILOpBool *within_width = ULT(VARL("count8"), U8(bits));
			shifted_out = OR(AND(past_width, MSB(VARL("dst"))), AND(within_width, right_shifted_out));
		} else {
			shifted_out = right_shifted_out;
		}
	}
	RzILOpBool *carry = AND(NON_ZERO(VARL("count8")), (RzILOpBool *)DUP(shifted_out));
	RzILOpBool *extend = OR(AND(IS_ZERO(VARL("count8")), ccr_bit(M68K_CCR_X)), AND(NON_ZERO(VARL("count8")), shifted_out));
	RzILOpBool *overflow = IL_FALSE;
	if (left && arithmetic) {
		for (ut32 i = 1; i <= bits; i++) {
			RzILOpBool *shift_reached = UGE(VARL("count8"), U8(i));
			RzILOpBool *new_sign = i < bits
				? NON_ZERO(LOGAND(SHIFTR0(VARL("dst"), U8(bits - 1 - i)), UN(bits, 1)))
				: IL_FALSE;
			RzILOpBool *sign_changed = NE(BOOL_TO_BV(MSB(VARL("dst")), 1), BOOL_TO_BV(new_sign, 1));
			overflow = OR(overflow, AND(shift_reached, sign_changed));
		}
	}
	return seq_append(seq, set_flags_nzvcx(VARL("res"), bits, overflow, carry, extend));
}

static RzILOpPure *rotate_expr(const char *value_local, const char *count_local, ut32 bits, bool left) {
	RzILOpPure *res = left
		? LOGOR(SHIFTL0(VARL(value_local), VARL(count_local)), SHIFTR0(VARL(value_local), SUB(U8(bits), VARL(count_local))))
		: LOGOR(SHIFTR0(VARL(value_local), VARL(count_local)), SHIFTL0(VARL(value_local), SUB(U8(bits), VARL(count_local))));
	return ITE(IS_ZERO(VARL(count_local)), VARL(value_local), res);
}

static RzILOpEffect *lift_rotate(M68KILCtx *ctx, bool left, bool extend) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	const cs_m68k_op *dst = NULL;
	if (ctx->m68k->op_count == 1) {
		dst = &ctx->m68k->operands[0];
		seq = seq_append(seq, SETL("count", U8(1)));
	} else {
		dst = &ctx->m68k->operands[1];
		if (!operand_to_local(ctx, "count", &ctx->m68k->operands[0], bits, &seq)) {
			return m68k_invalid_free(seq);
		}
	}

	M68KRWOperand dst_rw;
	if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, SETL("count_raw", LOGAND(cast_unsigned(8, VARL("count")), U8(0x3f))));
	seq = seq_append(seq, SETL("rot_count", MOD(VARL("count_raw"), U8(extend ? bits + 1 : bits))));
	if (extend) {
		ut32 wide_bits = bits + 1;
		RzILOpPure *wide = APPEND(BOOL_TO_BV(ccr_bit(M68K_CCR_X), 1), cast_unsigned(bits, VARL("dst")));
		seq = seq_append(seq, SETL("wide", wide));
		seq = seq_append(seq, SETL("wide_res", rotate_expr("wide", "rot_count", wide_bits, left)));
		seq = seq_append(seq, SETL("res", cast_unsigned(bits, VARL("wide_res"))));
	} else {
		seq = seq_append(seq, SETL("res", rotate_expr("dst", "rot_count", bits, left)));
	}

	RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, write);
	seq = seq_append(seq, dst_rw.post);

	RzILOpBool *did_rotate = NON_ZERO(VARL("count_raw"));
	RzILOpBool *carry = NULL;
	RzILOpBool *x = NULL;
	if (extend) {
		RzILOpBool *new_x = MSB(VARL("wide_res"));
		carry = OR(AND(INV((RzILOpBool *)DUP(did_rotate)), ccr_bit(M68K_CCR_X)),
			AND(did_rotate, (RzILOpBool *)DUP(new_x)));
		x = OR(AND(IS_ZERO(VARL("count_raw")), ccr_bit(M68K_CCR_X)),
			AND(NON_ZERO(VARL("count_raw")), new_x));
	} else {
		RzILOpBool *rotated_carry = left ? NON_ZERO(LOGAND(VARL("res"), UN(bits, 1))) : MSB(VARL("res"));
		carry = AND(did_rotate, rotated_carry);
	}
	return seq_append(seq, set_flags_nzvcx(VARL("res"), bits, IL_FALSE, carry, x));
}

static RzILOpEffect *lift_bitop(M68KILCtx *ctx, ut32 insn_id) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *bitop = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = dst->type == M68K_OP_REG ? 32 : 8;
	RzILOpEffect *seq = NULL;
	if (!operand_to_local(ctx, "bit", bitop, bits, &seq)) {
		return m68k_invalid();
	}
	M68KRWOperand dst_rw = { 0 };
	bool writes_dst = insn_id != M68K_INS_BTST;
	if (writes_dst) {
		if (!rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
			return m68k_invalid();
		}
	} else if (!operand_to_local(ctx, "dst", dst, bits, &seq)) {
		return m68k_invalid();
	}
	RzILOpPure *idx = MOD(cast_unsigned(bits, VARL("bit")), UN(bits, bits));
	RzILOpPure *mask = SHIFTL0(UN(bits, 1), cast_unsigned(8, idx));
	RzILOpBool *was_set = NON_ZERO(LOGAND(VARL("dst"), writes_dst ? DUP(mask) : mask));
	RzILOpPure *res = NULL;
	switch (insn_id) {
	case M68K_INS_BSET:
		res = LOGOR(VARL("dst"), mask);
		break;
	case M68K_INS_BCLR:
		res = LOGAND(VARL("dst"), LOGNOT(mask));
		break;
	case M68K_INS_BCHG:
		res = LOGXOR(VARL("dst"), mask);
		break;
	case M68K_INS_BTST:
		break;
	default:
		return m68k_invalid();
	}
	seq = seq_append(seq, set_ccr_from_value(ccr_with_flag(LOGAND(cast_unsigned(8, VARG("sr")), U8(0xfb)), M68K_CCR_Z, INV(was_set))));
	if (res) {
		RzILOpEffect *write = write_rw_operand(ctx, &dst_rw, bits, res);
		seq = seq_append(seq, write);
		seq = seq_append(seq, dst_rw.post);
	}
	return seq;
}

static RzILOpPure *bitfield_encoded_value(M68KILCtx *ctx, ut8 encoded, bool width) {
	if (M68K_BF_IS_REG(encoded)) {
		m68k_reg reg = M68K_REG_D0 + M68K_BF_REG_NUM(encoded);
		RzILOpPure *value = read_reg_sized(ctx, reg, 32);
		if (!value) {
			return NULL;
		}
		if (width) {
			RzILOpPure *low = LOGAND(value, U32(0x1f));
			return ITE(IS_ZERO(DUP(low)), U32(32), low);
		}
		return value;
	}
	if (width && encoded == 0) {
		return U32(32);
	}
	return U32(encoded);
}

static RzILOpPure *bitfield_mask64(void) {
	return SUB(SHIFTL0(U64(1), cast_unsigned(8, VARL("width"))), U64(1));
}

static RzILOpPure *bitfield_mask32(void) {
	return cast_unsigned(32, bitfield_mask64());
}

static RzILOpPure *bitfield_shift(void) {
	return SUB(U8(64), cast_unsigned(8, ADD(VARL("bit_offset"), VARL("width"))));
}

static RzILOpPure *bitfield_field_from_container(void) {
	return LOGAND(cast_unsigned(32, SHIFTR0(VARL("container"), bitfield_shift())), bitfield_mask32());
}

static RzILOpPure *bitfield_container_with_field(RzILOpPure *field) {
	RzILOpPure *shift = bitfield_shift();
	RzILOpPure *mask = SHIFTL0(bitfield_mask64(), (RzILOpPure *)DUP(shift));
	RzILOpPure *value = SHIFTL0(LOGAND(cast_unsigned(64, field), bitfield_mask64()), shift);
	return LOGOR(LOGAND(VARL("container"), LOGNOT(mask)), value);
}

static RzILOpPure *bitfield_data_reg_writeback(RzILOpPure *updated) {
	RzILOpPure *wrapped_mask = cast_unsigned(32, SHIFTL0(bitfield_mask64(), bitfield_shift()));
	RzILOpPure *upper = cast_unsigned(32, SHIFTR0((RzILOpPure *)DUP(updated), U8(32)));
	RzILOpPure *lower = cast_unsigned(32, updated);
	return LOGOR(LOGAND(upper, LOGNOT((RzILOpPure *)DUP(wrapped_mask))), LOGAND(lower, wrapped_mask));
}

static RzILOpPure *bitfield_sign_extend(void) {
	RzILOpPure *sign_mask = SHIFTL0(U32(1), cast_unsigned(8, SUB(VARL("width"), U32(1))));
	RzILOpBool *sign = NON_ZERO(LOGAND(VARL("field"), sign_mask));
	return ITE(sign, LOGOR(VARL("field"), LOGNOT(bitfield_mask32())), VARL("field"));
}

static RzILOpPure *bitfield_left_aligned(void) {
	return SHIFTL0(VARL("field"), SUB(U8(32), cast_unsigned(8, VARL("width"))));
}

static RzILOpEffect *set_flags_bitfield(RzILOpPure *field) {
	RzILOpPure *value = LOGAND(cast_unsigned(32, field), bitfield_mask32());
	RzILOpPure *sign_mask = SHIFTL0(U32(1), cast_unsigned(8, SUB(VARL("width"), U32(1))));
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xe0));
	ccr = ccr_with_flag(ccr, M68K_CCR_N, NON_ZERO(LOGAND(DUP(value), sign_mask)));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, IS_ZERO(value));
	ccr = ccr_with_flag(ccr, M68K_CCR_V, IL_FALSE);
	ccr = ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	ccr = LOGOR(ccr, LOGAND(cast_unsigned(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	return set_ccr_from_value(ccr);
}

static bool bitfield_target_to_local(M68KILCtx *ctx, const cs_m68k_op *op, M68KBitfieldTarget *target, RzILOpEffect **seq) {
	rz_return_val_if_fail(op && target && seq, false);
	*target = (M68KBitfieldTarget){
		.op = op,
		.memory = rz_m68k_op_is_mem_addr(op),
		.addr_local = "bf_addr",
		.post = NULL,
	};
	RzILOpPure *offset = bitfield_encoded_value(ctx, op->mem.offset, false);
	RzILOpPure *width = bitfield_encoded_value(ctx, op->mem.width, true);
	if (!offset || !width) {
		rz_il_op_pure_free(offset);
		rz_il_op_pure_free(width);
		return false;
	}
	*seq = seq_append(*seq, SETL("offset", offset));
	*seq = seq_append(*seq, SETL("width", width));
	if (target->memory) {
		M68KEA ea = effective_addr(ctx, op, 32);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return false;
		}
		*seq = seq_append(*seq, ea.pre);
		*seq = seq_append(*seq, SETL("base", cast_unsigned(32, ea.addr)));
		if (M68K_BF_IS_REG(op->mem.offset)) {
			*seq = seq_append(*seq, SETL("bit_offset", LOGAND(VARL("offset"), U32(7))));
			*seq = seq_append(*seq, SETL("byte_offset", SDIV(cast_signed(32, SUB(VARL("offset"), VARL("bit_offset"))), S32(8))));
		} else {
			*seq = seq_append(*seq, SETL("byte_offset", DIV(VARL("offset"), U32(8))));
			*seq = seq_append(*seq, SETL("bit_offset", MOD(VARL("offset"), U32(8))));
		}
		*seq = seq_append(*seq, SETL(target->addr_local, ADD(VARL("base"), VARL("byte_offset"))));
		*seq = seq_append(*seq, SETL("container", read_mem_sized(64, VARL(target->addr_local))));
		target->post = ea.post;
	} else if (rz_m68k_op_is_data_reg(op)) {
		RzILOpPure *value = read_reg_sized(ctx, op->reg, 32);
		if (!value) {
			return false;
		}
		*seq = seq_append(*seq, SETL("bit_offset", MOD(VARL("offset"), U32(32))));
		*seq = seq_append(*seq, SETL("container", APPEND(value, read_reg_sized(ctx, op->reg, 32))));
	} else {
		rz_il_op_effect_free(target->post);
		target->post = NULL;
		return false;
	}
	*seq = seq_append(*seq, SETL("field", bitfield_field_from_container()));
	return true;
}

static RzILOpEffect *write_bitfield_target(M68KILCtx *ctx, const M68KBitfieldTarget *target, RzILOpPure *field) {
	RzILOpEffect *write = NULL;
	RzILOpPure *updated = bitfield_container_with_field(field);
	if (target->memory) {
		write = write_mem_sized(64, VARL(target->addr_local), updated);
		if (!write) {
			rz_il_op_pure_free(updated);
		}
	} else if (rz_m68k_op_is_data_reg(target->op)) {
		write = write_reg_sized(ctx, target->op->reg, 32, bitfield_data_reg_writeback(updated));
	} else {
		rz_il_op_pure_free(updated);
	}
	if (!write) {
		rz_il_op_effect_free(target->post);
		return NULL;
	}
	return seq_append(write, target->post);
}

static RzILOpPure *bitfield_fffo_index(void) {
	RzILOpPure *res = VARL("width");
	for (st32 i = 31; i >= 0; i--) {
		RzILOpBool *in_range = ULT(U32(i), VARL("width"));
		RzILOpBool *bit_set = NON_ZERO(LOGAND(VARL("scan"), U32(1u << (31 - i))));
		res = ITE(AND(in_range, bit_set), U32(i), res);
	}
	return res;
}

static RzILOpEffect *lift_bitfield(M68KILCtx *ctx, ut32 insn_id) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	bool insert = insn_id == M68K_INS_BFINS;
	const cs_m68k_op *target_op = insert ? &ctx->m68k->operands[1] : &ctx->m68k->operands[0];
	M68KBitfieldTarget target = { 0 };
	RzILOpEffect *seq = NULL;
	if (!target_op->mem.bitfield || !bitfield_target_to_local(ctx, target_op, &target, &seq)) {
		return m68k_invalid_free(seq);
	}
	RzILOpEffect *write = NULL;
	switch (insn_id) {
	case M68K_INS_BFTST:
		seq = seq_append(seq, target.post);
		target.post = NULL;
		return seq_append(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFEXTU:
	case M68K_INS_BFEXTS:
		if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
			m68k_bitfield_target_fini(&target);
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, SETL("res", insn_id == M68K_INS_BFEXTS ? bitfield_sign_extend() : VARL("field")));
		seq = seq_append(seq, write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, VARL("res")));
		seq = seq_append(seq, target.post);
		target.post = NULL;
		return seq_append(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFFFO:
		if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
			m68k_bitfield_target_fini(&target);
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, SETL("scan", bitfield_left_aligned()));
		seq = seq_append(seq, SETL("first", bitfield_fffo_index()));
		seq = seq_append(seq, write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, ADD(VARL("offset"), VARL("first"))));
		seq = seq_append(seq, target.post);
		target.post = NULL;
		return seq_append(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFCHG:
		write = write_bitfield_target(ctx, &target, LOGXOR(VARL("field"), bitfield_mask32()));
		if (!write) {
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, write);
		return seq_append(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFCLR:
		write = write_bitfield_target(ctx, &target, U32(0));
		if (!write) {
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, write);
		return seq_append(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFSET:
		write = write_bitfield_target(ctx, &target, bitfield_mask32());
		if (!write) {
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, write);
		return seq_append(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFINS:
		if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[0])) {
			m68k_bitfield_target_fini(&target);
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, SETL("src", LOGAND(read_reg_sized(ctx, ctx->m68k->operands[0].reg, 32), bitfield_mask32())));
		write = write_bitfield_target(ctx, &target, VARL("src"));
		if (!write) {
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, write);
		return seq_append(seq, set_flags_bitfield(VARL("src")));
	default:
		m68k_bitfield_target_fini(&target);
		return m68k_invalid_free(seq);
	}
}

static RzILOpEffect *lift_mul(M68KILCtx *ctx, bool sign) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *dst_op = &ctx->m68k->operands[1];

	if (dst_op->type == M68K_OP_REG_PAIR) {
		ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
		if (bits != 32) {
			return m68k_invalid();
		}
		m68k_reg high_reg = dst_op->reg_pair.reg_0;
		m68k_reg low_reg = dst_op->reg_pair.reg_1;
		if (!rz_m68k_reg_is_dreg(high_reg) || !rz_m68k_reg_is_dreg(low_reg) || high_reg == low_reg) {
			return m68k_invalid();
		}
		RzILOpEffect *seq = NULL;
		if (!operand_to_local(ctx, "src", &ctx->m68k->operands[0], bits, &seq)) {
			return m68k_invalid_free(seq);
		}
		RzILOpPure *dst = read_reg_sized(ctx, low_reg, bits);
		if (!dst) {
			return m68k_invalid_free(seq);
		}
		RzILOpEffect *write_high = write_reg_sized(ctx, high_reg, 32, SHIFTR0(VARL("res"), U8(32)));
		RzILOpEffect *write_low = write_reg_sized(ctx, low_reg, 32, VARL("res"));
		if (!write_high || !write_low) {
			rz_il_op_effect_free(write_high);
			rz_il_op_effect_free(write_low);
			return m68k_invalid_free(seq);
		}
		RzILOpPure *lhs = sign ? cast_signed(64, VARL("dst")) : cast_unsigned(64, VARL("dst"));
		RzILOpPure *rhs = sign ? cast_signed(64, VARL("src")) : cast_unsigned(64, VARL("src"));
		return seq_append(seq, SEQ5(SETL("dst", dst), SETL("res", MUL(lhs, rhs)), write_low, write_high, set_flags_nzvcx(VARL("res"), 64, IL_FALSE, IL_FALSE, NULL)));
	}

	if (dst_op->type != M68K_OP_REG) {
		return m68k_invalid();
	}
	RzILOpEffect *seq = NULL;
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	if (bits != 16 && bits != 32) {
		return m68k_invalid();
	}
	if (!operand_to_local(ctx, "src", &ctx->m68k->operands[0], bits, &seq)) {
		return m68k_invalid_free(seq);
	}
	m68k_reg reg = dst_op->reg;
	RzILOpPure *dst = read_reg_sized(ctx, reg, bits);
	if (!dst) {
		return m68k_invalid_free(seq);
	}
	ut32 product_bits = bits == 32 ? 64 : 32;
	RzILOpPure *lhs = sign ? cast_signed(product_bits, dst) : cast_unsigned(product_bits, dst);
	RzILOpPure *rhs = sign ? cast_signed(product_bits, VARL("src")) : cast_unsigned(product_bits, VARL("src"));
	if (bits == 32) {
		RzILOpBool *overflow = sign
			? signed_out_of_range(VARL("res_wide"), 32)
			: UGT(VARL("res_wide"), U64(UT32_MAX));
		return seq_append(seq, SEQ4(SETL("res_wide", MUL(lhs, rhs)), SETL("res", cast_unsigned(32, VARL("res_wide"))), write_reg_sized(ctx, reg, 32, VARL("res")), set_flags_nzvcx(VARL("res"), 32, overflow, IL_FALSE, NULL)));
	}

	RzILOpPure *res = MUL(lhs, rhs);
	return seq_append(seq, SEQ3(SETL("res", DUP(res)), write_reg_sized(ctx, reg, 32, res), set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL)));
}

static RzILOpEffect *append_trap_arg_metadata(M68KILCtx *ctx, RzILOpEffect *seq) {
	if (ctx->m68k->op_count > 0 && ctx->m68k->operands[0].type == M68K_OP_IMM) {
		bool fpu_trap = ctx->insn->size > 0 && ctx->insn->bytes[0] == 0xf2;
		ut32 arg_bits = ctx->insn->size >= (fpu_trap ? 8 : 6) ? 32 : 16;
		seq = seq_append(seq, SETL("trap_arg", U32((ut32)ctx->m68k->operands[0].imm)));
		seq = seq_append(seq, SETL("trap_arg_bits", U32(arg_bits)));
	}
	return seq;
}

static bool explicit_trap_vector(M68KTrapOp trap_op, M68KExceptionVector *vector) {
	switch (trap_op) {
	case M68K_TRAP_OP_TRAPCC:
	case M68K_TRAP_OP_FTRAPCC:
	case M68K_TRAP_OP_TRAPV:
		*vector = M68K_VECTOR_TRAPV_TRAPCC;
		return true;
	default:
		return false;
	}
}

static RzILOpEffect *explicit_trap_effect(M68KILCtx *ctx, M68KTrapOp trap_op, bool append_arg) {
	RzILOpEffect *seq = SETL("trap_op", U32((ut32)trap_op));
	M68KExceptionVector vector;
	if (explicit_trap_vector(trap_op, &vector)) {
		seq = seq_append(seq, SETL("trap_vector", U32((ut32)vector)));
	}
	if (append_arg) {
		seq = append_trap_arg_metadata(ctx, seq);
	}
	return seq_append(seq, m68k_label("m68k_trap"));
}

static RzILOpEffect *lift_trapcc(M68KILCtx *ctx) {
	RzILOpBool *cond = cond_code(ctx, ctx->insn->id);
	if (!cond) {
		return explicit_trap_effect(ctx, M68K_TRAP_OP_TRAPCC, true);
	}
	return BRANCH(cond, explicit_trap_effect(ctx, M68K_TRAP_OP_TRAPCC, true), EMPTY());
}

static RzILOpEffect *lift_trapcc_cond(M68KILCtx *ctx, RzILOpBool *cond, M68KTrapOp trap_op) {
	return BRANCH(cond, explicit_trap_effect(ctx, trap_op, true), EMPTY());
}

static RzILOpEffect *lift_trap_vector(M68KILCtx *ctx) {
	M68KTrapOp trap_op = ctx->insn->id == M68K_INS_BKPT ? M68K_TRAP_OP_BKPT : M68K_TRAP_OP_TRAP;
	RzILOpEffect *seq = SETL("trap_op", U32((ut32)trap_op));
	if (ctx->m68k->op_count > 0 && ctx->m68k->operands[0].type == M68K_OP_IMM) {
		ut32 arg = (ut32)ctx->m68k->operands[0].imm;
		seq = seq_append(seq, SETL("trap_arg", U32(arg)));
		if (trap_op == M68K_TRAP_OP_TRAP) {
			seq = seq_append(seq, SETL("trap_vector", U32(M68K_VECTOR_TRAP_BASE + (arg & 0xf))));
		}
	}
	return seq_append(seq, m68k_label("m68k_trap"));
}

static RzILOpEffect *lift_fpu_conditional(M68KILCtx *ctx, RzILOpBool *cond) {
	if (ctx->m68k->op_count == 1 && ctx->m68k->operands[0].type == M68K_OP_BR_DISP) {
		return lift_branch_cond(ctx, cond, false);
	}
	if (ctx->m68k->op_count == 2 &&
		ctx->m68k->operands[0].type == M68K_OP_REG &&
		ctx->m68k->operands[1].type == M68K_OP_BR_DISP) {
		return lift_dbcc_cond(ctx, cond);
	}
	if (!ctx->m68k->op_count ||
		(ctx->m68k->op_count == 1 && ctx->m68k->operands[0].type == M68K_OP_IMM)) {
		return lift_trapcc_cond(ctx, cond, M68K_TRAP_OP_FTRAPCC);
	}
	return lift_scc_cond(ctx, cond);
}

static RzILOpEffect *lift_fmove_control(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	bool src_control = rz_m68k_op_is_fpu_control_reg(src);
	bool dst_control = rz_m68k_op_is_fpu_control_reg(dst);
	if (src_control == dst_control) {
		return NULL;
	}

	RzILOpEffect *seq = NULL;
	if (dst_control) {
		if (!operand_to_local(ctx, "src", src, 32, &seq)) {
			return m68k_invalid_free(seq);
		}
		return seq_append(seq, write_reg_sized(ctx, dst->reg, 32, VARL("src")));
	}

	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpEffect *write = write_operand(ctx, dst, 32, read_reg_sized(ctx, src->reg, 32), &pre, &post);
	if (!write) {
		rz_il_op_effect_free(pre);
		rz_il_op_effect_free(post);
		return m68k_invalid_free(seq);
	}
	seq = seq_append(seq, pre);
	seq = seq_append(seq, write);
	seq = seq_append(seq, post);
	return seq;
}

static RzFloatFormat fpu_format_for_bits(ut32 bits) {
	switch (bits) {
	case 32:
		return RZ_FLOAT_IEEE754_BIN_32;
	case 64:
		return RZ_FLOAT_IEEE754_BIN_64;
	case 80:
		return RZ_FLOAT_IEEE754_BIN_80;
	default:
		return RZ_FLOAT_IEEE754_BIN_80;
	}
}

static ut32 fpu_external_bits(M68KILCtx *ctx, ut32 bits) {
	return rz_m68k_fpu_size_is_extended(ctx->m68k) ? M68K_FMOVEM_EXTENDED_BITS : bits;
}

static RzFloatFormat fpu_insn_result_format(M68KILCtx *ctx, ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_FSABS:
	case M68K_INS_FSADD:
	case M68K_INS_FSDIV:
	case M68K_INS_FSMOVE:
	case M68K_INS_FSMUL:
	case M68K_INS_FSNEG:
	case M68K_INS_FSSQRT:
	case M68K_INS_FSSUB:
	case M68K_INS_FSGLDIV:
	case M68K_INS_FSGLMUL:
		return RZ_FLOAT_IEEE754_BIN_32;
	case M68K_INS_FDABS:
	case M68K_INS_FDADD:
	case M68K_INS_FDDIV:
	case M68K_INS_FDMOVE:
	case M68K_INS_FDMUL:
	case M68K_INS_FDNEG:
	case M68K_INS_FDSQRT:
	case M68K_INS_FDSUB:
		return RZ_FLOAT_IEEE754_BIN_64;
	case M68K_INS_FMOVE:
		if (ctx->m68k->op_size.type == M68K_SIZE_TYPE_FPU) {
			return fpu_format_for_bits(rz_m68k_detail_op_bits(ctx->m68k, 80));
		}
		return RZ_FLOAT_IEEE754_BIN_80;
	default:
		return RZ_FLOAT_IEEE754_BIN_80;
	}
}

static RzILOpFloat *fpu_to_format(RzILOpFloat *value, RzFloatFormat format) {
	return FCONVERT(format, RZ_FLOAT_RMODE_RNE, value);
}

static RzILOpFloat *fpu_result_to_fp80(RzILOpFloat *value, RzFloatFormat result_format) {
	RzILOpFloat *rounded = fpu_to_format(value, result_format);
	return result_format == RZ_FLOAT_IEEE754_BIN_80 ? rounded : fpu_to_format(rounded, RZ_FLOAT_IEEE754_BIN_80);
}

static RzILOpPure *fpu_fpcr_round_mode(void) {
	return LOGAND(SHIFTR0(cast_unsigned(32, VARG("fpcr")), U8(4)), U32(3));
}

static RzILOpPure *fpu_fpcr_precision(void) {
	return LOGAND(SHIFTR0(cast_unsigned(32, VARG("fpcr")), U8(6)), U32(3));
}

#define FPU_EXEC_WITH_RMODE(f, ...) \
	ITE(EQ(VARL("round_mode"), U32(0)), f(RZ_FLOAT_RMODE_RNE, __VA_ARGS__), \
		ITE(EQ(VARL("round_mode"), U32(1)), f(RZ_FLOAT_RMODE_RTZ, __VA_ARGS__), \
			ITE(EQ(VARL("round_mode"), U32(2)), f(RZ_FLOAT_RMODE_RTN, __VA_ARGS__), \
				f(RZ_FLOAT_RMODE_RTP, __VA_ARGS__))))

static RzILOpFloat *fpu_convert_with_rmode(RzFloatRMode mode, RzFloatFormat format, RzILOpFloat *value) {
	return FCONVERT(format, mode, value);
}

static RzILOpFloat *fpu_to_format_with_fpcr_rmode(RzILOpFloat *value, RzFloatFormat format) {
	return LET("fpcr_value", value,
		FPU_EXEC_WITH_RMODE(fpu_convert_with_rmode, format, VARLP("fpcr_value")));
}

static RzILOpFloat *fpu_result_to_fp80_with_fpcr_rmode(RzILOpFloat *value, RzFloatFormat result_format) {
	RzILOpFloat *rounded = fpu_to_format_with_fpcr_rmode(value, result_format);
	return result_format == RZ_FLOAT_IEEE754_BIN_80 ? rounded : fpu_to_format(rounded, RZ_FLOAT_IEEE754_BIN_80);
}

static RzILOpFloat *fpu_result_with_fpcr_precision(RzILOpFloat *value) {
	return LET("unrounded_fp", value,
		ITE(EQ(VARL("precision"), U32(1)),
			fpu_result_to_fp80_with_fpcr_rmode(VARLP("unrounded_fp"), RZ_FLOAT_IEEE754_BIN_32),
			ITE(EQ(VARL("precision"), U32(2)),
				fpu_result_to_fp80_with_fpcr_rmode(VARLP("unrounded_fp"), RZ_FLOAT_IEEE754_BIN_64),
				fpu_result_to_fp80_with_fpcr_rmode(VARLP("unrounded_fp"), RZ_FLOAT_IEEE754_BIN_80))));
}

static RzILOpFloat *fpu_binary_unrounded_result(ut32 insn_id) {
	RzILOpFloat *src_value = fpu_to_format_with_fpcr_rmode(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80);
	RzILOpFloat *dst_value = fpu_to_format_with_fpcr_rmode(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80);
	RzILOpFloat *result = NULL;
	switch (insn_id) {
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
		result = FPU_EXEC_WITH_RMODE(FADD, VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
		result = FPU_EXEC_WITH_RMODE(FSUB, VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FSGLMUL:
		result = FPU_EXEC_WITH_RMODE(FMUL, VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FSGLDIV:
		result = FPU_EXEC_WITH_RMODE(FDIV, VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FMOD:
		result = FPU_EXEC_WITH_RMODE(rz_il_op_new_fmod, VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FREM:
		result = LET("quot_fp",
			FROUND(RZ_FLOAT_RMODE_RNE, FPU_EXEC_WITH_RMODE(FDIV, VARLP("dst_ext"), VARLP("src_ext"))),
			LET("prod_fp",
				FPU_EXEC_WITH_RMODE(FMUL, VARLP("quot_fp"), VARLP("src_ext")),
				FPU_EXEC_WITH_RMODE(FSUB, VARLP("dst_ext"), VARLP("prod_fp"))));
		break;
	default:
		rz_il_op_pure_free(src_value);
		rz_il_op_pure_free(dst_value);
		return NULL;
	}
	return LET("src_ext", src_value, LET("dst_ext", dst_value, result));
}

static bool fpu_binary_uses_fpcr_precision(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_FADD:
	case M68K_INS_FSUB:
	case M68K_INS_FMUL:
	case M68K_INS_FDIV:
	case M68K_INS_FMOD:
	case M68K_INS_FREM:
		return true;
	default:
		return false;
	}
}

static RzILOpFloat *fpu_binary_result(M68KILCtx *ctx, ut32 insn_id) {
	RzILOpFloat *result = fpu_binary_unrounded_result(insn_id);
	if (!result) {
		return NULL;
	}
	if (fpu_binary_uses_fpcr_precision(insn_id)) {
		return fpu_result_with_fpcr_precision(result);
	}
	return fpu_result_to_fp80_with_fpcr_rmode(result, fpu_insn_result_format(ctx, insn_id));
}

static bool fpu_operand_to_float_local(M68KILCtx *ctx, const char *name, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq) {
	RzILOpFloat *value = NULL;
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;

	if (op->type == M68K_OP_MEM && op->address_mode == M68K_AM_NONE) {
		return false;
	}
	if (rz_m68k_op_is_fpu_reg(op)) {
		value = BV2F(RZ_FLOAT_IEEE754_BIN_80, read_reg_sized(ctx, op->reg, 80));
	} else if (op->type == M68K_OP_FP_SINGLE) {
		value = F32(op->simm);
	} else if (op->type == M68K_OP_FP_DOUBLE) {
		value = F64(op->dimm);
	} else if (ctx->m68k->op_size.type == M68K_SIZE_TYPE_FPU) {
		if (!rz_m68k_op_is_mem_addr(op)) {
			return false;
		}
		ut32 access_bits = fpu_external_bits(ctx, bits);
		RzILOpPure *raw = read_operand(ctx, op, access_bits, &pre, &post);
		if (!raw) {
			return false;
		}
		*seq = seq_append(*seq, pre);
		if (rz_m68k_fpu_size_is_extended(ctx->m68k)) {
			*seq = seq_append(*seq, SETL("mem_ext", raw));
			value = BV2F(RZ_FLOAT_IEEE754_BIN_80, fpu_ext96_to_fp80(VARL("mem_ext")));
		} else {
			value = BV2F(fpu_format_for_bits(bits), raw);
		}
	} else {
		RzILOpPure *raw = read_operand(ctx, op, bits, &pre, &post);
		if (!raw) {
			return false;
		}
		*seq = seq_append(*seq, pre);
		if (bits == 8 || bits == 16 || bits == 32) {
			value = SINT2F(RZ_FLOAT_IEEE754_BIN_80, RZ_FLOAT_RMODE_RNE, raw);
		} else {
			rz_il_op_pure_free(raw);
			rz_il_op_effect_free(post);
			return false;
		}
	}

	if (!value) {
		rz_il_op_effect_free(post);
		return false;
	}
	*seq = seq_append(*seq, SETL(name, value));
	*seq = seq_append(*seq, post);
	return true;
}

static RzILOpEffect *set_fpsr_cc_from_float_local(const char *name) {
	return set_fpsr_cc(
		IS_FNEG(VARL(name)),
		IS_FZERO(VARL(name)),
		IS_FINF(VARL(name)),
		IS_FNAN(VARL(name)));
}

static RzILOpBool *fpu_cmp_nan(const char *lhs, const char *rhs) {
	return OR(IS_FNAN(VARL(lhs)), IS_FNAN(VARL(rhs)));
}

static RzILOpEffect *set_fpsr_cc_from_float_cmp(const char *lhs, const char *rhs) {
	return set_fpsr_cc(
		AND(INV(fpu_cmp_nan(lhs, rhs)), FLT(VARL(lhs), VARL(rhs))),
		AND(INV(fpu_cmp_nan(lhs, rhs)), FEQ(VARL(lhs), VARL(rhs))),
		OR(IS_FINF(VARL(lhs)), IS_FINF(VARL(rhs))),
		fpu_cmp_nan(lhs, rhs));
}

static RzILOpEffect *fpu_read_failure_label(M68KILCtx *ctx, const cs_m68k_op *op) {
	if (rz_m68k_fpu_op_detail_is_invalid(op)) {
		return m68k_invalid();
	}
	return m68k_label(rz_m68k_fpu_op_is_illegal_read(ctx->m68k, op) ? "m68k_illegal" : "m68k_unimplemented");
}

static RzILOpEffect *fpu_write_failure_label(M68KILCtx *ctx, const cs_m68k_op *op) {
	if (rz_m68k_fpu_op_detail_is_invalid(op)) {
		return m68k_invalid();
	}
	return m68k_label(rz_m68k_fpu_op_is_illegal_write(ctx->m68k, op) ? "m68k_illegal" : "m68k_unimplemented");
}

static RzILOpEffect *fpu_write_float_local(M68KILCtx *ctx, const cs_m68k_op *dst, ut32 bits, const char *name, RzILOpEffect *seq) {
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpPure *value = NULL;
	if (dst->type == M68K_OP_MEM && dst->address_mode == M68K_AM_NONE) {
		return m68k_null_free(seq);
	}
	if (rz_m68k_op_is_fpu_reg(dst)) {
		RzILOpEffect *write = write_reg_sized(ctx, dst->reg, 80, F2BV(fpu_to_format(VARL(name), RZ_FLOAT_IEEE754_BIN_80)));
		if (!write) {
			return m68k_null_free(seq);
		}
		return seq_append(seq, write);
	}
	if (ctx->m68k->op_size.type == M68K_SIZE_TYPE_FPU) {
		if (!rz_m68k_op_is_mem_addr(dst)) {
			return m68k_null_free(seq);
		}
		if (rz_m68k_fpu_size_is_extended(ctx->m68k)) {
			seq = seq_append(seq, SETL("fp80_bits", F2BV(fpu_to_format(VARL(name), RZ_FLOAT_IEEE754_BIN_80))));
			value = fpu_fp80_to_ext96(VARL("fp80_bits"));
			bits = M68K_FMOVEM_EXTENDED_BITS;
		} else {
			RzFloatFormat format = fpu_format_for_bits(bits);
			value = F2BV(fpu_to_format_with_fpcr_rmode(VARL(name), format));
		}
	} else if (bits == 8 || bits == 16 || bits == 32) {
		value = F2SINT(bits, RZ_FLOAT_RMODE_RNE, VARL(name));
	} else {
		return m68k_null_free(seq);
	}

	RzILOpEffect *write = write_operand(ctx, dst, bits, value, &pre, &post);
	if (!write) {
		rz_il_op_effect_free(pre);
		rz_il_op_effect_free(post);
		return m68k_null_free(seq);
	}
	seq = seq_append(seq, pre);
	seq = seq_append(seq, write);
	seq = seq_append(seq, post);
	return seq;
}

static bool fmovecr_const_parts(ut64 selector, ut16 *sign_exp, ut64 *mantissa) {
	static const M68KFMovecrConst constants[] = {
		{ 0x00, 0x4000, 0xc90fdaa22168c235ULL }, // pi
		{ 0x0b, 0x3ffd, 0x9a209a84fbcff799ULL }, // log10(2)
		{ 0x0c, 0x4000, 0xadf85458a2bb4a9bULL }, // e
		{ 0x0d, 0x3fff, 0xb8aa3b295c17f0bcULL }, // log2(e)
		{ 0x0e, 0x3ffd, 0xde5bd8a937287195ULL }, // log10(e)
		{ 0x0f, 0x0000, 0x0000000000000000ULL }, // 0.0
		{ 0x30, 0x3ffe, 0xb17217f7d1cf79acULL }, // ln(2)
		{ 0x31, 0x4000, 0x935d8dddaaa8ac17ULL }, // ln(10)
		{ 0x32, 0x3fff, 0x8000000000000000ULL }, // 10^0
		{ 0x33, 0x4002, 0xa000000000000000ULL }, // 10^1
		{ 0x34, 0x4005, 0xc800000000000000ULL }, // 10^2
		{ 0x35, 0x400c, 0x9c40000000000000ULL }, // 10^4
		{ 0x36, 0x4019, 0xbebc200000000000ULL }, // 10^8
		{ 0x37, 0x4034, 0x8e1bc9bf04000000ULL }, // 10^16
		{ 0x38, 0x4069, 0x9dc5ada82b70b59eULL }, // 10^32
		{ 0x39, 0x40d3, 0xc2781f49ffcfa6d5ULL }, // 10^64
		{ 0x3a, 0x41a8, 0x93ba47c980e98ce0ULL }, // 10^128
		{ 0x3b, 0x4351, 0xaa7eebfb9df9de8eULL }, // 10^256
		{ 0x3c, 0x46a3, 0xe319a0aea60e91c7ULL }, // 10^512
		{ 0x3d, 0x4d48, 0xc976758681750c17ULL }, // 10^1024
		{ 0x3e, 0x5a92, 0x9e8b3b5dc53d5de5ULL }, // 10^2048
		{ 0x3f, 0x7525, 0xc46052028a20979bULL }, // 10^4096
	};
	for (ut32 i = 0; i < RZ_ARRAY_SIZE(constants); i++) {
		if (constants[i].selector == selector) {
			*sign_exp = constants[i].sign_exp;
			*mantissa = constants[i].mantissa;
			return true;
		}
	}
	return false;
}

static RzILOpPure *fpu_const80_bits(ut16 sign_exp, ut64 mantissa) {
	return APPEND(U16(sign_exp), U64(mantissa));
}

static RzILOpEffect *lift_fmovecr(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}

	const cs_m68k_op *src = &ctx->m68k->operands[0];
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (src->type != M68K_OP_IMM) {
		return fpu_read_failure_label(ctx, src);
	}
	if (!rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}

	ut16 sign_exp = 0;
	ut64 mantissa = 0;
	if (!fmovecr_const_parts(src->imm, &sign_exp, &mantissa)) {
		return m68k_label("m68k_fpu");
	}

	RzILOpEffect *seq = NULL;
	seq = seq_append(seq, SETL("res", fpu_const80_bits(sign_exp, mantissa)));
	seq = seq_append(seq, write_reg_sized(ctx, dst->reg, 80, VARL("res")));
	seq = seq_append(seq, SETL("res_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("res"))));
	return seq_append(seq, set_fpsr_cc_from_float_local("res_fp"));
}

static const m68k_reg fmovem_fp_regs[] = {
	M68K_REG_FP0, M68K_REG_FP1, M68K_REG_FP2, M68K_REG_FP3,
	M68K_REG_FP4, M68K_REG_FP5, M68K_REG_FP6, M68K_REG_FP7
};

static m68k_reg fmovem_fp_reg_for_bit(ut32 bit) {
	ut32 index = bit >= 16 ? bit - 16 : bit;
	return index < RZ_ARRAY_SIZE(fmovem_fp_regs) ? fmovem_fp_regs[index] : M68K_REG_INVALID;
}

static ut32 fmovem_fp_reg_count(ut32 reg_bits) {
	ut32 count = 0;
	for (ut32 i = 0; i < RZ_ARRAY_SIZE(fmovem_fp_regs); i++) {
		if (reg_bits & (1u << (16 + i))) {
			count++;
		}
	}
	return count;
}

static ut32 fmovem_dynamic_mask_bit(ut32 fp_index, bool predec) {
	return predec ? fp_index : 7 - fp_index;
}

static RzILOpBool *fmovem_dynamic_mask_has(ut32 fp_index, bool predec) {
	return NON_ZERO(LOGAND(VARL("reg_mask"), U32(1u << fmovem_dynamic_mask_bit(fp_index, predec))));
}

static RzILOpPure *fpu_fp80_to_ext96(RzILOpPure *fp80) {
	RzILOpPure *sign_exp = cast_unsigned(16, SHIFTR0(DUP(fp80), U8(64)));
	RzILOpPure *mantissa = cast_unsigned(64, fp80);
	return APPEND(sign_exp, APPEND(U16(0), mantissa));
}

static RzILOpPure *fpu_ext96_to_fp80(RzILOpPure *ext96) {
	RzILOpPure *sign_exp = cast_unsigned(16, SHIFTR0(DUP(ext96), U8(80)));
	RzILOpPure *mantissa = cast_unsigned(64, ext96);
	return APPEND(sign_exp, mantissa);
}

static RzILOpEffect *lift_fmovem_data(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}

	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if (rz_m68k_fpu_op_detail_is_invalid(src) || rz_m68k_fpu_op_detail_is_invalid(dst)) {
		return m68k_invalid();
	}

	bool static_reg_to_mem = src->type == M68K_OP_REG_BITS && rz_m68k_op_is_mem_addr(dst);
	bool static_mem_to_reg = rz_m68k_op_is_mem_addr(src) && dst->type == M68K_OP_REG_BITS;
	bool dynamic_reg_to_mem = rz_m68k_op_is_data_reg(src) && rz_m68k_op_is_mem_addr(dst);
	bool dynamic_mem_to_reg = rz_m68k_op_is_mem_addr(src) && rz_m68k_op_is_data_reg(dst);
	bool reg_to_mem = static_reg_to_mem || dynamic_reg_to_mem;
	bool mem_to_reg = static_mem_to_reg || dynamic_mem_to_reg;
	if (!reg_to_mem && !mem_to_reg) {
		return m68k_invalid();
	}

	const cs_m68k_op *regs_op = reg_to_mem ? src : dst;
	const cs_m68k_op *mem = reg_to_mem ? dst : src;
	bool dynamic = dynamic_reg_to_mem || dynamic_mem_to_reg;
	ut32 reg_bits = 0;
	if (!dynamic) {
		reg_bits = regs_op->register_bits;
		if (reg_bits & ~M68K_FMOVEM_FP_REG_BITS_MASK) {
			return m68k_invalid();
		}

		ut32 count = fmovem_fp_reg_count(reg_bits);
		if (!count) {
			return NOP();
		}
	}
	if (mem->type == M68K_OP_MEM && mem->address_mode == M68K_AM_NONE) {
		return m68k_invalid();
	}

	bool predec = mem->address_mode == M68K_AM_REGI_ADDR_PRE_DEC;
	bool postinc = mem->address_mode == M68K_AM_REGI_ADDR_POST_INC;
	m68k_reg base_reg = rz_m68k_op_base_reg(mem);
	RzILOpEffect *seq = NULL;
	if (predec || postinc) {
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return m68k_invalid();
		}
		seq = seq_append(seq, SETL("addr", cast_unsigned(32, reg_value(ctx, base_reg))));
	} else {
		M68KEA ea = effective_addr(ctx, mem, M68K_FMOVEM_EXTENDED_BITS);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return m68k_invalid();
		}
		seq = seq_append(seq, ea.pre);
		seq = seq_append(seq, SETL("addr", cast_unsigned(32, ea.addr)));
		seq = seq_append(seq, ea.post);
	}

	if (dynamic) {
		seq = seq_append(seq, SETL("reg_mask", cast_unsigned(32, read_reg_sized(ctx, regs_op->reg, 32))));
		if (reg_to_mem && predec) {
			for (int i = (int)RZ_ARRAY_SIZE(fmovem_fp_regs) - 1; i >= 0; i--) {
				m68k_reg reg = fmovem_fp_regs[i];
				RzILOpPure *value = read_reg_sized(ctx, reg, 80);
				if (!value) {
					return m68k_invalid_free(seq);
				}
				RzILOpEffect *store = SEQ2(
					SETL("addr", SUB(VARL("addr"), U32(M68K_FMOVEM_EXTENDED_BYTES))),
					write_mem_sized(M68K_FMOVEM_EXTENDED_BITS, VARL("addr"), fpu_fp80_to_ext96(value)));
				seq = seq_append(seq, BRANCH(fmovem_dynamic_mask_has((ut32)i, true), store, EMPTY()));
			}
			return seq_append(seq, write_reg_sized(ctx, base_reg, 32, VARL("addr")));
		}

		for (ut32 i = 0; i < RZ_ARRAY_SIZE(fmovem_fp_regs); i++) {
			m68k_reg reg = fmovem_fp_regs[i];
			RzILOpEffect *op = NULL;
			if (reg_to_mem) {
				RzILOpPure *value = read_reg_sized(ctx, reg, 80);
				if (!value) {
					return m68k_invalid_free(seq);
				}
				op = SEQ2(
					write_mem_sized(M68K_FMOVEM_EXTENDED_BITS, VARL("addr"), fpu_fp80_to_ext96(value)),
					SETL("addr", ADD(VARL("addr"), U32(M68K_FMOVEM_EXTENDED_BYTES))));
			} else {
				op = SEQ3(
					SETL("mem_ext", read_mem_sized(M68K_FMOVEM_EXTENDED_BITS, VARL("addr"))),
					write_reg_sized(ctx, reg, 80, fpu_ext96_to_fp80(VARL("mem_ext"))),
					SETL("addr", ADD(VARL("addr"), U32(M68K_FMOVEM_EXTENDED_BYTES))));
			}
			seq = seq_append(seq, BRANCH(fmovem_dynamic_mask_has(i, false), op, EMPTY()));
		}
		if (postinc) {
			seq = seq_append(seq, write_reg_sized(ctx, base_reg, 32, VARL("addr")));
		}
		return seq;
	}

	if (reg_to_mem && predec) {
		for (int i = (int)RZ_ARRAY_SIZE(fmovem_fp_regs) - 1; i >= 0; i--) {
			ut32 bit = 16 + (ut32)i;
			if (!(reg_bits & (1u << bit))) {
				continue;
			}
			m68k_reg reg = fmovem_fp_reg_for_bit(bit);
			RzILOpPure *value = read_reg_sized(ctx, reg, 80);
			if (!value) {
				return m68k_invalid_free(seq);
			}
			seq = seq_append(seq, SETL("addr", SUB(VARL("addr"), U32(M68K_FMOVEM_EXTENDED_BYTES))));
			seq = seq_append(seq, write_mem_sized(M68K_FMOVEM_EXTENDED_BITS, VARL("addr"), fpu_fp80_to_ext96(value)));
		}
		return seq_append(seq, write_reg_sized(ctx, base_reg, 32, VARL("addr")));
	}

	ut32 offset = 0;
	for (ut32 i = 0; i < RZ_ARRAY_SIZE(fmovem_fp_regs); i++) {
		ut32 bit = 16 + i;
		if (!(reg_bits & (1u << bit))) {
			continue;
		}
		m68k_reg reg = fmovem_fp_reg_for_bit(bit);
		RzILOpPure *addr = movem_addr_at(offset);
		RzILOpEffect *op = NULL;
		if (reg_to_mem) {
			RzILOpPure *value = read_reg_sized(ctx, reg, 80);
			if (!value) {
				rz_il_op_pure_free(addr);
				return m68k_invalid_free(seq);
			}
			op = write_mem_sized(M68K_FMOVEM_EXTENDED_BITS, addr, fpu_fp80_to_ext96(value));
		} else {
			seq = seq_append(seq, SETL("mem_ext", read_mem_sized(M68K_FMOVEM_EXTENDED_BITS, addr)));
			op = write_reg_sized(ctx, reg, 80, fpu_ext96_to_fp80(VARL("mem_ext")));
		}
		if (!op) {
			return m68k_invalid_free(seq);
		}
		seq = seq_append(seq, op);
		offset += M68K_FMOVEM_EXTENDED_BYTES;
	}
	if (postinc) {
		seq = seq_append(seq, write_reg_sized(ctx, base_reg, 32, ADD(VARL("addr"), U32(offset))));
	}
	return seq;
}

static RzILOpEffect *lift_fpu_move_data(M68KILCtx *ctx, ut32 insn_id) {
	if (ctx->m68k->op_count < 2) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if ((rz_m68k_op_is_fpu_control_reg(src)) ||
		(rz_m68k_op_is_fpu_control_reg(dst))) {
		return NULL;
	}
	if (rz_m68k_fpu_op_detail_is_invalid(src)) {
		return fpu_read_failure_label(ctx, src);
	}
	if (rz_m68k_fpu_op_detail_is_invalid(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}
	bool src_data_fpu = rz_m68k_op_is_fpu_reg(src) || src->type == M68K_OP_FP_SINGLE || src->type == M68K_OP_FP_DOUBLE;
	bool dst_data_fpu = rz_m68k_op_is_fpu_reg(dst);
	if (!src_data_fpu && !dst_data_fpu && ctx->m68k->op_size.type != M68K_SIZE_TYPE_FPU) {
		return NULL;
	}

	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", src, bits, &seq)) {
		return m68k_effect_free(seq, fpu_read_failure_label(ctx, src));
	}
	seq = seq_append(seq, SETL("round_mode", fpu_fpcr_round_mode()));
	RzILOpFloat *result = NULL;
	if (insn_id == M68K_INS_FMOVE && dst_data_fpu && ctx->m68k->op_size.type != M68K_SIZE_TYPE_FPU) {
		seq = seq_append(seq, SETL("precision", fpu_fpcr_precision()));
		result = fpu_result_with_fpcr_precision(VARL("src_fp"));
	} else if (dst_data_fpu) {
		RzFloatFormat result_format = fpu_insn_result_format(ctx, insn_id);
		result = insn_id == M68K_INS_FMOVE
			? fpu_result_to_fp80(VARL("src_fp"), result_format)
			: fpu_result_to_fp80_with_fpcr_rmode(VARL("src_fp"), result_format);
	} else {
		result = fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80);
	}
	seq = seq_append(seq, SETL("res_fp", result));
	seq = fpu_write_float_local(ctx, dst, bits, "res_fp", seq);
	if (!seq) {
		return fpu_write_failure_label(ctx, dst);
	}
	return seq_append(seq, set_fpsr_cc_from_float_local("res_fp"));
}

static RzILOpEffect *lift_fpu_unary_data(M68KILCtx *ctx, ut32 insn_id) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_unary_dst_op(ctx->insn, src, &hidden_dst);
	if (!rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}

	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", src, bits, &seq)) {
		return m68k_effect_free(seq, fpu_read_failure_label(ctx, src));
	}
	seq = seq_append(seq, SETL("round_mode", fpu_fpcr_round_mode()));
	RzILOpFloat *result = NULL;
	switch (insn_id) {
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
		result = FABS(VARL("src_fp"));
		break;
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
		result = FNEG(VARL("src_fp"));
		break;
	case M68K_INS_FSQRT:
	case M68K_INS_FSSQRT:
	case M68K_INS_FDSQRT:
		result = FPU_EXEC_WITH_RMODE(FSQRT, VARL("src_fp"));
		break;
	case M68K_INS_FINT:
		result = FPU_EXEC_WITH_RMODE(FROUND, VARL("src_fp"));
		break;
	case M68K_INS_FINTRZ:
		result = FROUND(RZ_FLOAT_RMODE_RTZ, VARL("src_fp"));
		break;
	default:
		return m68k_effect_free(seq, m68k_label("m68k_unimplemented"));
	}

	switch (insn_id) {
	case M68K_INS_FABS:
	case M68K_INS_FNEG:
	case M68K_INS_FSQRT:
		seq = seq_append(seq, SETL("precision", fpu_fpcr_precision()));
		result = fpu_result_with_fpcr_precision(result);
		break;
	case M68K_INS_FSABS:
	case M68K_INS_FSNEG:
	case M68K_INS_FSSQRT:
		result = fpu_result_to_fp80_with_fpcr_rmode(result, RZ_FLOAT_IEEE754_BIN_32);
		break;
	case M68K_INS_FDABS:
	case M68K_INS_FDNEG:
	case M68K_INS_FDSQRT:
		result = fpu_result_to_fp80_with_fpcr_rmode(result, RZ_FLOAT_IEEE754_BIN_64);
		break;
	default:
		result = fpu_to_format(result, RZ_FLOAT_IEEE754_BIN_80);
		break;
	}
	seq = seq_append(seq, SETL("res_fp", result));
	seq = seq_append(seq, write_reg_sized(ctx, dst->reg, 80, F2BV(VARL("res_fp"))));
	return seq_append(seq, set_fpsr_cc_from_float_local("res_fp"));
}

static RzILOpEffect *lift_fpu_extract_data(M68KILCtx *ctx, ut32 insn_id) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (!rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}

	const cs_m68k_op *src = &ctx->m68k->operands[0];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", src, bits, &seq)) {
		return m68k_effect_free(seq, fpu_read_failure_label(ctx, src));
	}

	seq = seq_append(seq, SETL("src_bits", F2BV(fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80))));
	seq = seq_append(seq, SETL("src_sign", LOGAND(cast_unsigned(16, SHIFTR0(VARL("src_bits"), U8(64))), U16(0x8000))));
	seq = seq_append(seq, SETL("src_zero_bits", APPEND(VARL("src_sign"), U64(0))));
	if (insn_id == M68K_INS_FGETEXP) {
		RzILOpPure *exp = cast_unsigned(32, LOGAND(cast_unsigned(16, SHIFTR0(VARL("src_bits"), U8(64))), U16(0x7fff)));
		seq = seq_append(seq, SETL("src_exp", SUB(exp, U32(0x3fff))));
		RzILOpFloat *finite_res = SINT2F(RZ_FLOAT_IEEE754_BIN_80, RZ_FLOAT_RMODE_RNE, VARL("src_exp"));
		RzILOpFloat *res = ITE(IS_FNAN(VARL("src_fp")),
			fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80),
			ITE(IS_FINF(VARL("src_fp")),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80),
				ITE(IS_FZERO(VARL("src_fp")),
					BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("src_zero_bits")),
					finite_res)));
		seq = seq_append(seq, SETL("res_fp", res));
	} else if (insn_id == M68K_INS_FGETMAN) {
		RzILOpPure *sign_exp = LOGOR(
			VARL("src_sign"),
			U16(0x3fff));
		seq = seq_append(seq, SETL("finite_res_bits", APPEND(sign_exp, cast_unsigned(64, VARL("src_bits")))));
		RzILOpFloat *finite_res = BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("finite_res_bits"));
		RzILOpFloat *res = ITE(IS_FNAN(VARL("src_fp")),
			fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80),
			ITE(IS_FINF(VARL("src_fp")),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80),
				ITE(IS_FZERO(VARL("src_fp")),
					BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("src_zero_bits")),
					finite_res)));
		seq = seq_append(seq, SETL("res_fp", res));
	} else {
		return m68k_effect_free(seq, m68k_label("m68k_unimplemented"));
	}

	seq = seq_append(seq, write_reg_sized(ctx, dst->reg, 80, F2BV(VARL("res_fp"))));
	return seq_append(seq, set_fpsr_cc_from_float_local("res_fp"));
}

static RzILOpEffect *lift_fpu_binary_data(M68KILCtx *ctx, ut32 insn_id) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (!rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", src, bits, &seq)) {
		return m68k_effect_free(seq, fpu_read_failure_label(ctx, src));
	}
	if (!fpu_operand_to_float_local(ctx, "dst_fp", dst, 80, &seq)) {
		return m68k_effect_free(seq, fpu_read_failure_label(ctx, dst));
	}
	seq = seq_append(seq, SETL("round_mode", fpu_fpcr_round_mode()));
	if (fpu_binary_uses_fpcr_precision(insn_id)) {
		seq = seq_append(seq, SETL("precision", fpu_fpcr_precision()));
	}
	RzILOpFloat *result = fpu_binary_result(ctx, insn_id);
	if (!result) {
		return m68k_effect_free(seq, m68k_label("m68k_unimplemented"));
	}

	seq = seq_append(seq, SETL("res_fp", result));
	seq = seq_append(seq, write_reg_sized(ctx, dst->reg, 80, F2BV(VARL("res_fp"))));
	return seq_append(seq, set_fpsr_cc_from_float_local("res_fp"));
}

static RzILOpEffect *lift_fpu_data_alias(M68KILCtx *ctx) {
	if (!rz_m68k_insn_uses_fpu_operand(ctx->m68k) || !rz_m68k_fpu_insn_data_alias_has_dst(ctx->insn)) {
		return NULL;
	}

	switch (ctx->insn->id) {
	case M68K_INS_ADD:
		return lift_fpu_binary_data(ctx, M68K_INS_FADD);
	default:
		return NULL;
	}
}

static RzILOpEffect *lift_fpu_compare_data(M68KILCtx *ctx, bool test_zero) {
	if (ctx->m68k->op_count < 1) {
		return m68k_invalid();
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", &ctx->m68k->operands[0], bits, &seq)) {
		return m68k_effect_free(seq, fpu_read_failure_label(ctx, &ctx->m68k->operands[0]));
	}
	if (test_zero) {
		seq = seq_append(seq, SETL("zero_fp", F80(0.0L)));
		return seq_append(seq, set_fpsr_cc_from_float_cmp("src_fp", "zero_fp"));
	}
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (!rz_m68k_op_is_fpu_reg(dst)) {
		return m68k_effect_free(seq, fpu_write_failure_label(ctx, dst));
	}
	if (!fpu_operand_to_float_local(ctx, "dst_fp", dst, 80, &seq)) {
		return m68k_effect_free(seq, fpu_read_failure_label(ctx, dst));
	}
	return seq_append(seq, set_fpsr_cc_from_float_cmp("dst_fp", "src_fp"));
}

static RzILOpEffect *lift_fpu_data(M68KILCtx *ctx) {
	switch (ctx->insn->id) {
	case M68K_INS_FMOVECR:
		return lift_fmovecr(ctx);
	case M68K_INS_FMOVEM:
		return lift_fmovem_data(ctx);
	case M68K_INS_FMOVE:
	case M68K_INS_FSMOVE:
	case M68K_INS_FDMOVE:
		return lift_fpu_move_data(ctx, ctx->insn->id);
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
	case M68K_INS_FSQRT:
	case M68K_INS_FSSQRT:
	case M68K_INS_FDSQRT:
	case M68K_INS_FINT:
	case M68K_INS_FINTRZ:
		return lift_fpu_unary_data(ctx, ctx->insn->id);
	case M68K_INS_FETOX:
	case M68K_INS_FETOXM1:
	case M68K_INS_FTWOTOX:
	case M68K_INS_FTENTOX:
	case M68K_INS_FSIN:
	case M68K_INS_FCOS:
	case M68K_INS_FTAN:
	case M68K_INS_FASIN:
	case M68K_INS_FACOS:
	case M68K_INS_FATAN:
	case M68K_INS_FATANH:
	case M68K_INS_FLOGN:
	case M68K_INS_FLOGNP1:
	case M68K_INS_FLOG2:
	case M68K_INS_FLOG10:
	case M68K_INS_FSINH:
	case M68K_INS_FCOSH:
	case M68K_INS_FTANH:
		return NULL;
	case M68K_INS_FGETEXP:
	case M68K_INS_FGETMAN:
		return lift_fpu_extract_data(ctx, ctx->insn->id);
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FSGLMUL:
	case M68K_INS_FSGLDIV:
	case M68K_INS_FMOD:
	case M68K_INS_FREM:
		return lift_fpu_binary_data(ctx, ctx->insn->id);
	case M68K_INS_FSCALE:
		return NULL;
	case M68K_INS_FCMP:
		return lift_fpu_compare_data(ctx, false);
	case M68K_INS_FTST:
		return lift_fpu_compare_data(ctx, true);
	default:
		return NULL;
	}
}

static RzILOpEffect *lift_fpu_unmodeled_address_effects(M68KILCtx *ctx) {
	ut32 bits = fpu_external_bits(ctx, rz_m68k_detail_op_bits(ctx->m68k, 80));
	RzILOpEffect *seq = NULL;
	bool has_mem = false;
	for (ut8 i = 0; i < ctx->m68k->op_count; i++) {
		const cs_m68k_op *op = &ctx->m68k->operands[i];
		if (!rz_m68k_op_is_mem_addr(op)) {
			continue;
		}
		if (op->type == M68K_OP_MEM && op->address_mode == M68K_AM_NONE) {
			continue;
		}
		M68KEA ea = effective_addr(ctx, op, bits);
		if (!ea.addr) {
			return m68k_invalid();
		}
		seq = seq_append(seq, ea.pre);
		seq = seq_append(seq, SETL("fpu_addr", cast_unsigned(M68K_ADDR_BITS, ea.addr)));
		seq = seq_append(seq, ea.post);
		has_mem = true;
	}
	return has_mem ? seq_append(seq, m68k_label("m68k_fpu")) : m68k_label("m68k_fpu");
}

static RzILOpEffect *lift_trapv(M68KILCtx *ctx) {
	return BRANCH(ccr_bit(M68K_CCR_V), explicit_trap_effect(ctx, M68K_TRAP_OP_TRAPV, false), EMPTY());
}

RZ_IPI RzILOpEffect *rz_m68k_cs_get_il_op(csh handle, cs_mode mode, RZ_NONNULL const cs_insn *insn, ut64 addr) {
	rz_return_val_if_fail(insn && insn->detail, NULL);
	M68KILCtx ctx = {
		.handle = handle,
		.mode = mode,
		.insn = insn,
		.m68k = &insn->detail->m68k,
		.addr = addr,
		.next_addr = addr + insn->size,
	};

	RzILOpEffect *fpu_data = lift_fpu_data(&ctx);
	if (fpu_data) {
		return fpu_data;
	}

	RzILOpEffect *fpu_alias = lift_fpu_data_alias(&ctx);
	if (fpu_alias) {
		return fpu_alias;
	}

	if (rz_m68k_insn_uses_fpu_operand(ctx.m68k)) {
		return lift_fpu_unmodeled_address_effects(&ctx);
	}

	RzILOpBool *fpu_cond = fpu_cond_code(insn->id);
	if (fpu_cond) {
		return lift_fpu_conditional(&ctx, fpu_cond);
	}

	switch (insn->id) {
	case M68K_INS_INVALID:
		return m68k_invalid();
	case M68K_INS_NOP:
		return NOP();
	case M68K_INS_HALT:
		return lift_privileged_system(M68K_SYSTEM_OP_HALT);
	case M68K_INS_MOVE:
		return lift_move(&ctx, false);
	case M68K_INS_MOVEC:
		return lift_movec(&ctx);
	case M68K_INS_MOVES:
		return lift_moves(&ctx);
	case M68K_INS_MOVEP:
		return lift_movep(&ctx);
	case M68K_INS_MOVEM:
		return lift_movem(&ctx);
	case M68K_INS_MOVE16:
		return lift_move16(&ctx);
	case M68K_INS_MOVEA:
		return lift_move(&ctx, true);
	case M68K_INS_MOVEQ:
		return lift_moveq(&ctx);
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_INS_MOV3Q:
		return lift_mov3q(&ctx);
	case M68K_INS_MOVCLR:
		return lift_movclr(&ctx);
	case M68K_INS_MVS:
		return lift_mvs_mvz(&ctx, true);
	case M68K_INS_MVZ:
		return lift_mvs_mvz(&ctx, false);
	case M68K_INS_BITREV:
	case M68K_INS_BYTEREV:
	case M68K_INS_FF1:
		return lift_coldfire_bitop_reg(&ctx);
	case M68K_INS_REMS:
		return lift_rem(&ctx, true);
	case M68K_INS_REMU:
		return lift_rem(&ctx, false);
	case M68K_INS_SATS:
		return lift_sats(&ctx);
	case M68K_INS_MAAAC:
		return lift_mac_dual_acc(&ctx, false, false);
	case M68K_INS_MAC:
		return lift_mac_msac(&ctx, false);
	case M68K_INS_MASAC:
		return lift_mac_dual_acc(&ctx, false, true);
	case M68K_INS_MSAAC:
		return lift_mac_dual_acc(&ctx, true, false);
	case M68K_INS_MSAC:
		return lift_mac_msac(&ctx, true);
	case M68K_INS_MSSAC:
		return lift_mac_dual_acc(&ctx, true, true);
#endif
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	case M68K_INS_BGND:
		return explicit_trap_effect(&ctx, M68K_TRAP_OP_BGND, false);
#endif
	case M68K_INS_PULSE:
		return lift_privileged_system(M68K_SYSTEM_OP_PULSE);
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_INS_TPF:
		return NOP();
	case M68K_INS_CP0NOP:
	case M68K_INS_CP1NOP:
		return lift_coprocessor_nop(&ctx);
	case M68K_INS_INTOUCH:
		return lift_cache_address_effects(&ctx);
	case M68K_INS_STRLDSR:
		return lift_strldsr(&ctx);
	case M68K_INS_WDDATA:
		return lift_coldfire_debug_transfer(&ctx, rz_m68k_detail_op_bits(ctx.m68k, 32));
	case M68K_INS_WDEBUG:
		return lift_coldfire_debug_transfer(&ctx, 32);
	case M68K_INS_CP0BCBUSY:
	case M68K_INS_CP1BCBUSY:
		return lift_coprocessor_branch(&ctx);
	case M68K_INS_CP0LD:
	case M68K_INS_CP1LD:
	case M68K_INS_CP0ST:
	case M68K_INS_CP1ST:
		return lift_coprocessor_transfer(&ctx);
#endif
	case M68K_INS_LEA:
		return lift_lea(&ctx);
	case M68K_INS_PEA:
		return lift_pea(&ctx);
	case M68K_INS_ADD:
	case M68K_INS_ADDI:
		return lift_binop(&ctx, M68K_BIN_ADD, false, false);
	case M68K_INS_ADDQ:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_addr_reg(&ctx.m68k->operands[1])
			? lift_binop(&ctx, M68K_BIN_ADD, true, false)
			: lift_binop(&ctx, M68K_BIN_ADD, false, false);
	case M68K_INS_ADDX:
		return lift_addx_subx(&ctx, false);
	case M68K_INS_ABCD:
		return lift_abcd_sbcd(&ctx, false);
	case M68K_INS_PACK:
		return lift_pack_unpk(&ctx, false);
	case M68K_INS_ADDA:
		return lift_binop(&ctx, M68K_BIN_ADD, true, false);
	case M68K_INS_SUB:
	case M68K_INS_SUBI:
		return lift_binop(&ctx, M68K_BIN_SUB, false, false);
	case M68K_INS_SUBQ:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_addr_reg(&ctx.m68k->operands[1])
			? lift_binop(&ctx, M68K_BIN_SUB, true, false)
			: lift_binop(&ctx, M68K_BIN_SUB, false, false);
	case M68K_INS_SUBX:
		return lift_addx_subx(&ctx, true);
	case M68K_INS_SBCD:
		return lift_abcd_sbcd(&ctx, true);
	case M68K_INS_UNPK:
		return lift_pack_unpk(&ctx, true);
	case M68K_INS_SUBA:
		return lift_binop(&ctx, M68K_BIN_SUB, true, false);
	case M68K_INS_CMP:
	case M68K_INS_CMPI:
	case M68K_INS_CMPM:
		return lift_binop(&ctx, M68K_BIN_SUB, false, true);
	case M68K_INS_CMPA:
		return lift_binop(&ctx, M68K_BIN_SUB, true, true);
	case M68K_INS_CMP2:
		return lift_cmp2_chk2(&ctx, false);
	case M68K_INS_AND:
		return lift_binop(&ctx, M68K_BIN_AND, false, false);
	case M68K_INS_ANDI:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_status_reg(&ctx.m68k->operands[1])
			? lift_status_binop(&ctx, M68K_BIN_AND)
			: lift_binop(&ctx, M68K_BIN_AND, false, false);
	case M68K_INS_OR:
		return lift_binop(&ctx, M68K_BIN_OR, false, false);
	case M68K_INS_ORI:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_status_reg(&ctx.m68k->operands[1])
			? lift_status_binop(&ctx, M68K_BIN_OR)
			: lift_binop(&ctx, M68K_BIN_OR, false, false);
	case M68K_INS_EOR:
		return lift_binop(&ctx, M68K_BIN_XOR, false, false);
	case M68K_INS_EORI:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_status_reg(&ctx.m68k->operands[1])
			? lift_status_binop(&ctx, M68K_BIN_XOR)
			: lift_binop(&ctx, M68K_BIN_XOR, false, false);
	case M68K_INS_CLR:
		return lift_clr(&ctx);
	case M68K_INS_TST:
		return lift_tst(&ctx);
	case M68K_INS_NOT:
		return lift_not(&ctx);
	case M68K_INS_NEG:
		return lift_neg(&ctx, false);
	case M68K_INS_NEGX:
		return lift_neg(&ctx, true);
	case M68K_INS_NBCD:
		return lift_nbcd(&ctx);
	case M68K_INS_EXT:
	case M68K_INS_EXTB:
		return lift_ext(&ctx);
	case M68K_INS_TAS:
		return lift_tas(&ctx);
	case M68K_INS_SWAP:
		return lift_swap(&ctx);
	case M68K_INS_EXG:
		return lift_exg(&ctx);
	case M68K_INS_MULS:
		return lift_mul(&ctx, true);
	case M68K_INS_MULU:
		return lift_mul(&ctx, false);
	case M68K_INS_DIVS:
	case M68K_INS_DIVSL:
		return lift_div(&ctx, true);
	case M68K_INS_DIVU:
	case M68K_INS_DIVUL:
		return lift_div(&ctx, false);
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	case M68K_INS_TBLS:
	case M68K_INS_TBLU:
	case M68K_INS_TBLSN:
	case M68K_INS_TBLUN:
		return lift_tbl(&ctx);
#endif
	case M68K_INS_LSL:
		return lift_shift(&ctx, true, false);
	case M68K_INS_ASL:
		return lift_shift(&ctx, true, true);
	case M68K_INS_ASR:
		return lift_shift(&ctx, false, true);
	case M68K_INS_LSR:
		return lift_shift(&ctx, false, false);
	case M68K_INS_ROL:
		return lift_rotate(&ctx, true, false);
	case M68K_INS_ROR:
		return lift_rotate(&ctx, false, false);
	case M68K_INS_ROXL:
		return lift_rotate(&ctx, true, true);
	case M68K_INS_ROXR:
		return lift_rotate(&ctx, false, true);
	case M68K_INS_BRA:
		return lift_branch(&ctx, true, false);
	case M68K_INS_BSR:
		return lift_branch(&ctx, true, true);
	case M68K_INS_CALLM:
		return lift_callm_address_effects(&ctx);
	case M68K_INS_BHI:
	case M68K_INS_BLS:
	case M68K_INS_BCC:
	case M68K_INS_BHS:
	case M68K_INS_BCS:
	case M68K_INS_BLO:
	case M68K_INS_BNE:
	case M68K_INS_BEQ:
	case M68K_INS_BVC:
	case M68K_INS_BVS:
	case M68K_INS_BPL:
	case M68K_INS_BMI:
	case M68K_INS_BGE:
	case M68K_INS_BLT:
	case M68K_INS_BGT:
	case M68K_INS_BLE:
		return lift_branch(&ctx, false, false);
	case M68K_INS_JMP:
		return lift_jmp_jsr(&ctx, false);
	case M68K_INS_JSR:
		return lift_jmp_jsr(&ctx, true);
	case M68K_INS_RTS:
		return lift_rts(&ctx);
	case M68K_INS_LINK:
		return lift_link(&ctx);
	case M68K_INS_UNLK:
		return lift_unlk(&ctx);
	case M68K_INS_CINVA:
	case M68K_INS_CINVL:
	case M68K_INS_CINVP:
	case M68K_INS_CPUSHA:
	case M68K_INS_CPUSHL:
	case M68K_INS_CPUSHP:
		return guard_supervisor(lift_cache_address_effects(&ctx));
	case M68K_INS_PFLUSHA:
	case M68K_INS_PFLUSHAN:
		return guard_supervisor(lift_mmu_flush_all(&ctx));
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHN:
	case M68K_INS_PLOADR:
	case M68K_INS_PLOADW:
	case M68K_INS_PLPAR:
	case M68K_INS_PLPAW:
		return guard_supervisor(lift_mmu_address_effects(&ctx, 32, true));
	case M68K_INS_PMOVE:
	case M68K_INS_PMOVEFD:
		return guard_supervisor(lift_pmove(&ctx));
	case M68K_INS_PTESTR:
	case M68K_INS_PTESTW:
		return guard_supervisor(lift_mmu_address_effects(&ctx, 32, true));
	case M68K_INS_FSAVE:
	case M68K_INS_FRESTORE:
		return lift_fpu_state_address_effects(&ctx);
	case M68K_INS_FNOP:
		return NOP();
	case M68K_INS_FMOVE: {
		RzILOpEffect *effect = lift_fmove_control(&ctx);
		return effect ? effect : m68k_label("m68k_fpu");
	}
	case M68K_INS_ST:
	case M68K_INS_SF:
	case M68K_INS_SHI:
	case M68K_INS_SLS:
	case M68K_INS_SCC:
	case M68K_INS_SHS:
	case M68K_INS_SCS:
	case M68K_INS_SLO:
	case M68K_INS_SNE:
	case M68K_INS_SEQ:
	case M68K_INS_SVC:
	case M68K_INS_SVS:
	case M68K_INS_SPL:
	case M68K_INS_SMI:
	case M68K_INS_SGE:
	case M68K_INS_SLT:
	case M68K_INS_SGT:
	case M68K_INS_SLE:
		return lift_scc(&ctx);
	case M68K_INS_DBT:
	case M68K_INS_DBF:
	case M68K_INS_DBRA:
	case M68K_INS_DBHI:
	case M68K_INS_DBLS:
	case M68K_INS_DBCC:
	case M68K_INS_DBCS:
	case M68K_INS_DBNE:
	case M68K_INS_DBEQ:
	case M68K_INS_DBVC:
	case M68K_INS_DBVS:
	case M68K_INS_DBPL:
	case M68K_INS_DBMI:
	case M68K_INS_DBGE:
	case M68K_INS_DBLT:
	case M68K_INS_DBGT:
	case M68K_INS_DBLE:
		return lift_dbcc(&ctx);
	case M68K_INS_CHK:
		return lift_chk(&ctx);
	case M68K_INS_CHK2:
		return lift_cmp2_chk2(&ctx, true);
	case M68K_INS_CAS:
		return lift_cas(&ctx);
	case M68K_INS_CAS2:
		return lift_cas2(&ctx);
	case M68K_INS_BTST:
	case M68K_INS_BSET:
	case M68K_INS_BCLR:
	case M68K_INS_BCHG:
		return lift_bitop(&ctx, insn->id);
	case M68K_INS_BFCHG:
	case M68K_INS_BFCLR:
	case M68K_INS_BFEXTS:
	case M68K_INS_BFEXTU:
	case M68K_INS_BFFFO:
	case M68K_INS_BFINS:
	case M68K_INS_BFSET:
	case M68K_INS_BFTST:
		return lift_bitfield(&ctx, insn->id);
	case M68K_INS_TRAPT:
	case M68K_INS_TRAPF:
	case M68K_INS_TRAPHI:
	case M68K_INS_TRAPLS:
	case M68K_INS_TRAPCC:
	case M68K_INS_TRAPHS:
	case M68K_INS_TRAPCS:
	case M68K_INS_TRAPLO:
	case M68K_INS_TRAPNE:
	case M68K_INS_TRAPEQ:
	case M68K_INS_TRAPVC:
	case M68K_INS_TRAPVS:
	case M68K_INS_TRAPPL:
	case M68K_INS_TRAPMI:
	case M68K_INS_TRAPGE:
	case M68K_INS_TRAPLT:
	case M68K_INS_TRAPGT:
	case M68K_INS_TRAPLE:
		return lift_trapcc(&ctx);
	case M68K_INS_BKPT:
	case M68K_INS_TRAP:
		return lift_trap_vector(&ctx);
	case M68K_INS_TRAPV:
		return lift_trapv(&ctx);
	case M68K_INS_ILLEGAL:
		return m68k_label("m68k_illegal");
	case M68K_INS_RTR:
		return lift_rtr(&ctx);
	case M68K_INS_RTD:
		return lift_rtd(&ctx);
	case M68K_INS_RTE:
		return lift_rte(&ctx);
	case M68K_INS_RTM:
		return lift_rtm(&ctx);
	case M68K_INS_LPSTOP:
	case M68K_INS_STOP:
		return lift_stop(&ctx);
	case M68K_INS_RESET:
		return lift_privileged_system(M68K_SYSTEM_OP_RESET);
	default:
		if (insn->id >= M68K_INS_FABS && insn->id <= M68K_INS_FTWOTOX) {
			return lift_fpu_unmodeled_address_effects(&ctx);
		}
		return m68k_label("m68k_unimplemented");
	}
}

static void label_ignore(RzILVM *vm, RzILOpEffect *op) {
	(void)vm;
	(void)op;
}

static const char *m68k_il_regs[] = {
	"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
	"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
	// PC is synchronized through the VM program counter, not a global variable.
	"sr", "sfc", "dfc", "vbr", "cacr", "caar",
	"usp", "msp", "isp", "tc", "itt0", "itt1", "dtt0", "dtt1", "mmusr", "urp", "srp",
	"tt0", "tt1", "crp",
	"fp0", "fp1", "fp2", "fp3", "fp4", "fp5", "fp6", "fp7", "fpcr", "fpsr", "fpiar",
	"acc", "acc0", "acc1", "acc2", "acc3", "accext01", "accext23", "macsr", "mask",
	"cp_external_data",
	NULL
};

RZ_IPI RzAnalysisILConfig *rz_m68k_cs_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, true, 32);
	if (!cfg) {
		return NULL;
	}
	cfg->reg_bindings = m68k_il_regs;
	const char *labels[] = {
		"m68k_unimplemented",
		"m68k_trap",
		"m68k_illegal",
		"m68k_privilege",
		"m68k_chk",
		"m68k_fpu",
		"m68k_mmu",
		"m68k_cache",
		"m68k_debug",
		"m68k_coprocessor",
		"m68k_callm",
		"m68k_rtm",
		"m68k_system",
		NULL
	};
	for (size_t i = 0; labels[i]; i++) {
		RzILEffectLabel *label = rz_il_effect_label_new(labels[i], EFFECT_LABEL_SYSCALL);
		if (!label) {
			rz_analysis_il_config_free(cfg);
			return NULL;
		}
		label->hook = label_ignore;
		rz_analysis_il_config_add_label(cfg, label);
	}
	cfg->init_state = rz_analysis_il_init_state_new();
	if (!cfg->init_state) {
		rz_analysis_il_config_free(cfg);
		return NULL;
	}
	rz_analysis_il_init_state_set_var(cfg->init_state, "sr", rz_il_value_new_bitv(rz_bv_new_from_ut64(16, 0)));
	rz_analysis_il_init_state_set_var(cfg->init_state, "cp_external_data", rz_il_value_new_bitv(rz_bv_new_from_ut64(32, 0)));
	const char *fp_regs[] = {
		"fp0", "fp1", "fp2", "fp3", "fp4", "fp5", "fp6", "fp7", NULL
	};
	for (size_t i = 0; fp_regs[i]; i++) {
		rz_analysis_il_init_state_set_var(cfg->init_state, fp_regs[i], rz_il_value_new_bitv(rz_bv_new_from_ut64(80, 0)));
	}
	return cfg;
}

#include <rz_il/rz_il_opbuilder_end.h>

#endif // CAPSTONE_M68K_H
