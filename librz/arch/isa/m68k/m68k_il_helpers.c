// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "m68k/m68k_il_helpers.h"

#include <rz_il/rz_il_opbuilder_begin.h>
#include <rz_util/rz_assert.h>

RZ_IPI RzILOpPure *cast_unsigned(ut32 bits, RzILOpPure *v) {
	return CAST(bits, IL_FALSE, v);
}

RZ_IPI RzILOpPure *cast_signed(ut32 bits, RzILOpPure *v) {
	return CAST(bits, MSB(DUP(v)), v);
}

RZ_IPI RzILOpPure *extend_to_32(RzILOpPure *v, bool sign_extend) {
	return sign_extend ? cast_signed(32, v) : cast_unsigned(32, v);
}

static RzILOpPure *addr_add(RzILOpPure *base, RzILOpPure *delta) {
	return ADD(cast_unsigned(32, base), cast_unsigned(32, delta));
}

RZ_IPI RzILOpPure *reg_value(M68KILCtx *ctx, m68k_reg reg) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		return NULL;
	}
	return VARG(name);
}

RZ_IPI RzILOpPure *read_reg_sized(M68KILCtx *ctx, m68k_reg reg, ut32 bits) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		return NULL;
	}
	switch (reg) {
	case M68K_REG_A0:
	case M68K_REG_A1:
	case M68K_REG_A2:
	case M68K_REG_A3:
	case M68K_REG_A4:
	case M68K_REG_A5:
	case M68K_REG_A6:
	case M68K_REG_A7:
	case M68K_REG_PC:
	case M68K_REG_USP:
	case M68K_REG_MSP:
	case M68K_REG_ISP:
		return bits == 32 ? VARG(name) : cast_unsigned(bits, VARG(name));
	case M68K_REG_CCR:
		return cast_unsigned(bits, VARG("sr"));
	case M68K_REG_SR:
		return bits == 16 ? VARG(name) : cast_unsigned(bits, VARG(name));
	case M68K_REG_FP0:
	case M68K_REG_FP1:
	case M68K_REG_FP2:
	case M68K_REG_FP3:
	case M68K_REG_FP4:
	case M68K_REG_FP5:
	case M68K_REG_FP6:
	case M68K_REG_FP7:
		return bits == 80 ? VARG(name) : cast_unsigned(bits, VARG(name));
	default:
		break;
	}
	if (rz_m68k_reg_name_is_mmu_root_pointer(name)) {
		return bits == 64 ? VARG(name) : cast_unsigned(bits, VARG(name));
	}
	return bits == 32 ? VARG(name) : cast_unsigned(bits, VARG(name));
}

RZ_IPI RzILOpEffect *seq_append(RzILOpEffect *a, RzILOpEffect *b) {
	if (!a) {
		return b;
	}
	if (!b) {
		return a;
	}
	RzILOpEffect *seq = SEQ2(a, b);
	if (!seq) {
		rz_il_op_effect_free(a);
		rz_il_op_effect_free(b);
	}
	return seq;
}

RZ_IPI RzILOpEffect *set_ccr_from_value(RzILOpPure *new_ccr) {
	RzILOpPure *ccr8 = cast_unsigned(8, new_ccr);
	return SETG("sr", LOGOR(LOGAND(VARG("sr"), U16(0xff00)), cast_unsigned(16, ccr8)));
}

RZ_IPI RzILOpBool *ccr_bit(ut32 bit) {
	rz_return_val_if_fail(bit < 8, NULL);
	return NON_ZERO(LOGAND(cast_unsigned(8, VARG("sr")), U8(1u << bit)));
}

RZ_IPI RzILOpBool *fpsr_bit(ut32 bit) {
	rz_return_val_if_fail(bit < 32, NULL);
	return NON_ZERO(LOGAND(cast_unsigned(32, VARG("fpsr")), U32(1u << bit)));
}

RZ_IPI RzILOpEffect *set_fpsr_cc(RzILOpBool *n, RzILOpBool *z, RzILOpBool *i, RzILOpBool *nan) {
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

RZ_IPI RzILOpBool *supervisor_mode(void) {
	return sr_bit(M68K_SR_S);
}

RZ_IPI RzILOpPure *ccr_with_flag(RzILOpPure *ccr, ut32 bit, RzILOpBool *value) {
	RzILOpPure *cleared = LOGAND(ccr, U8((ut8) ~(1u << bit)));
	RzILOpPure *flag = SHIFTL0(BOOL_TO_BV(value, 8), U8(bit));
	return LOGOR(cleared, flag);
}

RZ_IPI RzILOpEffect *set_flags_nzvcx(RzILOpPure *value, ut32 bits, RzILOpBool *v, RzILOpBool *c, RzILOpBool *x) {
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

RZ_IPI RzILOpEffect *set_flags_nzvcx_extend(RzILOpPure *value, ut32 bits, RzILOpBool *v, RzILOpBool *c) {
	RzILOpPure *val = cast_unsigned(bits, value);
	RzILOpPure *ccr = LOGAND(cast_unsigned(8, VARG("sr")), U8(0xe0));
	ccr = ccr_with_flag(ccr, M68K_CCR_N, MSB(DUP(val)));
	ccr = ccr_with_flag(ccr, M68K_CCR_Z, AND(ccr_bit(M68K_CCR_Z), IS_ZERO(val)));
	ccr = ccr_with_flag(ccr, M68K_CCR_V, v);
	ccr = ccr_with_flag(ccr, M68K_CCR_C, c);
	ccr = ccr_with_flag(ccr, M68K_CCR_X, (RzILOpBool *)DUP(c));
	return set_ccr_from_value(ccr);
}

RZ_IPI RzILOpEffect *set_flags_div(RzILOpPure *quotient, ut32 bits, RzILOpBool *overflow) {
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

RZ_IPI RzILOpBool *m68k_add_overflow(RzILOpPure *a, RzILOpPure *b, RzILOpPure *r) {
	RzILOpBool *same_sign = EQ(BOOL_TO_BV(MSB(DUP(a)), 1), BOOL_TO_BV(MSB(b), 1));
	RzILOpBool *diff_result = NE(BOOL_TO_BV(MSB(a), 1), BOOL_TO_BV(MSB(r), 1));
	return AND(same_sign, diff_result);
}

RZ_IPI RzILOpBool *m68k_sub_overflow(RzILOpPure *a, RzILOpPure *b, RzILOpPure *r) {
	RzILOpBool *diff_sign = NE(BOOL_TO_BV(MSB(DUP(a)), 1), BOOL_TO_BV(MSB(b), 1));
	RzILOpBool *diff_result = NE(BOOL_TO_BV(MSB(a), 1), BOOL_TO_BV(MSB(r), 1));
	return AND(diff_sign, diff_result);
}

RZ_IPI RzILOpBool *signed_out_of_range(RzILOpPure *value, ut32 bits) {
	st64 min = -(1LL << (bits - 1));
	st64 max = (1LL << (bits - 1)) - 1;
	return OR(SLT(DUP(value), S64(min)), SGT(value, S64(max)));
}

RZ_IPI RzILOpBool *addx_overflow(ut32 bits) {
	RzILOpPure *sum = ADD(ADD(cast_signed(64, VARL("dst")), cast_signed(64, VARL("src"))), cast_unsigned(64, VARL("x")));
	return signed_out_of_range(sum, bits);
}

RZ_IPI RzILOpBool *subx_overflow(ut32 bits) {
	RzILOpPure *diff = SUB(SUB(cast_signed(64, VARL("dst")), cast_signed(64, VARL("src"))), cast_unsigned(64, VARL("x")));
	return signed_out_of_range(diff, bits);
}

RZ_IPI RzILOpBool *negx_overflow(ut32 bits) {
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

static inline bool m68k_mode_has_master_stack(cs_mode mode) {
	return mode == CS_MODE_M68K_020 || mode == CS_MODE_M68K_030 ||
		mode == CS_MODE_M68K_040 || mode == CS_MODE_M68K_060;
}

RZ_IPI RzILOpEffect *write_reg_sized(M68KILCtx *ctx, m68k_reg reg, ut32 bits, RzILOpPure *value) {
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
		bool has_master_stack = m68k_mode_has_master_stack(ctx->mode);
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

RZ_IPI bool m68k_mode_uses_later_movem_base_value(cs_mode mode) {
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

RZ_IPI bool m68k_mode_has_format_word(cs_mode mode) {
	return mode != CS_MODE_M68K_000;
}

RZ_IPI RzILOpBool *rte_format_valid(cs_mode mode) {
	switch (mode) {
	case CS_MODE_M68K_010:
		return OR(EQ(VARL("format"), U16(0)), EQ(VARL("format"), U16(8)));
	case CS_MODE_M68K_020:
	case CS_MODE_M68K_030:
		return OR(
			ULT(VARL("format"), U16(3)),
			AND(UGE(VARL("format"), U16(9)), ULT(VARL("format"), U16(12))));
	case CS_MODE_M68K_040:
		return OR(ULT(VARL("format"), U16(5)), EQ(VARL("format"), U16(7)));
	case CS_MODE_M68K_060:
		return AND(ULT(VARL("format"), U16(5)), NE(VARL("format"), U16(1)));
	default:
		break;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
	if (mode == CS_MODE_M68K_CPU32) {
		return OR(ULT(VARL("format"), U16(3)), EQ(VARL("format"), U16(12)));
	}
#endif
	return AND(
		ULT(VARL("format"), U16(12)),
		AND(NE(VARL("format"), U16(5)), NE(VARL("format"), U16(6))));
}

RZ_IPI RzILOpPure *rte_frame_size(cs_mode mode) {
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

RZ_IPI RzILOpPure *read_mem_sized(ut32 bits, RzILOpPure *addr) {
	return LOADW(bits, addr);
}

RZ_IPI RzILOpEffect *write_mem_sized(ut32 bits, RzILOpPure *addr, RzILOpPure *value) {
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
	rz_return_val_if_fail(ctx && ctx->insn && word, false);
	if (offset + 1 >= ctx->insn->size || offset + 1 >= sizeof(ctx->insn->bytes)) {
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
		switch (op->br_disp.disp_size) {
		case M68K_OP_BR_DISP_SIZE_BYTE:
			return 0;
		case M68K_OP_BR_DISP_SIZE_WORD:
			return 2;
		case M68K_OP_BR_DISP_SIZE_LONG:
			return 4;
		default:
			return 0;
		}
	case M68K_OP_INVALID:
	case M68K_OP_REG:
	case M68K_OP_REG_BITS:
	case M68K_OP_REG_PAIR:
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_OP_SHIFT:
#endif
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

RZ_IPI RzILOpPure *branch_disp_target(const M68KILCtx *ctx, const cs_m68k_op *op) {
	rz_return_val_if_fail(ctx && op, NULL);
	if (op->type != M68K_OP_BR_DISP) {
		return NULL;
	}
	return U32(branch_disp_base(ctx) + op->br_disp.disp);
}

RZ_IPI RzILOpEffect *set_addr_reg_delta(M68KILCtx *ctx, m68k_reg reg, st32 delta) {
	if (!rz_m68k_reg_is_areg(reg)) {
		return NULL;
	}
	RzILOpPure *base = reg_value(ctx, reg);
	RzILOpPure *res = delta >= 0 ? ADD(base, U32((ut32)delta)) : SUB(base, U32((ut32)-delta));
	return write_reg_sized(ctx, reg, 32, res);
}

RZ_IPI M68KEA effective_addr(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits) {
	M68KEA ea = { 0 };
	RzILOpPure *base = NULL;
	RzILOpPure *idx = NULL;
	m68k_reg base_reg = rz_m68k_op_base_reg(op);
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
		ea.addr = addr_add(reg_value(ctx, base_reg), S32((st32)op->mem.disp));
		break;
	case M68K_AM_AREGI_INDEX_8_BIT_DISP:
	case M68K_AM_AREGI_INDEX_BASE_DISP: {
		st64 disp = op->address_mode == M68K_AM_AREGI_INDEX_BASE_DISP ? op->mem.in_disp : op->mem.disp;
		base = base_reg != M68K_REG_INVALID ? reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(addr_add(base, S32((st32)disp)), idx);
		break;
	}
	case M68K_AM_MEMI_PRE_INDEX:
		base = base_reg != M68K_REG_INVALID ? reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(read_mem_sized(32, ADD(ADD(base, idx), S32((st32)op->mem.in_disp))), S32((st32)op->mem.out_disp));
		break;
	case M68K_AM_MEMI_POST_INDEX:
		base = base_reg != M68K_REG_INVALID ? reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(ADD(read_mem_sized(32, ADD(base, S32((st32)op->mem.in_disp))), idx), S32((st32)op->mem.out_disp));
		break;
	case M68K_AM_PCI_DISP:
		ea.addr = U32(pc_relative_base(ctx, op) + op->mem.disp);
		break;
	case M68K_AM_PCI_INDEX_8_BIT_DISP:
	case M68K_AM_PCI_INDEX_BASE_DISP: {
		st64 disp = op->address_mode == M68K_AM_PCI_INDEX_BASE_DISP ? op->mem.in_disp : op->mem.disp;
		idx = index_value(ctx, op);
		ea.addr = ADD(U32(pc_relative_base(ctx, op) + disp), idx);
		break;
	}
	case M68K_AM_PC_MEMI_PRE_INDEX:
		idx = index_value(ctx, op);
		ea.addr = ADD(read_mem_sized(32, ADD(ADD(U32(pc_relative_base(ctx, op)), idx), S32((st32)op->mem.in_disp))), S32((st32)op->mem.out_disp));
		break;
	case M68K_AM_PC_MEMI_POST_INDEX:
		idx = index_value(ctx, op);
		ea.addr = ADD(ADD(read_mem_sized(32, ADD(U32(pc_relative_base(ctx, op)), S32((st32)op->mem.in_disp))), idx), S32((st32)op->mem.out_disp));
		break;
	case M68K_AM_ABSOLUTE_DATA_SHORT:
		ea.addr = U32(rz_m68k_op_absolute_address(op, true));
		break;
	case M68K_AM_ABSOLUTE_DATA_LONG:
		ea.addr = U32(rz_m68k_op_absolute_address(op, false));
		break;
	default:
		if (rz_m68k_op_is_mem_addr(op) && base_reg != M68K_REG_INVALID) {
			ea.addr = ADD(reg_value(ctx, base_reg), S32((st32)op->mem.disp));
		} else if (rz_m68k_op_is_mem_addr(op)) {
			ea.addr = U32(rz_m68k_op_absolute_address(op, false));
		}
		break;
	}
	return ea;
}

RZ_IPI RzILOpPure *read_operand(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits, RzILOpEffect **pre, RzILOpEffect **post) {
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
		RzILOpPure *addr = ea.addr;
		ea.addr = NULL;
		if (pre) {
			*pre = ea.pre;
			ea.pre = NULL;
		}
		if (post) {
			*post = ea.post;
			ea.post = NULL;
		}
		m68k_ea_fini(&ea);
		return read_mem_sized(bits, addr);
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
	case M68K_OP_INVALID:
		return NULL;
	default:
		return NULL;
	}
}

RZ_IPI RzILOpEffect *write_operand(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits, RzILOpPure *value, RzILOpEffect **pre, RzILOpEffect **post) {
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
		RzILOpPure *addr = ea.addr;
		ea.addr = NULL;
		if (pre) {
			*pre = ea.pre;
			ea.pre = NULL;
		}
		if (post) {
			*post = ea.post;
			ea.post = NULL;
		}
		m68k_ea_fini(&ea);
		return write_mem_sized(bits, addr, value);
	}
	switch (op->type) {
	case M68K_OP_REG:
		return write_reg_sized(ctx, op->reg, bits, value);
	default:
		rz_il_op_pure_free(value);
		return NULL;
	}
}

RZ_IPI RzILOpEffect *m68k_label(const char *label) {
	if (RZ_STR_EQ(label, "m68k_illegal")) {
		RzILOpEffect *seq = SETL("trap_op", U32((ut32)M68K_TRAP_OP_ILLEGAL));
		seq = seq_append(seq, SETL("trap_vector", U32((ut32)M68K_VECTOR_ILLEGAL)));
		return seq_append(seq, GOTO(label));
	}
	if (RZ_STR_EQ(label, "m68k_privilege")) {
		RzILOpEffect *seq = SETL("trap_op", U32((ut32)M68K_TRAP_OP_PRIVILEGE));
		seq = seq_append(seq, SETL("trap_vector", U32((ut32)M68K_VECTOR_PRIVILEGE)));
		return seq_append(seq, GOTO(label));
	}
	return GOTO(label);
}

RZ_IPI RzILOpEffect *guard_supervisor(RzILOpEffect *effect) {
	return effect ? BRANCH(supervisor_mode(), effect, m68k_label("m68k_privilege")) : NULL;
}

RZ_IPI RzILOpEffect *m68k_invalid(void) {
	return NULL;
}

RZ_IPI RzILOpEffect *m68k_invalid_free(RzILOpEffect *seq) {
	rz_il_op_effect_free(seq);
	return NULL;
}

RZ_IPI bool rz_m68k_op_is_status_reg(const cs_m68k_op *op) {
	rz_return_val_if_fail(op, false);
	if (op->type != M68K_OP_REG) {
		return false;
	}
	return op->reg == M68K_REG_CCR || op->reg == M68K_REG_SR;
}

RZ_IPI RzILOpEffect *write_status_reg_unchecked(M68KILCtx *ctx, m68k_reg reg, RzILOpPure *value) {
	ut32 bits = reg == M68K_REG_CCR ? 8 : 16;
	return write_reg_sized(ctx, reg, bits, value);
}

RZ_IPI RzILOpEffect *write_status_reg(M68KILCtx *ctx, m68k_reg reg, RzILOpPure *value) {
	RzILOpEffect *write = write_status_reg_unchecked(ctx, reg, value);
	if (!write) {
		return NULL;
	}
	return reg == M68K_REG_SR ? BRANCH(supervisor_mode(), write, m68k_label("m68k_privilege")) : write;
}

RZ_IPI RzILOpEffect *m68k_null_free(RzILOpEffect *seq) {
	rz_il_op_effect_free(seq);
	return NULL;
}

RZ_IPI RzILOpEffect *m68k_effect_free(RzILOpEffect *seq, RzILOpEffect *effect) {
	rz_il_op_effect_free(seq);
	return effect;
}

RZ_IPI void m68k_ea_fini(M68KEA *ea) {
	if (!ea) {
		return;
	}
	rz_il_op_pure_free(ea->addr);
	rz_il_op_effect_free(ea->pre);
	rz_il_op_effect_free(ea->post);
	*ea = (M68KEA){ 0 };
}

RZ_IPI void m68k_rw_operand_fini(M68KRWOperand *rw) {
	if (!rw) {
		return;
	}
	rz_il_op_effect_free(rw->post);
	*rw = (M68KRWOperand){ 0 };
}

RZ_IPI void m68k_bitfield_target_fini(M68KBitfieldTarget *target) {
	if (!target) {
		return;
	}
	rz_il_op_effect_free(target->post);
	*target = (M68KBitfieldTarget){ 0 };
}

RZ_IPI RzILOpEffect *m68k_exception(M68KTrapOp trap_op, M68KExceptionVector vector, const char *label) {
	RzILOpEffect *seq = SETL("trap_op", U32((ut32)trap_op));
	seq = seq_append(seq, SETL("trap_vector", U32((ut32)vector)));
	return seq_append(seq, m68k_label(label));
}

RZ_IPI RzILOpEffect *operand_to_local(M68KILCtx *ctx, const char *name, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq) {
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

RZ_IPI bool rw_operand_to_local(M68KILCtx *ctx, M68KRWOperand *rw, const char *value_local, const char *addr_local, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq) {
	rz_return_val_if_fail(ctx && rw && value_local && addr_local && op && seq, false);
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
		RzILOpEffect *pre = ea.pre;
		ea.pre = NULL;
		RzILOpPure *addr = ea.addr;
		ea.addr = NULL;
		*seq = seq_append(*seq, pre);
		*seq = seq_append(*seq, SETL(addr_local, cast_unsigned(32, addr)));
		*seq = seq_append(*seq, SETL(value_local, read_mem_sized(bits, VARL(addr_local))));
		rw->post = ea.post;
		ea.post = NULL;
		m68k_ea_fini(&ea);
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

RZ_IPI RzILOpEffect *write_rw_operand(M68KILCtx *ctx, const M68KRWOperand *rw, ut32 bits, RzILOpPure *value) {
	rz_return_val_if_fail(ctx && rw && rw->op, NULL);
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

#include <rz_il/rz_il_opbuilder_end.h>
