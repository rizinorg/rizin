// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "m68k/m68k_il_helpers.h"

#include <rz_il/rz_il_opbuilder_begin.h>
#include <rz_util/rz_assert.h>

RZ_IPI RzILOpPure *m68k_reg_value(M68KILCtx *ctx, m68k_reg reg) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		rz_warn_if_reached();
		return NULL;
	}
	return VARG(name);
}

RZ_IPI RzILOpPure *m68k_read_reg_sized(M68KILCtx *ctx, m68k_reg reg, ut32 bits) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		rz_warn_if_reached();
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
		return bits == 32 ? VARG(name) : UNSIGNED(bits, VARG(name));
	case M68K_REG_CCR:
		return UNSIGNED(bits, VARG("sr"));
	case M68K_REG_SR:
		return bits == 16 ? VARG(name) : UNSIGNED(bits, VARG(name));
	case M68K_REG_FP0:
	case M68K_REG_FP1:
	case M68K_REG_FP2:
	case M68K_REG_FP3:
	case M68K_REG_FP4:
	case M68K_REG_FP5:
	case M68K_REG_FP6:
	case M68K_REG_FP7:
		return bits == 80 ? VARG(name) : UNSIGNED(bits, VARG(name));
	default:
		break;
	}
	if (rz_m68k_reg_name_is_mmu_root_pointer(name)) {
		return bits == 64 ? VARG(name) : UNSIGNED(bits, VARG(name));
	}
	return bits == 32 ? VARG(name) : UNSIGNED(bits, VARG(name));
}

RZ_IPI RzILOpEffect *m68k_set_ccr_from_value(RzILOpPure *new_ccr) {
	RzILOpPure *ccr8 = UNSIGNED(8, new_ccr);
	return SETG("sr", LOGOR(LOGAND(VARG("sr"), U16(0xff00)), UNSIGNED(16, ccr8)));
}

RZ_IPI RzILOpBool *m68k_ccr_bit(ut32 bit) {
	rz_return_val_if_fail(bit < 8, NULL);
	return NON_ZERO(LOGAND(UNSIGNED(8, VARG("sr")), U8(1u << bit)));
}

RZ_IPI RzILOpBool *m68k_fpsr_bit(ut32 bit) {
	rz_return_val_if_fail(bit < 32, NULL);
	return NON_ZERO(LOGAND(UNSIGNED(32, VARG("fpsr")), U32(1u << bit)));
}

RZ_IPI RzILOpEffect *m68k_set_fpsr_cc(RzILOpBool *n, RzILOpBool *z, RzILOpBool *i, RzILOpBool *nan) {
	RzILOpPure *cc = U32(0);
	cc = LOGOR(cc, SHIFTL0(BOOL_TO_BV(n, 32), U8(M68K_FPSR_CC_N)));
	cc = LOGOR(cc, SHIFTL0(BOOL_TO_BV(z, 32), U8(M68K_FPSR_CC_Z)));
	cc = LOGOR(cc, SHIFTL0(BOOL_TO_BV(i, 32), U8(M68K_FPSR_CC_I)));
	cc = LOGOR(cc, SHIFTL0(BOOL_TO_BV(nan, 32), U8(M68K_FPSR_CC_NAN)));
	return SETG("fpsr", LOGOR(LOGAND(UNSIGNED(32, VARG("fpsr")), U32(~M68K_FPSR_CC_MASK)), cc));
}

static RzILOpBool *sr_bit(ut32 bit) {
	return NON_ZERO(LOGAND(UNSIGNED(16, VARG("sr")), U16((ut16)(1u << bit))));
}

RZ_IPI RzILOpBool *m68k_supervisor_mode(void) {
	return sr_bit(M68K_SR_S);
}

RZ_IPI RzILOpPure *m68k_ccr_with_flag(RzILOpPure *ccr, ut32 bit, RzILOpBool *value) {
	RzILOpPure *cleared = LOGAND(ccr, U8((ut8) ~(1u << bit)));
	RzILOpPure *flag = SHIFTL0(BOOL_TO_BV(value, 8), U8(bit));
	return LOGOR(cleared, flag);
}

RZ_IPI RzILOpEffect *m68k_set_flags_nzvcx(RzILOpPure *value, ut32 bits, RzILOpBool *v, RzILOpBool *c, RzILOpBool *x) {
	RzILOpPure *val = UNSIGNED(bits, value);
	RzILOpPure *ccr = LOGAND(UNSIGNED(8, VARG("sr")), U8(0xe0));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_N, MSB(DUP(val)));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, IS_ZERO(val));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_V, v ? v : IL_FALSE);
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, c ? c : IL_FALSE);
	if (x) {
		ccr = m68k_ccr_with_flag(ccr, M68K_CCR_X, x);
	} else {
		ccr = LOGOR(ccr, LOGAND(UNSIGNED(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	}
	return m68k_set_ccr_from_value(ccr);
}

RZ_IPI RzILOpEffect *m68k_set_flags_nzvcx_extend(RzILOpPure *value, ut32 bits, RzILOpBool *v, RzILOpBool *c) {
	RzILOpPure *val = UNSIGNED(bits, value);
	RzILOpPure *ccr = LOGAND(UNSIGNED(8, VARG("sr")), U8(0xe0));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_N, MSB(DUP(val)));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, AND(m68k_ccr_bit(M68K_CCR_Z), IS_ZERO(val)));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_V, v);
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, c);
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_X, (RzILOpBool *)DUP(c));
	return m68k_set_ccr_from_value(ccr);
}

RZ_IPI RzILOpEffect *m68k_set_flags_div(RzILOpPure *quotient, ut32 bits, RzILOpBool *overflow) {
	RzILOpPure *quotient_sized = UNSIGNED(bits, quotient);
	RzILOpPure *ccr = LOGAND(UNSIGNED(8, VARG("sr")), U8(0xe0));
	RzILOpBool *no_overflow = INV((RzILOpBool *)DUP(overflow));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_N, AND(no_overflow, MSB(DUP(quotient_sized))));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, AND(INV((RzILOpBool *)DUP(overflow)), IS_ZERO(quotient_sized)));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_V, overflow);
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	ccr = LOGOR(ccr, LOGAND(UNSIGNED(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	return m68k_set_ccr_from_value(ccr);
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

RZ_IPI RzILOpBool *m68k_signed_out_of_range(RzILOpPure *value, ut32 bits) {
	st64 min = -(1LL << (bits - 1));
	st64 max = (1LL << (bits - 1)) - 1;
	return OR(SLT(DUP(value), S64(min)), SGT(value, S64(max)));
}

RZ_IPI RzILOpBool *m68k_addx_overflow(ut32 bits) {
	RzILOpPure *sum = ADD(ADD(SIGNED(64, VARL("dst")), SIGNED(64, VARL("src"))), UNSIGNED(64, VARL("x")));
	return m68k_signed_out_of_range(sum, bits);
}

RZ_IPI RzILOpBool *m68k_subx_overflow(ut32 bits) {
	RzILOpPure *diff = SUB(SUB(SIGNED(64, VARL("dst")), SIGNED(64, VARL("src"))), UNSIGNED(64, VARL("x")));
	return m68k_signed_out_of_range(diff, bits);
}

RZ_IPI RzILOpBool *m68k_negx_overflow(ut32 bits) {
	RzILOpPure *diff = SUB(SUB(S64(0), SIGNED(64, VARL("dst"))), UNSIGNED(64, VARL("borrow")));
	return m68k_signed_out_of_range(diff, bits);
}

static RzILOpPure *reg_write_value(M68KILCtx *ctx, m68k_reg reg, ut32 bits, RzILOpPure *value) {
	if (rz_m68k_reg_is_dreg(reg) && bits < 32) {
		ut32 mask = bits == 8 ? 0xffffff00u : 0xffff0000u;
		return LOGOR(LOGAND(m68k_reg_value(ctx, reg), U32(mask)), UNSIGNED(32, value));
	}
	if (rz_m68k_reg_is_areg(reg) && bits == 16) {
		return SIGNED(32, value);
	}
	if (reg == M68K_REG_CCR) {
		return UNSIGNED(8, value);
	}
	if (reg == M68K_REG_SR) {
		return UNSIGNED(16, value);
	}
	if (rz_m68k_reg_is_fpu(reg)) {
		return UNSIGNED(80, value);
	}
	const char *name = cs_reg_name(ctx->handle, reg);
	if (rz_m68k_reg_name_is_mmu_root_pointer(name)) {
		if (bits == 64) {
			return UNSIGNED(64, value);
		}
		return LOGOR(LOGAND(m68k_reg_value(ctx, reg), U64(0xffffffff00000000ULL)), UNSIGNED(64, value));
	}
	return UNSIGNED(32, value);
}

static inline bool m68k_mode_has_master_stack(cs_mode mode) {
	return mode == CS_MODE_M68K_020 || mode == CS_MODE_M68K_030 ||
		mode == CS_MODE_M68K_040 || mode == CS_MODE_M68K_060;
}

RZ_IPI RzILOpEffect *m68k_write_reg_sized(M68KILCtx *ctx, m68k_reg reg, ut32 bits, RzILOpPure *value) {
	const char *name = cs_reg_name(ctx->handle, reg);
	if (!name) {
		rz_warn_if_reached();
		rz_il_op_pure_free(value);
		return NULL;
	}
	if (reg == M68K_REG_PC) {
		return JMP(UNSIGNED(32, value));
	}
	if (reg == M68K_REG_CCR) {
		return m68k_set_ccr_from_value(value);
	}
	if (reg == M68K_REG_SR) {
		bool has_master_stack = m68k_mode_has_master_stack(ctx->mode);
		ut16 master_mask = has_master_stack ? 1u << M68K_SR_M : 0;
		RzILOpEffect *save_old_sp = BRANCH(
			IS_ZERO(LOGAND(UNSIGNED(16, VARG("sr")), U16(1u << M68K_SR_S))),
			SETG("usp", UNSIGNED(32, VARG("a7"))),
			BRANCH(
				NON_ZERO(LOGAND(UNSIGNED(16, VARG("sr")), U16(master_mask))),
				SETG("msp", UNSIGNED(32, VARG("a7"))),
				SETG("isp", UNSIGNED(32, VARG("a7")))));
		RzILOpEffect *load_new_sp = BRANCH(
			IS_ZERO(LOGAND(VARL("sr_write_value"), U16(1u << M68K_SR_S))),
			SETG("a7", UNSIGNED(32, VARG("usp"))),
			BRANCH(
				NON_ZERO(LOGAND(VARL("sr_write_value"), U16(master_mask))),
				SETG("a7", UNSIGNED(32, VARG("msp"))),
				SETG("a7", UNSIGNED(32, VARG("isp")))));
		RzILOpPure *old_bank = ITE(
			IS_ZERO(LOGAND(UNSIGNED(16, VARG("sr")), U16(1u << M68K_SR_S))),
			U8(0),
			ITE(NON_ZERO(LOGAND(UNSIGNED(16, VARG("sr")), U16(master_mask))), U8(2), U8(1)));
		RzILOpPure *new_bank = ITE(
			IS_ZERO(LOGAND(VARL("sr_write_value"), U16(1u << M68K_SR_S))),
			U8(0),
			ITE(NON_ZERO(LOGAND(VARL("sr_write_value"), U16(master_mask))), U8(2), U8(1)));
		return SEQ3(
			SETL("sr_write_value", UNSIGNED(16, value)),
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

RZ_IPI RzILOpBool *m68k_rte_format_valid(cs_mode mode) {
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

RZ_IPI RzILOpPure *m68k_rte_frame_size(cs_mode mode) {
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

static RzILOpPure *index_value(M68KILCtx *ctx, const cs_m68k_op *op) {
	if (op->mem.index_reg == M68K_REG_INVALID) {
		return U32(0);
	}
	RzILOpPure *idx = m68k_read_reg_sized(ctx, op->mem.index_reg, op->mem.index_size ? 32 : 16);
	if (!idx) {
		return NULL;
	}
	idx = !op->mem.index_size ? SIGNED(32, idx) : UNSIGNED(32, idx);
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
static bool insn_word_at(const M68KILCtx *ctx, ut32 offset, ut16 *ext_word) {
	rz_return_val_if_fail(ctx && ctx->insn && ext_word, false);
	if (offset + 1 >= ctx->insn->size || offset + 1 >= sizeof(ctx->insn->bytes)) {
		return false;
	}
	*ext_word = ((ut16)ctx->insn->bytes[offset] << 8) | ctx->insn->bytes[offset + 1];
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
	case M68K_OP_MEM:
		return mem_extension_bytes(op);
	case M68K_OP_INVALID:
	case M68K_OP_REG:
	case M68K_OP_REG_BITS:
	case M68K_OP_REG_PAIR:
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	case M68K_OP_SHIFT:
#endif
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

/* 680x0 brief/full index extension word (M68000PRM indexed addressing). */
enum {
	M68K_EXT_WORD_INDEX_ADDR_REG = 0x8000, /* D/A, bit 15 */
	M68K_EXT_WORD_INDEX_LONG = 0x0800, /* W/L, bit 11 */
	M68K_EXT_WORD_FULL_FORMAT = 0x0100, /* 0=brief, 1=full, bit 8 */
	M68K_EXT_WORD_INDEX_SUPPRESS = 0x0040, /* full-format IS, bit 6 */
};

static bool index_extension_word_matches(const cs_m68k_op *op, ut16 ext_word, bool full) {
	if (((ext_word & M68K_EXT_WORD_FULL_FORMAT) != 0) != full) {
		return false;
	}
	if (op->mem.index_reg == M68K_REG_INVALID) {
		return full && (ext_word & M68K_EXT_WORD_INDEX_SUPPRESS);
	}
	m68k_reg index_reg = ((ext_word & M68K_EXT_WORD_INDEX_ADDR_REG) ? M68K_REG_A0 : M68K_REG_D0) +
		((ext_word >> 12) & 7);
	if (op->mem.index_reg != index_reg) {
		return false;
	}
	if (op->mem.index_size != ((ext_word & M68K_EXT_WORD_INDEX_LONG) ? 1 : 0)) {
		return false;
	}
	ut8 scale = 1 << ((ext_word >> 9) & 3);
	return (op->mem.scale ? op->mem.scale : 1) == scale;
}

static bool pc_relative_extension_word_matches(const cs_m68k_op *op, ut16 ext_word) {
	switch (op->address_mode) {
	case M68K_AM_PCI_DISP:
		return (st16)ext_word == op->mem.disp;
	case M68K_AM_PCI_INDEX_8_BIT_DISP:
		return index_extension_word_matches(op, ext_word, false) && (st8)(ext_word & 0xff) == op->mem.disp;
	case M68K_AM_PCI_INDEX_BASE_DISP:
	case M68K_AM_PC_MEMI_PRE_INDEX:
	case M68K_AM_PC_MEMI_POST_INDEX:
		return index_extension_word_matches(op, ext_word, true);
	default:
		return false;
	}
}

static ut32 pc_relative_extension_offset(const M68KILCtx *ctx, const cs_m68k_op *op) {
	ut32 expected = expected_pc_relative_extension_offset(ctx, op);
	ut16 ext_word = 0;
	if (insn_word_at(ctx, expected, &ext_word) && pc_relative_extension_word_matches(op, ext_word)) {
		return expected;
	}

	ut32 fallback = expected;
	bool found = false;
	for (ut32 offset = 2; offset + 1 < ctx->insn->size; offset += 2) {
		if (!insn_word_at(ctx, offset, &ext_word) || !pc_relative_extension_word_matches(op, ext_word)) {
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
	(void)op;
	return branch_disp_base(ctx);
#else
	return ctx->addr + pc_relative_extension_offset(ctx, op);
#endif
}

RZ_IPI RzILOpPure *m68k_branch_disp_target(const M68KILCtx *ctx, const cs_m68k_op *op) {
	rz_return_val_if_fail(ctx && op, NULL);
	if (op->type != M68K_OP_BR_DISP) {
		return NULL;
	}
	return U32(branch_disp_base(ctx) + op->br_disp.disp);
}

RZ_IPI RzILOpEffect *m68k_set_addr_reg_delta(M68KILCtx *ctx, m68k_reg reg, st32 delta) {
	if (!rz_m68k_reg_is_areg(reg)) {
		return NULL;
	}
	RzILOpPure *base = m68k_reg_value(ctx, reg);
	RzILOpPure *res = delta >= 0 ? ADD(base, U32((ut32)delta)) : SUB(base, U32((ut32)-delta));
	return m68k_write_reg_sized(ctx, reg, 32, res);
}

RZ_IPI M68KEA m68k_effective_addr(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits) {
	M68KEA ea = { 0 };
	rz_return_val_if_fail(ctx && op, ea);
	RzILOpPure *base = NULL;
	RzILOpPure *idx = NULL;
	m68k_reg base_reg = rz_m68k_op_base_reg(op);
	switch (op->address_mode) {
	case M68K_AM_REGI_ADDR:
		ea.addr = m68k_reg_value(ctx, base_reg);
		break;
	case M68K_AM_REGI_ADDR_POST_INC:
		ea.addr = m68k_reg_value(ctx, base_reg);
		ea.post = m68k_set_addr_reg_delta(ctx, base_reg, rz_m68k_reg_stack_access_bytes(base_reg, bits));
		break;
	case M68K_AM_REGI_ADDR_PRE_DEC:
		ea.pre = m68k_set_addr_reg_delta(ctx, base_reg, -(st32)rz_m68k_reg_stack_access_bytes(base_reg, bits));
		ea.addr = m68k_reg_value(ctx, base_reg);
		break;
	case M68K_AM_REGI_ADDR_DISP:
		ea.addr = ADD(UNSIGNED(32, m68k_reg_value(ctx, base_reg)), UNSIGNED(32, S32((st32)op->mem.disp)));
		break;
	case M68K_AM_AREGI_INDEX_8_BIT_DISP:
	case M68K_AM_AREGI_INDEX_BASE_DISP: {
		st64 disp = op->address_mode == M68K_AM_AREGI_INDEX_BASE_DISP ? op->mem.in_disp : op->mem.disp;
		base = base_reg != M68K_REG_INVALID ? m68k_reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(ADD(UNSIGNED(32, base), UNSIGNED(32, S32((st32)disp))), idx);
		break;
	}
	case M68K_AM_MEMI_PRE_INDEX:
		base = base_reg != M68K_REG_INVALID ? m68k_reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(LOADW(32, ADD(ADD(base, idx), S32((st32)op->mem.in_disp))), S32((st32)op->mem.out_disp));
		break;
	case M68K_AM_MEMI_POST_INDEX:
		base = base_reg != M68K_REG_INVALID ? m68k_reg_value(ctx, base_reg) : U32(0);
		idx = index_value(ctx, op);
		ea.addr = ADD(ADD(LOADW(32, ADD(base, S32((st32)op->mem.in_disp))), idx), S32((st32)op->mem.out_disp));
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
		ea.addr = ADD(LOADW(32, ADD(ADD(U32(pc_relative_base(ctx, op)), idx), S32((st32)op->mem.in_disp))), S32((st32)op->mem.out_disp));
		break;
	case M68K_AM_PC_MEMI_POST_INDEX:
		idx = index_value(ctx, op);
		ea.addr = ADD(ADD(LOADW(32, ADD(U32(pc_relative_base(ctx, op)), S32((st32)op->mem.in_disp))), idx), S32((st32)op->mem.out_disp));
		break;
	case M68K_AM_ABSOLUTE_DATA_SHORT:
		ea.addr = U32(rz_m68k_op_absolute_address(op, true));
		break;
	case M68K_AM_ABSOLUTE_DATA_LONG:
		ea.addr = U32(rz_m68k_op_absolute_address(op, false));
		break;
	default:
		if (rz_m68k_op_is_mem_addr(op) && base_reg != M68K_REG_INVALID) {
			ea.addr = ADD(m68k_reg_value(ctx, base_reg), S32((st32)op->mem.disp));
		} else if (rz_m68k_op_is_mem_addr(op)) {
			ea.addr = U32(rz_m68k_op_absolute_address(op, false));
		}
		break;
	}
	return ea;
}

RZ_IPI RzILOpPure *m68k_read_operand(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits, RzILOpEffect **pre, RzILOpEffect **post) {
	if (pre) {
		*pre = NULL;
	}
	if (post) {
		*post = NULL;
	}
	rz_return_val_if_fail(ctx && op, NULL);
	if (rz_m68k_op_is_mem_addr(op)) {
		M68KEA ea = m68k_effective_addr(ctx, op, bits);
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
		return LOADW(bits, addr);
	}
	switch (op->type) {
	case M68K_OP_REG:
		return m68k_read_reg_sized(ctx, op->reg, bits);
	case M68K_OP_IMM:
		return UN(bits, op->imm);
	case M68K_OP_BR_DISP:
		return m68k_branch_disp_target(ctx, op);
	case M68K_OP_FP_SINGLE:
		return F2BV(F32(op->simm));
	case M68K_OP_FP_DOUBLE:
		return F2BV(F64(op->dimm));
	case M68K_OP_INVALID:
	default:
		return NULL;
	}
}

static RzILOpEffect *write_operand_before_store(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits,
	RzILOpEffect *before_store, RzILOpPure *value) {
	if (!ctx || !op) {
		rz_il_op_effect_free(before_store);
		rz_il_op_pure_free(value);
	}
	rz_return_val_if_fail(ctx && op, NULL);
	if (rz_m68k_op_is_mem_addr(op)) {
		M68KEA ea = m68k_effective_addr(ctx, op, bits);
		if (!ea.addr) {
			rz_il_op_effect_free(before_store);
			rz_il_op_pure_free(value);
			m68k_ea_fini(&ea);
			return NULL;
		}
		RzILOpPure *addr = ea.addr;
		RzILOpEffect *pre = ea.pre;
		RzILOpEffect *post = ea.post;
		ea.addr = NULL;
		ea.pre = NULL;
		ea.post = NULL;
		m68k_ea_fini(&ea);
		RzILOpEffect *store = STOREW(addr, UNSIGNED(bits, value));
		if (before_store) {
			store = SEQ2(before_store, store);
		}
		return m68k_effect_pre_post(pre, store, post);
	}
	switch (op->type) {
	case M68K_OP_REG: {
		RzILOpEffect *write = m68k_write_reg_sized(ctx, op->reg, bits, value);
		if (!write) {
			rz_il_op_effect_free(before_store);
			return NULL;
		}
		return before_store ? SEQ2(before_store, write) : write;
	}
	default:
		rz_il_op_effect_free(before_store);
		rz_il_op_pure_free(value);
		return NULL;
	}
}

/**
 * \brief Write \p value to \p op, including EA predecrement/postincrement.
 *
 * \param ctx Lift context
 * \param op Destination operand
 * \param bits Access width
 * \param value Value to store; consumed on all paths
 * \return `pre ; store ; post`. EA side effects are part of the returned effect.
 *
 * Do not sequence a SETL that the store reads *before* this effect: `pre` runs
 * first and must not be assumed to commute with caller locals. Bind such a
 * local with m68k_write_operand_local() so it is set after `pre`.
 */
RZ_IPI RZ_OWN RzILOpEffect *m68k_write_operand(M68KILCtx *ctx, const cs_m68k_op *op,
	ut32 bits, RZ_OWN RzILOpPure *value) {
	return write_operand_before_store(ctx, op, bits, NULL, value);
}

/**
 * \brief Bind \p value to \p name after EA pre-effects, then store that local.
 *
 * \return `pre ; SETL(name, value) ; store(VARL(name)) ; post`
 */
RZ_IPI RZ_OWN RzILOpEffect *m68k_write_operand_local(M68KILCtx *ctx, const cs_m68k_op *op,
	ut32 bits, const char *name, RZ_OWN RzILOpPure *value) {
	if (!name) {
		rz_il_op_pure_free(value);
	}
	rz_return_val_if_fail(name, NULL);
	return write_operand_before_store(ctx, op, bits, SETL(name, value), VARL(name));
}

RZ_IPI RzILOpEffect *m68k_label(const char *label) {
	if (RZ_STR_EQ(label, "m68k_illegal")) {
		return SEQ3(
			SETL("trap_op", U32((ut32)M68K_TRAP_OP_ILLEGAL)),
			SETL("trap_vector", U32((ut32)M68K_VECTOR_ILLEGAL)),
			GOTO(label));
	}
	if (RZ_STR_EQ(label, "m68k_privilege")) {
		return SEQ3(
			SETL("trap_op", U32((ut32)M68K_TRAP_OP_PRIVILEGE)),
			SETL("trap_vector", U32((ut32)M68K_VECTOR_PRIVILEGE)),
			GOTO(label));
	}
	return GOTO(label);
}

RZ_IPI RzILOpEffect *m68k_guard_supervisor(RzILOpEffect *effect) {
	return effect ? BRANCH(m68k_supervisor_mode(), effect, m68k_label("m68k_privilege")) : NULL;
}

RZ_IPI RzILOpEffect *m68k_write_status_reg_unchecked(M68KILCtx *ctx, m68k_reg reg, RzILOpPure *value) {
	ut32 bits = reg == M68K_REG_CCR ? 8 : 16;
	return m68k_write_reg_sized(ctx, reg, bits, value);
}

RZ_IPI RzILOpEffect *m68k_write_status_reg(M68KILCtx *ctx, m68k_reg reg, RzILOpPure *value) {
	RzILOpEffect *write = m68k_write_status_reg_unchecked(ctx, reg, value);
	if (!write) {
		return NULL;
	}
	return reg == M68K_REG_SR ? BRANCH(m68k_supervisor_mode(), write, m68k_label("m68k_privilege")) : write;
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

/**
 * \brief Sequence optional bookends around a required effect: pre, then \p eff, then post.
 *
 * \param pre Side effects before \p eff, or NULL
 * \param eff Required effect
 * \param post Side effects after \p eff, or NULL
 * \return `pre ; eff ; post`. `pre` and `post` are skipped when NULL.
 */
RZ_IPI RZ_OWN RzILOpEffect *m68k_effect_pre_post(RZ_NULLABLE RZ_OWN RzILOpEffect *pre,
	RZ_NONNULL RZ_OWN RzILOpEffect *eff, RZ_NULLABLE RZ_OWN RzILOpEffect *post) {
	if (!eff) {
		rz_il_op_effect_free(pre);
		rz_il_op_effect_free(post);
		rz_return_val_if_fail(eff, NULL);
		return NULL;
	}
	if (post) {
		eff = SEQ2(eff, post);
	}
	if (pre) {
		eff = SEQ2(pre, eff);
	}
	return eff;
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
	return SEQ3(
		SETL("trap_op", U32((ut32)trap_op)),
		SETL("trap_vector", U32((ut32)vector)),
		m68k_label(label));
}

RZ_IPI bool m68k_operand_to_local(M68KILCtx *ctx, const char *name, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq) {
	rz_return_val_if_fail(ctx && name && op && seq, false);
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpPure *value = m68k_read_operand(ctx, op, bits, &pre, &post);
	if (!value) {
		return false;
	}
	RzILOpEffect *set = m68k_effect_pre_post(pre, SETL(name, value), post);
	*seq = *seq ? SEQ2(*seq, set) : set;
	return true;
}

RZ_IPI bool m68k_rw_operand_to_local(M68KILCtx *ctx, M68KRWOperand *rw, const char *value_local, const char *addr_local, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq) {
	rz_return_val_if_fail(ctx && rw && value_local && addr_local && op && seq, false);
	*rw = (M68KRWOperand){
		.op = op,
		.addr_local = addr_local,
		.post = NULL,
	};
	if (rz_m68k_op_is_mem_addr(op)) {
		M68KEA ea = m68k_effective_addr(ctx, op, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return false;
		}
		RzILOpEffect *pre = ea.pre;
		ea.pre = NULL;
		RzILOpPure *addr = ea.addr;
		ea.addr = NULL;
		RzILOpEffect *load = m68k_effect_pre_post(pre,
			SEQ2(SETL(addr_local, UNSIGNED(32, addr)),
				SETL(value_local, LOADW(bits, VARL(addr_local)))),
			NULL);
		*seq = *seq ? SEQ2(*seq, load) : load;
		rw->post = ea.post;
		ea.post = NULL;
		m68k_ea_fini(&ea);
		return true;
	}
	switch (op->type) {
	case M68K_OP_REG: {
		RzILOpPure *value = m68k_read_reg_sized(ctx, op->reg, bits);
		if (!value) {
			return false;
		}
		*seq = *seq ? SEQ2(*seq, SETL(value_local, value)) : SETL(value_local, value);
		return true;
	}
	default:
		return false;
	}
}

RZ_IPI RzILOpEffect *m68k_write_rw_operand(M68KILCtx *ctx, const M68KRWOperand *rw, ut32 bits, RzILOpPure *value) {
	rz_return_val_if_fail(ctx && rw && rw->op, NULL);
	if (rz_m68k_op_is_mem_addr(rw->op)) {
		return STOREW(VARL(rw->addr_local), UNSIGNED(bits, value));
	}
	switch (rw->op->type) {
	case M68K_OP_REG:
		return m68k_write_reg_sized(ctx, rw->op->reg, bits, value);
	default:
		rz_il_op_pure_free(value);
		return NULL;
	}
}

#include <rz_il/rz_il_opbuilder_end.h>
