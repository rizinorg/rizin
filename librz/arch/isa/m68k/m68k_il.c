// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "m68k/m68k_il.h"
#include "m68k/m68k_cs.h"
#include "m68k/m68k_il_helpers.h"

#include <rz_il/rz_il_opbuilder_begin.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_bits.h>

static RzILOpPure *fpu_fp80_to_ext96(RzILOpPure *fp80);
static RzILOpPure *fpu_ext96_to_fp80(RzILOpPure *ext96);
static RzILOpPure *fpu_const80_bits(ut16 sign_exp, ut64 mantissa);
static bool fmovecr_const_parts(ut64 selector, ut16 *sign_exp, ut64 *mantissa);

static RzILOpEffect *lift_move(M68KILCtx *ctx, bool address_dst) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	bool uses_usp = (src->type == M68K_OP_REG && src->reg == M68K_REG_USP) ||
		(dst->type == M68K_OP_REG && dst->reg == M68K_REG_USP);
	bool reads_sr = src->type == M68K_OP_REG && src->reg == M68K_REG_SR;
	bool reads_ccr = src->type == M68K_OP_REG && src->reg == M68K_REG_CCR;
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", src, bits, &seq)) {
		return NULL;
	}
	if (rz_m68k_op_is_status_reg(dst)) {
		RzILOpEffect *write = m68k_write_status_reg_unchecked(ctx, dst->reg, VARL("src"));
		if (!write) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, write);
		return dst->reg == M68K_REG_SR ? BRANCH(m68k_supervisor_mode(), seq, m68k_label("m68k_privilege")) : seq;
	}
	RzILOpEffect *write = m68k_write_operand(ctx, dst, bits, VARL("src"));
	if (!write) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, write);
	if (!address_dst && !uses_usp && !reads_sr && !reads_ccr) {
		seq = SEQ2(seq, m68k_set_flags_nzvcx(VARL("src"), bits, IL_FALSE, IL_FALSE, NULL));
	}
	if (uses_usp || (reads_sr && ctx->mode != CS_MODE_M68K_000)) {
		return BRANCH(m68k_supervisor_mode(), seq, m68k_label("m68k_privilege"));
	}
	return seq;
}

static RzILOpEffect *lift_moveq(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (ctx->m68k->operands[1].type != M68K_OP_REG) {
		return NULL;
	}
	RzILOpPure *value = S32((st8)ctx->m68k->operands[0].imm);
	return SEQ3(
		SETL("res", DUP(value)),
		m68k_write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, value),
		m68k_set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_movec(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_REG || ctx->m68k->operands[1].type != M68K_OP_REG) {
		return NULL;
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
		return NULL;
	}
	m68k_reg cr = src_control ? src->reg : dst->reg;
	if (!rz_m68k_control_reg_implemented(ctx->mode, cr)) {
		return BRANCH(m68k_supervisor_mode(), m68k_label("m68k_illegal"), m68k_label("m68k_privilege"));
	}
	RzILOpPure *value = m68k_read_reg_sized(ctx, src->reg, 32);
	if (!value) {
		return NULL;
	}
	if (dst_control && (dst->reg == M68K_REG_SFC || dst->reg == M68K_REG_DFC)) {
		value = LOGAND(value, U32(7));
	}
	RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, 32, value);
	if (!write) {
		return NULL;
	}
	return BRANCH(m68k_supervisor_mode(), write, m68k_label("m68k_privilege"));
}

static RzILOpEffect *lift_moves(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	bool src_reg = rz_m68k_op_is_gpr(src);
	bool dst_reg = rz_m68k_op_is_gpr(dst);
	bool src_mem = rz_m68k_op_is_mem_addr(src);
	bool dst_mem = rz_m68k_op_is_mem_addr(dst);
	if (!((src_reg && dst_mem) || (src_mem && dst_reg))) {
		return NULL;
	}

	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq;
	if (src_mem) {
		M68KEA ea = m68k_effective_addr(ctx, src, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return NULL;
		}
		ut32 write_bits = bits;
		RzILOpPure *value = VARL("src");
		if (rz_m68k_reg_is_areg(dst->reg) && bits < 32) {
			value = SIGNED(32, value);
			write_bits = 32;
		}
		RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, write_bits, value);
		if (!write) {
			m68k_ea_fini(&ea);
			return NULL;
		}
		seq = m68k_effect_pre_post(ea.pre,
			SETL("src", LOADW(bits, UNSIGNED(M68K_ADDR_BITS, ea.addr))),
			ea.post);
		seq = SEQ2(seq, write);
	} else {
		RzILOpPure *value = m68k_read_reg_sized(ctx, src->reg, bits);
		M68KEA ea = m68k_effective_addr(ctx, dst, bits);
		if (!value || !ea.addr) {
			rz_il_op_pure_free(value);
			m68k_ea_fini(&ea);
			return NULL;
		}
		seq = SEQ2(
			SETL("src", value),
			m68k_effect_pre_post(ea.pre,
				STOREW(UNSIGNED(M68K_ADDR_BITS, ea.addr), UNSIGNED(bits, VARL("src"))),
				ea.post));
	}
	return BRANCH(m68k_supervisor_mode(), seq, m68k_label("m68k_privilege"));
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
	RzILOpPure *src = source;
	RzILOpPure *ccr = LOGAND(UNSIGNED(8, VARG("sr")), U8(0xe0));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_N, MSB(DUP(src)));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, IS_ZERO(src));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_V, IL_FALSE);
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	ccr = LOGOR(ccr, LOGAND(UNSIGNED(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	return m68k_set_ccr_from_value(ccr);
}

static RzILOpEffect *set_flags_rem(RzILOpPure *quotient, RzILOpBool *overflow) {
	RzILOpPure *quotient32 = UNSIGNED(32, quotient);
	RzILOpPure *ccr = LOGAND(UNSIGNED(8, VARG("sr")), U8(0xe0));
	RzILOpBool *no_overflow = INV((RzILOpBool *)DUP(overflow));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_N, AND(no_overflow, MSB(DUP(quotient32))));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, AND(INV((RzILOpBool *)DUP(overflow)), IS_ZERO(quotient32)));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_V, overflow);
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	ccr = LOGOR(ccr, LOGAND(UNSIGNED(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	return m68k_set_ccr_from_value(ccr);
}

static RzILOpEffect *lift_mov3q(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return NULL;
	}
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	RzILOpPure *value = U32((ut32)ctx->m68k->operands[0].imm);
	RzILOpEffect *write = m68k_write_operand_local(ctx, dst, 32, "res", value);
	if (!write && dst->type == M68K_OP_IMM) {
		write = SEQ2(SETL("res", U32((ut32)ctx->m68k->operands[0].imm)),
			STOREW(U32((ut32)dst->imm), UNSIGNED(32, VARL("res"))));
	}
	if (!write) {
		return NULL;
	}
	return SEQ2(write, m68k_set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static RzILOpBool *macsr_signed(void);

static int mac_acc_index(m68k_reg reg) {
	if (reg == M68K_REG_ACC || reg == M68K_REG_ACC0) {
		return 0;
	}
	if (reg >= M68K_REG_ACC1 && reg <= M68K_REG_ACC3) {
		return (int)(reg - M68K_REG_ACC0);
	}
	return -1;
}

static RzILOpPure *mac_acc_ext16(M68KILCtx *ctx, int acc_index) {
	m68k_reg ext_reg = acc_index < 2 ? M68K_REG_ACCEXT01 : M68K_REG_ACCEXT23;
	RzILOpPure *ext = m68k_read_reg_sized(ctx, ext_reg, 32);
	if (!ext) {
		return NULL;
	}
	if (acc_index & 1) {
		return UNSIGNED(16, SHIFTR0(ext, U8(16)));
	}
	return UNSIGNED(16, ext);
}

static RzILOpBool *macsr_flag(ut32 bit) {
	return NON_ZERO(LOGAND(VARG("macsr"), U32(1u << bit)));
}

static RzILOpPure *mac_round_nearest_even32(const char *value, const char *frac, ut32 mid) {
	RzILOpBool *tie_up = NON_ZERO(LOGAND(VARL(value), U32(1)));
	return ITE(ULT(VARL(frac), U32(mid)),
		VARL(value),
		ITE(UGT(VARL(frac), U32(mid)),
			ADD(VARL(value), U32(1)),
			ITE(tie_up, ADD(VARL(value), U32(1)), VARL(value))));
}

static RzILOpPure *mac_round_nearest_even64(const char *value, const char *frac32, ut64 mid) {
	RzILOpBool *tie_up = NON_ZERO(LOGAND(VARL(value), U64(1)));
	RzILOpPure *frac = UNSIGNED(64, VARL(frac32));
	return ITE(ULT(frac, U64(mid)),
		VARL(value),
		ITE(UGT(UNSIGNED(64, VARL(frac32)), U64(mid)),
			ADD(VARL(value), U64(1)),
			ITE(tie_up, ADD(VARL(value), U64(1)), VARL(value))));
}

/* CFPRM integer MOVCLR/MOVE from ACC with OMC=1 uses the 48-bit accumulator
 * {ACCext[15:0], ACC[31:0]}. Signed fits iff ACC[47:31] is all 0 or all 1;
 * unsigned fits iff ACC[47:32] is 0. Fractional mode packs
 * {ACCext[15:8], ACC[31:0], ACCext[7:0]} and rounds/saturates from that. */
static RzILOpPure *mac_movclr_integer_store(void) {
	RzILOpBool *omc = macsr_flag(M68K_MACSR_OMC);
	RzILOpBool *signed_fits = OR(IS_ZERO(VARL("bits_47_31")), EQ(VARL("bits_47_31"), U32(0x1ffff)));
	RzILOpBool *unsigned_fits = IS_ZERO(VARL("ext16"));
	RzILOpPure *signed_sat = ITE(MSB(VARL("ext16")), U32(0x80000000u), U32(0x7fffffffu));
	return ITE(omc,
		ITE(macsr_signed(),
			ITE(signed_fits, VARL("src"), signed_sat),
			ITE(unsigned_fits, VARL("src"), U32(0xffffffffu))),
		VARL("src"));
}

static RzILOpPure *mac_movclr_fractional_store(void) {
	RzILOpBool *acc47 = NON_ZERO(LOGAND(VARL("ext_hi"), U32(0x80)));
	RzILOpPure *unsat32 = ITE(macsr_flag(M68K_MACSR_RT), VARL("rnd32"), VARL("src"));
	RzILOpBool *fits9 = OR(IS_ZERO(VARL("bits_47_39")), EQ(VARL("bits_47_39"), U32(0x1ff)));
	RzILOpPure *sat32_trunc = ITE(fits9, VARL("src"), ITE(acc47, U32(0x80000000u), U32(0x7fffffffu)));
	RzILOpBool *rnd32_fits9 = OR(IS_ZERO(VARL("rnd32_bits_47_39")), EQ(VARL("rnd32_bits_47_39"), U32(0x1ff)));
	RzILOpBool *rnd32_neg = NON_ZERO(LOGAND(VARL("rnd40"), U64(1ull << 39)));
	RzILOpPure *sat32_round = ITE(rnd32_fits9, VARL("rnd32"), ITE(rnd32_neg, U32(0x80000000u), U32(0x7fffffffu)));
	RzILOpBool *rnd16_fits9 = OR(IS_ZERO(VARL("rnd16_bits_47_39")), EQ(VARL("rnd16_bits_47_39"), U32(0x1ff)));
	RzILOpBool *rnd16_neg = NON_ZERO(LOGAND(VARL("rnd24"), U64(1ull << 23)));
	RzILOpPure *sat16 = ITE(rnd16_fits9, LOGAND(VARL("rnd16"), U32(0xffff)), ITE(rnd16_neg, U32(0x8000), U32(0x7fff)));
	RzILOpPure *sat32 = ITE(macsr_flag(M68K_MACSR_RT), sat32_round, sat32_trunc);
	return ITE(macsr_flag(M68K_MACSR_SU),
		ITE(macsr_flag(M68K_MACSR_OMC), sat16, LOGAND(VARL("rnd16"), U32(0xffff))),
		ITE(macsr_flag(M68K_MACSR_OMC), sat32, unsat32));
}

static RzILOpPure *mac_movclr_store_value(void) {
	return ITE(macsr_flag(M68K_MACSR_FI),
		mac_movclr_fractional_store(),
		mac_movclr_integer_store());
}

static RzILOpEffect *mac_clear_extension(M68KILCtx *ctx, int acc_index) {
	m68k_reg ext_reg = acc_index < 2 ? M68K_REG_ACCEXT01 : M68K_REG_ACCEXT23;
	ut32 keep = (acc_index & 1) ? 0x0000ffffu : 0xffff0000u;
	RzILOpPure *ext = m68k_read_reg_sized(ctx, ext_reg, 32);
	if (!ext) {
		return NULL;
	}
	return m68k_write_reg_sized(ctx, ext_reg, 32, LOGAND(ext, U32(keep)));
}
#endif

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static RzILOpEffect *mac_bind_acc_store(M68KILCtx *ctx, m68k_reg acc, int acc_index) {
	RzILOpPure *ext16 = mac_acc_ext16(ctx, acc_index);
	if (!ext16) {
		return NULL;
	}
	return SEQN(17,
		SETL("src", m68k_read_reg_sized(ctx, acc, 32)),
		SETL("ext16", ext16),
		SETL("ext_hi", SHIFTR0(UNSIGNED(32, VARL("ext16")), U8(8))),
		SETL("ext_lo", LOGAND(UNSIGNED(32, VARL("ext16")), U32(0xff))),
		SETL("hi16", SHIFTR0(VARL("src"), U8(16))),
		SETL("frac24", LOGOR(SHIFTL0(LOGAND(VARL("src"), U32(0xffff)), U8(8)), VARL("ext_lo"))),
		SETL("bits_47_31", LOGOR(SHIFTL0(UNSIGNED(32, VARL("ext16")), U8(1)), BOOL_TO_BV(MSB(VARL("src")), 32))),
		SETL("bits_47_39", LOGOR(SHIFTL0(VARL("ext_hi"), U8(1)), BOOL_TO_BV(MSB(VARL("src")), 32))),
		SETL("field40", LOGOR(SHIFTL0(UNSIGNED(64, VARL("ext_hi")), U8(32)), UNSIGNED(64, VARL("src")))),
		SETL("field24", LOGOR(SHIFTL0(UNSIGNED(64, VARL("ext_hi")), U8(16)), UNSIGNED(64, VARL("hi16")))),
		SETL("rnd32", mac_round_nearest_even32("src", "ext_lo", 0x80)),
		SETL("rnd16", mac_round_nearest_even32("hi16", "frac24", 0x800000u)),
		SETL("rnd40", mac_round_nearest_even64("field40", "ext_lo", 0x80)),
		SETL("rnd24", mac_round_nearest_even64("field24", "frac24", 0x800000ull)),
		SETL("rnd32_bits_47_39", UNSIGNED(32, LOGAND(SHIFTR0(VARL("rnd40"), U8(31)), U64(0x1ff)))),
		SETL("rnd16_bits_47_39", UNSIGNED(32, LOGAND(SHIFTR0(VARL("rnd24"), U8(15)), U64(0x1ff)))),
		SETL("stored", mac_movclr_store_value()));
}

static RzILOpEffect *lift_move_from_acc(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_acc_reg(&ctx->m68k->operands[0]) ||
		!rz_m68k_op_is_gpr(&ctx->m68k->operands[1])) {
		return NULL;
	}
	m68k_reg acc = ctx->m68k->operands[0].reg;
	m68k_reg dst = ctx->m68k->operands[1].reg;
	int acc_index = mac_acc_index(acc);
	if (acc_index < 0) {
		return NULL;
	}
	RzILOpEffect *seq = mac_bind_acc_store(ctx, acc, acc_index);
	if (!seq) {
		return NULL;
	}
	RzILOpEffect *write_dst = m68k_write_reg_sized(ctx, dst, 32, VARL("stored"));
	if (!write_dst) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	return SEQ2(seq, write_dst);
}

static RzILOpEffect *mac_write_ext16(M68KILCtx *ctx, int acc_index) {
	m68k_reg ext_reg = acc_index < 2 ? M68K_REG_ACCEXT01 : M68K_REG_ACCEXT23;
	RzILOpPure *ext = m68k_read_reg_sized(ctx, ext_reg, 32);
	if (!ext) {
		return NULL;
	}
	RzILOpPure *merged = (acc_index & 1)
		? LOGOR(SHIFTL0(UNSIGNED(32, VARL("ext16")), U8(16)), LOGAND(ext, U32(0x0000ffffu)))
		: LOGOR(LOGAND(ext, U32(0xffff0000u)), UNSIGNED(32, VARL("ext16")));
	return m68k_write_reg_sized(ctx, ext_reg, 32, merged);
}

static RzILOpEffect *mac_update_macsr_acc_copy(cs_mode mode, int src_index, int dst_index) {
	const bool emac = rz_m68k_mode_has_emac(mode);
	ut32 pav_src = 1u << (M68K_MACSR_PAV0 + src_index);
	ut32 pav_dst = 1u << (M68K_MACSR_PAV0 + dst_index);
	ut32 clear = (1u << M68K_MACSR_N) | (1u << M68K_MACSR_Z) | (1u << M68K_MACSR_V) | pav_dst;
	if (emac) {
		clear |= 1u << M68K_MACSR_EV;
	}
	RzILOpBool *src_pav = NON_ZERO(LOGAND(VARG("macsr"), U32(pav_src)));
	RzILOpBool *n = NON_ZERO(LOGAND(UNSIGNED(32, VARL("ext16")), U32(0x8000)));
	RzILOpBool *z = AND(IS_ZERO(VARL("src")), IS_ZERO(VARL("ext16")));
	RzILOpBool *int_ev = ITE(macsr_signed(),
		INV(OR(IS_ZERO(VARL("bits_47_31")), EQ(VARL("bits_47_31"), U32(0x1ffff)))),
		NON_ZERO(VARL("ext16")));
	RzILOpBool *frac_ev = INV(OR(IS_ZERO(VARL("bits_47_39")), EQ(VARL("bits_47_39"), U32(0x1ff))));
	RzILOpPure *flags = LOGAND(VARG("macsr"), U32(~clear));
	flags = LOGOR(flags, ITE(n, U32(1u << M68K_MACSR_N), U32(0)));
	flags = LOGOR(flags, ITE(z, U32(1u << M68K_MACSR_Z), U32(0)));
	flags = LOGOR(flags, ITE(src_pav, U32((1u << M68K_MACSR_V) | pav_dst), U32(0)));
	if (emac) {
		flags = LOGOR(flags, ITE(ITE(macsr_flag(M68K_MACSR_FI), frac_ev, int_ev), U32(1u << M68K_MACSR_EV), U32(0)));
	}
	return SETG("macsr", flags);
}

static RzILOpEffect *lift_move_acc_to_acc(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_acc_reg(&ctx->m68k->operands[0]) ||
		!rz_m68k_op_is_acc_reg(&ctx->m68k->operands[1])) {
		return NULL;
	}
	m68k_reg src = ctx->m68k->operands[0].reg;
	m68k_reg dst = ctx->m68k->operands[1].reg;
	int src_index = mac_acc_index(src);
	int dst_index = mac_acc_index(dst);
	if (src_index < 0 || dst_index < 0) {
		return NULL;
	}
	RzILOpPure *ext16 = mac_acc_ext16(ctx, src_index);
	if (!ext16) {
		return NULL;
	}
	RzILOpEffect *seq = SEQ5(
		SETL("src", m68k_read_reg_sized(ctx, src, 32)),
		SETL("ext16", ext16),
		SETL("ext_hi", SHIFTR0(UNSIGNED(32, VARL("ext16")), U8(8))),
		SETL("bits_47_31", LOGOR(SHIFTL0(UNSIGNED(32, VARL("ext16")), U8(1)), BOOL_TO_BV(MSB(VARL("src")), 32))),
		SETL("bits_47_39", LOGOR(SHIFTL0(VARL("ext_hi"), U8(1)), BOOL_TO_BV(MSB(VARL("src")), 32))));
	RzILOpEffect *write_acc = m68k_write_reg_sized(ctx, dst, 32, VARL("src"));
	RzILOpEffect *write_ext = mac_write_ext16(ctx, dst_index);
	if (!write_acc || !write_ext) {
		rz_il_op_effect_free(seq);
		rz_il_op_effect_free(write_acc);
		rz_il_op_effect_free(write_ext);
		return NULL;
	}
	return SEQ4(seq, write_acc, write_ext,
		mac_update_macsr_acc_copy(ctx->mode, src_index, dst_index));
}

static RzILOpEffect *lift_move_to_acc(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_acc_reg(&ctx->m68k->operands[1])) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	m68k_reg dst = ctx->m68k->operands[1].reg;
	int acc_index = mac_acc_index(dst);
	if (acc_index < 0) {
		return NULL;
	}
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", src, 32, &seq)) {
		return NULL;
	}
	RzILOpPure *signed_ext = ITE(MSB(VARL("src")), U32(0xffff), U32(0));
	RzILOpPure *frac_ext = ITE(MSB(VARL("src")), U32(0xff00), U32(0));
	seq = SEQ2(seq, SETL("ext16", ITE(macsr_flag(M68K_MACSR_FI), frac_ext, ITE(macsr_signed(), signed_ext, U32(0)))));
	RzILOpEffect *write_acc = m68k_write_reg_sized(ctx, dst, 32, VARL("src"));
	RzILOpEffect *write_ext = mac_write_ext16(ctx, acc_index);
	if (!write_acc || !write_ext) {
		rz_il_op_effect_free(seq);
		rz_il_op_effect_free(write_acc);
		rz_il_op_effect_free(write_ext);
		return NULL;
	}
	ut32 pav = 1u << (M68K_MACSR_PAV0 + acc_index);
	ut32 clear = (1u << M68K_MACSR_N) | (1u << M68K_MACSR_Z) | (1u << M68K_MACSR_V) |
		(1u << M68K_MACSR_EV) | pav;
	RzILOpBool *n = NON_ZERO(LOGAND(VARL("ext16"), U32(0x8000)));
	RzILOpBool *z = AND(IS_ZERO(VARL("src")), IS_ZERO(VARL("ext16")));
	RzILOpPure *flags = LOGAND(VARG("macsr"), U32(~clear));
	flags = LOGOR(flags, ITE(n, U32(1u << M68K_MACSR_N), U32(0)));
	flags = LOGOR(flags, ITE(z, U32(1u << M68K_MACSR_Z), U32(0)));
	return SEQ4(seq, write_acc, write_ext, SETG("macsr", flags));
}

static bool mac_op_is_accext(const cs_m68k_op *op) {
	return op && op->type == M68K_OP_REG &&
		(op->reg == M68K_REG_ACCEXT01 || op->reg == M68K_REG_ACCEXT23);
}

static RzILOpEffect *lift_move_accext(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if (dst->type != M68K_OP_REG) {
		return NULL;
	}
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", src, 32, &seq)) {
		return NULL;
	}
	RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, 32, VARL("src"));
	if (!write) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	return SEQ2(seq, write);
}

static bool mac_op_is_mask(const cs_m68k_op *op) {
	return op && op->type == M68K_OP_REG && op->reg == M68K_REG_MASK;
}

static RzILOpEffect *lift_move_mask(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if (dst->type != M68K_OP_REG) {
		return NULL;
	}
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", src, 32, &seq)) {
		return NULL;
	}
	seq = SEQ2(seq, SETL("masked", LOGOR(LOGAND(VARL("src"), U32(0xffff)), U32(0xffff0000))));
	RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, 32, VARL("masked"));
	if (!write) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	return SEQ2(seq, write);
}

static bool mac_op_is_macsr(const cs_m68k_op *op) {
	return op && op->type == M68K_OP_REG && op->reg == M68K_REG_MACSR;
}

static ut32 macsr_visible_mask(cs_mode mode) {
	/* CFPRM MOVE from MACSR: EMAC clears Rx[31:12]; original MAC clears Rx[31:8]. */
	return rz_m68k_mode_has_emac(mode) ? 0xfffu : 0xffu;
}

static RzILOpEffect *lift_move_macsr(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 2) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if (dst->type != M68K_OP_REG) {
		return NULL;
	}
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", src, 32, &seq)) {
		return NULL;
	}
	seq = SEQ2(seq, SETL("vis", LOGAND(VARL("src"), U32(macsr_visible_mask(ctx->mode)))));
	RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, 32, VARL("vis"));
	if (!write) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	return SEQ2(seq, write);
}

static bool mac_op_is_ccr(const cs_m68k_op *op) {
	return op && op->type == M68K_OP_REG && op->reg == M68K_REG_CCR;
}

static RzILOpEffect *lift_move_macsr_to_ccr(M68KILCtx *ctx) {
	RzILOpEffect *seq = SETL("macsr_src", VARG("macsr"));
	RzILOpPure *ccr = U8(0);
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_N, NON_ZERO(LOGAND(VARL("macsr_src"), U32(1u << M68K_MACSR_N))));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, NON_ZERO(LOGAND(VARL("macsr_src"), U32(1u << M68K_MACSR_Z))));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_V, NON_ZERO(LOGAND(VARL("macsr_src"), U32(1u << M68K_MACSR_V))));
	if (rz_m68k_mode_has_emac(ctx->mode)) {
		ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, NON_ZERO(LOGAND(VARL("macsr_src"), U32(1u << M68K_MACSR_EV))));
	} else {
		ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	}
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_X, IL_FALSE);
	return SEQ2(seq, m68k_set_ccr_from_value(ccr));
}
#endif

static RzILOpEffect *lift_movclr(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_REG || ctx->m68k->operands[1].type != M68K_OP_REG) {
		return NULL;
	}
	m68k_reg acc = ctx->m68k->operands[0].reg;
	m68k_reg dst = ctx->m68k->operands[1].reg;
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	int acc_index = mac_acc_index(acc);
	if (acc_index < 0) {
		return NULL;
	}
	ut32 pav = 1u << (M68K_MACSR_PAV0 + acc_index);
	RzILOpEffect *seq = mac_bind_acc_store(ctx, acc, acc_index);
	if (!seq) {
		return NULL;
	}
	RzILOpEffect *write_dst = m68k_write_reg_sized(ctx, dst, 32, VARL("stored"));
	RzILOpEffect *write_acc = m68k_write_reg_sized(ctx, acc, 32, U32(0));
	RzILOpEffect *write_ext = mac_clear_extension(ctx, acc_index);
	if (!write_dst || !write_acc || !write_ext) {
		rz_il_op_effect_free(seq);
		rz_il_op_effect_free(write_dst);
		rz_il_op_effect_free(write_acc);
		rz_il_op_effect_free(write_ext);
		return NULL;
	}
	return SEQ5(seq, write_dst, write_acc, write_ext,
		SETG("macsr", LOGAND(VARG("macsr"), U32(~pav))));
#else
	return SEQ3(
		SETL("src", m68k_read_reg_sized(ctx, acc, 32)),
		m68k_write_reg_sized(ctx, dst, 32, VARL("src")),
		m68k_write_reg_sized(ctx, acc, 32, U32(0)));
#endif
}

static RzILOpEffect *lift_mvs_mvz(M68KILCtx *ctx, bool sign_extend) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (!rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
		return NULL;
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	rz_return_val_if_fail(bits == 8 || bits == 16, NULL);
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", &ctx->m68k->operands[0], bits, &seq)) {
		return NULL;
	}
	seq = SEQ3(
		seq,
		SETL("res", sign_extend ? SIGNED(32, VARL("src")) : UNSIGNED(32, VARL("src"))),
		m68k_write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, VARL("res")));
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_coldfire_debug_transfer(M68KILCtx *ctx, ut32 bits) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (!rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0])) {
		return NULL;
	}
	const cs_m68k_op *op = &ctx->m68k->operands[0];
	if (op->type == M68K_OP_MEM && op->address_mode == M68K_AM_NONE) {
		return NULL;
	}
	M68KEA ea = m68k_effective_addr(ctx, op, bits);
	if (!ea.addr) {
		return NULL;
	}
	RzILOpEffect *seq = m68k_effect_pre_post(ea.pre,
		SEQ2(SETL("debug_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr)),
			SETL("debug_data", LOADW(bits, VARL("debug_addr")))),
		ea.post);
	seq = SEQ3(
		seq,
		SETL("debug_op", U32(ctx->insn->id == M68K_INS_WDEBUG ? M68K_DEBUG_OP_DEBUG : M68K_DEBUG_OP_DATA)),
		SETL("debug_bits", U32(bits)));
	return SEQ2(seq, m68k_label("m68k_debug"));
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
		seq = seq ? SEQ2(seq, SETL("cp_num", U32(cp_num))) : SETL("cp_num", U32(cp_num));
	}
	M68KCoprocessorOp cp_op = M68K_CP_OP_NOP;
	if (coprocessor_operation(ctx->insn->id, &cp_op)) {
		seq = seq ? SEQ2(seq, SETL("cp_op", U32((ut32)cp_op))) : SETL("cp_op", U32((ut32)cp_op));
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
	seq = seq ? SEQ2(seq, SETL("cp_store", U32(coprocessor_transfer_is_store(ctx) ? 1 : 0))) : SETL("cp_store", U32(coprocessor_transfer_is_store(ctx) ? 1 : 0));
	seq = SEQ2(seq, SETL("cp_bits", U32(bits)));
	if (ctx->m68k->op_count > 2 && ctx->m68k->operands[2].type == M68K_OP_IMM) {
		seq = SEQ2(seq, SETL("cp_selector", U32((ut32)ctx->m68k->operands[2].imm)));
	}
	if (ctx->m68k->op_count > 3 && ctx->m68k->operands[3].type == M68K_OP_IMM) {
		seq = SEQ2(seq, SETL("cp_extension", U32((ut32)ctx->m68k->operands[3].imm)));
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
		M68KEA ea = m68k_effective_addr(ctx, src, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = m68k_effect_pre_post(ea.pre,
			SEQ2(SETL("cp_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr)),
				SETL("cp_data", LOADW(bits, VARL("cp_addr")))),
			ea.post);
	} else {
		RzILOpPure *value = m68k_read_operand(ctx, src, bits, NULL, NULL);
		if (!value) {
			return m68k_label("m68k_coprocessor");
		}
		seq = SETL("cp_data", value);
	}
	seq = append_coprocessor_transfer_metadata(ctx, seq, bits);
	return seq ? SEQ2(seq, m68k_label("m68k_coprocessor")) : m68k_label("m68k_coprocessor");
}

static RzILOpEffect *coprocessor_metadata_only_transfer(M68KILCtx *ctx, ut32 bits) {
	RzILOpEffect *seq = NULL;
	seq = append_coprocessor_transfer_metadata(ctx, seq, bits);
	return seq ? SEQ2(seq, m68k_label("m68k_coprocessor")) : m68k_label("m68k_coprocessor");
}

static RzILOpPure *coprocessor_external_data(ut32 bits) {
	return bits == 32 ? VARG("cp_external_data") : UNSIGNED(bits, VARG("cp_external_data"));
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
		M68KEA ea = m68k_effective_addr(ctx, dst, bits);
		if (!ea.addr) {
			return NULL;
		}
		seq = SEQ2(seq,
			m68k_effect_pre_post(ea.pre,
				SEQ2(SETL("cp_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr)),
					STOREW(VARL("cp_addr"), UNSIGNED(bits, VARL("cp_data")))),
				ea.post));
	} else if (dst->type == M68K_OP_REG) {
		RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, bits, VARL("cp_data"));
		if (!write) {
			return coprocessor_metadata_only_transfer(ctx, bits);
		}
		seq = SEQ2(seq, write);
	} else {
		return coprocessor_metadata_only_transfer(ctx, bits);
	}

	seq = append_coprocessor_transfer_metadata(ctx, seq, bits);
	return seq ? SEQ2(seq, m68k_label("m68k_coprocessor")) : m68k_label("m68k_coprocessor");
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
		seq = seq ? SEQ2(seq, SETL("cp_branch", m68k_read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL))) : SETL("cp_branch", m68k_read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL));
	}
	return SEQ2(seq, m68k_label("m68k_coprocessor"));
}

static RzILOpEffect *lift_coprocessor_nop(M68KILCtx *ctx) {
	RzILOpEffect *seq = append_coprocessor_common(ctx, NULL);
	if (ctx->m68k->op_count > 0 && ctx->m68k->operands[0].type == M68K_OP_IMM) {
		seq = seq ? SEQ2(seq, SETL("cp_extension", U32((ut32)ctx->m68k->operands[0].imm))) : SETL("cp_extension", U32((ut32)ctx->m68k->operands[0].imm));
	}
	return SEQ2(seq, m68k_label("m68k_coprocessor"));
}
#endif

static ut32 fsave_idle_format(cs_mode mode) {
	if (mode == CS_MODE_M68K_060) {
		return M68K_FSAVE_IDLE_060;
	}
	if (mode == CS_MODE_M68K_040) {
		return M68K_FSAVE_IDLE_040;
	}
	if (mode == CS_MODE_M68K_030) {
		return M68K_FSAVE_IDLE_68882;
	}
	return M68K_FSAVE_IDLE_68881;
}

static ut32 fsave_idle_size(cs_mode mode) {
	if (mode == CS_MODE_M68K_060) {
		return M68K_FSAVE_SIZE_060;
	}
	if (mode == CS_MODE_M68K_040) {
		return M68K_FSAVE_SIZE_040;
	}
	if (mode == CS_MODE_M68K_030) {
		return M68K_FSAVE_SIZE_68882;
	}
	return M68K_FSAVE_SIZE_68881;
}

static ut32 fsave_null_size(cs_mode mode) {
	return mode == CS_MODE_M68K_060 ? M68K_FSAVE_SIZE_060 : 4;
}

static RzILOpEffect *fsave_store_idle_frame(RzILOpPure *addr, ut32 format, ut32 size) {
	RzILOpEffect *seq = SEQ2(
		SETL("fpu_state_addr", UNSIGNED(M68K_ADDR_BITS, addr)),
		STOREW(VARL("fpu_state_addr"), U32(format)));
	for (ut32 off = 4; off < size; off += 4) {
		seq = SEQ2(seq, STOREW(ADD(VARL("fpu_state_addr"), U32(off)), U32(0)));
	}
	return seq;
}

static RzILOpEffect *fsave_store_null_frame(RzILOpPure *addr, ut32 size) {
	RzILOpEffect *seq = SEQ2(
		SETL("fpu_state_addr", UNSIGNED(M68K_ADDR_BITS, addr)),
		STOREW(VARL("fpu_state_addr"), U32(0)));
	for (ut32 off = 4; off < size; off += 4) {
		seq = SEQ2(seq, STOREW(ADD(VARL("fpu_state_addr"), U32(off)), U32(0)));
	}
	return seq;
}

static RzILOpEffect *fsave_store_current_frame(RzILOpPure *addr, cs_mode mode) {
	RzILOpPure *null_addr = DUP(addr);
	return BRANCH(NON_ZERO(VARG("fpu_state")),
		fsave_store_null_frame(null_addr, fsave_null_size(mode)),
		fsave_store_idle_frame(addr, fsave_idle_format(mode), fsave_idle_size(mode)));
}

/* UM 6.4.2.1: version zero identifies a null frame and acts as a wildcard;
 * its size byte is ignored. The low 16 bits of the first longword are
 * reserved and are not part of the format word. */
static RzILOpBool *frestore_legacy_is_null_frame(void) {
	return IS_ZERO(LOGAND(VARL("fpu_fmt"), U32(0xff00)));
}

static RzILOpEffect *frestore_bind_frame_size(cs_mode mode) {
	RzILOpPure *size = NULL;
	if (mode == CS_MODE_M68K_060) {
		/* MC68060 UM 6.7: frame format moved to bits 15-8. All
		 * null, idle, and exception frames contain three longwords. */
		size = ITE(NON_ZERO(VARL("fpu_null")), U32(M68K_FSAVE_SIZE_060),
			ITE(EQ(VARL("fpu_fmt"), U32(0x60)), U32(M68K_FSAVE_SIZE_060),
				ITE(EQ(VARL("fpu_fmt"), U32(0xe0)), U32(M68K_FSAVE_SIZE_060), U32(0))));
		return SEQ3(
			SETL("fpu_fmt", LOGAND(SHIFTR0(VARL("fpu_state_format"), U8(8)), U32(0xff))),
			SETL("fpu_null", BOOL_TO_BV(IS_ZERO(VARL("fpu_fmt")), 32)),
			SETL("fpu_frame_size", size));
	}
	if (mode == CS_MODE_M68K_040) {
		size = ITE(OR(NON_ZERO(VARL("fpu_null")), EQ(VARL("fpu_fmt"), U32(0x4100))), U32(4),
			ITE(EQ(VARL("fpu_fmt"), U32(M68K_FRESTORE_UNIMP_040)), U32(52),
				ITE(EQ(VARL("fpu_fmt"), U32(M68K_FRESTORE_BUSY_040)), U32(100), U32(0))));
	} else if (mode == CS_MODE_M68K_030) {
		size = ITE(NON_ZERO(VARL("fpu_null")), U32(4),
			ITE(EQ(VARL("fpu_fmt"), U32(0x1f38)), U32(M68K_FSAVE_SIZE_68882),
				ITE(EQ(VARL("fpu_fmt"), U32(M68K_FRESTORE_BUSY_68882)), U32(216), U32(0))));
	} else {
		size = ITE(NON_ZERO(VARL("fpu_null")), U32(4),
			ITE(EQ(VARL("fpu_fmt"), U32(0x1f18)), U32(M68K_FSAVE_SIZE_68881),
				ITE(EQ(VARL("fpu_fmt"), U32(M68K_FRESTORE_BUSY_68881)), U32(184), U32(0))));
	}
	return SEQ3(
		SETL("fpu_fmt", SHIFTR0(VARL("fpu_state_format"), U8(16))),
		SETL("fpu_null", BOOL_TO_BV(frestore_legacy_is_null_frame(), 32)),
		SETL("fpu_frame_size", size));
}

/* MC68881 UM 4-88 / PRM 5-164 / MC68060 UM 6.7: restoring a null
 * frame is a hardware reset of the FPU programmer's model. */
static RzILOpPure *frestore_reset_nan_bits(void) {
	/* UM 3.2.5: an FPCP-created NAN has every mantissa bit set. */
	return APPEND(U16(0x7fff), U64(0xffffffffffffffffULL));
}

static RzILOpEffect *frestore_reset_null_programmer_model(void) {
	return SEQN(11,
		SETG("fp0", frestore_reset_nan_bits()),
		SETG("fp1", frestore_reset_nan_bits()),
		SETG("fp2", frestore_reset_nan_bits()),
		SETG("fp3", frestore_reset_nan_bits()),
		SETG("fp4", frestore_reset_nan_bits()),
		SETG("fp5", frestore_reset_nan_bits()),
		SETG("fp6", frestore_reset_nan_bits()),
		SETG("fp7", frestore_reset_nan_bits()),
		SETG("fpcr", U32(0)),
		SETG("fpsr", U32(0)),
		SETG("fpiar", U32(0)));
}

static RzILOpEffect *frestore_apply_programmer_model(void) {
	return SEQ2(
		BRANCH(NON_ZERO(VARL("fpu_null")),
			frestore_reset_null_programmer_model(),
			NOP()),
		SETG("fpu_state", VARL("fpu_null")));
}

static RzILOpEffect *lift_fpu_state_address_effects(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1) {
		return NULL;
	}
	if (!rz_m68k_mode_has_fsave(ctx->mode)) {
		return BRANCH(m68k_supervisor_mode(), m68k_label("m68k_illegal"), m68k_label("m68k_privilege"));
	}

	const cs_m68k_op *op = &ctx->m68k->operands[0];
	if (op->type == M68K_OP_MEM && op->address_mode == M68K_AM_NONE) {
		return NULL;
	}
	if (!rz_m68k_op_is_mem_addr(op)) {
		return NULL;
	}

	const bool is_restore = ctx->insn->id == M68K_INS_FRESTORE;
	const ut32 idle_size = fsave_idle_size(ctx->mode);
	const ut32 null_size = fsave_null_size(ctx->mode);

	if (op->address_mode == M68K_AM_REGI_ADDR_PRE_DEC) {
		if (is_restore) {
			return NULL;
		}
		m68k_reg base_reg = rz_m68k_op_base_reg(op);
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return NULL;
		}
		RzILOpEffect *update_addr = m68k_write_reg_sized(ctx, base_reg, 32,
			SUB(m68k_reg_value(ctx, base_reg), VARL("fpu_frame_size")));
		if (!update_addr) {
			return NULL;
		}
		RzILOpEffect *seq = SEQ3(
			SETL("fpu_frame_size", ITE(NON_ZERO(VARG("fpu_state")), U32(null_size), U32(idle_size))),
			update_addr,
			fsave_store_current_frame(m68k_reg_value(ctx, base_reg), ctx->mode));
		return m68k_guard_supervisor(seq);
	}
	if (op->address_mode == M68K_AM_REGI_ADDR_POST_INC) {
		if (!is_restore) {
			return NULL;
		}
		m68k_reg base_reg = rz_m68k_op_base_reg(op);
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return NULL;
		}
		RzILOpEffect *seq = SEQ3(
			SETL("fpu_state_addr", UNSIGNED(M68K_ADDR_BITS, m68k_reg_value(ctx, base_reg))),
			SETL("fpu_state_format", LOADW(32, VARL("fpu_state_addr"))),
			frestore_bind_frame_size(ctx->mode));
		RzILOpEffect *update_addr = m68k_write_reg_sized(ctx, base_reg, 32, ADD(VARL("fpu_state_addr"), VARL("fpu_frame_size")));
		if (!update_addr) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		RzILOpEffect *ok = SEQ2(frestore_apply_programmer_model(), update_addr);
		seq = SEQ2(seq, BRANCH(IS_ZERO(VARL("fpu_frame_size")), m68k_exception(M68K_TRAP_OP_FORMAT, M68K_VECTOR_FORMAT_ERROR, "m68k_trap"), ok));
		return m68k_guard_supervisor(seq);
	}

	M68KEA ea = m68k_effective_addr(ctx, op, 32);
	if (!ea.addr) {
		m68k_ea_fini(&ea);
		return NULL;
	}

	RzILOpEffect *seq = m68k_effect_pre_post(ea.pre,
		SETL("fpu_state_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr)), ea.post);
	if (is_restore) {
		seq = SEQ4(
			seq,
			SETL("fpu_state_format", LOADW(32, VARL("fpu_state_addr"))),
			frestore_bind_frame_size(ctx->mode),
			BRANCH(IS_ZERO(VARL("fpu_frame_size")), m68k_exception(M68K_TRAP_OP_FORMAT, M68K_VECTOR_FORMAT_ERROR, "m68k_trap"), frestore_apply_programmer_model()));
	} else {
		seq = SEQ2(seq, fsave_store_current_frame(VARL("fpu_state_addr"), ctx->mode));
	}
	return m68k_guard_supervisor(seq);
}

static RzILOpPure *callm_frame_addr(ut32 offset) {
	return offset ? ADD(VARL("callm_frame"), U32(offset)) : VARL("callm_frame");
}

static const m68k_reg m68k_data_addr_regs[] = {
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

static m68k_reg callm_reg_from_code(ut32 code) {
	return code < RZ_ARRAY_SIZE(m68k_data_addr_regs) ? m68k_data_addr_regs[code] : M68K_REG_INVALID;
}

static RzILOpBool *callm_reg_code_is(ut32 code) {
	return EQ(VARL("callm_reg_code"), U32(code));
}

static RzILOpEffect *callm_store_selected_reg(M68KILCtx *ctx) {
	RzILOpEffect *effect = EMPTY();
	for (st32 code = 15; code >= 0; code--) {
		m68k_reg reg = callm_reg_from_code((ut32)code);
		RzILOpPure *value = m68k_read_reg_sized(ctx, reg, 32);
		RzILOpEffect *store = value ? STOREW(callm_frame_addr(0x10), value) : NULL;
		if (!store) {
			rz_warn_if_reached();
			return NULL;
		}
		effect = BRANCH(callm_reg_code_is((ut32)code), store, effect);
	}
	return effect;
}

static RzILOpEffect *callm_load_selected_reg(M68KILCtx *ctx) {
	RzILOpEffect *effect = EMPTY();
	for (st32 code = 14; code >= 0; code--) {
		m68k_reg reg = callm_reg_from_code((ut32)code);
		RzILOpEffect *write = m68k_write_reg_sized(ctx, reg, 32, VARL("callm_data"));
		if (!write) {
			rz_warn_if_reached();
			return NULL;
		}
		effect = BRANCH(callm_reg_code_is((ut32)code), write, effect);
	}
	return effect;
}

static RzILOpEffect *lift_callm_type0(M68KILCtx *ctx) {
	return SEQN(11,
		callm_store_selected_reg(ctx),
		STOREW(callm_frame_addr(0), UNSIGNED(16, VARL("callm_frame_info"))),
		SETL("callm_ccr_arg", LOGOR(SHIFTL0(UNSIGNED(16, UNSIGNED(8, VARG("sr"))), U8(8)), UNSIGNED(16, VARL("callm_count")))),
		STOREW(callm_frame_addr(2), UNSIGNED(16, VARL("callm_ccr_arg"))),
		STOREW(callm_frame_addr(4), UNSIGNED(32, VARL("callm_addr"))),
		STOREW(callm_frame_addr(8), m68k_reg_value(ctx, M68K_REG_A7)),
		STOREW(callm_frame_addr(0x0c), U32(ctx->next_addr)),
		STOREW(callm_frame_addr(0x14), U32(0)),
		m68k_write_reg_sized(ctx, M68K_REG_A7, 32, VARL("callm_frame")),
		callm_load_selected_reg(ctx),
		JMP(ADD(VARL("callm_entry"), U32(2))));
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

	M68KEA ea = m68k_effective_addr(ctx, target, 32);
	if (!ea.addr) {
		return NULL;
	}

	RzILOpEffect *seq = SEQ8(
		SETL("callm_count", U32((ut32)(ctx->m68k->operands[0].imm & 0xff))),
		SETL("callm_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr)),
		SETL("callm_frame_info", LOADW(16, VARL("callm_addr"))),
		SETL("callm_entry", LOADW(32, ADD(VARL("callm_addr"), U32(4)))),
		SETL("callm_data", LOADW(32, ADD(VARL("callm_addr"), U32(8)))),
		SETL("callm_entry_word", LOADW(16, VARL("callm_entry"))),
		SETL("callm_reg_code", UNSIGNED(32, SHIFTR0(VARL("callm_entry_word"), U8(12)))),
		SETL("callm_frame", SUB(m68k_reg_value(ctx, M68K_REG_A7), U32(0x18))));
	seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
	return SEQ2(seq, BRANCH(IS_ZERO(LOGAND(VARL("callm_frame_info"), U16(0xff00))), lift_callm_type0(ctx), m68k_label("m68k_callm")));
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
		if (RZ_STR_EQ(name, "srp") || RZ_STR_EQ(name, "crp")) {
			return 64;
		}
		if (RZ_STR_EQ(name, "mmusr")) {
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
	if (RZ_STR_EQ(name, "mmusr")) {
		return 16;
	}
	if (RZ_STR_EQ(name, "srp") || RZ_STR_EQ(name, "crp")) {
		return 64;
	}
	if (RZ_STR_EQ(name, "tc") ||
		RZ_STR_EQ(name, "itt0") || RZ_STR_EQ(name, "itt1") ||
		RZ_STR_EQ(name, "dtt0") || RZ_STR_EQ(name, "dtt1") ||
		RZ_STR_EQ(name, "tt0") || RZ_STR_EQ(name, "tt1")) {
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

/**
 * \brief Transfer direction encoded by an MMU instruction.
 * \return 0 for a read, 1 for a write, or -1 when the instruction has no direction.
 */
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
		RzILOpPure *value = m68k_read_reg_sized(ctx, op->reg, 32);
		return value;
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
				seq = seq ? SEQ2(seq, SETL("mmu_fc", fc)) : SETL("mmu_fc", fc);
			}
		}
		if ((ctx->insn->id == M68K_INS_PTESTR || ctx->insn->id == M68K_INS_PTESTW) &&
			ctx->m68k->op_count > 2 && ctx->m68k->operands[2].type == M68K_OP_IMM) {
			seq = SEQ2(seq, SETL("mmu_level", U32((ut32)ctx->m68k->operands[2].imm)));
		}
		break;
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHN:
		if (ctx->m68k->op_count > 2) {
			RzILOpPure *fc = mmu_function_code_value(ctx, &ctx->m68k->operands[0]);
			if (fc) {
				seq = SEQ2(seq, SETL("mmu_fc", fc));
			}
			if (ctx->m68k->operands[1].type == M68K_OP_IMM) {
				seq = SEQ2(seq, SETL("mmu_mask", U32((ut32)ctx->m68k->operands[1].imm)));
			}
		}
		break;
	default:
		break;
	}
	return seq;
}

static RzILOpEffect *append_mmu_metadata(M68KILCtx *ctx, RzILOpEffect *seq) {
	seq = seq ? SEQ2(seq, SETL("mmu_op", U32((ut32)mmu_operation(ctx->insn->id)))) : SETL("mmu_op", U32((ut32)mmu_operation(ctx->insn->id)));
	int rw = mmu_read_write_access(ctx->insn->id);
	if (rw >= 0) {
		seq = SEQ2(seq, SETL("mmu_rw", U32((ut32)rw)));
	}
	switch (ctx->insn->id) {
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHN:
	case M68K_INS_PFLUSHA:
	case M68K_INS_PFLUSHAN:
		seq = SEQ2(seq, SETL("mmu_flush_non_global", U32(ctx->insn->id == M68K_INS_PFLUSHN || ctx->insn->id == M68K_INS_PFLUSHAN ? 1 : 0)));
		break;
	case M68K_INS_PMOVEFD:
		seq = SEQ2(seq, SETL("mmu_fd", U32(1)));
		break;
	default:
		break;
	}
	return append_mmu_operand_metadata(ctx, seq);
}

static RzILOpEffect *lift_mmu_address_effects(M68KILCtx *ctx, ut32 bits) {
	RzILOpEffect *seq = NULL;
	const cs_m68k_op *op = mmu_address_operand(ctx);
	if (op) {
		if (op->type == M68K_OP_MEM && !op->address_mode) {
			return NULL;
		}
		if (rz_m68k_op_is_gpr(op)) {
			RzILOpPure *addr = m68k_read_reg_sized(ctx, op->reg, M68K_ADDR_BITS);
			if (!addr) {
				return NULL;
			}
			seq = SETL("mmu_addr", UNSIGNED(M68K_ADDR_BITS, addr));
		} else if (op->type == M68K_OP_IMM) {
			seq = SETL("mmu_addr", U32((ut32)op->imm));
		} else if (!rz_m68k_op_is_mem_addr(op)) {
			return m68k_label("m68k_mmu");
		} else {
			M68KEA ea = m68k_effective_addr(ctx, op, bits);
			if (!ea.addr) {
				m68k_ea_fini(&ea);
				return NULL;
			}
			seq = SETL("mmu_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr));
			seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
		}
	}
	seq = append_mmu_metadata(ctx, seq);
	return SEQ2(seq, m68k_label("m68k_mmu"));
}

static RzILOpEffect *lift_mmu_flush_all(M68KILCtx *ctx) {
	RzILOpEffect *seq = NULL;
	seq = append_mmu_metadata(ctx, seq);
	seq = SEQ2(seq, SETL("mmu_flush_all", U32(1)));
	return SEQ2(seq, m68k_label("m68k_mmu"));
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
	seq = seq ? SEQ2(seq, SETL("cache_op", U32((ut32)cache_operation(ctx->insn->id)))) : SETL("cache_op", U32((ut32)cache_operation(ctx->insn->id)));
	if (ctx->m68k->op_count > 0 && ctx->m68k->operands[0].type == M68K_OP_IMM) {
		seq = SEQ2(seq, SETL("cache_selector", U32((ut32)ctx->m68k->operands[0].imm)));
	}
	if (all_scope) {
		seq = SEQ2(seq, SETL("cache_all", U32(1)));
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
			return NULL;
		}
		seq = append_cache_metadata(ctx, seq, true);
		return SEQ2(seq, m68k_label("m68k_cache"));
	}
	if (op->type == M68K_OP_MEM && !op->address_mode) {
		if (needs_address) {
			return NULL;
		}
		seq = append_cache_metadata(ctx, seq, true);
		return SEQ2(seq, m68k_label("m68k_cache"));
	}
	if (rz_m68k_op_is_addr_reg(op)) {
		RzILOpPure *addr = m68k_read_reg_sized(ctx, op->reg, M68K_ADDR_BITS);
		if (!addr) {
			return NULL;
		}
		seq = SETL("cache_addr", UNSIGNED(M68K_ADDR_BITS, addr));
		seq = append_cache_metadata(ctx, seq, false);
		return SEQ2(seq, m68k_label("m68k_cache"));
	}
	if (!rz_m68k_op_is_mem_addr(op)) {
		return m68k_label(needs_address ? "m68k_illegal" : "m68k_cache");
	}

	M68KEA ea = m68k_effective_addr(ctx, op, 32);
	if (!ea.addr) {
		m68k_ea_fini(&ea);
		return NULL;
	}
	seq = SETL("cache_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr));
	seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
	seq = append_cache_metadata(ctx, seq, false);
	return SEQ2(seq, m68k_label("m68k_cache"));
}

static RzILOpEffect *lift_pmove(M68KILCtx *ctx) {
	if (ctx->m68k->op_count != 2) {
		return lift_mmu_address_effects(ctx, pmove_address_bits(ctx));
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
			return lift_mmu_address_effects(ctx, pmove_address_bits(ctx));
		}
		RzILOpPure *value = m68k_read_operand(ctx, src, bits, NULL, NULL);
		if (!value) {
			return NULL;
		}
		RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, bits, VARL("src"));
		if (!write) {
			rz_il_op_pure_free(value);
			return NULL;
		}
		return SEQ2(SETL("src", value), write);
	} else {
		return lift_mmu_address_effects(ctx, pmove_address_bits(ctx));
	}

	ut32 bits = pmove_transfer_bits(ctx, reg->reg);
	if (!bits) {
		return lift_mmu_address_effects(ctx, pmove_address_bits(ctx));
	}
	if (mem->type == M68K_OP_MEM && !mem->address_mode) {
		return NULL;
	}
	if (!rz_m68k_op_is_mem_addr(mem)) {
		return lift_mmu_address_effects(ctx, bits);
	}

	M68KEA ea = m68k_effective_addr(ctx, mem, bits);
	if (!ea.addr) {
		m68k_ea_fini(&ea);
		return NULL;
	}

	RzILOpEffect *seq = SETL("mmu_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr));
	if (mem_to_reg) {
		seq = m68k_effect_pre_post(ea.pre,
			SEQ2(seq, SETL("src", LOADW(bits, VARL("mmu_addr")))),
			ea.post);
		RzILOpEffect *write = m68k_write_reg_sized(ctx, reg->reg, bits, VARL("src"));
		if (!write) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		return SEQ2(seq, write);
	}

	RzILOpPure *value = m68k_read_reg_sized(ctx, reg->reg, bits);
	if (!value) {
		rz_il_op_effect_free(seq);
		rz_il_op_effect_free(ea.pre);
		rz_il_op_effect_free(ea.post);
		return NULL;
	}
	return m68k_effect_pre_post(ea.pre,
		SEQ3(seq, SETL("src", value), STOREW(VARL("mmu_addr"), UNSIGNED(bits, VARL("src")))),
		ea.post);
}

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static RzILOpEffect *lift_coldfire_bitop_reg(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (!rz_m68k_op_is_data_reg(&ctx->m68k->operands[0])) {
		return NULL;
	}
	m68k_reg reg = ctx->m68k->operands[0].reg;
	RzILOpEffect *seq = SEQ2(
		SETL("src", m68k_read_reg_sized(ctx, reg, 32)),
		SETL("res", ctx->insn->id == M68K_INS_BITREV ? reverse_bits32("src") : ctx->insn->id == M68K_INS_BYTEREV ? reverse_bytes32("src")
															 : ff1_result32("src")));
	seq = seq ? SEQ2(seq, m68k_write_reg_sized(ctx, reg, 32, VARL("res"))) : m68k_write_reg_sized(ctx, reg, 32, VARL("res"));
	if (ctx->insn->id == M68K_INS_FF1) {
		seq = SEQ2(seq, set_flags_ff1(VARL("src")));
	}
	return seq;
}

static RzILOpEffect *lift_rem(M68KILCtx *ctx, bool sign) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (!rz_m68k_op_is_data_reg_pair(&ctx->m68k->operands[1])) {
		return NULL;
	}
	m68k_reg dw = ctx->m68k->operands[1].reg_pair.reg_0;
	m68k_reg dx = ctx->m68k->operands[1].reg_pair.reg_1;
	if (dw == dx) {
		return NULL;
	}
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", &ctx->m68k->operands[0], 32, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpPure *dst = m68k_read_reg_sized(ctx, dx, 32);
	if (!dst) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, SETL("dst", dst));

	RzILOpPure *dividend = sign ? SIGNED(64, VARL("dst")) : UNSIGNED(64, VARL("dst"));
	RzILOpPure *divisor = sign ? SIGNED(64, VARL("src")) : UNSIGNED(64, VARL("src"));
	RzILOpEffect *write_remainder = m68k_write_reg_sized(ctx, dw, 32, UNSIGNED(32, VARL("rem")));
	if (!write_remainder) {
		rz_il_op_pure_free(dividend);
		rz_il_op_pure_free(divisor);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpEffect *normal = SEQ4(
		SETL("quot", sign ? SDIV(dividend, divisor) : DIV(dividend, divisor)),
		SETL("rem", SUB(sign ? SIGNED(64, VARL("dst")) : UNSIGNED(64, VARL("dst")), MUL(VARL("quot"), sign ? SIGNED(64, VARL("src")) : UNSIGNED(64, VARL("src"))))),
		write_remainder,
		set_flags_rem(VARL("quot"), IL_FALSE));
	RzILOpBool *overflow = sign
		? AND(EQ(VARL("dst"), U32(0x80000000)), EQ(VARL("src"), U32(0xffffffff)))
		: UGT(DIV(UNSIGNED(64, VARL("dst")), UNSIGNED(64, VARL("src"))), U64(0x7fffffff));
	RzILOpEffect *do_divide = BRANCH(overflow, set_flags_rem(U32(0), IL_TRUE), normal);
	return SEQ2(seq, BRANCH(IS_ZERO(VARL("src")), m68k_exception(M68K_TRAP_OP_DIV_ZERO, M68K_VECTOR_ZERO_DIVIDE, "m68k_trap"), do_divide));
}

static RzILOpEffect *lift_sats(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (!rz_m68k_op_is_data_reg(&ctx->m68k->operands[0])) {
		return NULL;
	}
	m68k_reg reg = ctx->m68k->operands[0].reg;
	return SEQ4(
		SETL("src", m68k_read_reg_sized(ctx, reg, 32)),
		SETL("res", ITE(m68k_ccr_bit(M68K_CCR_V), ITE(MSB(VARL("src")), U32(0x7fffffffu), U32(0x80000000u)), VARL("src"))),
		m68k_write_reg_sized(ctx, reg, 32, VARL("res")),
		m68k_set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpBool *macsr_signed(void) {
	/* ColdFire PRM integer mode: S/U=0 signed, S/U=1 unsigned.
	 * QEMU treats MACSR_SU the other way around; do not follow QEMU. */
	return IS_ZERO(LOGAND(VARG("macsr"), U32(1u << M68K_MACSR_SU)));
}

static RzILOpBool *mac_mode_signed(void) {
	/* Fractional operands are always two's-complement signed. In fractional
	 * mode S/U selects the store width rather than operand signedness. */
	return OR(macsr_flag(M68K_MACSR_FI), macsr_signed());
}

static RzILOpPure *mac_read_reg_part(M68KILCtx *ctx, const cs_m68k_op *op, ut32 bits) {
	if (!rz_m68k_op_is_gpr(op)) {
		return NULL;
	}
	RzILOpPure *value = m68k_read_reg_sized(ctx, op->reg, 32);
	if (!value) {
		return NULL;
	}
	if (bits == 16) {
		const bool upper = op->flags & M68K_OP_FLAG_REG_UPPER;
		RzILOpPure *fractional_half = upper
			? LOGAND(DUP(value), U32(0xffff0000))
			: SHIFTL0(DUP(value), U8(16));
		value = upper ? SHIFTR0(value, U8(16)) : value;
		value = UNSIGNED(16, value);
		RzILOpPure *unsigned_half = DUP(value);
		RzILOpPure *integer_half = ITE(macsr_signed(), SIGNED(32, value), UNSIGNED(32, unsigned_half));
		return ITE(macsr_flag(M68K_MACSR_FI), fractional_half, integer_half);
	}
	return value;
}

static RzILOpBool *mac_local_out_of_range(const char *local, ut32 bits) {
	return ITE(mac_mode_signed(),
		NE(SIGNED(80, SIGNED(bits, VARL(local))), VARL(local)),
		NON_ZERO(SHIFTR0(VARL(local), U8((ut8)bits))));
}

static RzILOpEffect *mac_bind_product(cs_mode mode, const cs_m68k_op *shift) {
	const ut32 product_bits = rz_m68k_mode_has_emac(mode) ? 40 : 32;
	const ut32 fractional_shift = 64 - product_bits;
	const ut64 remainder_mask = (1ULL << fractional_shift) - 1;
	const ut64 halfway = 1ULL << (fractional_shift - 1);

	RzILOpEffect *seq = SETL("prod_wide",
		ITE(mac_mode_signed(),
			MUL(SIGNED(80, VARL("src0")), SIGNED(80, VARL("src1"))),
			MUL(UNSIGNED(80, VARL("src0")), UNSIGNED(80, VARL("src1")))));
	RzILOpPure *scaled = VARL("prod_wide");
	if (shift) {
		if (shift->flags & M68K_OP_FLAG_SHIFT_LEFT) {
			scaled = SHIFTL0(scaled, U8(1));
		} else {
			scaled = ITE(mac_mode_signed(), SHIFTRA(DUP(scaled), U8(1)), SHIFTR0(scaled, U8(1)));
		}
	}
	seq = SEQ2(seq, SETL("prod_scaled", scaled));

	/* The CFPRM specifies that the encoded scale factor is ignored for
	 * fractional operands, so truncation and rounding use prod_wide. */
	RzILOpPure *fractional_truncated = SHIFTR0(VARL("prod_wide"), U8((ut8)fractional_shift));
	RzILOpPure *remainder = LOGAND(VARL("prod_wide"), UN(80, remainder_mask));
	RzILOpBool *round_fractional = AND(
		macsr_flag(M68K_MACSR_RT),
		OR(
			UGT(DUP(remainder), UN(80, halfway)),
			AND(EQ(remainder, UN(80, halfway)), NON_ZERO(LOGAND(DUP(fractional_truncated), UN(80, 1))))));
	RzILOpPure *fractional_product = SIGNED(64,
		UNSIGNED(product_bits,
			ADD(fractional_truncated, ITE(round_fractional, UN(80, 1), UN(80, 0)))));
	RzILOpPure *integer_product_bits = UNSIGNED(product_bits, VARL("prod_scaled"));
	RzILOpPure *integer_product = ITE(macsr_signed(),
		SIGNED(64, DUP(integer_product_bits)),
		UNSIGNED(64, integer_product_bits));
	return SEQ3(seq,
		SETL("prod", ITE(macsr_flag(M68K_MACSR_FI), fractional_product, integer_product)),
		SETL("prod_overflow", ITE(macsr_flag(M68K_MACSR_FI), U32(0), ITE(mac_local_out_of_range("prod_scaled", product_bits), U32(1), U32(0)))));
}

static RzILOpEffect *mac_bind_acc(M68KILCtx *ctx, m68k_reg acc_reg, int acc_index) {
	rz_return_val_if_fail(ctx, NULL);
	RzILOpPure *acc = m68k_read_reg_sized(ctx, acc_reg, 32);
	if (!acc) {
		return NULL;
	}
	if (!rz_m68k_mode_has_emac(ctx->mode)) {
		return SEQ2(
			SETL("acc_full", acc),
			SETL("acc", ITE(mac_mode_signed(), SIGNED(64, VARL("acc_full")), UNSIGNED(64, VARL("acc_full")))));
	}
	RzILOpPure *ext = mac_acc_ext16(ctx, acc_index);
	if (!ext) {
		rz_il_op_pure_free(acc);
		return NULL;
	}
	RzILOpPure *fractional = LOGOR(
		SHIFTL0(UNSIGNED(48, SHIFTR0(VARL("acc_ext"), U8(8))), U8(40)),
		LOGOR(
			SHIFTL0(UNSIGNED(48, VARL("acc_word")), U8(8)),
			UNSIGNED(48, LOGAND(VARL("acc_ext"), U16(0xff)))));
	RzILOpPure *integer = LOGOR(
		SHIFTL0(UNSIGNED(48, VARL("acc_ext")), U8(32)),
		UNSIGNED(48, VARL("acc_word")));
	return SEQ4(
		SETL("acc_word", acc),
		SETL("acc_ext", ext),
		SETL("acc_full", ITE(macsr_flag(M68K_MACSR_FI), fractional, integer)),
		SETL("acc", ITE(mac_mode_signed(), SIGNED(64, VARL("acc_full")), UNSIGNED(64, VARL("acc_full")))));
}

static RzILOpPure *mac_accumulate_result(bool subtract) {
	RzILOpPure *signed_result = subtract
		? SUB(SIGNED(80, VARL("acc")), SIGNED(80, VARL("prod")))
		: ADD(SIGNED(80, VARL("acc")), SIGNED(80, VARL("prod")));
	RzILOpPure *unsigned_result = subtract
		? SUB(UNSIGNED(80, VARL("acc")), UNSIGNED(80, VARL("prod")))
		: ADD(UNSIGNED(80, VARL("acc")), UNSIGNED(80, VARL("prod")));
	return ITE(mac_mode_signed(), signed_result, unsigned_result);
}

static RzILOpEffect *mac_bind_result(cs_mode mode) {
	if (!rz_m68k_mode_has_emac(mode)) {
		return SEQ2(
			SETL("res_full", UNSIGNED(32, VARL("res_wide"))),
			SETL("res", VARL("res_full")));
	}
	RzILOpPure *fractional_ext = LOGOR(
		SHIFTL0(UNSIGNED(16, SHIFTR0(VARL("res_full"), U8(40))), U8(8)),
		UNSIGNED(16, LOGAND(VARL("res_full"), UN(48, 0xff))));
	RzILOpPure *integer_ext = UNSIGNED(16, SHIFTR0(VARL("res_full"), U8(32)));
	RzILOpPure *fractional_acc = UNSIGNED(32, SHIFTR0(VARL("res_full"), U8(8)));
	RzILOpPure *integer_acc = UNSIGNED(32, VARL("res_full"));
	return SEQ3(
		SETL("res_full", UNSIGNED(48, VARL("res_wide"))),
		SETL("res", ITE(macsr_flag(M68K_MACSR_FI), fractional_acc, integer_acc)),
		SETL("ext16", ITE(macsr_flag(M68K_MACSR_FI), fractional_ext, integer_ext)));
}

static RzILOpEffect *mac_write_result(M68KILCtx *ctx, m68k_reg acc_reg, int acc_index) {
	rz_return_val_if_fail(ctx, NULL);
	RzILOpEffect *write_acc = m68k_write_reg_sized(ctx, acc_reg, 32, VARL("res"));
	if (!write_acc) {
		return NULL;
	}
	if (!rz_m68k_mode_has_emac(ctx->mode)) {
		return write_acc;
	}
	RzILOpEffect *write_ext = mac_write_ext16(ctx, acc_index);
	if (!write_ext) {
		rz_il_op_effect_free(write_acc);
		return NULL;
	}
	return SEQ2(write_acc, write_ext);
}

static RzILOpBool *mac_result_out_of_range(ut32 bits) {
	return mac_local_out_of_range("res_wide", bits);
}

static RzILOpBool *mac_accumulation_overflow(cs_mode mode) {
	return mac_result_out_of_range(rz_m68k_mode_has_emac(mode) ? 48 : 32);
}

static RzILOpBool *mac_operation_overflow(cs_mode mode) {
	return OR(NON_ZERO(VARL("prod_overflow")), mac_accumulation_overflow(mode));
}

static RzILOpBool *mac_extension_overflow(void) {
	return ITE(macsr_flag(M68K_MACSR_FI),
		mac_result_out_of_range(40),
		mac_result_out_of_range(32));
}

static RzILOpEffect *mac_update_macsr(cs_mode mode, int acc_index) {
	const bool emac = rz_m68k_mode_has_emac(mode);
	ut32 clear = (1u << M68K_MACSR_N) | (1u << M68K_MACSR_Z) | (1u << M68K_MACSR_V);
	if (emac) {
		clear |= 1u << M68K_MACSR_EV;
	}
	RzILOpBool *overflow = mac_operation_overflow(mode);
	RzILOpPure *flags = LOGAND(VARG("macsr"), U32(~clear));
	flags = LOGOR(flags, ITE(MSB(VARL("res_full")), U32(1u << M68K_MACSR_N), U32(0)));
	flags = LOGOR(flags, ITE(IS_ZERO(VARL("res_full")), U32(1u << M68K_MACSR_Z), U32(0)));
	if (emac) {
		ut32 pav = 1u << (M68K_MACSR_PAV0 + acc_index);
		RzILOpBool *past_overflow = NON_ZERO(LOGAND(VARG("macsr"), U32(pav)));
		flags = LOGOR(flags, ITE(OR(DUP(overflow), past_overflow), U32(1u << M68K_MACSR_V), U32(0)));
		flags = LOGOR(flags, ITE(mac_extension_overflow(), U32(1u << M68K_MACSR_EV), U32(0)));
		flags = LOGOR(flags, ITE(overflow, U32(pav), U32(0)));
	} else {
		flags = LOGOR(flags, ITE(overflow, U32(1u << M68K_MACSR_V), U32(0)));
	}
	return SETG("macsr", flags);
}

/* CFPRM MAAAC/MASAC/MSAAC/MSSAC: N/Z/V/EV come from the secondary
 * accumulator. V is also set when PAVw was already set. PAVx and PAVw
 * are set on overflow of that destination and otherwise left alone. */
static RzILOpEffect *mac_update_macsr_dual(cs_mode mode, int first_index, int second_index) {
	const bool emac = rz_m68k_mode_has_emac(mode);
	ut32 clear = (1u << M68K_MACSR_N) | (1u << M68K_MACSR_Z) | (1u << M68K_MACSR_V);
	if (emac) {
		clear |= 1u << M68K_MACSR_EV;
	}
	ut32 pav_first = 1u << (M68K_MACSR_PAV0 + first_index);
	ut32 pav_second = 1u << (M68K_MACSR_PAV0 + second_index);
	RzILOpBool *v = OR(NON_ZERO(VARL("ov_second")),
		NON_ZERO(LOGAND(VARG("macsr"), U32(pav_second))));
	RzILOpPure *flags = LOGAND(VARG("macsr"), U32(~clear));
	flags = LOGOR(flags, ITE(MSB(VARL("res_full")), U32(1u << M68K_MACSR_N), U32(0)));
	flags = LOGOR(flags, ITE(IS_ZERO(VARL("res_full")), U32(1u << M68K_MACSR_Z), U32(0)));
	flags = LOGOR(flags, ITE(v, U32(1u << M68K_MACSR_V), U32(0)));
	if (emac) {
		flags = LOGOR(flags, ITE(NON_ZERO(VARL("ev_second")), U32(1u << M68K_MACSR_EV), U32(0)));
	}
	flags = LOGOR(flags, ITE(NON_ZERO(VARL("ov_first")), U32(pav_first), U32(0)));
	flags = LOGOR(flags, ITE(NON_ZERO(VARL("ov_second")), U32(pav_second), U32(0)));
	return SETG("macsr", flags);
}

static RzILOpEffect *mac_memory_update(M68KILCtx *ctx, RzILOpEffect *seq, const cs_m68k_op *mem, const cs_m68k_op *reg) {
	if (!mem || !reg || !rz_m68k_op_is_gpr(reg)) {
		return seq;
	}
	/* Parallel load is always a longword; MASK applies only to the load address.
	 * Predecrement/postincrement writeback uses the unmasked EA (ColdFire PRM). */
	M68KEA ea = m68k_effective_addr(ctx, mem, 32);
	if (!ea.addr) {
		m68k_ea_fini(&ea);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpEffect *write = m68k_write_reg_sized(ctx, reg->reg, 32, VARL("mem_load"));
	if (!write) {
		m68k_ea_fini(&ea);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpEffect *access = m68k_effect_pre_post(ea.pre,
		SEQ3(SETL("mem_addr", LOGAND(UNSIGNED(32, ea.addr), VARG("mask"))),
			SETL("mem_load", LOADW(32, VARL("mem_addr"))),
			write),
		ea.post);
	return seq ? SEQ2(seq, access) : access;
}

static RzILOpEffect *lift_mac_msac(M68KILCtx *ctx, bool subtract) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 3, NULL);
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	rz_return_val_if_fail(bits == 16 || bits == 32, NULL);
	const cs_m68k_op *src0 = &ctx->m68k->operands[0];
	const cs_m68k_op *src1 = &ctx->m68k->operands[1];
	const cs_m68k_op *acc_op = &ctx->m68k->operands[ctx->m68k->op_count - 1];
	if (!rz_m68k_op_is_acc_reg(acc_op)) {
		return NULL;
	}
	int acc_index = mac_acc_index(acc_op->reg);
	if (acc_index < 0) {
		return NULL;
	}
	RzILOpPure *src0_value = mac_read_reg_part(ctx, src0, bits);
	RzILOpPure *src1_value = mac_read_reg_part(ctx, src1, bits);
	if (!src0_value || !src1_value) {
		rz_il_op_pure_free(src0_value);
		rz_il_op_pure_free(src1_value);
		return NULL;
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

	RzILOpEffect *bind_acc = mac_bind_acc(ctx, acc_op->reg, acc_index);
	if (!bind_acc) {
		rz_il_op_pure_free(src0_value);
		rz_il_op_pure_free(src1_value);
		return NULL;
	}
	RzILOpEffect *seq = SEQ6(
		SETL("src0", src0_value),
		SETL("src1", src1_value),
		bind_acc,
		mac_bind_product(ctx->mode, shift),
		SETL("res_wide", mac_accumulate_result(subtract)),
		mac_bind_result(ctx->mode));
	RzILOpEffect *write_result = mac_write_result(ctx, acc_op->reg, acc_index);
	if (!write_result) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ3(seq, write_result, mac_update_macsr(ctx->mode, acc_index));
	return mac_memory_update(ctx, seq, mem, update_reg);
}

static RzILOpEffect *mac_dual_acc_write(M68KILCtx *ctx, RzILOpEffect *seq, const cs_m68k_op *acc_op, bool subtract, const char *overflow_local, const char *extension_overflow_local) {
	if (!rz_m68k_op_is_acc_reg(acc_op)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	int acc_index = mac_acc_index(acc_op->reg);
	if (acc_index < 0) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpEffect *bind_acc = mac_bind_acc(ctx, acc_op->reg, acc_index);
	if (!bind_acc) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ4(
		seq,
		bind_acc,
		SETL("res_wide", mac_accumulate_result(subtract)),
		mac_bind_result(ctx->mode));
	RzILOpEffect *write_result = mac_write_result(ctx, acc_op->reg, acc_index);
	if (!write_result) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	return SEQ4(seq, write_result,
		SETL(overflow_local, ITE(mac_operation_overflow(ctx->mode), U32(1), U32(0))),
		SETL(extension_overflow_local, ITE(mac_extension_overflow(), U32(1), U32(0))));
}

static RzILOpEffect *lift_mac_dual_acc(M68KILCtx *ctx, bool subtract_first, bool subtract_second) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 4, NULL);
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	rz_return_val_if_fail(bits == 16 || bits == 32, NULL);
	const cs_m68k_op *src0 = &ctx->m68k->operands[0];
	const cs_m68k_op *src1 = &ctx->m68k->operands[1];
	const cs_m68k_op *acc0 = &ctx->m68k->operands[ctx->m68k->op_count - 2];
	const cs_m68k_op *acc1 = &ctx->m68k->operands[ctx->m68k->op_count - 1];
	if (!rz_m68k_op_is_acc_reg(acc0) || !rz_m68k_op_is_acc_reg(acc1)) {
		return NULL;
	}
	int first_index = mac_acc_index(acc0->reg);
	int second_index = mac_acc_index(acc1->reg);
	if (first_index < 0 || second_index < 0) {
		return NULL;
	}
	RzILOpPure *src0_value = mac_read_reg_part(ctx, src0, bits);
	RzILOpPure *src1_value = mac_read_reg_part(ctx, src1, bits);
	if (!src0_value || !src1_value) {
		rz_il_op_pure_free(src0_value);
		rz_il_op_pure_free(src1_value);
		return NULL;
	}

	const cs_m68k_op *shift = NULL;
	for (ut8 i = 2; i + 2 < ctx->m68k->op_count; i++) {
		const cs_m68k_op *op = &ctx->m68k->operands[i];
		if (op->type == M68K_OP_SHIFT) {
			shift = op;
		} else {
			rz_il_op_pure_free(src0_value);
			rz_il_op_pure_free(src1_value);
			return NULL;
		}
	}

	RzILOpEffect *seq = SEQ3(
		SETL("src0", src0_value),
		SETL("src1", src1_value),
		mac_bind_product(ctx->mode, shift));
	seq = mac_dual_acc_write(ctx, seq, acc0, subtract_first, "ov_first", "ev_first");
	if (!seq) {
		return NULL;
	}
	seq = mac_dual_acc_write(ctx, seq, acc1, subtract_second, "ov_second", "ev_second");
	if (!seq) {
		return NULL;
	}
	return SEQ2(seq, mac_update_macsr_dual(ctx->mode, first_index, second_index));
}
#endif

static RzILOpPure *div_quotient_expr(bool sign, const char *dividend_local, const char *divisor_local) {
	RzILOpPure *dividend = sign ? SIGNED(64, VARL(dividend_local)) : UNSIGNED(64, VARL(dividend_local));
	RzILOpPure *divisor = sign ? SIGNED(64, VARL(divisor_local)) : UNSIGNED(64, VARL(divisor_local));
	return sign ? SDIV(dividend, divisor) : DIV(dividend, divisor);
}

static RzILOpPure *div_remainder_expr(bool sign, const char *dividend_local, const char *divisor_local) {
	/* 680x0 remainder keeps the dividend sign (truncating toward zero).
	 * RzIL SMOD follows the divisor sign, so derive rem from quot. */
	RzILOpPure *dividend = sign ? SIGNED(64, VARL(dividend_local)) : UNSIGNED(64, VARL(dividend_local));
	RzILOpPure *divisor = sign ? SIGNED(64, VARL(divisor_local)) : UNSIGNED(64, VARL(divisor_local));
	return SUB(dividend, MUL(VARL("quot"), divisor));
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
	RzILOpPure *dst = m68k_read_reg_sized(ctx, reg, 32);
	if (!dst) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = seq ? SEQ2(seq, SETL("dst", dst)) : SETL("dst", dst);
	ut32 quotient_bits = bits == 16 ? 16 : 32;
	RzILOpEffect *write_result = NULL;
	if (bits == 16) {
		RzILOpPure *result = LOGOR(
			SHIFTL0(UNSIGNED(32, VARL("rem")), U8(16)),
			UNSIGNED(32, VARL("quot")));
		write_result = m68k_write_reg_sized(ctx, reg, 32, result);
	} else {
		write_result = m68k_write_reg_sized(ctx, reg, 32, UNSIGNED(32, VARL("quot")));
	}
	if (!write_result) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpEffect *normal = bits == 16
		? SEQ4(
			  SETL("quot", div_quotient_expr(sign, "dst", "src")),
			  SETL("rem", div_remainder_expr(sign, "dst", "src")),
			  write_result,
			  m68k_set_flags_div(VARL("quot"), quotient_bits, IL_FALSE))
		: SEQ3(
			  SETL("quot", div_quotient_expr(sign, "dst", "src")),
			  write_result,
			  m68k_set_flags_div(VARL("quot"), quotient_bits, IL_FALSE));
	RzILOpBool *overflow = div_quotient_overflows(sign, quotient_bits, div_quotient_expr(sign, "dst", "src"));
	RzILOpEffect *do_divide = BRANCH(overflow, m68k_set_flags_div(UN(quotient_bits, 0), quotient_bits, IL_TRUE), normal);
	return SEQ2(seq, BRANCH(IS_ZERO(VARL("src")), m68k_exception(M68K_TRAP_OP_DIV_ZERO, M68K_VECTOR_ZERO_DIVIDE, "m68k_trap"), do_divide));
}

static RzILOpEffect *lift_div_pair(M68KILCtx *ctx, bool sign, m68k_reg high_reg, m68k_reg low_reg, RzILOpEffect *seq) {
	if (!rz_m68k_reg_is_dreg(high_reg) || !rz_m68k_reg_is_dreg(low_reg) || high_reg == low_reg) {
		return NULL;
	}
	RzILOpEffect *write_high = m68k_write_reg_sized(ctx, high_reg, 32, UNSIGNED(32, VARL("rem")));
	RzILOpEffect *write_low = m68k_write_reg_sized(ctx, low_reg, 32, UNSIGNED(32, VARL("quot")));
	if (!write_high || !write_low) {
		return NULL;
	}
	seq = seq ? SEQ2(seq, SETL("dst", APPEND(m68k_read_reg_sized(ctx, high_reg, 32), m68k_read_reg_sized(ctx, low_reg, 32)))) : SETL("dst", APPEND(m68k_read_reg_sized(ctx, high_reg, 32), m68k_read_reg_sized(ctx, low_reg, 32)));
	RzILOpEffect *normal = SEQ5(
		SETL("quot", div_quotient_expr(sign, "dst", "src")),
		SETL("rem", div_remainder_expr(sign, "dst", "src")),
		write_low,
		write_high,
		m68k_set_flags_div(VARL("quot"), 32, IL_FALSE));
	RzILOpBool *overflow = div_quotient_overflows(sign, 32, div_quotient_expr(sign, "dst", "src"));
	RzILOpEffect *do_divide = BRANCH(overflow, m68k_set_flags_div(U32(0), 32, IL_TRUE), normal);
	return SEQ2(seq, BRANCH(IS_ZERO(VARL("src")), m68k_exception(M68K_TRAP_OP_DIV_ZERO, M68K_VECTOR_ZERO_DIVIDE, "m68k_trap"), do_divide));
}

static RzILOpEffect *lift_div(M68KILCtx *ctx, bool sign) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	rz_return_val_if_fail(bits == 16 || bits == 32, NULL);
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", &ctx->m68k->operands[0], bits, &seq)) {
		return NULL;
	}
	if (rz_m68k_op_is_data_reg(dst)) {
		return lift_div_reg(ctx, sign, dst->reg, bits, seq);
	}
	if (bits == 32 && dst->type == M68K_OP_REG_PAIR) {
		return lift_div_pair(ctx, sign, dst->reg_pair.reg_0, dst->reg_pair.reg_1, seq);
	}
	return NULL;
}

static RzILOpPure *movep_addr(ut32 offset) {
	return offset ? ADD(VARL("addr"), U32(offset)) : VARL("addr");
}

static RzILOpPure *movep_read_byte(ut32 offset, ut32 bits, ut32 shift) {
	RzILOpPure *byte = UNSIGNED(bits, LOADW(8, movep_addr(offset)));
	return shift ? SHIFTL0(byte, U8(shift)) : byte;
}

static RzILOpEffect *movep_store_byte(ut32 offset, ut32 shift) {
	RzILOpPure *byte = shift ? SHIFTR0(VARL("src"), U8(shift)) : VARL("src");
	return STOREW(movep_addr(offset), UNSIGNED(8, byte));
}

static RzILOpEffect *lift_movep(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	rz_return_val_if_fail(bits == 16 || bits == 32, NULL);
	bool mem_to_reg = rz_m68k_op_is_mem_addr(src) && rz_m68k_op_is_data_reg(dst);
	bool reg_to_mem = rz_m68k_op_is_data_reg(src) && rz_m68k_op_is_mem_addr(dst);
	if (!mem_to_reg && !reg_to_mem) {
		return NULL;
	}
	const cs_m68k_op *mem = mem_to_reg ? src : dst;
	M68KEA ea = m68k_effective_addr(ctx, mem, bits);
	if (!ea.addr) {
		return NULL;
	}

	RzILOpEffect *seq = SETL("addr", UNSIGNED(32, ea.addr));
	if (mem_to_reg) {
		RzILOpPure *res = bits == 16
			? LOGOR(movep_read_byte(0, 16, 8), movep_read_byte(2, 16, 0))
			: LOGOR(LOGOR(movep_read_byte(0, 32, 24), movep_read_byte(2, 32, 16)), LOGOR(movep_read_byte(4, 32, 8), movep_read_byte(6, 32, 0)));
		seq = SEQ3(
			seq,
			SETL("res", res),
			m68k_write_reg_sized(ctx, dst->reg, bits, VARL("res")));
	} else {
		seq = SEQ3(
			seq,
			SETL("src", m68k_read_reg_sized(ctx, src->reg, bits)),
			bits == 16 ? SEQ2(movep_store_byte(0, 8), movep_store_byte(2, 0)) : SEQ4(movep_store_byte(0, 24), movep_store_byte(2, 16), movep_store_byte(4, 8), movep_store_byte(6, 0)));
	}
	return m68k_effect_pre_post(ea.pre, seq, ea.post);
}

static m68k_reg movem_reg_for_bit(ut32 bit) {
	return bit < RZ_ARRAY_SIZE(m68k_data_addr_regs) ? m68k_data_addr_regs[bit] : M68K_REG_INVALID;
}

static ut32 movem_reg_count(ut32 reg_bits) {
	return (ut32)rz_bits_count_ones_ut32(reg_bits);
}

static RzILOpPure *movem_addr_at(ut32 offset) {
	return offset ? ADD(VARL("addr"), U32(offset)) : VARL("addr");
}

static RzILOpEffect *write_movem_reg(M68KILCtx *ctx, m68k_reg reg, ut32 bits, RzILOpPure *value) {
	if (bits == 16) {
		return m68k_write_reg_sized(ctx, reg, 32, SIGNED(32, value));
	}
	return m68k_write_reg_sized(ctx, reg, 32, value);
}

static RzILOpEffect *lift_movem(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	rz_return_val_if_fail(bits == 16 || bits == 32, NULL);
	bool reg_to_mem = src->type == M68K_OP_REG_BITS && rz_m68k_op_is_mem_addr(dst);
	bool mem_to_reg = rz_m68k_op_is_mem_addr(src) && dst->type == M68K_OP_REG_BITS;
	if (!reg_to_mem && !mem_to_reg) {
		return NULL;
	}
	const cs_m68k_op *regs_op = reg_to_mem ? src : dst;
	const cs_m68k_op *mem = reg_to_mem ? dst : src;
	ut32 reg_bits = regs_op->register_bits;
	if (reg_bits & ~0xffffu) {
		return NULL;
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
			return NULL;
		}
		seq = SETL("addr", m68k_reg_value(ctx, base_reg));
	} else {
		M68KEA ea = m68k_effective_addr(ctx, mem, bits);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return NULL;
		}
		seq = SETL("addr", UNSIGNED(32, ea.addr));
		seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
	}

	if (reg_to_mem && predec) {
		for (int i = 15; i >= 0; i--) {
			if (!(reg_bits & (1u << i))) {
				continue;
			}
			m68k_reg reg = movem_reg_for_bit((ut32)i);
			RzILOpPure *value = reg == base_reg && m68k_mode_uses_later_movem_base_value(ctx->mode)
				? UNSIGNED(bits, SUB(m68k_reg_value(ctx, base_reg), U32(bytes)))
				: m68k_read_reg_sized(ctx, reg, bits);
			if (!value) {
				rz_il_op_effect_free(seq);
				return NULL;
			}
			seq = SEQ2(seq, SETL("addr", SUB(VARL("addr"), U32(bytes))));
			RzILOpEffect *write = STOREW(VARL("addr"), UNSIGNED(bits, value));
			if (!write) {
				rz_il_op_pure_free(value);
				rz_il_op_effect_free(seq);
				return NULL;
			}
			seq = SEQ2(seq, write);
		}
		return SEQ2(seq, m68k_write_reg_sized(ctx, base_reg, 32, VARL("addr")));
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
			value = m68k_read_reg_sized(ctx, reg, bits);
			if (!value) {
				rz_il_op_effect_free(seq);
				return NULL;
			}
			op = STOREW(movem_addr_at(offset), UNSIGNED(bits, value));
		} else {
			value = LOADW(bits, movem_addr_at(offset));
			op = write_movem_reg(ctx, reg, bits, value);
		}
		if (!op) {
			if (reg_to_mem) {
				rz_il_op_pure_free(value);
			}
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, op);
		offset += bytes;
	}
	if (postinc) {
		seq = SEQ2(seq, m68k_write_reg_sized(ctx, base_reg, 32, ADD(VARL("addr"), U32(offset))));
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
		*seq = *seq ? SEQ2(*seq, SETL(addr_local, m68k_reg_value(ctx, base_reg))) : SETL(addr_local, m68k_reg_value(ctx, base_reg));
		*postinc_reg = base_reg;
		return true;
	}
	M68KEA ea = m68k_effective_addr(ctx, op, 32);
	if (!ea.addr) {
		return false;
	}
	RzILOpEffect *set = m68k_effect_pre_post(ea.pre,
		SETL(addr_local, UNSIGNED(32, ea.addr)), ea.post);
	*seq = *seq ? SEQ2(*seq, set) : set;
	return true;
}

static RzILOpEffect *lift_move16(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	RzILOpEffect *seq = NULL;
	m68k_reg src_postinc = M68K_REG_INVALID;
	m68k_reg dst_postinc = M68K_REG_INVALID;
	if (!move16_operand_addr(ctx, src, "src_addr", &seq, &src_postinc) ||
		!move16_operand_addr(ctx, dst, "dst_addr", &seq, &dst_postinc)) {
		return NULL;
	}

	seq = SEQN(11,
		seq,
		SETL("src_line", LOGAND(VARL("src_addr"), U32(~0xfu))),
		SETL("dst_line", LOGAND(VARL("dst_addr"), U32(~0xfu))),
		SETL("word0", LOADW(32, move16_addr_at("src_line", 0))),
		SETL("word1", LOADW(32, move16_addr_at("src_line", 4))),
		SETL("word2", LOADW(32, move16_addr_at("src_line", 8))),
		SETL("word3", LOADW(32, move16_addr_at("src_line", 12))),
		STOREW(move16_addr_at("dst_line", 0), UNSIGNED(32, VARL("word0"))),
		STOREW(move16_addr_at("dst_line", 4), UNSIGNED(32, VARL("word1"))),
		STOREW(move16_addr_at("dst_line", 8), UNSIGNED(32, VARL("word2"))),
		STOREW(move16_addr_at("dst_line", 12), UNSIGNED(32, VARL("word3"))));
	if (src_postinc != M68K_REG_INVALID) {
		seq = SEQ2(seq, m68k_write_reg_sized(ctx, src_postinc, 32, ADD(VARL("src_addr"), U32(16))));
	}
	if (dst_postinc != M68K_REG_INVALID && dst_postinc != src_postinc) {
		seq = SEQ2(seq, m68k_write_reg_sized(ctx, dst_postinc, 32, ADD(VARL("dst_addr"), U32(16))));
	}
	return seq;
}

static RzILOpEffect *lift_lea(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (!rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0]) || ctx->m68k->operands[1].type != M68K_OP_REG) {
		return NULL;
	}
	M68KEA ea = m68k_effective_addr(ctx, &ctx->m68k->operands[0], 32);
	if (!ea.addr) {
		return NULL;
	}
	RzILOpEffect *seq = m68k_write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, ea.addr);
	seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
	return seq;
}

static RzILOpEffect *push32(M68KILCtx *ctx, RzILOpPure *value) {
	return SEQ3(
		SETL("push_value", value),
		m68k_set_addr_reg_delta(ctx, M68K_REG_A7, -4),
		STOREW(m68k_reg_value(ctx, M68K_REG_A7), UNSIGNED(32, VARL("push_value"))));
}

static RzILOpEffect *lift_pea(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (!rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0])) {
		return NULL;
	}
	M68KEA ea = m68k_effective_addr(ctx, &ctx->m68k->operands[0], 32);
	RzILOpEffect *seq = push32(ctx, ea.addr);
	seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
	return seq;
}

static RzILOpPure *apply_binop(RzILOpPureCode binop, RzILOpPure *dst, RzILOpPure *src) {
	switch (binop) {
	case RZ_IL_OP_ADD:
		return ADD(dst, src);
	case RZ_IL_OP_SUB:
		return SUB(dst, src);
	case RZ_IL_OP_LOGAND:
		return LOGAND(dst, src);
	case RZ_IL_OP_LOGOR:
		return LOGOR(dst, src);
	case RZ_IL_OP_LOGXOR:
		return LOGXOR(dst, src);
	default:
		return NULL;
	}
}

static RzILOpEffect *lift_binop(M68KILCtx *ctx, RzILOpPureCode binop, bool address_dst, bool compare_only) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 op_bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	ut32 bits = address_dst ? 32 : op_bits;
	RzILOpEffect *seq = NULL;
	if (address_dst && op_bits == 16) {
		if (!m68k_operand_to_local(ctx, "src_raw", src, op_bits, &seq)) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, SETL("src", SIGNED(32, VARL("src_raw"))));
	} else if (!m68k_operand_to_local(ctx, "src", src, op_bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpPure *res = apply_binop(binop, VARL("dst"), VARL("src"));
	if (!res) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, SETL("res", res));
	if (!compare_only) {
		RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, address_dst ? 32 : bits, VARL("res"));
		if (!write) {
			m68k_rw_operand_fini(&dst_rw);
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, write);
	}
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}
	if (!address_dst || compare_only) {
		RzILOpBool *v = NULL;
		RzILOpBool *c = NULL;
		RzILOpBool *x = NULL;
		if (binop == RZ_IL_OP_ADD) {
			v = m68k_add_overflow(VARL("dst"), VARL("src"), VARL("res"));
			c = ULT(VARL("res"), VARL("dst"));
			x = (RzILOpBool *)DUP(c);
		} else if (binop == RZ_IL_OP_SUB) {
			v = m68k_sub_overflow(VARL("dst"), VARL("src"), VARL("res"));
			c = ULT(VARL("dst"), VARL("src"));
			x = compare_only ? NULL : (RzILOpBool *)DUP(c);
		} else {
			v = IL_FALSE;
			c = IL_FALSE;
		}
		seq = SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), bits, v, c, x));
	}
	return seq;
}

static RzILOpEffect *lift_status_binop(M68KILCtx *ctx, RzILOpPureCode binop) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if (!rz_m68k_op_is_status_reg(dst)) {
		return NULL;
	}
	ut32 bits = dst->reg == M68K_REG_CCR ? 8 : 16;
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", src, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, SETL("dst", m68k_read_reg_sized(ctx, dst->reg, bits)));
	RzILOpPure *res = apply_binop(binop, VARL("dst"), VARL("src"));
	if (!res) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, SETL("res", res));
	RzILOpEffect *write = m68k_write_status_reg(ctx, dst->reg, VARL("res"));
	if (!write) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	return SEQ2(seq, write);
}

static RzILOpEffect *lift_addx_subx(M68KILCtx *ctx, bool subtract) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", src, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}

	seq = SEQ3(
		seq,
		SETL("x", BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_X), bits)),
		SETL("srcx", ADD(VARL("src"), VARL("x"))));
	RzILOpPure *res = subtract ? SUB(VARL("dst"), VARL("srcx")) : ADD(VARL("dst"), VARL("srcx"));
	seq = SEQ2(seq, SETL("res", res));
	RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, write);
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}

	RzILOpPure *wide_dst = UNSIGNED(64, VARL("dst"));
	RzILOpPure *wide_src = UNSIGNED(64, VARL("src"));
	RzILOpPure *wide_x = UNSIGNED(64, VARL("x"));
	RzILOpBool *c = subtract
		? ULT(wide_dst, ADD(wide_src, wide_x))
		: UGT(ADD(ADD(wide_dst, wide_src), wide_x), U64(bits == 32 ? UT32_MAX : ((1ULL << bits) - 1)));
	RzILOpBool *v = subtract ? m68k_subx_overflow(bits) : m68k_addx_overflow(bits);
	return SEQ2(seq, m68k_set_flags_nzvcx_extend(VARL("res"), bits, v, c));
}

static RzILOpPure *bcd_byte_to_decimal(const char *local) {
	RzILOpPure *high = UNSIGNED(32, SHIFTR0(LOGAND(VARL(local), U8(0xf0)), U8(4)));
	RzILOpPure *low = UNSIGNED(32, LOGAND(VARL(local), U8(0x0f)));
	return ADD(MUL(high, U32(10)), low);
}

static RzILOpPure *bcd_decimal_to_byte(const char *local) {
	RzILOpPure *high = SHIFTL0(DIV(UNSIGNED(32, VARL(local)), U32(10)), U8(4));
	RzILOpPure *low = MOD(UNSIGNED(32, VARL(local)), U32(10));
	return UNSIGNED(8, LOGOR(high, low));
}

static RzILOpEffect *set_flags_bcd(RzILOpPure *result, RzILOpBool *carry) {
	RzILOpPure *ccr = LOGAND(UNSIGNED(8, VARG("sr")), U8(0xea));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, AND(m68k_ccr_bit(M68K_CCR_Z), IS_ZERO(UNSIGNED(8, result))));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, (RzILOpBool *)DUP(carry));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_X, carry);
	return m68k_set_ccr_from_value(ccr);
}

static RzILOpEffect *lift_abcd_sbcd(M68KILCtx *ctx, bool subtract) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "src", &ctx->m68k->operands[0], 8, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[1], 8, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ4(
		seq,
		SETL("src_dec", bcd_byte_to_decimal("src")),
		SETL("dst_dec", bcd_byte_to_decimal("dst")),
		SETL("x", BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_X), 32)));
	if (subtract) {
		seq = SEQ3(
			seq,
			SETL("diff", SUB(SUB(VARL("dst_dec"), VARL("src_dec")), VARL("x"))),
			SETL("res_dec", ITE(SLT(VARL("diff"), S32(0)), ADD(VARL("diff"), S32(100)), VARL("diff"))));
	} else {
		seq = SEQ3(
			seq,
			SETL("sum", ADD(ADD(VARL("dst_dec"), VARL("src_dec")), VARL("x"))),
			SETL("res_dec", MOD(VARL("sum"), U32(100))));
	}
	seq = SEQ2(seq, SETL("res", bcd_decimal_to_byte("res_dec")));
	RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, 8, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, write);
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}
	RzILOpBool *carry = subtract ? SLT(VARL("diff"), S32(0)) : UGT(VARL("sum"), U32(99));
	return SEQ2(seq, set_flags_bcd(VARL("res"), carry));
}

static RzILOpEffect *lift_nbcd(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	RzILOpEffect *seq = NULL;
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[0], 8, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ7(
		seq,
		SETL("dst_dec", bcd_byte_to_decimal("dst")),
		SETL("x", BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_X), 32)),
		SETL("diff", SUB(S32(0), ADD(VARL("dst_dec"), VARL("x")))),
		SETL("borrow", BOOL_TO_BV(SLT(VARL("diff"), S32(0)), 32)),
		SETL("res_dec", ITE(NON_ZERO(VARL("borrow")), ADD(VARL("diff"), S32(100)), VARL("diff"))),
		SETL("res", bcd_decimal_to_byte("res_dec")));
	RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, 8, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, write);
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}
	return SEQ2(seq, set_flags_bcd(VARL("res"), NON_ZERO(VARL("borrow"))));
}

static RzILOpPure *pack_adjustment(M68KILCtx *ctx) {
	if (ctx->m68k->op_count > 2 && ctx->m68k->operands[2].type == M68K_OP_IMM) {
		return U16((ut16)ctx->m68k->operands[2].imm);
	}
	return U16(0);
}

static RzILOpEffect *lift_pack_unpk(M68KILCtx *ctx, bool unpack) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	bool reg_to_reg = rz_m68k_op_is_data_reg(src) && rz_m68k_op_is_data_reg(dst);
	bool mem_to_mem = rz_m68k_op_is_predec_areg(src) && rz_m68k_op_is_predec_areg(dst);
	if (!reg_to_reg && !mem_to_mem) {
		return NULL;
	}

	RzILOpEffect *seq = NULL;
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpPure *src_value = m68k_read_operand(ctx, src, unpack ? 8 : 16, &pre, &post);
	if (!src_value) {
		return NULL;
	}
	seq = m68k_effect_pre_post(pre, SETL("src", src_value), post);
	seq = SEQ2(seq, SETL("adjustment", pack_adjustment(ctx)));
	if (unpack) {
		RzILOpPure *high = SHIFTL0(UNSIGNED(16, LOGAND(VARL("src"), U8(0xf0))), U8(4));
		RzILOpPure *low = UNSIGNED(16, LOGAND(VARL("src"), U8(0x0f)));
		seq = SEQ3(
			seq,
			SETL("expanded", LOGOR(high, low)),
			SETL("res", ADD(VARL("expanded"), VARL("adjustment"))));
	} else {
		seq = SEQ2(seq, SETL("adjusted", ADD(UNSIGNED(16, VARL("src")), VARL("adjustment"))));
		RzILOpPure *high = SHIFTR0(LOGAND(VARL("adjusted"), U16(0x0f00)), U8(4));
		RzILOpPure *low = LOGAND(VARL("adjusted"), U16(0x000f));
		seq = SEQ2(seq, SETL("res", UNSIGNED(8, LOGOR(high, low))));
	}

	RzILOpEffect *write = m68k_write_operand(ctx, dst, unpack ? 16 : 8, VARL("res"));
	if (!write) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, write);
	return seq;
}

static RzILOpEffect *lift_unary_write_result(M68KILCtx *ctx, RzILOpPure *result, bool set_flags) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	const cs_m68k_op *dst = &ctx->m68k->operands[0];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = m68k_write_operand_local(ctx, dst, bits, "res", result);
	if (!seq) {
		return NULL;
	}
	if (set_flags) {
		seq = SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), bits, IL_FALSE, IL_FALSE, NULL));
	}
	return seq;
}

static RzILOpEffect *lift_tst(M68KILCtx *ctx) {
	RzILOpEffect *seq = NULL;
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	if (!m68k_operand_to_local(ctx, "dst", &ctx->m68k->operands[0], bits, &seq)) {
		return NULL;
	}
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("dst"), bits, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_clr(M68KILCtx *ctx) {
	return lift_unary_write_result(ctx, UN(rz_m68k_detail_op_bits(ctx->m68k, 32), 0), true);
}

static RzILOpEffect *lift_not(M68KILCtx *ctx) {
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[0], bits, &seq)) {
		return NULL;
	}
	seq = SEQ2(seq, SETL("res", LOGNOT(VARL("dst"))));
	RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	seq = SEQ2(seq, write);
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), bits, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_neg(M68KILCtx *ctx, bool with_extend) {
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[0], bits, &seq)) {
		return NULL;
	}
	if (with_extend) {
		seq = SEQ3(
			seq,
			SETL("borrow", BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_X), bits)),
			SETL("res", SUB(SUB(UN(bits, 0), VARL("dst")), VARL("borrow"))));
	} else {
		seq = SEQ2(seq, SETL("res", SUB(SUB(UN(bits, 0), VARL("dst")), UN(bits, 0))));
	}
	RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	seq = SEQ2(seq, write);
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}
	RzILOpBool *c = with_extend ? OR(NON_ZERO(VARL("dst")), m68k_ccr_bit(M68K_CCR_X)) : NON_ZERO(VARL("dst"));
	RzILOpBool *v = with_extend ? m68k_negx_overflow(bits) : m68k_sub_overflow(UN(bits, 0), VARL("dst"), VARL("res"));
	return SEQ2(seq, with_extend ? m68k_set_flags_nzvcx_extend(VARL("res"), bits, v, c) : m68k_set_flags_nzvcx(VARL("res"), bits, v, c, (RzILOpBool *)DUP(c)));
}

static RzILOpEffect *lift_swap(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (!rz_m68k_op_is_data_reg(&ctx->m68k->operands[0])) {
		return NULL;
	}
	m68k_reg reg = ctx->m68k->operands[0].reg;
	RzILOpPure *v = m68k_reg_value(ctx, reg);
	RzILOpPure *res = LOGOR(SHIFTL0(v, U8(16)), SHIFTR0(DUP(v), U8(16)));
	return SEQ3(
		SETL("res", DUP(res)),
		m68k_write_reg_sized(ctx, reg, 32, res),
		m68k_set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_exg(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_REG || ctx->m68k->operands[1].type != M68K_OP_REG) {
		return NULL;
	}
	m68k_reg a = ctx->m68k->operands[0].reg;
	m68k_reg b = ctx->m68k->operands[1].reg;
	return SEQ3(
		SETL("tmp", m68k_read_reg_sized(ctx, a, 32)),
		m68k_write_reg_sized(ctx, a, 32, m68k_read_reg_sized(ctx, b, 32)),
		m68k_write_reg_sized(ctx, b, 32, VARL("tmp")));
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
		return AND(INV(m68k_ccr_bit(M68K_CCR_C)), INV(m68k_ccr_bit(M68K_CCR_Z)));
	case M68K_INS_BLS:
	case M68K_INS_DBLS:
	case M68K_INS_SLS:
	case M68K_INS_TRAPLS:
		return OR(m68k_ccr_bit(M68K_CCR_C), m68k_ccr_bit(M68K_CCR_Z));
	case M68K_INS_BCC:
	case M68K_INS_BHS:
	case M68K_INS_DBCC:
	case M68K_INS_SCC:
	case M68K_INS_SHS:
	case M68K_INS_TRAPCC:
	case M68K_INS_TRAPHS:
		return INV(m68k_ccr_bit(M68K_CCR_C));
	case M68K_INS_BCS:
	case M68K_INS_BLO:
	case M68K_INS_DBCS:
	case M68K_INS_SCS:
	case M68K_INS_SLO:
	case M68K_INS_TRAPCS:
	case M68K_INS_TRAPLO:
		return m68k_ccr_bit(M68K_CCR_C);
	case M68K_INS_BNE:
	case M68K_INS_DBNE:
	case M68K_INS_SNE:
	case M68K_INS_TRAPNE:
		return INV(m68k_ccr_bit(M68K_CCR_Z));
	case M68K_INS_BEQ:
	case M68K_INS_DBEQ:
	case M68K_INS_SEQ:
	case M68K_INS_TRAPEQ:
		return m68k_ccr_bit(M68K_CCR_Z);
	case M68K_INS_BVC:
	case M68K_INS_DBVC:
	case M68K_INS_SVC:
	case M68K_INS_TRAPVC:
		return INV(m68k_ccr_bit(M68K_CCR_V));
	case M68K_INS_BVS:
	case M68K_INS_DBVS:
	case M68K_INS_SVS:
	case M68K_INS_TRAPVS:
		return m68k_ccr_bit(M68K_CCR_V);
	case M68K_INS_BPL:
	case M68K_INS_DBPL:
	case M68K_INS_SPL:
	case M68K_INS_TRAPPL:
		return INV(m68k_ccr_bit(M68K_CCR_N));
	case M68K_INS_BMI:
	case M68K_INS_DBMI:
	case M68K_INS_SMI:
	case M68K_INS_TRAPMI:
		return m68k_ccr_bit(M68K_CCR_N);
	case M68K_INS_BGE:
	case M68K_INS_DBGE:
	case M68K_INS_SGE:
	case M68K_INS_TRAPGE:
		return EQ(BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_N), 1), BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_V), 1));
	case M68K_INS_BLT:
	case M68K_INS_DBLT:
	case M68K_INS_SLT:
	case M68K_INS_TRAPLT:
		return NE(BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_N), 1), BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_V), 1));
	case M68K_INS_BGT:
	case M68K_INS_DBGT:
	case M68K_INS_SGT:
	case M68K_INS_TRAPGT:
		return AND(INV(m68k_ccr_bit(M68K_CCR_Z)), EQ(BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_N), 1), BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_V), 1)));
	case M68K_INS_BLE:
	case M68K_INS_DBLE:
	case M68K_INS_SLE:
	case M68K_INS_TRAPLE:
		return OR(m68k_ccr_bit(M68K_CCR_Z), NE(BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_N), 1), BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_V), 1)));
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
	return AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_NAN)),
		AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_Z)), INV(m68k_fpsr_bit(M68K_FPSR_CC_N))));
}

static RzILOpBool *fpu_cond_oge(void) {
	return OR(m68k_fpsr_bit(M68K_FPSR_CC_Z),
		AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_NAN)), INV(m68k_fpsr_bit(M68K_FPSR_CC_N))));
}

static RzILOpBool *fpu_cond_olt(void) {
	return AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_NAN)),
		AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_Z)), m68k_fpsr_bit(M68K_FPSR_CC_N)));
}

static RzILOpBool *fpu_cond_ole(void) {
	return OR(m68k_fpsr_bit(M68K_FPSR_CC_Z),
		AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_NAN)), m68k_fpsr_bit(M68K_FPSR_CC_N)));
}

static RzILOpBool *fpu_cond_ogl(void) {
	return AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_NAN)), INV(m68k_fpsr_bit(M68K_FPSR_CC_Z)));
}

static RzILOpBool *fpu_cond_ueq(void) {
	return OR(m68k_fpsr_bit(M68K_FPSR_CC_NAN), m68k_fpsr_bit(M68K_FPSR_CC_Z));
}

static RzILOpBool *fpu_cond_ugt(void) {
	return OR(m68k_fpsr_bit(M68K_FPSR_CC_NAN),
		AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_Z)), INV(m68k_fpsr_bit(M68K_FPSR_CC_N))));
}

static RzILOpBool *fpu_cond_uge(void) {
	return OR(m68k_fpsr_bit(M68K_FPSR_CC_NAN),
		OR(m68k_fpsr_bit(M68K_FPSR_CC_Z), INV(m68k_fpsr_bit(M68K_FPSR_CC_N))));
}

static RzILOpBool *fpu_cond_ult(void) {
	return OR(m68k_fpsr_bit(M68K_FPSR_CC_NAN),
		AND(INV(m68k_fpsr_bit(M68K_FPSR_CC_Z)), m68k_fpsr_bit(M68K_FPSR_CC_N)));
}

static RzILOpBool *fpu_cond_ule(void) {
	return OR(m68k_fpsr_bit(M68K_FPSR_CC_NAN),
		OR(m68k_fpsr_bit(M68K_FPSR_CC_Z), m68k_fpsr_bit(M68K_FPSR_CC_N)));
}

static RzILOpBool *fpu_cond_code(ut32 insn_id) {
	switch (fpu_cond_offset(insn_id)) {
	case 0: // F
	case 16: // SF
		return IL_FALSE;
	case 1: // EQ
	case 17: // SEQ
		return m68k_fpsr_bit(M68K_FPSR_CC_Z);
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
		return INV(m68k_fpsr_bit(M68K_FPSR_CC_NAN));
	case 8: // UN
	case 24: // NGLE
		return m68k_fpsr_bit(M68K_FPSR_CC_NAN);
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
		return INV(m68k_fpsr_bit(M68K_FPSR_CC_Z));
	case 15: // T
	case 31: // ST
		return IL_TRUE;
	default:
		return NULL;
	}
}

static RzILOpEffect *lift_branch_cond(M68KILCtx *ctx, RzILOpBool *cond, bool call) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	RzILOpPure *target = m68k_read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL);
	if (!target) {
		return NULL;
	}
	RzILOpEffect *jmp = JMP(target);
	if (call) {
		jmp = SEQ2(push32(ctx, U32(ctx->next_addr)), jmp);
	}
	return BRANCH(cond, jmp, EMPTY());
}

static RzILOpEffect *lift_branch(M68KILCtx *ctx, bool unconditional, bool call) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	RzILOpPure *target = m68k_read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL);
	if (!target) {
		return NULL;
	}
	RzILOpEffect *jmp = JMP(target);
	if (call) {
		jmp = SEQ2(push32(ctx, U32(ctx->next_addr)), jmp);
	}
	if (unconditional) {
		return jmp;
	}
	RzILOpBool *cond = cond_code(ctx, ctx->insn->id);
	if (!cond) {
		return NULL;
	}
	return BRANCH(cond, jmp, EMPTY());
}

static RzILOpEffect *lift_jmp_jsr(M68KILCtx *ctx, bool call) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	RzILOpPure *target = NULL;
	RzILOpEffect *seq = NULL;
	if (rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0])) {
		M68KEA ea = m68k_effective_addr(ctx, &ctx->m68k->operands[0], 32);
		if (ea.pre) {
			seq = ea.pre;
		}
		target = ea.addr;
		if (ea.post) {
			seq = seq ? SEQ2(seq, ea.post) : ea.post;
		}
	} else {
		target = m68k_read_operand(ctx, &ctx->m68k->operands[0], 32, NULL, NULL);
	}
	if (!target) {
		return NULL;
	}
	if (call) {
		seq = seq ? SEQ2(seq, SETL("target", target)) : SETL("target", target);
		seq = SEQ2(seq, push32(ctx, U32(ctx->next_addr)));
		target = VARL("target");
	}
	seq = seq ? SEQ2(seq, JMP(target)) : JMP(target);
	return seq;
}

static RzILOpEffect *lift_rts(M68KILCtx *ctx) {
	return SEQ3(
		SETL("target", LOADW(32, m68k_reg_value(ctx, M68K_REG_A7))),
		m68k_set_addr_reg_delta(ctx, M68K_REG_A7, 4),
		JMP(VARL("target")));
}

static RzILOpEffect *lift_rtd(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return NULL;
	}
	st32 disp = (st16)ctx->m68k->operands[0].imm;
	return SEQ3(
		SETL("target", LOADW(32, m68k_reg_value(ctx, M68K_REG_A7))),
		m68k_set_addr_reg_delta(ctx, M68K_REG_A7, 4 + disp),
		JMP(VARL("target")));
}

static RzILOpEffect *lift_rtr(M68KILCtx *ctx) {
	return SEQ5(
		SETL("ccr", LOADW(16, m68k_reg_value(ctx, M68K_REG_A7))),
		m68k_set_addr_reg_delta(ctx, M68K_REG_A7, 2),
		SETL("target", LOADW(32, m68k_reg_value(ctx, M68K_REG_A7))),
		m68k_set_addr_reg_delta(ctx, M68K_REG_A7, 4),
		SEQ2(m68k_set_ccr_from_value(VARL("ccr")), JMP(VARL("target"))));
}

static RzILOpEffect *lift_rte(M68KILCtx *ctx) {
	RzILOpEffect *effect = SEQ3(
		SETL("frame", m68k_reg_value(ctx, M68K_REG_A7)),
		SETL("new_sr", LOADW(16, VARL("frame"))),
		SETL("target", LOADW(32, ADD(VARL("frame"), U32(2)))));
	RzILOpEffect *restore = NULL;
	if (m68k_mode_has_format_word(ctx->mode)) {
		effect = SEQ3(
			effect,
			SETL("format", SHIFTR0(LOADW(16, ADD(VARL("frame"), U32(6))), U8(12))),
			SETL("frame_size", m68k_rte_frame_size(ctx->mode)));
		restore = SEQ3(
			m68k_write_reg_sized(ctx, M68K_REG_A7, 32, ADD(VARL("frame"), VARL("frame_size"))),
			m68k_write_reg_sized(ctx, M68K_REG_SR, 16, VARL("new_sr")),
			JMP(VARL("target")));
		effect = SEQ2(effect, BRANCH(m68k_rte_format_valid(ctx->mode), restore, m68k_exception(M68K_TRAP_OP_FORMAT, M68K_VECTOR_FORMAT_ERROR, "m68k_trap")));
	} else {
		restore = SEQ3(
			m68k_write_reg_sized(ctx, M68K_REG_A7, 32, ADD(VARL("frame"), U32(6))),
			m68k_write_reg_sized(ctx, M68K_REG_SR, 16, VARL("new_sr")),
			JMP(VARL("target")));
		effect = SEQ2(effect, restore);
	}
	return BRANCH(m68k_supervisor_mode(), effect, m68k_label("m68k_privilege"));
}

static RzILOpEffect *lift_rtm(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (!rz_m68k_op_is_gpr(&ctx->m68k->operands[0])) {
		return NULL;
	}

	m68k_reg module_reg = ctx->m68k->operands[0].reg;
	RzILOpEffect *restore = SEQ4(
		m68k_set_ccr_from_value(SHIFTR0(VARL("ccr_arg"), U8(8))),
		m68k_write_reg_sized(ctx, module_reg, 32, VARL("module_data")),
		m68k_write_reg_sized(ctx, M68K_REG_A7, 32, ADD(ADD(VARL("frame"), U32(0x18)), VARL("arg_count"))),
		JMP(VARL("target")));

	RzILOpEffect *seq = SEQ6(
		SETL("frame", m68k_reg_value(ctx, M68K_REG_A7)),
		SETL("frame_info", LOADW(16, VARL("frame"))),
		SETL("ccr_arg", LOADW(16, ADD(VARL("frame"), U32(2)))),
		SETL("arg_count", UNSIGNED(32, UNSIGNED(8, VARL("ccr_arg")))),
		SETL("target", LOADW(32, ADD(VARL("frame"), U32(0x0c)))),
		SETL("module_data", LOADW(32, ADD(VARL("frame"), U32(0x10)))));
	return SEQ2(seq, BRANCH(IS_ZERO(LOGAND(VARL("frame_info"), U16(0xff00))), restore, m68k_label("m68k_rtm")));
}

static RzILOpEffect *lift_stop(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return NULL;
	}
	ut16 new_sr = (ut16)ctx->m68k->operands[0].imm;
	RzILOpEffect *load_sr = m68k_write_reg_sized(ctx, M68K_REG_SR, 16, U16(new_sr));
	if (!load_sr) {
		return NULL;
	}
	RzILOpEffect *effect = SEQ4(
		SETL("system_op", U32(ctx->insn->id == M68K_INS_LPSTOP ? M68K_SYSTEM_OP_LPSTOP : M68K_SYSTEM_OP_STOP)),
		SETL("system_sr", U32(new_sr)),
		load_sr,
		m68k_label("m68k_system"));
	return BRANCH(m68k_supervisor_mode(), effect, m68k_label("m68k_privilege"));
}

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static RzILOpEffect *lift_strldsr(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_IMM) {
		return NULL;
	}

	ut16 new_sr = (ut16)ctx->m68k->operands[0].imm;
	if (!(new_sr & (1u << M68K_SR_S))) {
		return m68k_label("m68k_privilege");
	}

	RzILOpEffect *effect = SEQ2(
		push32(ctx, UNSIGNED(32, VARG("sr"))),
		m68k_write_reg_sized(ctx, M68K_REG_SR, 16, U16(new_sr)));
	return BRANCH(m68k_supervisor_mode(), effect, m68k_label("m68k_privilege"));
}
#endif

static RzILOpEffect *lift_privileged_system(M68KSystemOp op) {
	RzILOpEffect *effect = SEQ2(
		SETL("system_op", U32((ut32)op)),
		m68k_label("m68k_system"));
	return BRANCH(m68k_supervisor_mode(), effect, m68k_label("m68k_privilege"));
}

static RzILOpEffect *lift_link(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (!rz_m68k_op_is_addr_reg(&ctx->m68k->operands[0]) ||
		ctx->m68k->operands[1].type != M68K_OP_IMM) {
		return NULL;
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	st32 disp = bits == 16
		? (st32)(st16)(ut16)ctx->m68k->operands[1].imm
		: (st32)ctx->m68k->operands[1].imm;
	m68k_reg areg = ctx->m68k->operands[0].reg;
	return SEQ4(
		push32(ctx, m68k_read_reg_sized(ctx, areg, 32)),
		m68k_write_reg_sized(ctx, areg, 32, m68k_reg_value(ctx, M68K_REG_A7)),
		SETL("new_sp", disp >= 0 ? ADD(m68k_reg_value(ctx, M68K_REG_A7), U32((ut32)disp)) : SUB(m68k_reg_value(ctx, M68K_REG_A7), U32((ut32)-disp))),
		m68k_write_reg_sized(ctx, M68K_REG_A7, 32, VARL("new_sp")));
}

static RzILOpEffect *lift_unlk(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_REG) {
		return NULL;
	}
	m68k_reg areg = ctx->m68k->operands[0].reg;
	/* Sequential op: (An) -> An; An+4 -> SP. When An is A7, the final SP
	 * write must keep the +4 rather than being overwritten by An = old. */
	if (areg == M68K_REG_A7) {
		return SEQ2(
			SETL("old", LOADW(32, m68k_reg_value(ctx, M68K_REG_A7))),
			m68k_write_reg_sized(ctx, M68K_REG_A7, 32, ADD(VARL("old"), U32(4))));
	}
	return SEQ4(
		m68k_write_reg_sized(ctx, M68K_REG_A7, 32, m68k_read_reg_sized(ctx, areg, 32)),
		SETL("old", LOADW(32, m68k_reg_value(ctx, M68K_REG_A7))),
		m68k_set_addr_reg_delta(ctx, M68K_REG_A7, 4),
		m68k_write_reg_sized(ctx, areg, 32, VARL("old")));
}

static RzILOpEffect *lift_scc_cond(M68KILCtx *ctx, RzILOpBool *cond) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	RzILOpPure *value = ITE(cond, U8(0xff), U8(0));
	return m68k_write_operand(ctx, &ctx->m68k->operands[0], 8, value);
}

static RzILOpEffect *lift_scc(M68KILCtx *ctx) {
	RzILOpBool *cond = cond_code(ctx, ctx->insn->id);
	if (!cond) {
		return NULL;
	}
	return lift_scc_cond(ctx, cond);
}

static RzILOpEffect *lift_dbcc_cond(M68KILCtx *ctx, RzILOpBool *cond) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (!rz_m68k_op_is_data_reg(&ctx->m68k->operands[0]) || ctx->m68k->operands[1].type != M68K_OP_BR_DISP) {
		return NULL;
	}
	m68k_reg reg = ctx->m68k->operands[0].reg;
	RzILOpPure *m68k_reg_value = m68k_read_reg_sized(ctx, reg, 32);
	if (!m68k_reg_value) {
		return NULL;
	}
	RzILOpPure *target = m68k_branch_disp_target(ctx, &ctx->m68k->operands[1]);
	if (!target) {
		rz_il_op_pure_free(m68k_reg_value);
		return NULL;
	}
	RzILOpEffect *seq = SETL("dec", SUB(UNSIGNED(16, m68k_reg_value), U16(1)));
	seq = SEQ3(
		seq,
		m68k_write_reg_sized(ctx, reg, 16, VARL("dec")),
		BRANCH(NE(VARL("dec"), U16(0xffff)), JMP(target), EMPTY()));
	return BRANCH(cond,
		EMPTY(),
		seq);
}

static RzILOpEffect *lift_dbcc(M68KILCtx *ctx) {
	RzILOpBool *cond = cond_code(ctx, ctx->insn->id);
	if (!cond) {
		return NULL;
	}
	return lift_dbcc_cond(ctx, cond);
}

static RzILOpPure *signed_zero_for_bits(ut32 bits) {
	return bits == 16 ? S16(0) : S32(0);
}

static RzILOpEffect *lift_chk(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (!rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
		return NULL;
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	rz_return_val_if_fail(bits == 16 || bits == 32, NULL);
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "bound", &ctx->m68k->operands[0], bits, &seq)) {
		return NULL;
	}
	RzILOpPure *dst = m68k_read_reg_sized(ctx, ctx->m68k->operands[1].reg, bits);
	if (!dst) {
		return NULL;
	}
	seq = SEQ2(seq, SETL("dst", dst));

	RzILOpEffect *neg_trap = SEQ2(
		m68k_set_ccr_from_value(m68k_ccr_with_flag(UNSIGNED(8, VARG("sr")), M68K_CCR_N, IL_TRUE)),
		m68k_exception(M68K_TRAP_OP_CHK, M68K_VECTOR_CHK, "m68k_chk"));
	RzILOpEffect *high_trap = SEQ2(
		m68k_set_ccr_from_value(m68k_ccr_with_flag(UNSIGNED(8, VARG("sr")), M68K_CCR_N, IL_FALSE)),
		m68k_exception(M68K_TRAP_OP_CHK, M68K_VECTOR_CHK, "m68k_chk"));
	return SEQ2(seq, BRANCH(SLT(VARL("dst"), signed_zero_for_bits(bits)), neg_trap, BRANCH(SGT(VARL("dst"), VARL("bound")), high_trap, EMPTY())));
}

static RzILOpPure *cmp2_extend_value(RzILOpPure *value, ut32 bits) {
	return bits == 32 ? value : SIGNED(32, value);
}

static RzILOpBool *cmp2_outside_bounds(void) {
	RzILOpBool *ordered = SLE(VARL("lower"), VARL("upper"));
	RzILOpBool *outside_ordered = OR(SLT(VARL("rn"), VARL("lower")), SGT(VARL("rn"), VARL("upper")));
	RzILOpBool *outside_wrapped = AND(SGT(VARL("rn"), VARL("upper")), SLT(VARL("rn"), VARL("lower")));
	return OR(AND(ordered, outside_ordered), AND(INV(SLE(VARL("lower"), VARL("upper"))), outside_wrapped));
}

static RzILOpEffect *set_flags_cmp2(void) {
	RzILOpPure *ccr = LOGAND(UNSIGNED(8, VARG("sr")), U8(0xfa));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, NON_ZERO(VARL("equal")));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, NON_ZERO(VARL("outside")));
	return m68k_set_ccr_from_value(ccr);
}

static RzILOpEffect *lift_cmp2_chk2(M68KILCtx *ctx, bool trap) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (!rz_m68k_op_is_mem_addr(&ctx->m68k->operands[0]) || !rz_m68k_op_is_gpr(&ctx->m68k->operands[1])) {
		return NULL;
	}
	const cs_m68k_op *bounds = &ctx->m68k->operands[0];
	const cs_m68k_op *reg = &ctx->m68k->operands[1];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	rz_return_val_if_fail(bits == 8 || bits == 16 || bits == 32, NULL);
	M68KEA ea = m68k_effective_addr(ctx, bounds, bits);
	if (!ea.addr) {
		return NULL;
	}
	RzILOpPure *rn = m68k_read_reg_sized(ctx, reg->reg, rz_m68k_reg_is_areg(reg->reg) ? 32 : bits);
	if (!rn) {
		return NULL;
	}
	if (rz_m68k_reg_is_dreg(reg->reg)) {
		rn = cmp2_extend_value(rn, bits);
	}
	RzILOpPure *addr = UNSIGNED(32, ea.addr);
	RzILOpPure *upper_addr = ADD(VARL("bounds_addr"), U32(rz_m68k_bits_access_bytes(bits)));
	RzILOpEffect *seq = SEQ7(
		SETL("bounds_addr", addr),
		SETL("lower", cmp2_extend_value(LOADW(bits, VARL("bounds_addr")), bits)),
		SETL("upper", cmp2_extend_value(LOADW(bits, upper_addr), bits)),
		SETL("rn", rn),
		SETL("outside", BOOL_TO_BV(cmp2_outside_bounds(), 1)),
		SETL("equal", BOOL_TO_BV(OR(EQ(VARL("rn"), VARL("lower")), EQ(VARL("rn"), VARL("upper"))), 1)),
		set_flags_cmp2());
	seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
	if (trap) {
		seq = SEQ2(seq, BRANCH(NON_ZERO(VARL("outside")), m68k_exception(M68K_TRAP_OP_CHK, M68K_VECTOR_CHK, "m68k_chk"), EMPTY()));
	}
	return seq;
}

static RzILOpEffect *lift_cas(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 3, NULL);
	if (!rz_m68k_op_is_data_reg(&ctx->m68k->operands[0]) ||
		!rz_m68k_op_is_data_reg(&ctx->m68k->operands[1]) ||
		!rz_m68k_op_is_mem_addr(&ctx->m68k->operands[2])) {
		return NULL;
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	rz_return_val_if_fail(bits == 8 || bits == 16 || bits == 32, NULL);
	RzILOpPure *cmp = m68k_read_reg_sized(ctx, ctx->m68k->operands[0].reg, bits);
	RzILOpPure *upd = m68k_read_reg_sized(ctx, ctx->m68k->operands[1].reg, bits);
	if (!cmp || !upd) {
		return NULL;
	}
	RzILOpEffect *seq = SEQ2(SETL("cmp", cmp), SETL("upd", upd));
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[2], bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, SETL("res", SUB(VARL("dst"), VARL("cmp"))));
	RzILOpEffect *success = m68k_write_rw_operand(ctx, &dst_rw, bits, VARL("upd"));
	RzILOpEffect *failure = m68k_write_reg_sized(ctx, ctx->m68k->operands[0].reg, bits, VARL("dst"));
	if (!success || !failure) {
		m68k_rw_operand_fini(&dst_rw);
		rz_il_op_effect_free(success);
		rz_il_op_effect_free(failure);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, BRANCH(EQ(UNSIGNED(bits, VARL("cmp")), UNSIGNED(bits, VARL("dst"))), success, failure));
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), bits, m68k_sub_overflow(VARL("dst"), VARL("cmp"), VARL("res")), ULT(VARL("dst"), VARL("cmp")), NULL));
}

static RzILOpEffect *lift_cas2(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 3, NULL);
	if (!rz_m68k_op_is_data_reg_pair(&ctx->m68k->operands[0]) ||
		!rz_m68k_op_is_data_reg_pair(&ctx->m68k->operands[1]) ||
		!rz_m68k_op_is_gpr_reg_pair(&ctx->m68k->operands[2])) {
		return NULL;
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	rz_return_val_if_fail(bits == 16 || bits == 32, NULL);

	const cs_m68k_op *cmp = &ctx->m68k->operands[0];
	const cs_m68k_op *upd = &ctx->m68k->operands[1];
	const cs_m68k_op *addr = &ctx->m68k->operands[2];
	RzILOpPure *addr0 = m68k_read_reg_sized(ctx, addr->reg_pair.reg_0, 32);
	RzILOpPure *addr1 = m68k_read_reg_sized(ctx, addr->reg_pair.reg_1, 32);
	RzILOpPure *cmp0 = m68k_read_reg_sized(ctx, cmp->reg_pair.reg_0, bits);
	RzILOpPure *cmp1 = m68k_read_reg_sized(ctx, cmp->reg_pair.reg_1, bits);
	RzILOpPure *upd0 = m68k_read_reg_sized(ctx, upd->reg_pair.reg_0, bits);
	RzILOpPure *upd1 = m68k_read_reg_sized(ctx, upd->reg_pair.reg_1, bits);
	if (!addr0 || !addr1 || !cmp0 || !cmp1 || !upd0 || !upd1) {
		return NULL;
	}

	RzILOpEffect *success = SEQ2(
		STOREW(VARL("addr0"), UNSIGNED(bits, VARL("upd0"))),
		STOREW(VARL("addr1"), UNSIGNED(bits, VARL("upd1"))));
	RzILOpEffect *fail_second = m68k_write_reg_sized(ctx, cmp->reg_pair.reg_1, bits, VARL("dst1"));
	RzILOpEffect *fail_first = m68k_write_reg_sized(ctx, cmp->reg_pair.reg_0, bits, VARL("dst0"));
	if (!success || !fail_second || !fail_first) {
		rz_il_op_effect_free(success);
		rz_il_op_effect_free(fail_second);
		rz_il_op_effect_free(fail_first);
		return NULL;
	}
	RzILOpEffect *failure = SEQ2(fail_second, fail_first);

	RzILOpEffect *seq = SEQ9(
		SETL("addr0", addr0),
		SETL("addr1", addr1),
		SETL("cmp0", cmp0),
		SETL("cmp1", cmp1),
		SETL("upd0", upd0),
		SETL("upd1", upd1),
		SETL("dst0", LOADW(bits, VARL("addr0"))),
		SETL("dst1", LOADW(bits, VARL("addr1"))),
		SETL("first_eq", BOOL_TO_BV(EQ(VARL("cmp0"), VARL("dst0")), 1)));
	seq = seq ? SEQ2(seq, SETL("second_eq", BOOL_TO_BV(EQ(VARL("cmp1"), VARL("dst1")), 1))) : SETL("second_eq", BOOL_TO_BV(EQ(VARL("cmp1"), VARL("dst1")), 1));
	seq = SEQ7(
		seq,
		SETL("res0", SUB(VARL("dst0"), VARL("cmp0"))),
		SETL("res1", SUB(VARL("dst1"), VARL("cmp1"))),
		SETL("flag_cmp", ITE(NON_ZERO(VARL("first_eq")), VARL("cmp1"), VARL("cmp0"))),
		SETL("flag_dst", ITE(NON_ZERO(VARL("first_eq")), VARL("dst1"), VARL("dst0"))),
		SETL("res", ITE(NON_ZERO(VARL("first_eq")), VARL("res1"), VARL("res0"))),
		BRANCH(AND(NON_ZERO(VARL("first_eq")), NON_ZERO(VARL("second_eq"))), success, failure));
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), bits, m68k_sub_overflow(VARL("flag_dst"), VARL("flag_cmp"), VARL("res")), ULT(VARL("flag_dst"), VARL("flag_cmp")), NULL));
}

#ifdef RZ_CAPSTONE_HAS_M68K_CPU32
static RzILOpPure *tbl_extend_entry(RzILOpPure *value, bool sign) {
	return sign ? SIGNED(64, value) : UNSIGNED(64, value);
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
	RzILOpPure *sized = UNSIGNED(result_bits, VARL("fixed"));
	return sign ? SIGNED(32, sized) : UNSIGNED(32, sized);
}

static RzILOpPure *tbl_immediate_base(M68KILCtx *ctx, ut32 bits) {
	return U32(ctx->addr + 4 + (bits == 8 ? 1 : 0));
}

static RzILOpEffect *lift_tbl(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	if (!rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	m68k_reg dst_reg = ctx->m68k->operands[1].reg;
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	rz_return_val_if_fail(bits == 8 || bits == 16 || bits == 32, NULL);

	bool sign = rz_m68k_tbl_insn_is_signed(ctx->insn->id);
	bool unrounded = rz_m68k_tbl_insn_is_unrounded(ctx->insn->id);
	RzILOpEffect *seq = SEQ2(SETL("x", m68k_read_reg_sized(ctx, dst_reg, 16)), SETL("frac", UNSIGNED(64, LOGAND(VARL("x"), U16(0xff)))));

	if (rz_m68k_op_is_data_reg_pair(src)) {
		seq = SEQ3(
			seq,
			SETL("entry0", tbl_extend_entry(m68k_read_reg_sized(ctx, src->reg_pair.reg_0, bits), sign)),
			SETL("entry1", tbl_extend_entry(m68k_read_reg_sized(ctx, src->reg_pair.reg_1, bits), sign)));
	} else if (rz_m68k_op_is_mem_addr(src)) {
		M68KEA ea = m68k_effective_addr(ctx, src, bits);
		if (!ea.addr) {
			return NULL;
		}
		ut32 bytes = rz_m68k_bits_access_bytes(bits);
		seq = SEQ2(seq,
			m68k_effect_pre_post(ea.pre,
				SEQ5(SETL("base", UNSIGNED(32, ea.addr)),
					SETL("index", UNSIGNED(32, SHIFTR0(LOGAND(VARL("x"), U16(0xff00)), U8(8)))),
					SETL("entry_addr", ADD(VARL("base"), MUL(VARL("index"), U32(bytes)))),
					SETL("entry0", tbl_extend_entry(LOADW(bits, VARL("entry_addr")), sign)),
					SETL("entry1", tbl_extend_entry(LOADW(bits, ADD(VARL("entry_addr"), U32(bytes))), sign))),
				ea.post));
	} else if (src->type == M68K_OP_IMM) {
		ut32 bytes = rz_m68k_bits_access_bytes(bits);
		seq = SEQ6(
			seq,
			SETL("base", tbl_immediate_base(ctx, bits)),
			SETL("index", UNSIGNED(32, SHIFTR0(LOGAND(VARL("x"), U16(0xff00)), U8(8)))),
			SETL("entry_addr", ADD(VARL("base"), MUL(VARL("index"), U32(bytes)))),
			SETL("entry0", tbl_extend_entry(LOADW(bits, VARL("entry_addr")), sign)),
			SETL("entry1", tbl_extend_entry(LOADW(bits, ADD(VARL("entry_addr"), U32(bytes))), sign)));
	} else {
		rz_il_op_effect_free(seq);
		return NULL;
	}

	seq = SEQ3(
		seq,
		SETL("diff", SUB(VARL("entry1"), VARL("entry0"))),
		SETL("prod", MUL(VARL("diff"), VARL("frac"))));
	if (unrounded) {
		seq = SEQ4(
			seq,
			SETL("fixed", ADD(SHIFTL0(VARL("entry0"), U8(8)), VARL("prod"))),
			SETL("res", tbl_unrounded_result(bits, sign)),
			m68k_write_reg_sized(ctx, dst_reg, 32, VARL("res")));
		return SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL));
	}

	seq = SEQ3(
		seq,
		SETL("res", UNSIGNED(bits, ADD(VARL("entry0"), tbl_rounded_delta()))),
		m68k_write_reg_sized(ctx, dst_reg, bits, VARL("res")));
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), bits, IL_FALSE, IL_FALSE, NULL));
}
#endif

static RzILOpEffect *lift_ext(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	if (ctx->m68k->operands[0].type != M68K_OP_REG) {
		return NULL;
	}
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	ut32 src_bits = ctx->insn->id == M68K_INS_EXTB ? 8 : (bits == 32 ? 16 : 8);
	m68k_reg reg = ctx->m68k->operands[0].reg;
	RzILOpPure *src = UNSIGNED(src_bits, m68k_read_reg_sized(ctx, reg, 32));
	RzILOpPure *res = SIGNED(bits, src);
	return SEQ3(
		SETL("res", DUP(res)),
		m68k_write_reg_sized(ctx, reg, bits, res),
		m68k_set_flags_nzvcx(VARL("res"), bits, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_tas(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	RzILOpEffect *seq = NULL;
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", &ctx->m68k->operands[0], 8, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, SETL("res", LOGOR(VARL("dst"), U8(0x80))));
	RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, 8, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, write);
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("dst"), 8, IL_FALSE, IL_FALSE, NULL));
}

static RzILOpEffect *lift_shift(M68KILCtx *ctx, bool left, bool arithmetic) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	const cs_m68k_op *dst = NULL;
	if (ctx->m68k->op_count == 1) {
		dst = &ctx->m68k->operands[0];
		seq = SETL("count", U8(1));
	} else {
		dst = &ctx->m68k->operands[1];
		if (!m68k_operand_to_local(ctx, "count", &ctx->m68k->operands[0], bits, &seq)) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
	}
	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpPure *count = UNSIGNED(8, VARL("count"));
	seq = SEQ2(seq, SETL("count8", LOGAND(count, U8(0x3f))));
	RzILOpPure *res = left ? SHIFTL0(VARL("dst"), VARL("count8")) : (arithmetic ? SHIFTRA(VARL("dst"), VARL("count8")) : SHIFTR0(VARL("dst"), VARL("count8")));
	seq = SEQ2(seq, SETL("res", res));
	RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, write);
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}
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
	RzILOpBool *extend = OR(AND(IS_ZERO(VARL("count8")), m68k_ccr_bit(M68K_CCR_X)), AND(NON_ZERO(VARL("count8")), shifted_out));
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
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), bits, overflow, carry, extend));
}

static RzILOpPure *rotate_expr(const char *value_local, const char *count_local, ut32 bits, bool left) {
	RzILOpPure *res = left
		? LOGOR(SHIFTL0(VARL(value_local), VARL(count_local)), SHIFTR0(VARL(value_local), SUB(U8(bits), VARL(count_local))))
		: LOGOR(SHIFTR0(VARL(value_local), VARL(count_local)), SHIFTL0(VARL(value_local), SUB(U8(bits), VARL(count_local))));
	return ITE(IS_ZERO(VARL(count_local)), VARL(value_local), res);
}

static RzILOpEffect *lift_rotate(M68KILCtx *ctx, bool left, bool extend) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
	RzILOpEffect *seq = NULL;
	const cs_m68k_op *dst = NULL;
	if (ctx->m68k->op_count == 1) {
		dst = &ctx->m68k->operands[0];
		seq = SETL("count", U8(1));
	} else {
		dst = &ctx->m68k->operands[1];
		if (!m68k_operand_to_local(ctx, "count", &ctx->m68k->operands[0], bits, &seq)) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
	}

	M68KRWOperand dst_rw;
	if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ3(
		seq,
		SETL("count_raw", LOGAND(UNSIGNED(8, VARL("count")), U8(0x3f))),
		SETL("rot_count", MOD(VARL("count_raw"), U8(extend ? bits + 1 : bits))));
	if (extend) {
		ut32 wide_bits = bits + 1;
		RzILOpPure *wide = APPEND(BOOL_TO_BV(m68k_ccr_bit(M68K_CCR_X), 1), UNSIGNED(bits, VARL("dst")));
		seq = SEQ4(
			seq,
			SETL("wide", wide),
			SETL("wide_res", rotate_expr("wide", "rot_count", wide_bits, left)),
			SETL("res", UNSIGNED(bits, VARL("wide_res"))));
	} else {
		seq = SEQ2(seq, SETL("res", rotate_expr("dst", "rot_count", bits, left)));
	}

	RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, bits, VARL("res"));
	if (!write) {
		m68k_rw_operand_fini(&dst_rw);
		rz_il_op_effect_free(seq);
		return NULL;
	}
	seq = SEQ2(seq, write);
	if (dst_rw.post) {
		seq = SEQ2(seq, dst_rw.post);
	}

	RzILOpBool *did_rotate = NON_ZERO(VARL("count_raw"));
	RzILOpBool *carry = NULL;
	RzILOpBool *x = NULL;
	if (extend) {
		RzILOpBool *new_x = MSB(VARL("wide_res"));
		carry = OR(AND(INV((RzILOpBool *)DUP(did_rotate)), m68k_ccr_bit(M68K_CCR_X)),
			AND(did_rotate, (RzILOpBool *)DUP(new_x)));
		x = OR(AND(IS_ZERO(VARL("count_raw")), m68k_ccr_bit(M68K_CCR_X)),
			AND(NON_ZERO(VARL("count_raw")), new_x));
	} else {
		RzILOpBool *rotated_carry = left ? NON_ZERO(LOGAND(VARL("res"), UN(bits, 1))) : MSB(VARL("res"));
		carry = AND(did_rotate, rotated_carry);
	}
	return SEQ2(seq, m68k_set_flags_nzvcx(VARL("res"), bits, IL_FALSE, carry, x));
}

static RzILOpEffect *lift_bitop(M68KILCtx *ctx, ut32 insn_id) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *bitop = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	ut32 bits = dst->type == M68K_OP_REG ? 32 : 8;
	RzILOpEffect *seq = NULL;
	if (!m68k_operand_to_local(ctx, "bit", bitop, bits, &seq)) {
		return NULL;
	}
	M68KRWOperand dst_rw = { 0 };
	bool writes_dst = insn_id != M68K_INS_BTST;
	if (writes_dst) {
		if (!m68k_rw_operand_to_local(ctx, &dst_rw, "dst", "dst_addr", dst, bits, &seq)) {
			return NULL;
		}
	} else if (!m68k_operand_to_local(ctx, "dst", dst, bits, &seq)) {
		return NULL;
	}
	RzILOpPure *idx = MOD(UNSIGNED(bits, VARL("bit")), UN(bits, bits));
	RzILOpPure *mask = SHIFTL0(UN(bits, 1), UNSIGNED(8, idx));
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
		return NULL;
	}
	seq = SEQ2(seq, m68k_set_ccr_from_value(m68k_ccr_with_flag(LOGAND(UNSIGNED(8, VARG("sr")), U8(0xfb)), M68K_CCR_Z, INV(was_set))));
	if (res) {
		RzILOpEffect *write = m68k_write_rw_operand(ctx, &dst_rw, bits, res);
		seq = SEQ2(seq, write);
		if (dst_rw.post) {
			seq = SEQ2(seq, dst_rw.post);
		}
	}
	return seq;
}

static RzILOpPure *bitfield_encoded_value(M68KILCtx *ctx, ut8 encoded, bool width) {
	if (M68K_BF_IS_REG(encoded)) {
		m68k_reg reg = M68K_REG_D0 + M68K_BF_REG_NUM(encoded);
		RzILOpPure *value = m68k_read_reg_sized(ctx, reg, 32);
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
	return SUB(SHIFTL0(U64(1), UNSIGNED(8, VARL("width"))), U64(1));
}

static RzILOpPure *bitfield_mask32(void) {
	return UNSIGNED(32, bitfield_mask64());
}

static RzILOpPure *bitfield_shift(void) {
	return SUB(U8(64), UNSIGNED(8, ADD(VARL("bit_offset"), VARL("width"))));
}

static RzILOpPure *bitfield_field_from_container(void) {
	return LOGAND(UNSIGNED(32, SHIFTR0(VARL("container"), bitfield_shift())), bitfield_mask32());
}

static RzILOpPure *bitfield_container_with_field(RzILOpPure *field) {
	RzILOpPure *shift = bitfield_shift();
	RzILOpPure *mask = SHIFTL0(bitfield_mask64(), (RzILOpPure *)DUP(shift));
	RzILOpPure *value = SHIFTL0(LOGAND(UNSIGNED(64, field), bitfield_mask64()), shift);
	return LOGOR(LOGAND(VARL("container"), LOGNOT(mask)), value);
}

static RzILOpPure *bitfield_data_reg_writeback(RzILOpPure *updated) {
	RzILOpPure *wrapped_mask = UNSIGNED(32, SHIFTL0(bitfield_mask64(), bitfield_shift()));
	RzILOpPure *upper = UNSIGNED(32, SHIFTR0((RzILOpPure *)DUP(updated), U8(32)));
	RzILOpPure *lower = UNSIGNED(32, updated);
	return LOGOR(LOGAND(upper, LOGNOT((RzILOpPure *)DUP(wrapped_mask))), LOGAND(lower, wrapped_mask));
}

static RzILOpPure *bitfield_sign_extend(void) {
	RzILOpPure *sign_mask = SHIFTL0(U32(1), UNSIGNED(8, SUB(VARL("width"), U32(1))));
	RzILOpBool *sign = NON_ZERO(LOGAND(VARL("field"), sign_mask));
	return ITE(sign, LOGOR(VARL("field"), LOGNOT(bitfield_mask32())), VARL("field"));
}

static RzILOpPure *bitfield_left_aligned(void) {
	return SHIFTL0(VARL("field"), SUB(U8(32), UNSIGNED(8, VARL("width"))));
}

static RzILOpPure *bitfield_memory_byte_addr(const char *addr_local, ut32 offset) {
	return offset ? ADD(VARL(addr_local), U32(offset)) : VARL(addr_local);
}

enum {
	M68K_BITFIELD_MAX_MEMORY_BYTES = 5,
};

static RzILOpEffect *read_bitfield_memory(const char *addr_local) {
	RzILOpEffect *seq = SETL("container", U64(0));
	for (ut32 i = 0; i < M68K_BITFIELD_MAX_MEMORY_BYTES; i++) {
		RzILOpPure *byte = UNSIGNED(64, LOADW(8, bitfield_memory_byte_addr(addr_local, i)));
		byte = SHIFTL0(byte, U8(56 - (i * 8)));
		RzILOpEffect *load = SETL("container", LOGOR(VARL("container"), byte));
		if (i > 0) {
			load = BRANCH(UGT(VARL("byte_count"), U32(i)), load, EMPTY());
		}
		seq = SEQ2(seq, load);
	}
	return seq;
}

static RzILOpEffect *write_bitfield_memory(const char *addr_local, RzILOpPure *updated) {
	RzILOpEffect *seq = SETL("updated_container", updated);
	for (ut32 i = 0; i < M68K_BITFIELD_MAX_MEMORY_BYTES; i++) {
		RzILOpPure *byte = UNSIGNED(8, SHIFTR0(VARL("updated_container"), U8(56 - (i * 8))));
		RzILOpEffect *store = STOREW(bitfield_memory_byte_addr(addr_local, i), UNSIGNED(8, byte));
		if (i > 0) {
			store = BRANCH(UGT(VARL("byte_count"), U32(i)), store, EMPTY());
		}
		seq = SEQ2(seq, store);
	}
	return seq;
}

static RzILOpEffect *set_flags_bitfield(RzILOpPure *field) {
	RzILOpPure *value = LOGAND(field, bitfield_mask32());
	RzILOpPure *sign_mask = SHIFTL0(U32(1), UNSIGNED(8, SUB(VARL("width"), U32(1))));
	RzILOpPure *ccr = LOGAND(UNSIGNED(8, VARG("sr")), U8(0xe0));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_N, NON_ZERO(LOGAND(DUP(value), sign_mask)));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_Z, IS_ZERO(value));
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_V, IL_FALSE);
	ccr = m68k_ccr_with_flag(ccr, M68K_CCR_C, IL_FALSE);
	ccr = LOGOR(ccr, LOGAND(UNSIGNED(8, VARG("sr")), U8(1u << M68K_CCR_X)));
	return m68k_set_ccr_from_value(ccr);
}

static bool bitfield_target_to_local(M68KILCtx *ctx, const cs_m68k_op *op, M68KBitfieldTarget *target, RzILOpEffect **seq) {
	rz_return_val_if_fail(ctx && op && target && seq, false);
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
	*seq = *seq ? SEQ2(*seq, SETL("offset", offset)) : SETL("offset", offset);
	*seq = SEQ2(*seq, SETL("width", width));
	if (target->memory) {
		M68KEA ea = m68k_effective_addr(ctx, op, 32);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return false;
		}
		*seq = SEQ2(*seq,
			m68k_effect_pre_post(ea.pre, SETL("base", UNSIGNED(32, ea.addr)), NULL));
		if (M68K_BF_IS_REG(op->mem.offset)) {
			*seq = SEQ3(
				*seq,
				SETL("bit_offset", LOGAND(VARL("offset"), U32(7))),
				SETL("byte_offset", SDIV(SUB(VARL("offset"), VARL("bit_offset")), S32(8))));
		} else {
			*seq = SEQ3(
				*seq,
				SETL("byte_offset", DIV(VARL("offset"), U32(8))),
				SETL("bit_offset", MOD(VARL("offset"), U32(8))));
		}
		*seq = SEQ4(
			*seq,
			SETL(target->addr_local, ADD(VARL("base"), VARL("byte_offset"))),
			SETL("byte_count", DIV(ADD(ADD(VARL("bit_offset"), VARL("width")), U32(7)), U32(8))),
			read_bitfield_memory(target->addr_local));
		target->post = ea.post;
	} else if (rz_m68k_op_is_data_reg(op)) {
		RzILOpPure *value = m68k_read_reg_sized(ctx, op->reg, 32);
		if (!value) {
			return false;
		}
		*seq = SEQ3(
			*seq,
			SETL("bit_offset", MOD(VARL("offset"), U32(32))),
			SETL("container", APPEND(value, m68k_read_reg_sized(ctx, op->reg, 32))));
	} else {
		rz_il_op_effect_free(target->post);
		target->post = NULL;
		return false;
	}
	*seq = SEQ2(*seq, SETL("field", bitfield_field_from_container()));
	return true;
}

static RzILOpEffect *write_bitfield_target(M68KILCtx *ctx, const M68KBitfieldTarget *target, RzILOpPure *field) {
	RzILOpEffect *write = NULL;
	RzILOpPure *updated = bitfield_container_with_field(field);
	if (target->memory) {
		write = write_bitfield_memory(target->addr_local, updated);
	} else if (rz_m68k_op_is_data_reg(target->op)) {
		write = m68k_write_reg_sized(ctx, target->op->reg, 32, bitfield_data_reg_writeback(updated));
	} else {
		rz_il_op_pure_free(updated);
	}
	if (!write) {
		rz_il_op_effect_free(target->post);
		return NULL;
	}
	return m68k_effect_pre_post(NULL, write, target->post);
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
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	bool insert = insn_id == M68K_INS_BFINS;
	const cs_m68k_op *target_op = insert ? &ctx->m68k->operands[1] : &ctx->m68k->operands[0];
	M68KBitfieldTarget target = { 0 };
	RzILOpEffect *seq = NULL;
	if (!target_op->mem.bitfield || !bitfield_target_to_local(ctx, target_op, &target, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	RzILOpEffect *write = NULL;
	switch (insn_id) {
	case M68K_INS_BFTST:
		if (target.post) {
			seq = SEQ2(seq, target.post);
		}
		target.post = NULL;
		return SEQ2(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFEXTU:
	case M68K_INS_BFEXTS:
		if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
			m68k_bitfield_target_fini(&target);
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ3(
			seq,
			SETL("res", insn_id == M68K_INS_BFEXTS ? bitfield_sign_extend() : VARL("field")),
			m68k_write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, VARL("res")));
		if (target.post) {
			seq = SEQ2(seq, target.post);
		}
		target.post = NULL;
		return SEQ2(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFFFO:
		if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[1])) {
			m68k_bitfield_target_fini(&target);
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ4(
			seq,
			SETL("scan", bitfield_left_aligned()),
			SETL("first", bitfield_fffo_index()),
			m68k_write_reg_sized(ctx, ctx->m68k->operands[1].reg, 32, ADD(VARL("offset"), VARL("first"))));
		if (target.post) {
			seq = SEQ2(seq, target.post);
		}
		target.post = NULL;
		return SEQ2(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFCHG:
		write = write_bitfield_target(ctx, &target, LOGXOR(VARL("field"), bitfield_mask32()));
		if (!write) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, write);
		return SEQ2(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFCLR:
		write = write_bitfield_target(ctx, &target, U32(0));
		if (!write) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, write);
		return SEQ2(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFSET:
		write = write_bitfield_target(ctx, &target, bitfield_mask32());
		if (!write) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, write);
		return SEQ2(seq, set_flags_bitfield(VARL("field")));
	case M68K_INS_BFINS:
		if (ctx->m68k->op_count < 2 || !rz_m68k_op_is_data_reg(&ctx->m68k->operands[0])) {
			m68k_bitfield_target_fini(&target);
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, SETL("src", LOGAND(m68k_read_reg_sized(ctx, ctx->m68k->operands[0].reg, 32), bitfield_mask32())));
		write = write_bitfield_target(ctx, &target, VARL("src"));
		if (!write) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, write);
		return SEQ2(seq, set_flags_bitfield(VARL("src")));
	default:
		m68k_bitfield_target_fini(&target);
		rz_il_op_effect_free(seq);
		return NULL;
	}
}

static RzILOpEffect *lift_mul(M68KILCtx *ctx, bool sign) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *dst_op = &ctx->m68k->operands[1];

	if (dst_op->type == M68K_OP_REG_PAIR) {
		ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 32);
		if (bits != 32) {
			return NULL;
		}
		m68k_reg high_reg = dst_op->reg_pair.reg_0;
		m68k_reg low_reg = dst_op->reg_pair.reg_1;
		if (!rz_m68k_reg_is_dreg(high_reg) || !rz_m68k_reg_is_dreg(low_reg) || high_reg == low_reg) {
			return NULL;
		}
		RzILOpEffect *seq = NULL;
		if (!m68k_operand_to_local(ctx, "src", &ctx->m68k->operands[0], bits, &seq)) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		RzILOpPure *dst = m68k_read_reg_sized(ctx, low_reg, bits);
		if (!dst) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		RzILOpEffect *write_high = m68k_write_reg_sized(ctx, high_reg, 32, SHIFTR0(VARL("res"), U8(32)));
		RzILOpEffect *write_low = m68k_write_reg_sized(ctx, low_reg, 32, VARL("res"));
		if (!write_high || !write_low) {
			rz_il_op_effect_free(write_high);
			rz_il_op_effect_free(write_low);
			rz_il_op_effect_free(seq);
			return NULL;
		}
		RzILOpPure *lhs = sign ? SIGNED(64, VARL("dst")) : UNSIGNED(64, VARL("dst"));
		RzILOpPure *rhs = sign ? SIGNED(64, VARL("src")) : UNSIGNED(64, VARL("src"));
		return SEQ2(seq, SEQ5(SETL("dst", dst), SETL("res", MUL(lhs, rhs)), write_low, write_high, m68k_set_flags_nzvcx(VARL("res"), 64, IL_FALSE, IL_FALSE, NULL)));
	}

	if (dst_op->type != M68K_OP_REG) {
		return NULL;
	}
	RzILOpEffect *seq = NULL;
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 16);
	rz_return_val_if_fail(bits == 16 || bits == 32, NULL);
	if (!m68k_operand_to_local(ctx, "src", &ctx->m68k->operands[0], bits, &seq)) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	m68k_reg reg = dst_op->reg;
	RzILOpPure *dst = m68k_read_reg_sized(ctx, reg, bits);
	if (!dst) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	ut32 product_bits = bits == 32 ? 64 : 32;
	RzILOpPure *lhs = sign ? SIGNED(product_bits, dst) : UNSIGNED(product_bits, dst);
	RzILOpPure *rhs = sign ? SIGNED(product_bits, VARL("src")) : UNSIGNED(product_bits, VARL("src"));
	if (bits == 32) {
		RzILOpBool *overflow = sign
			? m68k_signed_out_of_range(VARL("res_wide"), 32)
			: UGT(VARL("res_wide"), U64(UT32_MAX));
		return SEQ2(seq, SEQ4(SETL("res_wide", MUL(lhs, rhs)), SETL("res", UNSIGNED(32, VARL("res_wide"))), m68k_write_reg_sized(ctx, reg, 32, VARL("res")), m68k_set_flags_nzvcx(VARL("res"), 32, overflow, IL_FALSE, NULL)));
	}

	RzILOpPure *res = MUL(lhs, rhs);
	return SEQ2(seq, SEQ3(SETL("res", DUP(res)), m68k_write_reg_sized(ctx, reg, 32, res), m68k_set_flags_nzvcx(VARL("res"), 32, IL_FALSE, IL_FALSE, NULL)));
}

static RzILOpEffect *append_trap_arg_metadata(M68KILCtx *ctx, RzILOpEffect *seq) {
	if (ctx->m68k->op_count > 0 && ctx->m68k->operands[0].type == M68K_OP_IMM) {
		bool fpu_trap = ctx->insn->size > 0 && ctx->insn->bytes[0] == 0xf2;
		ut32 arg_bits = ctx->insn->size >= (fpu_trap ? 8 : 6) ? 32 : 16;
		seq = seq ? SEQ2(seq, SETL("trap_arg", U32((ut32)ctx->m68k->operands[0].imm))) : SETL("trap_arg", U32((ut32)ctx->m68k->operands[0].imm));
		seq = SEQ2(seq, SETL("trap_arg_bits", U32(arg_bits)));
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
		seq = SEQ2(seq, SETL("trap_vector", U32((ut32)vector)));
	}
	if (append_arg) {
		seq = append_trap_arg_metadata(ctx, seq);
	}
	return seq ? SEQ2(seq, m68k_label("m68k_trap")) : m68k_label("m68k_trap");
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
		seq = SEQ2(seq, SETL("trap_arg", U32(arg)));
		if (trap_op == M68K_TRAP_OP_TRAP) {
			seq = SEQ2(seq, SETL("trap_vector", U32(M68K_VECTOR_TRAP_BASE + (arg & 0xf))));
		}
	}
	return SEQ2(seq, m68k_label("m68k_trap"));
}

/* UM 6.1.1: IEEE nonaware / signaling predicates set BSUN+IOP when NAN
 * is set. IEEE aware tests (EQ/OGT/...) do not. Trap-disabled evaluation
 * still uses the predicate; GT with NAN is false. */
static RzILOpEffect *set_fpsr_bsun_if_unordered(ut32 insn_id) {
	if (fpu_cond_offset(insn_id) < 16) {
		return NULL;
	}
	return SETG("fpsr",
		ITE(m68k_fpsr_bit(M68K_FPSR_CC_NAN),
			LOGOR(VARG("fpsr"),
				U32((1u << M68K_FPSR_EXC_BSUN) | (1u << M68K_FPSR_AEXC_IOP))),
			VARG("fpsr")));
}

static RzILOpEffect *lift_fpu_conditional(M68KILCtx *ctx, RzILOpBool *cond) {
	RzILOpEffect *seq = set_fpsr_bsun_if_unordered(ctx->insn->id);
	RzILOpEffect *effect;
	if (ctx->m68k->op_count == 1 && ctx->m68k->operands[0].type == M68K_OP_BR_DISP) {
		effect = lift_branch_cond(ctx, cond, false);
	} else if (ctx->m68k->op_count == 2 &&
		ctx->m68k->operands[0].type == M68K_OP_REG &&
		ctx->m68k->operands[1].type == M68K_OP_BR_DISP) {
		effect = lift_dbcc_cond(ctx, cond);
	} else if (!ctx->m68k->op_count ||
		(ctx->m68k->op_count == 1 && ctx->m68k->operands[0].type == M68K_OP_IMM)) {
		effect = lift_trapcc_cond(ctx, cond, M68K_TRAP_OP_FTRAPCC);
	} else {
		effect = lift_scc_cond(ctx, cond);
	}
	return seq ? SEQ2(seq, effect) : effect;
}

static ut32 fpu_control_implemented_mask(m68k_reg reg) {
	switch (reg) {
	case M68K_REG_FPCR:
		return M68K_FPCR_IMPLEMENTED_MASK;
	case M68K_REG_FPSR:
		return M68K_FPSR_IMPLEMENTED_MASK;
	default:
		return 0xffffffffu;
	}
}

/* PRM 5-80 / 68881 UM 4-69: unimplemented control bits read as zero and
 * are ignored on writes. Writing ENABLE/EXC cannot raise a new trap. */
static RzILOpPure *fpu_control_implemented_bits(m68k_reg reg, RzILOpPure *value) {
	ut32 mask = fpu_control_implemented_mask(reg);
	if (mask == 0xffffffffu) {
		return value;
	}
	return LOGAND(UNSIGNED(32, value), U32(mask));
}

/* PRM 5-91: FMOVEM control always moves FPCR, then FPSR, then FPIAR at
 * increasing addresses. Capstone only names the first selected register. */
static ut32 fpu_control_list_count(ut32 list) {
	ut32 count = 0;
	if (list & 4) {
		count++;
	}
	if (list & 2) {
		count++;
	}
	if (list & 1) {
		count++;
	}
	return count;
}

static RzILOpEffect *lift_fmovem_control(M68KILCtx *ctx, ut32 list, bool to_mem) {
	if (ctx->m68k->op_count < 2) {
		return NULL;
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	const cs_m68k_op *mem = rz_m68k_op_is_mem_addr(src) ? src : (rz_m68k_op_is_mem_addr(dst) ? dst : NULL);
	if (!mem || (mem->type == M68K_OP_MEM && mem->address_mode == M68K_AM_NONE)) {
		return NULL;
	}

	ut32 count = fpu_control_list_count(list);
	ut32 bytes = count * 4;
	bool predec = mem->address_mode == M68K_AM_REGI_ADDR_PRE_DEC;
	bool postinc = mem->address_mode == M68K_AM_REGI_ADDR_POST_INC;
	m68k_reg base_reg = rz_m68k_op_base_reg(mem);
	RzILOpEffect *seq = NULL;
	if (predec || postinc) {
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return NULL;
		}
		seq = SETL("addr", m68k_reg_value(ctx, base_reg));
		if (predec) {
			seq = SEQ3(
				seq,
				SETL("addr", SUB(VARL("addr"), U32(bytes))),
				m68k_write_reg_sized(ctx, base_reg, 32, VARL("addr")));
		}
	} else {
		M68KEA ea = m68k_effective_addr(ctx, mem, 32);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return NULL;
		}
		seq = m68k_effect_pre_post(ea.pre,
			SETL("addr", UNSIGNED(32, ea.addr)), ea.post);
	}

	static const m68k_reg regs[] = { M68K_REG_FPCR, M68K_REG_FPSR, M68K_REG_FPIAR };
	static const ut32 bits[] = { 4, 2, 1 };
	for (ut32 i = 0; i < RZ_ARRAY_SIZE(regs); i++) {
		if (!(list & bits[i])) {
			continue;
		}
		if (to_mem) {
			seq = SEQ2(seq, STOREW(VARL("addr"), fpu_control_implemented_bits(regs[i], m68k_read_reg_sized(ctx, regs[i], 32))));
		} else {
			seq = SEQ3(
				seq,
				SETL("src", LOADW(32, VARL("addr"))),
				m68k_write_reg_sized(ctx, regs[i], 32, fpu_control_implemented_bits(regs[i], VARL("src"))));
		}
		seq = SEQ2(seq, SETL("addr", ADD(VARL("addr"), U32(4))));
	}
	if (postinc) {
		seq = SEQ2(seq, m68k_write_reg_sized(ctx, base_reg, 32, VARL("addr")));
	}
	return seq;
}

static RzILOpEffect *lift_fmove_control(M68KILCtx *ctx) {
	ut16 extension = 0;
	if (rz_m68k_fpu_insn_extension_word(ctx->insn, &extension)) {
		ut32 list = (extension >> 10) & 7;
		if (fpu_control_list_count(list) > 1) {
			return lift_fmovem_control(ctx, list, (extension >> 13) & 1);
		}
	}
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

	if (dst_control) {
		RzILOpEffect *seq = NULL;
		if (!m68k_operand_to_local(ctx, "src", src, 32, &seq)) {
			return NULL;
		}
		RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, 32, fpu_control_implemented_bits(dst->reg, VARL("src")));
		if (!write) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		return SEQ2(seq, write);
	}

	return m68k_write_operand(ctx, dst, 32,
		fpu_control_implemented_bits(src->reg, m68k_read_reg_sized(ctx, src->reg, 32)));
}

static RzFloatFormat fpu_format_for_bits(ut32 bits) {
	switch (bits) {
	case 32:
		return RZ_FLOAT_IEEE754_BIN_32;
	case 64:
		return RZ_FLOAT_IEEE754_BIN_64;
	case 80:
	default:
		return RZ_FLOAT_IEEE754_BIN_80;
	}
}

static ut32 fpu_external_bits(M68KILCtx *ctx, ut32 bits) {
	if (rz_m68k_fpu_size_is_extended(ctx->m68k)) {
		return M68K_FMOVEM_EXTENDED_BITS;
	}
#ifdef RZ_CAPSTONE_HAS_M68K_FP_FORMATS
	if (rz_m68k_fpu_size_is_packed(ctx->m68k)) {
		return M68K_FMOVEM_EXTENDED_BITS;
	}
#endif
	return bits;
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
	/* Map 680x0 FPCR rounding bits to RzFloatRMode.
	 * FPCR[5:4]: 0=RNE, 1=RTZ, 2=RTN, 3=RTP.
	 * Enum order is RNE, RNA, RTP, RTN, RTZ — not the 680x0 encoding. */
	return LET("fpcr_round_mode", LOGAND(SHIFTR0(VARG("fpcr"), U8(4)), U32(3)),
		ITE(EQ(VARLP("fpcr_round_mode"), U32(0)), U32(RZ_FLOAT_RMODE_RNE),
			ITE(EQ(VARLP("fpcr_round_mode"), U32(1)), U32(RZ_FLOAT_RMODE_RTZ),
				ITE(EQ(VARLP("fpcr_round_mode"), U32(2)), U32(RZ_FLOAT_RMODE_RTN),
					U32(RZ_FLOAT_RMODE_RTP)))));
}

static RzILOpPure *fpu_fpcr_precision(void) {
	return LOGAND(SHIFTR0(VARG("fpcr"), U8(6)), U32(3));
}

static RzILOpFloat *fpu_to_format_with_fpcr_rmode(RzILOpFloat *value, RzFloatFormat format) {
	return FCONVERT_DYN_RMODE(format, VARL("round_mode"), value);
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

#ifdef RZ_CAPSTONE_HAS_M68K_FP_FORMATS
static RzILOpFloat *fpu_packed_one(void) {
	return BV2F(RZ_FLOAT_IEEE754_BIN_80,
		fpu_const80_bits(0x3fff, 0x8000000000000000ULL));
}

static RzILOpFloat *fpu_packed_ten(void) {
	return BV2F(RZ_FLOAT_IEEE754_BIN_80,
		fpu_const80_bits(0x4002, 0xa000000000000000ULL));
}

static RzILOpFloat *fpu_packed_pow10_const(ut8 selector) {
	ut16 sign_exp = 0;
	ut64 mantissa = 0;
	if (!fmovecr_const_parts(selector, &sign_exp, &mantissa)) {
		return NULL;
	}
	return BV2F(RZ_FLOAT_IEEE754_BIN_80,
		fpu_const80_bits(sign_exp, mantissa));
}

enum {
	M68K_PACKED_LOAD_INTEGER_BITS = 4096,
	M68K_PACKED_STORE_INTEGER_BITS = 12288,
};

/* Construct 5^packed_power_exp_abs exactly. Repeated shift-and-add is much
 * cheaper than multiplying two dense multi-kilobit RzIL bitvectors. */
static RzILOpEffect *fpu_packed_power5_effect(ut32 bits) {
	RzILOpEffect *body = SEQ2(
		SETL("packed_power5", ADD(VARL("packed_power5"), SHIFTL0(VARL("packed_power5"), U8(2)))),
		SETL("packed_power5_work", SUB(VARL("packed_power5_work"), U32(1))));
	return SEQ3(
		SETL("packed_power5", UNSIGNED(bits, U64(1))),
		SETL("packed_power5_work", VARL("packed_power_exp_abs")),
		REPEAT(NON_ZERO(VARL("packed_power5_work")), body));
}

static RzILOpEffect *fpu_packed_wide_multiply_u64_effect(ut32 bits,
	const char *wide_name, const char *multiplier_name, const char *result_name) {
	rz_return_val_if_fail(wide_name && multiplier_name && result_name, NULL);

	RzILOpEffect *add = BRANCH(
		LSB(VARL("packed_wide_mul_multiplier")),
		SETL("packed_wide_mul_result", ADD(VARL("packed_wide_mul_result"), VARL("packed_wide_mul_addend"))),
		EMPTY());
	RzILOpEffect *body = SEQ3(
		add,
		SETL("packed_wide_mul_addend", SHIFTL0(VARL("packed_wide_mul_addend"), U8(1))),
		SETL("packed_wide_mul_multiplier", SHIFTR0(VARL("packed_wide_mul_multiplier"), U8(1))));
	return SEQ5(
		SETL("packed_wide_mul_result", UNSIGNED(bits, U64(0))),
		SETL("packed_wide_mul_addend", VARL(wide_name)),
		SETL("packed_wide_mul_multiplier", VARL(multiplier_name)),
		REPEAT(NON_ZERO(VARL("packed_wide_mul_multiplier")), body),
		SETL(result_name, VARL("packed_wide_mul_result")));
}

/* Represent coefficient * 10^scale as numerator / denominator * 2^scale.
 * The coefficient is at most 64 bits; numerator and denominator use the
 * caller-selected width needed for the packed load or full-range FP80 store. */
static RzILOpEffect *fpu_packed_decimal_rational_effect(ut32 bits,
	const char *scale_name, RzILOpPure *coefficient) {
	rz_return_val_if_fail(scale_name && coefficient, NULL);

	RzILOpEffect *positive_scale = SEQ2(
		fpu_packed_wide_multiply_u64_effect(bits, "packed_power5", "packed_integer_coefficient", "packed_numerator"),
		SETL("packed_denominator", UNSIGNED(bits, U64(1))));
	RzILOpEffect *negative_scale = SEQ2(
		SETL("packed_numerator", UNSIGNED(bits, VARL("packed_integer_coefficient"))),
		SETL("packed_denominator", VARL("packed_power5")));
	return SEQ3(
		SETL("packed_integer_coefficient", UNSIGNED(64, coefficient)),
		fpu_packed_power5_effect(bits),
		BRANCH(SGE(VARL(scale_name), S32(0)), positive_scale, negative_scale));
}

static RzILOpEffect *fpu_packed_apply_binary_shift_effect(void) {
	return BRANCH(
		SGE(VARL("packed_binary_shift"), S32(0)),
		SETL("packed_numerator", SHIFTL0(VARL("packed_numerator"), VARL("packed_binary_shift"))),
		SETL("packed_denominator", SHIFTL0(VARL("packed_denominator"), NEG(VARL("packed_binary_shift")))));
}

/* The quotient is known to fit in 64 bits. Long division keeps the exact
 * remainder without invoking a second wide division or multiplication. */
static RzILOpEffect *fpu_packed_divide_rational_effect(void) {
	RzILOpEffect *take_bit = SEQ2(
		SETL("packed_remainder", SUB(VARL("packed_remainder"), VARL("packed_trial_denominator"))),
		SETL("packed_quotient", LOGOR(VARL("packed_quotient"), VARL("packed_quotient_bit"))));
	RzILOpEffect *body = SEQ4(
		BRANCH(UGE(VARL("packed_remainder"), VARL("packed_trial_denominator")), take_bit, EMPTY()),
		SETL("packed_trial_denominator", SHIFTR0(VARL("packed_trial_denominator"), U8(1))),
		SETL("packed_quotient_bit", SHIFTR0(VARL("packed_quotient_bit"), U8(1))),
		SETL("packed_divide_count", SUB(VARL("packed_divide_count"), U8(1))));
	return SEQ5(
		SETL("packed_remainder", VARL("packed_numerator")),
		SETL("packed_trial_denominator", SHIFTL0(VARL("packed_denominator"), U8(63))),
		SETL("packed_quotient", U64(0)),
		SETL("packed_quotient_bit", U64(0x8000000000000000ULL)),
		SEQ2(
			SETL("packed_divide_count", U8(64)),
			REPEAT(NON_ZERO(VARL("packed_divide_count")), body)));
}

static RzILOpBool *fpu_packed_round_quotient_up(void) {
	RzILOpBool *nearest = AND(
		EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RNE)),
		OR(
			UGT(VARL("packed_remainder"), SUB(VARL("packed_denominator"), VARL("packed_remainder"))),
			AND(EQ(VARL("packed_remainder"), SUB(VARL("packed_denominator"), VARL("packed_remainder"))),
				LSB(VARL("packed_quotient")))));
	RzILOpBool *directed = AND(
		NON_ZERO(VARL("packed_remainder")),
		OR(
			AND(INV(VARL("packed_negative")), EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTP))),
			AND(VARL("packed_negative"), EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTN)))));
	return OR(nearest, directed);
}

static RzILOpEffect *fpu_packed_bit_length_effect(const char *value_name,
	const char *work_name, const char *result_name) {
	rz_return_val_if_fail(value_name && work_name && result_name, NULL);

	RzILOpEffect *chunks = REPEAT(
		NON_ZERO(SHIFTR0(VARL(work_name), U8(64))),
		SEQ2(
			SETL(work_name, SHIFTR0(VARL(work_name), U8(64))),
			SETL(result_name, ADD(VARL(result_name), U32(64)))));
	RzILOpEffect *bits = REPEAT(
		NON_ZERO(VARL(work_name)),
		SEQ2(
			SETL(work_name, SHIFTR0(VARL(work_name), U8(1))),
			SETL(result_name, ADD(VARL(result_name), U32(1)))));
	return SEQ4(
		SETL(work_name, VARL(value_name)),
		SETL(result_name, U32(0)),
		chunks,
		bits);
}

/* Convert the finite packed coefficient to FP80 from an exact integer ratio.
 * Packed exponents cannot reach the FP80 denormal or overflow ranges. */
static RzILOpEffect *fpu_packed_load_finite_effect(void) {
	RzILOpEffect *seq = SETL("packed_negative",
		NON_ZERO(LOGAND(VARL("packed_header"), U32(0x80000000u))));
	seq = SEQ2(seq, fpu_packed_decimal_rational_effect(M68K_PACKED_LOAD_INTEGER_BITS, "packed_scale_exp", VARL("packed_coefficient")));
	seq = SEQ3(
		seq,
		fpu_packed_bit_length_effect("packed_numerator", "packed_numerator_bits_work", "packed_numerator_bits"),
		fpu_packed_bit_length_effect("packed_denominator", "packed_denominator_bits_work", "packed_denominator_bits"));
	seq = SEQ2(seq, SETL("packed_ratio_exp", SUB(VARL("packed_numerator_bits"), VARL("packed_denominator_bits"))));
	RzILOpBool *below_power = ITE(
		SGE(VARL("packed_ratio_exp"), S32(0)),
		ULT(VARL("packed_numerator"), SHIFTL0(VARL("packed_denominator"), VARL("packed_ratio_exp"))),
		ULT(SHIFTL0(VARL("packed_numerator"), NEG(VARL("packed_ratio_exp"))), VARL("packed_denominator")));
	seq = SEQ3(
		seq,
		SETL("packed_ratio_exp", SUB(VARL("packed_ratio_exp"), ITE(below_power, U32(1), U32(0)))),
		SETL("packed_binary_exp", ADD(VARL("packed_ratio_exp"), VARL("packed_scale_exp"))));
	seq = SEQ3(
		seq,
		SETL("packed_binary_shift", SUB(S32(63), VARL("packed_ratio_exp"))),
		fpu_packed_apply_binary_shift_effect());
	seq = SEQ2(seq, fpu_packed_divide_rational_effect());
	seq = SEQ3(
		seq,
		SETL("packed_input_inexact", NON_ZERO(VARL("packed_remainder"))),
		SETL("packed_round_up", fpu_packed_round_quotient_up()));
	seq = SEQ3(
		seq,
		SETL("packed_round_carry", AND(VARL("packed_round_up"), EQ(VARL("packed_quotient"), U64(0xffffffffffffffffULL)))),
		SETL("packed_result_mantissa",
			ITE(VARL("packed_round_carry"),
				U64(0x8000000000000000ULL),
				ADD(VARL("packed_quotient"), ITE(VARL("packed_round_up"), U64(1), U64(0))))));
	seq = SEQ2(seq, SETL("packed_result_exp", ADD(ADD(VARL("packed_binary_exp"), S32(0x3fff)), ITE(VARL("packed_round_carry"), U32(1), U32(0)))));
	RzILOpPure *sign_exp = LOGOR(
		ITE(VARL("packed_negative"), U16(0x8000), U16(0)),
		UNSIGNED(16, VARL("packed_result_exp")));
	return SEQ2(seq, SETL("packed_finite_bits", APPEND(sign_exp, VARL("packed_result_mantissa"))));
}

/* Decode the raw 96-bit packed-decimal representation into an FP80 local.
 * EXP3 is ignored on input. Non-decimal A-F nibbles deliberately retain
 * their numeric values 10-15, matching the repeatable MC6888x behavior. */
static RzILOpEffect *fpu_packed_decode_effect(RzILOpPure *raw, const char *name) {
	rz_return_val_if_fail(raw && name, NULL);

	RzILOpEffect *seq = SEQ4(
		SETL("packed_raw", raw),
		SETL("packed_header", UNSIGNED(32, SHIFTR0(VARL("packed_raw"), U8(64)))),
		SETL("packed_fraction", UNSIGNED(64, VARL("packed_raw"))),
		SETL("packed_coefficient", UNSIGNED(64, LOGAND(VARL("packed_header"), U32(0xf)))));
	for (ut32 i = 0; i < 16; i++) {
		ut8 shift = (ut8)(60 - i * 4);
		RzILOpPure *digit = UNSIGNED(64,
			LOGAND(SHIFTR0(VARL("packed_fraction"), U8(shift)), U64(0xf)));
		seq = SEQ2(seq, SETL("packed_coefficient", ADD(MUL(VARL("packed_coefficient"), U64(10)), digit)));
	}

	RzILOpPure *exp2 = MUL(
		LOGAND(SHIFTR0(VARL("packed_header"), U8(24)), U32(0xf)), U32(100));
	RzILOpPure *exp1 = MUL(
		LOGAND(SHIFTR0(VARL("packed_header"), U8(20)), U32(0xf)), U32(10));
	RzILOpPure *exp0 = LOGAND(SHIFTR0(VARL("packed_header"), U8(16)), U32(0xf));
	seq = SEQN(8,
		seq,
		SETL("packed_exp_magnitude", ADD(ADD(exp2, exp1), exp0)),
		SETL("packed_signed_exp",
			ITE(NON_ZERO(LOGAND(VARL("packed_header"), U32(0x40000000u))),
				NEG(VARL("packed_exp_magnitude")), VARL("packed_exp_magnitude"))),
		SETL("packed_scale_exp", SUB(VARL("packed_signed_exp"), S32(16))),
		SETL("packed_power_exp_abs",
			ITE(SLT(VARL("packed_scale_exp"), S32(0)),
				NEG(VARL("packed_scale_exp")), VARL("packed_scale_exp"))),
		SETL("packed_special",
			EQ(LOGAND(SHIFTR0(VARL("packed_header"), U8(16)), U32(0x7fff)), U32(0x7fff))),
		SETL("packed_zero", AND(IS_ZERO(LOGAND(VARL("packed_header"), U32(0xf))), IS_ZERO(VARL("packed_fraction")))),
		SETL("packed_input_snan", AND(VARL("packed_special"), AND(NON_ZERO(VARL("packed_fraction")), IS_ZERO(LOGAND(VARL("packed_fraction"), U64(0x4000000000000000ULL)))))));

	RzILOpBool *finite = AND(INV(VARL("packed_special")), INV(VARL("packed_zero")));
	RzILOpEffect *nonfinite = SEQ2(
		SETL("packed_finite_bits", UNSIGNED(80, U64(0))),
		SETL("packed_input_inexact", IL_FALSE));
	seq = SEQ2(seq, BRANCH(finite, fpu_packed_load_finite_effect(), nonfinite));

	RzILOpPure *sign_exp = LOGOR(
		ITE(NON_ZERO(LOGAND(VARL("packed_header"), U32(0x80000000u))), U16(0x8000), U16(0)),
		U16(0x7fff));
	RzILOpPure *special_mantissa = ITE(
		IS_ZERO(VARL("packed_fraction")),
		U64(0x8000000000000000ULL),
		VARL("packed_fraction"));
	RzILOpPure *special_bits = APPEND(sign_exp, special_mantissa);
	RzILOpPure *special_fp = BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("packed_special_bits"));
	RzILOpPure *zero_bits = APPEND(
		ITE(NON_ZERO(LOGAND(VARL("packed_header"), U32(0x80000000u))), U16(0x8000), U16(0)),
		U64(0));
	RzILOpFloat *finite_fp = BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("packed_finite_bits"));
	RzILOpFloat *value = ITE(
		VARL("packed_special"),
		special_fp,
		ITE(VARL("packed_zero"),
			BV2F(RZ_FLOAT_IEEE754_BIN_80, zero_bits), finite_fp));
	return SEQ3(seq,
		SETL("packed_special_bits", special_bits),
		SETL(name, value));
}

/* Normalize |src_fp| to [1, 10) while retaining a signed base-10 exponent.
 * FMOVECR's architectural 10^(2^n) constants make this logarithmic even for
 * the full FP80 decimal range; final one-decade loops correct boundaries. */
static RzILOpEffect *fpu_packed_normalize_effect(void) {
	RzILOpEffect *large = EMPTY();
	RzILOpEffect *small = EMPTY();
	for (int selector = 0x3f; selector >= 0x33; selector--) {
		ut32 power = 1u << (selector - 0x33);
		RzILOpFloat *large_const_cond = fpu_packed_pow10_const((ut8)selector);
		RzILOpFloat *large_const_body = fpu_packed_pow10_const((ut8)selector);
		RzILOpEffect *large_step = SEQ2(
			SETL("packed_norm", FDIV(RZ_FLOAT_RMODE_RNE, VARL("packed_norm"), large_const_body)),
			SETL("packed_decimal_exp", ADD(VARL("packed_decimal_exp"), U32(power))));
		large = SEQ2(large, BRANCH(FGE(VARL("packed_norm"), large_const_cond), large_step, EMPTY()));

		RzILOpFloat *small_const_cond = fpu_packed_pow10_const((ut8)selector);
		RzILOpFloat *small_const_body = fpu_packed_pow10_const((ut8)selector);
		RzILOpEffect *small_step = SEQ2(
			SETL("packed_norm", FMUL(RZ_FLOAT_RMODE_RNE, VARL("packed_norm"), small_const_body)),
			SETL("packed_decimal_exp", SUB(VARL("packed_decimal_exp"), U32(power))));
		small = SEQ2(small, BRANCH(FLT(FMUL(RZ_FLOAT_RMODE_RNE, VARL("packed_norm"), small_const_cond), fpu_packed_one()), small_step, EMPTY()));
	}

	large = SEQ2(large, REPEAT(FGE(VARL("packed_norm"), fpu_packed_ten()), SEQ2(SETL("packed_norm", FDIV(RZ_FLOAT_RMODE_RNE, VARL("packed_norm"), fpu_packed_ten())), SETL("packed_decimal_exp", ADD(VARL("packed_decimal_exp"), U32(1))))));
	small = SEQ2(small, REPEAT(FLT(VARL("packed_norm"), fpu_packed_one()), SEQ2(SETL("packed_norm", FMUL(RZ_FLOAT_RMODE_RNE, VARL("packed_norm"), fpu_packed_ten())), SETL("packed_decimal_exp", SUB(VARL("packed_decimal_exp"), U32(1))))));

	return SEQ3(
		SETL("packed_norm", FABS(VARL("src_fp"))),
		SETL("packed_decimal_exp", S32(0)),
		BRANCH(FGE(VARL("packed_norm"), fpu_packed_one()), large, small));
}
#endif

static RzILOpEffect *normalize_fpu_quotient_operand(const char *float_name, const char *bits_name,
	const char *exp_field_name, const char *exp_name, const char *mant_name) {
	RzILOpEffect *seq = SETL(bits_name, F2BV(fpu_to_format(VARL(float_name), RZ_FLOAT_IEEE754_BIN_80)));
	seq = SEQ4(
		seq,
		SETL(exp_field_name, UNSIGNED(32, LOGAND(UNSIGNED(16, SHIFTR0(VARL(bits_name), U8(64))), U16(0x7fff)))),
		SETL(exp_name, ITE(IS_ZERO(VARL(exp_field_name)), U32(1), VARL(exp_field_name))),
		SETL(mant_name, UNSIGNED(64, VARL(bits_name))));
	return SEQ2(seq, REPEAT(AND(NON_ZERO(VARL(mant_name)), INV(MSB(VARL(mant_name)))), SEQ2(SETL(mant_name, SHIFTL0(VARL(mant_name), U8(1))), SETL(exp_name, SUB(VARL(exp_name), U32(1))))));
}

static RzILOpPure *fpu_quotient_add_mod(RzILOpPure *left, RzILOpPure *right) {
	return LET("quot_mod_sum", ADD(left, right),
		ITE(UGE(VARLP("quot_mod_sum"), VARL("quot_modulus")),
			SUB(VARLP("quot_mod_sum"), VARL("quot_modulus")),
			VARLP("quot_mod_sum")));
}

static RzILOpEffect *multiply_fpu_quotient_mod(const char *left_name, const char *right_name, const char *result_name) {
	RzILOpEffect *seq = SETL("quot_mul_result", UNSIGNED(128, U32(0)));
	seq = SEQ3(
		seq,
		SETL("quot_mul_addend", VARL(left_name)),
		SETL("quot_mul_factor", VARL(right_name)));
	RzILOpEffect *add = BRANCH(
		LSB(VARL("quot_mul_factor")),
		SETL("quot_mul_result", fpu_quotient_add_mod(VARL("quot_mul_result"), VARL("quot_mul_addend"))),
		EMPTY());
	RzILOpEffect *double_addend = SETL("quot_mul_addend",
		fpu_quotient_add_mod(VARL("quot_mul_addend"), VARL("quot_mul_addend")));
	RzILOpEffect *shift_factor = SETL("quot_mul_factor", SHIFTR0(VARL("quot_mul_factor"), U8(1)));
	seq = SEQ2(seq, REPEAT(NON_ZERO(VARL("quot_mul_factor")), SEQ3(add, double_addend, shift_factor)));
	return SEQ2(seq, SETL(result_name, VARL("quot_mul_result")));
}

/* For normalized FP80 operands, the quotient magnitude is
 * dst_mant * 2^quot_exp_delta / src_mant. Reduce the scaled numerator
 * modulo 128 * src_mant so the exact low seven quotient bits survive even
 * when the full quotient exceeds FP80 precision. */
static RzILOpEffect *set_fpu_nonnegative_quotient_low7(ut32 insn_id) {
	RzILOpEffect *seq = SETL("quot_modulus",
		SHIFTL0(UNSIGNED(128, VARL("quot_src_mant")), U8(7)));
	seq = seq ? SEQ2(seq, SETL("quot_mod_value", UNSIGNED(128, VARL("quot_dst_mant")))) : SETL("quot_mod_value", UNSIGNED(128, VARL("quot_dst_mant")));
	seq = SEQ3(
		seq,
		SETL("quot_mod_factor", UNSIGNED(128, U32(2))),
		SETL("quot_mod_exp", VARL("quot_exp_delta")));
	RzILOpEffect *multiply_factor = BRANCH(
		LSB(VARL("quot_mod_exp")),
		multiply_fpu_quotient_mod("quot_mod_value", "quot_mod_factor", "quot_mod_value"),
		EMPTY());
	RzILOpEffect *square_factor = multiply_fpu_quotient_mod("quot_mod_factor", "quot_mod_factor", "quot_mod_factor");
	RzILOpEffect *shift_exp = SETL("quot_mod_exp", SHIFTR0(VARL("quot_mod_exp"), U8(1)));
	seq = SEQ7(
		seq,
		REPEAT(NON_ZERO(VARL("quot_mod_exp")), SEQ3(multiply_factor, square_factor, shift_exp)),
		SETL("quot_den", UNSIGNED(128, VARL("quot_src_mant"))),
		SETL("quot_floor", U32(0)),
		SETL("quot_remainder", VARL("quot_mod_value")),
		REPEAT(UGE(VARL("quot_remainder"), VARL("quot_den")), SEQ2(SETL("quot_remainder", SUB(VARL("quot_remainder"), VARL("quot_den"))), SETL("quot_floor", ADD(VARL("quot_floor"), U32(1))))),
		SETL("quot_trunc_low7", LOGAND(VARL("quot_floor"), U32(0x7f))));
	RzILOpPure *quotient = VARL("quot_floor");
	if (insn_id == M68K_INS_FREM) {
		RzILOpPure *round_up = BOOL_TO_BV(
			OR(UGT(SHIFTL0(VARL("quot_remainder"), U8(1)), VARL("quot_den")),
				AND(EQ(SHIFTL0(VARL("quot_remainder"), U8(1)), VARL("quot_den")),
					LSB(VARL("quot_floor")))),
			32);
		quotient = ADD(quotient, round_up);
	}
	return SEQ2(seq, SETL("quot_low7", LOGAND(quotient, U32(0x7f))));
}

static RzILOpEffect *set_fpu_negative_quotient_low7(ut32 insn_id) {
	RzILOpPure *round_up = insn_id == M68K_INS_FREM
		? BOOL_TO_BV(AND(EQ(VARL("quot_exp_delta"), S32(-1)),
				     UGT(VARL("quot_dst_mant"), VARL("quot_src_mant"))),
			  32)
		: U32(0);
	return SEQ2(SETL("quot_trunc_low7", U32(0)), SETL("quot_low7", round_up));
}

static RzILOpEffect *set_fpsr_quotient_byte(ut32 insn_id) {
	RzILOpEffect *seq = normalize_fpu_quotient_operand("src_fp", "quot_src_bits",
		"quot_src_exp_field", "quot_src_exp", "quot_src_mant");
	seq = seq ? SEQ2(seq, normalize_fpu_quotient_operand("dst_fp", "quot_dst_bits", "quot_dst_exp_field", "quot_dst_exp", "quot_dst_mant")) : normalize_fpu_quotient_operand("dst_fp", "quot_dst_bits", "quot_dst_exp_field", "quot_dst_exp", "quot_dst_mant");
	seq = SEQ2(seq, SETL("quot_exp_delta", SUB(VARL("quot_dst_exp"), VARL("quot_src_exp"))));
	RzILOpBool *valid = AND(
		AND(NE(VARL("quot_src_exp_field"), U32(0x7fff)),
			NE(VARL("quot_dst_exp_field"), U32(0x7fff))),
		NON_ZERO(VARL("quot_src_mant")));
	RzILOpEffect *set_valid_quotient = BRANCH(
		SLT(VARL("quot_exp_delta"), S32(0)),
		set_fpu_negative_quotient_low7(insn_id),
		set_fpu_nonnegative_quotient_low7(insn_id));
	seq = SEQ2(seq, BRANCH(valid, set_valid_quotient, SEQ2(SETL("quot_trunc_low7", U32(0)), SETL("quot_low7", U32(0)))));
	RzILOpPure *quotient_byte = LOGOR(
		SHIFTL0(BOOL_TO_BV(XOR(IS_FNEG(VARL("dst_fp")), IS_FNEG(VARL("src_fp"))), 32), U8(7)),
		VARL("quot_low7"));
	return SEQ2(seq, SETG("fpsr", LOGOR(LOGAND(VARG("fpsr"), U32(~M68K_FPSR_QUOTIENT_MASK)), SHIFTL0(quotient_byte, U8(M68K_FPSR_QUOTIENT_SHIFT)))));
}

static RzILOpFloat *fpu_nearest_remainder_result(void) {
	RzILOpFloat *truncated = FMOD_DYN_RMODE(VARL("round_mode"),
		VARLP("dst_ext"), VARLP("src_ext"));
	RzILOpFloat *twice_remainder = FADD_DYN_RMODE(VARL("round_mode"),
		FABS(VARLP("trunc_rem")), FABS(VARLP("trunc_rem")));
	RzILOpBool *adjust = OR(
		FLT(VARLP("abs_src"), VARLP("twice_rem")),
		AND(FEQ(VARLP("abs_src"), VARLP("twice_rem")),
			LSB(VARL("quot_trunc_low7"))));
	RzILOpFloat *signed_src_magnitude = ITE(
		IS_FNEG(VARLP("dst_ext")),
		FNEG(VARLP("abs_src")),
		VARLP("abs_src"));
	RzILOpFloat *adjusted = FSUB_DYN_RMODE(VARL("round_mode"),
		VARLP("trunc_rem"), VARLP("signed_src_magnitude"));
	return LET("trunc_rem", truncated,
		LET("abs_src", FABS(VARLP("src_ext")),
			LET("twice_rem", twice_remainder,
				LET("signed_src_magnitude", signed_src_magnitude,
					ITE(adjust, adjusted, VARLP("trunc_rem"))))));
}

/* Unrounded FREM remainder from already-converted 80-bit src80/dst80.
 * Used for UNFL (UM 6.1.5): compare the intermediate exponent, not the
 * PREC-rounded stored encoding. */
static RzILOpFloat *fpu_frem_unrounded_from_80(void) {
	RzILOpFloat *truncated = FMOD_DYN_RMODE(VARL("round_mode"),
		VARL("dst80"), VARL("src80"));
	RzILOpFloat *twice_remainder = FADD_DYN_RMODE(VARL("round_mode"),
		FABS(VARLP("trunc_rem")), FABS(VARLP("trunc_rem")));
	RzILOpBool *adjust = OR(
		FLT(VARLP("abs_src"), VARLP("twice_rem")),
		AND(FEQ(VARLP("abs_src"), VARLP("twice_rem")),
			LSB(VARL("quot_trunc_low7"))));
	RzILOpFloat *signed_src_magnitude = ITE(
		IS_FNEG(VARL("dst80")),
		FNEG(VARLP("abs_src")),
		VARLP("abs_src"));
	RzILOpFloat *adjusted = FSUB_DYN_RMODE(VARL("round_mode"),
		VARLP("trunc_rem"), VARLP("signed_src_magnitude"));
	return LET("trunc_rem", truncated,
		LET("abs_src", FABS(VARL("src80")),
			LET("twice_rem", twice_remainder,
				LET("signed_src_magnitude", signed_src_magnitude,
					ITE(adjust, adjusted, VARLP("trunc_rem"))))));
}

static bool fpu_insn_is_fsgl(ut32 insn_id) {
	return insn_id == M68K_INS_FSGLMUL || insn_id == M68K_INS_FSGLDIV;
}

/* FSGLMUL/FSGLDIV truncate both input mantissas to 24 bits before the
 * operation, but retain the extended exponent (PRM 5-112 / 5-115). */
static RzILOpFloat *fpu_fsgl_truncate_operand(RzILOpFloat *value) {
	RzILOpPure *bits = F2BV(fpu_to_format(value, RZ_FLOAT_IEEE754_BIN_80));
	RzILOpPure *sign_exp = UNSIGNED(16, SHIFTR0(VARLP("fsgl_operand_bits"), U8(64)));
	RzILOpPure *mant = UNSIGNED(64, VARLP("fsgl_operand_bits"));
	RzILOpPure *truncated_bits = APPEND(VARLP("fsgl_operand_sign_exp"),
		LOGAND(VARLP("fsgl_operand_mant"), U64(0xffffff0000000000ULL)));
	return LET("fsgl_operand_bits", bits,
		LET("fsgl_operand_sign_exp", sign_exp,
			LET("fsgl_operand_mant", mant,
				ITE(EQ(LOGAND(VARLP("fsgl_operand_sign_exp"), U16(0x7fff)), U16(0x7fff)),
					BV2F(RZ_FLOAT_IEEE754_BIN_80, VARLP("fsgl_operand_bits")),
					BV2F(RZ_FLOAT_IEEE754_BIN_80, truncated_bits)))));
}

/* FSGL result range control is extended precision even though the result
 * mantissa is rounded to 24 bits (PRM 5-112 / 5-115). Round the FP80
 * significand directly so a finite exponent outside the IEEE binary32
 * range is not turned into infinity or zero by FCONVERT(binary32). */
static RzILOpFloat *fpu_fsgl_round_result(RzILOpFloat *value) {
	RzILOpPure *bits = F2BV(value);
	RzILOpPure *sign_exp = UNSIGNED(16, SHIFTR0(VARLP("fsgl_result_bits"), U8(64)));
	RzILOpPure *exp = LOGAND(VARLP("fsgl_result_sign_exp"), U16(0x7fff));
	RzILOpPure *mant = UNSIGNED(64, VARLP("fsgl_result_bits"));
	RzILOpPure *kept = LOGAND(VARLP("fsgl_result_mant"), U64(0xffffff0000000000ULL));
	RzILOpPure *discarded = LOGAND(VARLP("fsgl_result_mant"), U64(0x000000ffffffffffULL));
	RzILOpBool *rne_up = AND(NON_ZERO(LOGAND(VARLP("fsgl_result_discarded"), U64(0x0000008000000000ULL))),
		OR(NON_ZERO(LOGAND(VARLP("fsgl_result_discarded"), U64(0x0000007fffffffffULL))),
			NON_ZERO(LOGAND(VARLP("fsgl_result_kept"), U64(0x0000010000000000ULL)))));
	RzILOpBool *round_up = ITE(EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RNE)), rne_up,
		ITE(EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTZ)), IL_FALSE,
			ITE(EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTP)),
				AND(INV(MSB(VARLP("fsgl_result_sign_exp"))), NON_ZERO(VARLP("fsgl_result_discarded"))),
				AND(MSB(VARLP("fsgl_result_sign_exp")), NON_ZERO(VARLP("fsgl_result_discarded"))))));
	RzILOpPure *rounded = ADD(VARLP("fsgl_result_kept"),
		ITE(VARLP("fsgl_result_round_up"), U64(0x0000010000000000ULL), U64(0)));
	RzILOpBool *carry = AND(VARLP("fsgl_result_round_up"),
		EQ(VARLP("fsgl_result_kept"), U64(0xffffff0000000000ULL)));
	RzILOpPure *new_exp = ITE(VARLP("fsgl_result_carry"),
		ADD(VARLP("fsgl_result_exp"), U16(1)),
		ITE(AND(IS_ZERO(VARLP("fsgl_result_exp")), MSB(VARLP("fsgl_result_rounded"))),
			U16(1), VARLP("fsgl_result_exp")));
	RzILOpPure *new_sign_exp = LOGOR(LOGAND(VARLP("fsgl_result_sign_exp"), U16(0x8000)),
		VARLP("fsgl_result_new_exp"));
	RzILOpPure *new_mant = ITE(VARLP("fsgl_result_carry"),
		U64(0x8000000000000000ULL), VARLP("fsgl_result_rounded"));
	RzILOpPure *rounded_bits = APPEND(VARLP("fsgl_result_new_sign_exp"), VARLP("fsgl_result_new_mant"));
	return LET("fsgl_result_bits", bits,
		LET("fsgl_result_sign_exp", sign_exp,
			LET("fsgl_result_exp", exp,
				LET("fsgl_result_mant", mant,
					LET("fsgl_result_kept", kept,
						LET("fsgl_result_discarded", discarded,
							LET("fsgl_result_round_up", round_up,
								LET("fsgl_result_rounded", rounded,
									LET("fsgl_result_carry", carry,
										LET("fsgl_result_new_exp", new_exp,
											LET("fsgl_result_new_sign_exp", new_sign_exp,
												LET("fsgl_result_new_mant", new_mant,
													ITE(EQ(VARLP("fsgl_result_exp"), U16(0x7fff)),
														BV2F(RZ_FLOAT_IEEE754_BIN_80, VARLP("fsgl_result_bits")),
														BV2F(RZ_FLOAT_IEEE754_BIN_80, rounded_bits))))))))))))));
}

static RzILOpFloat *fpu_binary_unrounded_result(ut32 insn_id) {
	RzILOpFloat *src_value = fpu_to_format_with_fpcr_rmode(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80);
	RzILOpFloat *dst_value = fpu_to_format_with_fpcr_rmode(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80);
	if (fpu_insn_is_fsgl(insn_id)) {
		src_value = fpu_fsgl_truncate_operand(src_value);
		dst_value = fpu_fsgl_truncate_operand(dst_value);
	}
	RzILOpFloat *result = NULL;
	switch (insn_id) {
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
		result = FADD_DYN_RMODE(VARL("round_mode"), VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
		result = FSUB_DYN_RMODE(VARL("round_mode"), VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FSGLMUL:
		result = FMUL_DYN_RMODE(VARL("round_mode"), VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FSGLDIV:
		result = FDIV_DYN_RMODE(VARL("round_mode"), VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FMOD:
		result = FMOD_DYN_RMODE(VARL("round_mode"), VARLP("dst_ext"), VARLP("src_ext"));
		break;
	case M68K_INS_FREM:
		result = fpu_nearest_remainder_result();
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
	if (fpu_insn_is_fsgl(insn_id)) {
		return fpu_fsgl_round_result(result);
	}
	if (fpu_binary_uses_fpcr_precision(insn_id)) {
		return fpu_result_with_fpcr_precision(result);
	}
	return fpu_result_to_fp80_with_fpcr_rmode(result, fpu_insn_result_format(ctx, insn_id));
}

static bool fpu_operand_to_float_local(M68KILCtx *ctx, const char *name, const char *raw80_name, const cs_m68k_op *op, ut32 bits, RzILOpEffect **seq) {
	RzILOpFloat *value = NULL;
	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	bool raw80_set = false;

	if (op->type == M68K_OP_MEM && op->address_mode == M68K_AM_NONE) {
		return false;
	}
	if (rz_m68k_op_is_fpu_reg(op)) {
		RzILOpPure *raw = m68k_read_reg_sized(ctx, op->reg, 80);
		if (raw80_name) {
			*seq = *seq ? SEQ2(*seq, SETL(raw80_name, raw)) : SETL(raw80_name, raw);
			value = BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL(raw80_name));
			raw80_set = true;
		} else {
			value = BV2F(RZ_FLOAT_IEEE754_BIN_80, raw);
		}
	} else if (op->type == M68K_OP_FP_SINGLE) {
		value = F32(op->simm);
	} else if (op->type == M68K_OP_FP_DOUBLE) {
		value = F64(op->dimm);
#ifdef RZ_CAPSTONE_HAS_M68K_FP_FORMATS
	} else if (op->type == M68K_OP_FP_EXTENDED) {
		RzILOpPure *raw80 = fpu_const80_bits(op->fp_extended.sign_exp, op->fp_extended.significand);
		if (raw80_name) {
			*seq = *seq ? SEQ2(*seq, SETL(raw80_name, raw80)) : SETL(raw80_name, raw80);
			value = BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL(raw80_name));
			raw80_set = true;
		} else {
			value = BV2F(RZ_FLOAT_IEEE754_BIN_80, raw80);
		}
	} else if (op->type == M68K_OP_FP_PACKED || rz_m68k_fpu_size_is_packed(ctx->m68k)) {
		return false;
#endif
	} else if (ctx->m68k->op_size.type == M68K_SIZE_TYPE_FPU) {
		if (!rz_m68k_op_is_mem_addr(op)) {
			return false;
		}
		ut32 access_bits = fpu_external_bits(ctx, bits);
		RzILOpPure *raw = m68k_read_operand(ctx, op, access_bits, &pre, &post);
		if (!raw) {
			return false;
		}
		if (pre) {
			*seq = *seq ? SEQ2(*seq, pre) : pre;
		}
		if (rz_m68k_fpu_size_is_extended(ctx->m68k)) {
			*seq = *seq ? SEQ2(*seq, SETL("mem_ext", raw)) : SETL("mem_ext", raw);
			RzILOpPure *raw80 = fpu_ext96_to_fp80(VARL("mem_ext"));
			if (raw80_name) {
				*seq = SEQ2(*seq, SETL(raw80_name, raw80));
				value = BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL(raw80_name));
				raw80_set = true;
			} else {
				value = BV2F(RZ_FLOAT_IEEE754_BIN_80, raw80);
			}
		} else {
			value = BV2F(fpu_format_for_bits(bits), raw);
		}
	} else {
		RzILOpPure *raw = m68k_read_operand(ctx, op, bits, &pre, &post);
		if (!raw) {
			return false;
		}
		if (pre) {
			*seq = *seq ? SEQ2(*seq, pre) : pre;
		}
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
	*seq = *seq ? SEQ2(*seq, SETL(name, value)) : SETL(name, value);
	if (raw80_name && !raw80_set) {
		*seq = SEQ2(*seq, SETL(raw80_name, F2BV(fpu_to_format(VARL(name), RZ_FLOAT_IEEE754_BIN_80))));
	}
	if (post) {
		*seq = SEQ2(*seq, post);
	}
	return true;
}

static RzILOpEffect *set_fpsr_cc_from_float_local(const char *name) {
	return m68k_set_fpsr_cc(
		IS_FNEG(VARL(name)),
		IS_FZERO(VARL(name)),
		IS_FINF(VARL(name)),
		IS_FNAN(VARL(name)));
}

static RzILOpBool *fpu_cmp_nan(const char *lhs, const char *rhs) {
	return OR(IS_FNAN(VARL(lhs)), IS_FNAN(VARL(rhs)));
}

static RzILOpEffect *set_fpsr_cc_from_float_cmp(const char *lhs, const char *rhs) {
	/* FCMP always clears I (UM 4-31). N is the sign of dest−src (4.5.5.1 /
	 * Table 2-1). Finite x−x is +0 (Z only). Dest sign applies only when the
	 * table hard-wires NZ: both zeros or both infinities. */
	RzILOpBool *nan = fpu_cmp_nan(lhs, rhs);
	RzILOpBool *eq_signed_zero_or_inf = AND(FEQ(VARL(lhs), VARL(rhs)),
		AND(OR(AND(IS_FZERO(VARL(lhs)), IS_FZERO(VARL(rhs))),
			    AND(IS_FINF(VARL(lhs)), IS_FINF(VARL(rhs)))),
			IS_FNEG(VARL(lhs))));
	return m68k_set_fpsr_cc(
		AND(INV(nan), OR(FLT(VARL(lhs), VARL(rhs)), eq_signed_zero_or_inf)),
		AND(INV(fpu_cmp_nan(lhs, rhs)), FEQ(VARL(lhs), VARL(rhs))),
		IL_FALSE,
		fpu_cmp_nan(lhs, rhs));
}

static RzILOpEffect *fpu_read_failure_label(M68KILCtx *ctx, const cs_m68k_op *op) {
	if (rz_m68k_fpu_op_detail_is_invalid(op)) {
		return NULL;
	}
	return m68k_label(rz_m68k_fpu_op_is_illegal_read(ctx->m68k, op) ? "m68k_illegal" : "m68k_unimplemented");
}

static RzILOpEffect *fpu_write_failure_label(M68KILCtx *ctx, const cs_m68k_op *op) {
	if (rz_m68k_fpu_op_detail_is_invalid(op)) {
		return NULL;
	}
	return m68k_label(rz_m68k_fpu_op_is_illegal_write(ctx->m68k, op) ? "m68k_illegal" : "m68k_unimplemented");
}

static RzILOpEffect *fpu_write_float_local(M68KILCtx *ctx, const cs_m68k_op *dst, ut32 bits, const char *name, RzILOpEffect *seq) {
	RzILOpPure *value = NULL;
	if (dst->type == M68K_OP_MEM && dst->address_mode == M68K_AM_NONE) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	if (rz_m68k_op_is_fpu_reg(dst)) {
		RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, 80, F2BV(fpu_to_format(VARL(name), RZ_FLOAT_IEEE754_BIN_80)));
		if (!write) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		return seq ? SEQ2(seq, write) : write;
	}
	if (ctx->m68k->op_size.type == M68K_SIZE_TYPE_FPU) {
		if (!rz_m68k_op_is_mem_addr(dst)) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		if (rz_m68k_fpu_size_is_extended(ctx->m68k)) {
			seq = seq ? SEQ2(seq, SETL("fp80_bits", F2BV(fpu_to_format(VARL(name), RZ_FLOAT_IEEE754_BIN_80)))) : SETL("fp80_bits", F2BV(fpu_to_format(VARL(name), RZ_FLOAT_IEEE754_BIN_80)));
			value = fpu_fp80_to_ext96(VARL("fp80_bits"));
			bits = M68K_FMOVEM_EXTENDED_BITS;
		} else {
			RzFloatFormat format = fpu_format_for_bits(bits);
			value = F2BV(fpu_to_format_with_fpcr_rmode(VARL(name), format));
		}
	} else if (bits == 8 || bits == 16 || bits == 32) {
		value = F2SINT_DYN_RMODE(bits, VARL("round_mode"), VARL(name));
	} else {
		rz_il_op_effect_free(seq);
		return NULL;
	}

	RzILOpEffect *write = m68k_write_operand(ctx, dst, bits, value);
	if (!write) {
		rz_il_op_effect_free(seq);
		return NULL;
	}
	return seq ? SEQ2(seq, write) : write;
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

/* FMOVECR rebuilds the exception byte (PRM 5-83). INEX2 is set when the
 * rounded result is not the extended-precision ROM constant (UM 6.1.7).
 * Accrued INEX is sticky (PRM 1.2.3.4). */
static RzILOpEffect *set_fpsr_fmovecr_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *inex2 = ITE(INV(EQ(VARL("src_bits"), F2BV(VARL("res_fp")))),
		U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)),
		U32(0));
	return SETG("fpsr", LOGOR(cleared, inex2));
}

/* 80-bit extended is an integer iff it is ±0 or no significand bit sits
 * below the units place. Do not use FEQ of a SINT2F round-trip: RzIL
 * FEQ is a bit-order compare of encodings, not numerical equality. */
static RzILOpBool *fpu_fp80_is_integer(void) {
	return OR(AND(IS_ZERO(VARL("src_exp")), IS_ZERO(VARL("src_man"))),
		AND(UGE(VARL("src_exp"), U16(0x3fff)),
			OR(UGE(VARL("src_exp"), U16(0x403e)),
				IS_ZERO(LOGAND(VARL("src_man"),
					SUB(SHIFTL0(U64(1), UNSIGNED(8, SUB(U16(0x403e), VARL("src_exp")))),
						U64(1)))))));
}

static RzILOpBool *fpu_fmove_src_special(void) {
	return OR(IS_FINF(VARL("src_fp")), IS_FNAN(VARL("src_fp")));
}

static RzILOpBool *fpu_fmove_real_ovfl(void) {
	return AND(INV(fpu_fmove_src_special()), OR(IS_FINF(VARL("dest_fp")), UGE(VARL("src_exp"), VARL("ovfl_exp"))));
}

static RzILOpBool *fpu_fmove_real_unfl(void) {
	return AND(INV(fpu_fmove_src_special()),
		AND(INV(IS_FZERO(VARL("src_fp"))), ULT(VARL("src_exp"), VARL("unfl_exp"))));
}

static RzILOpBool *fpu_fmove_real_inex2(void) {
	return AND(INV(IS_FNAN(VARL("src_fp"))), AND(INV(IS_FINF(VARL("src_fp"))), INV(EQ(VARL("src_bits"), F2BV(VARL("back_fp"))))));
}

static RzILOpPure *fpu_exc_with_src_snan(RzILOpPure *flags);

/* FMOVE to S/D: FPCC unchanged (PRM 5-76). OVFL if the source exponent
 * reaches the dest format maximum (UM 6.1.4). UNFL if the unrounded source
 * exponent is below the dest format minimum normalized exponent (UM 6.1.5).
 * INEX2 if the dest encoding is not the source (UM 6.1.7). Accrued UNFL
 * needs UNFL and INEX2; accrued INEX follows INEX2 or OVFL (UM 2.3.4).
 * Do not copy SoftFloat flags. */
static RzILOpEffect *set_fpsr_fmove_real_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(LOGOR(
					  ITE(fpu_fmove_real_ovfl(), U32((1u << M68K_FPSR_EXC_OVFL) | (1u << M68K_FPSR_AEXC_OVFL) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)),
					  ITE(fpu_fmove_real_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0))),
		LOGOR(
			ITE(AND(fpu_fmove_real_unfl(), fpu_fmove_real_inex2()), U32(1u << M68K_FPSR_AEXC_UNFL), U32(0)),
			ITE(fpu_fmove_real_inex2(), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_src_snan(flags)));
}

/* FMOVE to FPn (UM 4-64): OVFL cleared. UNFL if the source is an extended
 * denormal (UM 6.1.5); a single/double denormal is normalized when converted
 * to 80-bit, so it does not UNFL. INEX2 if PREC rounding changes the 80-bit
 * encoding (UM 6.1.7 / 4-64 table). Quotient unchanged. */
static RzILOpBool *fpu_fmove_fpn_unfl(void) {
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FINF(VARL("src_fp"))),
			AND(INV(IS_FZERO(VARL("src_fp"))),
				IS_ZERO(VARL("src_exp")))));
}

static RzILOpBool *fpu_fmove_fpn_inex2(void) {
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		INV(EQ(VARL("res_bits"), VARL("src80_bits"))));
}

static RzILOpEffect *set_fpsr_fmove_fpn_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(
		ITE(fpu_fmove_fpn_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0)),
		LOGOR(
			ITE(AND(fpu_fmove_fpn_unfl(), fpu_fmove_fpn_inex2()), U32(1u << M68K_FPSR_AEXC_UNFL), U32(0)),
			ITE(fpu_fmove_fpn_inex2(), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_src_snan(flags)));
}

/* FINT/FINTRZ: CC from the integer result (UM 4-50). OPERR/OVFL/UNFL/DZ
 * cleared. INEX2 if the source is finite and not an integer (UM 6.1.7). */
static RzILOpEffect *set_fpsr_fint_exc(void) {
	RzILOpBool *inex2 = AND(INV(IS_FNAN(VARL("src_fp"))), AND(INV(IS_FINF(VARL("src_fp"))), INV(fpu_fp80_is_integer())));
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = ITE(inex2, U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_src_snan(flags)));
}

/* FGETEXP/FGETMAN: CC from the extracted result (UM 4-45 / 4-47).
 * OPERR if the source is ±infinity. Other EXC bits cleared. Quotient
 * is unchanged. Do not follow QEMU: SoftFloat flags are not Motorola EXC. */
static RzILOpEffect *set_fpsr_fget_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = ITE(IS_FINF(VARL("src_fp")),
		U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)),
		U32(0));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_src_snan(flags)));
}

/* FSQRT: CC from the root (UM 4-109). OPERR if the source is negative
 * and not zero. -0 stays -0 without OPERR. INEX2 if the stored root is
 * not exact (UM 6.1.7): compare directed sqrt results, then account for
 * destination-precision rounding. Other EXC bits cleared. Quotient unchanged. */
static RzILOpBool *fpu_fsqrt_operr(void) {
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(IS_FNEG(VARL("src_fp")), INV(IS_FZERO(VARL("src_fp")))));
}

static RzILOpBool *fpu_fsqrt_inex2(void) {
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FINF(VARL("src_fp"))),
			AND(INV(IS_FZERO(VARL("src_fp"))),
				AND(INV(fpu_fsqrt_operr()),
					OR(INV(EQ(VARL("sqrt_rtz_bits"), VARL("sqrt_rtp_bits"))),
						INV(EQ(VARL("res_bits"), VARL("sqrt_rne_bits"))))))));
}

static RzILOpEffect *set_fpsr_fsqrt_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(
		ITE(fpu_fsqrt_operr(), U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
		ITE(fpu_fsqrt_inex2(), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_src_snan(flags)));
}

/* SNAN: NaN with the format's quiet bit clear (IEEE 754-2008 / UM 4.5.4.2).
 * Detect on the original encoding width: F2BV of a single is 32 bits.
 * Quieting is FCONVERT to 80-bit, which yields a QNaN. Do not use FEQ. */
static RzILOpBool *fpu_is_snan(const char *fp_name) {
	return LET("snan_bits", CAST(80, IL_FALSE, F2BV(VARL(fp_name))),
		AND(IS_FNAN(VARL(fp_name)),
			IS_ZERO(LOGAND(VARLP("snan_bits"),
				ITE(IS_ZERO(SHIFTR0(VARLP("snan_bits"), U8(32))),
					UN(80, 0x00400000),
					ITE(IS_ZERO(SHIFTR0(VARLP("snan_bits"), U8(64))),
						UN(80, 0x0008000000000000ull),
						UN(80, 0x4000000000000000ull)))))));
}

static RzILOpPure *fpu_quiet_fp80_nan_bits(RzILOpPure *bits) {
	rz_return_val_if_fail(bits, NULL);
	return LOGOR(UNSIGNED(80, bits), UN(80, 0x4000000000000000ULL));
}

static RzILOpBool *fpu_binary_snan(void) {
	return OR(fpu_is_snan("src_fp"), fpu_is_snan("dst_fp"));
}

static RzILOpPure *fpu_binary_snan_result(void) {
	/* After quieting, 4.5.4.1: one NAN → that NAN; both → dest. */
	return ITE(IS_FNAN(VARL("dst_fp")),
		fpu_to_format(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80),
		fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80));
}

static RzILOpPure *fpu_exc_with_snan(RzILOpPure *flags) {
	return ITE(fpu_binary_snan(),
		U32((1u << M68K_FPSR_EXC_SNAN) | (1u << M68K_FPSR_AEXC_IOP)),
		flags);
}

static RzILOpPure *fpu_exc_with_src_snan(RzILOpPure *flags) {
	return ITE(fpu_is_snan("src_fp"),
		U32((1u << M68K_FPSR_EXC_SNAN) | (1u << M68K_FPSR_AEXC_IOP)),
		flags);
}

/* FADD: CC from the sum (UM 4-13 / Figure 4-2). OPERR if the operands
 * are infinities of opposite sign. Same-sign infinities stay inf.
 * INEX2 if RN/RZ/RP/RM 80-bit encodings disagree (UM 6.1.7; not FEQ).
 * OVFL if the unrounded 80-bit sum exponent meets the selected PREC
 * format maximum (UM 6.1.4 / 3.2.4); trap-disabled RZ stores the largest
 * finite number. UNFL if the unrounded 80-bit sum exponent is below the
 * selected PREC minimum normalized exponent (UM 6.1.5); exact 0 from
 * cancellation is not UNFL. Accrued UNFL needs UNFL and INEX2; accrued
 * INEX follows INEX2 or OVFL (UM 2.3.4). Quotient unchanged. */
static bool fpu_insn_is_fadd(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_FADD:
	case M68K_INS_FSADD:
	case M68K_INS_FDADD:
		return true;
	default:
		return false;
	}
}

static RzILOpBool *fpu_fadd_operr(void) {
	return AND(IS_FINF(VARL("src_fp")),
		AND(IS_FINF(VARL("dst_fp")),
			XOR(IS_FNEG(VARL("src_fp")), IS_FNEG(VARL("dst_fp")))));
}

static RzILOpBool *fpu_fadd_ovfl(void) {
	/* UM 6.1.4: overflow if the unrounded intermediate exponent meets
	 * the selected PREC format maximum. Trap-disabled RZ stores the
	 * largest finite number, so IS_FINF(res) is not sufficient. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					ITE(EQ(VARL("precision"), U32(1)),
						UGE(VARL("exact_exp"), U16(0x407f)),
						ITE(EQ(VARL("precision"), U32(2)),
							UGE(VARL("exact_exp"), U16(0x43ff)),
							UGE(VARL("exact_exp"), U16(0x7fff))))))));
}

static RzILOpBool *fpu_fadd_inex2(void) {
	/* +0 vs -0 is an exact cancellation whose sign follows the rounding
	 * mode (UM 4-21 note 1). That is not INEX2. */
	RzILOpBool *signed_zero_only = AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rne_bits"))),
		AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtz_bits"))),
			AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtp_bits"))),
				IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtn_bits"))))));
	return AND(INV(fpu_fadd_operr()),
		AND(INV(IS_FNAN(VARL("src_fp"))),
			AND(INV(IS_FNAN(VARL("dst_fp"))),
				AND(INV(signed_zero_only),
					OR(INV(EQ(VARL("res_bits"), VARL("rne_bits"))),
						OR(INV(EQ(VARL("rne_bits"), VARL("rtz_bits"))),
							OR(INV(EQ(VARL("rne_bits"), VARL("rtp_bits"))),
								INV(EQ(VARL("rne_bits"), VARL("rtn_bits"))))))))));
}

static RzILOpBool *fpu_fadd_unfl(void) {
	/* UM 6.1.5: underflow if the unrounded intermediate exponent is too
	 * small to be a normalized number in the selected PREC. A single
	 * denormal converted back to 80-bit is renormalized, so res_exp==0
	 * is not sufficient. Exact 0 from cancellation is not UNFL. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(fpu_fadd_operr()),
						AND(INV(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rne_bits")))),
							ITE(EQ(VARL("precision"), U32(1)),
								ULT(VARL("exact_exp"), U16(0x3f81)),
								ITE(EQ(VARL("precision"), U32(2)),
									ULT(VARL("exact_exp"), U16(0x3c01)),
									IS_ZERO(VARL("exact_exp"))))))))));
}

static RzILOpEffect *set_fpsr_fadd_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(LOGOR(
					  ITE(fpu_fadd_operr(), U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
					  ITE(fpu_fadd_ovfl(), U32((1u << M68K_FPSR_EXC_OVFL) | (1u << M68K_FPSR_AEXC_OVFL) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))),
		LOGOR(LOGOR(
			      ITE(fpu_fadd_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0)),
			      ITE(AND(fpu_fadd_unfl(), fpu_fadd_inex2()), U32(1u << M68K_FPSR_AEXC_UNFL), U32(0))),
			ITE(fpu_fadd_inex2(), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_snan(flags)));
}

/* FSUB: CC from the difference (UM 4-110). OPERR if the operands are
 * like-signed infinities. Opposite-sign infinities stay inf.
 * INEX2 if RN/RZ/RP/RM 80-bit encodings disagree (UM 6.1.7; not FEQ),
 * or the stored encoding is not the 80-bit difference.
 * OVFL if the unrounded 80-bit difference exponent meets the selected
 * PREC format maximum (UM 6.1.4 / 3.2.4); trap-disabled RZ stores the
 * largest finite number. UNFL if the unrounded 80-bit difference exponent
 * is below the selected PREC minimum normalized exponent (UM 6.1.5);
 * exact 0 from cancellation is not UNFL. Accrued UNFL needs UNFL and
 * INEX2; accrued INEX follows INEX2 or OVFL (UM 2.3.4).
 * Quotient unchanged. */
static bool fpu_insn_is_fsub(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_FSUB:
	case M68K_INS_FSSUB:
	case M68K_INS_FDSUB:
		return true;
	default:
		return false;
	}
}

static RzILOpBool *fpu_fsub_operr(void) {
	return AND(IS_FINF(VARL("src_fp")),
		AND(IS_FINF(VARL("dst_fp")),
			INV(XOR(IS_FNEG(VARL("src_fp")), IS_FNEG(VARL("dst_fp"))))));
}

static RzILOpBool *fpu_fsub_ovfl(void) {
	/* UM 6.1.4: overflow if the unrounded intermediate exponent meets
	 * the selected PREC format maximum. Trap-disabled RZ stores the
	 * largest finite number, so IS_FINF(res) is not sufficient. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					ITE(EQ(VARL("precision"), U32(1)),
						UGE(VARL("exact_exp"), U16(0x407f)),
						ITE(EQ(VARL("precision"), U32(2)),
							UGE(VARL("exact_exp"), U16(0x43ff)),
							UGE(VARL("exact_exp"), U16(0x7fff))))))));
}

static RzILOpBool *fpu_fsub_inex2(void) {
	/* +0 vs -0 is an exact cancellation whose sign follows the rounding
	 * mode (UM 4-110 note 1). That is not INEX2. */
	RzILOpBool *signed_zero_only = AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rne_bits"))),
		AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtz_bits"))),
			AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtp_bits"))),
				IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtn_bits"))))));
	return AND(INV(fpu_fsub_operr()),
		AND(INV(IS_FNAN(VARL("src_fp"))),
			AND(INV(IS_FNAN(VARL("dst_fp"))),
				AND(INV(signed_zero_only),
					OR(INV(EQ(VARL("res_bits"), VARL("rne_bits"))),
						OR(INV(EQ(VARL("rne_bits"), VARL("rtz_bits"))),
							OR(INV(EQ(VARL("rne_bits"), VARL("rtp_bits"))),
								INV(EQ(VARL("rne_bits"), VARL("rtn_bits"))))))))));
}

static RzILOpBool *fpu_fsub_unfl(void) {
	/* UM 6.1.5: underflow if the unrounded intermediate exponent is too
	 * small to be a normalized number in the selected PREC. A single
	 * denormal converted back to 80-bit is renormalized, so res_exp==0
	 * is not sufficient. Exact 0 from cancellation is not UNFL. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(fpu_fsub_operr()),
						AND(INV(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rne_bits")))),
							ITE(EQ(VARL("precision"), U32(1)),
								ULT(VARL("exact_exp"), U16(0x3f81)),
								ITE(EQ(VARL("precision"), U32(2)),
									ULT(VARL("exact_exp"), U16(0x3c01)),
									IS_ZERO(VARL("exact_exp"))))))))));
}

static RzILOpEffect *set_fpsr_fsub_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(LOGOR(
					  ITE(fpu_fsub_operr(), U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
					  ITE(fpu_fsub_ovfl(), U32((1u << M68K_FPSR_EXC_OVFL) | (1u << M68K_FPSR_AEXC_OVFL) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))),
		LOGOR(LOGOR(
			      ITE(fpu_fsub_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0)),
			      ITE(AND(fpu_fsub_unfl(), fpu_fsub_inex2()), U32(1u << M68K_FPSR_AEXC_UNFL), U32(0))),
			ITE(fpu_fsub_inex2(), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_snan(flags)));
}

/* FMUL: CC from the product (UM 4-79). OPERR if one operand is 0 and the
 * other is ±infinity (UM Table 6-2). 0×0 stays 0; inf×inf stays inf.
 * INEX2 if RN/RZ/RP/RM 80-bit encodings disagree (UM 6.1.7; not FEQ),
 * or the stored encoding is not the 80-bit product.
 * OVFL if the unrounded 80-bit product exponent meets the selected
 * PREC format maximum (UM 6.1.4 / 3.2.4); trap-disabled RZ stores the
 * largest finite number. UNFL if the unrounded 80-bit product exponent
 * is below the selected PREC minimum normalized exponent (UM 6.1.5).
 * Accrued UNFL needs UNFL and INEX2; accrued INEX follows INEX2 or OVFL
 * (UM 2.3.4). Quotient unchanged. */
static bool fpu_insn_is_fmul(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_FMUL:
	case M68K_INS_FSMUL:
	case M68K_INS_FDMUL:
	case M68K_INS_FSGLMUL:
		return true;
	default:
		return false;
	}
}

static RzILOpBool *fpu_fmul_operr(void) {
	return OR(AND(IS_FZERO(VARL("src_fp")), IS_FINF(VARL("dst_fp"))),
		AND(IS_FINF(VARL("src_fp")), IS_FZERO(VARL("dst_fp"))));
}

static RzILOpBool *fpu_fmul_ovfl(void) {
	/* UM 6.1.4: overflow if the unrounded intermediate exponent meets
	 * the selected PREC format maximum. Trap-disabled RZ stores the
	 * largest finite number, so IS_FINF(res) is not sufficient. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(IS_FZERO(VARL("src_fp"))),
						AND(INV(IS_FZERO(VARL("dst_fp"))),
							ITE(EQ(VARL("precision"), U32(1)),
								UGE(VARL("exact_exp"), U16(0x407f)),
								ITE(EQ(VARL("precision"), U32(2)),
									UGE(VARL("exact_exp"), U16(0x43ff)),
									UGE(VARL("exact_exp"), U16(0x7fff))))))))));
}

static RzILOpBool *fpu_fmul_inex2(void) {
	RzILOpBool *signed_zero_only = AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rne_bits"))),
		AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtz_bits"))),
			AND(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtp_bits"))),
				IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("rtn_bits"))))));
	return AND(INV(fpu_fmul_operr()),
		AND(INV(IS_FNAN(VARL("src_fp"))),
			AND(INV(IS_FNAN(VARL("dst_fp"))),
				AND(INV(signed_zero_only),
					OR(INV(EQ(VARL("res_bits"), VARL("rne_bits"))),
						OR(INV(EQ(VARL("rne_bits"), VARL("rtz_bits"))),
							OR(INV(EQ(VARL("rne_bits"), VARL("rtp_bits"))),
								INV(EQ(VARL("rne_bits"), VARL("rtn_bits"))))))))));
}

static RzILOpBool *fpu_fmul_unfl(void) {
	/* UM 6.1.5: underflow if the unrounded intermediate exponent is too
	 * small to be a normalized number in the selected PREC. A single
	 * denormal converted back to 80-bit is renormalized, so res_exp==0
	 * is not sufficient. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(IS_FZERO(VARL("src_fp"))),
						AND(INV(IS_FZERO(VARL("dst_fp"))),
							AND(INV(fpu_fmul_operr()),
								ITE(EQ(VARL("precision"), U32(1)),
									ULT(VARL("exact_exp"), U16(0x3f81)),
									ITE(EQ(VARL("precision"), U32(2)),
										ULT(VARL("exact_exp"), U16(0x3c01)),
										IS_ZERO(VARL("exact_exp")))))))))));
}

static RzILOpEffect *set_fpsr_fmul_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(LOGOR(
					  ITE(fpu_fmul_operr(), U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
					  ITE(fpu_fmul_ovfl(), U32((1u << M68K_FPSR_EXC_OVFL) | (1u << M68K_FPSR_AEXC_OVFL) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))),
		LOGOR(LOGOR(
			      ITE(fpu_fmul_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0)),
			      ITE(AND(fpu_fmul_unfl(), fpu_fmul_inex2()), U32(1u << M68K_FPSR_AEXC_UNFL), U32(0))),
			ITE(fpu_fmul_inex2(), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_snan(flags)));
}

/* FMOD/FREM: OPERR if the source is 0 or the destination is infinity
 * (UM 4-61 / 4-85, Table 6-2). NaNs follow 4.5.4. Finite dest and infinite
 * source return dest without OPERR, then the normal end rounding (4-61
 * note 2 / 4-85 note 2). FMOD INEX2 if the stored encoding is not the
 * unrounded 80-bit remainder or dest (UM 6.1.7; not FEQ). PREC=S/D can
 * also set OVFL. UNFL if the unrounded intermediate exponent is below the
 * selected PREC minimum normalized exponent (UM 6.1.5). FREM still rounds
 * dest; INEX2 and OVFL are cleared (UM 4-86). Quotient byte is loaded
 * separately. */
static bool fpu_insn_is_fmod(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_FMOD:
	case M68K_INS_FREM:
		return true;
	default:
		return false;
	}
}

static RzILOpBool *fpu_fmod_operr(void) {
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			OR(IS_FZERO(VARL("src_fp")), IS_FINF(VARL("dst_fp")))));
}

static RzILOpBool *fpu_fmod_inex2(void) {
	/* UM 6.1.7 / 4-61 note 2: INEX2 if the stored remainder or dest is not
	 * the unrounded 80-bit encoding (PREC=S/D rounds it). Compare encodings,
	 * not FEQ. Finite dest and infinite source still go through rounding. */
	return AND(INV(fpu_fmod_operr()),
		AND(INV(IS_FNAN(VARL("src_fp"))),
			AND(INV(IS_FNAN(VARL("dst_fp"))),
				AND(INV(IS_FZERO(VARL("src_fp"))),
					INV(EQ(VARL("res_bits"), VARL("exact_bits")))))));
}

static RzILOpBool *fpu_fmod_ovfl(void) {
	/* UM 6.1.4 / 4-61 note 2: overflow if the unrounded intermediate
	 * exponent meets the selected PREC format maximum. Trap-disabled RZ
	 * (and RM+/RP−) stores the largest finite number, so IS_FINF(res) is
	 * not sufficient. Single threshold unbiased 128 (exp 0x407f); double
	 * 1024 (exp 0x43ff); extended uses format max 0x7fff. */
	return AND(INV(fpu_fmod_operr()),
		AND(INV(IS_FNAN(VARL("src_fp"))),
			AND(INV(IS_FNAN(VARL("dst_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					ITE(EQ(VARL("precision"), U32(1)),
						UGE(VARL("exact_exp"), U16(0x407f)),
						ITE(EQ(VARL("precision"), U32(2)),
							UGE(VARL("exact_exp"), U16(0x43ff)),
							UGE(VARL("exact_exp"), U16(0x7fff))))))));
}

static RzILOpBool *fpu_fmod_unfl(void) {
	/* UM 6.1.5 / 4-61 note 2: underflow if the unrounded dest or remainder
	 * exponent is too small to be a normalized number in the selected PREC.
	 * A single denormal converted back to 80-bit is renormalized, so
	 * res_exp==0 is not sufficient. */
	return AND(INV(fpu_fmod_operr()),
		AND(INV(IS_FNAN(VARL("src_fp"))),
			AND(INV(IS_FNAN(VARL("dst_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(IS_FZERO(VARL("dst_fp"))),
						AND(INV(IS_FZERO(BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("exact_bits")))),
							ITE(EQ(VARL("precision"), U32(1)),
								ULT(VARL("exact_exp"), U16(0x3f81)),
								ITE(EQ(VARL("precision"), U32(2)),
									ULT(VARL("exact_exp"), U16(0x3c01)),
									IS_ZERO(VARL("exact_exp"))))))))));
}

static RzILOpEffect *set_fpsr_fmod_exc(bool set_inex2) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(LOGOR(
					  ITE(fpu_fmod_operr(), U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
					  set_inex2
						  ? LOGOR(
							    ITE(fpu_fmod_ovfl(), U32((1u << M68K_FPSR_EXC_OVFL) | (1u << M68K_FPSR_AEXC_OVFL) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)),
							    ITE(fpu_fmod_inex2(), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)))
						  : U32(0)),
		LOGOR(
			ITE(fpu_fmod_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0)),
			set_inex2
				? ITE(AND(fpu_fmod_unfl(), fpu_fmod_inex2()), U32(1u << M68K_FPSR_AEXC_UNFL), U32(0))
				: U32(0)));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_snan(flags)));
}

/* FDIV: CC from the quotient (UM 4-39). DZ if the source is zero and the
 * destination is finite and nonzero (UM 6.1.6 / Table 6-3). OPERR for 0/0
 * or inf/inf. INEX2 if RN/RZ/RP/RM 80-bit encodings disagree (UM 6.1.7;
 * not FEQ), or the stored encoding is not the 80-bit quotient.
 * OVFL if the unrounded 80-bit quotient exponent meets the selected
 * PREC format maximum (UM 6.1.4 / 3.2.4); trap-disabled RZ stores the
 * largest finite number. UNFL if the unrounded 80-bit quotient exponent
 * is below the selected PREC minimum normalized exponent (UM 6.1.5).
 * Accrued UNFL needs UNFL and INEX2; accrued INEX follows INEX2 or OVFL
 * (UM 2.3.4). Quotient byte unchanged. */
static bool fpu_insn_is_fdiv(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_FDIV:
	case M68K_INS_FSDIV:
	case M68K_INS_FDDIV:
	case M68K_INS_FSGLDIV:
		return true;
	default:
		return false;
	}
}

static RzILOpBool *fpu_fdiv_operr(void) {
	return OR(AND(IS_FZERO(VARL("src_fp")), IS_FZERO(VARL("dst_fp"))),
		AND(IS_FINF(VARL("src_fp")), IS_FINF(VARL("dst_fp"))));
}

static RzILOpBool *fpu_fdiv_dz(void) {
	return AND(IS_FZERO(VARL("src_fp")),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("dst_fp"))), INV(IS_FZERO(VARL("dst_fp"))))));
}

static RzILOpBool *fpu_fdiv_ovfl(void) {
	/* UM 6.1.4: overflow if the unrounded intermediate exponent meets
	 * the selected PREC format maximum. Trap-disabled RZ stores the
	 * largest finite number, so IS_FINF(res) is not sufficient. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(IS_FZERO(VARL("src_fp"))),
						ITE(EQ(VARL("precision"), U32(1)),
							UGE(VARL("exact_exp"), U16(0x407f)),
							ITE(EQ(VARL("precision"), U32(2)),
								UGE(VARL("exact_exp"), U16(0x43ff)),
								UGE(VARL("exact_exp"), U16(0x7fff)))))))));
}

static RzILOpBool *fpu_fdiv_unfl(void) {
	/* UM 6.1.5: underflow if the unrounded intermediate exponent is too
	 * small to be a normalized number in the selected PREC. A single
	 * denormal converted back to 80-bit is renormalized, so res_exp==0
	 * is not sufficient. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(IS_FZERO(VARL("src_fp"))),
						AND(INV(IS_FZERO(VARL("dst_fp"))),
							ITE(EQ(VARL("precision"), U32(1)),
								ULT(VARL("exact_exp"), U16(0x3f81)),
								ITE(EQ(VARL("precision"), U32(2)),
									ULT(VARL("exact_exp"), U16(0x3c01)),
									IS_ZERO(VARL("exact_exp"))))))))));
}

static RzILOpBool *fpu_fdiv_inex2(void) {
	return AND(INV(fpu_fdiv_operr()),
		AND(INV(fpu_fdiv_dz()),
			AND(INV(IS_FNAN(VARL("src_fp"))),
				AND(INV(IS_FNAN(VARL("dst_fp"))),
					OR(INV(EQ(VARL("res_bits"), VARL("rne_bits"))),
						OR(INV(EQ(VARL("rne_bits"), VARL("rtz_bits"))),
							OR(INV(EQ(VARL("rne_bits"), VARL("rtp_bits"))),
								INV(EQ(VARL("rne_bits"), VARL("rtn_bits"))))))))));
}

static RzILOpEffect *set_fpsr_fdiv_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(LOGOR(
					  ITE(fpu_fdiv_operr(), U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
					  ITE(fpu_fdiv_dz(), U32((1u << M68K_FPSR_EXC_DZ) | (1u << M68K_FPSR_AEXC_DZ)), U32(0))),
		LOGOR(LOGOR(
			      ITE(fpu_fdiv_ovfl(), U32((1u << M68K_FPSR_EXC_OVFL) | (1u << M68K_FPSR_AEXC_OVFL) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)),
			      ITE(fpu_fdiv_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0))),
			LOGOR(
				ITE(AND(fpu_fdiv_unfl(), fpu_fdiv_inex2()), U32(1u << M68K_FPSR_AEXC_UNFL), U32(0)),
				ITE(fpu_fdiv_inex2(), U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)))));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_snan(flags)));
}

/* FMOVE to B/W/L: FPCC unchanged (PRM 5-76). OPERR if inf, a quiet NaN,
 * or the rounded integer does not fit (UM 6.1.3 / Table 6-2). A signaling
 * NaN takes only the SNAN path. INEX2 if the integer is not the source value. */
static RzILOpEffect *set_fpsr_fmove_int_exc(void) {
	RzILOpBool *operr = AND(INV(fpu_is_snan("src_fp")),
		OR(IS_FINF(VARL("src_fp")), OR(IS_FNAN(VARL("src_fp")), VARL("overflow"))));
	RzILOpBool *inex2 = AND(INV(IS_FINF(VARL("src_fp"))), AND(INV(IS_FNAN(VARL("src_fp"))), INV(fpu_fp80_is_integer())));
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(
		ITE(fpu_is_snan("src_fp"), U32((1u << M68K_FPSR_EXC_SNAN) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
		LOGOR(
			ITE(operr, U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
			ITE(inex2, U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0))));
	return SETG("fpsr", LOGOR(cleared, flags));
}

static RzILOpEffect *lift_fmovecr(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);

	const cs_m68k_op *src = &ctx->m68k->operands[0];
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (src->type != M68K_OP_IMM) {
		return fpu_read_failure_label(ctx, src);
	}
	if (!dst || !rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}

	ut16 sign_exp = 0;
	ut64 mantissa = 0;
	if (!fmovecr_const_parts(src->imm, &sign_exp, &mantissa)) {
		return m68k_label("m68k_fpu");
	}

	return SEQ8(
		SETL("round_mode", fpu_fpcr_round_mode()),
		SETL("precision", fpu_fpcr_precision()),
		SETL("src_bits", fpu_const80_bits(sign_exp, mantissa)),
		SETL("src_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("src_bits"))),
		SETL("res_fp", fpu_result_with_fpcr_precision(VARL("src_fp"))),
		m68k_write_reg_sized(ctx, dst->reg, 80, F2BV(VARL("res_fp"))),
		set_fpsr_cc_from_float_local("res_fp"),
		set_fpsr_fmovecr_exc());
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
	RzILOpPure *sign_exp = UNSIGNED(16, SHIFTR0(DUP(fp80), U8(64)));
	RzILOpPure *mantissa = UNSIGNED(64, fp80);
	return APPEND(sign_exp, APPEND(U16(0), mantissa));
}

static RzILOpPure *fpu_ext96_to_fp80(RzILOpPure *ext96) {
	RzILOpPure *sign_exp = UNSIGNED(16, SHIFTR0(DUP(ext96), U8(80)));
	RzILOpPure *mantissa = UNSIGNED(64, ext96);
	return APPEND(sign_exp, mantissa);
}

static RzILOpEffect *lift_fmovem_data(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);

	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	if (rz_m68k_fpu_op_detail_is_invalid(src) || rz_m68k_fpu_op_detail_is_invalid(dst)) {
		return NULL;
	}

	bool static_reg_to_mem = src->type == M68K_OP_REG_BITS && rz_m68k_op_is_mem_addr(dst);
	bool static_mem_to_reg = rz_m68k_op_is_mem_addr(src) && dst->type == M68K_OP_REG_BITS;
	bool dynamic_reg_to_mem = rz_m68k_op_is_data_reg(src) && rz_m68k_op_is_mem_addr(dst);
	bool dynamic_mem_to_reg = rz_m68k_op_is_mem_addr(src) && rz_m68k_op_is_data_reg(dst);
	bool reg_to_mem = static_reg_to_mem || dynamic_reg_to_mem;
	bool mem_to_reg = static_mem_to_reg || dynamic_mem_to_reg;
	if (!reg_to_mem && !mem_to_reg) {
		return NULL;
	}

	const cs_m68k_op *regs_op = reg_to_mem ? src : dst;
	const cs_m68k_op *mem = reg_to_mem ? dst : src;
	bool dynamic = dynamic_reg_to_mem || dynamic_mem_to_reg;
	ut32 reg_bits = 0;
	if (!dynamic) {
		reg_bits = regs_op->register_bits;
		if (reg_bits & ~M68K_FMOVEM_FP_REG_BITS_MASK) {
			return NULL;
		}

		ut32 count = fmovem_fp_reg_count(reg_bits);
		if (!count) {
			return NOP();
		}
	}
	if (mem->type == M68K_OP_MEM && mem->address_mode == M68K_AM_NONE) {
		return NULL;
	}

	bool predec = mem->address_mode == M68K_AM_REGI_ADDR_PRE_DEC;
	bool postinc = mem->address_mode == M68K_AM_REGI_ADDR_POST_INC;
	m68k_reg base_reg = rz_m68k_op_base_reg(mem);
	RzILOpEffect *seq = NULL;
	if (predec || postinc) {
		if (!rz_m68k_reg_is_areg(base_reg)) {
			return NULL;
		}
		seq = SETL("addr", m68k_reg_value(ctx, base_reg));
	} else {
		M68KEA ea = m68k_effective_addr(ctx, mem, M68K_FMOVEM_EXTENDED_BITS);
		if (!ea.addr) {
			m68k_ea_fini(&ea);
			return NULL;
		}
		seq = SETL("addr", UNSIGNED(32, ea.addr));
		seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
	}

	if (dynamic) {
		seq = SEQ2(seq, SETL("reg_mask", m68k_read_reg_sized(ctx, regs_op->reg, 32)));
		if (reg_to_mem && predec) {
			for (int i = (int)RZ_ARRAY_SIZE(fmovem_fp_regs) - 1; i >= 0; i--) {
				m68k_reg reg = fmovem_fp_regs[i];
				RzILOpPure *value = m68k_read_reg_sized(ctx, reg, 80);
				if (!value) {
					rz_il_op_effect_free(seq);
					return NULL;
				}
				RzILOpEffect *store = SEQ2(
					SETL("addr", SUB(VARL("addr"), U32(M68K_FMOVEM_EXTENDED_BYTES))),
					STOREW(VARL("addr"), UNSIGNED(M68K_FMOVEM_EXTENDED_BITS, fpu_fp80_to_ext96(value))));
				seq = SEQ2(seq, BRANCH(fmovem_dynamic_mask_has((ut32)i, true), store, EMPTY()));
			}
			return SEQ2(seq, m68k_write_reg_sized(ctx, base_reg, 32, VARL("addr")));
		}

		for (ut32 i = 0; i < RZ_ARRAY_SIZE(fmovem_fp_regs); i++) {
			m68k_reg reg = fmovem_fp_regs[i];
			RzILOpEffect *op = NULL;
			if (reg_to_mem) {
				RzILOpPure *value = m68k_read_reg_sized(ctx, reg, 80);
				if (!value) {
					rz_il_op_effect_free(seq);
					return NULL;
				}
				op = SEQ2(
					STOREW(VARL("addr"), UNSIGNED(M68K_FMOVEM_EXTENDED_BITS, fpu_fp80_to_ext96(value))),
					SETL("addr", ADD(VARL("addr"), U32(M68K_FMOVEM_EXTENDED_BYTES))));
			} else {
				op = SEQ3(
					SETL("mem_ext", LOADW(M68K_FMOVEM_EXTENDED_BITS, VARL("addr"))),
					m68k_write_reg_sized(ctx, reg, 80, fpu_ext96_to_fp80(VARL("mem_ext"))),
					SETL("addr", ADD(VARL("addr"), U32(M68K_FMOVEM_EXTENDED_BYTES))));
			}
			seq = SEQ2(seq, BRANCH(fmovem_dynamic_mask_has(i, false), op, EMPTY()));
		}
		if (postinc) {
			seq = SEQ2(seq, m68k_write_reg_sized(ctx, base_reg, 32, VARL("addr")));
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
			RzILOpPure *value = m68k_read_reg_sized(ctx, reg, 80);
			if (!value) {
				rz_il_op_effect_free(seq);
				return NULL;
			}
			seq = SEQ3(
				seq,
				SETL("addr", SUB(VARL("addr"), U32(M68K_FMOVEM_EXTENDED_BYTES))),
				STOREW(VARL("addr"), UNSIGNED(M68K_FMOVEM_EXTENDED_BITS, fpu_fp80_to_ext96(value))));
		}
		return SEQ2(seq, m68k_write_reg_sized(ctx, base_reg, 32, VARL("addr")));
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
			RzILOpPure *value = m68k_read_reg_sized(ctx, reg, 80);
			if (!value) {
				rz_il_op_pure_free(addr);
				rz_il_op_effect_free(seq);
				return NULL;
			}
			op = STOREW(addr, UNSIGNED(M68K_FMOVEM_EXTENDED_BITS, fpu_fp80_to_ext96(value)));
		} else {
			seq = SEQ2(seq, SETL("mem_ext", LOADW(M68K_FMOVEM_EXTENDED_BITS, addr)));
			op = m68k_write_reg_sized(ctx, reg, 80, fpu_ext96_to_fp80(VARL("mem_ext")));
		}
		if (!op) {
			rz_il_op_effect_free(seq);
			return NULL;
		}
		seq = SEQ2(seq, op);
		offset += M68K_FMOVEM_EXTENDED_BYTES;
	}
	if (postinc) {
		seq = SEQ2(seq, m68k_write_reg_sized(ctx, base_reg, 32, ADD(VARL("addr"), U32(offset))));
	}
	return seq;
}

#ifdef RZ_CAPSTONE_HAS_M68K_FP_FORMATS
static RzILOpEffect *fpu_packed_zero_raw_effect(void) {
	RzILOpPure *header = ITE(IS_FNEG(VARL("src_fp")), U32(0x80000000u), U32(0));
	return SETL("packed_raw", APPEND(header, U64(0)));
}

static RzILOpEffect *fpu_packed_special_raw_effect(void) {
	RzILOpPure *quiet_bits = fpu_quiet_fp80_nan_bits(VARL("src_bits"));
	RzILOpPure *header = LOGOR(
		ITE(MSB(VARL("src_bits")), U32(0x80000000u), U32(0)),
		U32(0x7fff0000u));
	RzILOpPure *fraction = ITE(
		IS_FNAN(VARL("src_fp")),
		UNSIGNED(64, quiet_bits),
		U64(0));
	return SETL("packed_raw", APPEND(header, fraction));
}

static RzILOpEffect *fpu_packed_encode_nonzero_effect(void) {
	RzILOpEffect *seq = SEQ2(
		SETL("packed_digit_count", U32(1)),
		SETL("packed_digit_threshold", U64(10)));
	seq = SEQ2(seq, REPEAT(UGE(VARL("packed_coefficient"), VARL("packed_digit_threshold")), SEQ2(SETL("packed_digit_count", ADD(VARL("packed_digit_count"), U32(1))), SETL("packed_digit_threshold", MUL(VARL("packed_digit_threshold"), U64(10))))));

	seq = SEQN(6,
		seq,
		SETL("packed_output_exp", ADD(SUB(VARL("packed_decimal_exp"), VARL("packed_digits_requested")), VARL("packed_digit_count"))),
		SETL("packed_output_exp_abs", ITE(SLT(VARL("packed_output_exp"), S32(0)), NEG(VARL("packed_output_exp")), VARL("packed_output_exp"))),
		SETL("packed_operr", OR(VARL("packed_operr"), UGT(VARL("packed_output_exp_abs"), U32(999)))),
		SETL("packed_padded_coefficient", VARL("packed_coefficient")),
		SETL("packed_pad_count", SUB(U32(17), VARL("packed_digit_count"))));
	seq = SEQ2(seq, REPEAT(NON_ZERO(VARL("packed_pad_count")), SEQ2(SETL("packed_padded_coefficient", MUL(VARL("packed_padded_coefficient"), U64(10))), SETL("packed_pad_count", SUB(VARL("packed_pad_count"), U32(1))))));

	seq = SEQ3(
		seq,
		SETL("packed_bcd_work", VARL("packed_padded_coefficient")),
		SETL("packed_bcd_fraction", U64(0)));
	for (ut32 i = 0; i < 16; i++) {
		RzILOpPure *digit = MOD(VARL("packed_bcd_work"), U64(10));
		RzILOpPure *placed = i ? SHIFTL0(digit, U8((ut8)(i * 4))) : digit;
		seq = SEQ3(
			seq,
			SETL("packed_bcd_fraction", LOGOR(VARL("packed_bcd_fraction"), placed)),
			SETL("packed_bcd_work", DIV(VARL("packed_bcd_work"), U64(10))));
	}

	RzILOpPure *exp0 = MOD(VARL("packed_output_exp_abs"), U32(10));
	RzILOpPure *exp1 = MOD(DIV(VARL("packed_output_exp_abs"), U32(10)), U32(10));
	RzILOpPure *exp2 = MOD(DIV(VARL("packed_output_exp_abs"), U32(100)), U32(10));
	RzILOpPure *exp3 = MOD(DIV(VARL("packed_output_exp_abs"), U32(1000)), U32(10));
	RzILOpPure *header = LOGOR(
		LOGOR(
			ITE(IS_FNEG(VARL("src_fp")), U32(0x80000000u), U32(0)),
			ITE(SLT(VARL("packed_output_exp"), S32(0)), U32(0x40000000u), U32(0))),
		LOGOR(
			LOGOR(SHIFTL0(exp2, U8(24)), SHIFTL0(exp1, U8(20))),
			LOGOR(
				LOGOR(SHIFTL0(exp0, U8(16)), SHIFTL0(exp3, U8(12))),
				UNSIGNED(32, VARL("packed_bcd_work")))));
	return SEQ2(seq, SETL("packed_raw", APPEND(header, VARL("packed_bcd_fraction"))));
}

/* Round src_fp * 10^packed_round_scale_exp from its exact FP80 integer
 * significand. The 12288-bit ratio covers the complete FP80 exponent range. */
static RzILOpEffect *fpu_packed_store_exact_round_effect(void) {
	RzILOpEffect *seq = SEQ4(
		SETL("packed_negative", IS_FNEG(VARL("src_fp"))),
		SETL("packed_src_exp", UNSIGNED(32, LOGAND(UNSIGNED(16, SHIFTR0(VARL("src_bits"), U8(64))), U16(0x7fff)))),
		SETL("packed_src_mantissa", UNSIGNED(64, VARL("src_bits"))),
		SETL("packed_src_binary_exp", SUB(ITE(IS_ZERO(VARL("packed_src_exp")), S32(1), VARL("packed_src_exp")), S32(0x403e))));
	seq = SEQ2(seq, fpu_packed_decimal_rational_effect(M68K_PACKED_STORE_INTEGER_BITS, "packed_round_scale_exp", VARL("packed_src_mantissa")));
	seq = SEQ3(
		seq,
		SETL("packed_binary_shift", ADD(VARL("packed_src_binary_exp"), VARL("packed_round_scale_exp"))),
		fpu_packed_apply_binary_shift_effect());
	seq = SEQ2(seq, fpu_packed_divide_rational_effect());
	seq = SEQ3(
		seq,
		SETL("packed_round_exact", IS_ZERO(VARL("packed_remainder"))),
		SETL("packed_round_up", fpu_packed_round_quotient_up()));
	return SEQ2(seq,
		SETL("packed_coefficient",
			ADD(VARL("packed_quotient"), ITE(VARL("packed_round_up"), U64(1), U64(0)))));
}

static RzILOpEffect *fpu_packed_finite_raw_effect(void) {
	RzILOpEffect *seq = fpu_packed_normalize_effect();
	seq = SEQN(5,
		seq,
		SETL("packed_digits_requested", ITE(SGT(VARL("packed_effective_k"), S32(0)), VARL("packed_effective_k"), ADD(SUB(VARL("packed_decimal_exp"), VARL("packed_effective_k")), U32(1)))),
		SETL("packed_digits_requested", ITE(SGT(VARL("packed_digits_requested"), S32(17)), S32(17), VARL("packed_digits_requested"))),
		SETL("packed_round_scale_exp", SUB(SUB(VARL("packed_digits_requested"), U32(1)), VARL("packed_decimal_exp"))),
		SETL("packed_power_exp_abs", ITE(SLT(VARL("packed_round_scale_exp"), S32(0)), NEG(VARL("packed_round_scale_exp")), VARL("packed_round_scale_exp"))));

	RzILOpBool *round_away = OR(
		AND(INV(IS_FNEG(VARL("src_fp"))), EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTP))),
		AND(IS_FNEG(VARL("src_fp")), EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTN))));
	RzILOpEffect *negative_precision = SEQ2(
		SETL("packed_coefficient", ITE(round_away, U64(1), U64(0))),
		SETL("packed_round_exact", IL_FALSE));
	seq = SEQ2(seq, BRANCH(SGE(VARL("packed_digits_requested"), S32(0)), fpu_packed_store_exact_round_effect(), negative_precision));

	/* 17 requested digits can round 9.99… to the 18-digit integer 10^17.
	 * Renormalize it before BCD packing; lower precisions still fit in the
	 * 17 available nibbles without this step. */
	seq = SEQ2(seq, BRANCH(AND(EQ(VARL("packed_digits_requested"), S32(17)), EQ(VARL("packed_coefficient"), U64(100000000000000000ULL))), SEQ2(SETL("packed_coefficient", DIV(VARL("packed_coefficient"), U64(10))), SETL("packed_decimal_exp", ADD(VARL("packed_decimal_exp"), U32(1)))), EMPTY()));
	return SEQ2(seq, BRANCH(IS_ZERO(VARL("packed_coefficient")), fpu_packed_zero_raw_effect(), fpu_packed_encode_nonzero_effect()));
}

/* Packed input is rounded directly to extended precision. Decimal conversion
 * inexactness uses INEX1; all unrelated current exception bits are cleared. */
static RzILOpEffect *set_fpsr_fmove_packed_load_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = ITE(
		VARL("packed_input_snan"),
		U32((1u << M68K_FPSR_EXC_SNAN) | (1u << M68K_FPSR_AEXC_IOP)),
		ITE(VARL("packed_input_inexact"),
			U32((1u << M68K_FPSR_EXC_INEX1) | (1u << M68K_FPSR_AEXC_INEX)),
			U32(0)));
	return SETG("fpsr", LOGOR(cleared, flags));
}

/* Packed output uses INEX2. A k-factor above 17 or a rounded decimal exponent
 * wider than three digits sets OPERR, while the four-digit result is stored. */
static RzILOpEffect *set_fpsr_fmove_packed_store_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(
		ITE(VARL("packed_operr"),
			U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)), U32(0)),
		ITE(VARL("packed_output_inexact"),
			U32((1u << M68K_FPSR_EXC_INEX2) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)));
	flags = ITE(fpu_is_snan("src_fp"),
		U32((1u << M68K_FPSR_EXC_SNAN) | (1u << M68K_FPSR_AEXC_IOP)), flags);
	return SETG("fpsr", LOGOR(cleared, flags));
}

static RzILOpEffect *lift_fpu_move_packed_load(M68KILCtx *ctx, const cs_m68k_op *src, const cs_m68k_op *dst) {
	rz_return_val_if_fail(ctx && src && dst, NULL);
	if (!rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}

	RzILOpEffect *pre = NULL;
	RzILOpEffect *post = NULL;
	RzILOpPure *raw = NULL;
	if (src->type == M68K_OP_FP_PACKED) {
		raw = APPEND(U32(src->fp_packed.header), U64(src->fp_packed.fraction));
	} else if (rz_m68k_op_is_mem_addr(src)) {
		raw = m68k_read_operand(ctx, src, M68K_FMOVEM_EXTENDED_BITS, &pre, &post);
	}
	if (!raw) {
		rz_il_op_effect_free(pre);
		rz_il_op_effect_free(post);
		return fpu_read_failure_label(ctx, src);
	}

	RzILOpEffect *seq = SETL("round_mode", fpu_fpcr_round_mode());
	if (pre) {
		seq = SEQ2(seq, pre);
	}
	seq = SEQ2(seq, fpu_packed_decode_effect(raw, "src_fp"));
	if (post) {
		seq = SEQ2(seq, post);
	}
	/* Decimal input conversion always rounds to extended precision. The FPCR
	 * precision field is ignored for this step, but its rounding mode applies. */
	seq = SEQN(3,
		seq,
		SETL("packed_res_bits",
			ITE(VARL("packed_special"),
				ITE(VARL("packed_input_snan"),
					fpu_quiet_fp80_nan_bits(VARL("packed_special_bits")),
					VARL("packed_special_bits")),
				F2BV(VARL("src_fp")))),
		SETL("res_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("packed_res_bits"))));
	RzILOpEffect *write = m68k_write_reg_sized(ctx, dst->reg, 80, VARL("packed_res_bits"));
	if (!write) {
		rz_il_op_effect_free(seq);
		return fpu_write_failure_label(ctx, dst);
	}
	return SEQ4(
		seq,
		write,
		set_fpsr_cc_from_float_local("res_fp"),
		set_fpsr_fmove_packed_load_exc());
}

static RzILOpEffect *lift_fpu_move_packed_store(M68KILCtx *ctx, const cs_m68k_op *src, const cs_m68k_op *dst) {
	rz_return_val_if_fail(ctx && src && dst, NULL);
	if (!rz_m68k_op_is_fpu_reg(src) || ctx->m68k->op_count != 3 || rz_m68k_fpu_op_is_illegal_write(ctx->m68k, dst)) {
		return fpu_write_failure_label(ctx, dst);
	}
	const cs_m68k_op *k_op = &ctx->m68k->operands[2];
	RzILOpPure *k = NULL;
	if (k_op->type == M68K_OP_IMM) {
		k = S32((st32)(st64)k_op->imm);
	} else if (rz_m68k_op_is_data_reg(k_op)) {
		RzILOpPure *raw_k = m68k_read_reg_sized(ctx, k_op->reg, 32);
		if (raw_k) {
			k = SIGNED(32, UNSIGNED(7, raw_k));
		}
	}
	RzILOpPure *src_bits = m68k_read_reg_sized(ctx, src->reg, 80);
	if (!k || !src_bits) {
		rz_il_op_pure_free(k);
		rz_il_op_pure_free(src_bits);
		return fpu_read_failure_label(ctx, k ? src : k_op);
	}

	RzILOpEffect *seq = SEQN(8,
		SETL("round_mode", fpu_fpcr_round_mode()),
		SETL("src_bits", src_bits),
		SETL("src_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("src_bits"))),
		SETL("packed_k", k),
		SETL("packed_operr", SGT(VARL("packed_k"), S32(17))),
		SETL("packed_effective_k", ITE(SGT(VARL("packed_k"), S32(17)), S32(17), VARL("packed_k"))),
		SETL("packed_output_finite", AND(INV(IS_FNAN(VARL("src_fp"))), INV(IS_FINF(VARL("src_fp"))))),
		SETL("packed_round_exact", IL_TRUE));
	seq = SEQ2(seq, BRANCH(OR(IS_FNAN(VARL("src_fp")), IS_FINF(VARL("src_fp"))), fpu_packed_special_raw_effect(), BRANCH(IS_FZERO(VARL("src_fp")), fpu_packed_zero_raw_effect(), fpu_packed_finite_raw_effect())));

	seq = SEQ2(seq, SETL("packed_output_inexact", AND(VARL("packed_output_finite"), INV(VARL("packed_round_exact")))));
	RzILOpEffect *write = m68k_write_operand(ctx, dst, M68K_FMOVEM_EXTENDED_BITS, VARL("packed_raw"));
	if (!write) {
		rz_il_op_effect_free(seq);
		return fpu_write_failure_label(ctx, dst);
	}
	return SEQ3(seq, write, set_fpsr_fmove_packed_store_exc());
}

static RzILOpEffect *lift_fpu_move_packed(M68KILCtx *ctx) {
	rz_return_val_if_fail(ctx && ctx->m68k->op_count >= 2, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	const cs_m68k_op *dst = &ctx->m68k->operands[1];
	return ctx->m68k->op_count == 3
		? lift_fpu_move_packed_store(ctx, src, dst)
		: lift_fpu_move_packed_load(ctx, src, dst);
}
#endif

static RzILOpEffect *lift_fpu_move_data(M68KILCtx *ctx, ut32 insn_id) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 2, NULL);
#ifdef RZ_CAPSTONE_HAS_M68K_FP_FORMATS
	if (insn_id == M68K_INS_FMOVE && rz_m68k_fpu_size_is_packed(ctx->m68k)) {
		return lift_fpu_move_packed(ctx);
	}
#endif
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
#ifdef RZ_CAPSTONE_HAS_M68K_FP_FORMATS
	src_data_fpu = src_data_fpu || src->type == M68K_OP_FP_EXTENDED || src->type == M68K_OP_FP_PACKED;
#endif
	bool dst_data_fpu = rz_m68k_op_is_fpu_reg(dst);
	if (!src_data_fpu && !dst_data_fpu && ctx->m68k->op_size.type != M68K_SIZE_TYPE_FPU) {
		return NULL;
	}

	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", "src_bits", src, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, src);
	}
	seq = SEQ2(seq, SETL("round_mode", fpu_fpcr_round_mode()));
	RzILOpFloat *result = NULL;
	if (insn_id == M68K_INS_FMOVE && dst_data_fpu) {
		seq = SEQ2(seq, SETL("precision", fpu_fpcr_precision()));
		result = fpu_result_with_fpcr_precision(VARL("src_fp"));
	} else if (dst_data_fpu) {
		RzFloatFormat result_format = fpu_insn_result_format(ctx, insn_id);
		result = insn_id == M68K_INS_FMOVE
			? fpu_result_to_fp80(VARL("src_fp"), result_format)
			: fpu_result_to_fp80_with_fpcr_rmode(VARL("src_fp"), result_format);
	} else {
		result = fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80);
	}
	seq = SEQ3(
		seq,
		SETL("res_fp", result),
		SETL("res_fp", ITE(fpu_is_snan("src_fp"), fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80), VARL("res_fp"))));
	if (!dst_data_fpu && ctx->m68k->op_size.type == M68K_SIZE_TYPE_CPU && (bits == 8 || bits == 16 || bits == 32)) {
		seq = SEQ5(
			seq,
			SETL("src_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("src_bits"), U8(64)), UN(80, 0x7fff)))),
			SETL("src_man", UNSIGNED(64, VARL("src_bits"))),
			SETL("int_wide", F2SINT_DYN_RMODE(64, VARL("round_mode"), VARL("src_fp"))),
			SETL("overflow", m68k_signed_out_of_range(VARL("int_wide"), bits)));
		RzILOpPure *nan_bits = CAST(bits, IL_FALSE,
			SHIFTR0(LOGOR(VARL("src_man"), U64(0x4000000000000000ULL)), U8((ut8)(64 - bits))));
		RzILOpPure *limit = ITE(IS_FNEG(VARL("src_fp")), UN(bits, 1ULL << (bits - 1)), UN(bits, (1ULL << (bits - 1)) - 1));
		RzILOpPure *int_res = ITE(IS_FNAN(VARL("src_fp")), nan_bits,
			ITE(OR(IS_FINF(VARL("src_fp")), VARL("overflow")),
				limit,
				CAST(bits, MSB(VARL("int_wide")), VARL("int_wide"))));
		seq = SEQ2(seq, SETL("int_res", int_res));
		RzILOpEffect *write = m68k_write_operand(ctx, dst, bits, VARL("int_res"));
		if (!write) {
			rz_il_op_effect_free(seq);
			return fpu_write_failure_label(ctx, dst);
		}
		return SEQ3(seq, write, set_fpsr_fmove_int_exc());
	}
	if (!dst_data_fpu && ctx->m68k->op_size.type == M68K_SIZE_TYPE_FPU && (bits == 32 || bits == 64)) {
		ut8 exp_shift = bits == 32 ? 23 : 52;
		ut64 exp_mask = bits == 32 ? 0xffull : 0x7ffull;
		ut16 ovfl_exp = bits == 32 ? 0x407f : 0x43ff;
		ut16 unfl_exp = bits == 32 ? 0x3f81 : 0x3c01;
		RzFloatFormat format = fpu_format_for_bits(bits);
		seq = SEQ9(
			seq,
			SETL("src_bits", F2BV(VARL("src_fp"))),
			SETL("src_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("src_bits"), U8(64)), UN(80, 0x7fff)))),
			SETL("ovfl_exp", U16(ovfl_exp)),
			SETL("unfl_exp", U16(unfl_exp)),
			SETL("dest_fp", FCONVERT_DYN_RMODE(format, VARL("round_mode"), VARL("src_fp"))),
			SETL("dest_bits", F2BV(VARL("dest_fp"))),
			SETL("dest_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("dest_bits"), U8(exp_shift)), UN(bits, exp_mask)))),
			SETL("back_fp", fpu_to_format(VARL("dest_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		RzILOpEffect *write = m68k_write_operand(ctx, dst, bits, VARL("dest_bits"));
		if (!write) {
			rz_il_op_effect_free(seq);
			return fpu_write_failure_label(ctx, dst);
		}
		return SEQ3(seq, write, set_fpsr_fmove_real_exc());
	}
	if (!dst_data_fpu && ctx->m68k->op_size.type == M68K_SIZE_TYPE_FPU &&
		rz_m68k_fpu_size_is_extended(ctx->m68k)) {
		/* UM 4-66: FMOVE.X to memory. FPCC unchanged. OVFL/UNFL/INEX2
		 * follow 6.1.4 / 6.1.5 / 6.1.7. Rebuild the exception byte. */
		seq = SEQN(10,
			seq,
			SETL("src_bits", F2BV(VARL("src_fp"))),
			SETL("src_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("src_bits"), U8(64)), UN(80, 0x7fff)))),
			SETL("ovfl_exp", U16(0x7fff)),
			SETL("unfl_exp", U16(1)),
			SETL("dest_fp", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)),
			SETL("dest_bits", F2BV(VARL("dest_fp"))),
			SETL("dest_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("dest_bits"), U8(64)), UN(80, 0x7fff)))),
			SETL("back_fp", VARL("dest_fp")),
			SETL("fp80_bits", VARL("dest_bits")));
		RzILOpEffect *write = m68k_write_operand(ctx, dst, M68K_FMOVEM_EXTENDED_BITS,
			fpu_fp80_to_ext96(VARL("fp80_bits")));
		if (!write) {
			rz_il_op_effect_free(seq);
			return fpu_write_failure_label(ctx, dst);
		}
		return SEQ3(seq, write, set_fpsr_fmove_real_exc());
	}
	seq = fpu_write_float_local(ctx, dst, bits, "res_fp", seq);
	if (!seq) {
		return fpu_write_failure_label(ctx, dst);
	}
	if (dst_data_fpu) {
		seq = SEQ6(
			seq,
			set_fpsr_cc_from_float_local("res_fp"),
			SETL("src80_bits", F2BV(fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80))),
			SETL("src_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("src80_bits"), U8(64)), UN(80, 0x7fff)))),
			SETL("res_bits", F2BV(VARL("res_fp"))),
			set_fpsr_fmove_fpn_exc());
	}
	return seq;
}

/* FABS/FNEG: CC from the result (UM 4-19 / 4-82). NANs follow 4.5.4: return
 * the NAN (quieted if SNAN) without applying abs/neg. SNAN sets SNAN+IOP.
 * UNFL if the source is an extended denormal (UM 6.1.5); a single/double
 * denormal is normalized when converted to extended, so it does not UNFL.
 * OPERR/OVFL/DZ/INEX2 cleared. Accrued UNFL needs UNFL and INEX2, so a
 * denormal abs/neg does not set AUNFL. Quotient unchanged. */
static bool fpu_insn_is_fabs_or_fneg(ut32 insn_id) {
	switch (insn_id) {
	case M68K_INS_FABS:
	case M68K_INS_FSABS:
	case M68K_INS_FDABS:
	case M68K_INS_FNEG:
	case M68K_INS_FSNEG:
	case M68K_INS_FDNEG:
		return true;
	default:
		return false;
	}
}

static RzILOpBool *fpu_fabs_unfl(void) {
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FINF(VARL("src_fp"))),
			AND(INV(IS_FZERO(VARL("src_fp"))),
				IS_ZERO(VARL("src_exp")))));
}

static RzILOpEffect *set_fpsr_fabs_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = ITE(fpu_fabs_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_src_snan(flags)));
}

static RzILOpEffect *lift_fpu_unary_data(M68KILCtx *ctx, ut32 insn_id) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_unary_dst_op(ctx->insn, src, &hidden_dst);
	if (!dst || !rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}

	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", "src_bits", src, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, src);
	}
	seq = SEQ2(seq, SETL("round_mode", fpu_fpcr_round_mode()));
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
		/* Promote narrow memory/imm sources to FP80 before sqrt so FPCR /
		 * FS/FD destination precision is applied to a full-width root. */
		result = FSQRT_DYN_RMODE(VARL("round_mode"),
			fpu_to_format_with_fpcr_rmode(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80));
		break;
	case M68K_INS_FINT:
		result = FROUND_DYN_RMODE(VARL("round_mode"), VARL("src_fp"));
		break;
	case M68K_INS_FINTRZ:
		result = FROUND(RZ_FLOAT_RMODE_RTZ, VARL("src_fp"));
		break;
	default:
		rz_il_op_effect_free(seq);
		return m68k_label("m68k_unimplemented");
	}

	switch (insn_id) {
	case M68K_INS_FABS:
	case M68K_INS_FNEG:
	case M68K_INS_FSQRT:
		seq = SEQ2(seq, SETL("precision", fpu_fpcr_precision()));
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
	seq = SEQ2(seq, SETL("res_fp", result));
	if (insn_id == M68K_INS_FSQRT || insn_id == M68K_INS_FSSQRT || insn_id == M68K_INS_FDSQRT) {
		seq = SEQ2(seq, SETL("res_fp", ITE(IS_FNAN(VARL("src_fp")), BV2F(RZ_FLOAT_IEEE754_BIN_80, fpu_quiet_fp80_nan_bits(VARL("src_bits"))), ITE(IS_FZERO(VARL("src_fp")), BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("src_bits")), ITE(fpu_fsqrt_operr(), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80), VARL("res_fp"))))));
	}
	if (fpu_insn_is_fabs_or_fneg(insn_id)) {
		/* 4.5.4: any NAN is returned as the NAN (quieted if SNAN). Do not apply abs/neg. */
		seq = SEQ2(seq, SETL("res_fp", ITE(IS_FNAN(VARL("src_fp")), BV2F(RZ_FLOAT_IEEE754_BIN_80, fpu_quiet_fp80_nan_bits(VARL("src_bits"))), VARL("res_fp"))));
	} else {
		seq = SEQ2(seq, SETL("res_fp", ITE(fpu_is_snan("src_fp"), BV2F(RZ_FLOAT_IEEE754_BIN_80, fpu_quiet_fp80_nan_bits(VARL("src_bits"))), VARL("res_fp"))));
	}
	seq = SEQ3(
		seq,
		m68k_write_reg_sized(ctx, dst->reg, 80, F2BV(VARL("res_fp"))),
		set_fpsr_cc_from_float_local("res_fp"));
	if (insn_id == M68K_INS_FINT || insn_id == M68K_INS_FINTRZ) {
		seq = SEQ5(
			seq,
			SETL("src_bits", F2BV(fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80))),
			SETL("src_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("src_bits"), U8(64)), UN(80, 0x7fff)))),
			SETL("src_man", UNSIGNED(64, VARL("src_bits"))),
			set_fpsr_fint_exc());
	}
	if (insn_id == M68K_INS_FSQRT || insn_id == M68K_INS_FSSQRT || insn_id == M68K_INS_FDSQRT) {
		seq = SEQ6(
			seq,
			SETL("sqrt_rne_bits", F2BV(FSQRT(RZ_FLOAT_RMODE_RNE, fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)))),
			SETL("sqrt_rtz_bits", F2BV(FSQRT(RZ_FLOAT_RMODE_RTZ, fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)))),
			SETL("sqrt_rtp_bits", F2BV(FSQRT(RZ_FLOAT_RMODE_RTP, fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)))),
			SETL("res_bits", F2BV(VARL("res_fp"))),
			set_fpsr_fsqrt_exc());
	}
	if (fpu_insn_is_fabs_or_fneg(insn_id)) {
		seq = SEQ4(
			seq,
			SETL("src_bits", F2BV(fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80))),
			SETL("src_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("src_bits"), U8(64)), UN(80, 0x7fff)))),
			set_fpsr_fabs_exc());
	}
	return seq;
}

static RzILOpEffect *lift_fpu_extract_data(M68KILCtx *ctx, ut32 insn_id) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (!dst || !rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}

	const cs_m68k_op *src = &ctx->m68k->operands[0];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", "src_bits", src, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, src);
	}

	seq = SEQ7(
		seq,
		SETL("src_sign", LOGAND(UNSIGNED(16, SHIFTR0(VARL("src_bits"), U8(64))), U16(0x8000))),
		SETL("src_zero_bits", APPEND(VARL("src_sign"), U64(0))),
		SETL("src_exp_field", UNSIGNED(32, LOGAND(UNSIGNED(16, SHIFTR0(VARL("src_bits"), U8(64))), U16(0x7fff)))),
		SETL("src_norm_mant", UNSIGNED(64, VARL("src_bits"))),
		SETL("src_shift", U32(0)),
		REPEAT(AND(IS_ZERO(VARL("src_exp_field")), AND(NON_ZERO(VARL("src_norm_mant")), INV(MSB(VARL("src_norm_mant"))))), SEQ2(SETL("src_norm_mant", SHIFTL0(VARL("src_norm_mant"), U8(1))), SETL("src_shift", ADD(VARL("src_shift"), U32(1))))));
	if (insn_id == M68K_INS_FGETEXP) {
		RzILOpPure *exp = ITE(IS_ZERO(VARL("src_exp_field")),
			SUB(S32(1 - 0x3fff), VARL("src_shift")),
			SUB(VARL("src_exp_field"), U32(0x3fff)));
		seq = SEQ2(seq, SETL("src_exp", exp));
		RzILOpFloat *finite_res = SINT2F(RZ_FLOAT_IEEE754_BIN_80, RZ_FLOAT_RMODE_RNE, VARL("src_exp"));
		RzILOpFloat *res = ITE(IS_FNAN(VARL("src_fp")),
			fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80),
			ITE(IS_FINF(VARL("src_fp")),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80),
				ITE(IS_FZERO(VARL("src_fp")),
					BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("src_zero_bits")),
					finite_res)));
		seq = SEQ2(seq, SETL("res_fp", res));
	} else if (insn_id == M68K_INS_FGETMAN) {
		RzILOpPure *sign_exp = LOGOR(
			VARL("src_sign"),
			U16(0x3fff));
		seq = SEQ2(seq, SETL("finite_res_bits", APPEND(sign_exp, VARL("src_norm_mant"))));
		RzILOpFloat *finite_res = BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("finite_res_bits"));
		RzILOpFloat *res = ITE(IS_FNAN(VARL("src_fp")),
			fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80),
			ITE(IS_FINF(VARL("src_fp")),
				IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80),
				ITE(IS_FZERO(VARL("src_fp")),
					BV2F(RZ_FLOAT_IEEE754_BIN_80, VARL("src_zero_bits")),
					finite_res)));
		seq = SEQ2(seq, SETL("res_fp", res));
	} else {
		rz_il_op_effect_free(seq);
		return m68k_label("m68k_unimplemented");
	}

	return SEQ4(
		seq,
		m68k_write_reg_sized(ctx, dst->reg, 80, F2BV(VARL("res_fp"))),
		set_fpsr_cc_from_float_local("res_fp"),
		set_fpsr_fget_exc());
}

/* MC68881/68882 FSCALE: convert the source to an integer with round-toward-zero
 * and add it to the destination exponent. A NaN source replaces the destination.
 * A NaN destination is unchanged. Source ±infinity with a non-NaN destination
 * yields a quiet NaN and sets OPERR (UM 4-93 / Table 6-2), not overflow/underflow.
 * SNAN follows 4.5.4 (detect on the original encoding width). Zero source returns
 * dest after normal end rounding (4-93 note 1). OVFL if the unrounded intermediate
 * exponent meets the selected PREC format maximum (UM 6.1.4 / 3.2.4); trap-disabled
 * RZ stores the largest finite number. UNFL if the unrounded intermediate
 * exponent is below the selected PREC minimum normalized exponent (UM 6.1.5),
 * even when the value still fits in 80-bit after a denormal round-trip.
 * Single threshold unbiased -126 (exp 0x3f81); double -1022 (exp 0x3c01);
 * extended uses a zero exponent. INEX2 is cleared so AUNFL is not set
 * (UM 4-94 / 2.3.4). Accrued INEX follows OVFL. Quotient unchanged. */
static RzILOpBool *fpu_fscale_ovfl(void) {
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(IS_FZERO(VARL("dst_fp"))),
						ITE(EQ(VARL("precision"), U32(1)),
							UGE(VARL("exact_exp"), U16(0x407f)),
							ITE(EQ(VARL("precision"), U32(2)),
								UGE(VARL("exact_exp"), U16(0x43ff)),
								UGE(VARL("exact_exp"), U16(0x7fff)))))))));
}

static RzILOpBool *fpu_fscale_unfl(void) {
	/* UM 6.1.5: underflow if the unrounded intermediate exponent is too
	 * small to be a normalized number in the selected PREC. A single
	 * denormal converted back to 80-bit is renormalized, so res_exp==0
	 * is not sufficient. */
	return AND(INV(IS_FNAN(VARL("src_fp"))),
		AND(INV(IS_FNAN(VARL("dst_fp"))),
			AND(INV(IS_FINF(VARL("src_fp"))),
				AND(INV(IS_FINF(VARL("dst_fp"))),
					AND(INV(IS_FZERO(VARL("dst_fp"))),
						ITE(EQ(VARL("precision"), U32(1)),
							ULT(VARL("exact_exp"), U16(0x3f81)),
							ITE(EQ(VARL("precision"), U32(2)),
								ULT(VARL("exact_exp"), U16(0x3c01)),
								IS_ZERO(VARL("exact_exp")))))))));
}

static RzILOpEffect *set_fpsr_fscale_exc(void) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = LOGOR(
		ITE(AND(IS_FINF(VARL("src_fp")), INV(IS_FNAN(VARL("dst_fp")))),
			U32((1u << M68K_FPSR_EXC_OPERR) | (1u << M68K_FPSR_AEXC_IOP)),
			U32(0)),
		LOGOR(
			ITE(fpu_fscale_ovfl(), U32((1u << M68K_FPSR_EXC_OVFL) | (1u << M68K_FPSR_AEXC_OVFL) | (1u << M68K_FPSR_AEXC_INEX)), U32(0)),
			ITE(fpu_fscale_unfl(), U32(1u << M68K_FPSR_EXC_UNFL), U32(0))));
	return SETG("fpsr", LOGOR(cleared, fpu_exc_with_snan(flags)));
}

static RzILOpEffect *fscale_commit(M68KILCtx *ctx, m68k_reg dst_reg) {
	return SEQ4(
		m68k_write_reg_sized(ctx, dst_reg, 80, F2BV(VARL("res_fp"))),
		set_fpsr_cc_from_float_local("res_fp"),
		SETL("res_exp", UNSIGNED(16, LOGAND(SHIFTR0(F2BV(VARL("res_fp")), U8(64)), UN(80, 0x7fff)))),
		set_fpsr_fscale_exc());
}

static RzILOpEffect *fscale_round_and_commit(M68KILCtx *ctx, m68k_reg dst_reg) {
	return SEQ3(
		SETL("exact_exp", UNSIGNED(16, LOGAND(SHIFTR0(F2BV(VARL("res_fp")), U8(64)), UN(80, 0x7fff)))),
		SETL("res_fp", fpu_result_with_fpcr_precision(VARL("res_fp"))),
		fscale_commit(ctx, dst_reg));
}

static RzILOpBool *fscale_overflow_rounds_to_inf(void) {
	RzILOpBool *negative = NON_ZERO(VARL("dst_sign"));
	return OR(EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RNE)),
		OR(AND(INV(DUP(negative)), EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTP))),
			AND(negative, EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTN)))));
}

static RzILOpFloat *fscale_overflow_result(void) {
	RzILOpFloat *max_fp = BV2F(RZ_FLOAT_IEEE754_BIN_80,
		APPEND(LOGOR(VARL("dst_sign"), U16(0x7ffe)), U64(0xffffffffffffffffULL)));
	RzILOpFloat *narrow = fpu_result_with_fpcr_precision(DUP(max_fp));
	RzILOpFloat *extended = ITE(fscale_overflow_rounds_to_inf(), VARL("inf_fp"), max_fp);
	return ITE(OR(EQ(VARL("precision"), U32(1)), EQ(VARL("precision"), U32(2))),
		narrow, extended);
}

static RzILOpEffect *fscale_bind_denormal(void) {
	RzILOpBool *short_shift = ULT(VARL("denorm_shift"), U64(64));
	RzILOpPure *shift8 = UNSIGNED(8, VARL("denorm_shift"));
	RzILOpPure *truncated = ITE(DUP(short_shift),
		SHIFTR0(VARL("dst_mant"), DUP(shift8)), U64(0));
	RzILOpPure *remainder = ITE(short_shift,
		SUB(VARL("dst_mant"), SHIFTL0(VARL("denorm_truncated"), shift8)),
		VARL("dst_mant"));
	RzILOpPure *half = ITE(ULT(VARL("denorm_shift"), U64(64)),
		SHIFTL0(U64(1), UNSIGNED(8, SUB(VARL("denorm_shift"), U64(1)))),
		U64(0x8000000000000000ULL));
	RzILOpBool *rne_increment = AND(ULE(VARL("denorm_shift"), U64(64)),
		OR(UGT(VARL("denorm_remainder"), VARL("denorm_half")),
			AND(EQ(VARL("denorm_remainder"), VARL("denorm_half")), LSB(VARL("denorm_truncated")))));
	RzILOpBool *discarded = NON_ZERO(VARL("denorm_remainder"));
	RzILOpBool *directed_increment = AND(DUP(discarded),
		OR(AND(IS_ZERO(VARL("dst_sign")), EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTP))),
			AND(NON_ZERO(VARL("dst_sign")), EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTN)))));
	RzILOpBool *increment = ITE(EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RNE)),
		rne_increment,
		ITE(EQ(VARL("round_mode"), U32(RZ_FLOAT_RMODE_RTZ)), IL_FALSE, directed_increment));
	return SEQN(7,
		SETL("denorm_shift", UNSIGNED(64, SUB(S64(1), VARL("new_exp64")))),
		SETL("denorm_truncated", truncated),
		SETL("denorm_remainder", remainder),
		SETL("denorm_half", half),
		SETL("denorm_increment", BOOL_TO_BV(increment, 64)),
		SETL("denorm_mant", ADD(VARL("denorm_truncated"), VARL("denorm_increment"))),
		SETL("denorm_exp", ITE(MSB(VARL("denorm_mant")), U16(1), U16(0))));
}

static RzILOpEffect *lift_fpu_scale_data(M68KILCtx *ctx) {
	if (ctx->m68k->op_count < 1) {
		return NULL;
	}
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (!dst || !rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", "src_bits", src, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, src);
	}
	if (!fpu_operand_to_float_local(ctx, "dst_fp", "dst_bits", dst, 80, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, dst);
	}

	seq = SEQ6(
		seq,
		SETL("round_mode", fpu_fpcr_round_mode()),
		SETL("precision", fpu_fpcr_precision()),
		SETL("dst_sign", LOGAND(UNSIGNED(16, SHIFTR0(VARL("dst_bits"), U8(64))), U16(0x8000))),
		SETL("inf_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, APPEND(LOGOR(VARL("dst_sign"), U16(0x7fff)), U64(0x8000000000000000ULL)))),
		SETL("zero_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, APPEND(VARL("dst_sign"), U64(0)))));

	RzILOpEffect *scaled_commit = fscale_commit(ctx, dst->reg);
	if (!scaled_commit) {
		rz_il_op_effect_free(seq);
		return NULL;
	}

	RzILOpEffect *denormal = SEQ2(
		fscale_bind_denormal(),
		SETL("res_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, APPEND(LOGOR(VARL("dst_sign"), VARL("denorm_exp")), VARL("denorm_mant")))));
	RzILOpEffect *select_scaled = BRANCH(
		IS_ZERO(VARL("src_int")),
		SETL("res_fp", VARL("dst_fp")),
		BRANCH(SGE(VARL("new_exp64"), S64(0x7fff)),
			SETL("res_fp", fscale_overflow_result()),
			BRANCH(SLE(VARL("new_exp64"), S64(0)),
				denormal,
				SETL("res_fp", VARL("finite_fp")))));
	RzILOpEffect *scale = SEQN(12,
		SETL("dst_exp_field", UNSIGNED(32, LOGAND(UNSIGNED(16, SHIFTR0(VARL("dst_bits"), U8(64))), U16(0x7fff)))),
		SETL("dst_mant", UNSIGNED(64, VARL("dst_bits"))),
		SETL("dst_shift", U32(0)),
		REPEAT(AND(IS_ZERO(VARL("dst_exp_field")), AND(NON_ZERO(VARL("dst_mant")), INV(MSB(VARL("dst_mant"))))), SEQ2(SETL("dst_mant", SHIFTL0(VARL("dst_mant"), U8(1))), SETL("dst_shift", ADD(VARL("dst_shift"), U32(1))))),
		SETL("dst_exp", ITE(IS_ZERO(VARL("dst_exp_field")), SUB(S32(1), VARL("dst_shift")), VARL("dst_exp_field"))),
		SETL("src_int", F2SINT(32, RZ_FLOAT_RMODE_RTZ, VARL("src_fp"))),
		SETL("new_exp64", ADD(SIGNED(64, VARL("dst_exp")), SIGNED(64, VARL("src_int")))),
		SETL("exact_exp", ITE(SGE(VARL("new_exp64"), S64(0x7fff)), U16(0x7fff), ITE(SLE(VARL("new_exp64"), S64(0)), U16(0), UNSIGNED(16, VARL("new_exp64"))))),
		SETL("finite_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, APPEND(LOGOR(VARL("dst_sign"), UNSIGNED(16, VARL("new_exp64"))), VARL("dst_mant")))),
		select_scaled,
		SETL("res_fp", fpu_result_with_fpcr_precision(VARL("res_fp"))),
		scaled_commit);

	RzILOpEffect *nan = SEQ3(
		SETL("res_fp", BV2F(RZ_FLOAT_IEEE754_BIN_80, fpu_quiet_fp80_nan_bits(ITE(IS_FNAN(VARL("dst_fp")), VARL("dst_bits"), VARL("src_bits"))))),
		SETL("exact_exp", U16(0x7fff)),
		fscale_commit(ctx, dst->reg));
	seq = SEQ2(seq, BRANCH(OR(IS_FNAN(VARL("src_fp")), IS_FNAN(VARL("dst_fp"))), nan, BRANCH(IS_FINF(VARL("src_fp")), SEQ2(SETL("res_fp", IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80)), fscale_round_and_commit(ctx, dst->reg)), BRANCH(OR(IS_FINF(VARL("dst_fp")), IS_FZERO(VARL("dst_fp"))), SEQ2(SETL("res_fp", VARL("dst_fp")), fscale_round_and_commit(ctx, dst->reg)), scale))));
	return seq;
}

static RzILOpEffect *lift_fpu_binary_data(M68KILCtx *ctx, ut32 insn_id) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (!dst || !rz_m68k_op_is_fpu_reg(dst)) {
		return fpu_write_failure_label(ctx, dst);
	}
	const cs_m68k_op *src = &ctx->m68k->operands[0];
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", NULL, src, bits, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, src);
	}
	if (!fpu_operand_to_float_local(ctx, "dst_fp", NULL, dst, 80, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, dst);
	}
	seq = SEQ2(seq, SETL("round_mode", fpu_fpcr_round_mode()));
	if (fpu_binary_uses_fpcr_precision(insn_id)) {
		seq = SEQ2(seq, SETL("precision", fpu_fpcr_precision()));
	} else if (insn_id == M68K_INS_FSADD || insn_id == M68K_INS_FSSUB ||
		insn_id == M68K_INS_FSMUL || insn_id == M68K_INS_FSDIV) {
		seq = SEQ2(seq, SETL("precision", U32(1)));
	} else if (fpu_insn_is_fsgl(insn_id)) {
		/* FSGL rounds only its mantissa to single precision. Range
		 * control continues to use the extended exponent. */
		seq = SEQ2(seq, SETL("precision", U32(0)));
	} else if (insn_id == M68K_INS_FDADD || insn_id == M68K_INS_FDSUB ||
		insn_id == M68K_INS_FDMUL || insn_id == M68K_INS_FDDIV) {
		seq = SEQ2(seq, SETL("precision", U32(2)));
	}
	if (insn_id == M68K_INS_FMOD || insn_id == M68K_INS_FREM) {
		seq = SEQ2(seq, set_fpsr_quotient_byte(insn_id));
	}
	RzILOpFloat *result = fpu_binary_result(ctx, insn_id);
	if (!result) {
		rz_il_op_effect_free(seq);
		return m68k_label("m68k_unimplemented");
	}

	seq = SEQ2(seq, SETL("res_fp", result));
	if (fpu_insn_is_fdiv(insn_id)) {
		seq = SEQ2(seq, SETL("res_fp", ITE(fpu_fdiv_operr(), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80), VARL("res_fp"))));
	}
	if (fpu_insn_is_fadd(insn_id)) {
		seq = SEQ2(seq, SETL("res_fp", ITE(fpu_fadd_operr(), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80), VARL("res_fp"))));
	}
	if (fpu_insn_is_fsub(insn_id)) {
		seq = SEQ2(seq, SETL("res_fp", ITE(fpu_fsub_operr(), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80), VARL("res_fp"))));
	}
	if (fpu_insn_is_fmul(insn_id)) {
		seq = SEQ2(seq, SETL("res_fp", ITE(fpu_fmul_operr(), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80), VARL("res_fp"))));
	}
	if (fpu_insn_is_fmod(insn_id)) {
		seq = SEQ2(seq, SETL("res_fp", ITE(fpu_fmod_operr(), IL_FQNAN(RZ_FLOAT_IEEE754_BIN_80), ITE(AND(IS_FINF(VARL("src_fp")), AND(INV(IS_FNAN(VARL("dst_fp"))), INV(IS_FINF(VARL("dst_fp"))))), fpu_result_with_fpcr_precision(VARL("dst_fp")), VARL("res_fp")))));
	}
	seq = SEQ2(seq, SETL("res_fp", ITE(fpu_binary_snan(), fpu_binary_snan_result(), VARL("res_fp"))));
	seq = SEQ2(seq, m68k_write_reg_sized(ctx, dst->reg, 80, F2BV(VARL("res_fp"))));
	seq = SEQ2(seq, set_fpsr_cc_from_float_local("res_fp"));
	if (fpu_insn_is_fadd(insn_id)) {
		seq = SEQ2(seq, SETL("src80", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		seq = SEQ2(seq, SETL("dst80", fpu_to_format(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		seq = SEQ2(seq, SETL("rne_bits", F2BV(FADD(RZ_FLOAT_RMODE_RNE, VARL("dst80"), VARL("src80")))));
		seq = SEQ2(seq, SETL("rtz_bits", F2BV(FADD(RZ_FLOAT_RMODE_RTZ, VARL("dst80"), VARL("src80")))));
		seq = SEQ2(seq, SETL("rtp_bits", F2BV(FADD(RZ_FLOAT_RMODE_RTP, VARL("dst80"), VARL("src80")))));
		seq = SEQ2(seq, SETL("rtn_bits", F2BV(FADD(RZ_FLOAT_RMODE_RTN, VARL("dst80"), VARL("src80")))));
		seq = SEQ2(seq, SETL("res_bits", F2BV(VARL("res_fp"))));
		seq = SEQ2(seq, SETL("res_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("res_bits"), U8(64)), UN(80, 0x7fff)))));
		seq = SEQ2(seq, SETL("exact_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("rne_bits"), U8(64)), UN(80, 0x7fff)))));
		seq = SEQ2(seq, set_fpsr_fadd_exc());
	}
	if (fpu_insn_is_fsub(insn_id)) {
		seq = SEQ2(seq, SETL("src80", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		seq = SEQ2(seq, SETL("dst80", fpu_to_format(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		seq = SEQ2(seq, SETL("rne_bits", F2BV(FSUB(RZ_FLOAT_RMODE_RNE, VARL("dst80"), VARL("src80")))));
		seq = SEQ2(seq, SETL("rtz_bits", F2BV(FSUB(RZ_FLOAT_RMODE_RTZ, VARL("dst80"), VARL("src80")))));
		seq = SEQ2(seq, SETL("rtp_bits", F2BV(FSUB(RZ_FLOAT_RMODE_RTP, VARL("dst80"), VARL("src80")))));
		seq = SEQ2(seq, SETL("rtn_bits", F2BV(FSUB(RZ_FLOAT_RMODE_RTN, VARL("dst80"), VARL("src80")))));
		seq = SEQ2(seq, SETL("res_bits", F2BV(VARL("res_fp"))));
		seq = SEQ2(seq, SETL("res_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("res_bits"), U8(64)), UN(80, 0x7fff)))));
		seq = SEQ2(seq, SETL("exact_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("rne_bits"), U8(64)), UN(80, 0x7fff)))));
		seq = SEQ2(seq, set_fpsr_fsub_exc());
	}
	if (fpu_insn_is_fmul(insn_id)) {
		seq = SEQ2(seq, SETL("src80", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		seq = SEQ2(seq, SETL("dst80", fpu_to_format(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		const char *src_calc = "src80";
		const char *dst_calc = "dst80";
		if (fpu_insn_is_fsgl(insn_id)) {
			seq = SEQ2(seq, SETL("src_calc80", fpu_fsgl_truncate_operand(VARL("src80"))));
			seq = SEQ2(seq, SETL("dst_calc80", fpu_fsgl_truncate_operand(VARL("dst80"))));
			src_calc = "src_calc80";
			dst_calc = "dst_calc80";
		}
		seq = SEQ2(seq, SETL("rne_bits", F2BV(FMUL(RZ_FLOAT_RMODE_RNE, VARL(dst_calc), VARL(src_calc)))));
		seq = SEQ2(seq, SETL("rtz_bits", F2BV(FMUL(RZ_FLOAT_RMODE_RTZ, VARL(dst_calc), VARL(src_calc)))));
		seq = SEQ2(seq, SETL("rtp_bits", F2BV(FMUL(RZ_FLOAT_RMODE_RTP, VARL(dst_calc), VARL(src_calc)))));
		seq = SEQ2(seq, SETL("rtn_bits", F2BV(FMUL(RZ_FLOAT_RMODE_RTN, VARL(dst_calc), VARL(src_calc)))));
		seq = SEQ2(seq, SETL("res_bits", F2BV(VARL("res_fp"))));
		seq = SEQ2(seq, SETL("res_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("res_bits"), U8(64)), UN(80, 0x7fff)))));
		seq = SEQ2(seq, SETL("exact_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("rne_bits"), U8(64)), UN(80, 0x7fff)))));
		seq = SEQ2(seq, set_fpsr_fmul_exc());
	}
	if (fpu_insn_is_fmod(insn_id)) {
		if (insn_id == M68K_INS_FMOD) {
			seq = SEQ2(seq, SETL("src80", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)));
			seq = SEQ2(seq, SETL("dst80", fpu_to_format(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80)));
			seq = SEQ2(seq, SETL("exact_bits", ITE(AND(IS_FINF(VARL("src_fp")), AND(INV(IS_FNAN(VARL("dst_fp"))), INV(IS_FINF(VARL("dst_fp"))))), F2BV(VARL("dst80")), F2BV(FMOD(RZ_FLOAT_RMODE_RTZ, VARL("dst80"), VARL("src80"))))));
			seq = SEQ2(seq, SETL("res_bits", F2BV(VARL("res_fp"))));
			seq = SEQ2(seq, SETL("exact_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("exact_bits"), U8(64)), UN(80, 0x7fff)))));
			seq = SEQ2(seq, set_fpsr_fmod_exc(true));
		} else {
			seq = SEQ2(seq, SETL("src80", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)));
			seq = SEQ2(seq, SETL("dst80", fpu_to_format(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80)));
			seq = SEQ2(seq, SETL("exact_bits", ITE(AND(IS_FINF(VARL("src_fp")), AND(INV(IS_FNAN(VARL("dst_fp"))), INV(IS_FINF(VARL("dst_fp"))))), F2BV(VARL("dst80")), F2BV(fpu_frem_unrounded_from_80()))));
			seq = SEQ2(seq, SETL("exact_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("exact_bits"), U8(64)), UN(80, 0x7fff)))));
			seq = SEQ2(seq, set_fpsr_fmod_exc(false));
		}
	}
	if (fpu_insn_is_fdiv(insn_id)) {
		seq = SEQ2(seq, SETL("src80", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		seq = SEQ2(seq, SETL("dst80", fpu_to_format(VARL("dst_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		const char *src_calc = "src80";
		const char *dst_calc = "dst80";
		if (fpu_insn_is_fsgl(insn_id)) {
			seq = SEQ2(seq, SETL("src_calc80", fpu_fsgl_truncate_operand(VARL("src80"))));
			seq = SEQ2(seq, SETL("dst_calc80", fpu_fsgl_truncate_operand(VARL("dst80"))));
			src_calc = "src_calc80";
			dst_calc = "dst_calc80";
		}
		seq = SEQ2(seq, SETL("rne_bits", F2BV(FDIV(RZ_FLOAT_RMODE_RNE, VARL(dst_calc), VARL(src_calc)))));
		seq = SEQ2(seq, SETL("rtz_bits", F2BV(FDIV(RZ_FLOAT_RMODE_RTZ, VARL(dst_calc), VARL(src_calc)))));
		seq = SEQ2(seq, SETL("rtp_bits", F2BV(FDIV(RZ_FLOAT_RMODE_RTP, VARL(dst_calc), VARL(src_calc)))));
		seq = SEQ2(seq, SETL("rtn_bits", F2BV(FDIV(RZ_FLOAT_RMODE_RTN, VARL(dst_calc), VARL(src_calc)))));
		seq = SEQ2(seq, SETL("res_bits", F2BV(VARL("res_fp"))));
		seq = SEQ2(seq, SETL("res_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("res_bits"), U8(64)), UN(80, 0x7fff)))));
		seq = SEQ2(seq, SETL("exact_exp", UNSIGNED(16, LOGAND(SHIFTR0(VARL("rne_bits"), U8(64)), UN(80, 0x7fff)))));
		seq = SEQ2(seq, set_fpsr_fdiv_exc());
	}
	return seq;
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

/* FCMP/FTST: CC as in UM 4-31 / 4-103. SNAN if an operand is SNAN (4.5.4).
 * Other EXC bits cleared. Quotient unchanged. Detect SNAN on the original
 * encoding width before converting a memory/imm source to 80-bit. */
static RzILOpEffect *set_fpsr_fcmp_exc(bool binary) {
	RzILOpPure *cleared = LOGAND(VARG("fpsr"), U32(~M68K_FPSR_EXC_MASK));
	RzILOpPure *flags = binary ? fpu_exc_with_snan(U32(0)) : fpu_exc_with_src_snan(U32(0));
	return SETG("fpsr", LOGOR(cleared, flags));
}

static RzILOpEffect *lift_fpu_compare_data(M68KILCtx *ctx, bool test_zero) {
	rz_return_val_if_fail(ctx->m68k->op_count >= 1, NULL);
	ut32 bits = rz_m68k_detail_op_bits(ctx->m68k, 80);
	RzILOpEffect *seq = NULL;
	if (!fpu_operand_to_float_local(ctx, "src_fp", NULL, &ctx->m68k->operands[0], bits, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, &ctx->m68k->operands[0]);
	}
	if (test_zero) {
		/* EXC first on the original encoding. Do not reuse src_fp: a 32-bit
		 * memory/imm source cannot be rebound as an 80-bit float.
		 * FTST CC is the operand itself (UM 4-103): −0 is NZ, not Z. */
		seq = SEQ2(seq, set_fpsr_fcmp_exc(false));
		seq = SEQ2(seq, SETL("src80", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)));
		return SEQ2(seq, set_fpsr_cc_from_float_local("src80"));
	}
	cs_m68k_op hidden_dst;
	const cs_m68k_op *dst = rz_m68k_fpu_insn_second_op_or_hidden_dst(ctx->insn, &hidden_dst);
	if (!dst || !rz_m68k_op_is_fpu_reg(dst)) {
		rz_il_op_effect_free(seq);
		return fpu_write_failure_label(ctx, dst);
	}
	if (!fpu_operand_to_float_local(ctx, "dst_fp", NULL, dst, 80, &seq)) {
		rz_il_op_effect_free(seq);
		return fpu_read_failure_label(ctx, dst);
	}
	seq = SEQ2(seq, set_fpsr_fcmp_exc(true));
	seq = SEQ2(seq, SETL("src80", fpu_to_format(VARL("src_fp"), RZ_FLOAT_IEEE754_BIN_80)));
	return SEQ2(seq, set_fpsr_cc_from_float_cmp("dst_fp", "src80"));
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
		return lift_fpu_scale_data(ctx);
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
		M68KEA ea = m68k_effective_addr(ctx, op, bits);
		if (!ea.addr) {
			return NULL;
		}
		seq = SETL("fpu_addr", UNSIGNED(M68K_ADDR_BITS, ea.addr));
		seq = m68k_effect_pre_post(ea.pre, seq, ea.post);
		has_mem = true;
	}
	return has_mem ? (seq ? SEQ2(seq, m68k_label("m68k_fpu")) : (m68k_label("m68k_fpu"))) : m68k_label("m68k_fpu");
}

/* UM 2.4 / PRM 1.2.4: before an exception-capable FPU instruction is
 * executed, load its logical address into FPIAR unless every arithmetic
 * exception is disabled. FPCR ENABLE occupies the same bit positions as
 * the FPSR EXC byte. FMOVE control and every FMOVEM are excluded by the
 * caller because they cannot generate floating-point exceptions. */
static RzILOpEffect *set_fpiar_for_fpu_exception_instruction(M68KILCtx *ctx) {
	return BRANCH(
		NON_ZERO(LOGAND(VARG("fpcr"), U32(M68K_FPSR_EXC_MASK))),
		SETG("fpiar", U32((ut32)ctx->addr)),
		EMPTY());
}

static bool fpu_effect_rejects_instruction(const RzILOpEffect *effect) {
	rz_return_val_if_fail(effect, false);
	/* m68k_illegal also binds trap metadata before its terminal label. */
	while (effect->code == RZ_IL_OP_SEQ) {
		effect = effect->op.seq.y;
	}
	if (effect->code != RZ_IL_OP_GOTO) {
		return false;
	}
	const char *label = effect->op.goto_.lbl;
	return RZ_STR_EQ(label, "m68k_illegal") || RZ_STR_EQ(label, "m68k_unimplemented");
}

static RzILOpEffect *prepend_fpiar_update(M68KILCtx *ctx, RzILOpEffect *effect) {
	rz_return_val_if_fail(ctx && effect, NULL);
	if (fpu_effect_rejects_instruction(effect)) {
		return effect;
	}
	return SEQ2(set_fpiar_for_fpu_exception_instruction(ctx), effect);
}

static RzILOpEffect *fpu_mark_idle(RzILOpEffect *effect) {
	rz_return_val_if_fail(effect, NULL);
	if (fpu_effect_rejects_instruction(effect)) {
		return effect;
	}
	return SEQ2(SETG("fpu_state", U32(0)), effect);
}

static RzILOpEffect *lift_trapv(M68KILCtx *ctx) {
	return BRANCH(m68k_ccr_bit(M68K_CCR_V), explicit_trap_effect(ctx, M68K_TRAP_OP_TRAPV, false), EMPTY());
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
	for (ut8 i = 0; i < ctx.m68k->op_count; i++) {
		// Capstone can leave M68K_OP_INVALID on malformed encodings.
		if (rz_m68k_fpu_op_detail_is_invalid(&ctx.m68k->operands[i])) {
			return NULL;
		}
	}

	RzILOpEffect *fpu_data = lift_fpu_data(&ctx);
	if (fpu_data) {
		RzILOpEffect *effect = insn->id == M68K_INS_FMOVEM
			? fpu_data
			: prepend_fpiar_update(&ctx, fpu_data);
		return fpu_mark_idle(effect);
	}

	RzILOpEffect *fpu_alias = lift_fpu_data_alias(&ctx);
	if (fpu_alias) {
		return fpu_mark_idle(prepend_fpiar_update(&ctx, fpu_alias));
	}

	if (rz_m68k_insn_uses_fpu_operand(ctx.m68k)) {
		return fpu_mark_idle(prepend_fpiar_update(&ctx, lift_fpu_unmodeled_address_effects(&ctx)));
	}

	RzILOpBool *fpu_cond = fpu_cond_code(insn->id);
	if (fpu_cond) {
		RzILOpEffect *conditional = lift_fpu_conditional(&ctx, fpu_cond);
		RzILOpEffect *effect = fpu_cond_offset(insn->id) < 16
			? conditional
			: prepend_fpiar_update(&ctx, conditional);
		return fpu_mark_idle(effect);
	}

	switch (insn->id) {
	case M68K_INS_INVALID:
		return NULL;
	case M68K_INS_NOP:
		return NOP();
	case M68K_INS_HALT:
		return lift_privileged_system(M68K_SYSTEM_OP_HALT);
	case M68K_INS_MOVE:
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
		if (insn->detail && insn->detail->m68k.op_count >= 2) {
			const cs_m68k_op *move_src = &insn->detail->m68k.operands[0];
			const cs_m68k_op *move_dst = &insn->detail->m68k.operands[1];
			if (rz_m68k_op_is_acc_reg(move_src) && rz_m68k_op_is_acc_reg(move_dst)) {
				return lift_move_acc_to_acc(&ctx);
			}
			if (rz_m68k_op_is_acc_reg(move_src) && rz_m68k_op_is_gpr(move_dst)) {
				return lift_move_from_acc(&ctx);
			}
			if (rz_m68k_op_is_acc_reg(move_dst) &&
				(rz_m68k_op_is_gpr(move_src) || move_src->type == M68K_OP_IMM)) {
				return lift_move_to_acc(&ctx);
			}
			if (mac_op_is_accext(move_src) && rz_m68k_op_is_gpr(move_dst)) {
				return lift_move_accext(&ctx);
			}
			if (mac_op_is_accext(move_dst) &&
				(rz_m68k_op_is_gpr(move_src) || move_src->type == M68K_OP_IMM)) {
				return lift_move_accext(&ctx);
			}
			if (mac_op_is_mask(move_src) && rz_m68k_op_is_gpr(move_dst)) {
				return lift_move_mask(&ctx);
			}
			if (mac_op_is_mask(move_dst) &&
				(rz_m68k_op_is_gpr(move_src) || move_src->type == M68K_OP_IMM)) {
				return lift_move_mask(&ctx);
			}
			if (mac_op_is_macsr(move_src) && mac_op_is_ccr(move_dst)) {
				return lift_move_macsr_to_ccr(&ctx);
			}
			if (mac_op_is_macsr(move_src) && rz_m68k_op_is_gpr(move_dst)) {
				return lift_move_macsr(&ctx);
			}
			if (mac_op_is_macsr(move_dst) &&
				(rz_m68k_op_is_gpr(move_src) || move_src->type == M68K_OP_IMM)) {
				return lift_move_macsr(&ctx);
			}
		}
#endif
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
		return lift_binop(&ctx, RZ_IL_OP_ADD, false, false);
	case M68K_INS_ADDQ:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_addr_reg(&ctx.m68k->operands[1])
			? lift_binop(&ctx, RZ_IL_OP_ADD, true, false)
			: lift_binop(&ctx, RZ_IL_OP_ADD, false, false);
	case M68K_INS_ADDX:
		return lift_addx_subx(&ctx, false);
	case M68K_INS_ABCD:
		return lift_abcd_sbcd(&ctx, false);
	case M68K_INS_PACK:
		return lift_pack_unpk(&ctx, false);
	case M68K_INS_ADDA:
		return lift_binop(&ctx, RZ_IL_OP_ADD, true, false);
	case M68K_INS_SUB:
	case M68K_INS_SUBI:
		return lift_binop(&ctx, RZ_IL_OP_SUB, false, false);
	case M68K_INS_SUBQ:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_addr_reg(&ctx.m68k->operands[1])
			? lift_binop(&ctx, RZ_IL_OP_SUB, true, false)
			: lift_binop(&ctx, RZ_IL_OP_SUB, false, false);
	case M68K_INS_SUBX:
		return lift_addx_subx(&ctx, true);
	case M68K_INS_SBCD:
		return lift_abcd_sbcd(&ctx, true);
	case M68K_INS_UNPK:
		return lift_pack_unpk(&ctx, true);
	case M68K_INS_SUBA:
		return lift_binop(&ctx, RZ_IL_OP_SUB, true, false);
	case M68K_INS_CMP:
	case M68K_INS_CMPI:
	case M68K_INS_CMPM:
		return lift_binop(&ctx, RZ_IL_OP_SUB, false, true);
	case M68K_INS_CMPA:
		return lift_binop(&ctx, RZ_IL_OP_SUB, true, true);
	case M68K_INS_CMP2:
		return lift_cmp2_chk2(&ctx, false);
	case M68K_INS_AND:
		return lift_binop(&ctx, RZ_IL_OP_LOGAND, false, false);
	case M68K_INS_ANDI:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_status_reg(&ctx.m68k->operands[1])
			? lift_status_binop(&ctx, RZ_IL_OP_LOGAND)
			: lift_binop(&ctx, RZ_IL_OP_LOGAND, false, false);
	case M68K_INS_OR:
		return lift_binop(&ctx, RZ_IL_OP_LOGOR, false, false);
	case M68K_INS_ORI:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_status_reg(&ctx.m68k->operands[1])
			? lift_status_binop(&ctx, RZ_IL_OP_LOGOR)
			: lift_binop(&ctx, RZ_IL_OP_LOGOR, false, false);
	case M68K_INS_EOR:
		return lift_binop(&ctx, RZ_IL_OP_LOGXOR, false, false);
	case M68K_INS_EORI:
		return ctx.m68k->op_count >= 2 && rz_m68k_op_is_status_reg(&ctx.m68k->operands[1])
			? lift_status_binop(&ctx, RZ_IL_OP_LOGXOR)
			: lift_binop(&ctx, RZ_IL_OP_LOGXOR, false, false);
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
		return m68k_guard_supervisor(lift_cache_address_effects(&ctx));
	case M68K_INS_PFLUSHA:
	case M68K_INS_PFLUSHAN:
		return m68k_guard_supervisor(lift_mmu_flush_all(&ctx));
	case M68K_INS_PFLUSH:
	case M68K_INS_PFLUSHN:
	case M68K_INS_PLOADR:
	case M68K_INS_PLOADW:
	case M68K_INS_PLPAR:
	case M68K_INS_PLPAW:
		return m68k_guard_supervisor(lift_mmu_address_effects(&ctx, 32));
	case M68K_INS_PMOVE:
	case M68K_INS_PMOVEFD:
		return m68k_guard_supervisor(lift_pmove(&ctx));
	case M68K_INS_PTESTR:
	case M68K_INS_PTESTW:
		return m68k_guard_supervisor(lift_mmu_address_effects(&ctx, 32));
	case M68K_INS_FSAVE:
	case M68K_INS_FRESTORE:
		return lift_fpu_state_address_effects(&ctx);
	case M68K_INS_FNOP:
		return fpu_mark_idle(NOP());
	case M68K_INS_FMOVE: {
		RzILOpEffect *effect = lift_fmove_control(&ctx);
		return fpu_mark_idle(effect ? effect : m68k_label("m68k_fpu"));
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
			return fpu_mark_idle(lift_fpu_unmodeled_address_effects(&ctx));
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
	"cp_external_data", "fpu_state",
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
	rz_analysis_il_init_state_set_var(cfg->init_state, "mask", rz_il_value_new_bitv(rz_bv_new_from_ut64(32, M68K_MAC_MASK_RESET)));
	rz_analysis_il_init_state_set_var(cfg->init_state, "macsr", rz_il_value_new_bitv(rz_bv_new_from_ut64(32, 0)));
	rz_analysis_il_init_state_set_var(cfg->init_state, "cp_external_data", rz_il_value_new_bitv(rz_bv_new_from_ut64(32, 0)));
	rz_analysis_il_init_state_set_var(cfg->init_state, "fpu_state", rz_il_value_new_bitv(rz_bv_new_from_ut64(32, 0)));
	const char *fp_regs[] = {
		"fp0", "fp1", "fp2", "fp3", "fp4", "fp5", "fp6", "fp7", NULL
	};
	for (size_t i = 0; fp_regs[i]; i++) {
		rz_analysis_il_init_state_set_var(cfg->init_state, fp_regs[i], rz_il_value_new_bitv(rz_bv_new_from_ut64(80, 0)));
	}
	return cfg;
}

#include <rz_il/rz_il_opbuilder_end.h>
