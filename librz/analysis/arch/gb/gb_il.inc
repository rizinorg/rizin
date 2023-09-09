// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * GameBoy lifting to be included from analysis_gb.c and plugged directly into the decoding logic.
 */

static ut32 gb_reg_bits(gb_reg reg) {
	switch (reg) {
	case GB_REG_A:
	case GB_REG_B:
	case GB_REG_C:
	case GB_REG_D:
	case GB_REG_E:
	case GB_REG_H:
	case GB_REG_L:
		return 8;
	case GB_REG_AF:
	case GB_REG_BC:
	case GB_REG_DE:
	case GB_REG_HL:
	case GB_REG_SP:
		return 16;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

/**
 * Get the register that forms the lower part of \p reg (which must be BC, DE or HL)
 */
static gb_reg gb_reg_lower(gb_reg reg) {
	switch (reg) {
	case GB_REG_BC:
		return GB_REG_C;
	case GB_REG_DE:
		return GB_REG_E;
	case GB_REG_HL:
		return GB_REG_L;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

/**
 * Get the register that forms the higher part of \p reg (which must be BC, DE or HL)
 */
static gb_reg gb_reg_higher(gb_reg reg) {
	switch (reg) {
	case GB_REG_BC:
		return GB_REG_B;
	case GB_REG_DE:
		return GB_REG_D;
	case GB_REG_HL:
		return GB_REG_H;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static const char *gb_reg_name(gb_reg reg) {
	switch (reg) {
	case GB_REG_A:
		return "a";
	case GB_REG_B:
		return "b";
	case GB_REG_C:
		return "c";
	case GB_REG_D:
		return "d";
	case GB_REG_E:
		return "e";
	case GB_REG_H:
		return "h";
	case GB_REG_L:
		return "l";
	case GB_REG_AF:
		return "af";
	case GB_REG_BC:
		return "bc";
	case GB_REG_DE:
		return "de";
	case GB_REG_HL:
		return "hl";
	case GB_REG_SP:
		return "sp";
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

static const char *gb_flag_name(gb_flag flag) {
	switch (flag) {
	case GB_FLAG_Z:
		return "Z";
	case GB_FLAG_N:
		return "N";
	case GB_FLAG_H:
		return "H";
	case GB_FLAG_C:
		return "C";
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \name Address Calculation
 * Because Gameboy uses bank switching, where one part of memory may be switched to
 * different rom parts at runtime, but we still want to be able to see the entire code
 * all the time, Rizin flattens out the ROM over a 32-bit space.
 * This imposes a challenge to lifting because we have to determine into which 64k "page"
 * a 16-bit pointer will actually point. Due to the dynamic nature of bank switching,
 * this is not always possible and no static implementation will be perfect, so we abstract
 * this logic out of the lifting code itself and into the following functions to enable
 * easy future adjustments.
 *
 * In the current implementation we try to do a best effort approach by leveraging the
 * higher bits of the current program counter as extra context. If these high bits are 0,
 * it will stay in the 0 page, meaning actual emulation in a pure 16-bit space will not
 * be affected.
 * @{
 */

static RzILOpBitVector *gb_il_resolve_addr_data(ut64 op_addr, RzILOpBitVector *target_addr16) {
	(void)op_addr; // currently unused, but the returned addr could be made 32-bits and depend on the op_addr, like with code
	return target_addr16;
}

static RzILOpBitVector *gb_il_resolve_addr_code(ut64 op_addr, RzILOpBitVector *target_addr16) {
	// Similar logic as in gb_op_calljump(), but dynamic.
	if (op_addr >> 16) {
		return APPEND(
			op_addr >> 16 ? ITE(MSB(UNSIGNED(15, target_addr16)), U16((op_addr >> 16) & 0xffff), U16(0)) : U16(0),
			DUP(target_addr16));
	}
	return UNSIGNED(32, target_addr16);
}

static RzILOpBitVector *gb_il_resolve_addr_code_imm(ut64 addr) {
	// No calculation done here at the moment as these addrs are assumed to be already translated
	// for example by gb_op_calljump()
	return U32(addr);
}

/// @}

/*
 * Calculate the carry of a \p carry_bits addition (or subtraction) of \p a, \p b and optinally C, where \p a, \p b are of size \p src_bits
 * Example:
 *   gb_il_carry(false, a, b, 16, 8)
 * calculates:
 *   (a & 0xff) + (b & 0xff) > 0xff
 */
static RzILOpBool *gb_il_carry(bool sub, RzILOpBitVector *a, RzILOpBitVector *b, bool carry_in, ut32 src_bits, ut32 carry_bits) {
	RzILOpBitVector *(*binop)(RzILOpBitVector *, RzILOpBitVector *) = sub ? rz_il_op_new_sub : rz_il_op_new_add;
	if (carry_bits >= src_bits) {
		src_bits = carry_bits + 1;
		a = UNSIGNED(carry_bits + 1, a);
		b = UNSIGNED(carry_bits + 1, b);
		if (carry_in) {
			b = ADD(b, ITE(VARG("C"), UN(carry_bits + 1, 1), UN(carry_bits + 1, 0)));
		}
		return MSB(binop(a, b));
	}
	ut64 mask = rz_num_bitmask(carry_bits);
	a = LOGAND(a, UN(src_bits, mask));
	b = LOGAND(b, UN(src_bits, mask));
	if (carry_in) {
		b = ADD(b, ITE(VARG("C"), UN(src_bits, 1), UN(src_bits, 0)));
	}
	return UGT(binop(a, b), UN(src_bits, mask));
}

static RzILOpEffect *gb_il_write_flags(RzILOpBitVector *src) {
	return SEQ4(
		SETG("Z", MSB(UNSIGNED(8, src))),
		SETG("N", MSB(UNSIGNED(7, DUP(src)))),
		SETG("H", MSB(UNSIGNED(6, DUP(src)))),
		SETG("C", MSB(UNSIGNED(5, DUP(src)))));
}

/**
 * \p val must be of size gb_reg_bits(dst)
 */
static RzILOpEffect *gb_il_write_reg(gb_reg dst, RzILOpBitVector *val) {
	switch (dst) {
	case GB_REG_A:
	case GB_REG_B:
	case GB_REG_C:
	case GB_REG_D:
	case GB_REG_E:
	case GB_REG_H:
	case GB_REG_L:
	case GB_REG_SP:
		return SETG(gb_reg_name(dst), val);
	case GB_REG_AF:
		return SEQ2(
			SETG("a", UNSIGNED(8, SHIFTR0(val, UN(4, 8)))),
			gb_il_write_flags(DUP(val)));
	case GB_REG_BC:
	case GB_REG_DE:
	case GB_REG_HL:
		return SEQ2(
			SETG(gb_reg_name(gb_reg_higher(dst)), UNSIGNED(8, SHIFTR0(val, UN(4, 8)))),
			SETG(gb_reg_name(gb_reg_lower(dst)), UNSIGNED(8, DUP(val))));
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

static RzILOpBitVector *gb_il_read_flags() {
	return LOGOR(
		ITE(VARG("Z"), U8(0x80), U8(0)),
		LOGOR(
			ITE(VARG("N"), U8(0x40), U8(0)),
			LOGOR(
				ITE(VARG("H"), U8(0x20), U8(0)),
				ITE(VARG("C"), U8(0x10), U8(0)))));
}

static RzILOpBitVector *gb_il_read_reg(gb_reg reg) {
	if (gb_reg_bits(reg) == 8 || reg == GB_REG_SP) {
		return VARG(gb_reg_name(reg));
	}
	switch (reg) {
	case GB_REG_AF:
		return APPEND(
			VARG("a"),
			gb_il_read_flags());
	case GB_REG_BC:
	case GB_REG_DE:
	case GB_REG_HL:
		return APPEND(
			VARG(gb_reg_name(gb_reg_higher(reg))),
			VARG(gb_reg_name(gb_reg_lower(reg))));
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

static RzILOpEffect *gb_il_mov_imm(gb_reg dst, ut16 imm) {
	if (gb_reg_bits(dst) == 8) {
		return gb_il_write_reg(dst, U8(imm & 0xff));
	}
	// do not use gb_il_write_reg for 16-bit to avoid unnecessary 16-bit casting of the constant value
	gb_reg h, l;
	switch (dst) {
	case GB_REG_SP:
		return SETG(gb_reg_name(dst), U16(imm));
	case GB_REG_BC:
		h = GB_REG_B;
		l = GB_REG_C;
		break;
	case GB_REG_DE:
		h = GB_REG_D;
		l = GB_REG_E;
		break;
	case GB_REG_HL:
		h = GB_REG_H;
		l = GB_REG_L;
		break;
	default:
		rz_warn_if_reached();
		return NULL;
	}
	return SEQ2(
		SETG(gb_reg_name(h), U8(imm >> 8)),
		SETG(gb_reg_name(l), U8(imm & 0xff)));
}

static RzILOpEffect *gb_il_mov_hl_sp(st8 imm) {
	return SEQ5(
		gb_il_write_reg(GB_REG_HL, imm < 0 ? SUB(VARG("sp"), U16(-imm)) : ADD(VARG("sp"), U16(imm))),
		SETG("Z", IL_FALSE),
		SETG("N", IL_FALSE),
		SETG("H", gb_il_carry(false, VARG("sp"), U16((ut8)imm), false, 16, 4)),
		SETG("C", gb_il_carry(false, VARG("sp"), U16((ut8)imm), false, 16, 8)));
}

static RzILOpEffect *gb_il_mov_sp_hl() {
	return SETG("sp", APPEND(VARG("h"), VARG("l")));
}

static RzILOpEffect *gb_il_mov_mov(gb_reg dst, gb_reg src) {
	return gb_il_write_reg(dst, gb_il_read_reg(src));
}

static RzILOpEffect *gb_il_inc(gb_reg reg, bool dec) {
	if (gb_reg_bits(reg) == 8) {
		RzILOpBitVector *r = VARG(gb_reg_name(reg));
		return SEQ4(
			SETG(gb_reg_name(reg), dec ? SUB(r, U8(1)) : ADD(r, U8(1))),
			SETG("Z", IS_ZERO(DUP(r))),
			SETG("N", dec ? IL_TRUE : IL_FALSE),
			SETG("H", dec ? EQ(UNSIGNED(4, DUP(r)), UN(4, 0xf)) : IS_ZERO(UNSIGNED(4, DUP(r)))));
	}
	if (reg == GB_REG_SP) {
		return SETG("sp", dec ? SUB(VARG("sp"), U16(1)) : ADD(VARG("sp"), U16(1)));
	}
	gb_reg h = gb_reg_higher(reg);
	gb_reg l = gb_reg_lower(reg);
	if (dec) {
		return SEQ2(
			SETG(gb_reg_name(h),
				ITE(IS_ZERO(VARG(gb_reg_name(l))),
					SUB(VARG(gb_reg_name(h)), U8(1)),
					VARG(gb_reg_name(h)))),
			SETG(gb_reg_name(l),
				SUB(VARG(gb_reg_name(l)), U8(1))));
	}
	return SEQ2(
		SETG(gb_reg_name(l),
			ADD(VARG(gb_reg_name(l)), U8(1))),
		SETG(gb_reg_name(h),
			ITE(IS_ZERO(VARG(gb_reg_name(l))),
				ADD(VARG(gb_reg_name(h)), U8(1)),
				VARG(gb_reg_name(h)))));
}

static RzILOpEffect *gb_il_inc_hl_mem(bool dec, ut64 op_addr) {
	return SEQ5(
		SETL("v", (dec ? rz_il_op_new_sub : rz_il_op_new_add)(LOAD(gb_il_resolve_addr_data(op_addr, gb_il_read_reg(GB_REG_HL))), U8(1))),
		STORE(gb_il_resolve_addr_data(op_addr, gb_il_read_reg(GB_REG_HL)), VARL("v")),
		SETG("Z", IS_ZERO(VARL("v"))),
		SETG("N", dec ? IL_TRUE : IL_FALSE),
		SETG("H", dec ? EQ(UNSIGNED(4, VARL("v")), UN(4, 0xf)) : IS_ZERO(UNSIGNED(4, VARL("v")))));
}

static RzILOpEffect *gb_il_store_imm_a(ut16 dst_addr, ut64 op_addr) {
	return STORE(gb_il_resolve_addr_data(op_addr, U16(dst_addr)), VARG("a"));
}

static RzILOpEffect *gb_il_store_imm_sp(ut16 dst_addr, ut64 op_addr) {
	return STOREW(gb_il_resolve_addr_data(op_addr, U16(dst_addr)), VARG("sp"));
}

/**
 * Resolve the indirect address pointed to by a register for load/store ops
 *   ld a, [<reg>]
 *   ld [<reg>], a
 */
static RzILOpBitVector *load_store_reg_addr(gb_reg reg, ut64 op_addr) {
	RzILOpBitVector *addr = gb_il_read_reg(reg);
	if (reg == GB_REG_C) {
		addr = APPEND(U8(0xff), addr);
	}
	return gb_il_resolve_addr_data(op_addr, addr);
}

static RzILOpEffect *gb_il_store_reg_reg(gb_reg dst_reg, bool inc, bool dec, gb_reg src_reg, ut64 op_addr) {
	rz_return_val_if_fail(!(inc && dec), NULL);
	RzILOpEffect *r = STORE(load_store_reg_addr(dst_reg, op_addr), gb_il_read_reg(src_reg));
	if (inc || dec) {
		r = SEQ2(r, gb_il_inc(dst_reg, dec));
	}
	return r;
}

static RzILOpEffect *gb_il_store_reg_imm(gb_reg dst_reg, ut8 imm, ut64 op_addr) {
	return STORE(gb_il_resolve_addr_data(op_addr, gb_il_read_reg(dst_reg)), U8(imm));
}

static RzILOpEffect *gb_il_load_reg_reg(gb_reg dst_reg, gb_reg src_reg, bool inc, bool dec, ut64 op_addr) {
	rz_return_val_if_fail(!(inc && dec), NULL);
	RzILOpEffect *r = gb_il_write_reg(dst_reg, LOAD(load_store_reg_addr(src_reg, op_addr)));
	if (inc || dec) {
		r = SEQ2(r, gb_il_inc(src_reg, dec));
	}
	return r;
}

static RzILOpEffect *gb_il_load_a_imm(ut16 src_addr, ut64 op_addr) {
	return SETG("a", LOAD(gb_il_resolve_addr_data(op_addr, U16(src_addr))));
}

static RzILOpEffect *gb_il_add(gb_reg dst_reg, RzILOpBitVector *src, bool carry_in) {
	RzILOpBitVector *dst = gb_il_read_reg(dst_reg);
	return SEQ6(
		SETG("H", gb_il_carry(false, dst, src, carry_in, 8, 4)),
		SETL("CC", gb_il_carry(false, DUP(dst), DUP(src), carry_in, 8, 8)),
		gb_il_write_reg(dst_reg, ADD(DUP(dst), carry_in ? ADD(DUP(src), ITE(VARG("C"), U8(1), U8(0))) : DUP(src))),
		SETG("C", VARL("CC")),
		SETG("Z", IS_ZERO(DUP(dst))),
		SETG("N", IL_FALSE));
}

static RzILOpEffect *gb_il_sub(gb_reg dst_reg, RzILOpBitVector *src, bool carry_in) {
	RzILOpBitVector *dst = gb_il_read_reg(dst_reg);
	return SEQ6(
		SETG("H", gb_il_carry(true, dst, src, carry_in, 8, 4)),
		SETL("CC", gb_il_carry(true, DUP(dst), DUP(src), carry_in, 8, 8)),
		gb_il_write_reg(dst_reg, SUB(DUP(dst), carry_in ? ADD(DUP(src), ITE(VARG("C"), U8(1), U8(0))) : DUP(src))),
		SETG("C", VARL("CC")),
		SETG("Z", IS_ZERO(DUP(dst))),
		SETG("N", IL_TRUE));
}

static RzILOpEffect *gb_il_and(gb_reg dst_reg, RzILOpBitVector *src) {
	RzILOpBitVector *dst = gb_il_read_reg(dst_reg);
	return SEQ5(
		gb_il_write_reg(dst_reg, LOGAND(dst, src)),
		SETG("Z", IS_ZERO(DUP(dst))),
		SETG("N", IL_FALSE),
		SETG("H", IL_TRUE),
		SETG("C", IL_FALSE));
}

static RzILOpEffect *gb_il_xor(gb_reg dst_reg, RzILOpBitVector *src) {
	RzILOpBitVector *dst = gb_il_read_reg(dst_reg);
	return SEQ5(
		gb_il_write_reg(dst_reg, LOGXOR(dst, src)),
		SETG("Z", IS_ZERO(DUP(dst))),
		SETG("N", IL_FALSE),
		SETG("H", IL_FALSE),
		SETG("C", IL_FALSE));
}

static RzILOpEffect *gb_il_or(gb_reg dst_reg, RzILOpBitVector *src) {
	RzILOpBitVector *dst = gb_il_read_reg(dst_reg);
	return SEQ5(
		gb_il_write_reg(dst_reg, LOGOR(dst, src)),
		SETG("Z", IS_ZERO(DUP(dst))),
		SETG("N", IL_FALSE),
		SETG("H", IL_FALSE),
		SETG("C", IL_FALSE));
}

static RzILOpEffect *gb_il_cmp(gb_reg dst_reg, RzILOpBitVector *src) {
	RzILOpBitVector *dst = gb_il_read_reg(dst_reg);
	return SEQ4(
		SETG("Z", EQ(dst, src)),
		SETG("N", IL_TRUE),
		SETG("H", ULT(UNSIGNED(4, DUP(dst)), UNSIGNED(4, DUP(src)))),
		SETG("C", ULT(DUP(dst), DUP(src))));
}

typedef enum {
	GB_IL_BINOP_ADD,
	GB_IL_BINOP_ADC,
	GB_IL_BINOP_SUB,
	GB_IL_BINOP_SBC,
	GB_IL_BINOP_AND,
	GB_IL_BINOP_XOR,
	GB_IL_BINOP_OR,
	GB_IL_BINOP_CMP
} gb_il_binop;

static RzILOpEffect *gb_il_binop_dispatch(gb_il_binop op, gb_reg dst_reg, RzILOpBitVector *src) {
	switch (op) {
	case GB_IL_BINOP_ADD:
		return gb_il_add(dst_reg, src, false);
	case GB_IL_BINOP_ADC:
		return gb_il_add(dst_reg, src, true);
	case GB_IL_BINOP_SUB:
		return gb_il_sub(dst_reg, src, false);
	case GB_IL_BINOP_SBC:
		return gb_il_sub(dst_reg, src, true);
	case GB_IL_BINOP_AND:
		return gb_il_and(dst_reg, src);
	case GB_IL_BINOP_XOR:
		return gb_il_xor(dst_reg, src);
	case GB_IL_BINOP_OR:
		return gb_il_or(dst_reg, src);
	case GB_IL_BINOP_CMP:
		return gb_il_cmp(dst_reg, src);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

static RzILOpEffect *gb_il_binop_imm(gb_il_binop op, gb_reg dst_reg, ut8 imm) {
	return gb_il_binop_dispatch(op, dst_reg, U8(imm));
}

static RzILOpEffect *gb_il_binop_reg(gb_il_binop op, gb_reg dst_reg, gb_reg src_reg) {
	return gb_il_binop_dispatch(op, dst_reg, gb_il_read_reg(src_reg));
}

static RzILOpEffect *gb_il_binop_reg_memref(gb_il_binop op, gb_reg dst_reg, gb_reg src_reg, ut64 op_addr) {
	return SEQ2(
		SETL("src", LOAD(gb_il_resolve_addr_data(op_addr, gb_il_read_reg(src_reg)))),
		gb_il_binop_dispatch(op, dst_reg, VARL("src")));
}

static RzILOpEffect *gb_il_add_hl(gb_reg src_reg) {
	RzILOpBitVector *dst = gb_il_read_reg(GB_REG_HL);
	RzILOpBitVector *src = gb_il_read_reg(src_reg);
	return SEQ4(
		SETG("H", gb_il_carry(false, dst, src, false, 16, 12)),
		SETG("C", gb_il_carry(false, DUP(dst), DUP(src), false, 16, 16)),
		gb_il_write_reg(GB_REG_HL, ADD(DUP(dst), DUP(src))),
		SETG("N", IL_FALSE));
}

static RzILOpEffect *gb_il_add_sp(st8 imm) {
	return SEQ5(
		SETG("H", gb_il_carry(false, VARG("sp"), S16(imm), false, 16, 4)),
		SETG("C", gb_il_carry(false, VARG("sp"), S16(imm), false, 16, 8)),
		SETG("sp", imm < 0 ? SUB(VARG("sp"), U16(-(st16)imm)) : ADD(VARG("sp"), U16(imm))),
		SETG("Z", IL_FALSE),
		SETG("N", IL_FALSE));
}

/**
 * Read an 8-bit value from either the given reg directly, or [HL] if reg == GB_REG_HL
 */
static RzILOpBitVector *gb_il_read_reg_or_mem(gb_reg reg, ut64 op_addr) {
	if (reg == GB_REG_HL) {
		return LOAD(gb_il_resolve_addr_data(op_addr, gb_il_read_reg(GB_REG_HL)));
	}
	return gb_il_read_reg(reg);
}

/**
 * Write an 8-bit value to either the given reg directly, or [HL] if reg == GB_REG_HL
 */
static RzILOpEffect *gb_il_write_reg_or_mem(gb_reg reg, RzILOpBitVector *val, ut64 op_addr) {
	if (reg == GB_REG_HL) {
		return STORE(gb_il_resolve_addr_data(op_addr, gb_il_read_reg(GB_REG_HL)), val);
	}
	return gb_il_write_reg(reg, val);
}

static RzILOpEffect *gb_il_rot_ca(bool right) {
	return SEQ5(
		SETG("C", right ? LSB(VARG("a")) : MSB(VARG("a"))),
		SETG("a", (right ? rz_il_op_new_shiftr : rz_il_op_new_shiftl)(VARG("C"), VARG("a"), UN(3, 1))),
		SETG("Z", IL_FALSE),
		SETG("N", IL_FALSE),
		SETG("H", IL_FALSE));
}

static RzILOpEffect *gb_il_rot_c(gb_reg reg, bool right, ut64 op_addr) {
	RzILOpBitVector *src = gb_il_read_reg_or_mem(reg, op_addr);
	return SEQ5(
		SETG("C", right ? LSB(src) : MSB(src)),
		gb_il_write_reg_or_mem(reg, (right ? rz_il_op_new_shiftr : rz_il_op_new_shiftl)(VARG("C"), DUP(src), UN(3, 1)), op_addr),
		SETG("Z", IS_ZERO(DUP(src))),
		SETG("N", IL_FALSE),
		SETG("H", IL_FALSE));
}

static RzILOpEffect *gb_il_rot(gb_reg reg, bool right, bool set_z, ut64 op_addr) {
	RzILOpBitVector *src = gb_il_read_reg_or_mem(reg, op_addr);
	return SEQ6(
		SETL("CC", VARG("C")),
		SETG("C", right ? LSB(src) : MSB(src)),
		gb_il_write_reg_or_mem(reg, (right ? rz_il_op_new_shiftr : rz_il_op_new_shiftl)(VARL("CC"), DUP(src), UN(3, 1)), op_addr),
		SETG("Z", set_z ? IS_ZERO(DUP(src)) : IL_FALSE),
		SETG("N", IL_FALSE),
		SETG("H", IL_FALSE));
}

static RzILOpEffect *gb_il_shift(gb_reg reg, bool right, bool is_signed, ut64 op_addr) {
	RzILOpBitVector *src = gb_il_read_reg_or_mem(reg, op_addr);
	return SEQ5(
		SETG("C", right ? LSB(DUP(src)) : MSB(DUP(src))),
		gb_il_write_reg_or_mem(reg, (right ? rz_il_op_new_shiftr : rz_il_op_new_shiftl)(is_signed ? MSB(DUP(src)) : IL_FALSE, src, UN(3, 1)), op_addr),
		SETG("Z", IS_ZERO(DUP(src))),
		SETG("N", IL_FALSE),
		SETG("H", IL_FALSE));
}

static RzILOpEffect *gb_il_swap(gb_reg reg, ut64 op_addr) {
	RzILOpBitVector *src = gb_il_read_reg_or_mem(reg, op_addr);
	return SEQ5(
		gb_il_write_reg_or_mem(reg, APPEND(UNSIGNED(4, src), UNSIGNED(4, SHIFTR0(DUP(src), UN(3, 4)))), op_addr),
		SETG("Z", IS_ZERO(DUP(src))),
		SETG("N", IL_FALSE),
		SETG("H", IL_FALSE),
		SETG("C", IL_FALSE));
}

static RzILOpEffect *gb_il_bit(gb_reg reg, ut8 bit, ut64 op_addr) {
	RzILOpBitVector *src = gb_il_read_reg_or_mem(reg, op_addr);
	return SEQ3(
		SETG("Z", IS_ZERO(LOGAND(src, U8(bit)))),
		SETG("N", IL_FALSE),
		SETG("H", IL_TRUE));
}

static RzILOpEffect *gb_il_set(gb_reg reg, ut8 bit, ut64 op_addr) {
	return gb_il_write_reg_or_mem(reg, LOGOR(gb_il_read_reg_or_mem(reg, op_addr), U8(bit)), op_addr);
}

static RzILOpEffect *gb_il_res(gb_reg reg, ut8 bit, ut64 op_addr) {
	return gb_il_write_reg_or_mem(reg, LOGAND(gb_il_read_reg_or_mem(reg, op_addr), U8(bit)), op_addr);
}

static RzILOpEffect *gb_il_cpl() {
	return SEQ3(
		SETG("a", LOGNOT(VARG("a"))),
		SETG("N", IL_TRUE),
		SETG("H", IL_TRUE));
}

static RzILOpEffect *gb_il_ccf() {
	return SEQ3(
		SETG("C", INV(VARG("C"))),
		SETG("N", IL_FALSE),
		SETG("H", IL_FALSE));
}

static RzILOpEffect *gb_il_ret(ut64 op_addr) {
	return SEQ3(
		SETL("r", LOADW(16, gb_il_resolve_addr_data(op_addr, VARG("sp")))),
		SETG("sp", ADD(VARG("sp"), U16(2))),
		JMP(gb_il_resolve_addr_code(op_addr, VARL("r"))));
}

static RzILOpEffect *gb_il_cond(gb_flag cond_flag, bool neg, RzILOpEffect *eff) {
	RzILOpBool *cond = VARG(gb_flag_name(cond_flag));
	if (neg) {
		return BRANCH(cond, NOP(), eff);
	}
	return BRANCH(cond, eff, NOP());
}

static RzILOpEffect *gb_il_cret(gb_flag cond_flag, bool neg, ut64 op_addr) {
	return gb_il_cond(cond_flag, neg, gb_il_ret(op_addr));
}

static RzILOpEffect *gb_il_reti(ut64 op_addr) {
	return SEQ2(
		SETG("ime", IL_TRUE),
		gb_il_ret(op_addr));
}

static RzILOpEffect *gb_il_mov_ime(bool value) {
	return SETG("ime", value ? IL_TRUE : IL_FALSE);
}

static RzILOpEffect *gb_il_push(gb_reg src, ut64 op_addr) {
	return SEQ2(
		SETG("sp", SUB(VARG("sp"), U16(2))),
		STOREW(gb_il_resolve_addr_data(op_addr, VARG("sp")), gb_il_read_reg(src)));
}

static RzILOpEffect *gb_il_pop(gb_reg dst, ut64 op_addr) {
	return SEQ2(
		gb_il_write_reg(dst, LOADW(16, gb_il_resolve_addr_data(op_addr, VARG("sp")))),
		SETG("sp", ADD(VARG("sp"), U16(2))));
}

static RzILOpEffect *gb_il_jmp(ut64 dst) {
	return JMP(gb_il_resolve_addr_code_imm(dst));
}

static RzILOpEffect *gb_il_cjmp(ut64 dst, gb_flag cond_flag, bool neg) {
	return gb_il_cond(cond_flag, neg, gb_il_jmp(dst));
}

static RzILOpEffect *gb_il_jmp_hl(ut64 op_addr) {
	return JMP(gb_il_resolve_addr_code(op_addr, gb_il_read_reg(GB_REG_HL)));
}

static RzILOpEffect *gb_il_halt() {
	// wait until interrupt
	return NOP();
}

static RzILOpEffect *gb_il_stop() {
	// similar to halt, but super low power, display off and waiting until interrupt
	return NOP();
}

static RzILOpEffect *gb_il_call(ut64 dst, ut64 op_addr, ut8 op_size) {
	return SEQ3(
		SETG("sp", SUB(VARG("sp"), U16(2))),
		STOREW(gb_il_resolve_addr_data(op_addr, VARG("sp")), U16((ut16)op_addr + op_size)),
		JMP(gb_il_resolve_addr_code_imm(dst)));
}

static RzILOpEffect *gb_il_ccall(ut64 dst, ut64 op_addr, ut8 op_size, gb_flag cond_flag, bool neg) {
	return gb_il_cond(cond_flag, neg, gb_il_call(dst, op_addr, op_size));
}

static RzILOpEffect *gb_il_scf() {
	return SEQ3(
		SETG("C", IL_TRUE),
		SETG("H", IL_FALSE),
		SETG("N", IL_FALSE));
}

static RzILOpEffect *gb_il_daa() {
	// clang-format off
	return SEQ5(
		SETL("res", LET("v0", UNSIGNED(9, VARG("a")),
			ITE(VARG("N"),
				LET("v1",
					ITE(VARG("H"),
						LOGAND(SUB(VARLP("v0"), UN(9, 0x06)), UN(9, 0xff)),
						VARLP("v0")),
					ITE(VARG("C"),
						SUB(VARLP("v1"), UN(9, 0x60)),
						VARLP("v1"))),
				LET("v1",
					ITE(OR(VARG("H"), UGT(LOGAND(VARLP("v0"), UN(9, 0xf)), UN(9, 9))),
						ADD(VARLP("v0"), UN(9, 0x06)),
						VARLP("v0")),
					ITE(OR(VARG("C"), UGT(VARLP("v1"), UN(9, 0x9f))),
						ADD(VARLP("v1"), UN(9, 0x60)),
						VARLP("v1")))))),
		SETG("a", UNSIGNED(8, VARL("res"))),
		SETG("Z", IS_ZERO(VARG("a"))),
		SETG("H", IL_FALSE),
		SETG("C", OR(VARG("C"), MSB(VARL("res")))));
	// clang-format on
}

#include <rz_il/rz_il_opbuilder_end.h>
