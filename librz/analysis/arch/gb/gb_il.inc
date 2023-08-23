// SPDX-FileCopyrightText: 2023 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * GameBoy lifting to be included from analysis_gb.c and plugged directly into the decoding logic.
 */

//-----------------
// TODO: remove this include block, it is only to give clangd some context
#ifndef RZ_TYPES_H
#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_reg.h>
#define GB_DIS_LEN_ONLY
#include "../../asm/arch/gb/gbdis.c"
#include "gb_makros.h"
#include "meta_gb_cmt.c"
#endif
//----------------

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * Resolve the given 16-bit \p target_addr16 to the memory space that Rizin uses.
 *
 * Because Gameboy uses bank switching, where one part of memory may be switched to
 * different rom parts at runtime, but we still want to be able to see the entire code
 * all the time, Rizin flattens out the ROM over a 32-bit space.
 *
 * TODO: polish these docs
 */

static RzILOpBitVector *gb_il_resolve_addr_data(ut64 op_addr, RzILOpBitVector *target_addr16) {
	(void)op_addr;
	return target_addr16;
}

static RzILOpBitVector *gb_il_resolve_addr_code(ut64 op_addr, RzILOpBitVector *target_addr16) {
	return APPEND(U16((op_addr >> 16) & 0xffff), target_addr16);
}

/*
 * Calculate the carry of a \p carry_bits addition of \p a, \p b and optinally C, where \p a, \p b are of size \p src_bits
 * Example:
 *   gb_il_carry(a, b, 16, 8)
 * calculates:
 *   (a & 0xff) + (b & 0xff) > 0xff
 */
static RzILOpBool *gb_il_carry(RzILOpBitVector *a, RzILOpBitVector *b, bool carry_in, ut32 src_bits, ut32 carry_bits) {
	if (carry_bits >= src_bits) {
		src_bits = carry_bits + 1;
		a = UNSIGNED(carry_bits + 1, a);
		b = UNSIGNED(carry_bits + 1, b);
		if (carry_in) {
			b = ADD(b, ITE(VARG("C"), UN(carry_bits + 1, 1), UN(carry_bits + 1, 0)));
		}
		return MSB(ADD(a, b));
	}
	ut64 mask = rz_num_bitmask(carry_bits);
	a = LOGAND(a, UN(src_bits, mask));
	b = LOGAND(b, UN(src_bits, mask));
	if (carry_in) {
		b = ADD(b, ITE(VARG("C"), UN(src_bits, 1), UN(src_bits, 0)));
	}
	return UGT(ADD(a, b), UN(src_bits, mask));
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
		// TODO: assign a and flags
		rz_warn_if_reached();
		return NULL;
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

static RzILOpBitVector *gb_il_read_reg(gb_reg reg) {
	if (gb_reg_bits(reg) == 8 || reg == GB_REG_SP) {
		return VARG(gb_reg_name(reg));
	}
	switch (reg) {
	case GB_REG_AF:
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
		SETG("H", gb_il_carry(VARG("sp"), U16((ut8)imm), false, 16, 4)),
		SETG("C", gb_il_carry(VARG("sp"), U16((ut8)imm), false, 16, 8)));
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
		SETG("H", IS_ZERO(UNSIGNED(4, VARL("v")))));
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

static RzILOpEffect *gb_il_add(gb_reg dst_reg, gb_reg src_reg, bool carry_in) {
	RzILOpBitVector *dst = gb_il_read_reg(dst_reg);
	RzILOpBitVector *src = gb_il_read_reg(src_reg);
	return SEQ5(
		SETG("H", gb_il_carry(dst, src, carry_in, 8, 4)),
		SETG("C", gb_il_carry(DUP(dst), DUP(src), carry_in, 8, 8)),
		gb_il_write_reg(dst_reg, ADD(DUP(dst), carry_in ? ADD(DUP(src), ITE(VARG("C"), U8(1), U8(0))) : DUP(src))),
		SETG("Z", IS_ZERO(DUP(dst))),
		SETG("N", IL_FALSE));
}

#include <rz_il/rz_il_opbuilder_end.h>
