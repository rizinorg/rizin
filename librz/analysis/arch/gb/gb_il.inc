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
 * \p val must be of size gb_reg_bits(dst)
 */
static RzILOpEffect *gb_il_assign_reg(gb_reg dst, RzILOpBitVector *val) {
	gb_reg h, l;
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
		SETG(gb_reg_name(h), UNSIGNED(8, SHIFTR0(val, UN(4, 8)))),
		SETG(gb_reg_name(l), UNSIGNED(8, DUP(val))));
}

static RzILOpEffect *gb_il_mov_imm(gb_reg dst, ut16 imm) {
	if (gb_reg_bits(dst) == 8) {
		return gb_il_assign_reg(dst, U8(imm & 0xff));
	}
	// do not use gb_il_assign_reg for 16-bit to avoid unnecessary 16-bit casting of the constant value
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

#include <rz_il/rz_il_opbuilder_end.h>
