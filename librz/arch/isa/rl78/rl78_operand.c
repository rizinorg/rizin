// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rl78_operand.h"

#include <rz_types.h>
#include <rz_core.h>
#include <rz_util.h>

static const char *RL78_STRINGS_SYMBOLS[] = {
	[RL78_GPR_X] = "x",
	[RL78_GPR_A] = "a",
	[RL78_GPR_C] = "c",
	[RL78_GPR_B] = "b",
	[RL78_GPR_E] = "e",
	[RL78_GPR_D] = "d",
	[RL78_GPR_L] = "l",
	[RL78_GPR_H] = "h",
	[RL78_GPR_AX] = "ax",
	[RL78_GPR_BC] = "bc",
	[RL78_GPR_DE] = "de",
	[RL78_GPR_HL] = "hl",
	[RL78_SFR_MEM] = "mem",
	[RL78_SFR_PMC] = "pmc",
	[RL78_SFR_ES] = "es",
	[RL78_SFR_CS] = "cs",
	[RL78_SFR_PSW] = "psw",
	[RL78_SFR_SPH] = "sph",
	[RL78_SFR_SPL] = "spl",
	[RL78_CR_PC] = "pc",
	[RL78_CR_PSW] = "psw",
	[RL78_CR_SP] = "sp",
	[RL78_RB_RB0] = "rb0",
	[RL78_RB_RB1] = "rb1",
	[RL78_RB_RB2] = "rb2",
	[RL78_RB_RB3] = "rb3",
	[RL78_PSW_CY] = "cy",
	[RL78_PSW_AC] = "ac",
	[RL78_PSW_Z] = "z",
};

bool rl78_operand_to_string(RzStrBuf RZ_OUT *dst, const RL78Operand RZ_BORROW *operand) {
	if (operand->type <= RL78_OP_TYPE_NONE ||
		operand->type >= _RL78_OP_TYPE_COUNT) {
		return false;
	}

	RzStrBuf strbuf;
	switch (operand->type) {
	case RL78_OP_TYPE_IMMEDIATE_8:
	case RL78_OP_TYPE_IMMEDIATE_16:
		rz_strf(strbuf.buf, "#0x%" PFMT32x, operand->v0);
		break;
	case RL78_OP_TYPE_SYMBOL:
		rz_return_val_if_fail(rl78_symbol_valid(operand->v0), false);

		rz_strf(strbuf.buf, "%s", RL78_STRINGS_SYMBOLS[operand->v0]);
		break;
	case RL78_OP_TYPE_SFR:
	case RL78_OP_TYPE_SADDR:
		if (rl78_symbol_valid(operand->v0)) {
			rz_strf(strbuf.buf, "%s", RL78_STRINGS_SYMBOLS[operand->v0]);
		} else {
			rz_strf(strbuf.buf, "0x%" PFMT32x, operand->v0);
		}
		break;
	case RL78_OP_TYPE_ABSOLUTE_ADDR_16:
		if (rl78_symbol_valid(operand->v0)) {
			rz_strf(strbuf.buf, "%s", RL78_STRINGS_SYMBOLS[operand->v0]);
		} else {
			rz_strf(strbuf.buf, "!0x%" PFMT32x, operand->v0);
		}
		break;
	case RL78_OP_TYPE_DECIMAL:
		rz_strf(strbuf.buf, "%d", operand->v0);
		break;
	case RL78_OP_TYPE_ABSOLUTE_ADDR_20:
		if (rl78_symbol_valid(operand->v0)) {
			rz_strf(strbuf.buf, "%s", RL78_STRINGS_SYMBOLS[operand->v0]);
		} else {
			rz_strf(strbuf.buf, "!!0x%" PFMT32x, operand->v0);
		}
		break;
	case RL78_OP_TYPE_RELATIVE_ADDR_8:
		rz_strf(strbuf.buf, "$0x%" PFMT32x, operand->v0);
		break;
	case RL78_OP_TYPE_RELATIVE_ADDR_16:
		rz_strf(strbuf.buf, "$!0x%" PFMT32x, operand->v0);
		break;
	case RL78_OP_TYPE_INDIRECT_ADDR:
		if (rl78_symbol_valid(operand->v0)) {
			rz_strf(strbuf.buf, "[%s]", RL78_STRINGS_SYMBOLS[operand->v0]);
		} else {
			rz_strf(strbuf.buf, "[0x%" PFMT32x "]", operand->v0);
		}

		break;
	case RL78_OP_TYPE_BASED_ADDR_8:
		rz_return_val_if_fail(rl78_symbol_valid(operand->v0), false);

		rz_strf(strbuf.buf, "[%s+0x%" PFMT32x "]",
			RL78_STRINGS_SYMBOLS[operand->v0], operand->v1);
		break;
	case RL78_OP_TYPE_BASED_ADDR_16:
		rz_return_val_if_fail(rl78_symbol_valid(operand->v0), false);

		rz_strf(strbuf.buf, "0x%" PFMT32x "[%s]",
			operand->v1, RL78_STRINGS_SYMBOLS[operand->v0]);
		break;
	case RL78_OP_TYPE_BASED_INDEX_ADDR:
		rz_return_val_if_fail(rl78_symbol_valid(operand->v0) &&
				rl78_symbol_valid(operand->v1),
			false);

		rz_strf(strbuf.buf, "[%s+%s]",
			RL78_STRINGS_SYMBOLS[operand->v0],
			RL78_STRINGS_SYMBOLS[operand->v1]);
		break;
	default:
		rz_warn_if_reached();
	}

	// prefix (extension addressing) and suffix (bit index)
	const char *prefix = operand->flags & RL78_OP_FLAG_ES ? "es:" : "";
	if (operand->flags & RL78_OP_FLAG_BA) {
		rz_strf(dst->buf, "%s%s.%d", prefix, strbuf.buf, operand->v1);
	} else {
		rz_strf(dst->buf, "%s%s", prefix, strbuf.buf);
	}

	return true;
}

bool rl78_symbol_valid(int symbol) {
	return symbol >= 0 && symbol < _RL78_SYMBOL_COUNT;
}
