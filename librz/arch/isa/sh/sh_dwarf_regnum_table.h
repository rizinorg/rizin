// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Found in the linux kernel perf tools.
 * latest/source/tools/perf/arch/sh/include/dwarf-regs-table.h
 */
static const char *map_dwarf_reg_to_sh_reg(ut32 reg_num) {
	switch (reg_num) {
	// General Register
	case 0: return "r0";
	case 1: return "r1";
	case 2: return "r2";
	case 3: return "r3";
	case 4: return "r4";
	case 5: return "r5";
	case 6: return "r6";
	case 7: return "r7";
	case 8: return "r8";
	case 9: return "r9";
	case 10: return "r10";
	case 11: return "r11";
	case 12: return "r12";
	case 13: return "r13";
	case 14: return "r14";
	case 15: return "r15";
	case 16: return "pc";
	case 17: return "pr";
	default:
		rz_warn_if_reached();
		return "unsupported_reg";
	}
}
