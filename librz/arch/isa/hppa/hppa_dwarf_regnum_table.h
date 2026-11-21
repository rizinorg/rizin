// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef HPPA_DWARF_REGNUM_TABLE_H
#define HPPA_DWARF_REGNUM_TABLE_H

#include <rz_types_base.h>

/**
 * \brief Map a PA-RISC DWARF register number to the register name.
 *
 * GCC numbers the general registers as themselves and fr4 to fr31 from 72
 * on, each followed by its right half. Call frame information numbers the
 * floating point registers differently.
 *
 * \param left Names of fr4 to fr31, the left halves in 32-bit code
 */
static const char *hppa_dwarf_reg(ut32 reg_num, const char *const left[28]) {
	static const char *const gr[] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
		"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		"r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
		"r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"
	};
	static const char *const right[] = {
		"fr4R", "fr5R", "fr6R", "fr7R", "fr8R", "fr9R", "fr10R",
		"fr11R", "fr12R", "fr13R", "fr14R", "fr15R", "fr16R", "fr17R",
		"fr18R", "fr19R", "fr20R", "fr21R", "fr22R", "fr23R", "fr24R",
		"fr25R", "fr26R", "fr27R", "fr28R", "fr29R", "fr30R", "fr31R"
	};
	if (reg_num < RZ_ARRAY_SIZE(gr)) {
		return gr[reg_num];
	}
	if (reg_num >= 72 && reg_num - 72 < 2 * RZ_ARRAY_SIZE(right)) {
		ut32 i = (reg_num - 72) / 2;
		return reg_num & 1 ? right[i] : left[i];
	}
	rz_warn_if_reached();
	return "unsupported_reg";
}

static const char *map_dwarf_reg_to_hppa_reg(ut32 reg_num) {
	static const char *const left[] = {
		"fr4L", "fr5L", "fr6L", "fr7L", "fr8L", "fr9L", "fr10L",
		"fr11L", "fr12L", "fr13L", "fr14L", "fr15L", "fr16L", "fr17L",
		"fr18L", "fr19L", "fr20L", "fr21L", "fr22L", "fr23L", "fr24L",
		"fr25L", "fr26L", "fr27L", "fr28L", "fr29L", "fr30L", "fr31L"
	};
	return hppa_dwarf_reg(reg_num, left);
}

static const char *map_dwarf_reg_to_hppa64_reg(ut32 reg_num) {
	static const char *const whole[] = {
		"fr4", "fr5", "fr6", "fr7", "fr8", "fr9", "fr10",
		"fr11", "fr12", "fr13", "fr14", "fr15", "fr16", "fr17",
		"fr18", "fr19", "fr20", "fr21", "fr22", "fr23", "fr24",
		"fr25", "fr26", "fr27", "fr28", "fr29", "fr30", "fr31"
	};
	return hppa_dwarf_reg(reg_num, whole);
}

#endif // HPPA_DWARF_REGNUM_TABLE_H
