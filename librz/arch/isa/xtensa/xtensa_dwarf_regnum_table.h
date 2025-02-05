// SPDX-FileCopyrightText: 2025 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef XTENSA_DWARF_REGNUM_TABLE_H
#define XTENSA_DWARF_REGNUM_TABLE_H

static const char *
xtensa_register_name(ut32 index) {
	static const char *const reg_names[] = {
		"a0", "sp", "a2", "a3", "a4", "a5", "a6", "a7",
		"a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15",
		"fp", "argp", "b0",
		"f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
		"f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",
		"acc"
	};
	if (index >= RZ_ARRAY_SIZE(reg_names)) {
		return NULL;
	}
	return reg_names[index];
}

#endif // XTENSA_DWARF_REGNUM_TABLE_H
