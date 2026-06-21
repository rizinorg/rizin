// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_types.h>

// found in gdb/h8300-tdep.c

static const char *
h8300_register_name_common(const char *regnames[], ut32 numregs, ut32 regno) {
	if (regno >= numregs || regno < 0) {
		RZ_LOG_ERROR("h8300_register_name invalid register number: %d\n", regno);
		return NULL;
	}
	return regnames[regno];
}

static const char *
h8300_register_name(ut32 regno) {
	/* The register names change depending on which h8300 processor
	   type is selected.  */
	static const char *register_names[] = {
		"r0", "r1", "r2", "r3", "r4", "r5", "r6",
		"sp", "", "pc", "cycles", "tick", "inst",
		"ccr", /* pseudo register */
	};
	return h8300_register_name_common(register_names, RZ_ARRAY_SIZE(register_names),
		regno);
}

static const char *
h8300h_register_name(ut32 regno) {
	static const char *register_names[] = {
		"er0", "er1", "er2", "er3", "er4", "er5", "er6",
		"sp", "", "pc", "cycles", "tick", "inst",
		"ccr", /* pseudo register */
	};
	return h8300_register_name_common(register_names, RZ_ARRAY_SIZE(register_names),
		regno);
}
