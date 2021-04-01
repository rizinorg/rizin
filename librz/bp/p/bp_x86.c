// SPDX-FileCopyrightText: 2009-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>
#include <rz_lib.h>

static struct rz_bp_arch_t rz_bp_plugin_x86_bps[] = {
	{ 0, 1, 0, (const ut8 *)"\xcc" }, // valid for 16, 32, 64
	{ 0, 2, 0, (const ut8 *)"\xcd\x03" },
	{ 0, 0, 0, NULL },
};

struct rz_bp_plugin_t rz_bp_plugin_x86 = {
	.name = "x86",
	.arch = "x86",
	.nbps = 2,
	.bps = rz_bp_plugin_x86_bps,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BP,
	.data = &rz_bp_plugin_x86,
	.version = RZ_VERSION
};
#endif
