// SPDX-FileCopyrightText: 2009-2015 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>
#include <rz_lib.h>

static struct rz_bp_arch_t rz_bp_plugin_sh_bps[] = {
	{ 32, 2, 0, (const ut8 *)"\x20\xc3" }, //Little endian bp
	{ 32, 2, 1, (const ut8 *)"\xc3\x20" }, //Big endian bp
	{ 0, 0, 0, NULL },
};

struct rz_bp_plugin_t rz_bp_plugin_sh = {
	.name = "sh",
	.arch = "sh",
	.nbps = 2,
	.bps = rz_bp_plugin_sh_bps,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BP,
	.data = &rz_bp_plugin_sh,
	.version = RZ_VERSION
};
#endif
