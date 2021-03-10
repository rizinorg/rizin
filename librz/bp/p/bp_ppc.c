// SPDX-FileCopyrightText: 2010 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bp.h>
#include <rz_lib.h>

static struct rz_bp_arch_t rz_bp_plugin_ppc_bps[] = {
	/* XXX: FIX those are not really breakpoint opcodes at all */
	{ 32, 4, 0, (const ut8 *)"\x00\x00\x00\x0d" }, // little endian
	{ 32, 4, 1, (const ut8 *)"\x0d\x00\x00\x00" }, // big endian
	{ 0, 0, 0, NULL }
};

struct rz_bp_plugin_t rz_bp_plugin_ppc = {
	.name = "ppc",
	.arch = "ppc",
	.nbps = 2,
	.bps = rz_bp_plugin_ppc_bps,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BP,
	.data = &rz_bp_plugin_ppc,
	.version = RZ_VERSION
};
#endif
