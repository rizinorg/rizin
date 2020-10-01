/* rizin - LGPL - Copyright 2010-2015 - pancake */

#include <rz_bp.h>
#include <rz_lib.h>

static struct rz_bp_arch_t rz_bp_plugin_mips_bps[] = {
	{ 32, 4, 0, (const ut8*)"\x0d\x00\x00\x00" },
	{ 32, 4, 1, (const ut8*)"\x00\x00\x00\x0d" },
	{ 64, 4, 0, (const ut8*)"\x0d\x00\x00\x00" },
	{ 64, 4, 1, (const ut8*)"\x00\x00\x00\x0d" },
	{ 0, 0, 0, NULL }
};

struct rz_bp_plugin_t rz_bp_plugin_mips = {
	.name = "mips",
	.arch = "mips",
	.nbps = 10,
	.bps = rz_bp_plugin_mips_bps,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &rz_bp_plugin_mips,
	.version = R2_VERSION
};
#endif
