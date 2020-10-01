/* radare - LGPL - Copyright 2009-2015 - pancake */

#include <rz_bp.h>
#include <rz_lib.h>

static struct rz_bp_arch_t rz_bp_plugin_x86_bps[] = {
	{ 0, 1, 0, (const ut8*)"\xcc" }, // valid for 16, 32, 64
	{ 0, 2, 0, (const ut8*)"\xcd\x03" },
	{ 0, 0, 0, NULL },
};

struct rz_bp_plugin_t rz_bp_plugin_x86 = {
	.name = "x86",
	.arch = "x86",
	.nbps = 2,
	.bps = rz_bp_plugin_x86_bps,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &rz_bp_plugin_x86,
	.version = R2_VERSION
};
#endif
