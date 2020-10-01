/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <rz_bp.h>
#include <rz_lib.h>

static struct rz_bp_arch_t rz_bp_plugin_bf_bps[] = {
	{ 0, 1, 0, (const ut8*)"\xff" },
	{ 0, 1, 0, (const ut8*)"\x00" },
	{ 0, 0, 0, NULL },
};

struct rz_bp_plugin_t rz_bp_plugin_bf = {
	.name = "bf",
	.arch = "bf",
	.nbps = 2,
	.bps = rz_bp_plugin_bf_bps,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BP,
	.data = &rz_bp_plugin_bf,
	.version = R2_VERSION
};
#endif
