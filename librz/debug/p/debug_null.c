/* radare - LGPL - Copyright 2016-2017 pancake */

#include <rz_io.h>
#include <rz_debug.h>

RzDebugPlugin rz_debug_plugin_null = {
	.name = "null",
	.license = "MIT",
	.arch = "any",
	.bits = R_SYS_BITS_32 | R_SYS_BITS_64,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_null,
	.version = R2_VERSION
};
#endif
