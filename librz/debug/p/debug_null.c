/* radare - LGPL - Copyright 2016-2017 pancake */

#include <rz_io.h>
#include <rz_debug.h>

RzDebugPlugin rz_debug_plugin_null = {
	.name = "null",
	.license = "MIT",
	.arch = "any",
	.bits = RZ_SYS_BITS_32 | RZ_SYS_BITS_64,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = RZ_LIB_TYPE_DBG,
	.data = &rz_debug_plugin_null,
	.version = RZ_VERSION
};
#endif
