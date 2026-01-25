#include <rz_bin.h>
#include <rz_lib.h>
#include "../format/luaJIT/luaJIT.h"


RzBinPlugin rz_bin_plugin_luaJIT = {
    .name = "luaJIT",
	.desc = "LuaJIT compiled binary",
	.license = "LGPL3",
    .author = "Arya H R",
    .check_buffer = luaJIT_check_buffer,
    .load_buffer = luaJIT_load_buffer,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_luaJIT,
	.version = RZ_VERSION
};
#endif