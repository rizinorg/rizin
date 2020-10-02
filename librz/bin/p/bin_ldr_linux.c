/* radare - LGPL - Copyright 2018 pancake */

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

static bool load(RBin *bin) {
	if (!bin || !bin->cur) {
	    return false;
	}
	if (!bin->file) {
	   	bin->file = bin->cur->file;
	}
	return bin->cur->xtr_obj? true : false;
}


RBinLdrPlugin rz_bin_ldr_plugin_ldr_linux = {
	.name = "ldr.linux",
	.desc = "Linux loader plugin for RBin",
	.license = "MIT",
	.load = &load,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN_LDR,
	.data = &rz_bin_ldr_plugin_ldr_linux,
	.version = RZ_VERSION
};
#endif
