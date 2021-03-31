// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

static bool load(RzBin *bin) {
	if (!bin || !bin->cur) {
		return false;
	}
	if (!bin->file) {
		bin->file = bin->cur->file;
	}
	return bin->cur->xtr_obj ? true : false;
}

RzBinLdrPlugin rz_bin_ldr_plugin_ldr_linux = {
	.name = "ldr.linux",
	.desc = "Linux loader plugin for RzBin",
	.license = "MIT",
	.load = &load,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN_LDR,
	.data = &rz_bin_ldr_plugin_ldr_linux,
	.version = RZ_VERSION
};
#endif
