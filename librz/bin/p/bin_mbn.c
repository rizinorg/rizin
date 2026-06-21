// SPDX-FileCopyrightText: 2015-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../format/mbn/mbn.h"

RzBinPlugin rz_bin_plugin_mbn = {
	.name = "mbn",
	.desc = "MBN/SBL bootloader binary",
	.license = "LGPL3",
	.author = "pancake",
	.load_buffer = &mbn_load_buffer,
	.destroy = &mbn_destroy,
	.bin_structure = &mbn_structure_bin,
	.size = &mbn_size,
	.check_buffer = &mbn_check_buffer,
	.baddr = &mbn_baddr,
	.entries = &mbn_entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &mbn_sections,
	.strings = &mbn_strings,
	.info = &mbn_info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mbn,
	.version = RZ_VERSION
};
#endif
