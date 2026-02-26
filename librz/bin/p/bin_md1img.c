// SPDX-FileCopyrightText: 2025 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

#include "../format/mtk/md1img.h"

RzBinPlugin rz_bin_plugin_md1img = {
	.name = "md1img",
	.desc = "MediaTek md1img firmware container",
	.license = "LGPL3",
	.author = "godcodehunter",
	.check_buffer = &md1img_check_buffer,
	.load_buffer = &md1img_load_buffer,
	.destroy = &md1img_destroy,
	.baddr = &md1img_baddr,
	.entries = &md1img_entries,
	.virtual_files = &md1img_virtual_files,
	.maps = &md1img_maps,
	.sections = &md1img_sections,
	.symbols = &md1img_symbols,
	.strings = &md1img_strings,
	.info = &md1img_info,
	.bin_structure = &md1img_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_md1img,
	.version = RZ_VERSION
};
#endif
