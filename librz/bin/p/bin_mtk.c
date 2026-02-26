// SPDX-FileCopyrightText: 2025 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

#include "../format/mtk/mtk.h"

RzBinPlugin rz_bin_plugin_mtk = {
	.name = "mtk",
	.desc = "MediaTek GFH firmware image (md1rom)",
	.license = "LGPL3",
	.author = "godcodehunter",
	.check_buffer = &mtk_check_buffer,
	.load_buffer = &mtk_load_buffer,
	.destroy = &mtk_destroy,
	.baddr = &mtk_baddr,
	.entries = &mtk_entries,
	.sections = &mtk_sections,
	.maps = &rz_bin_maps_of_file_sections,
	.info = &mtk_info,
	.bin_structure = &mtk_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mtk,
	.version = RZ_VERSION
};
#endif
