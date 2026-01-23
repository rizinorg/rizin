// SPDX-FileCopyrightText: 2025 Zapper9982
// SPDX-License-Identifier: LGPL-3.0-only

#include "../format/gns1/gns1.h"

RzBinPlugin rz_bin_plugin_gns1 = {
	.name = "gns1",
	.desc = "Apple C4000 baseband firmware (GNS1.bin)",
	.license = "LGPL3",
	.author = "Zapper9982",
	.check_buffer = &gns1_check_buffer,
	.load_buffer = &gns1_load_buffer,
	.destroy = &gns1_destroy,
	.baddr = &gns1_baddr,
	.entries = &gns1_entries,
	.sections = &gns1_sections,
	.maps = &rz_bin_maps_of_file_sections,
	.info = &gns1_info,
	.bin_structure = &gns1_structure,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_gns1,
	.version = RZ_VERSION
};
#endif
