// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "../format/mdt/mdt.h"

static RzBinInfo *mdt_info(RzBinFile *bf) {
	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}
	RzBinMdtObj *mdt = bf->o->bin_obj;
	ret->lang = "";
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("mdt");
	ret->has_pi = 0;
	ret->has_canary = 0;
	ret->has_retguard = -1;
	ret->big_endian = Elf_(rz_bin_elf_is_big_endian)(mdt->header);
	ret->has_va = Elf_(rz_bin_elf_has_va)(mdt->header);
	ret->has_nx = Elf_(rz_bin_elf_has_nx)(mdt->header);
	ret->intrp = Elf_(rz_bin_elf_get_intrp)(mdt->header);
	ret->compiler = Elf_(rz_bin_elf_get_compiler)(mdt->header);
	ret->dbg_info = 0;
	ret->bits = 32;
	ret->arch = Elf32_rz_bin_elf_get_arch(mdt->header);
	ret->cpu = Elf32_rz_bin_elf_get_cpu(mdt->header);
	ret->machine = Elf32_rz_bin_elf_get_machine_name(mdt->header);
	return ret;
}

RzBinPlugin rz_bin_plugin_mdt = {
	.name = "mdt",
	.desc = "Qualcomm Peripheral Image Loader (32bit only)",
	.author = "Rot127",
	.license = "LGPL3",
	.check_filename = &rz_bin_mdt_check_filename,
	.load_buffer = &rz_bin_mdt_load_buffer,
	.info = &mdt_info,
	.bin_structure = &rz_bin_mdt_structure,
	.maps = &rz_bin_mdt_get_maps,
	.entries = &rz_bin_mdt_get_entry_points,
	.check_buffer = &rz_bin_mdt_check_buffer,
	.virtual_files = &rz_bin_mdt_virtual_files,
	.destroy = &rz_bin_mdt_destroy,
	.hashes = NULL,
	.sections = &rz_bin_mdt_sections,
	.symbols = &rz_bin_mdt_symbols,
	.imports = NULL,
	.libs = NULL,
	.relocs = rz_bin_mdt_relocs,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mdt,
	.version = RZ_VERSION
};
#endif
