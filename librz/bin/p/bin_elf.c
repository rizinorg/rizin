// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../format/elf/elf_parser.h"

static bool check_buffer(RzBuffer *buf) {
	return elf_check_buffer_aux(buf) == ELFCLASS32;
}

static RzStructuredData *elf_info_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = (ELFOBJ *)bf->o->bin_obj;
	return elf_structure(bin);
}

RzBinPlugin rz_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF (Executable and Linkable Format)",
	.license = "LGPL3",
	.author = "nibble",
	.get_sdb = &elf_get_sdb,
	.load_buffer = &elf_load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &elf_baddr,
	.boffset = &elf_boffset,
	.binsym = &elf_binsym,
	.entries = &elf_entries,
	.virtual_files = &elf_virtual_files,
	.maps = &elf_maps,
	.sections = &elf_sections,
	.symbols = &elf_symbols,
	.imports = &elf_imports,
	.info = &elf_info,
	.bin_structure = &elf_info_structure,
	.fields = &elf_fields,
	.size = &elf_size,
	.libs = &elf_libs,
	.relocs = &elf_relocs,
	.create = &elf_create_elf,
	.file_type = &elf_get_file_type,
	.regstate = &elf_regstate,
	.section_type_to_string = &Elf_(rz_bin_elf_section_type_to_string),
	.section_flag_to_rzlist = &Elf_(rz_bin_elf_section_flag_to_rzlist),
	.destroy = elf_destroy,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_elf,
	.version = RZ_VERSION
};
#endif
