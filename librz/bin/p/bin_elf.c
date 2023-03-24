// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 dso <dso@rice.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bin_elf.inc"

static bool check_buffer(RzBuffer *buf) {
	return check_buffer_aux(buf) == ELFCLASS32;
}

RzBinPlugin rz_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF format plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.boffset = &boffset,
	.binsym = &binsym,
	.entries = &entries,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.sections = &sections,
	.populate_symbols = &symbols,
	.imports = &imports,
	.strings = &strings,
	.minstrlen = 4,
	.info = &info,
	.fields = &fields,
	.header = &headers,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.create = &create_elf,
	.file_type = &get_file_type,
	.regstate = &regstate,
	.section_type_to_string = &Elf_(rz_bin_elf_section_type_to_string),
	.section_flag_to_rzlist = &Elf_(rz_bin_elf_section_flag_to_rzlist),
	.destroy = destroy,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_elf,
	.version = RZ_VERSION
};
#endif
