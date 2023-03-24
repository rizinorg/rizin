// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#define RZ_BIN_ELF64 1
#include "bin_elf.inc"

static bool check_buffer(RzBuffer *buf) {
	return check_buffer_aux(buf) == ELFCLASS64;
}

static ut64 get_elf_vaddr64(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	// NOTE(aaSSfxxx): since RVA is vaddr - "official" image base, we just need to add imagebase to vaddr
	ELFOBJ *bin = bf->o->bin_obj;
	return bin->baddr - bin->boffset + vaddr;
}

RzBinPlugin rz_bin_plugin_elf64 = {
	.name = "elf64",
	.desc = "elf64 bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.check_buffer = &check_buffer,
	.load_buffer = &load_buffer,
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
	.get_vaddr = &get_elf_vaddr64,
	.file_type = &get_file_type,
	.regstate = &regstate,
	.section_type_to_string = &Elf_(rz_bin_elf_section_type_to_string),
	.section_flag_to_rzlist = &Elf_(rz_bin_elf_section_flag_to_rzlist),
	.destroy = destroy,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_elf64,
	.version = RZ_VERSION
};
#endif
