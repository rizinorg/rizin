// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2019 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../format/elf/elf64_parser.h"

static bool check_buffer(RzBuffer *buf) {
	return elf64_check_buffer_aux(buf) == ELFCLASS64;
}

static ut64 get_elf_vaddr64(RzBinFile *bf, ut64 baddr, ut64 paddr, ut64 vaddr) {
	// NOTE(aaSSfxxx): since RVA is vaddr - "official" image base, we just need to add imagebase to vaddr
	ELFOBJ *bin = bf->o->bin_obj;
	return bin->baddr - bin->boffset + vaddr;
}

static RzStructuredData *elf64_info_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	ELFOBJ *bin = (ELFOBJ *)bf->o->bin_obj;
	return elf64_structure(bin);
}

RzBinPlugin rz_bin_plugin_elf64 = {
	.name = "elf64",
	.desc = "ELF64 (64-bit Executable and Linkable Format)",
	.license = "LGPL3",
	.author = "nibble",
	.get_sdb = &elf64_get_sdb,
	.check_buffer = &check_buffer,
	.load_buffer = &elf64_load_buffer,
	.baddr = &elf64_baddr,
	.boffset = &elf64_boffset,
	.binsym = &elf64_binsym,
	.entries = &elf64_entries,
	.virtual_files = &elf64_virtual_files,
	.maps = &elf64_maps,
	.sections = &elf64_sections,
	.symbols = &elf64_symbols,
	.imports = &elf64_imports,
	.info = &elf64_info,
	.bin_structure = &elf64_info_structure,
	.fields = &elf64_fields,
	.size = &elf64_size,
	.libs = &elf64_libs,
	.relocs = &elf64_relocs,
	.create = &elf64_create_elf,
	.get_vaddr = &get_elf_vaddr64,
	.file_type = &elf64_get_file_type,
	.regstate = &elf64_regstate,
	.section_type_to_string = &Elf_(rz_bin_elf_section_type_to_string),
	.section_flag_to_rzlist = &Elf_(rz_bin_elf_section_flag_to_rzlist),
	.destroy = elf64_destroy,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_elf64,
	.version = RZ_VERSION
};
#endif
