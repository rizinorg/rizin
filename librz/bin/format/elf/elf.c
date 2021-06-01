// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <rz_types.h>
#include <rz_util.h>
#include "elf.h"

// Contain deprecated function
#include "rz_bin_elf_get_p2v_new.inc"
#include "rz_bin_elf_get_v2p_new.inc"
#include "rz_bin_elf_deprecated.inc"

// RZ_IPI
#include "rz_bin_elf_get_import_addr.inc"
#include "rz_bin_elf_get_number_of_dynamic_symbols.inc"
#include "rz_bin_elf_get_prstatus.inc"
#include "rz_bin_elf_get_prstatus_layout.inc"
#include "rz_bin_elf_get_symbols_with_type.inc"
#include "rz_bin_elf_get_symbols_with_type_from_phdr.inc"
#include "rz_bin_elf_get_ver_flags.inc"
#include "rz_bin_elf_get_verdaux_entry.inc"
#include "rz_bin_elf_get_verdef_entry.inc"
#include "rz_bin_elf_get_vernaux_entry.inc"
#include "rz_bin_elf_get_verneed_entry.inc"
#include "rz_bin_elf_get_version_info.inc"
#include "rz_bin_elf_get_version_info_gnu_verdef.inc"
#include "rz_bin_elf_get_version_info_gnu_verneed.inc"
#include "rz_bin_elf_get_version_info_gnu_versym.inc"
#include "rz_bin_elf_init_dynamic_section.inc"
#include "rz_bin_elf_init_dynstr.inc"
#include "rz_bin_elf_init_ehdr.inc"
#include "rz_bin_elf_init_notes.inc"
#include "rz_bin_elf_init_phdr.inc"
#include "rz_bin_elf_init_shdr.inc"
#include "rz_bin_elf_init_shstrtab.inc"
#include "rz_bin_elf_init_strtab.inc"
#include "rz_bin_elf_is_sh_index_valid.inc"
#include "rz_bin_elf_set_import_by_ord.inc"
#include "rz_bin_elf_symbol_type_to_str.inc"

// RZ_API
#include "rz_bin_elf_compiler.inc"
#include "rz_bin_elf_convert_import.inc"
#include "rz_bin_elf_convert_symbol.inc"
#include "rz_bin_elf_free.inc"
#include "rz_bin_elf_get_abi.inc"
#include "rz_bin_elf_get_arch.inc"
#include "rz_bin_elf_get_baddr.inc"
#include "rz_bin_elf_get_bits.inc"
#include "rz_bin_elf_get_boffset.inc"
#include "rz_bin_elf_get_cpu.inc"
#include "rz_bin_elf_get_data_encoding.inc"
#include "rz_bin_elf_get_elf_class.inc"
#include "rz_bin_elf_get_entry_offset.inc"
#include "rz_bin_elf_get_fields.inc"
#include "rz_bin_elf_get_file_type.inc"
#include "rz_bin_elf_get_fini_offset.inc"
#include "rz_bin_elf_get_head_flag.inc"
#include "rz_bin_elf_get_init_offset.inc"
#include "rz_bin_elf_get_libs.inc"
#include "rz_bin_elf_get_machine_name.inc"
#include "rz_bin_elf_get_main_offset.inc"
#include "rz_bin_elf_get_osabi_name.inc"
#include "rz_bin_elf_get_relocs.inc"
#include "rz_bin_elf_get_rpath.inc"
#include "rz_bin_elf_get_section.inc"
#include "rz_bin_elf_get_section_addr.inc"
#include "rz_bin_elf_get_section_addr_end.inc"
#include "rz_bin_elf_get_section_offset.inc"
#include "rz_bin_elf_get_sections.inc"
#include "rz_bin_elf_get_sp_val.inc"
#include "rz_bin_elf_get_stripped.inc"
#include "rz_bin_elf_grab_regstate.inc"
#include "rz_bin_elf_has_nx.inc"
#include "rz_bin_elf_has_relro.inc"
#include "rz_bin_elf_has_va.inc"
#include "rz_bin_elf_intrp.inc"
#include "rz_bin_elf_is_big_endian.inc"
#include "rz_bin_elf_is_executable.inc"
#include "rz_bin_elf_is_relocatable.inc"
#include "rz_bin_elf_is_static.inc"
#include "rz_bin_elf_new_buf.inc"
#include "section_flag_to_rzlist.inc"
#include "section_type_to_string.inc"

#define MAX_REL_RELA_SZ (sizeof(Elf_(Rel)) > sizeof(Elf_(Rela)) ? sizeof(Elf_(Rel)) : sizeof(Elf_(Rela)))

RzBinElfSymbol *Elf_(rz_bin_elf_get_symbols)(ELFOBJ *bin) {
	if (!bin->g_symbols) {
		bin->g_symbols = Elf_(rz_bin_elf_get_symbols_with_type)(bin, RZ_BIN_ELF_ALL_SYMBOLS);
	}
	return bin->g_symbols;
}

RzBinElfSymbol *Elf_(rz_bin_elf_get_imports)(ELFOBJ *bin) {
	if (!bin->g_imports) {
		bin->g_imports = Elf_(rz_bin_elf_get_symbols_with_type)(bin, RZ_BIN_ELF_IMPORT_SYMBOLS);
	}
	return bin->g_imports;
}
