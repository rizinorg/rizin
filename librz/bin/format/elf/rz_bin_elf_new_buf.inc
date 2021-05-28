// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static HtUP *rel_cache_new(RzBinElfReloc *relocs, ut32 reloc_num) {
	if (!relocs || reloc_num == 0) {
		return NULL;
	}
	const int htsize = RZ_MIN(reloc_num, 1024);
	HtUP *rel_cache = ht_up_new_size(htsize, NULL, NULL, NULL);
	if (rel_cache) {
		size_t i;
		for (i = 0; i < reloc_num; i++) {
			RzBinElfReloc *tmp = relocs + i;
			ht_up_insert(rel_cache, tmp->sym, tmp);
		}
	}
	return rel_cache;
}

static bool rz_bin_elf_init(ELFOBJ *bin) {
	/* bin is not an ELF */
	if (!Elf_(rz_bin_elf_init_ehdr)(bin)) {
		return false;
	}
	if (!Elf_(rz_bin_elf_init_phdr)(bin) && !Elf_(rz_bin_elf_is_relocatable)(bin)) {
		bprintf("Cannot initialize program headers\n");
	}
	if (bin->ehdr.e_type == ET_CORE) {
		if (!Elf_(rz_bin_elf_init_notes)(bin)) {
			bprintf("Cannot parse PT_NOTE segments\n");
		}
	} else {
		if (!Elf_(rz_bin_elf_init_shdr)(bin)) {
			bprintf("Cannot initialize section headers\n");
		}

		if (!Elf_(rz_bin_elf_init_shstrtab)(bin)) {
			bprintf("Cannot initialize strings table\n");
		}

		if (!Elf_(rz_bin_elf_init_dynstr)(bin) && !Elf_(rz_bin_elf_is_relocatable)(bin)) {
			bprintf("Cannot initialize dynamic strings\n");
		}

		bin->baddr = Elf_(rz_bin_elf_get_baddr)(bin);

		if (!Elf_(rz_bin_elf_is_relocatable)(bin) && !Elf_(rz_bin_elf_is_static)(bin)) {
			if (!Elf_(rz_bin_elf_init_dynamic_section)(bin) || !Elf_(rz_bin_elf_init_strtab)(bin)) {
				bprintf("Cannot initialize dynamic section\n");
			}
		}
	}

	bin->boffset = Elf_(rz_bin_elf_get_boffset)(bin);

	bin->imports_by_ord_size = 0;
	bin->imports_by_ord = NULL;
	bin->symbols_by_ord_size = 0;
	bin->symbols_by_ord = NULL;

	bin->g_sections = Elf_(rz_bin_elf_get_sections)(bin);
	bin->g_relocs = Elf_(rz_bin_elf_get_relocs)(bin);

	bin->rel_cache = rel_cache_new(bin->g_relocs, bin->g_reloc_num);

	sdb_ns_set(bin->kv, "versioninfo", Elf_(rz_bin_elf_get_version_info)(bin));

	return true;
}

RZ_OWN ELFOBJ *Elf_(rz_bin_elf_new_buf)(RZ_NONNULL RzBuffer *buf, bool verbose) {
	rz_return_val_if_fail(buf, NULL);

	ELFOBJ *bin = RZ_NEW0(ELFOBJ);
	if (!bin) {
		return NULL;
	}

	bin->b = rz_buf_ref(buf);
	bin->size = rz_buf_size(buf);
	bin->kv = sdb_new0();
	bin->verbose = verbose;

	if (rz_bin_elf_init(bin)) {
		return bin;
	}

	Elf_(rz_bin_elf_free)(bin);
	return NULL;
}
