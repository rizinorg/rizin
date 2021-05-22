// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void create_section_from_phdr(ELFOBJ *bin, RzBinElfSection *section, size_t *pos, const char *name, ut64 addr, ut64 sz) {
	if (!addr || addr == RZ_BIN_ELF_ADDR_MAX) {
		return;
	}

	(*pos)++;
	section->offset = Elf_(rz_bin_elf_v2p_new)(bin, addr);
	section->rva = addr;
	section->size = sz;
	rz_str_ncpy(section->name, name, ELF_STRING_LENGTH);
	section->last = 0;
}

static const char *get_plt_name(ELFOBJ *bin) {
	if (bin->dyn_info.dt_pltrel == DT_REL) {
		return ".rel.plt";
	}

	return ".rela.plt";
}

static void create_section_plt(ELFOBJ *bin, RzBinElfSection *section, size_t *pos) {
	const char *plt_name = get_plt_name(bin);
	create_section_from_phdr(bin, section, pos, plt_name, bin->dyn_info.dt_jmprel, bin->dyn_info.dt_pltrelsz);
}

static RzBinElfSection *get_sections_from_dt_dynamic(ELFOBJ *bin) {
	size_t pos = 0;

	RzBinElfSection *ret = RZ_NEWS(RzBinElfSection, 5);
	if (!ret) {
		return NULL;
	}

	// There is no info about the got size
	create_section_from_phdr(bin, ret + pos, &pos, ".got.plt", bin->dyn_info.dt_pltgot, 0);
	create_section_from_phdr(bin, ret + pos, &pos, ".rel.dyn", bin->dyn_info.dt_rel, bin->dyn_info.dt_relsz);
	create_section_from_phdr(bin, ret + pos, &pos, ".rela.dyn", bin->dyn_info.dt_rela, bin->dyn_info.dt_relasz);
	create_section_plt(bin, ret + pos, &pos);

	ret[pos].last = 1;

	return ret;
}

static void set_rz_bin_elf_section_basic_from_shdr(ELFOBJ *bin, RzBinElfSection *section, size_t section_id) {
	section->offset = bin->shdr[section_id].sh_offset;
	section->size = bin->shdr[section_id].sh_size;
	section->align = bin->shdr[section_id].sh_addralign;
	section->flags = bin->shdr[section_id].sh_flags;
	section->link = bin->shdr[section_id].sh_link;
	section->info = bin->shdr[section_id].sh_info;
	section->type = bin->shdr[section_id].sh_type;
}

static void set_rz_bin_elf_section_rva_from_shdr(ELFOBJ *bin, RzBinElfSection *section, size_t section_id) {
	if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
		section->rva = bin->baddr + bin->shdr[section_id].sh_offset;
	} else {
		section->rva = bin->shdr[section_id].sh_addr;
	}
}

static bool is_invalid_strtab_section(ELFOBJ *bin, Elf_(Word) sh_name) {
	return !bin->shstrtab_section || !bin->shstrtab_size || sh_name > bin->shstrtab_size;
}

static bool is_valid_sh_name(ELFOBJ *bin, Elf_(Word) sh_name, Elf_(Word) sh_size) {
	return bin->shstrtab && sh_name < sh_size;
}

static size_t max_sh_name_size(Elf_(Word) sh_name, Elf_(Word) sh_size) {
	size_t size = sh_size - sh_name;
	return RZ_MIN(size, ELF_STRING_LENGTH);
}

static void set_rz_bin_elf_section_name_from_shdr(ELFOBJ *bin, RzBinElfSection *section, size_t section_id) {
	Elf_(Word) sh_name = bin->shdr[section_id].sh_name;
	Elf_(Word) sh_size = bin->shstrtab_size;

	if (is_invalid_strtab_section(bin, sh_name)) { // TODO add test
		snprintf(section->name, ELF_STRING_LENGTH, "invalid%zu", section_id);
	} else if (is_valid_sh_name(bin, sh_name, sh_size)) {
		rz_str_ncpy(section->name, bin->shstrtab + sh_name, max_sh_name_size(sh_name, sh_size));
	} else if (bin->shdr[section_id].sh_type == SHT_NULL) {
		section->name[0] = '\0';
	} else {
		snprintf(section->name, ELF_STRING_LENGTH, "unknown%zu", section_id); // TODO add test
	}
}

static void set_rz_bin_elf_section_from_shdr(ELFOBJ *bin, RzBinElfSection *section, size_t section_id) {
	set_rz_bin_elf_section_basic_from_shdr(bin, section, section_id);
	set_rz_bin_elf_section_rva_from_shdr(bin, section, section_id);
	set_rz_bin_elf_section_name_from_shdr(bin, section, section_id);
	section->last = 0;
}

static RzBinElfSection *get_sections_from_shdr(ELFOBJ *bin) {
	size_t len = bin->ehdr.e_shnum;

	RzBinElfSection *ret = RZ_NEWS(RzBinElfSection, len + 1);
	if (!ret) {
		return NULL;
	}

	for (size_t i = 0; i < len; i++) {
		set_rz_bin_elf_section_from_shdr(bin, ret + i, i);
	}

	ret[len].last = 1;
	return ret;
}

/**
 * \brief Return the list of rizin sections
 * \param elf binary
 * \return a ptr to an array terminated with an item with .last set to 1
 *
 * Generate the elf section from the section header(shdr) or the segment header(phdr)
 */
RZ_OWN RzBinElfSection *Elf_(rz_bin_elf_get_sections)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	//	if (bin->g_sections) {
	//		return bin->g_sections;
	//	}
	//

	if (bin->shdr) {
		return get_sections_from_shdr(bin);
	}

	if (bin->phdr) {
		return get_sections_from_dt_dynamic(bin);
	}

	return NULL;
}
