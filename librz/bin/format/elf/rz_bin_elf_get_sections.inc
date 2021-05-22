// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void create_section_from_phdr(ELFOBJ *bin, RzBinElfSection *ret, size_t *i, const char *name, ut64 addr, ut64 sz) {
	if (!addr) {
		return;
	}

	ret[*i].offset = Elf_(rz_bin_elf_v2p_new)(bin, addr);
	ret[*i].rva = addr;
	ret[*i].size = sz;
	strncpy(ret[*i].name, name, RZ_ARRAY_SIZE(ret[*i].name) - 1);
	ret[*i].name[RZ_ARRAY_SIZE(ret[*i].name) - 1] = '\0';
	ret[*i].last = 0;
	*i = *i + 1;
}

static RzBinElfSection *get_sections_from_phdr(ELFOBJ *bin) {
	RzBinElfSection *ret;
	size_t num_sections = 0;
	ut64 reldyn = 0, relava = 0, pltgotva = 0, relva = 0;
	ut64 reldynsz = 0, relasz = 0, pltgotsz = 0;
	rz_return_val_if_fail(bin && bin->phdr, NULL);

	if (!bin->ehdr.e_phnum) {
		return NULL;
	}

	if (bin->dyn_info.dt_rel != RZ_BIN_ELF_ADDR_MAX) {
		reldyn = bin->dyn_info.dt_rel;
		num_sections++;
	}
	if (bin->dyn_info.dt_rela != RZ_BIN_ELF_ADDR_MAX) {
		relva = bin->dyn_info.dt_rela;
		num_sections++;
	}
	if (bin->dyn_info.dt_relsz) {
		reldynsz = bin->dyn_info.dt_relsz;
	}
	if (bin->dyn_info.dt_relasz) {
		relasz = bin->dyn_info.dt_relasz;
	}
	if (bin->dyn_info.dt_pltgot != RZ_BIN_ELF_ADDR_MAX) {
		pltgotva = bin->dyn_info.dt_pltgot;
		num_sections++;
	}
	if (bin->dyn_info.dt_pltrelsz) {
		pltgotsz = bin->dyn_info.dt_pltrelsz;
	}
	if (bin->dyn_info.dt_jmprel != RZ_BIN_ELF_ADDR_MAX) {
		relava = bin->dyn_info.dt_jmprel;
		num_sections++;
	}

	ret = calloc(num_sections + 1, sizeof(RzBinElfSection));
	if (!ret) {
		return NULL;
	}

	size_t i = 0;
	create_section_from_phdr(bin, ret, &i, ".rel.dyn", reldyn, reldynsz);
	create_section_from_phdr(bin, ret, &i, ".rela.plt", relava, pltgotsz);
	create_section_from_phdr(bin, ret, &i, ".rel.plt", relva, relasz);
	create_section_from_phdr(bin, ret, &i, ".got.plt", pltgotva, pltgotsz);
	ret[i].last = 1;

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

	return get_sections_from_phdr(bin);
}
