// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct type_translation {
	ut64 type;
	const char *name;
};

struct flag_translation {
	ut64 flag;
	char *name;
};

static const struct type_translation type_translation_table[] = {
	{ SHT_NULL, "NULL" },
	{ SHT_PROGBITS, "PROGBITS" },
	{ SHT_SYMTAB, "SYMTAB" },
	{ SHT_STRTAB, "STRTAB" },
	{ SHT_RELA, "RELA" },
	{ SHT_HASH, "HASH" },
	{ SHT_DYNAMIC, "DYNAMIC" },
	{ SHT_NOTE, "NOTE" },
	{ SHT_NOBITS, "NOBITS" },
	{ SHT_REL, "REL" },
	{ SHT_SHLIB, "SHLIB" },
	{ SHT_DYNSYM, "DYNSYM" },
	{ SHT_INIT_ARRAY, "INIT_ARRAY" },
	{ SHT_FINI_ARRAY, "FINI_ARRAY" },
	{ SHT_PREINIT_ARRAY, "PREINIT_ARRAY" },
	{ SHT_GROUP, "GROUP" },
	{ SHT_SYMTAB_SHNDX, "SYMTAB_SHNDX" },
	{ SHT_NUM, "NUM" },
	{ SHT_LOOS, "LOOS" },
	{ SHT_GNU_ATTRIBUTES, "GNU_ATTRIBUTES" },
	{ SHT_GNU_HASH, "GNU_HASH" },
	{ SHT_GNU_LIBLIST, "GNU_LIBLIST" },
	{ SHT_CHECKSUM, "CHECKSUM" },
	{ SHT_SUNW_move, "MOVE" },
	{ SHT_SUNW_COMDAT, "COMDAT" },
	{ SHT_SUNW_syminfo, "SYMINFO" },
	{ SHT_GNU_verdef, "VERDEF" },
	{ SHT_GNU_verneed, "VERNEED" },
	{ SHT_GNU_versym, "VERSYM" }
};

static const struct flag_translation flag_translation_table[] = {
	{ SHF_WRITE, "write" },
	{ SHF_ALLOC, "alloc" },
	{ SHF_EXECINSTR, "execute" },
	{ SHF_MERGE, "merge" },
	{ SHF_STRINGS, "strings" },
	{ SHF_INFO_LINK, "info" },
	{ SHF_LINK_ORDER, "link_order" },
	{ SHF_OS_NONCONFORMING, "extra_os_processing_reqd" },
	{ SHF_GROUP, "group" },
	{ SHF_TLS, "TLS" },
	{ SHF_EXCLUDE, "exclude" },
	{ SHF_COMPRESSED, "compressed" }
};

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
	ut64 dt_pltrel;

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTREL, &dt_pltrel)) {
		return NULL;
	}

	if (dt_pltrel == DT_REL) {
		return ".rel.plt";
	}

	return ".rela.plt";
}

static void create_section_plt(ELFOBJ *bin, RzBinElfSection *section, size_t *pos) {
	ut64 addr;
	ut64 size;

	const char *plt_name = get_plt_name(bin);

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_JMPREL, &addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTRELSZ, &size)) {
		return;
	}

	create_section_from_phdr(bin, section, pos, plt_name, addr, size);
}

static RzBinElfSection *get_sections_from_dt_dynamic(ELFOBJ *bin) {
	ut64 addr;
	ut64 size;

	size_t pos = 0;

	RzBinElfSection *ret = RZ_NEWS(RzBinElfSection, 5);
	if (!ret) {
		return NULL;
	}

	// There is no info about the got size
	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &addr)) {
		create_section_from_phdr(bin, ret + pos, &pos, ".got.plt", addr, 0);
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_REL, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELSZ, &size)) {
		create_section_from_phdr(bin, ret + pos, &pos, ".rel.dyn", addr, size);
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELA, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELASZ, &size)) {
		create_section_from_phdr(bin, ret + pos, &pos, ".rela.dyn", addr, size);
	}

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
 * \brief Return the section with the specified name
 * \param elf binary
 * \param section name
 * \return a ptr to the section with the specified name
 *
 * Search a specific section in the g_sections structure
 */
RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name) {
	rz_return_val_if_fail(bin && section_name, NULL);

	if (!bin->g_sections) {
		return NULL;
	}

	for (size_t i = 0; !bin->g_sections[i].last; i++) {
		if (!strcmp(bin->g_sections[i].name, section_name)) {
			return bin->g_sections + i;
		}
	}

	return NULL;
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

/**
 * \brief Return a list of string representing flag options
 * \param elf flag
 * \return RzList of string representing flag options
 *
 * Compare the flag to common option such as SHF_WRITE, SHF_ALLOC, ect
 */
RZ_OWN RzList *Elf_(rz_bin_elf_section_flag_to_rzlist)(ut64 flag) {
	RzList *flag_list = rz_list_new();
	if (!flag_list) {
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(flag_translation_table); i++) {
		if (flag & flag_translation_table[i].flag) {
			rz_list_append(flag_list, flag_translation_table[i].name);
		}
	}

	return flag_list;
}

/**
 * \brief Return a string representing the elf type
 * \param elf type
 * \return allocated string
 *
 * Compare the type SHT_NULL, SHT_PROGBITS, etc and return the string representation
 */
RZ_OWN char *Elf_(rz_bin_elf_section_type_to_string)(ut64 type) {

	for (size_t i = 0; i < RZ_ARRAY_SIZE(type_translation_table); i++) {
		if (type == type_translation_table[i].type) {
			return rz_str_new(type_translation_table[i].name);
		}
	}

	if (type >= SHT_LOPROC && type <= SHT_HIPROC) {
		return rz_str_newf("LOPROC+0x%08" PFMT64x, type - SHT_LOPROC);
	}

	if (type >= SHT_LOUSER && type <= SHT_HIUSER) {
		return rz_str_newf("LOUSER+0x%08" PFMT64x, type - SHT_LOUSER);
	}

	return rz_str_newf("0x%" PFMT64x, type);
}

bool Elf_(rz_bin_elf_is_sh_index_valid)(RZ_NONNULL ELFOBJ *bin, Elf_(Half) index) {
	rz_return_val_if_fail(bin, false);

	return index < bin->ehdr.e_shnum && !RZ_BETWEEN(SHN_LORESERVE, index, SHN_HIRESERVE);
}

/**
 * \brief Return the section real virtual address with the specified name
 * \param elf binary
 * \param section name
 * \return section offset
 *
 * Search a specific section in the g_sections structure and return the section real virtual address
 */
ut64 Elf_(rz_bin_elf_get_section_addr)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name) {
	rz_return_val_if_fail(bin && section_name, UT64_MAX);

	RzBinElfSection *section = Elf_(rz_bin_elf_get_section)(bin, section_name);
	return section ? section->rva : UT64_MAX;
}

/**
 * \brief Return the section offset with the specified name
 * \param elf binary
 * \param section name
 * \return section offset
 *
 * Search a specific section in the g_sections structure and return the section offset
 */
ut64 Elf_(rz_bin_elf_get_section_offset)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *section_name) {
	rz_return_val_if_fail(bin && section_name, UT64_MAX);

	RzBinElfSection *section = Elf_(rz_bin_elf_get_section)(bin, section_name);
	return section ? section->offset : UT64_MAX;
}
