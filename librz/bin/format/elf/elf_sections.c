// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
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

static bool create_section_from_phdr(ELFOBJ *bin, RzVector /*<RzBinElfSection>*/ *result, const char *name, ut64 addr, ut64 sz) {
	RzBinElfSection section = { 0 };

	section.offset = Elf_(rz_bin_elf_v2p)(bin, addr);
	if (section.offset == UT64_MAX) {
		RZ_LOG_WARN("Failed to convert section virtual address to physical address.\n")
		return false;
	}

	section.rva = addr;
	section.size = sz;
	section.name = strdup(name);
	if (!section.name) {
		return false;
	}

	if (!rz_vector_push(result, &section)) {
		return false;
	}

	return true;
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

static bool create_section_plt(ELFOBJ *bin, RzVector /*<RzBinElfSection>*/ *result) {
	ut64 addr;
	ut64 size;

	const char *plt_name = get_plt_name(bin);
	if (!plt_name) {
		return true;
	}

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_JMPREL, &addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTRELSZ, &size)) {
		return true;
	}

	return create_section_from_phdr(bin, result, plt_name, addr, size);
}

static void rz_bin_elf_section_free(void *e, RZ_UNUSED void *user) {
	RzBinElfSection *ptr = e;
	free(ptr->name);
}

static RzVector /*<RzBinElfSection>*/ *get_sections_from_dt_dynamic(ELFOBJ *bin) {
	ut64 addr;
	ut64 size;

	RzVector *result = rz_vector_new(sizeof(RzBinElfSection), rz_bin_elf_section_free, NULL);
	if (!result) {
		return NULL;
	}

	// There is no info about the got size
	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &addr)) {
		if (!create_section_from_phdr(bin, result, ".got.plt", addr, 0)) {
			rz_vector_free(result);
			return NULL;
		}
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_REL, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELSZ, &size)) {
		if (!create_section_from_phdr(bin, result, ".rel.dyn", addr, size)) {
			rz_vector_free(result);
			return NULL;
		}
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELA, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELASZ, &size)) {
		if (!create_section_from_phdr(bin, result, ".rela.dyn", addr, size)) {
			rz_vector_free(result);
			return NULL;
		}
	}

	if (!create_section_plt(bin, result)) {
		rz_vector_free(result);
		return NULL;
	}

	if (!rz_vector_len(result)) {
		rz_vector_free(result);
		return NULL;
	}

	return result;
}

static bool get_shdr_entry_aux(ELFOBJ *bin, Elf_(Shdr) * section, ut64 offset) {
	return Elf_(rz_bin_elf_read_word)(bin, &offset, &section->sh_name) &&
		Elf_(rz_bin_elf_read_word)(bin, &offset, &section->sh_type) &&
		Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &section->sh_flags) &&
		Elf_(rz_bin_elf_read_addr)(bin, &offset, &section->sh_addr) &&
		Elf_(rz_bin_elf_read_off)(bin, &offset, &section->sh_offset) &&
		Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &section->sh_size) &&
		Elf_(rz_bin_elf_read_word)(bin, &offset, &section->sh_link) &&
		Elf_(rz_bin_elf_read_word)(bin, &offset, &section->sh_info) &&
		Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &section->sh_addralign) &&
		Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &section->sh_entsize);
}

static bool get_shdr_entry(ELFOBJ *bin, Elf_(Shdr) * section, ut64 offset) {
	if (!get_shdr_entry_aux(bin, section, offset)) {
		RZ_LOG_WARN("Failed to read section entry at 0x%" PFMT64x ".\n", offset);
		return false;
	}

	return true;
}

static bool set_elf_section_name(ELFOBJ *bin, RzBinElfSection *section, Elf_(Shdr) * shdr, size_t id) {
	if (!bin->shstrtab || !Elf_(rz_bin_elf_strtab_has_index)(bin->shstrtab, shdr->sh_name)) {
		section->name = rz_str_newf("invalid%zu", id);
		return false;
	}

	if (shdr->sh_type == SHT_NULL) {
		section->name = NULL;
		return true;
	}

	section->name = Elf_(rz_bin_elf_strtab_get_dup)(bin->shstrtab, shdr->sh_name);
	if (section->name) {
		return true;
	}

	section->name = NULL;
	return false;
}

static bool set_elf_section_aux(ELFOBJ *bin, RzBinElfSection *section, Elf_(Shdr) * shdr, size_t id) {
	section->offset = shdr->sh_offset;
	section->size = shdr->sh_size;
	section->align = shdr->sh_addralign;
	section->flags = shdr->sh_flags;
	section->link = shdr->sh_link;
	section->info = shdr->sh_info;
	section->type = shdr->sh_type;

	if (Elf_(rz_bin_elf_is_relocatable)(bin)) {
		section->rva = bin->baddr + shdr->sh_offset;
	} else {
		if (shdr->sh_flags & SHF_ALLOC) {
			section->rva = shdr->sh_addr;
		} else {
			section->rva = UT64_MAX;
		}
	}
	return set_elf_section_name(bin, section, shdr, id);
}

static bool verify_shdr_entry(ELFOBJ *bin, Elf_(Shdr) * section) {
	if (section->sh_link != SHT_SUNW_COMDAT && section->sh_link >= bin->ehdr.e_shnum) {
		return false;
	}

	Elf_(Off) end_off;
	if (!Elf_(rz_bin_elf_add_off)(&end_off, section->sh_offset, section->sh_size)) {
		return false;
	}

	if (section->sh_type != SHT_NOBITS && end_off > bin->size) {
		return false;
	}

	if (!Elf_(rz_bin_elf_add_addr)(NULL, section->sh_addr, section->sh_size)) {
		return false;
	}

	return true;
}

static bool set_elf_section(ELFOBJ *bin, RzBinObjectLoadOptions *option, RzBinElfSection *section, Elf_(Shdr) * shdr, size_t id) {
	bool tmp = set_elf_section_aux(bin, section, shdr, id);

	if (!option->elf_checks_sections) {
		section->is_valid = true;
		return true;
	}

	section->is_valid = tmp && verify_shdr_entry(bin, shdr);
	return section->is_valid;
}

RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section)(RZ_NONNULL ELFOBJ *bin, Elf_(Half) index) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->sections) {
		return NULL;
	}

	if (index < rz_vector_len(bin->sections)) {
		return rz_vector_index_ptr(bin->sections, index);
	}

	return NULL;
}

RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section_with_name)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfSection *section;
	rz_bin_elf_foreach_sections(bin, section) {
		if (section->is_valid && section->name && !strcmp(section->name, name)) {
			return section;
		}
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
RZ_OWN RzList /*<char *>*/ *Elf_(rz_bin_elf_section_flag_to_rzlist)(ut64 flag) {
	RzList *flag_list = rz_list_new();
	if (!flag_list) {
		return NULL;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(flag_translation_table); i++) {
		if (flag & flag_translation_table[i].flag) {
			if (!rz_list_append(flag_list, flag_translation_table[i].name)) {
				rz_list_free(flag_list);
				return NULL;
			}
		}
	}

	return flag_list;
}

static RzBinElfSection convert_elf_section(ELFOBJ *bin, RzBinObjectLoadOptions *options, Elf_(Shdr) * shdr, size_t pos) {
	RzBinElfSection section;

	if (!set_elf_section(bin, options, &section, shdr, pos)) {
		RZ_LOG_WARN("The section %zu at 0x%" PFMT64x " seems to be invalid.\n", pos, section.offset);
	}

	return section;
}

static RzVector /*<RzBinElfSection>*/ *convert_sections_from_shdr(ELFOBJ *bin, RzBinObjectLoadOptions *options, RzVector /*<Elf_(Shdr)>*/ *sections) {
	if (!sections) {
		return NULL;
	}

	RzVector *result = rz_vector_new(sizeof(RzBinElfSection), rz_bin_elf_section_free, NULL);
	if (!result) {
		return NULL;
	}

	size_t i;
	Elf_(Shdr) * section;
	rz_vector_enumerate (sections, section, i) {
		RzBinElfSection tmp = convert_elf_section(bin, options, section, i);
		if (!rz_vector_push(result, &tmp)) {
			rz_vector_free(result);
			return NULL;
		}
	}

	return result;
}

static RzVector /*<RzBinElfSection>*/ *convert_sections(ELFOBJ *bin, RzBinObjectLoadOptions *options, RzVector /*<Elf_(Shdr)>*/ *sections) {
	RzVector *result = convert_sections_from_shdr(bin, options, sections);
	if (result) {
		return result;
	}

	if (Elf_(rz_bin_elf_has_segments)(bin)) {
		return get_sections_from_dt_dynamic(bin);
	}

	return result;
}

RZ_OWN RzVector /*<RzBinElfSection>*/ *Elf_(rz_bin_elf_convert_sections)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RzBinObjectLoadOptions *options, RzVector /*<Elf_(Shdr)>*/ *sections) {
	rz_return_val_if_fail(bin && options, NULL);

	RzVector *result = convert_sections(bin, options, sections);
	if (!result) {
		return NULL;
	}

	if (!rz_vector_len(result)) {
		rz_vector_free(result);
		return NULL;
	}

	return result;
}

RZ_OWN RzVector /*<Elf_(Shdr)>*/ *Elf_(rz_bin_elf_sections_new)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!bin->ehdr.e_shnum) {
		return NULL;
	}

	if (!Elf_(rz_bin_elf_check_array)(bin, bin->ehdr.e_shoff, bin->ehdr.e_shnum, sizeof(Elf_(Phdr)))) {
		RZ_LOG_WARN("Invalid section header (check array failed).\n");
		return NULL;
	}

	RzVector *result = rz_vector_new(sizeof(Elf_(Shdr)), NULL, NULL);
	if (!result) {
		return NULL;
	}

	ut64 offset = bin->ehdr.e_shoff;

	for (size_t i = 0; i < bin->ehdr.e_shnum; i++) {
		Elf_(Shdr) *section = rz_vector_push(result, NULL);
		if (!section) {
			rz_vector_free(result);
			return NULL;
		}

		if (!get_shdr_entry(bin, section, offset)) {
			rz_vector_free(result);
			return NULL;
		}

		offset += sizeof(Elf_(Shdr));
	}

	return result;
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
			return rz_str_dup(type_translation_table[i].name);
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

bool Elf_(rz_bin_elf_has_sections)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->sections;
}
