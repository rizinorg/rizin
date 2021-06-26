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

static void create_section_from_phdr(ELFOBJ *bin, RzVector *result, const char *name, ut64 addr, ut64 sz) {
	RzBinElfSection *section = rz_vector_push(result, NULL);
	if (!section) {
		return;
	}

	section->offset = Elf_(rz_bin_elf_v2p_new)(bin, addr);
	section->rva = addr;
	section->size = sz;
	rz_str_ncpy(section->name, name, ELF_STRING_LENGTH);
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

static void create_section_plt(ELFOBJ *bin, RzVector *result) {
	ut64 addr;
	ut64 size;

	const char *plt_name = get_plt_name(bin);
	if (!plt_name) {
		return;
	}

	if (!Elf_(rz_bin_elf_get_dt_info)(bin, DT_JMPREL, &addr) || !Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTRELSZ, &size)) {
		return;
	}

	create_section_from_phdr(bin, result, plt_name, addr, size);
}

static RzVector *get_sections_from_dt_dynamic(ELFOBJ *bin) {
	ut64 addr;
	ut64 size;

	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return NULL;
	}

	RzVector *result = rz_vector_new(sizeof(RzBinElfSection), NULL, NULL);
	if (!result) {
		return NULL;
	}

	// There is no info about the got size
	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_PLTGOT, &addr)) {
		create_section_from_phdr(bin, result, ".got.plt", addr, 0);
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_REL, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELSZ, &size)) {
		create_section_from_phdr(bin, result, ".rel.dyn", addr, size);
	}

	if (Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELA, &addr) && Elf_(rz_bin_elf_get_dt_info)(bin, DT_RELASZ, &size)) {
		create_section_from_phdr(bin, result, ".rela.dyn", addr, size);
	}

	create_section_plt(bin, result);

	return result;
}

static bool set_shdr_entry(ELFOBJ *bin, Elf_(Shdr) * section, ut64 offset) {
	if (!Elf_(rz_bin_elf_read_word)(bin, &offset, &section->sh_name) ||
		!Elf_(rz_bin_elf_read_word)(bin, &offset, &section->sh_type) ||
		!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &section->sh_flags) ||
		!Elf_(rz_bin_elf_read_addr)(bin, &offset, &section->sh_addr) ||
		!Elf_(rz_bin_elf_read_off)(bin, &offset, &section->sh_offset) ||
		!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &section->sh_size) ||
		!Elf_(rz_bin_elf_read_word)(bin, &offset, &section->sh_link) ||
		!Elf_(rz_bin_elf_read_word)(bin, &offset, &section->sh_info) ||
		!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &section->sh_addralign) ||
		!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &section->sh_entsize)) {
		return false;
	}

	return true;
}

static bool set_elf_section_name(ELFOBJ *bin, RzBinElfSection *section, Elf_(Shdr) * shdr, size_t id) {
	if (!bin->shstrtab || !Elf_(rz_bin_elf_strtab_has_index)(bin->shstrtab, shdr->sh_name)) {
		snprintf(section->name, ELF_STRING_LENGTH, "invalid%zu", id);
		return false;
	}

	if (shdr->sh_type == SHT_NULL) {
		section->name[0] = '\0';
		return true;
	}

	if (!Elf_(rz_bin_elf_strtab_cpy)(bin->shstrtab, section->name, shdr->sh_name)) {
		section->name[0] = '\0';
		return false;
	}

	return true;
}

static bool set_elf_section(ELFOBJ *bin, RzBinElfSection *section, Elf_(Shdr) * shdr, size_t id) {
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
		section->rva = shdr->sh_addr;
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

RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section)(RZ_NONNULL ELFOBJ *bin, Elf_(Half) index) {
	rz_return_val_if_fail(bin && bin->sections, NULL);

	if (index < rz_vector_len(bin->sections)) {
		return rz_vector_index_ptr(bin->sections, index);
	}

	return NULL;
}

RZ_BORROW RzBinElfSection *Elf_(rz_bin_elf_get_section_with_name)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(bin && bin->sections && name, NULL);

	RzBinElfSection *section;
	rz_bin_elf_foreach_sections(bin, section) {
		if (section->is_valid && !strcmp(section->name, name)) {
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

static RzBinElfSection convert_elf_section(ELFOBJ *bin, Elf_(Shdr) * shdr, size_t pos) {
	RzBinElfSection section;

	section.is_valid = set_elf_section(bin, &section, shdr, pos) && verify_shdr_entry(bin, shdr);
	if (!section.is_valid) {
		RZ_LOG_WARN("Invalid section %zu at 0x%" PFMT64x "\n", pos, section.offset);
	}

	return section;
}

static RzVector *convert_sections_from_shdr(ELFOBJ *bin, RzVector *sections) {
	if (!sections) {
		return NULL;
	}

	RzVector *result = rz_vector_new(sizeof(RzBinElfSection), NULL, NULL);
	if (!result) {
		return NULL;
	}

	size_t i;
	Elf_(Shdr) * section;
	rz_vector_enumerate(sections, section, i) {
		RzBinElfSection tmp = convert_elf_section(bin, section, i);
		rz_vector_push(result, &tmp);
	}

	return result;
}

RZ_OWN RzVector *Elf_(rz_bin_elf_convert_sections)(RZ_NONNULL ELFOBJ *bin, RzVector *sections) {
	rz_return_val_if_fail(bin, NULL);

	RzVector *result = convert_sections_from_shdr(bin, sections);
	if (result) {
		return result;
	}

	if (Elf_(rz_bin_elf_has_segments)(bin)) {
		return get_sections_from_dt_dynamic(bin);
	}

	return NULL;
}

RZ_OWN RzVector *Elf_(rz_bin_elf_new_sections)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!Elf_(rz_bin_elf_check_array)(bin, bin->ehdr.e_shoff, bin->ehdr.e_shnum, sizeof(Elf_(Phdr)))) {
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

		if (!set_shdr_entry(bin, section, offset)) {
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

bool Elf_(rz_bin_elf_has_sections)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->sections && rz_vector_len(bin->sections);
}
