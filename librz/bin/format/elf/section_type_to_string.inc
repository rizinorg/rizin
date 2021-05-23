// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct type_translation {
	ut64 type;
	const char *name;
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

/**
 * \brief Return a string representing the elf type
 * \param elf type
 * \return allocated string
 *
 * Compare the type SHT_NULL, SHT_PROGBITS, etc and return the string representation
 */
RZ_OWN char *Elf_(section_type_to_string)(ut64 type) {

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
