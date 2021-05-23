// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Return a string representing the elf type
 * \param elf type
 * \return allocated string
 *
 * Compare the type SHT_NULL, SHT_PROGBITS, etc and return the string representation
 */
RZ_OWN char *Elf_(section_type_to_string)(ut64 type) {
	switch (type) {
	case SHT_NULL:
		return rz_str_new("NULL");
	case SHT_PROGBITS:
		return rz_str_new("PROGBITS");
	case SHT_SYMTAB:
		return rz_str_new("SYMTAB");
	case SHT_STRTAB:
		return rz_str_new("STRTAB");
	case SHT_RELA:
		return rz_str_new("RELA");
	case SHT_HASH:
		return rz_str_new("HASH");
	case SHT_DYNAMIC:
		return rz_str_new("DYNAMIC");
	case SHT_NOTE:
		return rz_str_new("NOTE");
	case SHT_NOBITS:
		return rz_str_new("NOBITS");
	case SHT_REL:
		return rz_str_new("REL");
	case SHT_SHLIB:
		return rz_str_new("SHLIB");
	case SHT_DYNSYM:
		return rz_str_new("DYNSYM");
	case SHT_INIT_ARRAY:
		return rz_str_new("INIT_ARRAY");
	case SHT_FINI_ARRAY:
		return rz_str_new("FINI_ARRAY");
	case SHT_PREINIT_ARRAY:
		return rz_str_new("PREINIT_ARRAY");
	case SHT_GROUP:
		return rz_str_new("GROUP");
	case SHT_SYMTAB_SHNDX:
		return rz_str_new("SYMTAB_SHNDX");
	case SHT_NUM:
		return rz_str_new("NUM");
	case SHT_LOOS:
		return rz_str_new("LOOS");
	case SHT_GNU_ATTRIBUTES:
		return rz_str_new("GNU_ATTRIBUTES");
	case SHT_GNU_HASH:
		return rz_str_new("GNU_HASH");
	case SHT_GNU_LIBLIST:
		return rz_str_new("GNU_LIBLIST");
	case SHT_CHECKSUM:
		return rz_str_new("CHECKSUM");
	case SHT_SUNW_move:
		return rz_str_new("MOVE");
	case SHT_SUNW_COMDAT:
		return rz_str_new("COMDAT");
	case SHT_SUNW_syminfo:
		return rz_str_new("SYMINFO");
	case SHT_GNU_verdef:
		return rz_str_new("VERDEF");
	case SHT_GNU_verneed:
		return rz_str_new("VERNEED");
	case SHT_GNU_versym:
		return rz_str_new("VERSYM");
	default:
		if (type >= SHT_LOPROC && type <= SHT_HIPROC) {
			return rz_str_newf("LOPROC+0x%08" PFMT64x, type - SHT_LOPROC);
		}
		if (type >= SHT_LOUSER && type <= SHT_HIUSER) {
			return rz_str_newf("LOUSER+0x%08" PFMT64x, type - SHT_LOUSER);
		}
		return rz_str_newf("0x%" PFMT64x, type);
	}
}
