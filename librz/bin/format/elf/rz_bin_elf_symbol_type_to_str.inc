// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct symbol_type_translation {
	unsigned char type;
	const char *name;
};

static const struct symbol_type_translation symbol_type_translation_table[] = {
	{ STT_NOTYPE, RZ_BIN_TYPE_NOTYPE_STR },
	{ STT_OBJECT, RZ_BIN_TYPE_OBJECT_STR },
	{ STT_FUNC, RZ_BIN_TYPE_FUNC_STR },
	{ STT_SECTION, RZ_BIN_TYPE_SECTION_STR },
	{ STT_FILE, RZ_BIN_TYPE_FILE_STR },
	{ STT_COMMON, RZ_BIN_TYPE_COMMON_STR },
	{ STT_TLS, RZ_BIN_TYPE_TLS_STR },
	{ STT_NUM, RZ_BIN_TYPE_NUM_STR },
	{ STT_LOOS, RZ_BIN_TYPE_LOOS_STR },
	{ STT_HIOS, RZ_BIN_TYPE_HIOS_STR },
	{ STT_LOPROC, RZ_BIN_TYPE_LOPROC_STR },
	{ STT_HIPROC, RZ_BIN_TYPE_HIPROC_STR }
};

static bool is_special_arm_symbol(ELFOBJ *bin, Elf_(Sym) * sym, const char *name) {
	if (name[0] != '$') {
		return false;
	}

	if (name[1] == 'a' || name[1] == 't' || name[1] == 'd' || name[1] == 'x') {
		return (name[2] == '\0' || name[2] == '.') &&
			ELF_ST_TYPE(sym->st_info) == STT_NOTYPE &&
			ELF_ST_BIND(sym->st_info) == STB_LOCAL &&
			ELF_ST_VISIBILITY(sym->st_info) == STV_DEFAULT;
	}

	return false;
}

static bool is_special_symbol(ELFOBJ *bin, Elf_(Sym) * sym, const char *name) {
	switch (bin->ehdr.e_machine) {
	case EM_ARM:
	case EM_AARCH64:
		return is_special_arm_symbol(bin, sym, name);
	default:
		return false;
	}
}

RZ_IPI RZ_BORROW const char *Elf_(rz_bin_elf_symbol_type_to_str)(ELFOBJ *bin, RzBinElfSymbol *ret, RZ_NONNULL Elf_(Sym) * sym) {
	rz_return_val_if_fail(sym, NULL);

	if (bin && ret && is_special_symbol(bin, sym, ret->name)) {
		return RZ_BIN_TYPE_SPECIAL_SYM_STR;
	}

	for (size_t i = 0; i < RZ_ARRAY_SIZE(symbol_type_translation_table); i++) {
		if (ELF_ST_TYPE(sym->st_info) == symbol_type_translation_table[i].type) {
			return symbol_type_translation_table[i].name;
		}
	}

	return RZ_BIN_TYPE_UNKNOWN_STR;
}
