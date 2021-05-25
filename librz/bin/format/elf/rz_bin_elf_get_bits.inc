// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

struct mips_bits_translation {
	Elf_(Word) type;
	int bits;
};

static const struct mips_bits_translation mips_bits_translation_table[] = {
	{ EF_MIPS_ARCH_1, 32 },
	{ EF_MIPS_ARCH_2, 32 },
	{ EF_MIPS_ARCH_3, 32 },
	{ EF_MIPS_ARCH_4, 32 },
	{ EF_MIPS_ARCH_5, 32 },
	{ EF_MIPS_ARCH_32, 32 },
	{ EF_MIPS_ARCH_64, 64 },
	{ EF_MIPS_ARCH_32R2, 32 },
	{ EF_MIPS_ARCH_64R2, 64 }
};

static int get_bits_common(ELFOBJ *bin) {
	switch (bin->ehdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		return 32;
	case ELFCLASS64:
		return 64;
	case ELFCLASSNONE:
	default:
		return 32;
	}
}

static bool has_thumb_symbol(ELFOBJ *bin) {
	struct rz_bin_elf_symbol_t *symbols = Elf_(rz_bin_elf_get_symbols)(bin);

	if (!symbols) {
		return false;
	}

	for (size_t i = 0; !symbols[i].last; i++) {
		if (symbols[i].offset & 1) {
			return true;
		}
	}

	return false;
}

static bool arch_is_arm(ELFOBJ *bin) {
	return bin->ehdr.e_machine == EM_ARM;
}

static int get_bits_mips_common(Elf_(Word) mips_type) {
	for (size_t i = 0; i < RZ_ARRAY_SIZE(mips_bits_translation_table); i++) {
		if (mips_type == mips_bits_translation_table[i].type) {
			return mips_bits_translation_table[i].bits;
		}
	}

	return 32;
}

static int is_playstation_hack(ELFOBJ *bin, Elf_(Word) mips_type) {
	return Elf_(rz_bin_elf_is_executable)(bin) && Elf_(rz_bin_elf_is_static)(bin) && mips_type == EF_MIPS_ARCH_3;
}

static int get_bits_mips(ELFOBJ *bin) {
	const Elf_(Word) mips_type = bin->ehdr.e_flags & EF_MIPS_ARCH;

	if (is_playstation_hack(bin, mips_type)) {
		return 64;
	}

	return get_bits_mips_common(mips_type);
}

static bool arch_is_mips(ELFOBJ *bin) {
	return bin->phdr && bin->ehdr.e_machine == EM_MIPS;
}

static bool arch_is_arcompact(ELFOBJ *bin) {
	return bin->ehdr.e_machine == EM_ARC_A5;
}

/**
 * \brief Return the elf bits
 * \param elf binary
 * \return the number of bits
 *
 * ...
 */
int Elf_(rz_bin_elf_get_bits)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, 0);

	/* Hack for ARCompact */
	if (arch_is_arcompact(bin)) {
		return 16;
	}

	/* Hack for Ps2 */
	if (arch_is_mips(bin)) {
		return get_bits_mips(bin);
	}

	/* Hack for Thumb */
	if (arch_is_arm(bin)) {
		if (bin->ehdr.e_type != ET_EXEC && has_thumb_symbol(bin)) {
			return 16;
		}

		if (Elf_(rz_bin_elf_get_entry_offset)(bin) & 1) {
			return 16;
		}
	}

	return get_bits_common(bin);
}
