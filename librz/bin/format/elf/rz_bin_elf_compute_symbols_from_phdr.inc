// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void set_by_ord(ELFOBJ *bin, RzBinElfSymbol *symbols, size_t pos, int type) {
	if (type == RZ_BIN_ELF_IMPORT_SYMBOLS && !bin->imports_by_ord_size) {
		bin->imports_by_ord_size = pos;

		if (!pos) {
			bin->imports_by_ord = NULL;
			return;
		}

		bin->imports_by_ord = RZ_NEWS0(RzBinImport *, pos);

		for (size_t i = 0; i < pos - 1; i++) {
			Elf_(rz_bin_elf_set_import_by_ord)(bin, symbols + i);
		}
	} else if (type == RZ_BIN_ELF_ALL_SYMBOLS && !bin->symbols_by_ord_size && pos) {
		bin->symbols_by_ord_size = pos;

		if (pos > 0) {
			bin->symbols_by_ord = RZ_NEWS0(RzBinSymbol *, pos);
		} else {
			bin->symbols_by_ord = NULL;
		}
	}
}

RZ_IPI RZ_OWN RzBinElfSymbol *Elf_(rz_bin_elf_compute_symbols_from_phdr)(RZ_NONNULL ELFOBJ *bin, int type) {
	rz_return_val_if_fail(bin, NULL);

	ut64 entry_size = bin->dyn_info.dt_syment;
	if (bin->dyn_info.dt_symtab == RZ_BIN_ELF_ADDR_MAX || !entry_size) {
		return NULL;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p)(bin, bin->dyn_info.dt_symtab);
	if (offset == UT64_MAX) {
		return NULL;
	}

	size_t num = Elf_(rz_bin_elf_get_number_of_dynamic_symbols)(bin);
	if (!num) {
		return NULL;
	}

	RzVector *tmp = Elf_(rz_bin_elf_compute_symbols_from_segment)(bin, type, offset, num, entry_size);
	if (!tmp) {
		return NULL;
	}

	RzBinElfSymbol *end = rz_vector_push(tmp, NULL);
	end->last = 1;

	size_t len = rz_vector_len(tmp);
	RzBinElfSymbol *result = rz_vector_flush(tmp);
	rz_vector_free(tmp);

	set_by_ord(bin, result, len, type);

	return result;
}
