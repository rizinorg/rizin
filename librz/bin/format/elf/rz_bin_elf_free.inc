// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

/**
 * \brief Free the elf binary
 * \param elf binary
 *
 * ...
 */
void Elf_(rz_bin_elf_free)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_if_fail(bin);

	free(bin->phdr);
	free(bin->shdr);
	free(bin->strtab);
	free(bin->shstrtab);
	free(bin->dynstr);

	free(bin->g_sections);
	free(bin->g_symbols);
	free(bin->g_imports);
	free(bin->g_relocs);

	if (bin->g_symbols != bin->phdr_symbols) {
		free(bin->phdr_symbols);
	}

	if (bin->g_imports != bin->phdr_imports) {
		free(bin->phdr_imports);
	}

	ht_up_free(bin->rel_cache);

	rz_vector_fini(&bin->dyn_info.dt_needed);
	rz_list_free(bin->note_segments);

	if (bin->imports_by_ord) {
		for (size_t i = 0; i < bin->imports_by_ord_size; i++) {
			rz_bin_import_free(bin->imports_by_ord[i]);
		}
		free(bin->imports_by_ord);
	}

	if (bin->symbols_by_ord) {
		for (size_t i = 0; i < bin->symbols_by_ord_size; i++) {
			rz_bin_symbol_free(bin->symbols_by_ord[i]);
		}
		free(bin->symbols_by_ord);
	}

	rz_buf_free(bin->b);
	free(bin);
}
