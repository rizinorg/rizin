// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"
#include "elf_imports.h"

RZ_BORROW RzBinImport *Elf_(rz_bin_elf_get_import)(RZ_NONNULL ELFOBJ *bin, ut32 ordinal) {
	rz_return_val_if_fail(bin && bin->imports, NULL);

	RzBinImport *import;
	rz_bin_elf_foreach_imports(bin, import) {
		if (import->ordinal == ordinal) {
			return import;
		}
	}

	return NULL;
}

RZ_BORROW RzBinElfSymbol *Elf_(rz_bin_elf_get_elf_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->imports, NULL);
	return bin->imports->elf_imports;
}

RZ_BORROW RzVector *Elf_(rz_bin_elf_get_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->imports, NULL);
	return bin->imports->imports;
}

bool Elf_(rz_bin_elf_has_imports)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->imports;
}

void Elf_(rz_bin_elf_imports_free)(RzBinElfImports *ptr) {
	if (!ptr) {
		return;
	}

	free(ptr->elf_imports);
	rz_vector_free(ptr->imports);
}
