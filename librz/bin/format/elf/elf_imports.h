// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#ifndef _INCLUDE_ELF_IMPORTS_H_
#define _INCLUDE_ELF_IMPORTS_H_

struct rz_bin_elf_imports_t {
	RzVector *elf_imports;	// RzVector<RzBinElfSymbols> store import as RzBinElfSymbol
	RzVector *imports; 	// RzVector<RzBinImports> store import as RzBinImport
	RzVector *symbols; 	// RzVector<RzBinSymbols> store import as RzBinSymbol
};

#endif
