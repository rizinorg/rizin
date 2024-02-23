// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_SYMBOL_H
#define RIZIN_SYMBOL_H

#include "symbol_enum.h"
#include <rz_util/rz_buf.h>
#include <rz_pdb.h>

RZ_IPI bool PDBSectionOffset_parse(RzBuffer *b, PDBSectionOffset *section_offset);

RZ_IPI bool PDBSymbol_parse(RzBuffer *b, PDBSymbol *symbol);

typedef struct {
	RzBuffer *b;
} PDBSymbolTable;

typedef struct {
	RzBuffer *b;
} PDBSymbolIter;

RZ_IPI bool PDBSymbolTable_iter(PDBSymbolTable *symbol_table, PDBSymbolIter *iter);
RZ_IPI PDBSymbol *PDBSymbolTable_symbol_by_index(PDBSymbolTable *symbol_table, PDBSymbolIndex index);

RZ_IPI bool PDBSymbolIter_next(PDBSymbolIter *iter, PDBSymbol *symbol);
RZ_IPI bool PDBSymbolIter_seek(PDBSymbolIter *iter, PDBSymbolIndex index);
RZ_IPI bool PDBSymbolIter_collect(PDBSymbolIter *iter, RzPVector /*<PDBSymbol *>*/ **psymbols);

#endif // RIZIN_SYMBOL_H
