// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

RZ_IPI bool parse_gdata_stream(RzPdb *pdb, RzPdbMsfStream *stream) {
	rz_return_val_if_fail(pdb && stream, false);
	PDBSymbolTable *syms = pdb_global_symbols(pdb);
	if (!syms) {
		return false;
	}
	if (!pdb->s_gdata) {
		pdb->s_gdata = RZ_NEW0(RzPdbGDataStream);
	}
	RzPdbGDataStream *s = pdb->s_gdata;
	if (!s) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		return false;
	}
	s->global_symbols = rz_pvector_new(free);
	if (!s->global_symbols) {
		return false;
	}

	PDBSymbolIter iter = { 0 };
	PDBSymbolTable_iter(syms, &iter);
	while (true) {
		PDBSymbol *symbol = RZ_NEW0(PDBSymbol);
		if (!symbol) {
			goto err;
		}
		if (!PDBSymbolIter_next(&iter, symbol)) {
			free(symbol);
			break;
		}
		if (!symbol->data) {
			free(symbol);
			continue;
		}
		rz_pvector_push(s->global_symbols, symbol);
	}

	return true;
err:
	return false;
}

RZ_IPI void free_gdata_stream(RzPdbGDataStream *stream) {
	if (!stream) {
		return;
	}
	rz_pvector_free(stream->global_symbols);
	free(stream);
}
