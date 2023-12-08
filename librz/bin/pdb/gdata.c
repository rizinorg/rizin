// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

RZ_IPI bool gdata_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream) {
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
		goto err;
	}

	PDBSymbolIter iter = { 0 };
	PDBSymbolTable_iter(syms, &iter);
	if (!PDBSymbolIter_collect(&iter, &s->global_symbols)) {
		goto err;
	}
	free(syms);
	return true;
err:
	free(syms);
	return false;
}

RZ_IPI void gdata_stream_free(RzPdbGDataStream *stream) {
	if (!stream) {
		return;
	}
	rz_pvector_free(stream->global_symbols);
	free(stream);
}
