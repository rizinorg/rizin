// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "modi.h"

static bool PDBModuleInfo_symbols(const PDBModuleInfo *modi, PDBSymbolIter *iter) {
	RzBuffer *b = rz_buf_new_slice(modi->stream, 0, modi->symbols_size);
	if (!b) {
		return false;
	}
	if (modi->symbols_size > 0) {
		ut32 sig = 0;
		if (!rz_buf_read_le32(b, &sig)) {
			goto err;
		}
		if (sig != CV_SIGNATURE_C13) {
			RZ_LOG_ERROR("Unsupported symbol data format: 0x%" PFMT32x "\n", sig);
			goto err;
		}
	}
	iter->b = b;
	return true;
err:
	rz_buf_free(b);
	return false;
}

RZ_IPI bool PDBModuleInfo_parse(const RzPdb *pdb, const PDB_DBIModule *m, PDBModuleInfo *modi) {
	if (!(pdb && m && modi)) {
		return false;
	}
	modi->stream_index = m->stream;
	modi->symbols_size = m->symbols_size;
	if (modi->symbols_size == 0) {
		return true;
	}

	const RzPdbMsfStream *stream = pdb_raw_steam(pdb, modi->stream_index);
	if (!stream) {
		return false;
	}
	modi->stream = stream->stream_data;

	PDBSymbolIter iter = { 0 };
	if (!PDBModuleInfo_symbols(modi, &iter)) {
		return false;
	}
	if (!PDBSymbolIter_collect(&iter, &modi->symbols)) {
		return false;
	}
	return true;
}
