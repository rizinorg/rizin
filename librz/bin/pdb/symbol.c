// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "symbol.h"

#include "pdb.h"

RZ_IPI bool PDBSectionOffset_parse(RzBuffer *b, PDBSectionOffset *section_offset) {
	if (!section_offset) {
		return false;
	}
	ut32 offset = 0;
	ut16 section_index = 0;
	if (!(rz_buf_read_le32(b, &offset) &&
		    rz_buf_read_le16(b, &section_index))) {
		return false;
	}
	section_offset->section_index = section_index;
	section_offset->offset = offset;
	return true;
}

static bool symbol_name_parse(RzBuffer *b, PDBSymbolKind kind, char **result) {
	if (kind < S_ST_MAX) {
		return buf_read_u8_pascal_string(b, result);
	} else {
		return rz_buf_read_string(b, result) > 0;
	}
	return false;
}

RZ_IPI bool PDBSData_parse(RzBuffer *b, PDBSymbolKind kind, PDBSData *sdata) {
	if (!sdata) {
		return false;
	}

	if (!(rz_buf_read_le32(b, &sdata->type_index) &&
		    PDBSectionOffset_parse(b, &sdata->offset) &&
		    symbol_name_parse(b, kind, &sdata->name))) {
		return false;
	}

	switch (kind) {
	case S_GMANDATA:
	case S_GMANDATA_ST:
		sdata->managed = true;
		sdata->global = true;
		break;
	case S_GDATA32:
	case S_GDATA32_ST:
		sdata->global = true;
		break;
	case S_LMANDATA:
	case S_LMANDATA_ST:
		sdata->managed = true;
		break;
	default: break;
	}
	return true;
}

RZ_IPI bool PDBSPublic_parse(RzBuffer *b, PDBSymbolKind kind, PDBSPublic *s) {
	map_err(b && s);
	ut32 flags = 0;
	map_err(rz_buf_read_le32(b, &flags) &&
		PDBSectionOffset_parse(b, &s->offset) &&
		symbol_name_parse(b, kind, &s->name));
	s->code = flags & cvpsfCode;
	s->function = flags & cvpsfFunction;
	s->managed = flags & cvpsfManaged;
	s->msil = flags & cvpsfMSIL;
	return true;
err:
	return false;
}

RZ_IPI bool PDBSymbol_parse(RzBuffer *b, PDBSymbol *symbol) {
	if (!symbol) {
		return false;
	}
	map_err(rz_buf_read_le16(b, &symbol->raw_kind));

	switch (symbol->raw_kind) {
	case S_LDATA32:
	case S_LDATA32_ST:
	case S_GDATA32:
	case S_GDATA32_ST:
	case S_LMANDATA:
	case S_LMANDATA_ST:
	case S_GMANDATA:
	case S_GMANDATA_ST:
		symbol->kind = PDB_Data;
		symbol->data = RZ_NEW0(PDBSData);
		map_err(symbol->data);
		map_err(PDBSData_parse(b, symbol->raw_kind, symbol->data));
		break;
	case S_PUB32:
	case S_PUB32_ST:
		symbol->kind = PDB_Public;
		symbol->data = RZ_NEW0(PDBSPublic);
		map_err(symbol->data);
		map_err(PDBSPublic_parse(b, symbol->raw_kind, symbol->data));
		break;
	default:
		RZ_LOG_DEBUG("unimplemented symbol kind: 0x%" PFMT32x "\n", symbol->raw_kind);
		break;
	}

	return true;
err:
	return false;
}

RZ_IPI bool PDBSymbolTable_iter(PDBSymbolTable *symbol_table, PDBSymbolIter *iter) {
	map_err(symbol_table && iter);
	iter->b = rz_buf_new_with_buf(symbol_table->b);
	return true;
err:
	return false;
}

RZ_IPI PDBSymbol *PDBSymbolTable_symbol_by_index(PDBSymbolTable *symbol_table, PDBSymbolIndex index) {
	PDBSymbolIter iter = { 0 };
	PDBSymbol *symbol = NULL;
	map_err(PDBSymbolTable_iter(symbol_table, &iter));
	map_err(PDBSymbolIter_seek(&iter, index));
	symbol = RZ_NEW0(PDBSymbol);
	map_err(symbol);
	map_err(PDBSymbolIter_next(&iter, symbol));

	return symbol;
err:
	free(symbol);
	return NULL;
}

RZ_IPI bool PDBSymbolIter_next(PDBSymbolIter *iter, PDBSymbol *symbol) {
	if (!iter) {
		return false;
	}
	RzBuffer *b = NULL;

	while (rz_buf_tell(iter->b) < rz_buf_size(iter->b)) {
		PDBSymbolIndex index = rz_buf_tell(iter->b);
		ut16 length = 0;
		map_err(rz_buf_read_le16(iter->b, &length));
		if (length < 2) {
			return false;
		}
		const ut64 begin = rz_buf_tell(iter->b);
		rz_buf_seek(iter->b, length, RZ_BUF_CUR);
		if (!symbol) {
			goto loop_continue;
		}

		b = rz_buf_new_slice(iter->b, begin, length);
		map_err(b);
		symbol->index = index;
		symbol->length = length;
		map_err(PDBSymbol_parse(b, symbol));

		switch (symbol->raw_kind) {
		case S_ALIGN:
		case S_SKIP:
			goto loop_continue;
		default:
			if (!symbol->data) {
				goto loop_continue;
			}
			rz_buf_free(b);
			return true;
		}
	loop_continue:
		rz_buf_free(b);
		b = NULL;
	}
err:
	rz_buf_free(b);
	return false;
}

RZ_IPI bool PDBSymbolIter_seek(PDBSymbolIter *iter, PDBSymbolIndex index) {
	map_err(iter);
	rz_buf_seek(iter->b, index, RZ_BUF_SET);
	return true;
err:
	return false;
}

static void PDBSymbol_free(void *x) {
	if (!x) {
		return;
	}
	PDBSymbol *symbol = x;
	if (symbol->data) {
		switch (symbol->kind) {
		case PDB_Public: {
			PDBSPublic *d = symbol->data;
			free(d->name);
			break;
		}
		case PDB_Data: {
			PDBSData *d = symbol->data;
			free(d->name);
			break;
		}
		default: rz_warn_if_reached(); break;
		}
		free(symbol->data);
	}
	free(symbol);
}

RZ_IPI bool PDBSymbolIter_collect(PDBSymbolIter *iter, RzPVector /*<PDBSymbol *>*/ **psymbols) {
	RzPVector *symbols = *psymbols = rz_pvector_new(PDBSymbol_free);
	if (!symbols) {
		return false;
	}
	while (true) {
		PDBSymbol *symbol = RZ_NEW0(PDBSymbol);
		if (!symbol) {
			rz_pvector_free(symbols);
			psymbols = NULL;
			return false;
		}
		if (!PDBSymbolIter_next(iter, symbol)) {
			break;
		}
		rz_pvector_push(symbols, symbol);
	}
	return true;
}

RZ_API bool rz_pdb_all_symbols_foreach(
	RZ_BORROW RZ_NONNULL RzPdb *pdb,
	RZ_BORROW RZ_NONNULL bool (*f)(RzPdb *, const PDBSymbol *, void *),
	RZ_BORROW RZ_NULLABLE void *u) {
	rz_return_val_if_fail(pdb && f, false);
	if (!(pdb->s_gdata && pdb->s_gdata->global_symbols)) {
		return true;
	}
	void **it;
	rz_pvector_foreach (pdb->s_gdata->global_symbols, it) {
		if (!f(pdb, *it, u)) {
			return false;
		}
	}
	if (!pdb->module_infos) {
		return true;
	}
	void **modit;
	rz_pvector_foreach (pdb->module_infos, modit) {
		PDBModuleInfo *modi = *modit;
		if (!modi->symbols) {
			continue;
		}
		rz_pvector_foreach (modi->symbols, it) {
			if (!f(pdb, *it, u)) {
				return false;
			}
		}
	}
	return true;
}
