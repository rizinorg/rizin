// SPDX-FileCopyrightText: 2017-2021 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2021 cgvwzq
// SPDX-License-Identifier: LGPL-3.0-only

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "wasm/wasm.h"
#include "../format/wasm/wasm.h"

static bool check_buffer(RzBuffer *rbuf) {
	ut8 buf[4] = { 0 };
	return rbuf && rz_buf_read_at(rbuf, 0, buf, 4) == 4 && !memcmp(buf, RZ_BIN_WASM_MAGIC_BYTES, 4);
}

static bool find_export(const ut32 *p, const RzBinWasmExportEntry *q, void *user) {
	if (q->kind != RZ_BIN_WASM_EXTERNALKIND_Function) {
		return true;
	}
	return q->index != (*p);
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	rz_return_val_if_fail(bf && buf && rz_buf_size(buf) != UT64_MAX, false);

	if (check_buffer(buf)) {
		obj->bin_obj = rz_bin_wasm_init(bf, buf);
		return true;
	}
	return false;
}

static void destroy(RzBinFile *bf) {
	rz_bin_wasm_destroy(bf);
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol type) {
	return NULL; // TODO
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf);

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzBinWasmObj *bin = bf && bf->o ? bf->o->bin_obj : NULL;
	// TODO
	RzPVector *ret = NULL;
	RzBinAddr *ptr = NULL;
	ut64 addr = 0x0;

	if (!(ret = rz_pvector_new((RzPVectorFree)free))) {
		return NULL;
	}

	addr = (ut64)rz_bin_wasm_get_entrypoint(bin);
	if (!addr) {
		RzList *codes = rz_bin_wasm_get_codes(bin);
		if (codes) {
			RzListIter *iter;
			RzBinWasmCodeEntry *func;
			rz_list_foreach (codes, iter, func) {
				addr = func->code;
				break;
			}
		}
		if (!addr) {
			rz_pvector_free(ret);
			return NULL;
		}
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		ptr->paddr = addr;
		ptr->vaddr = addr;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzBinWasmObj *bin = bf && bf->o ? bf->o->bin_obj : NULL;
	RzPVector *ret = NULL;
	RzList *secs = NULL;
	RzBinSection *ptr = NULL;
	RzBinWasmSection *sec;

	if (!(ret = rz_pvector_new((RzPVectorFree)free))) {
		return NULL;
	}
	if (!(secs = rz_bin_wasm_get_sections(bin))) {
		rz_pvector_free(ret);
		return NULL;
	}
	RzListIter *iter;
	rz_list_foreach (secs, iter, sec) {
		if (!(ptr = RZ_NEW0(RzBinSection))) {
			rz_list_free(secs);
			rz_pvector_free(ret);
			return NULL;
		}
		ptr->name = rz_str_dup((char *)sec->name);
		if (sec->id == RZ_BIN_WASM_SECTION_DATA || sec->id == RZ_BIN_WASM_SECTION_MEMORY) {
			ptr->is_data = true;
		}
		ptr->size = sec->payload_len;
		ptr->vsize = sec->payload_len;
		ptr->vaddr = sec->offset;
		ptr->paddr = sec->offset;
		// TODO permissions
		ptr->perm = 0;
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzBinWasmObj *bin = NULL;
	RzList *codes = NULL, *imports = NULL, *exports = NULL;
	RzPVector *ret = NULL;
	RzBinSymbol *ptr = NULL;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = bf->o->bin_obj;
	if (!(ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free))) {
		return NULL;
	}
	if (!(codes = rz_bin_wasm_get_codes(bin))) {
		goto bad_alloc;
	}
	if (!(imports = rz_bin_wasm_get_imports(bin))) {
		goto bad_alloc;
	}
	if (!(exports = rz_bin_wasm_get_exports(bin))) {
		goto bad_alloc;
	}

	ut32 fcn_idx = 0;
	ut32 i = 0;
	RzBinWasmImportEntry *imp;
	RzListIter *iter;
	rz_list_foreach (imports, iter, imp) {
		if (!(ptr = RZ_NEW0(RzBinSymbol))) {
			goto bad_alloc;
		}
		ptr->name = rz_str_dup(imp->field_str);
		ptr->libname = rz_str_dup(imp->module_str);
		ptr->is_imported = true;
		ptr->forwarder = "NONE";
		ptr->bind = "NONE";
		switch (imp->kind) {
		case RZ_BIN_WASM_EXTERNALKIND_Function:
			ptr->type = RZ_BIN_TYPE_FUNC_STR;
			fcn_idx++;
			break;
		case RZ_BIN_WASM_EXTERNALKIND_Table:
			ptr->type = "TABLE";
			break;
		case RZ_BIN_WASM_EXTERNALKIND_Memory:
			ptr->type = "MEMORY";
			break;
		case RZ_BIN_WASM_EXTERNALKIND_Global:
			ptr->type = RZ_BIN_BIND_GLOBAL_STR;
			break;
		}
		ptr->size = 0;
		ptr->vaddr = -1;
		ptr->paddr = -1;
		ptr->ordinal = i;
		i += 1;
		rz_pvector_push(ret, ptr);
	}

	RzListIter *is_exp = NULL;
	RzBinWasmCodeEntry *func;
	// RzBinWasmExportEntry *export = NULL;
	rz_list_foreach (codes, iter, func) {
		if (!(ptr = RZ_NEW0(RzBinSymbol))) {
			goto bad_alloc;
		}

		const char *fcn_name = rz_bin_wasm_get_function_name(bin, fcn_idx);
		if (fcn_name) {
			ptr->name = rz_str_dup(fcn_name);

			is_exp = rz_list_find(exports, &fcn_idx, (RzListComparator)find_export, NULL);
			if (is_exp) {
				ptr->bind = RZ_BIN_BIND_GLOBAL_STR;
			}
		} else {
			// fallback if symbol is not found.
			ptr->name = rz_str_newf("fcn.%d", fcn_idx);
		}

		ptr->forwarder = "NONE";
		if (!ptr->bind) {
			ptr->bind = "NONE";
		}
		ptr->type = RZ_BIN_TYPE_FUNC_STR;
		ptr->size = func->len;
		ptr->vaddr = (ut64)func->code;
		ptr->paddr = (ut64)func->code;
		ptr->ordinal = i;
		i++;
		fcn_idx++;
		rz_pvector_push(ret, ptr);
	}

	// TODO: globals, tables and memories
	return ret;
bad_alloc:
	// not so sure if imports should be freed.
	rz_list_free(exports);
	rz_list_free(codes);
	rz_pvector_free(ret);
	return NULL;
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	RzBinWasmObj *bin = NULL;
	RzList *imports = NULL;
	RzBinImport *ptr = NULL;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzListFree)rz_bin_import_free);
	if (!ret) {
		return NULL;
	}
	if (!(imports = rz_bin_wasm_get_imports(bin))) {
		goto bad_alloc;
	}

	RzBinWasmImportEntry *import = NULL;
	ut32 i = 0;
	RzListIter *iter;
	rz_list_foreach (imports, iter, import) {
		if (!(ptr = RZ_NEW0(RzBinImport))) {
			goto bad_alloc;
		}
		ptr->name = rz_str_dup(import->field_str);
		ptr->classname = rz_str_dup(import->module_str);
		ptr->ordinal = i;
		ptr->bind = "NONE";
		switch (import->kind) {
		case RZ_BIN_WASM_EXTERNALKIND_Function:
			ptr->type = "FUNC";
			break;
		case RZ_BIN_WASM_EXTERNALKIND_Table:
			ptr->type = "TABLE";
			break;
		case RZ_BIN_WASM_EXTERNALKIND_Memory:
			ptr->type = "MEM";
			break;
		case RZ_BIN_WASM_EXTERNALKIND_Global:
			ptr->type = "GLOBAL";
			break;
		}
		rz_pvector_push(ret, ptr);
	}
	return ret;
bad_alloc:
	rz_list_free(imports);
	rz_pvector_free(ret);
	return NULL;
}

static RzPVector /*<char *>*/ *libs(RzBinFile *bf) {
	return NULL;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;

	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("module");
	ret->rclass = rz_str_dup("wasm");
	ret->os = rz_str_dup("WebAssembly");
	ret->arch = rz_str_dup("wasm");
	ret->machine = rz_str_dup(ret->arch);
	ret->subsystem = rz_str_dup("wasm");
	ret->type = rz_str_dup("EXEC");
	ret->bits = 32;
	ret->has_va = 0;
	ret->big_endian = false;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size(RzBinFile *bf) {
	if (!bf || !bf->buf) {
		return 0;
	}
	return rz_buf_size(bf->buf);
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RzBuffer *create(RzBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RzBinArchOptions *opt) {
	RzBuffer *buf = rz_buf_new_with_bytes(NULL, 0);
#define B(x, y) rz_buf_append_bytes(buf, (const ut8 *)(x), y)
#define D(x)    rz_buf_append_ut32(buf, x)
	B("\x00"
	  "asm",
		4);
	B("\x01\x00\x00\x00", 4);
	return buf;
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	// The WebAssembly standard defines names in UTF-8:
	// https://webassembly.github.io/spec/core/bikeshed/#binary-utf8
	opt.string_encoding = RZ_STRING_ENC_UTF8;
	return rz_bin_file_strings(bf, &opt);
}

static RzStructuredData *wasm_sections_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_sections) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmSection *section;

	rz_list_foreach (bin->g_sections, it, section) {
		if (!section) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "id", section->id, false);
		rz_structured_data_map_add_unsigned(m, "size", section->size, false);
		rz_structured_data_map_add_unsigned(m, "name_len", section->name_len, false);
		rz_structured_data_map_add_unsigned(m, "offset", section->offset, true);
		rz_structured_data_map_add_unsigned(m, "payload_data", section->payload_data, true);
		rz_structured_data_map_add_unsigned(m, "payload_len", section->payload_len, false);
		rz_structured_data_map_add_unsigned(m, "count", section->count, false);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_types_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_types) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmTypeEntry *type;

	rz_list_foreach (bin->g_types, it, type) {
		if (!type) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "form", type->form, false);
		rz_structured_data_map_add_unsigned(m, "param_count", type->param_count, false);
		rz_structured_data_map_add_signed(m, "return_count", type->return_count);
		rz_structured_data_map_add_unsigned(m, "return_type", type->return_type, false);

		if (type->param_types && type->param_count) {
			RzStructuredData *params = rz_structured_data_new_array();
			if (!params) {
				rz_structured_data_free(arr);
				rz_structured_data_free(m);
				return NULL;
			}
			for (ut32 i = 0; i < type->param_count; i++) {
				rz_structured_data_array_add_unsigned(params, type->param_types[i], false);
			}
			rz_structured_data_map_add(m, "param_types", params);
		}

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_imports_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_imports) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmImportEntry *import;

	rz_list_foreach (bin->g_imports, it, import) {
		if (!import) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "module_len", import->module_len, false);
		rz_structured_data_map_add_unsigned(m, "field_len", import->field_len, false);
		rz_structured_data_map_add_unsigned(m, "kind", import->kind, false);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_tables_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_tables) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmTableEntry *table;

	rz_list_foreach (bin->g_tables, it, table) {
		if (!table) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "element_type", table->element_type, false);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_memories_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_memories) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmMemoryEntry *memory;

	rz_list_foreach (bin->g_memories, it, memory) {
		if (!memory) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_globals_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_globals) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmGlobalEntry *global;

	rz_list_foreach (bin->g_globals, it, global) {
		if (!global) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "content_type", global->content_type, false);
		rz_structured_data_map_add_unsigned(m, "mutability", global->mutability, false);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_exports_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_exports) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmExportEntry *export;

	rz_list_foreach (bin->g_exports, it, export) {
		if (!export) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "field_len", export->field_len, false);
		rz_structured_data_map_add_unsigned(m, "kind", export->kind, false);
		rz_structured_data_map_add_unsigned(m, "index", export->index, false);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_elements_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_elements) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmElementEntry *element;

	rz_list_foreach (bin->g_elements, it, element) {
		if (!element) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "index", element->index, false);
		rz_structured_data_map_add_unsigned(m, "num_elem", element->num_elem, false);

		if (element->num_elem) {
			RzStructuredData *elems = rz_structured_data_new_array();
			if (!elems) {
				rz_structured_data_free(arr);
				rz_structured_data_free(m);
				return NULL;
			}
			for (ut32 i = 0; i < element->num_elem; i++) {
				rz_structured_data_array_add_unsigned(elems, element->elems[i], false);
			}
			rz_structured_data_map_add(m, "elems", elems);
		}

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_codes_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_codes) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmCodeEntry *code;

	rz_list_foreach (bin->g_codes, it, code) {
		if (!code) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "body_size", code->body_size, false);
		rz_structured_data_map_add_unsigned(m, "local_count", code->local_count, false);
		rz_structured_data_map_add_unsigned(m, "code", code->code, true);
		rz_structured_data_map_add_unsigned(m, "len", code->len, false);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_datas_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinWasmObj *bin = bf->o->bin_obj;

	if (!bin->g_datas) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	RzBinWasmDataEntry *data;

	rz_list_foreach (bin->g_datas, it, data) {
		if (!data) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "index", data->index, false);
		rz_structured_data_map_add_unsigned(m, "size", data->size, false);
		rz_structured_data_map_add_unsigned(m, "data", data->data, true);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *wasm_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzBinWasmObj *bin = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *wasm_sd = rz_structured_data_map_add_map(info, "wasm");
	if (!wasm_sd) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(wasm_sd, "size", bin->size, false);
	rz_structured_data_map_add_unsigned(wasm_sd, "entrypoint", bin->entrypoint, true);

	RzStructuredData *sections = wasm_sections_structure(bf);
	if (sections) {
		rz_structured_data_map_add(wasm_sd, "sections", sections);
	}

	RzStructuredData *types = wasm_types_structure(bf);
	if (types) {
		rz_structured_data_map_add(wasm_sd, "types", types);
	}

	RzStructuredData *imports = wasm_imports_structure(bf);
	if (imports) {
		rz_structured_data_map_add(wasm_sd, "imports", imports);
	}

	RzStructuredData *tables = wasm_tables_structure(bf);
	if (tables) {
		rz_structured_data_map_add(wasm_sd, "tables", tables);
	}

	RzStructuredData *memories = wasm_memories_structure(bf);
	if (memories) {
		rz_structured_data_map_add(wasm_sd, "memories", memories);
	}

	RzStructuredData *globals = wasm_globals_structure(bf);
	if (globals) {
		rz_structured_data_map_add(wasm_sd, "globals", globals);
	}

	RzStructuredData *exports = wasm_exports_structure(bf);
	if (exports) {
		rz_structured_data_map_add(wasm_sd, "exports", exports);
	}

	RzStructuredData *elements = wasm_elements_structure(bf);
	if (elements) {
		rz_structured_data_map_add(wasm_sd, "elements", elements);
	}

	RzStructuredData *codes = wasm_codes_structure(bf);
	if (codes) {
		rz_structured_data_map_add(wasm_sd, "codes", codes);
	}

	RzStructuredData *datas = wasm_datas_structure(bf);
	if (datas) {
		rz_structured_data_map_add(wasm_sd, "datas", datas);
	}

	return info;
}

RzBinPlugin rz_bin_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly",
	.license = "MIT",
	.author = "pancake",
	.load_buffer = &load_buffer,
	.size = &size,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.create = &create,
	.strings = &strings,
	.bin_structure = &wasm_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_wasm,
	.version = RZ_VERSION
};
#endif
