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

RzBinPlugin rz_bin_plugin_wasm = {
	.name = "wasm",
	.desc = "WebAssembly bin plugin",
	.license = "MIT",
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
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_wasm,
	.version = RZ_VERSION
};
#endif
