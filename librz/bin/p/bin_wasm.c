/* rizin - LGPL - Copyright 2017-2019 - pancake, cgvwzq */

// http://webassembly.org/docs/binary-encoding/#module-structure

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "wasm/wasm.h"
#include "../format/wasm/wasm.h"

static bool check_buffer (RBuffer *rbuf) {
	ut8 buf[4] = { 0 };
	return rbuf && rz_buf_read_at (rbuf, 0, buf, 4) == 4 && !memcmp (buf, R_BIN_WASM_MAGIC_BYTES, 4);
}

static bool find_export (const ut32 *p, const RBinWasmExportEntry *q) {
	if (q->kind != R_BIN_WASM_EXTERNALKIND_Function) {
		return true;
	}
	return q->index != (*p);
}

static bool load_buffer (RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	rz_return_val_if_fail (bf && buf && rz_buf_size (buf) != UT64_MAX, NULL);

	if (check_buffer (buf)) {
		*bin_obj = rz_bin_wasm_init (bf, buf);
		return true;
	}
	return false;
}

static void destroy (RBinFile *bf) {
	rz_bin_wasm_destroy (bf);
}

static ut64 baddr (RBinFile *bf) {
	return 0;
}

static RBinAddr *binsym (RBinFile *bf, int type) {
	return NULL; // TODO
}

static RzList *sections (RBinFile *bf);

static RzList *entries (RBinFile *bf) {
	RBinWasmObj *bin = bf && bf->o ? bf->o->bin_obj : NULL;
	// TODO
	RzList *ret = NULL;
	RBinAddr *ptr = NULL;
	ut64 addr = 0x0;

	if (!(ret = rz_list_newf ((RzListFree)free))) {
		return NULL;
	}

	addr = (ut64)rz_bin_wasm_get_entrypoint (bin);
	if (!addr) {
		RzList *codes = rz_bin_wasm_get_codes (bin);
		if (codes) {
			RzListIter *iter;
			RBinWasmCodeEntry *func;
			rz_list_foreach (codes, iter, func) {
				addr = func->code;
				break;
			}
		}
		if (!addr) {
			rz_list_free (ret);
			return NULL;
		}
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = addr;
		ptr->vaddr = addr;
		rz_list_append (ret, ptr);
	}
	return ret;
}

static RzList *sections (RBinFile *bf) {
	RBinWasmObj *bin = bf && bf->o ? bf->o->bin_obj : NULL;
	RzList *ret = NULL;
	RzList *secs = NULL;
	RBinSection *ptr = NULL;
	RBinWasmSection *sec;

	if (!(ret = rz_list_newf ((RzListFree)free))) {
		return NULL;
	}
	if (!(secs = rz_bin_wasm_get_sections (bin))) {
		rz_list_free (ret);
		return NULL;
	}
	RzListIter *iter;
	rz_list_foreach (secs, iter, sec) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			rz_list_free (secs);
			rz_list_free (ret);
			return NULL;
		}
		ptr->name = strdup ((char *)sec->name);
		if (sec->id == R_BIN_WASM_SECTION_DATA || sec->id == R_BIN_WASM_SECTION_MEMORY) {
			ptr->is_data = true;
		}
		ptr->size = sec->payload_len;
		ptr->vsize = sec->payload_len;
		ptr->vaddr = sec->offset;
		ptr->paddr = sec->offset;
		ptr->add = true;
		// TODO permissions
		ptr->perm = 0;
		rz_list_append (ret, ptr);
	}
	return ret;
}

static RzList *symbols (RBinFile *bf) {
	RBinWasmObj *bin = NULL;
	RzList *ret = NULL, *codes = NULL, *imports = NULL, *exports = NULL;
	RBinSymbol *ptr = NULL;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = bf->o->bin_obj;
	if (!(ret = rz_list_newf ((RzListFree)free))) {
		return NULL;
	}
	if (!(codes = rz_bin_wasm_get_codes (bin))) {
		goto bad_alloc;
	}
	if (!(imports = rz_bin_wasm_get_imports (bin))) {
		goto bad_alloc;
	}
	if (!(exports = rz_bin_wasm_get_exports (bin))) {
		goto bad_alloc;
	}

	ut32 fcn_idx = 0,
	     table_idx = 0,
	     mem_idx = 0,
	     global_idx = 0;

	ut32 i = 0;
	RBinWasmImportEntry *imp;
	RzListIter *iter;
	rz_list_foreach (imports, iter, imp) {
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			goto bad_alloc;
		}
		ptr->name = strdup (imp->field_str);
		ptr->libname = strdup (imp->module_str);
		ptr->is_imported = true;
		ptr->forwarder = "NONE";
		ptr->bind = "NONE";
		switch (imp->kind) {
		case R_BIN_WASM_EXTERNALKIND_Function:
			ptr->type = R_BIN_TYPE_FUNC_STR;
			fcn_idx++;
			break;
		case R_BIN_WASM_EXTERNALKIND_Table:
			ptr->type = "TABLE";
			table_idx++;
			break;
		case R_BIN_WASM_EXTERNALKIND_Memory:
			ptr->type = "MEMORY";
			mem_idx++;
			break;
		case R_BIN_WASM_EXTERNALKIND_Global:
			ptr->type = R_BIN_BIND_GLOBAL_STR;
			global_idx++;
			break;
		}
		ptr->size = 0;
		ptr->vaddr = -1;
		ptr->paddr = -1;
		ptr->ordinal = i;
		i += 1;
		rz_list_append (ret, ptr);
	}

	RzListIter *is_exp = NULL;
	RBinWasmCodeEntry *func;
	// RBinWasmExportEntry *export = NULL;
	rz_list_foreach (codes, iter, func) {
		if (!(ptr = R_NEW0 (RBinSymbol))) {
			goto bad_alloc;
		}

		const char *fcn_name = rz_bin_wasm_get_function_name (bin, fcn_idx);
		if (fcn_name) {
			ptr->name = strdup (fcn_name);

			is_exp = rz_list_find (exports, &fcn_idx, (RzListComparator)find_export);
			if (is_exp) {
				ptr->bind = R_BIN_BIND_GLOBAL_STR;
			}
		} else {
			// fallback if symbol is not found.
			ptr->name = rz_str_newf ("fcn.%d", fcn_idx);
		}

		ptr->forwarder = "NONE";
		if (!ptr->bind) {
			ptr->bind = "NONE";
		}
		ptr->type = R_BIN_TYPE_FUNC_STR;
		ptr->size = func->len;
		ptr->vaddr = (ut64)func->code;
		ptr->paddr = (ut64)func->code;
		ptr->ordinal = i;
		i++;
		fcn_idx++;
		rz_list_append (ret, ptr);
	}

	// TODO: globals, tables and memories
	return ret;
bad_alloc:
	// not so sure if imports should be freed.
	rz_list_free (exports);
	rz_list_free (codes);
	rz_list_free (ret);
	return NULL;
}

static RzList *imports (RBinFile *bf) {
	RBinWasmObj *bin = NULL;
	RzList *imports = NULL;
	RBinImport *ptr = NULL;
	RzList *ret = NULL;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	bin = bf->o->bin_obj;
	if (!(ret = rz_list_newf (rz_bin_import_free))) {
		return NULL;
	}
	if (!(imports = rz_bin_wasm_get_imports (bin))) {
		goto bad_alloc;
	}

	RBinWasmImportEntry *import = NULL;
	ut32 i = 0;
	RzListIter *iter;
	rz_list_foreach (imports, iter, import) {
		if (!(ptr = R_NEW0 (RBinImport))) {
			goto bad_alloc;
		}
		ptr->name = strdup (import->field_str);
		ptr->classname = strdup (import->module_str);
		ptr->ordinal = i;
		ptr->bind = "NONE";
		switch (import->kind) {
		case R_BIN_WASM_EXTERNALKIND_Function:
			ptr->type = "FUNC";
			break;
		case R_BIN_WASM_EXTERNALKIND_Table:
			ptr->type = "TABLE";
			break;
		case R_BIN_WASM_EXTERNALKIND_Memory:
			ptr->type = "MEM";
			break;
		case R_BIN_WASM_EXTERNALKIND_Global:
			ptr->type = "GLOBAL";
			break;
		}
		rz_list_append (ret, ptr);
	}
	return ret;
bad_alloc:
	rz_list_free (imports);
	rz_list_free (ret);
	return NULL;
}

static RzList *libs (RBinFile *bf) {
	return NULL;
}

static RBinInfo *info (RBinFile *bf) {
	RBinInfo *ret = NULL;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->bclass = strdup ("module");
	ret->rclass = strdup ("wasm");
	ret->os = strdup ("WebAssembly");
	ret->arch = strdup ("wasm");
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("wasm");
	ret->type = strdup ("EXEC");
	ret->bits = 32;
	ret->has_va = 0;
	ret->big_endian = false;
	ret->dbg_info = 0;
	return ret;
}

static ut64 size (RBinFile *bf) {
	if (!bf || !bf->buf) {
		return 0;
	}
	return rz_buf_size (bf->buf);
}

/* inspired in http://www.phreedom.org/solar/code/tinype/tiny.97/tiny.asm */
static RBuffer *create (RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen, RBinArchOptions *opt) {
	RBuffer *buf = rz_buf_new ();
#define B(x, y) rz_buf_append_bytes (buf, (const ut8 *)(x), y)
#define D(x) rz_buf_append_ut32 (buf, x)
	B ("\x00"
	   "asm",
		4);
	B ("\x01\x00\x00\x00", 4);
	return buf;
}

RBinPlugin rz_bin_plugin_wasm = {
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
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.create = &create,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_wasm,
	.version = R2_VERSION
};
#endif
