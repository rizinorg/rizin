// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017 cgvwzq
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#include "wasm.h"

typedef size_t (*ConsumeFcn)(const ut8 *p, const ut8 *max, ut32 *out_value);
typedef void *(*ParseEntryFcn)(RzBuffer *b, ut64 max);

// RzBuffer consume functions
static ut32 consume_r(RzBuffer *b, ut64 max, size_t *n_out, ConsumeFcn consume_fcn) {
	rz_return_val_if_fail(b && n_out && consume_fcn, 0);

	size_t n;
	ut32 tmp;
	ut64 cur = rz_buf_tell(b);
	if (max >= rz_buf_size(b) || cur > max) {
		return 0;
	}
	// 16 bytes are enough to store 128bits values
	ut8 *buf = RZ_NEWS(ut8, 16);
	if (!buf) {
		return 0;
	}
	rz_buf_read(b, buf, 16);
	if (!(n = consume_fcn(buf, buf + max + 1, &tmp))) {
		free(buf);
		return 0;
	}
	rz_buf_seek(b, cur + n, RZ_BUF_SET);
	*n_out = n;
	free(buf);
	return tmp;
}

static size_t consume_u32_r(RzBuffer *b, ut64 max, ut32 *out) {
	size_t n = 0;
	ut32 tmp = consume_r(b, max, &n, read_u32_leb128);
	if (out) {
		*out = tmp;
	}
	return n;
}

static size_t consume_u7_r(RzBuffer *b, ut64 max, ut8 *out) {
	size_t n = 0;
	ut32 tmp = consume_r(b, max, &n, read_u32_leb128);
	if (out) {
		*out = (ut8)(tmp & 0x7f);
	}
	return n;
}

static size_t consume_s7_r(RzBuffer *b, ut64 max, st8 *out) {
	size_t n = 0;
	ut32 tmp = consume_r(b, max, &n, (ConsumeFcn)read_i32_leb128);
	if (out) {
		*out = (st8)(((tmp & 0x10000000) << 7) | (tmp & 0x7f));
	}
	return n;
}

static size_t consume_u1_r(RzBuffer *b, ut64 max, ut8 *out) {
	size_t n = 0;
	ut32 tmp = consume_r(b, max, &n, read_u32_leb128);
	if (out) {
		*out = (ut8)(tmp & 0x1);
	}
	return n;
}

static size_t consume_str_r(RzBuffer *b, ut64 max, size_t sz, char *out) {
	ut64 cur = rz_buf_tell(b);
	if (!b || max >= rz_buf_size(b) || cur > max) {
		return 0;
	}
	if (!(cur + sz - 1 <= max)) {
		return 0;
	}
	if (sz > 0) {
		rz_buf_read(b, (ut8 *)out, RZ_MIN(RZ_BIN_WASM_STRING_LENGTH - 1, sz));
	} else {
		*out = 0;
	}
	return sz;
}

static size_t consume_init_expr_r(RzBuffer *b, ut64 max, ut8 eoc, void *out) {
	if (!b || max >= rz_buf_size(b) || rz_buf_tell(b) > max) {
		return 0;
	}
	size_t res = 0;
	ut8 cur = rz_buf_read8(b);
	while (rz_buf_tell(b) <= max && cur != eoc) {
		cur = rz_buf_read8(b);
		res++;
	}
	if (cur != eoc) {
		return 0;
	}
	return res + 1;
}

static size_t consume_locals_r(RzBuffer *b, ut64 max, RzBinWasmCodeEntry *out) {
	ut64 cur = rz_buf_tell(b);
	if (!b || max >= rz_buf_size(b) || cur > max) {
		return 0;
	}
	ut32 count = out ? out->local_count : 0;
	if (count > 0) {
		if (!(out->locals = RZ_NEWS0(struct rz_bin_wasm_local_entry_t, count))) {
			return 0;
		}
	}
	ut32 j = 0;
	while (rz_buf_tell(b) <= max && j < count) {
		if (!(consume_u32_r(b, max, (out ? &out->locals[j].count : NULL)))) {
			goto beach;
		}
		if (!(consume_s7_r(b, max, (out ? (st8 *)&out->locals[j].type : NULL)))) {
			goto beach;
		}
		j++;
	}
	if (j != count) {
		goto beach;
	}
	return j;
beach:
	RZ_FREE(out->locals);
	return 0;
}

static size_t consume_limits_r(RzBuffer *b, ut64 max, struct rz_bin_wasm_resizable_limits_t *out) {
	if (!b || max >= rz_buf_size(b) || rz_buf_tell(b) > max || !out) {
		return 0;
	}
	ut32 i = rz_buf_tell(b);
	if (!(consume_u7_r(b, max, &out->flags))) {
		return 0;
	}
	if (!(consume_u32_r(b, max, &out->initial))) {
		return 0;
	}
	if (out->flags && (!(consume_u32_r(b, max, &out->maximum)))) {
		return 0;
	}
	return (size_t)RZ_ABS(rz_buf_tell(b) - i);
}

// Utils
static RzList *rz_bin_wasm_get_sections_by_id(RzList *sections, ut8 id) {
	RzBinWasmSection *sec = NULL;
	RzList *ret = rz_list_newf(NULL);
	if (!ret) {
		return NULL;
	}
	RzListIter *iter;
	rz_list_foreach (sections, iter, sec) {
		if (sec->id == id) {
			rz_list_append(ret, sec);
		}
	}
	return ret;
}

#if 0
const char *rz_bin_wasm_valuetype_to_string (rz_bin_wasm_value_type_t type) {
	switch (type) {
	case RZ_BIN_WASM_VALUETYPE_i32:
		return "i32";
	case RZ_BIN_WASM_VALUETYPE_i64:
		return "i62";
	case RZ_BIN_WASM_VALUETYPE_f32:
		return "f32";
	case RZ_BIN_WASM_VALUETYPE_f64:
		return "f64";
	case RZ_BIN_WASM_VALUETYPE_ANYFUNC:
		return "ANYFUNC";
	case RZ_BIN_WASM_VALUETYPE_FUNC:
		return "FUNC";
	default:
		return "<?>";
	}
}

static char *rz_bin_wasm_type_entry_to_string(RzBinWasmTypeEntry *ptr) {
	if (!ptr) {
		return NULL;
	}
	char *buf = (char*)calloc (ptr->param_count, 5);
	if (!buf) {
		return NULL;
	}
	int p;
	for (p = 0; p < ptr->param_count; p++) {
		strcat (buf, rz_bin_wasm_valuetype_to_string (ptr->param_types[p]));
		if (p < ptr->param_count - 1) {
			strcat (buf, ", ");
		}
	}
	snprintf (ptr->to_str, RZ_BIN_WASM_STRING_LENGTH, "(%s) -> (%s)",
		(ptr->param_count > 0? buf: ""),
		(ptr->return_count == 1? rz_bin_wasm_valuetype_to_string (ptr->return_type): ""));
	free (buf);
	return ptr->to_str;
}
#endif

// Free
static void rz_bin_wasm_free_types(RzBinWasmTypeEntry *ptr) {
	if (ptr) {
		free(ptr->param_types);
	}
	free(ptr);
}

static void rz_bin_wasm_free_codes(RzBinWasmCodeEntry *ptr) {
	if (ptr) {
		free(ptr->locals);
	}
	free(ptr);
}

// Parsing
static RzList *get_entries_from_section(RzBinWasmObj *bin, RzBinWasmSection *sec, ParseEntryFcn parse_entry, RzListFree free_entry) {
	rz_return_val_if_fail(sec && bin, NULL);

	RzList *ret = rz_list_newf(free_entry);
	if (!ret) {
		return NULL;
	}
	RzBuffer *b = bin->buf;
	rz_buf_seek(b, sec->payload_data, RZ_BUF_SET);
	ut32 r = 0;
	ut64 max = rz_buf_tell(b) + sec->payload_len - 1;
	if (!(max < rz_buf_size(b))) {
		goto beach;
	}
	while (rz_buf_tell(b) <= max && r < sec->count) {
		void *entry = parse_entry(b, max);
		if (!entry) {
			goto beach;
		}

		if (!rz_list_append(ret, entry)) {
			free_entry(entry);
			// should this jump to beach?
		}
		r++;
	}
	return ret;
beach:
	eprintf("[wasm] error: beach reading entries for section %s\n", sec->name);
	return ret;
}

static void *parse_type_entry(RzBuffer *b, ut64 max) {
	RzBinWasmTypeEntry *ptr = RZ_NEW0(RzBinWasmTypeEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_u7_r(b, max, &ptr->form))) {
		goto beach;
	}
	// check valid type?
	if (!(consume_u32_r(b, max, &ptr->param_count))) {
		goto beach;
	}
	ut32 count = ptr ? ptr->param_count : 0;
	if (!(rz_buf_tell(b) + count <= max)) {
		goto beach;
	}
	if (count > 0) {
		if (!(ptr->param_types = RZ_NEWS0(rz_bin_wasm_value_type_t, count))) {
			goto beach;
		}
	}
	int j;
	for (j = 0; j < count; j++) {
		if (!(consume_s7_r(b, max, (st8 *)&ptr->param_types[j]))) {
			goto beach;
		}
	}
	if (!(consume_u1_r(b, max, (ut8 *)&ptr->return_count))) {
		goto beach;
	}
	if (ptr->return_count > 1) {
		goto beach;
	}
	if (ptr->return_count == 1) {
		if (!(consume_s7_r(b, max, (st8 *)&ptr->return_type))) {
			goto beach;
		}
	}
	return ptr;

beach:
	rz_bin_wasm_free_types(ptr);
	return NULL;
}
static void *parse_import_entry(RzBuffer *b, ut64 max) {
	RzBinWasmImportEntry *ptr = RZ_NEW0(RzBinWasmImportEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_u32_r(b, max, &ptr->module_len))) {
		goto beach;
	}
	if (consume_str_r(b, max, ptr->module_len, ptr->module_str) < ptr->module_len) {
		goto beach;
	}
	if (!(consume_u32_r(b, max, &ptr->field_len))) {
		goto beach;
	}
	if (consume_str_r(b, max, ptr->field_len, ptr->field_str) < ptr->field_len) {
		goto beach;
	}
	if (!(consume_u7_r(b, max, &ptr->kind))) {
		goto beach;
	}
	switch (ptr->kind) {
	case 0: // Function
		if (!(consume_u32_r(b, max, &ptr->type_f))) {
			goto beach;
		}
		break;
	case 1: // Table
		if (!(consume_s7_r(b, max, (st8 *)&ptr->type_t.elem_type))) {
			goto beach;
		}
		if (!(consume_limits_r(b, max, &ptr->type_t.limits))) {
			goto beach;
		}
		break;
	case 2: // Memory
		if (!(consume_limits_r(b, max, &ptr->type_m.limits))) {
			goto beach;
		}
		break;
	case 3: // Global
		if (!(consume_s7_r(b, max, (st8 *)&ptr->type_g.content_type))) {
			goto beach;
		}
		if (!(consume_u1_r(b, max, (ut8 *)&ptr->type_g.mutability))) {
			goto beach;
		}
		break;
	default:
		goto beach;
	}
	return ptr;

beach:
	free(ptr);
	return NULL;
}

static void *parse_export_entry(RzBuffer *b, ut64 max) {
	RzBinWasmExportEntry *ptr = RZ_NEW0(RzBinWasmExportEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_u32_r(b, max, &ptr->field_len))) {
		goto beach;
	}
	if (consume_str_r(b, max, ptr->field_len, ptr->field_str) < ptr->field_len) {
		goto beach;
	}
	if (!(consume_u7_r(b, max, &ptr->kind))) {
		goto beach;
	}
	if (!(consume_u32_r(b, max, &ptr->index))) {
		goto beach;
	}
	return ptr;
beach:
	free(ptr);
	return NULL;
}

static void *parse_code_entry(RzBuffer *b, ut64 max) {
	RzBinWasmCodeEntry *ptr = RZ_NEW0(RzBinWasmCodeEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_u32_r(b, max, &ptr->body_size))) {
		goto beach;
	}
	ut32 j = rz_buf_tell(b);
	if (!(rz_buf_tell(b) + ptr->body_size - 1 <= max)) {
		goto beach;
	}
	if (!(consume_u32_r(b, max, &ptr->local_count))) {
		goto beach;
	}
	if (consume_locals_r(b, max, ptr) < ptr->local_count) {
		goto beach;
	}
	ptr->code = rz_buf_tell(b);
	ptr->len = ptr->body_size - ptr->code + j;
	rz_buf_seek(b, ptr->len - 1, RZ_BUF_CUR); // consume bytecode
	rz_buf_read(b, &ptr->byte, 1);
	if (ptr->byte != RZ_BIN_WASM_END_OF_CODE) {
		goto beach;
	}
	return ptr;

beach:
	rz_bin_wasm_free_codes(ptr);
	return NULL;
}

static void *parse_data_entry(RzBuffer *b, ut64 max) {
	RzBinWasmDataEntry *ptr = RZ_NEW0(RzBinWasmDataEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_u32_r(b, max, &ptr->index))) {
		goto beach;
	}
	if (!(ptr->offset.len = consume_init_expr_r(b, max, RZ_BIN_WASM_END_OF_CODE, NULL))) {
		goto beach;
	}
	if (!(consume_u32_r(b, max, &ptr->size))) {
		goto beach;
	}
	ptr->data = rz_buf_tell(b);
	rz_buf_seek(b, ptr->size, RZ_BUF_CUR);
	return ptr;

beach:
	free(ptr);
	return NULL;
}

static bool parse_namemap(RzBuffer *b, ut64 max, RzIDStorage *map, ut32 *count) {
	size_t i;
	if (!(consume_u32_r(b, max, count))) {
		return false;
	}

	for (i = 0; i < *count; i++) {
		struct rz_bin_wasm_name_t *name = RZ_NEW0(struct rz_bin_wasm_name_t);
		if (!name) {
			return false;
		}

		ut32 idx;
		if (!(consume_u32_r(b, max, &idx))) {
			RZ_FREE(name);
			return false;
		}

		if (!(consume_u32_r(b, max, &name->len))) {
			RZ_FREE(name);
			return false;
		}

		if (!(consume_str_r(b, max, name->len, (char *)name->name))) {
			RZ_FREE(name);
			return false;
		}
		name->name[name->len] = 0;

		if (!rz_id_storage_add(map, name, &idx)) {
			RZ_FREE(name);
			return false;
		};
	}

	return true;
}

static void *parse_custom_name_entry(RzBuffer *b, ut64 max) {
	RzBinWasmCustomNameEntry *ptr = NULL;
	size_t i;
	if (!(ptr = RZ_NEW0(RzBinWasmCustomNameEntry))) {
		return NULL;
	}

	if (!(consume_u7_r(b, max, &ptr->type))) {
		goto beach;
	};

	if (!(consume_u32_r(b, max, &ptr->size))) {
		goto beach;
	};

	switch (ptr->type) {
	case RZ_BIN_WASM_NAMETYPE_Module:
		ptr->mod_name = RZ_NEW0(struct rz_bin_wasm_name_t);
		if (!ptr->mod_name) {
			goto beach;
		}
		if (!(consume_u32_r(b, max, &ptr->mod_name->len))) {
			goto beach;
		}

		if (!(consume_str_r(b, max, ptr->mod_name->len, (char *)ptr->mod_name->name))) {
			goto beach;
		}

		ptr->mod_name->name[ptr->mod_name->len] = 0;
		break;
	case RZ_BIN_WASM_NAMETYPE_Function:
		ptr->func = RZ_NEW0(RzBinWasmCustomNameFunctionNames);
		if (!ptr->func) {
			goto beach;
		}

		ptr->func->names = rz_id_storage_new(0, UT32_MAX);

		if (!ptr->func->names) {
			goto beach;
		}

		if (!parse_namemap(b, max, ptr->func->names, &ptr->func->count)) {
			goto beach;
		}
		break;
	case RZ_BIN_WASM_NAMETYPE_Local:
		ptr->local = RZ_NEW0(RzBinWasmCustomNameLocalNames);
		if (!ptr->local) {
			goto beach;
		}
		if (!(consume_u32_r(b, max, &ptr->local->count))) {
			free(ptr->local);
			goto beach;
		}

		ptr->local->locals = rz_list_new();

		for (i = 0; i < ptr->local->count; i++) {
			RzBinWasmCustomNameLocalName *local_name = RZ_NEW0(RzBinWasmCustomNameLocalName);
			if (!local_name) {
				free(ptr->local);
				free(ptr);
				return NULL;
			}

			if (!(consume_u32_r(b, max, &local_name->index))) {
				rz_list_free(ptr->local->locals);
				free(ptr->local);
				free(local_name);
				goto beach;
			}

			local_name->names = rz_id_storage_new(0, UT32_MAX);
			if (!local_name->names) {
				rz_list_free(ptr->local->locals);
				free(ptr->local);
				free(local_name);
				goto beach;
			}

			if (!parse_namemap(b, max, local_name->names, &local_name->names_count)) {
				rz_id_storage_free(local_name->names);
				rz_list_free(ptr->local->locals);
				free(ptr->local);
				free(local_name);
				goto beach;
			}

			if (!rz_list_append(ptr->local->locals, local_name)) {
				free(local_name);
				goto beach;
			};
		}
		break;
	}

	return ptr;
beach:
	free(ptr);
	return NULL;
}

static void *parse_memory_entry(RzBuffer *b, ut64 max) {
	RzBinWasmMemoryEntry *ptr = RZ_NEW0(RzBinWasmMemoryEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_limits_r(b, max, &ptr->limits))) {
		goto beach;
	}
	return ptr;

beach:
	free(ptr);
	return NULL;
}

static void *parse_table_entry(RzBuffer *b, ut64 max) {
	RzBinWasmTableEntry *ptr = RZ_NEW0(RzBinWasmTableEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_s7_r(b, max, (st8 *)&ptr->element_type))) {
		goto beach;
	}
	if (!(consume_limits_r(b, max, &ptr->limits))) {
		goto beach;
	}
	return ptr;

beach:
	free(ptr);
	return NULL;
}

static void *parse_global_entry(RzBuffer *b, ut64 max) {
	RzBinWasmGlobalEntry *ptr = RZ_NEW0(RzBinWasmGlobalEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_u7_r(b, max, (ut8 *)&ptr->content_type))) {
		goto beach;
	}
	if (!(consume_u1_r(b, max, &ptr->mutability))) {
		goto beach;
	}
	if (!(consume_init_expr_r(b, max, RZ_BIN_WASM_END_OF_CODE, NULL))) {
		goto beach;
	}
	return ptr;

beach:
	free(ptr);
	return NULL;
}

static void *parse_element_entry(RzBuffer *b, ut64 max) {
	RzBinWasmElementEntry *ptr = RZ_NEW0(RzBinWasmElementEntry);
	if (!ptr) {
		return NULL;
	}
	if (!(consume_u32_r(b, max, &ptr->index))) {
		goto beach;
	}
	if (!(consume_init_expr_r(b, max, RZ_BIN_WASM_END_OF_CODE, NULL))) {
		goto beach;
	}
	if (!(consume_u32_r(b, max, &ptr->num_elem))) {
		goto beach;
	}
	ut32 j = 0;
	while (rz_buf_tell(b) <= max && j < ptr->num_elem) {
		// TODO: allocate space and fill entry
		if (!(consume_u32_r(b, max, NULL))) {
			goto beach;
		}
	}
	return ptr;

beach:
	free(ptr);
	return NULL;
}

static RzList *rz_bin_wasm_get_type_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_type_entry, (RzListFree)rz_bin_wasm_free_types);
}

static RzList *rz_bin_wasm_get_import_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_import_entry, (RzListFree)free);
}

static RzList *rz_bin_wasm_get_export_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_export_entry, (RzListFree)free);
}

static RzList *rz_bin_wasm_get_code_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_code_entry, (RzListFree)rz_bin_wasm_free_codes);
}

static RzList *rz_bin_wasm_get_data_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_data_entry, (RzListFree)free);
}

static RzBinWasmStartEntry *rz_bin_wasm_get_start(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	RzBinWasmStartEntry *ptr;

	if (!(ptr = RZ_NEW0(RzBinWasmStartEntry))) {
		return NULL;
	}

	RzBuffer *b = bin->buf;
	rz_buf_seek(b, sec->payload_data, RZ_BUF_SET);
	ut64 max = rz_buf_tell(b) + sec->payload_len - 1;
	if (!(max < rz_buf_size(b))) {
		goto beach;
	}
	if (!(consume_u32_r(b, max, &ptr->index))) {
		goto beach;
	}
	return ptr;
beach:
	eprintf("[wasm] error: beach start\n");
	free(ptr);
	return NULL;
}

static RzList *rz_bin_wasm_get_memory_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_memory_entry, (RzListFree)free);
}

static RzList *rz_bin_wasm_get_table_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_table_entry, (RzListFree)free);
}

static RzList *rz_bin_wasm_get_global_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_global_entry, (RzListFree)free);
}

static RzList *rz_bin_wasm_get_element_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	return get_entries_from_section(bin, sec, parse_element_entry, (RzListFree)free);
}

static RzList *rz_bin_wasm_get_custom_name_entries(RzBinWasmObj *bin, RzBinWasmSection *sec) {
	RzList *ret = rz_list_new();

	RzBuffer *buf = bin->buf;

	rz_buf_seek(buf, sec->payload_data, RZ_BUF_SET);
	ut64 max = sec->payload_data + sec->payload_len - 1;

	if (max > rz_buf_size(buf)) {
		goto beach;
	}

	while (rz_buf_tell(buf) < max) {
		RzBinWasmCustomNameEntry *nam = parse_custom_name_entry(buf, max);

		if (!nam) {
			goto beach;
		}

		if (!rz_list_append(ret, nam)) {
			goto beach;
		}
	}

	return ret;
beach:
	rz_list_free(ret);
	return NULL;
}

// Public functions
RzBinWasmObj *rz_bin_wasm_init(RzBinFile *bf, RzBuffer *buf) {
	RzBinWasmObj *bin = RZ_NEW0(RzBinWasmObj);
	if (!bin) {
		return NULL;
	}
	bin->buf = rz_buf_ref(buf);
	bin->size = (ut32)rz_buf_size(bf->buf);
	bin->g_sections = rz_bin_wasm_get_sections(bin);
	// TODO: recursive invocation more natural with streamed parsing
	// but dependency problems when sections are disordered (against spec)

	bin->g_types = rz_bin_wasm_get_types(bin);
	bin->g_imports = rz_bin_wasm_get_imports(bin);
	bin->g_exports = rz_bin_wasm_get_exports(bin);
	bin->g_tables = rz_bin_wasm_get_tables(bin);
	bin->g_memories = rz_bin_wasm_get_memories(bin);
	bin->g_globals = rz_bin_wasm_get_globals(bin);
	bin->g_codes = rz_bin_wasm_get_codes(bin);
	bin->g_datas = rz_bin_wasm_get_datas(bin);

	bin->g_names = rz_bin_wasm_get_custom_names(bin);

	// entrypoint from Start section
	bin->entrypoint = rz_bin_wasm_get_entrypoint(bin);

	return bin;
}

void rz_bin_wasm_destroy(RzBinFile *bf) {
	RzBinWasmObj *bin;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}

	bin = bf->o->bin_obj;
	rz_buf_free(bin->buf);

	rz_list_free(bin->g_sections);
	rz_list_free(bin->g_types);

	rz_list_free(bin->g_imports);
	rz_list_free(bin->g_exports);
	rz_list_free(bin->g_tables);
	rz_list_free(bin->g_memories);
	rz_list_free(bin->g_globals);
	rz_list_free(bin->g_codes);
	rz_list_free(bin->g_datas);

	RzListIter *iter;
	RzBinWasmCustomNameEntry *nam;
	rz_list_foreach (bin->g_names, iter, nam) {
		switch (nam->type) {
		case RZ_BIN_WASM_NAMETYPE_Module:
			if (nam->mod_name) {
				free(nam->mod_name);
			}
			break;
		case RZ_BIN_WASM_NAMETYPE_Function:
			if (nam->func) {
				rz_id_storage_free(nam->func->names);
			}
			break;
		case RZ_BIN_WASM_NAMETYPE_Local:
			if (nam->local && nam->local->locals) {
				RzListIter *iter;
				RzBinWasmCustomNameLocalName *local;
				rz_list_foreach (nam->local->locals, iter, local) {
					if (local->names) {
						rz_id_storage_free(local->names);
					}
				}

				rz_list_free(nam->local->locals);
			}
			break;
		}
	}
	rz_list_free(bin->g_names);

	free(bin->g_start);
	free(bin);
	bf->o->bin_obj = NULL;
}

RzList *rz_bin_wasm_get_sections(RzBinWasmObj *bin) {
	RzList *ret = NULL;
	RzBinWasmSection *ptr = NULL;

	if (!bin) {
		return NULL;
	}
	if (bin->g_sections) {
		return bin->g_sections;
	}
	if (!(ret = rz_list_newf((RzListFree)free))) {
		return NULL;
	}
	RzBuffer *b = bin->buf;
	ut64 max = rz_buf_size(b) - 1;
	rz_buf_seek(b, 8, RZ_BUF_SET);
	while (rz_buf_tell(b) <= max) {
		if (!(ptr = RZ_NEW0(RzBinWasmSection))) {
			return ret;
		}
		if (!(consume_u7_r(b, max, &ptr->id))) {
			goto beach;
		}
		if (!(consume_u32_r(b, max, &ptr->size))) {
			goto beach;
		}
		// against spec. TODO: choose criteria for parsing
		if (ptr->size < 1) {
			goto beach;
			// free (ptr);
			// continue;
		}
		if (!(rz_buf_tell(b) + (ut64)ptr->size - 1 <= max)) {
			goto beach;
		}
		ptr->count = 0;
		ptr->offset = rz_buf_tell(b);
		switch (ptr->id) {
		case RZ_BIN_WASM_SECTION_CUSTOM:
			// eprintf("custom section: 0x%x, ", (ut32)b->cur);
			if (!(consume_u32_r(b, max, &ptr->name_len))) {
				goto beach;
			}
			if (consume_str_r(b, max, ptr->name_len, (char *)ptr->name) < ptr->name_len) {
				goto beach;
			}
			// eprintf("name: %s\n", ptr->name);
			break;
		case RZ_BIN_WASM_SECTION_TYPE:
			// eprintf("section type: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "type");
			ptr->name_len = 4;
			break;
		case RZ_BIN_WASM_SECTION_IMPORT:
			// eprintf("section import: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "import");
			ptr->name_len = 6;
			break;
		case RZ_BIN_WASM_SECTION_FUNCTION:
			// eprintf("section function: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "function");
			ptr->name_len = 8;
			break;
		case RZ_BIN_WASM_SECTION_TABLE:
			// eprintf("section table: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "table");
			ptr->name_len = 5;
			break;
		case RZ_BIN_WASM_SECTION_MEMORY:
			// eprintf("section memory: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "memory");
			ptr->name_len = 6;
			break;
		case RZ_BIN_WASM_SECTION_GLOBAL:
			// eprintf("section global: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "global");
			ptr->name_len = 6;
			break;
		case RZ_BIN_WASM_SECTION_EXPORT:
			// eprintf("section export: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "export");
			ptr->name_len = 6;
			break;
		case RZ_BIN_WASM_SECTION_START:
			// eprintf("section start: 0x%x\n", (ut32)b->cur);
			strcpy(ptr->name, "start");
			ptr->name_len = 5;
			break;
		case RZ_BIN_WASM_SECTION_ELEMENT:
			// eprintf("section element: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "element");
			ptr->name_len = 7;
			break;
		case RZ_BIN_WASM_SECTION_CODE:
			// eprintf("section code: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "code");
			ptr->name_len = 4;
			break;
		case RZ_BIN_WASM_SECTION_DATA:
			// eprintf("section data: 0x%x, ", (ut32)b->cur);
			strcpy(ptr->name, "data");
			ptr->name_len = 4;
			break;
		default:
			eprintf("[wasm] error: unkown section id: %d\n", ptr->id);
			rz_buf_seek(b, ptr->size - 1, RZ_BUF_CUR);
			continue;
		}
		if (ptr->id != RZ_BIN_WASM_SECTION_START && ptr->id != RZ_BIN_WASM_SECTION_CUSTOM) {
			if (!(consume_u32_r(b, max, &ptr->count))) {
				goto beach;
			}
			// eprintf("count %d\n", ptr->count);
		}
		ptr->payload_data = rz_buf_tell(b);
		ptr->payload_len = ptr->size - (ptr->payload_data - ptr->offset);
		if (ptr->payload_len > ptr->size) {
			goto beach;
		}
		rz_buf_seek(b, ptr->payload_len, RZ_BUF_CUR);
		if (!rz_list_append(ret, ptr)) {
			free(ptr);
			// should it jump to beach?
		}
		ptr = NULL;
	}
	bin->g_sections = ret;
	return ret;
beach:
	eprintf("[wasm] error: beach sections\n");
	free(ptr);
	return ret;
}

ut32 rz_bin_wasm_get_entrypoint(RzBinWasmObj *bin) {
	RzList *secs = NULL;
	RzBinWasmStartEntry *start = NULL;
	RzBinWasmSection *sec = NULL;
	RzBinWasmCodeEntry *func = NULL;

	if (!bin || !bin->g_sections) {
		return 0;
	}
	if (bin->entrypoint) {
		return bin->entrypoint;
	}
	if (bin->g_start) {
		start = bin->g_start;
	} else if (!(secs = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_START))) {
		return 0;
	} else if (!(sec = (RzBinWasmSection *)rz_list_first(secs))) {
		rz_list_free(secs);
		return 0;
	} else {
		start = rz_bin_wasm_get_start(bin, sec);
		bin->g_start = start;
	}
	if (!start) {
		rz_list_free(secs);
		return 0;
	}
	// FIX: entrypoint can be also an import
	if (!bin->g_codes) {
		rz_list_free(secs);
		return 0;
	}
	func = rz_list_get_n(bin->g_codes, start->index);
	rz_list_free(secs);
	return (ut32)(func ? func->code : 0);
}

RzList *rz_bin_wasm_get_imports(RzBinWasmObj *bin) {
	RzBinWasmSection *import = NULL;
	RzList *imports = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_imports) {
		return bin->g_imports;
	}
	if (!(imports = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_IMPORT))) {
		return rz_list_new();
	}
	// support for multiple import sections against spec
	if (!(import = (RzBinWasmSection *)rz_list_first(imports))) {
		rz_list_free(imports);
		return rz_list_new();
	}
	bin->g_imports = rz_bin_wasm_get_import_entries(bin, import);
	rz_list_free(imports);
	return bin->g_imports;
}

RzList *rz_bin_wasm_get_exports(RzBinWasmObj *bin) {
	RzBinWasmSection *export = NULL;
	RzList *exports = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_exports) {
		return bin->g_exports;
	}
	if (!(exports = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_EXPORT))) {
		return rz_list_new();
	}
	// support for multiple export sections against spec
	if (!(export = (RzBinWasmSection *)rz_list_first(exports))) {
		rz_list_free(exports);
		return rz_list_new();
	}
	bin->g_exports = rz_bin_wasm_get_export_entries(bin, export);
	rz_list_free(exports);
	return bin->g_exports;
}

RzList *rz_bin_wasm_get_types(RzBinWasmObj *bin) {
	RzBinWasmSection *type = NULL;
	RzList *types = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_types) {
		return bin->g_types;
	}
	if (!(types = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_TYPE))) {
		return rz_list_new();
	}
	// support for multiple export sections against spec
	if (!(type = (RzBinWasmSection *)rz_list_first(types))) {
		rz_list_free(types);
		return rz_list_new();
	}
	bin->g_types = rz_bin_wasm_get_type_entries(bin, type);
	rz_list_free(types);
	return bin->g_types;
}

RzList *rz_bin_wasm_get_tables(RzBinWasmObj *bin) {
	RzBinWasmSection *table = NULL;
	RzList *tables = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_tables) {
		return bin->g_tables;
	}
	if (!(tables = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_TABLE))) {
		return rz_list_new();
	}
	// support for multiple export sections against spec
	if (!(table = (RzBinWasmSection *)rz_list_first(tables))) {
		rz_list_free(tables);
		return rz_list_new();
	}
	bin->g_tables = rz_bin_wasm_get_table_entries(bin, table);
	rz_list_free(tables);
	return bin->g_tables;
}

RzList *rz_bin_wasm_get_memories(RzBinWasmObj *bin) {
	RzBinWasmSection *memory;
	RzList *memories;

	if (!bin || !bin->g_sections) {
		return NULL;
	}

	if (bin->g_memories) {
		return bin->g_memories;
	}

	if (!(memories = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_MEMORY))) {
		return rz_list_new();
	}

	// support for multiple export sections against spec
	if (!(memory = (RzBinWasmSection *)rz_list_first(memories))) {
		rz_list_free(memories);
		return rz_list_new();
	}

	bin->g_memories = rz_bin_wasm_get_memory_entries(bin, memory);
	rz_list_free(memories);
	return bin->g_memories;
}

RzList *rz_bin_wasm_get_globals(RzBinWasmObj *bin) {
	RzBinWasmSection *global = NULL;
	RzList *globals = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_globals) {
		return bin->g_globals;
	}
	if (!(globals = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_GLOBAL))) {
		return rz_list_new();
	}
	// support for multiple export sections against spec
	if (!(global = (RzBinWasmSection *)rz_list_first(globals))) {
		rz_list_free(globals);
		return rz_list_new();
	}
	bin->g_globals = rz_bin_wasm_get_global_entries(bin, global);
	rz_list_free(globals);
	return bin->g_globals;
}

RzList *rz_bin_wasm_get_elements(RzBinWasmObj *bin) {
	RzBinWasmSection *element = NULL;
	RzList *elements = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_elements) {
		return bin->g_elements;
	}
	if (!(elements = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_ELEMENT))) {
		return rz_list_new();
	}
	// support for multiple export sections against spec
	if (!(element = (RzBinWasmSection *)rz_list_first(elements))) {
		rz_list_free(elements);
		return rz_list_new();
	}
	bin->g_elements = rz_bin_wasm_get_element_entries(bin, element);
	rz_list_free(elements);
	return bin->g_elements;
}

RzList *rz_bin_wasm_get_codes(RzBinWasmObj *bin) {
	RzBinWasmSection *code = NULL;
	;
	RzList *codes = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_codes) {
		return bin->g_codes;
	}
	if (!(codes = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_CODE))) {
		return rz_list_new();
	}
	// support for multiple export sections against spec
	if (!(code = (RzBinWasmSection *)rz_list_first(codes))) {
		rz_list_free(codes);
		return rz_list_new();
	}
	bin->g_codes = rz_bin_wasm_get_code_entries(bin, code);
	rz_list_free(codes);
	return bin->g_codes;
}

RzList *rz_bin_wasm_get_datas(RzBinWasmObj *bin) {
	RzBinWasmSection *data = NULL;
	RzList *datas = NULL;

	if (!bin || !bin->g_sections) {
		return NULL;
	}
	if (bin->g_datas) {
		return bin->g_datas;
	}
	if (!(datas = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_DATA))) {
		return rz_list_new();
	}
	// support for multiple export sections against spec
	if (!(data = (RzBinWasmSection *)rz_list_first(datas))) {
		rz_list_free(datas);
		return rz_list_new();
	}
	bin->g_datas = rz_bin_wasm_get_data_entries(bin, data);
	rz_list_free(datas);
	return bin->g_datas;
}

RzList *rz_bin_wasm_get_custom_names(RzBinWasmObj *bin) {
	RzBinWasmSection *cust = NULL;
	RzList *customs = NULL;

	rz_return_val_if_fail(bin && bin->g_sections, NULL);

	if (bin->g_names) {
		return bin->g_names;
	}
	if (!(customs = rz_bin_wasm_get_sections_by_id(bin->g_sections, RZ_BIN_WASM_SECTION_CUSTOM))) {
		return rz_list_new();
	}
	// support for multiple "name" sections against spec
	if (!(cust = (RzBinWasmSection *)rz_list_first(customs)) || strncmp(cust->name, "name", 5)) {
		rz_list_free(customs);
		return rz_list_new();
	}
	bin->g_names = rz_bin_wasm_get_custom_name_entries(bin, cust);
	rz_list_free(customs);
	return bin->g_names;
}

const char *rz_bin_wasm_get_function_name(RzBinWasmObj *bin, ut32 idx) {
	if (!(bin && bin->g_names)) {
		return NULL;
	};

	RzListIter *iter;
	RzBinWasmCustomNameEntry *nam;
	rz_list_foreach (bin->g_names, iter, nam) {
		if (nam->type == RZ_BIN_WASM_NAMETYPE_Function) {
			struct rz_bin_wasm_name_t *n = NULL;

			if ((n = rz_id_storage_get(nam->func->names, idx))) {
				return (const char *)n->name;
			}
		}
	}

	return NULL;
}
