// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "luajit.h"

void luajit_proto_entry_free(LuaJITProto *proto) {
	if (!proto) {
		return;
	}
	rz_list_free(proto->proto_entries);
	rz_list_free(proto->kgc_obj);
	rz_list_free(proto->table);
	rz_list_free(proto->constant_entries);
	rz_list_free(proto->local_var_entry);
	rz_list_free(proto->up_val_info);
	RZ_FREE(proto->hdr_dbg);
	free(proto);
}

void luajit_value_free(LuaJITValue *value) {
	if (!value) {
		return;
	}
	if (value->data) {
		RZ_FREE(value->data);
	}
	free(value);
}

void luajit_kgc_obj_free(LuaJITKgcObj *kgc_obj) {
	if (!kgc_obj) {
		return;
	}
	if (kgc_obj->data) {
		RZ_FREE(kgc_obj->data);
	}
	free(kgc_obj);
}

void luajit_table_free(LuaJITTable *table) {
	if (!table) {
		return;
	}
	rz_list_free(table->array_items);
	rz_list_free(table->hash_keys);
	rz_list_free(table->hash_values);
	free(table);
}

void luajit_free_local_var(LuaJITLocalVar *local_var_entry) {
	if (!local_var_entry) {
		return;
	}
	RZ_FREE(local_var_entry->varname);
	free(local_var_entry);
}

void luajit_free_upval_info(LuaJITUpValue *up_val_entry) {
	if (!up_val_entry) {
		return;
	}
	RZ_FREE(up_val_entry->uv_name);
	free(up_val_entry);
}

/* Parsing Section */

/**
 * \brief Checks the ULEB128 read was malformed or not.
 *
 * \param val The number of bytes read of ULEB128 encoded value.
 *
 * \return Returns true if malformed ULEB128 else false.
 */
RZ_IPI bool check_malformed_ULEB128(int val) {
	if (val == -1) {
		RZ_LOG_ERROR("malformed ULEB128\n");
		return true;
	}
	return false;
}

/**
 * \brief Parse string in the a buffer from given offset till fixed length.
 *
 * \param buf A pointer to RzBuffer instance.
 * \param offset Offset from where string is read.
 * \param type A raw value got from buffer for finding length (type - 5 = len)
 * \param dest A destination pointer to which the string is passed.
 *
 * \return End offset at which the string ends.
 */
RZ_IPI ut64 luajit_parse_string(RzBuffer *buf, ut64 offset, ut32 type, char **dest) {
	ut64 len = type - LUAJIT_TSTR;
	rz_return_val_if_fail(dest, offset + len);
	char *str = RZ_NEWS(char, len + 1);

	if (!str) {
		*dest = NULL;
		return offset;
	}

	rz_buf_read_at(buf, offset, (ut8 *)str, len);
	str[len] = '\0';

	if (dest) {
		*dest = str;
	} else {
		RZ_FREE(str);
	}
	return offset + len;
}

/**
 * \brief Create a new LuaJIT Table instance.
 *
 * \return Newly allocated LuaJITTable instance.
 */
RZ_IPI RZ_OWN LuaJITTable *luajit_new_table() {
	LuaJITTable *new_table = RZ_NEW0(LuaJITTable);
	if (!new_table) {
		return NULL;
	}
	new_table->array_items = rz_list_newf((RzListFree)luajit_value_free);
	new_table->hash_values = rz_list_newf((RzListFree)luajit_value_free);
	new_table->hash_keys = rz_list_newf((RzListFree)luajit_value_free);

	if (!(new_table->array_items && new_table->hash_values && new_table->hash_keys)) {
		return NULL;
	}
	return new_table;
}

/**
 * \brief Create a new LuaJIT Value instance.
 *
 * \return Newly allocated LuaJITValue instance.
 */
RZ_IPI RZ_OWN LuaJITValue *luajit_new_val() {
	LuaJITValue *new_value = RZ_NEW0(LuaJITValue);
	return new_value;
}

/**
 * \brief Create a new LuaJIT KGC object instance.
 *
 * \return Newly allocated LuaJITKgcObj instance.
 */
RZ_IPI RZ_OWN LuaJITKgcObj *luajit_kgc_obj_new() {
	LuaJITKgcObj *new_kgc_obj = RZ_NEW0(LuaJITKgcObj);
	return new_kgc_obj;
}

/**
 * \brief Create a new LuaJIT Constant entry instance.
 *
 * \return Newly allocated LuaJITConstEntry instance.
 */
RZ_IPI RZ_OWN LuaJITConstEntry *luajit_new_constant() {
	LuaJITConstEntry *constant_entry = RZ_NEW0(LuaJITConstEntry);
	if (!constant_entry) {
		return NULL;
	}
	return constant_entry;
}

/**
 * \brief Create a new LuaJIT local variable instance.
 *
 * \return Newly allocated LuaJITLocalVar instance.
 */
RZ_IPI RZ_OWN LuaJITLocalVar *luajit_new_localvar() {
	LuaJITLocalVar *localvar = RZ_NEW0(LuaJITLocalVar);
	if (!localvar) {
		return NULL;
	}
	return localvar;
}

/**
 * \brief Create a new LuaJIT upvalue instance.
 *
 * \return Newly allocated LuaJITUpValue instance.
 */
RZ_IPI RZ_OWN LuaJITUpValue *luajit_new_upvalue() {
	LuaJITUpValue *up_val = RZ_NEW0(LuaJITUpValue);
	if (!up_val) {
		return NULL;
	}
	return up_val;
}

/**
 * \brief Create a new LuaJIT proto instance.
 *
 * \return Newly allocated LuaJITProto instance.
 */
RZ_IPI RZ_OWN LuaJITProto *luajit_new_proto() {
	LuaJITProto *new_proto = RZ_NEW0(LuaJITProto);
	if (!new_proto) {
		RZ_LOG_ERROR("Cannot allocate LuaJITProto.\n");
		return NULL;
	}

	new_proto->proto_entries = rz_list_newf((RzListFree)luajit_proto_entry_free);
	if (!new_proto->proto_entries) {
		RZ_LOG_ERROR("Cannot allocate Proto Entry List.\n");
		goto fail;
	}

	new_proto->hdr_dbg = RZ_NEW0(LuaJITHdrDebug);
	if (!new_proto->hdr_dbg) {
		RZ_LOG_ERROR("Cannot allocate LuaJITHdrDebug.\n");
		goto fail;
	}

	new_proto->kgc_obj = rz_list_newf((RzListFree)luajit_kgc_obj_free);
	if (!new_proto->kgc_obj) {
		RZ_LOG_ERROR("Cannot allocate kgc_obj List.\n");
		goto fail;
	}

	new_proto->table = rz_list_newf((RzListFree)luajit_table_free);
	if (!new_proto->table) {
		RZ_LOG_ERROR("Cannot allocate table List.\n");
		goto fail;
	}

	new_proto->constant_entries = rz_list_newf(free);
	if (!new_proto->constant_entries) {
		RZ_LOG_ERROR("Cannot allocate constant entries List.\n");
		goto fail;
	}

	new_proto->local_var_entry = rz_list_newf((RzListFree)luajit_free_local_var);
	if (!new_proto->local_var_entry) {
		RZ_LOG_ERROR("Cannot allocate local varaible entry info List.\n");
		goto fail;
	}

	new_proto->up_val_info = rz_list_newf((RzListFree)luajit_free_upval_info);
	if (!new_proto->up_val_info) {
		RZ_LOG_ERROR("Cannot allocate upvalue varaible entry List.\n");
		goto fail;
	}

	return new_proto;

fail:
	luajit_proto_entry_free(new_proto);
	return NULL;
}

/* Load */

static LuaJITBinInfo *luajit_build_info_new() {
	LuaJITBinInfo *ret = RZ_NEW0(LuaJITBinInfo);

	ret->entry_vec = rz_pvector_new((RzPVectorFree)free);
	ret->strings = rz_list_newf((RzListFree)rz_bin_string_free);
	ret->symbol_list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	ret->sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);

	if ((!ret->strings || !ret->entry_vec || !ret->sections || !ret->symbol_list)) {
		rz_pvector_free(ret->entry_vec);
		rz_pvector_free(ret->sections);
		rz_list_free(ret->strings);
		rz_list_free(ret->symbol_list);
		return NULL;
	}
	return ret;
}

static int luajit_get_section_size(RzList /*<void *>*/ *l, LuaJITSection type) {
	if (rz_list_empty(l)) {
		return 0;
	}
	RzListIter *iter;
	int size = 0;

	switch (type) {
	case LUAJIT_STKGCOBJ: {
		LuaJITKgcObj *Kgc_obj;
		rz_list_foreach (l, iter, Kgc_obj) {
			size += Kgc_obj->size;
		}
		break;
	}
	case LUAJIT_STTABLE: {
		LuaJITTable *table;
		rz_list_foreach (l, iter, table) {
			size += table->size;
		}
		break;
	}
	case LUAJIT_STCONSTENTR: {
		LuaJITConstEntry *constant;
		rz_list_foreach (l, iter, constant) {
			size += constant->size;
		}
		break;
	}
	case LUAJIT_STLOCALVAR: {
		LuaJITLocalVar *localvar;
		rz_list_foreach (l, iter, localvar) {
			size += localvar->size;
		}
		break;
	}
	case LUAJIT_STUPVALINFO: {
		LuaJITUpValue *up_val_info;
		rz_list_foreach (l, iter, up_val_info) {
			size += up_val_info->size;
		}
		break;
	}
	default:
		RZ_LOG_ERROR("Invalid Section Type\n");
		return 0;
		break;
	}
	return size;
}

static char *get_symbol_const_name(char *proto_name, LuaJITConstEntry *const_entry) {
	rz_return_val_if_fail(proto_name || const_entry, NULL);
	ut8 tag = const_entry->type;
	char *ret;

	switch (tag) {
	case LUAJIT_TINT:
		ret = rz_str_newf("%s_const_%d", proto_name, const_entry->val.int_val);
		break;
	case LUAJIT_TFLT:
		ret = rz_str_newf("%s_const_%f", proto_name, const_entry->val.flt_val);
		break;
	default:
		ret = rz_str_newf("%s_const_0x%" PFMT64x, proto_name, const_entry->offset);
		break;
	}
	return ret;
}

static char *get_value_symbol_name(char *proto_name, LuaJITValue *val) {
	rz_return_val_if_fail(proto_name || val, NULL);
	ut8 tag = val->type;
	char *ret;

	switch (tag) {
	case LUAJIT_TNILL:
		ret = rz_str_newf("%s_val_nil", proto_name);
		break;
	case LUAJIT_TTRUE:
		ret = rz_str_newf("%s_val_true", proto_name);
		break;
	case LUAJIT_TFALSE:
		ret = rz_str_newf("%s_val_false", proto_name);
		break;
	case LUAJIT_TINT:
		ret = rz_str_newf("%s_val_%d", proto_name, *(int *)val->data);
		break;
	case LUAJIT_TFLT:
		ret = rz_str_newf("%s_val_%f", proto_name, *(double *)val->data);
		break;
	default:
		ret = rz_str_newf("%s_val_0x%" PFMT64x, proto_name, val->offset);
		break;
	}
	return ret;
}

static const char *get_tag_string(LuaJITValueType tag, bool is_const) {
	switch (tag) {
	case LUAJIT_TNILL:
		return is_const ? "CONST_NIL" : "VAL_NIL";
	case LUAJIT_TTRUE:
	case LUAJIT_TFALSE:
		return is_const ? "CONST_BOOL" : "VAL_BOOL";
	case LUAJIT_TINT:
	case LUAJIT_TFLT:
		return is_const ? "CONST_NUM" : "VAL_NUM";
	default:
		return is_const ? "CONST_UNKNOWN" : "VAL_UNKNOWN";
	}
}

static void add_table_string(LuaJITBinInfo *bi, LuaJITValue *val) {
	if (val->type > 5) {
		luac_add_string(bi->strings, val->data, val->offset, bi->baddr + val->offset, rz_str_ansi_len(val->data), LUAJIT_CPU);
	}
}

static char *get_luajit_cmplx_symbol(LuaJITKgcObj *k, char *proto_loc) {
	if (!k || !proto_loc) {
		return NULL;
	}
	return rz_str_newf("%s_kgcconst_%f%+fi", proto_loc, k->cmplx.r_bits, k->cmplx.i_bits);
}

static char *get_kgc_symbol_type(LuaJITKGCTypes type) {
	if (type == LUAJIT_KGCINT || type == LUAJIT_KGCFLT) {
		return "KGC_NUM";
	} else if (type == LUAJIT_KGCCMPLX) {
		return "KGC_CMPLX";
	}
	return NULL;
}

static void build_kgc_objects(LuaJITProto *proto, LuaJITBinInfo *info, char *proto_loc) {
	rz_return_if_fail(proto_loc);
	if (rz_list_empty(proto->kgc_obj)) {
		return;
	}

	RzListIter *iter;
	LuaJITKgcObj *kgc_obj = rz_list_first_val(proto->kgc_obj);
	ut64 current_offset = kgc_obj->offset;
	ut64 current_size = luajit_get_section_size(proto->kgc_obj, LUAJIT_STKGCOBJ);

	char *section_name = rz_str_newf("%s.kgcobj", proto_loc);
	rz_return_if_fail(section_name);
	luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
	free(section_name);

	rz_list_foreach (proto->kgc_obj, iter, kgc_obj) {
		char *symbol_name = NULL;
		const char *symbol_type = get_kgc_symbol_type(kgc_obj->type);

		switch (kgc_obj->type) {
		case LUAJIT_KGCINT:
			if (kgc_obj->data) {
				symbol_name = rz_str_newf("%s_kgcconst_%" PFMT64d, proto_loc, *(ut64 *)kgc_obj->data);
			}
			break;
		case LUAJIT_KGCFLT:
			if (kgc_obj->data) {
				symbol_name = rz_str_newf("%s_kgcconst_%f", proto_loc, *(double *)kgc_obj->data);
			}
			break;
		case LUAJIT_KGCCMPLX:
			symbol_name = get_luajit_cmplx_symbol(kgc_obj, proto_loc);
			break;
		default:
			if (kgc_obj->type >= LUAJIT_KGCSTR && kgc_obj->data) {
				luac_add_string(info->strings,
					kgc_obj->data,
					kgc_obj->offset,
					info->baddr + kgc_obj->offset,
					rz_str_ansi_len(kgc_obj->data),
					LUAJIT_CPU);
			}
			break;
		}

		if (symbol_name) {
			luac_add_symbol(info->symbol_list,
				symbol_name,
				kgc_obj->offset,
				info->baddr + kgc_obj->offset,
				kgc_obj->size,
				symbol_type);
			free(symbol_name);
		}
	}
}

static void build_constant_entries(LuaJITProto *proto, LuaJITBinInfo *info, char *proto_loc) {
	if (rz_list_empty(proto->constant_entries)) {
		return;
	}

	RzListIter *iter;
	LuaJITConstEntry *constant_entry = rz_list_first_val(proto->constant_entries);
	ut64 current_offset = constant_entry->offset;
	ut64 current_size = luajit_get_section_size(proto->constant_entries, LUAJIT_STCONSTENTR);

	char *section_name = rz_str_newf("%s.const", proto_loc);
	rz_return_if_fail(section_name);
	luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
	free(section_name);

	rz_list_foreach (proto->constant_entries, iter, constant_entry) {
		char *symbol_name = get_symbol_const_name(proto_loc, constant_entry);
		if (symbol_name) {
			luac_add_symbol(info->symbol_list,
				symbol_name,
				constant_entry->offset,
				constant_entry->offset + info->baddr,
				constant_entry->size,
				get_tag_string(constant_entry->type, true));
			free(symbol_name);
		}
	}
}

static void build_table_val(LuaJITBinInfo *info, LuaJITValue *val, char *proto_loc) {
	if (val->type >= LUAJIT_TSTR) {
		add_table_string(info, val);
		return;
	}

	char *symbol_name = get_value_symbol_name(proto_loc, val);
	if (symbol_name) {
		luac_add_symbol(info->symbol_list, symbol_name, val->offset, val->offset + info->baddr, val->size, get_tag_string(val->type, false));
		free(symbol_name);
	}
}

static void build_tables(LuaJITProto *proto, LuaJITBinInfo *info, char *proto_loc) {
	if (rz_list_empty(proto->table)) {
		return;
	}

	RzListIter *iter;
	LuaJITTable *table = rz_list_first_val(proto->table);
	ut64 current_offset = table->offset;
	ut64 current_size = luajit_get_section_size(proto->table, LUAJIT_STTABLE);

	char *section_name = rz_str_newf("%s.table", proto_loc);
	rz_return_if_fail(section_name);
	luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
	free(section_name);

	rz_list_foreach (proto->table, iter, table) {
		RzListIter *i;
		LuaJITValue *val;

		if (table->narray > 0) {
			rz_list_foreach (table->array_items, i, val) {
				build_table_val(info, val, proto_loc);
			}
		}

		if (table->nhash > 0) {
			rz_list_foreach (table->hash_keys, i, val) {
				build_table_val(info, val, proto_loc);
			}
			rz_list_foreach (table->hash_values, i, val) {
				build_table_val(info, val, proto_loc);
			}
		}
	}
}

static void build_local_vars(LuaJITProto *proto, LuaJITBinInfo *info, const char *proto_loc) {
	if (rz_list_empty(proto->local_var_entry)) {
		return;
	}

	RzListIter *iter;
	LuaJITLocalVar *local_var = rz_list_first_val(proto->local_var_entry);
	ut64 current_offset = local_var->offset;
	ut64 current_size = luajit_get_section_size(proto->local_var_entry, LUAJIT_STLOCALVAR);

	char *section_name = rz_str_newf("%s.localvar", proto_loc);
	if (section_name) {
		luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
		free(section_name);
		rz_list_foreach (proto->local_var_entry, iter, local_var) {
			/* local var field is the only field in luajit having '\0' at end of string in raw bytecode. */
			luac_add_string(info->strings,
				local_var->varname,
				local_var->offset,
				info->baddr + local_var->offset,
				local_var->varname_len - 1,
				0);
		}
	}
}

static void luajit_build_info_cb(LuaJITProto *proto, LuaJITBinInfo *info) {
	RzListIter *iter;
	char *section_name;
	char *proto_loc;

	ut64 current_offset;
	ut64 current_size;

	proto_loc = rz_str_newf("fcn.0x%" PFMT64x, proto->start_offset);

	current_offset = proto->start_offset;
	current_size = proto->hdr_size;
	section_name = rz_str_newf("%s.header", proto_loc);
	if (section_name) {
		luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
		free(section_name);
	}

	if (proto->hdr_dbg != NULL) {
		section_name = rz_str_newf("%s.hdr_debug", proto_loc);
		rz_return_if_fail(section_name);
		current_offset = proto->hdr_dbg->offset;
		current_size = proto->hdr_dbg->size;
		luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
		free(section_name);
	}

	if (proto->num_istr_cnt > 0) {
		section_name = rz_str_newf("%s.code", proto_loc);
		rz_return_if_fail(section_name);
		current_offset = proto->instr_offset;
		current_size = proto->num_istr_cnt * 4;
		luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, true);
		free(section_name);
		luac_add_entry(info->entry_vec, current_offset, RZ_BIN_ENTRY_TYPE_PROGRAM);
	}

	if (proto->num_up_val > 0) {
		current_offset = proto->up_val_entry_offset;
		current_size = proto->num_up_val * 2;
		section_name = rz_str_newf("%s.upvalueinstr", proto_loc);
		rz_return_if_fail(section_name);
		luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
		free(section_name);
	}

	build_kgc_objects(proto, info, proto_loc);

	build_constant_entries(proto, info, proto_loc);

	build_tables(proto, info, proto_loc);

	build_local_vars(proto, info, proto_loc);

	if (!rz_list_empty(proto->up_val_info)) {
		LuaJITUpValue *up_val_info = rz_list_first_val(proto->up_val_info);
		current_offset = up_val_info->offset;
		current_size = luajit_get_section_size(proto->up_val_info, LUAJIT_STUPVALINFO);
		section_name = rz_str_newf("%s.upvalnames", proto_loc);
		luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
		free(section_name);
	}

	current_offset = proto->debug_info_offset;
	current_size = proto->dbg_info_size;
	section_name = rz_str_newf("%s.debug", proto_loc);
	luac_add_section(info->sections, section_name, current_offset, current_offset + info->baddr, current_size, false);
	free(section_name);

	LuaJITProto *sub_proto;
	rz_list_foreach (proto->proto_entries, iter, sub_proto) {
		luajit_build_info_cb(sub_proto, info);
	}

	free(proto_loc);
}

static LuaJITBinInfo *luajit_build_info(LuaJITProto *proto, LuaJITBinInfo *ret) {
	if (!proto) {
		RZ_LOG_ERROR("Invalid luajit file\n");
		return NULL;
	}

	if (!ret) {
		return NULL;
	}
	if (ret->file_name) {
		int len = rz_str_ansi_len(ret->file_name);
		int vaddr = ret->baddr + ret->header_end - len;
		luac_add_string(
			ret->strings,
			ret->file_name,
			ret->header_end - len,
			vaddr,
			rz_str_ansi_len(ret->file_name),
			LUAJIT_CPU);
	}
	luajit_build_info_cb(proto, ret);
	return ret;
}

RZ_IPI bool luajit_load_buffer(RzBinFile *b, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	ut8 version;
	RzBinInfo *bin_info = NULL;
	LuaJITBinInfo *bin_info_obj = NULL;
	LuaJITProto *proto_info = NULL;

	/* A list to keep nested protos */
	RzList /*<LuaJITProto *>*/ *proto_list = rz_list_new();

	rz_buf_read_at(buf, LUAJIT_VERSION_OFFSET, &version, sizeof(version));

	bin_info_obj = luajit_build_info_new();
	if (!bin_info_obj) {
		rz_list_free(proto_list);
		return false;
	}

	switch ((int)version) {
	case 1:
		RZ_LOG_ERROR("luaJIT 2.0 not supported\n");
		break;
	case 2:
		bin_info = luajit_header_parser(b, bin_info_obj, 1);
		proto_info = luajit_parse_proto(buf, proto_list, bin_info_obj->header_end, bin_info_obj->header_end, true);
		break;
	default:
		RZ_LOG_ERROR("luaJIT 2.%c not supported\n", version);
		break;
	}
	bin_info_obj->baddr = obj->opts.baseaddr;
	bin_info_obj->cpu = LUAJIT_CPU;
	bin_info_obj = luajit_build_info(proto_info, bin_info_obj);
	if (bin_info_obj == NULL) {
		luajit_proto_entry_free(proto_info);
		rz_bin_info_free(bin_info);
		rz_list_free(proto_list);
		return false;
	}
	bin_info_obj->general_bin_info = bin_info;

	obj->bin_obj = bin_info_obj;
	rz_list_free(proto_list);
	luajit_proto_entry_free(proto_info);
	return true;
}

RZ_IPI RzPVector /*<RzBinString *>*/ *luajit_strings(RzBinFile *bf) {
	LuaJITBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuaJITBinInfo, bf);
	rz_return_val_if_fail(bin_info_obj && bin_info_obj->strings, NULL);
	RzPVector *pvec = rz_pvector_new((RzPVectorFree)rz_bin_string_free);
	if (!pvec || !rz_pvector_reserve(pvec, rz_list_length(bin_info_obj->strings))) {
		rz_pvector_free(pvec);
		return NULL;
	}
	RzListIter *iter;
	RzBinString *str;
	rz_list_foreach (bin_info_obj->strings, iter, str) {
		rz_pvector_push(pvec, str);
	}
	RzListFree free_cb = bin_info_obj->strings->free;
	bin_info_obj->strings->free = NULL;
	rz_list_purge(bin_info_obj->strings);
	bin_info_obj->strings->free = free_cb;
	return pvec;
}

RZ_IPI RzPVector /*<RzBinSection *>*/ *luajit_sections(RzBinFile *bf) {
	LuaJITBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuaJITBinInfo, bf);
	rz_return_val_if_fail(bin_info_obj && bin_info_obj->sections, NULL);
	return rz_pvector_clone(bin_info_obj->sections);
}

RZ_IPI RzPVector /*<RzBinSymbol *>*/ *luajit_symbols(RzBinFile *bf) {
	LuaJITBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuaJITBinInfo, bf);
	rz_return_val_if_fail(bin_info_obj && bin_info_obj->symbol_list, NULL);
	RzListIter *iter;
	RzBinSymbol *sym;
	RzPVector *vec = rz_pvector_new(NULL);
	rz_list_foreach (bin_info_obj->symbol_list, iter, sym) {
		rz_pvector_push(vec, sym);
	}
	return vec;
}

RZ_IPI RzBinInfo *luajit_info(RzBinFile *bf) {
	LuaJITBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuaJITBinInfo, bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	return bin_info_obj->general_bin_info;
}

RZ_IPI RzPVector /*<RzBinAddr *>*/ *luajit_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuaJITBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuaJITBinInfo, bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	return rz_pvector_clone(bin_info_obj->entry_vec);
}