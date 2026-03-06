// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "luajit.h"

void luajit_free_proto_entry(LuaJITProto *proto) {
	if (!proto) {
		return;
	}

	rz_list_free(proto->proto_entries);
	free(proto->hdr_dbg);

	rz_list_free(proto->kgc_obj);
	rz_list_free(proto->table);

	rz_list_free(proto->constant_entries);
	rz_list_free(proto->local_var_entry);
	rz_list_free(proto->up_val_info);

	free(proto);
}

void free_luajit_value(LuaJITValue *value) {
	if (!value) {
		return;
	}
	if (value->data) {
		RZ_FREE(value->data);
	}
	RZ_FREE(value);
}

void luajit_free_kgc_obj(LuaJITKgcObj *kgc_obj) {
	if (!kgc_obj) {
		return;
	}
	if (kgc_obj->data) {
		RZ_FREE(kgc_obj->data);
	}

	RZ_FREE(kgc_obj);
}

void luajit_free_table(LuaJITTable *table) {
	if (!table) {
		return;
	}
	rz_list_free(table->array_items);
	rz_list_free(table->hash_keys);
	rz_list_free(table->hash_values);

	RZ_FREE(table);
}

void luajit_free_local_var(LuaJITLocalVar *local_var_entry) {
	if (!local_var_entry) {
		return;
	}
	RZ_FREE(local_var_entry->varname);

	RZ_FREE(local_var_entry);
}

void luajit_free_upval_info(LuaJITUpValue *up_val_entry) {
	if (!up_val_entry) {
		return;
	}
	RZ_FREE(up_val_entry->uv_name);

	RZ_FREE(up_val_entry);
}

// Parsing Section

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
	} else {
		return false;
	}
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
RZ_IPI RZ_BORROW LuaJITTable *luajit_new_table() {
	LuaJITTable *new_table = RZ_NEW0(LuaJITTable);
	if (!new_table) {
		return NULL;
	}

	new_table->array_items = rz_list_newf((RzListFree)free_luajit_value);
	new_table->hash_values = rz_list_newf((RzListFree)free_luajit_value);
	new_table->hash_keys = rz_list_newf((RzListFree)free_luajit_value);

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
RZ_IPI RZ_BORROW LuaJITValue *luajit_new_val() {
	LuaJITValue *new_value = RZ_NEW0(LuaJITValue);
	return new_value;
}

/**
 * \brief Create a new LuaJIT KGC object instance.
 *
 * \return Newly allocated LuaJITKgcObj instance.
 */
RZ_IPI RZ_BORROW LuaJITKgcObj *luajit_kgc_obj_new() {
	LuaJITKgcObj *new_kgc_obj = RZ_NEW0(LuaJITKgcObj);
	return new_kgc_obj;
}

/**
 * \brief Create a new LuaJIT Constant entry instance.
 *
 * \return Newly allocated LuaJITConstEntry instance.
 */
RZ_IPI RZ_BORROW LuaJITConstEntry *luajit_new_constant() {
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
RZ_IPI RZ_BORROW LuaJITLocalVar *luajit_new_localvar() {
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
RZ_IPI RZ_BORROW LuaJITUpValue *luajit_new_upvalue() {
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
RZ_IPI RZ_BORROW LuaJITProto *luajit_new_proto() {
	LuaJITProto *new_proto = RZ_NEW0(LuaJITProto);
	if (!new_proto) {
		RZ_LOG_ERROR("Cannot allocate LuaJITProto.\n");
		return NULL;
	}

	new_proto->proto_entries = rz_list_newf((RzListFree)luajit_free_proto_entry);
	if (!new_proto->proto_entries) {
		RZ_LOG_ERROR("Cannot allocate Proto Entry List.\n");
		goto fail;
	}

	new_proto->hdr_dbg = RZ_NEW0(LuaJITHdrDebug);
	if (!new_proto->hdr_dbg) {
		RZ_LOG_ERROR("Cannot allocate LuaJITHdrDebug.\n");
		goto fail;
	}

	new_proto->kgc_obj = rz_list_newf((RzListFree)luajit_free_kgc_obj);
	if (!new_proto->kgc_obj) {
		RZ_LOG_ERROR("Cannot allocate kgc_obj List.\n");
		goto fail;
	}

	new_proto->table = rz_list_newf((RzListFree)luajit_free_table);
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
	luajit_free_proto_entry(new_proto);
	return NULL;
}