// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

// Implement Functions declared in luac_common.h

#include "luac_common.h"

LuaDbgUpvalueEntry *lua_new_dbg_upvalue_entry() {
	LuaDbgUpvalueEntry *entry = RZ_NEW0(LuaDbgUpvalueEntry);
	return entry;
}

LuaLocalVarEntry *lua_new_local_var_entry() {
	LuaLocalVarEntry *entry = RZ_NEW0(LuaLocalVarEntry);
	return entry;
}

LuaAbsLineinfoEntry *lua_new_abs_lineinfo_entry() {
	LuaAbsLineinfoEntry *entry = RZ_NEW0(LuaAbsLineinfoEntry);
	return entry;
}

LuaLineinfoEntry *lua_new_lineinfo_entry() {
	LuaLineinfoEntry *entry = RZ_NEW0(LuaLineinfoEntry);
	return entry;
}

LuaUpvalueEntry *lua_new_upvalue_entry() {
	LuaUpvalueEntry *entry = RZ_NEW0(LuaUpvalueEntry);
	return entry;
}

LuaConstEntry *lua_new_const_entry() {
	LuaConstEntry *entry = RZ_NEW0(LuaConstEntry);
	return entry;
}

LuaProto *lua_new_proto_entry() {
	LuaProto *proto = RZ_NEW0(LuaProto);
	if (!proto) {
		RZ_LOG_ERROR("Cannot allocate LuaProto\n");
		return NULL;
	}

	proto->const_entries = rz_list_newf((RzListFree)lua_free_const_entry);
	if (!proto->const_entries) {
		RZ_LOG_ERROR("Cannot allocate Const Entry List\n");
		goto fail;
	}

	proto->upvalue_entries = rz_list_newf(free);
	if (!proto->upvalue_entries) {
		RZ_LOG_ERROR("Cannot allocate Upvalue Entry List\n");
		goto fail;
	}

	proto->proto_entries = rz_list_newf((RzListFree)lua_free_proto_entry);
	if (!proto->proto_entries) {
		RZ_LOG_ERROR("Cannot allocate Proto Entry List\n");
		goto fail;
	}

	proto->line_info_entries = rz_list_newf(free);
	if (!proto->line_info_entries) {
		RZ_LOG_ERROR("Cannot allocate Debug Line Info\n");
		goto fail;
	}

	proto->abs_line_info_entries = rz_list_newf(free);
	if (!proto->abs_line_info_entries) {
		RZ_LOG_ERROR("Cannot allocate Abs Line Info\n");
		goto fail;
	}

	proto->local_var_info_entries = rz_list_newf((RzListFree)lua_free_local_var_entry);
	if (!proto->local_var_info_entries) {
		RZ_LOG_ERROR("Cannot allocate Local Var\n");
		goto fail;
	}

	proto->dbg_upvalue_entries = rz_list_newf((RzListFree)lua_free_dbg_upvalue_entry);
	if (!proto->dbg_upvalue_entries) {
		RZ_LOG_ERROR("Cannot allocate Debug Upvalues\n");
		goto fail;
	}

	return proto;

fail:
	lua_free_proto_entry(proto);
	return NULL;
}

void lua_free_dbg_upvalue_entry(LuaDbgUpvalueEntry *entry) {
	if (!entry) {
		return;
	}
	free(entry->upvalue_name);
	// leave entry to rz_list_free
	free(entry);
}

void lua_free_local_var_entry(LuaLocalVarEntry *entry) {
	if (!entry) {
		return;
	}
	free(entry->varname);
	free(entry);
}

void lua_free_const_entry(LuaConstEntry *entry) {
	if (!entry) {
		return;
	}
	free(entry->data);
	free(entry);
}

void lua_free_proto_entry(LuaProto *proto) {
	if (!proto) {
		return;
	}

	/* free constants entries */
	rz_list_free(proto->const_entries);

	/* free upvalue entries */
	rz_list_free(proto->upvalue_entries);

	/* free debug */
	rz_list_free(proto->line_info_entries);
	rz_list_free(proto->abs_line_info_entries);
	rz_list_free(proto->local_var_info_entries);
	rz_list_free(proto->dbg_upvalue_entries);

	/* recursively free protos */
	rz_list_free(proto->proto_entries);

	free(proto->proto_name);
	free(proto);
}