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
		return NULL;
	}

	proto->const_entries = rz_list_new();
	if (proto->const_entries == NULL) {
		eprintf("Init Const Entry List Failed\n");
		RZ_FREE(proto);
		return NULL;
	}

	proto->upvalue_entries = rz_list_new();
	if (proto->upvalue_entries == NULL) {
		eprintf("Init Upvalue Entry List Failed\n");
		rz_list_free(proto->const_entries);
		RZ_FREE(proto);
		return NULL;
	}

	proto->proto_entries = rz_list_new();
	if (proto->proto_entries == NULL) {
		eprintf("Init Proto Entry List Failed\n");
		rz_list_free(proto->const_entries);
		rz_list_free(proto->upvalue_entries);
		RZ_FREE(proto);
		return NULL;
	}

	proto->line_info_entries = rz_list_new();
	if (proto->line_info_entries == NULL) {
		eprintf("Init Debug Line Info Failed\n");
		rz_list_free(proto->const_entries);
		rz_list_free(proto->upvalue_entries);
		rz_list_free(proto->proto_entries);
		RZ_FREE(proto);
		return NULL;
	}

	proto->abs_line_info_entries = rz_list_new();
	if (proto->abs_line_info_entries == NULL) {
		eprintf("Init Abs Line Info Failed\n");
		rz_list_free(proto->const_entries);
		rz_list_free(proto->upvalue_entries);
		rz_list_free(proto->proto_entries);
		rz_list_free(proto->line_info_entries);
		RZ_FREE(proto);
		return NULL;
	}

	proto->local_var_info_entries = rz_list_new();
	if (proto->local_var_info_entries == NULL) {
		eprintf("Init Local Var Failed\n");
		rz_list_free(proto->const_entries);
		rz_list_free(proto->upvalue_entries);
		rz_list_free(proto->proto_entries);
		rz_list_free(proto->line_info_entries);
		rz_list_free(proto->abs_line_info_entries);
		RZ_FREE(proto);
		return NULL;
	}

	proto->dbg_upvalue_entries = rz_list_new();
	if (proto->dbg_upvalue_entries == NULL) {
		eprintf("Init Debug Upvalues Failed\n");
		rz_list_free(proto->const_entries);
		rz_list_free(proto->upvalue_entries);
		rz_list_free(proto->proto_entries);
		rz_list_free(proto->line_info_entries);
		rz_list_free(proto->abs_line_info_entries);
		rz_list_free(proto->dbg_upvalue_entries);
		RZ_FREE(proto);
		return NULL;
	}

	/* set free functions */
	proto->const_entries->free = (RzListFree)&lua_free_const_entry;
	proto->upvalue_entries->free = (RzListFree)&lua_free_upvalue_entry;
	proto->line_info_entries->free = (RzListFree)&lua_free_lineinfo_entry;
	proto->abs_line_info_entries->free = (RzListFree)&lua_free_abs_lineinfo_entry;
	proto->local_var_info_entries->free = (RzListFree)&lua_free_local_var_entry;
	proto->dbg_upvalue_entries->free = (RzListFree)&lua_free_dbg_upvalue_entry;
	proto->proto_entries->free = (RzListFree)&lua_free_proto_entry;

	return proto;
}

void lua_free_dbg_upvalue_entry(LuaDbgUpvalueEntry *entry) {
	rz_return_if_fail(entry);
	if (entry->upvalue_name != NULL) {
		RZ_FREE(entry->upvalue_name);
	}
	// leave entry to rz_list_free
	RZ_FREE(entry);
}

void lua_free_local_var_entry(LuaLocalVarEntry *entry) {
	rz_return_if_fail(entry);
	if (entry->varname != NULL) {
		RZ_FREE(entry->varname);
	}
	RZ_FREE(entry);
}

void lua_free_const_entry(LuaConstEntry *entry) {
	rz_return_if_fail(entry);
	if (entry->data != NULL) {
		RZ_FREE(entry->data);
	}
	RZ_FREE(entry);
}

void lua_free_abs_lineinfo_entry(LuaAbsLineinfoEntry *entry) {
	rz_return_if_fail(entry);
	RZ_FREE(entry);
}

void lua_free_lineinfo_entry(LuaLineinfoEntry *entry) {
	rz_return_if_fail(entry);
	RZ_FREE(entry);
}

void lua_free_upvalue_entry(LuaUpvalueEntry *entry) {
	rz_return_if_fail(entry);
	RZ_FREE(entry);
}

void lua_free_proto_entry(LuaProto *proto) {
	if (proto == NULL) {
		return;
	}

	/* free constants entries */
	rz_list_free(proto->const_entries);
	proto->const_entries = NULL;

	/* free upvalue entries */
	rz_list_free(proto->upvalue_entries);
	proto->upvalue_entries = NULL;

	/* free debug */
	rz_list_free(proto->line_info_entries);
	rz_list_free(proto->abs_line_info_entries);
	rz_list_free(proto->local_var_info_entries);
	rz_list_free(proto->dbg_upvalue_entries);
	proto->line_info_entries = NULL;
	proto->abs_line_info_entries = NULL;
	proto->local_var_info_entries = NULL;
	proto->dbg_upvalue_entries = NULL;

	/* recursively free protos */
	rz_list_free(proto->proto_entries);
	proto->proto_entries = NULL;

	RZ_FREE(proto->proto_name);
	RZ_FREE(proto);
}