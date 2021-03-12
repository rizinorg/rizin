// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

// Implement Functions declared in luac_common.h

#include "luac_common.h"

LuaDbgUpvalueEntry *lua_new_dbg_upvalue_entry(){
	LuaDbgUpvalueEntry *entry;
	rz_return_val_if_fail((entry = RZ_NEW0(LuaDbgUpvalueEntry)), NULL);
	return entry;
}

LuaLocalVarEntry *lua_new_local_var_entry(){
	LuaLocalVarEntry *entry;
	rz_return_val_if_fail((entry = RZ_NEW0(LuaLocalVarEntry)), NULL);
	return entry;
}

LuaAbsLineinfoEntry *lua_new_abs_lineinfo_entry(){
	LuaAbsLineinfoEntry *entry;
	rz_return_val_if_fail((entry = RZ_NEW0(LuaAbsLineinfoEntry)), NULL);
	return entry;
}

LuaLineinfoEntry *lua_new_lineinfo_entry(){
	LuaLineinfoEntry *entry;
	rz_return_val_if_fail((entry = RZ_NEW0(LuaLineinfoEntry)), NULL);
	return entry;
}

LuaUpvalueEntry *lua_new_upvalue_entry(){
	LuaUpvalueEntry *entry;
	rz_return_val_if_fail((entry = RZ_NEW0(LuaUpvalueEntry)), NULL);
	return entry;
}

LuaConstEntry *lua_new_const_entry(){
	LuaConstEntry *entry;
	rz_return_val_if_fail((entry = RZ_NEW0(LuaConstEntry)), NULL);
	return entry;
}

LuaProto *lua_new_proto_entry(){
	LuaProto *proto;
	rz_return_val_if_fail((proto = RZ_NEW0(LuaProto)), NULL);

	proto->const_entries = rz_list_new();
	if (proto->const_entries == NULL){
		eprintf("Init Const Entry List Failed\n");
		RZ_FREE(proto);
		return NULL;
	}

	proto->upvalue_entries = rz_list_new();
	if (proto->upvalue_entries == NULL){
		eprintf("Init Upvalue Entry List Failed\n");
		rz_list_free(proto->const_entries);
		RZ_FREE(proto);
		return NULL;
	}

        proto->proto_entries = rz_list_new();
	if (proto->proto_entries == NULL){
		eprintf("Init Proto Entry List Failed\n");
                rz_list_free(proto->const_entries);
		rz_list_free(proto->upvalue_entries);
                RZ_FREE(proto);
		return NULL;
	}

	proto->line_info_entries = rz_list_new();
	if (proto->line_info_entries == NULL){
		eprintf("Init Debug Line Info Failed\n");
                rz_list_free(proto->const_entries);
                rz_list_free(proto->upvalue_entries);
		rz_list_free(proto->proto_entries);
                RZ_FREE(proto);
		return NULL;
	}

	proto->abs_line_info_entries = rz_list_new();
	if (proto->abs_line_info_entries == NULL){
		eprintf("Init Abs Line Info Failed\n");
                rz_list_free(proto->const_entries);
                rz_list_free(proto->upvalue_entries);
                rz_list_free(proto->proto_entries);
		rz_list_free(proto->line_info_entries);
		RZ_FREE(proto);
		return NULL;
	}

	proto->local_var_info_entries = rz_list_new();
	if (proto->local_var_info_entries == NULL){
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
        if (proto->dbg_upvalue_entries == NULL){
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

	return proto;
}

void lua_free_dbg_upvalue_entry(LuaDbgUpvalueEntry *entry){
	if (entry == NULL){
		return;
	}
	if (entry->upvalue_name != NULL){
		RZ_FREE(entry->upvalue_name);
	}
	RZ_FREE(entry);
}

void lua_free_local_var_entry(LuaLocalVarEntry *entry){
	if (entry == NULL){
		return;
	}
	if (entry->varname != NULL){
		RZ_FREE(entry->varname);
	}
	RZ_FREE(entry);
}

void lua_free_const_entry(LuaConstEntry *entry){
	if (entry == NULL){
		return;
	}
	if (entry->data != NULL){
		RZ_FREE(entry->data);
	}
	RZ_FREE(entry);
}

void lua_free_abs_lineinfo_entry(LuaAbsLineinfoEntry *entry){
	if (entry == NULL){
		return;
	}
	RZ_FREE(entry);
}

void lua_free_lineinfo_entry(LuaLineinfoEntry *entry){
	if (entry == NULL){
		return;
	}
	RZ_FREE(entry);
}

void lua_free_upvalue_entry(LuaUpvalueEntry *entry){
	if (entry == NULL){
		return;
	}

	RZ_FREE(entry);
}

void lua_free_proto_entry(LuaProto *proto){
	RzListIter *iter;

	/* free constants entries */
	LuaConstEntry *const_entry;
	rz_list_foreach(proto->const_entries, iter, const_entry){
		if (const_entry == NULL){
			continue;
		}
		lua_free_const_entry(const_entry);
		const_entry = NULL;
	}
	rz_list_free(proto->const_entries);
	proto->const_entries = NULL;

	/* free upvalue entries */
	LuaUpvalueEntry *upvalue_entry;
	rz_list_foreach(proto->upvalue_entries, iter, upvalue_entry){
		if (upvalue_entry == NULL){
			continue;
		}
		lua_free_upvalue_entry(upvalue_entry);
		upvalue_entry = NULL;
	}
	rz_list_free(proto->upvalue_entries);
	proto->upvalue_entries = NULL;

	/* free debug */
	LuaLineinfoEntry *lineinfo_entry;
	LuaAbsLineinfoEntry *abs_entry;
	LuaLocalVarEntry *var_entry;
	LuaDbgUpvalueEntry *dbg_entry;

	rz_list_foreach(proto->line_info_entries, iter, lineinfo_entry){
		if (lineinfo_entry == NULL){
			continue;
		}
		lua_free_lineinfo_entry(lineinfo_entry);
		lineinfo_entry = NULL;
	}
	rz_list_foreach(proto->abs_line_info_entries, iter, abs_entry){
		if (abs_entry == NULL){
			continue;
		}
		lua_free_abs_lineinfo_entry(abs_entry);
		abs_entry = NULL;
	}
	rz_list_foreach(proto->local_var_info_entries, iter, var_entry){
		if (var_entry == NULL){
			continue;
		}
		lua_free_local_var_entry(var_entry);
		var_entry = NULL;
	}
	rz_list_foreach(proto->dbg_upvalue_entries, iter, dbg_entry){
		if (dbg_entry == NULL){
			continue;
		}
		lua_free_dbg_upvalue_entry(dbg_entry);
		dbg_entry = NULL;
	}

	rz_list_free(proto->line_info_entries);
	rz_list_free(proto->abs_line_info_entries);
	rz_list_free(proto->local_var_info_entries);
	rz_list_free(proto->dbg_upvalue_entries);
	proto->line_info_entries = NULL;
	proto->abs_line_info_entries = NULL;
	proto->local_var_info_entries = NULL;
	proto->dbg_upvalue_entries = NULL;

	/* recursively free protos */
	LuaProto *sub_proto;
	rz_list_foreach(proto->proto_entries, iter, sub_proto){
		if (sub_proto == NULL){
			continue;
		}
		lua_free_proto_entry(sub_proto);
		sub_proto = NULL;
	}
	rz_list_free(proto->proto_entries);
	proto->proto_entries = NULL;

	RZ_FREE(proto->proto_name);
	RZ_FREE(proto);
}