// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

// Implement Functions declared in luac_specs.h

#include "luac_common.h"
int lua_store_function(LuaFunction *function, LuaMetaData *lua_data){
        if (!lua_data->function_list){
                lua_data->function_list = rz_list_new();
                if (!lua_data->function_list){
                        eprintf("init lua function list failed\n");
                        return 0;
                }
        }
        rz_list_append(lua_data->function_list, function);
        return 1;
}

LuaFunction *lua_find_function_by_addr(ut64 addr, LuaMetaData *lua_data){
        if (!lua_data->function_list){
                return NULL;
        }
        LuaFunction *function = NULL;
        RzListIter *iter = NULL;
        rz_list_foreach(lua_data->function_list, iter, function){
                        if (function->offset == addr){
                                return function;
                        }
                }
        return NULL;
}

LuaFunction *lua_find_function_by_code_addr(ut64 addr, LuaMetaData *lua_data){
        if (!lua_data->function_list) {
                return NULL;
        }
        LuaFunction *function = NULL;
        RzListIter *iter = NULL;
        rz_list_foreach (lua_data->function_list, iter, function) {
                        if (function->code_offset + lua_data->integer_size <= addr && addr < function->const_offset) {
                                return function;
                        }
                }
        return NULL;
}