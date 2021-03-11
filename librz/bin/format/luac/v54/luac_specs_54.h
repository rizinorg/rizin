// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#ifndef BUILD_LUAC_54_H
#define BUILD_LUAC_54_H

#include "librz/bin/format/luac/luac_common.h"

/* Macros for bin_luac.c */

/* luac 5.4 spec */
/* Header Information */
#define LUAC_54_FORMAT_OFFSET           0x05
#define LUAC_54_LUAC_DATA_OFFSET        0x06
#define LUAC_54_INSTRUCTION_SIZE_OFFSET 0x0C
#define LUAC_54_INTEGER_SIZE_OFFSET     0x0D
#define LUAC_54_NUMBER_SIZE_OFFSET      0x0E
#define LUAC_54_INTEGER_VALID_OFFSET    0x0F
#define LUAC_54_NUMBER_VALID_OFFSET     0x17
#define LUAC_54_UPVALUES_NUMBER_OFFSET  0x1F

#define LUAC_54_SIGNATURE_SIZE        4
#define LUAC_54_VERSION_SIZE          1
#define LUAC_54_FORMAT_SIZE           1
#define LUAC_54_LUAC_DATA_SIZE        6
#define LUAC_54_INSTRUCTION_SIZE_SIZE 1
#define LUAC_54_INTEGER_SIZE_SIZE     1
#define LUAC_54_NUMBER_SIZE_SIZE      1
#define LUAC_54_INTEGER_VALID_SIZE    8
#define LUAC_54_NUMBER_VALID_SIZE     8
#define LUAC_54_UPVALUES_NUMBER_SIZE  1

#define LUAC_54_FORMAT            0 /* this is the official format */
#define LUAC_54_DATA              "\x19\x93\r\n\x1a\n"
#define LUAC_54_INT_VALIDATION    0x5678
#define LUAC_54_NUMBER_VALIDATION luac_cast_num(370.5)

#define LUAC_54_HDRSIZE 0x20

/* Body */
#define LUAC_FILENAME_OFFSET 0x20

/* Lua Constant Tag */
#define makevariant(t,v)	((t) | ((v) << 4))

#define LUA_TBOOLEAN		1
#define LUA_TNIL		0
#define LUA_TNUMBER		3
#define LUA_TSTRING		4


#define LUA_VNIL makevariant(LUA_TNIL, 0)
#define LUA_VFALSE	makevariant(LUA_TBOOLEAN, 0)
#define LUA_VTRUE	makevariant(LUA_TBOOLEAN, 1)
#define LUA_VNUMINT	makevariant(LUA_TNUMBER, 0)  /* integer numbers */
#define LUA_VNUMFLT	makevariant(LUA_TNUMBER, 1)  /* float numbers */
#define LUA_VSHRSTR	makevariant(LUA_TSTRING, 0)  /* short strings */
#define LUA_VLNGSTR	makevariant(LUA_TSTRING, 1)  /* long strings */

/* Lua Functions */
void luaLoadBlock(void *src, void *dest, size_t size);
#define luaLoadVector(src, buf, n) luaLoadBlock(src, buf, (n) * sizeof((buf)[0]))
#define luaLoadVar(raw_data, var)  luaLoadVector(raw_data, &(var), 1)
LUA_INTEGER luaLoadInteger(ut8 *src);
LUA_NUMBER luaLoadNumber(ut8 *src);
size_t luaLoadUnsigned(ut8 *src, size_t src_buf_limit, size_t type_limit);
size_t luaLoadSize(ut8 *src, size_t src_buf_limit);
char *luaLoadString(ut8 *src, size_t src_buf_limit);
size_t lua_parse_unsigned(const ut8 *data, size_t *dest,size_t src_buf_limit, size_t type_limit);
size_t lua_parse_size(const ut8 *data, size_t *dest,size_t src_buf_limit);

/* Parse Luac Format */
ut64 lua_parse_protos(const ut8 *data, ut64 offset, ut64 size, LuaFunction *parent_func, LuaParseStruct *lua_parse, LuaMetaData *lua_data);
ut64 lua_parse_function(const ut8 *data, ut64 offset, ut64 size, LuaFunction *parent_func, LuaParseStruct *lua_parse, LuaMetaData *lua_data);
ut64 lua_parse_string(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data);
ut64 lua_parse_string_n(const ut8 *data, ut64 offset, ut64 size, char **str_ptr, ut64 *str_len, LuaParseStruct *lua_parse, LuaMetaData *lua_data);
ut64 lua_parse_code(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data);
ut64 lua_parse_constants(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data);
ut64 lua_parse_upvalues(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data);
ut64 lua_parse_debug(const ut8 *data, ut64 offset, ut64 size, LuaParseStruct *lua_parse, LuaMetaData *lua_data);


#endif //BUILD_LUAC_54_H
