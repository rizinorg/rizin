// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

// put common definition of luac

#ifndef BUILD_LUAC_COMMON_H
#define BUILD_LUAC_COMMON_H

#include <rz_bin.h>
#include <rz_lib.h>
#include <rz_list.h>

/* Macros/Typedefs used in luac */
typedef double LUA_NUMBER;
typedef uint32_t LUA_INSTRUCTION;
typedef uint64_t LUA_INTEGER;

/* Macro Functions */
/* type casts (a macro highlights casts in the code) */
#define luac_cast(t, exp) ((t)(exp))
#define luac_cast_num(i)  luac_cast(LUA_NUMBER, (i))
#define luac_cast_int(i)  luac_cast(int, (i))

/* Macros About Luac Format */
#define LUAC_MAGIC_OFFSET   0x00
#define LUAC_MAGIC_SIZE     4
#define LUAC_VERSION_OFFSET 0x04
#define LUAC_VERSION_SIZE   1

#define LUAC_MAGIC "\x1b\x4c\x75\x61"

typedef struct lua_metadata{
	int instruction_size;
	int integer_size;
	int number_size;
	RzList *function_list;

        // for 5.3
        int int_size;
	int size_size;

} LuaMetaData;

typedef struct lua_function {
	ut64 offset;

	char *name_ptr; // only valid in onFunction method
	ut64 name_size;

        size_t line_defined;      // line number of function start
        size_t lastline_defined;   // line number of function end
        ut8 num_params;
        ut8 is_vararg;
        ut8 max_stack_size;

        struct lua_function *parent_func;// if != NULL, should always be valid

        ut64 const_size;
        ut64 code_size;
        ut64 upvalue_size;
        ut64 protos_size;

        ut64 const_offset;
        ut64 code_offset;
        ut64 upvalue_offset;
        ut64 protos_offset;
        ut64 debug_offset;

        ut64 size;
} LuaFunction;
typedef LuaFunction LuaProto;

struct lua_parse_struct;
typedef void (*LuaOnFunction) (LuaFunction *function, struct lua_parse_struct *parseStruct);
typedef void (*LuaOnString) (const ut8 *data, ut64 offset, ut64 size, struct lua_parse_struct *parseStruct);
typedef void (*LuaOnConst) (const ut8 *data, ut64 offset, ut64 size, struct lua_parse_struct *parseStruct);
typedef struct lua_parse_struct {
        LuaOnString onString;
        LuaOnFunction onFunction;
        LuaOnConst onConst;
        void *data;
} LuaParseStruct;

/* ========================================================
 * Common Operation to LuaMetaData/LuaProto/LuaParseStruct
 * Implemented in 'bin/format/luac/luac_common.c'
 * ======================================================== */
int lua_store_function(LuaFunction *function, LuaMetaData *lua_data);
LuaFunction *lua_find_function_by_addr(ut64 addr, LuaMetaData *lua_data);
LuaFunction *lua_find_function_by_code_addr(ut64 addr, LuaMetaData *lua_data);

/* ========================================================
 * Common Operation to RzBinInfo
 * Implemented in 'bin/format/luac/luac_common.c'
 * ======================================================== */
void lua_add_section(RzList *list, const char *name, ut64 addr, ut32 size, bool is_func);
void lua_add_symbol(RzList *list, char *name, ut64 addr, ut32 size, const char *type);

void lua_add_sections(LuaFunction *func, LuaParseStruct *lua_parse);

/* ========================================================
 * Export version specified Api to bin_luac.c
 * Implemented in 'bin/format/luac/v[version]/bin_[version]
 * ======================================================== */
RzBinInfo *lua_info_54(RzBinFile *bf, st32 major, st32 minor);

#endif //BUILD_LUAC_COMMON_H
