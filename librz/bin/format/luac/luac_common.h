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
#define LUA_SIZE_MAX_BYTE 8

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

/* Solution A: only store offset info about different parts
 * Leave parsing work to function */
typedef struct lua_proto {
	ut64 offset;    // proto offset in bytes
	ut64 size;      // current proto size

	char *proto_name;       // proto name
	ut64 name_size;         // size of proto name

	ut64 line_defined;      // line number of function start
	ut64 lastline_defined;  // line number of function end

	ut8 num_params;         // number of parameters of this proto
	ut8 is_vararg;          // is varArg?
	ut8 max_stack_size;     // max stack size

	/* Code of this proto */
	ut64 code_offset;
	ut64 code_size;

	/* Constants of this proto */
	ut64 const_offset;
	ut64 const_cnt;
	ut64 const_size;

	/* Upvalues of this proto */
	ut64 upvalues_offset;
	ut64 upvalues_cnt;
	ut64 upvalues_size;

	/* Protos defined in this proto */
	ut64 protos_offset;
	ut64 protos_cnt;
	ut64 protos_size;

	/* Debug info */
	ut64 lineinfo_offset;
	ut64 lineinfo_cnt;
	ut64 lineinfo_size;

	ut64 abs_lineinfo_offset;
	ut64 abs_lineinfo_cnt;
	ut64 abs_lineinfo_size;

	ut64 local_vars_offset;
	ut64 local_vars_cnt;
	ut64 local_vars_size;

	ut64 dbg_upvalues_offset;
	ut64 dbg_upvalues_cnt;
	ut64 dbg_upvalues_size;

} LuaProtoLight;


/* =================================================
 * Solution B : store info in a big struct
 * construct it in one turn scan
 * then we can operate on it only
 * =================================================*/
typedef struct lua_proto_ex{
        ut64 offset;    // proto offset in bytes
        ut64 size;      // current proto size

        ut8 *proto_name;       // proto name
        int name_size;         // size of proto name

        ut64 line_defined;      // line number of function start
        ut64 lastline_defined;  // line number of function end

        ut8 num_params;         // number of parameters of this proto
        ut8 is_vararg;          // is varArg?
        ut8 max_stack_size;     // max stack size

        /* Code of this proto */
        ut64 code_offset;
        ut64 code_size;

	/* store constant entries */
	RzList *const_entries;
	ut64 const_offset;

	/* store upvalue entries */
	RzList *upvalue_entries;
	ut64 upvalue_offset;

	/* store protos defined in this proto */
	RzList *proto_entries;
	ut64 inner_proto_offset;

	/* store Debug info */
	ut64 debug_offset;
	ut64 debug_size;
	RzList *line_info_entries;
	RzList *abs_line_info_entries;
	RzList *local_var_info_entries;
	RzList *dbg_upvalue_entries;

} LuaProtoHeavy;

/* Choose one of them */
typedef LuaProtoHeavy LuaProto;
// typedef LuaProtoLight LuaProto;

typedef struct lua_constant_entry{
	ut8 tag;                // type of this constant
	void *data;             // can be Number/Integer/String
	int data_len;
        ut64 offset;            // addr of this constant
} LuaConstEntry;

typedef struct lua_upvalue_entry{
	/* attribute of upvalue */
	ut8 instack;
	ut8 idx;
	ut8 kind;
	ut64 offset;
} LuaUpvalueEntry;

typedef struct LuaProto LuaProtoEntry;

typedef struct lua_lineinfo_entry{
	ut8 info_data;
	ut64 offset;
} LuaLineinfoEntry;

typedef struct lua_abs_lineinfo_entry{
	int pc;                /* pc in lua */
	int line;              /* line number in source file */
	ut64 offset;
} LuaAbsLineinfoEntry;

typedef struct lua_local_var_entry{
	ut8 *varname;
	int varname_len;
	int start_pc;
	int end_pc;
	ut64 offset;
} LuaLocalVarEntry;

typedef struct lua_dbg_upvalue_entry{
	ut8 *upvalue_name;
	int name_len;
	ut64 offset;
}LuaDbgUpvalueEntry;

/* ========================================================
 * Common Operation to RzBinInfo & Lua common structures
 * Implemented in 'bin/format/luac/luac_common.c'
 * ======================================================== */
LuaDbgUpvalueEntry *lua_new_dbg_upvalue_entry();
LuaLocalVarEntry *lua_new_local_var_entry();
LuaAbsLineinfoEntry *lua_new_abs_lineinfo_entry();
LuaLineinfoEntry *lua_new_lineinfo_entry();
LuaUpvalueEntry *lua_new_upvalue_entry();
LuaConstEntry *lua_new_const_entry();
LuaProto *lua_new_proto_entry();

void lua_free_dbg_upvalue_entry(LuaDbgUpvalueEntry *);
void lua_free_local_var_entry(LuaLocalVarEntry *);
void lua_free_abs_lineinfo_entry(LuaLocalVarEntry *);
void lua_free_lineinfo_entry(LuaLineinfoEntry *);
void lua_free_upvalue_entry(LuaUpvalueEntry *);
void lua_free_const_entry(LuaConstEntry *);
void lua_free_proto_entry(LuaProto *);

/* ========================================================
 * Export version specified Api to bin_luac.c
 * Implemented in 'bin/format/luac/v[version]/bin_[version]
 * ======================================================== */
RzBinInfo *lua_info_54(RzBinFile *bf, st32 major, st32 minor);
LuaProto *lua_parse_body_54(ut8 *data, ut64 offset, ut64 data_size);

#endif //BUILD_LUAC_COMMON_H
