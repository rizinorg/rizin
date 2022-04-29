// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

// put common definition of luac

#ifndef BUILD_LUAC_COMMON_H
#define BUILD_LUAC_COMMON_H

#include <rz_bin.h>
#include <rz_lib.h>
#include <rz_list.h>

typedef ut32 LUA_INSTRUCTION;

/* Macros About Luac Format */
#define LUAC_MAGIC_OFFSET   0x00
#define LUAC_MAGIC_SIZE     4
#define LUAC_VERSION_OFFSET 0x04
#define LUAC_VERSION_SIZE   1

#define LUAC_MAGIC "\x1b\x4c\x75\x61"

/* Lua Constant Tag */
#define makevariant(t, v) ((t) | ((v) << 4))

#define LUA_TNIL     0
#define LUA_TBOOLEAN 1
#define LUA_TNUMBER  3
#define LUA_TSTRING  4

#define LUA_VNIL    makevariant(LUA_TNIL, 0)
#define LUA_VFALSE  makevariant(LUA_TBOOLEAN, 0)
#define LUA_VTRUE   makevariant(LUA_TBOOLEAN, 1)
#define LUA_VNUMINT makevariant(LUA_TNUMBER, 0) /* integer numbers */
#define LUA_VNUMFLT makevariant(LUA_TNUMBER, 1) /* float numbers */
#define LUA_VSHRSTR makevariant(LUA_TSTRING, 0) /* short strings */
#define LUA_VLNGSTR makevariant(LUA_TSTRING, 1) /* long strings */

/**
 *  \struct lua_proto_ex
 *  \brief Store valuable info when parsing. Treat luac file body as a main function.
 */
typedef struct lua_proto_ex {
	ut64 offset; ///< proto offset in bytes
	ut64 size; ///< current proto size

	ut8 *proto_name; ///<  current proto name
	int name_size; ///< size of proto name

	ut64 line_defined; ///< line number of function start
	ut64 lastline_defined; ///< line number of function end

	ut8 num_params; ///< number of parameters of this proto
	ut8 is_vararg; ///< is variable arg?
	ut8 max_stack_size; ///< max stack size

	/* Code of this proto */
	ut64 code_offset; ///< code section offset
	ut64 code_size; ///< code section size
	ut64 code_skipped; ///< opcode data offset to code_offset.

	/* store constant entries */
	RzList *const_entries; ///< A list to store constant entries
	ut64 const_offset; ///< const section offset
	ut64 const_size; ///< const section size

	/* store upvalue entries */
	RzList *upvalue_entries; ///< A list to store upvalue entries
	ut64 upvalue_offset; ///< upvalue section offset
	ut64 upvalue_size; ///< upvalue section size

	/* store protos defined in this proto */
	RzList *proto_entries; ///< A list to store sub proto entries
	ut64 inner_proto_offset; ///< sub proto section offset
	ut64 inner_proto_size; ///< sub proto section size

	/* store Debug info */
	ut64 debug_offset; ///< debug section offset
	ut64 debug_size; ///< debug section size
	RzList *line_info_entries; ///< A list to store line info entries
	RzList *abs_line_info_entries; ///< A list to store absolutely line info entries
	RzList *local_var_info_entries; ///< A list to store local var entries
	RzList *dbg_upvalue_entries; ///< A list to store upvalue names

} LuaProtoHeavy;

typedef LuaProtoHeavy LuaProto;

/**
 * \struct lua_constant_entry
 * \brief Store constant type, data, and offset of this constant in luac file
 */
typedef struct lua_constant_entry {
	ut8 tag; ///< type of this constant, see LUA_V* macros in luac_common.h
	void *data; ///< can be Number/Integer/String
	int data_len; ///< len of data
	ut64 offset; ///< addr of this constant
} LuaConstEntry;

/**
 * \struct lua_upvalue_entry
 * \brief Store upvalue attributes
 */
typedef struct lua_upvalue_entry {
	/* attributes of upvalue */
	ut8 instack; ///< is in stack
	ut8 idx; ///< index
	ut8 kind; ///< kind
	ut64 offset; ///< offset of this upvalue
} LuaUpvalueEntry;

typedef struct LuaProto LuaProtoEntry;

/**
 * \struct lua_lineinfo_entry
 * \brief Store line info attributes
 */
typedef struct lua_lineinfo_entry {
	ut32 info_data;
	ut64 offset;
} LuaLineinfoEntry;

/**
 * \struct lua_abs_lineinfo_entry
 * \brief Store line info attributes
 */
typedef struct lua_abs_lineinfo_entry {
	int pc; ///< pc value of lua
	int line; ///< line number in source file
	ut64 offset;
} LuaAbsLineinfoEntry;

/**
 * \struct lua_local_var_entry
 * \brief Store local var names and other info
 */
typedef struct lua_local_var_entry {
	ut8 *varname; ///< name of this variable
	int varname_len; ///< length of name
	int start_pc; ///< first active position
	int end_pc; ///< first deactive position
	ut64 offset; ///< offset of this entry
} LuaLocalVarEntry;

/**
 * \struct lua_dbg_upvalue_entry
 * \brief Store upvalue's debug info
 */
typedef struct lua_dbg_upvalue_entry {
	ut8 *upvalue_name; ///< upvalue name
	int name_len; ///< length of name
	ut64 offset;
} LuaDbgUpvalueEntry;

/**
 * \struct lua_bin_info
 * \brief A context info structure for luac plugin.
 */
typedef struct luac_bin_info {
	st32 major; ///< major version
	st32 minor; ///< minor version
	RzList *section_list; ///< list of sections
	RzList *symbol_list; ///< list of symbols
	RzList *entry_list; ///< list of entries
	RzList *string_list; ///< list of strings
	RzBinInfo *general_info; ///< general binary info from luac header
} LuacBinInfo;

/* ========================================================
 * Common Operation to Lua structures
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
void lua_free_const_entry(LuaConstEntry *);
void lua_free_proto_entry(LuaProto *);

/* ========================================================
 * Common Operation to RzBinInfo
 * Implemented in 'bin/format/luac/luac_bin.c'
 * ======================================================== */
void luac_add_section(RzList *section_list, char *name, ut64 offset, ut32 size, bool is_func);
void luac_add_symbol(RzList *symbol_list, char *name, ut64 offset, ut64 size, const char *type);
void luac_add_entry(RzList *entry_list, ut64 offset, int entry_type);
void luac_add_string(RzList *string_list, char *string, ut64 offset, ut64 size);

LuacBinInfo *luac_build_info(LuaProto *proto);
void _luac_build_info(LuaProto *proto, LuacBinInfo *info);

/* ========================================================
 * Export version specified Api to bin_luac.c
 * Implemented in 'bin/format/luac/v[version]/bin_[version]
 * ======================================================== */
RzBinInfo *lua_parse_header_54(RzBinFile *bf, st32 major, st32 minor);
LuaProto *lua_parse_body_54(RzBuffer *buffer, ut64 offset, ut64 data_size);

RzBinInfo *lua_parse_header_53(RzBinFile *bf, st32 major, st32 minor);
LuaProto *lua_parse_body_53(RzBuffer *buffer, ut64 offset, ut64 data_size);

#define lua_check_error_offset(offset) \
	if ((offset) == 0) { \
		return 0; \
	}
#define lua_check_error_offset_proto(offset, proto) \
	if ((offset) == 0) { \
		lua_free_proto_entry((proto)); \
		return NULL; \
	}
#define lua_return_if_null(proto) \
	if ((proto) == NULL) { \
		return 0; \
	}

#endif // BUILD_LUAC_COMMON_H
