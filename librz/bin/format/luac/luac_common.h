// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#ifndef BUILD_LUAC_COMMON_H
#define BUILD_LUAC_COMMON_H

#include <rz_bin.h>
#include <rz_lib.h>
#include <rz_list.h>
#include <arch/isa/luac/lua_arch.h>

/* Macros for bin_luac.c */
#define METATABLES_VOFFSET             0x15000
#define PROTO_VADDRESS(index)          ((index * PROTO_VBANK) + PROTO_VBASE)
#define K_VADDRESS_BASE(proto_index)   PROTO_VADDRESS(proto_index) + CONST_OFFSET
#define VAR_VADDRESS_BASE(proto_index) PROTO_VADDRESS(proto_index) + LVARS_OFFSET
#define CHILD_VADDRESS(addr, b)        ((addr & ~0xFFF) + PROTO_VADDRESS(b))
#define K_VADDRESS(proto_index, index) PROTO_VADDRESS(proto_index) + CONST_OFFSET + (index * 0xFF)

#define PROTO_INDEX(addr)         (((addr & ~0xFFF) - PROTO_VBASE) >> 12)
#define VADDRESS_PROTO_BASE(addr) (addr & ~0xFFF)
#define CONST_VADDRESS(addr, b)   (VADDRESS_PROTO_BASE(addr) + CONST_OFFSET + ((b + 1) * 32))

#define PF_VAHID 1 /* function has hidden vararg arguments */
#define PF_VATAB 2 /* function has vararg table */
#define PF_FIXED 4 /* prototype has parts in fixed memory */

/* a vararg function either has hidden args. or a vararg table */
#define isvararg(flag) (flag & (PF_VAHID | PF_VATAB))

#define DEBUG_LINE_OFFSET(x) ((x > 0x80) ? (-((0xFF - x) + 1)) : x)

/* Macro Functions */
/* type casts (a macro highlights casts in the code) */
#define luac_cast(t, exp) ((t)(exp))
#define luac_cast_num(i)  luac_cast(double, (i))
#define luac_cast_int(i)  luac_cast(int, (i))

#define LUAC_MAGIC              "\x1b\x4c\x75\x61" ///< "\033Lua"
#define LUAC_MAGIC_SIZE         4
#define LUAC_FORMAT             0 /* this is the official format */
#define LUAC_DATA               "\x19\x93\r\n\x1a\n"
#define LUAC_INT_VALIDATION     luac_cast_int(0x5678)
#define LUAC5_INT_VALIDATION    luac_cast_int(0x12345678)
#define LUAC0_NUMBER_VALIDATION luac_cast_num(3.14159265358979323846E7)
#define LUAC_NUMBER_VALIDATION  luac_cast_num(370.5)
#define LUAC5_NUMBER_VALIDATION luac_cast_num(-370.5)

typedef ut32 LUA_INSTRUCTION;

/* Lua Constant Tag */
#define makevariant(t, v) ((t) | ((v) << 4))

#define LUA_TNIL        0
#define LUA_TBOOLEAN    1
#define LUA_TNUMBER     3
#define LUA_TSTRING     4
#define LUA_VSTRING_IDX 10

/* Macros of tag */
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
	ut32 index; ///< index for map protos
	ut64 offset; ///< proto offset in bytes
	ut64 size; ///< current proto size
	ut8 num_size; ///< numeric size for strings

	ut8 *proto_name; ///<  current proto name
	int name_size; ///< size of proto name

	ut32 line_defined; ///< line number of function start
	ut32 lastline_defined; ///< line number of function end

	ut8 nups; ///< 5.0 version
	ut8 num_params; ///< number of parameters of this proto
	ut8 is_vararg; ///< is variable arg?
	ut8 max_stack_size; ///< max stack size

	/* Code of this proto */
	ut64 code_offset; ///< code section offset
	ut64 code_size; ///< code section size
	ut64 code_skipped; ///< opcode data offset to code_offset.

	/* store constant entries */
	RzPVector /*<LuaConstEntry *>*/ *const_entries; ///< A list to store constant entries
	ut64 const_offset; ///< const section offset
	ut64 const_size; ///< const section size

	/* store upvalue entries */
	RzPVector /*<LuaUpvalueEntry *>*/ *upvalue_entries; ///< A list to store upvalue entries
	// RzList /*<LuaUpvalueEntry *>*/ *upvalue_entries; ///< A list to store upvalue entries
	ut64 upvalue_offset; ///< upvalue section offset
	ut64 upvalue_size; ///< upvalue section size
	ut64 size_upvalues; ///< upvalue size (v5.5)

	/* store protos defined in this proto */
	RzList /*<LuaProto *>*/ *proto_entries; ///< A list to store sub proto entries
	ut64 inner_proto_offset; ///< sub proto section offset
	ut64 inner_proto_size; ///< sub proto section size

	/* store Debug info */
	ut64 debug_offset; ///< debug section offset
	ut64 debug_size; ///< debug section size
	RzList /*<LuaLineinfoEntry *>*/ *line_info_entries; ///< A list to store line info entries
	RzList /*<LuaAbsLineinfoEntry *>*/ *abs_line_info_entries; ///< A list to store absolutely line info entries
	ut64 local_var_offset; ///< local var section offset
	ut64 local_var_size; ///< local var section size
	RzPVector /*<LuaLocalVarEntry *>*/ *local_var_info_entries; ///< A list to store local var entries
	// RzList /*<LuaLocalVarEntry *>*/ *local_var_info_entries; ///< A list to store local var entries
	RzPVector /*<LuaDbgUpvalueEntry *>*/ *dbg_upvalue_entries; ///< A list to store upvalue names
	// RzList /*<LuaDbgUpvalueEntry *>*/ *dbg_upvalue_entries; ///< A list to store upvalue names
} LuaProtoHeavy;

typedef LuaProtoHeavy LuaProto;

/**
 * \struct lua_header_info
 * \brief Store header information of luac file
 */
typedef struct lua_header_info {
	ut8 major; ///< major version
	ut8 minor; ///< minor version
	ut8 format; ///< official or unofficial compiler used
	ut8 endianness; ///< endianness on luac 5.1 and 5.2
	ut8 int_size; ///< size of int used, exclude 5.4
	ut8 size_t_size; ///< size of size_t used, < 5.4
	ut8 instruction_size; ///< size of instruction used
	ut8 integer_size; ///< size of lua integer used
	ut8 number_size; ///< size of lua number used
	ut8 is_number_integral; ///< is lua_Number integral? (< 5.3)
	bool is_openwrt; ///< may be custom system
	size_t psize; ///< physical size of header in bytes
	int proto_count; ///< proto index
	char *src_file_name;
} LuaHeaderInfo;

/**
 * \struct lua_constant_entry
 * \brief Store constant type, data, and offset of this constant in luac file
 */
typedef struct lua_constant_entry {
	ut8 tag; ///< type of this constant, see LUA_V* macros in luac_common.h
	void *data; ///< can be Number/Integer/String
	int data_len; ///< len of data
	ut64 offset; ///< addr of this constant
	ut64 prev_offset; ///< virtual addr of this constant
	ut64 string_start; ///< virtual addr of this constant
	ut64 voffset; ///< virtual addr of this constant
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
	ut64 voffset; ///< offset of this upvalue
	ut8 *upvalue_name; ///< upvalue name
	int name_len; ///< length of name
	ut64 name_offset;
} LuaUpvalueEntry;

typedef struct LuaProto LuaProtoEntry;

/**
 * \struct lua_lineinfo_entry
 * \brief Store line info attributes
 */
typedef struct lua_lineinfo_entry {
	ut8 info_data;
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
	ut64 voffset;
	size_t var_size;
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
 * \struct luac_bin_info
 * \brief A context info structure for luac plugin.
 */
typedef struct luac_bin_info {
	LuaProto *proto;
	RzPVector /*<LuaProto *>*/ *protos_vec; ///< list of all protos
	RzPVector /*<LuaConstEntry *>*/ *all_const_vec; ///< list of all constants (5.4-5.5)
	RzPVector /*<RzBinSection *>*/ *section_vec; ///< list of sections
	RzList /*<RzBinSymbol *>*/ *symbol_list; ///< list of symbols
	RzPVector /*<RzBinAddr *>*/ *entry_vec; ///< list of entries
	RzPVector /*<RzBinSourceLineSample *>*/ *line_nums_vec; ///< list of line numbers
	RzList /*<RzBinString *>*/ *string_list; ///< list of strings
	RzBinInfo *general_info; ///< general binary info from luac header
	LuaHeaderInfo *header;
	RzTypeDB *typedb;
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

void lua_free_upvalue_entry(LuaUpvalueEntry *);
void lua_free_dbg_upvalue_entry(LuaDbgUpvalueEntry *);
void lua_free_local_var_entry(LuaLocalVarEntry *);
void lua_free_const_entry(LuaConstEntry *);
void lua_free_proto_entry(LuaProto *);

/* ========================================================
 * Common Operation to RzBinInfo
 * Implemented in 'bin/format/luac/luac_bin.c'
 * ======================================================== */
void luac_add_section(RzPVector /*<RzBinSection *>*/ *section_vec, char *name, ut64 poffset, ut64 voffset, ut32 size, bool is_func);
void luac_add_symbol(RzList /*<RzBinSymbol *>*/ *symbol_list, char *name, ut64 poffset, ut64 voffset, ut64 size, const char *type);
void luac_add_entry(RzPVector /*<RzBinAddr *>*/ *entry_vec, ut64 offset, int entry_type);
void luac_add_string(RzList /*<RzBinString *>*/ *string_list, char *string, ut64 poffset, ut64 voffset, ut64 size);

LuacBinInfo *luac_build_info(RZ_NONNULL LuaProto *proto);
void luac_build_info_free(LuacBinInfo *bin_info);
void _luac_build_info(LuaProto *proto, LuacBinInfo *info);

/* ========================================================
 * Export version specified Api to bin_luac.c
 * Implemented in bin/format/luac/v[version]/bin_[version]
 * ======================================================== */
LuaProto *lua_parse_body(RzBuffer *buffer, LuaHeaderInfo *header, ut64 base_offset, ut64 data_size);
RzBinInfo *lua_parse_bin_info(const RzBinFile *bf, const LuaHeaderInfo *header);
size_t parse_header(const RzBinFile *bf, LuaHeaderInfo *header);

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

RZ_API bool rz_core_bin_apply_luac_debug(RzCore *core, RzBinFile *binfile);

LuacBinInfo *getLuacBinInfo(const RzAnalysis *analysis);
const char *get_metamethod_name(const ut8 minor, const ut32 index);
ut64 get_metamethod_address(const ut32 index);

ut64 get_const_address_b(const LuacBinInfo *lbi, ut64 addr, ut32 index);
#endif // BUILD_LUAC_COMMON_H
