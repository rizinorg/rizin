// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#ifndef BUILD_LUA_ARCH_H
#define BUILD_LUA_ARCH_H

#include <rz_types.h>
#include <rz_asm.h>

/* Prefix of lua op arguments */
#define LUA_REG_PREF     "R"
#define LUA_CONST_PREF   "CONST"
#define LUA_KR_PREF      "R/CONST"
#define LUA_UPVALUE_PREF "UPV"
#define LUA_EVENT_PREF   "EVENT"
#define LUA_KPROTO_PREF  "KPROTO"
#define LUA_NO_PREFIX    ""

/* Comment Mark */
#define LUA_EXTRAARG_MARK "#Ex"
#define LUA_KFLAG_MARK    "#Kflag"
#define LUA_JMP_MARK      "#To"
#define LUA_CLOSURE_MARK  "#CLOSURE"
#define LUA_KX_MARK       " CONST[#Ex]"

/* Opcode Instruction Type */
typedef ut32 LuaInstruction;

/* opcode names */
typedef char **LuaOpNameList;

/* convert a 4-byte ut8 buffer into a lua instruction (ut32) */
LuaInstruction lua_build_instruction(const ut8 *buf);
void lua_set_instruction(LuaInstruction instruction, ut8 *data);
int lua_load_next_arg_start(const char *raw_string, char *recv_buf);
bool lua_is_valid_num_value_string(const char *str);
int lua_convert_str_to_num(const char *str);

/* formatted output strings */
char *luaop_new_str_3arg(char *opname, int a, int b, int c);
char *luaop_new_str_2arg(char *opname, int a, int b);
char *luaop_new_str_1arg(char *opname, int a);
char *luaop_new_str_3arg_ex(char *opname, int a, int b, int c, int isk);
char *luaop_new_str_2arg_ex(char *opname, int a, int b, int isk);
char *luaop_new_str_1arg_ex(char *opname, int a, int isk);
/* Free Opname List */
bool free_lua_opnames(LuaOpNameList list);

/* Lua 5.4 specified */
int lua54_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
int lua54_anal_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);
bool lua54_assembly(const char *input, st32 input_size, LuaInstruction *instruction);
LuaOpNameList get_lua54_opnames(void);
ut8 get_lua54_opcode_by_name(const char *name, int len);

/* Lua 5.3 specified */
int lua53_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
int lua53_anal_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);
bool lua53_assembly(const char *input, st32 input_size, LuaInstruction *instruction);
LuaOpNameList get_lua53_opnames(void);
ut8 get_lua53_opcode_by_name(const char *name, int len);

#endif // BUILD_LUA_ARCH_H
