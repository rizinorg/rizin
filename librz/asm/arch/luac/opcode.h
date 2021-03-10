// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#ifndef BUILD_OPCODE_H
#define BUILD_OPCODE_H

#include <rz_types.h>
#include <rz_asm.h>

/* Prefix of lua op arguments */
#define LUA_REG_PREF "R"
#define LUA_CONST_PREF "CONST"
#define LUA_KR_PREF "R/CONST"
#define LUA_UPVALUE_PREF "UPV"
#define LUA_EVENT_PREF "EVENT"
#define LUA_KPROTO_PREF "KPROTO"
#define LUA_NO_PREFIX ""

/* Comment Mark */
#define LUA_EXTRAARG_MARK  "#Ex"
#define LUA_KFLAG_MARK "#Kflag"
#define LUA_JMP_MARK "#To"
#define LUA_CLOSURE_MARK "#CLOSURE"
#define LUA_KX_MARK " CONST[#Ex]"

/* Opcode Instruction Type */
typedef ut32 LuaInstruction;

/* opcode names */
typedef char **LuaOpNameList;

/* convert a 4-byte ut8 buffer into a lua instruction (ut32) */
LuaInstruction lua_build_instruction(const ut8 *buf);

/* formatted output strings */
char *luaop_new_str_3arg(char *opname, int a, int b, int c, char *mark);
char *luaop_new_str_2arg(char *opname, int a, int b, char *mark);
char *luaop_new_str_1arg(char *opname, int a, char *mark);
char *luaop_new_str_3arg_ex(char *opname, int a, int b, int c, char *mark, char *prefix_a, char *prefix_b, char *prefix_c);
char *luaop_new_str_2arg_ex(char *opname, int a, int b, char *mark, char *prefix_a, char *prefix_b);
char *luaop_new_str_1arg_ex(char *opname, int a, char *mark, char *prefix_a);

/* Free Opname List */
bool free_lua_opnames(LuaOpNameList list);

/* Lua 5.4 specified */
int lua54_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList oplist);
LuaOpNameList get_lua54_opnames(void);

#endif //BUILD_OPCODE_H
