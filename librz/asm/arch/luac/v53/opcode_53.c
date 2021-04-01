// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "arch_53.h"
#define lua_strcase(name, case_str) if (rz_str_ncasecmp((name), (case_str), sizeof(case_str) - 1) == 0)

LuaOpNameList get_lua53_opnames(void) {
	LuaOpNameList list = RZ_NEWS(char *, LUA_NUM_OPCODES + 1);
	if (list == NULL) {
		eprintf("No Op Names\n");
		return NULL;
	}

	// Do not free the const string
	list[OP_MOVE] = "move";
	list[OP_LOADK] = "loadk";
	list[OP_LOADKX] = "loadkx";
	list[OP_LOADBOOL] = "loadbool";
	list[OP_LOADNIL] = "loadnil";
	list[OP_GETUPVAL] = "getupval";
	list[OP_GETTABUP] = "gettabup";
	list[OP_GETTABLE] = "gettable";
	list[OP_SETTABUP] = "settabup";
	list[OP_SETUPVAL] = "setupval";
	list[OP_SETTABLE] = "settable";
	list[OP_NEWTABLE] = "newtable";
	list[OP_SELF] = "self";
	list[OP_ADD] = "add";
	list[OP_SUB] = "sub";
	list[OP_MUL] = "mul";
	list[OP_MOD] = "mod";
	list[OP_POW] = "pow";
	list[OP_DIV] = "div";
	list[OP_IDIV] = "idiv";
	list[OP_BAND] = "band";
	list[OP_BOR] = "bor";
	list[OP_BXOR] = "bxor";
	list[OP_SHL] = "shl";
	list[OP_SHR] = "shr";
	list[OP_UNM] = "unm";
	list[OP_BNOT] = "bnot";
	list[OP_NOT] = "not";
	list[OP_LEN] = "len";
	list[OP_CONCAT] = "concat";
	list[OP_JMP] = "jmp";
	list[OP_EQ] = "eq";
	list[OP_LT] = "lt";
	list[OP_LE] = "le";
	list[OP_TEST] = "test";
	list[OP_TESTSET] = "testset";
	list[OP_CALL] = "call";
	list[OP_TAILCALL] = "tailcall";
	list[OP_RETURN] = "return";
	list[OP_FORLOOP] = "forloop";
	list[OP_FORPREP] = "forprep";
	list[OP_TFORCALL] = "tforcall";
	list[OP_TFORLOOP] = "tforloop";
	list[OP_SETLIST] = "setlist";
	list[OP_CLOSURE] = "closure";
	list[OP_VARARG] = "vararg";
	list[OP_EXTRAARG] = "extraarg";

	return list;
}

ut8 get_lua53_opcode_by_name(const char *name) {
	lua_strcase(name, "move") return OP_MOVE;
	lua_strcase(name, "loadk") return OP_LOADK;
	lua_strcase(name, "loadkx") return OP_LOADKX;
	lua_strcase(name, "loadbool") return OP_LOADBOOL;
	lua_strcase(name, "loadnil") return OP_LOADNIL;
	lua_strcase(name, "getupval") return OP_GETUPVAL;
	lua_strcase(name, "gettabup") return OP_GETTABUP;
	lua_strcase(name, "gettable") return OP_GETTABLE;
	lua_strcase(name, "settabup") return OP_SETTABUP;
	lua_strcase(name, "setupval") return OP_SETUPVAL;
	lua_strcase(name, "settable") return OP_SETTABLE;
	lua_strcase(name, "newtable") return OP_NEWTABLE;

	lua_strcase(name, "self") return OP_SELF;
	lua_strcase(name, "add") return OP_ADD;
	lua_strcase(name, "sub") return OP_SUB;
	lua_strcase(name, "mul") return OP_MUL;
	lua_strcase(name, "mod") return OP_MOD;
	lua_strcase(name, "pow") return OP_POW;
	lua_strcase(name, "div") return OP_DIV;
	lua_strcase(name, "idiv") return OP_IDIV;
	lua_strcase(name, "band") return OP_BAND;
	lua_strcase(name, "bor") return OP_BOR;
	lua_strcase(name, "bxor") return OP_BXOR;
	lua_strcase(name, "shl") return OP_SHL;
	lua_strcase(name, "shr") return OP_SHR;
	lua_strcase(name, "unm") return OP_UNM;
	lua_strcase(name, "bnot") return OP_BNOT;
	lua_strcase(name, "not") return OP_NOT;

	lua_strcase(name, "len") return OP_LEN;
	lua_strcase(name, "concat") return OP_CONCAT;
	lua_strcase(name, "jmp") return OP_JMP;
	lua_strcase(name, "eq") return OP_EQ;
	lua_strcase(name, "lt") return OP_LT;
	lua_strcase(name, "le") return OP_LE;
	lua_strcase(name, "test") return OP_TEST;
	lua_strcase(name, "testset") return OP_TESTSET;

	lua_strcase(name, "call") return OP_CALL;
	lua_strcase(name, "tailcall") return OP_TAILCALL;
	lua_strcase(name, "return") return OP_RETURN;
	lua_strcase(name, "forloop") return OP_FORLOOP;
	lua_strcase(name, "forprep") return OP_FORPREP;
	lua_strcase(name, "tforcall") return OP_TFORCALL;
	lua_strcase(name, "tforloop") return OP_TFORLOOP;
	lua_strcase(name, "setlist") return OP_SETLIST;
	lua_strcase(name, "closure") return OP_CLOSURE;
	lua_strcase(name, "vararg") return OP_VARARG;
	lua_strcase(name, "extraarg") return OP_EXTRAARG;

	return OP_EXTRAARG + 1; //invalid
}