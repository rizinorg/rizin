// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2018 Maijin
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
	list[OP_MOVE] = "MOVE";
	list[OP_LOADK] = "LOADK";
	list[OP_LOADKX] = "LOADKX";
	list[OP_LOADBOOL] = "LOADBOOL";
	list[OP_LOADNIL] = "LOADNIL";
	list[OP_GETUPVAL] = "GETUPVAL";
	list[OP_GETTABUP] = "GETTABUP";
	list[OP_GETTABLE] = "GETTABLE";
	list[OP_SETTABUP] = "SETTABUP";
	list[OP_SETUPVAL] = "SETUPVAL";
	list[OP_SETTABLE] = "SETTABLE";
	list[OP_NEWTABLE] = "NEWTABLE";
	list[OP_SELF] = "SELF";
	list[OP_ADD] = "ADD";
	list[OP_SUB] = "SUB";
	list[OP_MUL] = "MUL";
	list[OP_MOD] = "MOD";
	list[OP_POW] = "POW";
	list[OP_DIV] = "DIV";
	list[OP_IDIV] = "IDIV";
	list[OP_BAND] = "BAND";
	list[OP_BOR] = "BOR";
	list[OP_BXOR] = "BXOR";
	list[OP_SHL] = "SHL";
	list[OP_SHR] = "SHR";
	list[OP_UNM] = "UNM";
	list[OP_BNOT] = "BNOT";
	list[OP_NOT] = "NOT";
	list[OP_LEN] = "LEN";
	list[OP_CONCAT] = "CONCAT";
	list[OP_JMP] = "JMP";
	list[OP_EQ] = "EQ";
	list[OP_LT] = "LT";
	list[OP_LE] = "LE";
	list[OP_TEST] = "TEST";
	list[OP_TESTSET] = "TESTSET ";
	list[OP_CALL] = "CALL ";
	list[OP_TAILCALL] = "TAILCALL";
	list[OP_RETURN] = "RETURN";
	list[OP_FORLOOP] = "FORLOOP ";
	list[OP_FORPREP] = "FORPREP ";
	list[OP_TFORCALL] = "TFORCALL";
	list[OP_TFORLOOP] = "TFORLOOP";
	list[OP_SETLIST] = "SETLIST ";
	list[OP_CLOSURE] = "CLOSURE ";
	list[OP_VARARG] = "VARARG ";
	list[OP_EXTRAARG] = "EXTRAARG";

	return list;
}

ut8 get_lua_opcode_by_name(const char *name, int n) {
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