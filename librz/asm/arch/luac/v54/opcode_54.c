// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "arch_54.h"
#define lua_strcase(name, case_str) if (rz_str_ncasecmp((name), (case_str), sizeof(case_str) - 1) == 0)

LuaOpNameList get_lua54_opnames(void) {
	LuaOpNameList list = RZ_NEWS(char *, LUA_NUM_OPCODES + 1);
	if (list == NULL) {
		eprintf("No Op Names\n");
		return NULL;
	}

	// Do not free the const string
	list[OP_MOVE] = "MOVE";
	list[OP_LOADI] = "LOADI",
	list[OP_LOADF] = "LOADF",
	list[OP_LOADK] = "LOADK",
	list[OP_LOADKX] = "LOADKX",
	list[OP_LOADFALSE] = "LOADFALSE",
	list[OP_LFALSESKIP] = "LFALSESKIP",
	list[OP_LOADTRUE] = "LOADTRUE",
	list[OP_LOADNIL] = "LOADNIL",
	list[OP_GETUPVAL] = "GETUPVAL",
	list[OP_SETUPVAL] = "SETUPVAL",
	list[OP_GETTABUP] = "GETTABUP",
	list[OP_GETTABLE] = "GETTABLE",
	list[OP_GETI] = "GETI",
	list[OP_GETFIELD] = "GETFIELD",
	list[OP_SETTABUP] = "SETTABUP",
	list[OP_SETTABLE] = "SETTABLE",
	list[OP_SETI] = "SETI",
	list[OP_SETFIELD] = "SETFIELD",
	list[OP_NEWTABLE] = "NEWTABLE",
	list[OP_SELF] = "SELF",
	list[OP_ADDI] = "ADDI",
	list[OP_ADDK] = "ADDK",
	list[OP_SUBK] = "SUBK",
	list[OP_MULK] = "MULK",
	list[OP_MODK] = "MODK",
	list[OP_POWK] = "POWK",
	list[OP_DIVK] = "DIVK",
	list[OP_IDIVK] = "IDIVK",
	list[OP_BANDK] = "BANDK",
	list[OP_BORK] = "BORK",
	list[OP_BXORK] = "BXORK",
	list[OP_SHRI] = "SHRI",
	list[OP_SHLI] = "SHLI",
	list[OP_ADD] = "ADD",
	list[OP_SUB] = "SUB",
	list[OP_MUL] = "MUL",
	list[OP_MOD] = "MOD",
	list[OP_POW] = "POW",
	list[OP_DIV] = "DIV",
	list[OP_IDIV] = "IDIV",
	list[OP_BAND] = "BAND",
	list[OP_BOR] = "BOR",
	list[OP_BXOR] = "BXOR",
	list[OP_SHL] = "SHL",
	list[OP_SHR] = "SHR",
	list[OP_MMBIN] = "MMBIN",
	list[OP_MMBINI] = "MMBINI",
	list[OP_MMBINK] = "MMBINK",
	list[OP_UNM] = "UNM",
	list[OP_BNOT] = "BNOT",
	list[OP_NOT] = "NOT",
	list[OP_LEN] = "LEN",
	list[OP_CONCAT] = "CONCAT",
	list[OP_CLOSE] = "CLOSE",
	list[OP_TBC] = "TBC",
	list[OP_JMP] = "JMP",
	list[OP_EQ] = "EQ",
	list[OP_LT] = "LT",
	list[OP_LE] = "LE",
	list[OP_EQK] = "EQK",
	list[OP_EQI] = "EQI",
	list[OP_LTI] = "LTI",
	list[OP_LEI] = "LEI",
	list[OP_GTI] = "GTI",
	list[OP_GEI] = "GEI",
	list[OP_TEST] = "TEST",
	list[OP_TESTSET] = "TESTSET",
	list[OP_CALL] = "CALL",
	list[OP_TAILCALL] = "TAILCALL",
	list[OP_RETURN] = "RETURN",
	list[OP_RETURN0] = "RETURN0",
	list[OP_RETURN1] = "RETURN1",
	list[OP_FORLOOP] = "FORLOOP",
	list[OP_FORPREP] = "FORPREP",
	list[OP_TFORPREP] = "TFORPREP",
	list[OP_TFORCALL] = "TFORCALL",
	list[OP_TFORLOOP] = "TFORLOOP",
	list[OP_SETLIST] = "SETLIST",
	list[OP_CLOSURE] = "CLOSURE",
	list[OP_VARARG] = "VARARG",
	list[OP_VARARGPREP] = "VARARGPREP",
	list[OP_EXTRAARG] = "EXTRAARG",
	list[LUA_NUM_OPCODES] = NULL;

	return list;
}

ut8 get_lua54_opcode_by_name(const char *name) {
	lua_strcase(name, "move") return OP_MOVE;
	lua_strcase(name, "loadi") return OP_LOADI;
	lua_strcase(name, "loadf") return OP_LOADF;
	lua_strcase(name, "loadk") return OP_LOADK;
	lua_strcase(name, "loadkx") return OP_LOADKX;
	lua_strcase(name, "loadfalse") return OP_LOADFALSE;
	lua_strcase(name, "lfalseskip") return OP_LFALSESKIP;
	lua_strcase(name, "loadtrue") return OP_LOADTRUE;
	lua_strcase(name, "loadnil") return OP_LOADNIL;
	lua_strcase(name, "getupval") return OP_GETUPVAL;
	lua_strcase(name, "setupval") return OP_SETUPVAL;

	lua_strcase(name, "gettabup") return OP_GETTABUP;
	lua_strcase(name, "gettable") return OP_GETTABLE;
	lua_strcase(name, "geti") return OP_GETI;
	lua_strcase(name, "getfield") return OP_GETFIELD;

	lua_strcase(name, "settabup") return OP_SETTABUP;
	lua_strcase(name, "settable") return OP_SETTABLE;
	lua_strcase(name, "seti") return OP_SETI;
	lua_strcase(name, "setfield") return OP_SETFIELD;

	lua_strcase(name, "newtable") return OP_NEWTABLE;

	lua_strcase(name, "self") return OP_SELF;

	lua_strcase(name, "addi") return OP_ADDI;

	lua_strcase(name, "addk") return OP_ADDK;
	lua_strcase(name, "subk") return OP_SUBK;
	lua_strcase(name, "mulk") return OP_MULK;
	lua_strcase(name, "modk") return OP_MODK;
	lua_strcase(name, "powk") return OP_POWK;
	lua_strcase(name, "divk") return OP_DIVK;
	lua_strcase(name, "idivk") return OP_IDIVK;

	lua_strcase(name, "bandk") return OP_BANDK;
	lua_strcase(name, "bork") return OP_BORK;
	lua_strcase(name, "bxork") return OP_BXORK;

	lua_strcase(name, "shri") return OP_SHRI;
	lua_strcase(name, "shli") return OP_SHLI;

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

	lua_strcase(name, "mmbin") return OP_MMBIN;
	lua_strcase(name, "mmbini") return OP_MMBINI;
	lua_strcase(name, "mmbink") return OP_MMBINK;

	lua_strcase(name, "unm") return OP_UNM;
	lua_strcase(name, "bnot") return OP_BNOT;
	lua_strcase(name, "not") return OP_NOT;
	lua_strcase(name, "len") return OP_LEN;
	lua_strcase(name, "concat") return OP_CONCAT;

	lua_strcase(name, "close") return OP_CLOSE;
	lua_strcase(name, "tbc") return OP_TBC;
	lua_strcase(name, "jmp") return OP_JMP;
	lua_strcase(name, "eq") return OP_EQ;
	lua_strcase(name, "lt") return OP_LT;
	lua_strcase(name, "le") return OP_LE;

	lua_strcase(name, "eqk") return OP_EQK;
	lua_strcase(name, "eqi") return OP_EQI;
	lua_strcase(name, "lti") return OP_LTI;
	lua_strcase(name, "lei") return OP_LEI;
	lua_strcase(name, "gti") return OP_GTI;
	lua_strcase(name, "gei") return OP_GEI;

	lua_strcase(name, "test") return OP_TEST;
	lua_strcase(name, "testset") return OP_TESTSET;

	lua_strcase(name, "call") return OP_CALL;
	lua_strcase(name, "tailcall") return OP_TAILCALL;

	lua_strcase(name, "return") return OP_RETURN;
	lua_strcase(name, "return0") return OP_RETURN0;
	lua_strcase(name, "return1") return OP_RETURN1;

	lua_strcase(name, "forloop") return OP_FORLOOP;
	lua_strcase(name, "forprep") return OP_FORPREP;

	lua_strcase(name, "tforprep") return OP_TFORPREP;
	lua_strcase(name, "tforcall") return OP_TFORCALL;
	lua_strcase(name, "tforloop") return OP_TFORLOOP;

	lua_strcase(name, "setlist") return OP_SETLIST;

	lua_strcase(name, "closure") return OP_CLOSURE;

	lua_strcase(name, "vararg") return OP_VARARG;

	lua_strcase(name, "varargprep") return OP_VARARGPREP;

	lua_strcase(name, "extraarg") return OP_EXTRAARG;

	return OP_EXTRAARG + 1; //invalid
}