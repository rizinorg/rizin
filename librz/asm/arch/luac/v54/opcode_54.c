// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "arch_54.h"
#define lua_strcase(case_str) if ( \
	((limit) <= sizeof(case_str) - 1) && \
	rz_str_ncasecmp((name), (case_str), sizeof(case_str) - 1) == 0)

LuaOpNameList get_lua54_opnames(void) {
	LuaOpNameList list = RZ_NEWS(char *, LUA_NUM_OPCODES + 1);
	if (list == NULL) {
		RZ_LOG_ERROR("Cannot allocate lua54 opcode list.\n");
		return NULL;
	}

	// Do not free the const string
	list[OP_MOVE] = "move";
	list[OP_LOADI] = "loadi",
	list[OP_LOADF] = "loadf",
	list[OP_LOADK] = "loadk",
	list[OP_LOADKX] = "loadkx",
	list[OP_LOADFALSE] = "loadfalse",
	list[OP_LFALSESKIP] = "lfalseskip",
	list[OP_LOADTRUE] = "loadtrue",
	list[OP_LOADNIL] = "loadnil",
	list[OP_GETUPVAL] = "getupval",
	list[OP_SETUPVAL] = "setupval",
	list[OP_GETTABUP] = "gettabup",
	list[OP_GETTABLE] = "gettable",
	list[OP_GETI] = "geti",
	list[OP_GETFIELD] = "getfield",
	list[OP_SETTABUP] = "settabup",
	list[OP_SETTABLE] = "settable",
	list[OP_SETI] = "seti",
	list[OP_SETFIELD] = "setfield",
	list[OP_NEWTABLE] = "newtable",
	list[OP_SELF] = "self",
	list[OP_ADDI] = "addi",
	list[OP_ADDK] = "addk",
	list[OP_SUBK] = "subk",
	list[OP_MULK] = "mulk",
	list[OP_MODK] = "modk",
	list[OP_POWK] = "powk",
	list[OP_DIVK] = "divk",
	list[OP_IDIVK] = "idivk",
	list[OP_BANDK] = "bandk",
	list[OP_BORK] = "bork",
	list[OP_BXORK] = "bxork",
	list[OP_SHRI] = "shri",
	list[OP_SHLI] = "shli",
	list[OP_ADD] = "add",
	list[OP_SUB] = "sub",
	list[OP_MUL] = "mul",
	list[OP_MOD] = "mod",
	list[OP_POW] = "pow",
	list[OP_DIV] = "div",
	list[OP_IDIV] = "idiv",
	list[OP_BAND] = "band",
	list[OP_BOR] = "bor",
	list[OP_BXOR] = "bxor",
	list[OP_SHL] = "shl",
	list[OP_SHR] = "shr",
	list[OP_MMBIN] = "mmbin",
	list[OP_MMBINI] = "mmbini",
	list[OP_MMBINK] = "mmbink",
	list[OP_UNM] = "unm",
	list[OP_BNOT] = "bnot",
	list[OP_NOT] = "not",
	list[OP_LEN] = "len",
	list[OP_CONCAT] = "concat",
	list[OP_CLOSE] = "close",
	list[OP_TBC] = "tbc",
	list[OP_JMP] = "jmp",
	list[OP_EQ] = "eq",
	list[OP_LT] = "lt",
	list[OP_LE] = "le",
	list[OP_EQK] = "eqk",
	list[OP_EQI] = "eqi",
	list[OP_LTI] = "lti",
	list[OP_LEI] = "lei",
	list[OP_GTI] = "gti",
	list[OP_GEI] = "gei",
	list[OP_TEST] = "test",
	list[OP_TESTSET] = "testset",
	list[OP_CALL] = "call",
	list[OP_TAILCALL] = "tailcall",
	list[OP_RETURN] = "return",
	list[OP_RETURN0] = "return0",
	list[OP_RETURN1] = "return1",
	list[OP_FORLOOP] = "forloop",
	list[OP_FORPREP] = "forprep",
	list[OP_TFORPREP] = "tforprep",
	list[OP_TFORCALL] = "tforcall",
	list[OP_TFORLOOP] = "tforloop",
	list[OP_SETLIST] = "setlist",
	list[OP_CLOSURE] = "closure",
	list[OP_VARARG] = "vararg",
	list[OP_VARARGPREP] = "varargprep",
	list[OP_EXTRAARG] = "extraarg",
	list[LUA_NUM_OPCODES] = NULL;

	return list;
}

ut8 get_lua54_opcode_by_name(const char *name, int limit) {
	lua_strcase("move") return OP_MOVE;
	lua_strcase("loadi") return OP_LOADI;
	lua_strcase("loadf") return OP_LOADF;
	lua_strcase("loadk") return OP_LOADK;
	lua_strcase("loadkx") return OP_LOADKX;
	lua_strcase("loadfalse") return OP_LOADFALSE;
	lua_strcase("lfalseskip") return OP_LFALSESKIP;
	lua_strcase("loadtrue") return OP_LOADTRUE;
	lua_strcase("loadnil") return OP_LOADNIL;
	lua_strcase("getupval") return OP_GETUPVAL;
	lua_strcase("setupval") return OP_SETUPVAL;

	lua_strcase("gettabup") return OP_GETTABUP;
	lua_strcase("gettable") return OP_GETTABLE;
	lua_strcase("geti") return OP_GETI;
	lua_strcase("getfield") return OP_GETFIELD;

	lua_strcase("settabup") return OP_SETTABUP;
	lua_strcase("settable") return OP_SETTABLE;
	lua_strcase("seti") return OP_SETI;
	lua_strcase("setfield") return OP_SETFIELD;

	lua_strcase("newtable") return OP_NEWTABLE;

	lua_strcase("self") return OP_SELF;

	lua_strcase("addi") return OP_ADDI;

	lua_strcase("addk") return OP_ADDK;
	lua_strcase("subk") return OP_SUBK;
	lua_strcase("mulk") return OP_MULK;
	lua_strcase("modk") return OP_MODK;
	lua_strcase("powk") return OP_POWK;
	lua_strcase("divk") return OP_DIVK;
	lua_strcase("idivk") return OP_IDIVK;

	lua_strcase("bandk") return OP_BANDK;
	lua_strcase("bork") return OP_BORK;
	lua_strcase("bxork") return OP_BXORK;

	lua_strcase("shri") return OP_SHRI;
	lua_strcase("shli") return OP_SHLI;

	lua_strcase("add") return OP_ADD;
	lua_strcase("sub") return OP_SUB;
	lua_strcase("mul") return OP_MUL;
	lua_strcase("mod") return OP_MOD;
	lua_strcase("pow") return OP_POW;
	lua_strcase("div") return OP_DIV;
	lua_strcase("idiv") return OP_IDIV;

	lua_strcase("band") return OP_BAND;
	lua_strcase("bor") return OP_BOR;
	lua_strcase("bxor") return OP_BXOR;
	lua_strcase("shl") return OP_SHL;
	lua_strcase("shr") return OP_SHR;

	lua_strcase("mmbin") return OP_MMBIN;
	lua_strcase("mmbini") return OP_MMBINI;
	lua_strcase("mmbink") return OP_MMBINK;

	lua_strcase("unm") return OP_UNM;
	lua_strcase("bnot") return OP_BNOT;
	lua_strcase("not") return OP_NOT;
	lua_strcase("len") return OP_LEN;
	lua_strcase("concat") return OP_CONCAT;

	lua_strcase("close") return OP_CLOSE;
	lua_strcase("tbc") return OP_TBC;
	lua_strcase("jmp") return OP_JMP;
	lua_strcase("eq") return OP_EQ;
	lua_strcase("lt") return OP_LT;
	lua_strcase("le") return OP_LE;

	lua_strcase("eqk") return OP_EQK;
	lua_strcase("eqi") return OP_EQI;
	lua_strcase("lti") return OP_LTI;
	lua_strcase("lei") return OP_LEI;
	lua_strcase("gti") return OP_GTI;
	lua_strcase("gei") return OP_GEI;

	lua_strcase("test") return OP_TEST;
	lua_strcase("testset") return OP_TESTSET;

	lua_strcase("call") return OP_CALL;
	lua_strcase("tailcall") return OP_TAILCALL;

	lua_strcase("return") return OP_RETURN;
	lua_strcase("return0") return OP_RETURN0;
	lua_strcase("return1") return OP_RETURN1;

	lua_strcase("forloop") return OP_FORLOOP;
	lua_strcase("forprep") return OP_FORPREP;

	lua_strcase("tforprep") return OP_TFORPREP;
	lua_strcase("tforcall") return OP_TFORCALL;
	lua_strcase("tforloop") return OP_TFORLOOP;

	lua_strcase("setlist") return OP_SETLIST;

	lua_strcase("closure") return OP_CLOSURE;

	lua_strcase("vararg") return OP_VARARG;

	lua_strcase("varargprep") return OP_VARARGPREP;

	lua_strcase("extraarg") return OP_EXTRAARG;

	return OP_EXTRAARG + 1; // invalid
}