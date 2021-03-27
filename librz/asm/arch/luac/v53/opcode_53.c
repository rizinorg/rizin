// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2018 Maijin
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "arch_53.h"

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
