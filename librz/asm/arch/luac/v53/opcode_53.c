//
// Created by heersin on 3/24/21.
//
#include "arch_53.h"

LuaOpNameList get_lua54_opnames(void) {
	LuaOpNameList list = RZ_NEWS(char *, LUA_NUM_OPCODES + 1);
	if (list == NULL) {
		eprintf("No Op Names\n");
		return NULL;
	}

	// Do not free the const string
	list[OP_MOVE] = "OP_MOVE";
	list[OP_LOADK] = "OP_LOADK";
	list[OP_LOADKX] = "OP_LOADKX";
	list[OP_LOADBOOL] = "OP_LOADBOOL";
	list[OP_LOADNIL] = "OP_LOADNIL";
	list[OP_GETUPVAL] = "OP_GETUPVAL";
	list[OP_GETTABUP] = "OP_GETTABUP";
	list[OP_GETTABLE] = "OP_GETTABLE";
	list[OP_SETTABUP] = "OP_SETTABUP";
	list[OP_SETUPVAL] = "OP_SETUPVAL";
	list[OP_SETTABLE] = "OP_SETTABLE";
	list[OP_NEWTABLE] = "OP_NEWTABLE";
	list[OP_SELF] = "OP_SELF";
	list[OP_ADD] = "OP_ADD";
	list[OP_SUB] = "OP_SUB";
	list[OP_MUL] = "OP_MUL";
	list[OP_MOD] = "OP_MOD";
	list[OP_POW] = "OP_POW";
	list[OP_DIV] = "OP_DIV";
	list[OP_IDIV] = "OP_IDIV";
	list[OP_BAND] = "OP_BAND";
	list[OP_BOR] = "OP_BOR";
	list[OP_BXOR] = "OP_BXOR";
	list[OP_SHL] = "OP_SHL";
	list[OP_SHR] = "OP_SHR";
	list[OP_UNM] = "OP_UNM";
	list[OP_BNOT] = "OP_BNOT";
	list[OP_NOT] = "OP_NOT";
	list[OP_LEN] = "OP_LEN";
	list[OP_CONCAT] = "OP_CONCAT";
	list[OP_JMP] = "OP_JMP";
	list[OP_EQ] = "OP_EQ";
	list[OP_LT] = "OP_LT";
	list[OP_LE] = "OP_LE";
	list[OP_TEST] = "OP_TEST";
	list[OP_TESTSET] = "OP_TESTSET ";
	list[OP_CALL] = "OP_CALL ";
	list[OP_TAILCALL] = "OP_TAILCALL";
	list[OP_RETURN] = "OP_RETURN";
	list[OP_FORLOOP] = "OP_FORLOOP ";
	list[OP_FORPREP] = "OP_FORPREP ";
	list[OP_TFORCALL] = "OP_TFORCALL";
	list[OP_TFORLOOP] = "OP_TFORLOOP";
	list[OP_SETLIST] = "OP_SETLIST ";
	list[OP_CLOSURE] = "OP_CLOSURE ";
	list[OP_VARARG] = "OP_VARARG ";
	list[OP_EXTRAARG] = "OP_EXTRAARG";

	return list;
}
