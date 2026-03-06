// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_2.1.h"

LuaJITOpNameList get_luajit_opnames(void) {
	LuaJITOpNameList list = RZ_NEWS(char *, LUAJIT_NUM_OPCODES + 1);
	if (list == NULL) {
		RZ_LOG_ERROR("Cannot allocate luajit opcode list.\n");
		return NULL;
	}

	// --- Comparison Ops ---
	list[OP_ISLT] = "islt";
	list[OP_ISGE] = "isge";
	list[OP_ISLE] = "isle";
	list[OP_ISGT] = "isgt";
	list[OP_ISEQV] = "iseqv";
	list[OP_ISNEV] = "isnev";
	list[OP_ISEQS] = "iseqs";
	list[OP_ISNES] = "isnes";
	list[OP_ISEQN] = "iseqn";
	list[OP_ISNEN] = "isnen";
	list[OP_ISEQP] = "iseqp";
	list[OP_ISNEP] = "isnep";

	// --- Test and Copy Ops ---
	list[OP_ISTC] = "istc";
	list[OP_ISFC] = "isfc";
	list[OP_IST] = "ist";
	list[OP_ISF] = "isf";
	list[OP_ISTYPE] = "istype";
	list[OP_ISNUM] = "isnum";

	// --- Unary Ops ---
	list[OP_MOV] = "mov";
	list[OP_NOT] = "not";
	list[OP_UNM] = "unm";
	list[OP_LEN] = "len";

	// --- Binary Math Ops (VN = Var/Num, NV = Num/Var, VV = Var/Var) ---
	list[OP_ADDVN] = "addvn";
	list[OP_SUBVN] = "subvn";
	list[OP_MULVN] = "mulvn";
	list[OP_DIVVN] = "divvn";
	list[OP_MODVN] = "modvn";
	list[OP_ADDNV] = "addnv";
	list[OP_SUBNV] = "subnv";
	list[OP_MULNV] = "mulnv";
	list[OP_DIVNV] = "divnv";
	list[OP_MODNV] = "modnv";
	list[OP_ADDVV] = "addvv";
	list[OP_SUBVV] = "subvv";
	list[OP_MULVV] = "mulvv";
	list[OP_DIVVV] = "divvv";
	list[OP_MODVV] = "modvv";
	list[OP_POW] = "pow";
	list[OP_CAT] = "cat";

	// --- Constant Ops ---
	list[OP_KSTR] = "kstr";
	list[OP_KCDATA] = "kcdata";
	list[OP_KSHORT] = "kshort";
	list[OP_KNUM] = "knum";
	list[OP_KPRI] = "kpri";
	list[OP_KNIL] = "knil";

	// --- Upvalue and Function Ops ---
	list[OP_UGET] = "uget";
	list[OP_USETV] = "usetv";
	list[OP_USETS] = "usets";
	list[OP_USETN] = "usetn";
	list[OP_USETP] = "usetp";
	list[OP_UCLO] = "uclo";
	list[OP_FNEW] = "fnew";

	// --- Table Ops ---
	list[OP_TNEW] = "tnew";
	list[OP_TDUP] = "tdup";
	list[OP_GGET] = "gget";
	list[OP_GSET] = "gset";
	list[OP_TGETV] = "tgetv";
	list[OP_TGETS] = "tgets";
	list[OP_TGETB] = "tgetb";
	list[OP_TGETR] = "tgetr";
	list[OP_TSETV] = "tsetv";
	list[OP_TSETS] = "tsets";
	list[OP_TSETB] = "tsetb";
	list[OP_TSETM] = "tsetm";
	list[OP_TSETR] = "tsetr";

	// --- Calls and Returns ---
	list[OP_CALLM] = "callm";
	list[OP_CALL] = "call";
	list[OP_CALLMT] = "callmt";
	list[OP_CALLT] = "callt";
	list[OP_ITERC] = "iterc";
	list[OP_ITERN] = "itern";
	list[OP_VARG] = "varg";
	list[OP_ISNEXT] = "isnext";
	list[OP_RETM] = "retm";
	list[OP_RET] = "ret";
	list[OP_RET0] = "ret0";
	list[OP_RET1] = "ret1";

	// --- Loops and Branches ---
	list[OP_FORI] = "fori";
	list[OP_JFORI] = "jfori";
	list[OP_FORL] = "forl";
	list[OP_IFORL] = "iforl";
	list[OP_JFORL] = "jforl";
	list[OP_ITERL] = "iterl";
	list[OP_IITERL] = "iiterl";
	list[OP_JITERL] = "jiterl";
	list[OP_LOOP] = "loop";
	list[OP_ILOOP] = "iloop";
	list[OP_JLOOP] = "jloop";
	list[OP_JMP] = "jmp";

	// --- Function Headers ---
	list[OP_FUNCF] = "funcf";
	list[OP_IFUNCF] = "ifuncf";
	list[OP_JFUNCF] = "jfuncf";
	list[OP_FUNCV] = "funcv";
	list[OP_IFUNCV] = "ifuncv";
	list[OP_JFUNCV] = "jfuncv";
	list[OP_FUNCC] = "funcc";
	list[OP_FUNCCW] = "funccw";

	list[LUAJIT_NUM_OPCODES] = NULL;

	return list;
}