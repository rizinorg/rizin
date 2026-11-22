// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_2.1.h"

static char *luajit_opname[LUAJIT_NUM_OPCODES] = {
	[LUAJIT_OP_ISLT] = "islt",
	[LUAJIT_OP_ISGE] = "isge",
	[LUAJIT_OP_ISLE] = "isle",
	[LUAJIT_OP_ISGT] = "isgt",
	[LUAJIT_OP_ISEQV] = "iseqv",
	[LUAJIT_OP_ISNEV] = "isnev",
	[LUAJIT_OP_ISEQS] = "iseqs",
	[LUAJIT_OP_ISNES] = "isnes",
	[LUAJIT_OP_ISEQN] = "iseqn",
	[LUAJIT_OP_ISNEN] = "isnen",
	[LUAJIT_OP_ISEQP] = "iseqp",
	[LUAJIT_OP_ISNEP] = "isnep",

	// --- Test and Copy Ops ---
	[LUAJIT_OP_ISTC] = "istc",
	[LUAJIT_OP_ISFC] = "isfc",
	[LUAJIT_OP_IST] = "ist",
	[LUAJIT_OP_ISF] = "isf",
	[LUAJIT_OP_ISTYPE] = "istype",
	[LUAJIT_OP_ISNUM] = "isnum",

	// --- Unary Ops ---
	[LUAJIT_OP_MOV] = "mov",
	[LUAJIT_OP_NOT] = "not",
	[LUAJIT_OP_UNM] = "unm",
	[LUAJIT_OP_LEN] = "len",

	// --- Binary Math Ops (VN = Var/Num, NV = Num/Var, VV = Var/Var) ---
	[LUAJIT_OP_ADDVN] = "addvn",
	[LUAJIT_OP_SUBVN] = "subvn",
	[LUAJIT_OP_MULVN] = "mulvn",
	[LUAJIT_OP_DIVVN] = "divvn",
	[LUAJIT_OP_MODVN] = "modvn",
	[LUAJIT_OP_ADDNV] = "addnv",
	[LUAJIT_OP_SUBNV] = "subnv",
	[LUAJIT_OP_MULNV] = "mulnv",
	[LUAJIT_OP_DIVNV] = "divnv",
	[LUAJIT_OP_MODNV] = "modnv",
	[LUAJIT_OP_ADDVV] = "addvv",
	[LUAJIT_OP_SUBVV] = "subvv",
	[LUAJIT_OP_MULVV] = "mulvv",
	[LUAJIT_OP_DIVVV] = "divvv",
	[LUAJIT_OP_MODVV] = "modvv",
	[LUAJIT_OP_POW] = "pow",
	[LUAJIT_OP_CAT] = "cat",

	// --- Constant Ops ---
	[LUAJIT_OP_KSTR] = "kstr",
	[LUAJIT_OP_KCDATA] = "kcdata",
	[LUAJIT_OP_KSHORT] = "kshort",
	[LUAJIT_OP_KNUM] = "knum",
	[LUAJIT_OP_KPRI] = "kpri",
	[LUAJIT_OP_KNIL] = "knil",

	// --- Upvalue and Function Ops ---
	[LUAJIT_OP_UGET] = "uget",
	[LUAJIT_OP_USETV] = "usetv",
	[LUAJIT_OP_USETS] = "usets",
	[LUAJIT_OP_USETN] = "usetn",
	[LUAJIT_OP_USETP] = "usetp",
	[LUAJIT_OP_UCLO] = "uclo",
	[LUAJIT_OP_FNEW] = "fnew",

	// --- Table Ops ---
	[LUAJIT_OP_TNEW] = "tnew",
	[LUAJIT_OP_TDUP] = "tdup",
	[LUAJIT_OP_GGET] = "gget",
	[LUAJIT_OP_GSET] = "gset",
	[LUAJIT_OP_TGETV] = "tgetv",
	[LUAJIT_OP_TGETS] = "tgets",
	[LUAJIT_OP_TGETB] = "tgetb",
	[LUAJIT_OP_TGETR] = "tgetr",
	[LUAJIT_OP_TSETV] = "tsetv",
	[LUAJIT_OP_TSETS] = "tsets",
	[LUAJIT_OP_TSETB] = "tsetb",
	[LUAJIT_OP_TSETM] = "tsetm",
	[LUAJIT_OP_TSETR] = "tsetr",

	// --- Calls and Returns ---
	[LUAJIT_OP_CALLM] = "callm",
	[LUAJIT_OP_CALL] = "call",
	[LUAJIT_OP_CALLMT] = "callmt",
	[LUAJIT_OP_CALLT] = "callt",
	[LUAJIT_OP_ITERC] = "iterc",
	[LUAJIT_OP_ITERN] = "itern",
	[LUAJIT_OP_VARG] = "varg",
	[LUAJIT_OP_ISNEXT] = "isnext",
	[LUAJIT_OP_RETM] = "retm",
	[LUAJIT_OP_RET] = "ret",
	[LUAJIT_OP_RET0] = "ret0",
	[LUAJIT_OP_RET1] = "ret1",

	// --- Loops and Branches ---
	[LUAJIT_OP_FORI] = "fori",
	[LUAJIT_OP_JFORI] = "jfori",
	[LUAJIT_OP_FORL] = "forl",
	[LUAJIT_OP_IFORL] = "iforl",
	[LUAJIT_OP_JFORL] = "jforl",
	[LUAJIT_OP_ITERL] = "iterl",
	[LUAJIT_OP_IITERL] = "iiterl",
	[LUAJIT_OP_JITERL] = "jiterl",
	[LUAJIT_OP_LOOP] = "loop",
	[LUAJIT_OP_ILOOP] = "iloop",
	[LUAJIT_OP_JLOOP] = "jloop",
	[LUAJIT_OP_JMP] = "jmp",

	// --- Function Headers ---
	[LUAJIT_OP_FUNCF] = "funcf",
	[LUAJIT_OP_IFUNCF] = "ifuncf",
	[LUAJIT_OP_JFUNCF] = "jfuncf",
	[LUAJIT_OP_FUNCV] = "funcv",
	[LUAJIT_OP_IFUNCV] = "ifuncv",
	[LUAJIT_OP_JFUNCV] = "jfuncv",
	[LUAJIT_OP_FUNCC] = "funcc",
	[LUAJIT_OP_FUNCCW] = "funccw",

};

LuaJITOpName luajit_get_opname(LuaJITOpCode opcode) {
	if (opcode < 0 || opcode >= LUAJIT_NUM_OPCODES) {
		return "unknown";
	}
	return luajit_opname[opcode];
}