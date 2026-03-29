// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_2.1.h"

static char *luajit_opname[LUAJIT_NUM_OPCODES] = {
	[OP_ISLT] = "islt",
	[OP_ISGE] = "isge",
	[OP_ISLE] = "isle",
	[OP_ISGT] = "isgt",
	[OP_ISEQV] = "iseqv",
	[OP_ISNEV] = "isnev",
	[OP_ISEQS] = "iseqs",
	[OP_ISNES] = "isnes",
	[OP_ISEQN] = "iseqn",
	[OP_ISNEN] = "isnen",
	[OP_ISEQP] = "iseqp",
	[OP_ISNEP] = "isnep",

	// --- Test and Copy Ops ---
	[OP_ISTC] = "istc",
	[OP_ISFC] = "isfc",
	[OP_IST] = "ist",
	[OP_ISF] = "isf",
	[OP_ISTYPE] = "istype",
	[OP_ISNUM] = "isnum",

	// --- Unary Ops ---
	[OP_MOV] = "mov",
	[OP_NOT] = "not",
	[OP_UNM] = "unm",
	[OP_LEN] = "len",

	// --- Binary Math Ops (VN = Var/Num, NV = Num/Var, VV = Var/Var) ---
	[OP_ADDVN] = "addvn",
	[OP_SUBVN] = "subvn",
	[OP_MULVN] = "mulvn",
	[OP_DIVVN] = "divvn",
	[OP_MODVN] = "modvn",
	[OP_ADDNV] = "addnv",
	[OP_SUBNV] = "subnv",
	[OP_MULNV] = "mulnv",
	[OP_DIVNV] = "divnv",
	[OP_MODNV] = "modnv",
	[OP_ADDVV] = "addvv",
	[OP_SUBVV] = "subvv",
	[OP_MULVV] = "mulvv",
	[OP_DIVVV] = "divvv",
	[OP_MODVV] = "modvv",
	[OP_POW] = "pow",
	[OP_CAT] = "cat",

	// --- Constant Ops ---
	[OP_KSTR] = "kstr",
	[OP_KCDATA] = "kcdata",
	[OP_KSHORT] = "kshort",
	[OP_KNUM] = "knum",
	[OP_KPRI] = "kpri",
	[OP_KNIL] = "knil",

	// --- Upvalue and Function Ops ---
	[OP_UGET] = "uget",
	[OP_USETV] = "usetv",
	[OP_USETS] = "usets",
	[OP_USETN] = "usetn",
	[OP_USETP] = "usetp",
	[OP_UCLO] = "uclo",
	[OP_FNEW] = "fnew",

	// --- Table Ops ---
	[OP_TNEW] = "tnew",
	[OP_TDUP] = "tdup",
	[OP_GGET] = "gget",
	[OP_GSET] = "gset",
	[OP_TGETV] = "tgetv",
	[OP_TGETS] = "tgets",
	[OP_TGETB] = "tgetb",
	[OP_TGETR] = "tgetr",
	[OP_TSETV] = "tsetv",
	[OP_TSETS] = "tsets",
	[OP_TSETB] = "tsetb",
	[OP_TSETM] = "tsetm",
	[OP_TSETR] = "tsetr",

	// --- Calls and Returns ---
	[OP_CALLM] = "callm",
	[OP_CALL] = "call",
	[OP_CALLMT] = "callmt",
	[OP_CALLT] = "callt",
	[OP_ITERC] = "iterc",
	[OP_ITERN] = "itern",
	[OP_VARG] = "varg",
	[OP_ISNEXT] = "isnext",
	[OP_RETM] = "retm",
	[OP_RET] = "ret",
	[OP_RET0] = "ret0",
	[OP_RET1] = "ret1",

	// --- Loops and Branches ---
	[OP_FORI] = "fori",
	[OP_JFORI] = "jfori",
	[OP_FORL] = "forl",
	[OP_IFORL] = "iforl",
	[OP_JFORL] = "jforl",
	[OP_ITERL] = "iterl",
	[OP_IITERL] = "iiterl",
	[OP_JITERL] = "jiterl",
	[OP_LOOP] = "loop",
	[OP_ILOOP] = "iloop",
	[OP_JLOOP] = "jloop",
	[OP_JMP] = "jmp",

	// --- Function Headers ---
	[OP_FUNCF] = "funcf",
	[OP_IFUNCF] = "ifuncf",
	[OP_JFUNCF] = "jfuncf",
	[OP_FUNCV] = "funcv",
	[OP_IFUNCV] = "ifuncv",
	[OP_JFUNCV] = "jfuncv",
	[OP_FUNCC] = "funcc",
	[OP_FUNCCW] = "funccw",

};

LuaJITOpName luajit_get_opname(LuaJITOpCode opcode) {
	if (opcode < 0 || opcode >= LUAJIT_NUM_OPCODES) {
		return "unknown";
	}
	return luajit_opname[opcode];
}