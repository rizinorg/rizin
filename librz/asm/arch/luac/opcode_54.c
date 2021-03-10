// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "opcode.h"
#include "opcode_54.h"

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

int lua54_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList opnames) {
	if (len < 4) {
		eprintf("truncated opcode\n");
		return 0;
	}

	LuaInstruction instruction = lua_build_instruction(buf);
	LuaOpCode opcode = LUA_GET_OPCODE(instruction);

	/* Pre-fetch arguments */
	int a = LUA_GETARG_A(instruction);
	int b = LUA_GETARG_B(instruction);
	int c = LUA_GETARG_C(instruction);
	int ax = LUA_GETARG_Ax(instruction);
	int bx = LUA_GETARG_Bx(instruction);
	int sb = LUA_GETARG_sB(instruction);
	int sc = LUA_GETARG_sC(instruction);
	int sbx = LUA_GETARG_sBx(instruction);
	int isk = LUA_GETARG_k(instruction);
	int sj = LUA_GETARG_sJ(instruction);

	/* Debug only */
	eprintf("Parse Bytes %08x\n", ((ut32 *)buf)[0]);

	char *asm_string;

	switch (opcode) {
		/* iABC Instruction */
	case OP_SETTABUP: /*	A B C	UpValue[A][K[B]:string] := RK(C)		*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			ISK(isk),
			LUA_UPVALUE_PREF, LUA_CONST_PREF, LUA_KR_PREF);
		break;

	case OP_SETI: /*	A B C	R[A][B] := RK(C)				*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			ISK(isk),
			LUA_REG_PREF, LUA_NO_PREFIX, LUA_KR_PREF);
		break;

	case OP_GETI: /*	A B C	R[A] := R[B][C]					*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			NULL,
			LUA_REG_PREF, LUA_REG_PREF, LUA_NO_PREFIX);
		break;

	case OP_SELF: /*	A B C	R[A+1] := R[B]; R[A] := R[B][RK(C):string]	*/
	case OP_SETTABLE: /*	A B C	R[A][R[B]] := RK(C)				*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			ISK(isk),
			LUA_REG_PREF, LUA_REG_PREF, LUA_KR_PREF);
		break;

	case OP_SETFIELD: /*	A B C	R[A][K[B]:string] := RK(C)			*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			ISK(isk),
			LUA_REG_PREF, LUA_CONST_PREF, LUA_KR_PREF);
		break;

	case OP_MMBIN: /*	A B C	call C metamethod over R[A] and R[B]		*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			NULL,
			LUA_REG_PREF, LUA_REG_PREF, LUA_EVENT_PREF);
		break;

	case OP_GETTABUP: /*	A B C	R[A] := UpValue[B][K[C]:string]			*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			NULL,
			LUA_REG_PREF, LUA_UPVALUE_PREF, LUA_CONST_PREF);
		break;

	case OP_CALL: /*	A B C	R[A], ... ,R[A+C-2] := R[A](R[A+1], ... ,R[A+B-1]) */
		// TODO : In and Out status
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			NULL,
			LUA_NO_PREFIX, LUA_NO_PREFIX, LUA_NO_PREFIX);
		break;

	case OP_GETTABLE: /*	A B C	R[A] := R[B][R[C]]				*/
	case OP_ADD: /*	        A B C	R[A] := R[B] + R[C]				*/
	case OP_SUB: /*	        A B C	R[A] := R[B] - R[C]				*/
	case OP_MUL: /*	        A B C	R[A] := R[B] * R[C]				*/
	case OP_MOD: /*	        A B C	R[A] := R[B] % R[C]				*/
	case OP_POW: /* 	A B C	R[A] := R[B] ^ R[C]				*/
	case OP_DIV: /*	        A B C	R[A] := R[B] / R[C]				*/
	case OP_IDIV: /*	A B C	R[A] := R[B] // R[C]				*/
	case OP_BAND: /*	A B C	R[A] := R[B] & R[C]				*/
	case OP_BOR: /* 	A B C	R[A] := R[B] | R[C]				*/
	case OP_BXOR: /*	A B C	R[A] := R[B] ~ R[C]				*/
	case OP_SHL: /*	        A B C	R[A] := R[B] << R[C]				*/
	case OP_SHR: /*	        A B C	R[A] := R[B] >> R[C]				*/
		/* fall through */
		asm_string = luaop_new_str_3arg(opnames[opcode], a, b, c, NULL);
		break;

	case OP_ADDK: /*	A B C	R[A] := R[B] + K[C]				*/
	case OP_SUBK: /*	A B C	R[A] := R[B] - K[C]				*/
	case OP_MULK: /*	A B C	R[A] := R[B] * K[C]				*/
	case OP_MODK: /*	A B C	R[A] := R[B] % K[C]				*/
	case OP_POWK: /*	A B C	R[A] := R[B] ^ K[C]				*/
	case OP_DIVK: /*	A B C	R[A] := R[B] / K[C]				*/
	case OP_IDIVK: /*	A B C	R[A] := R[B] // K[C]				*/
	case OP_BANDK: /*	A B C	R[A] := R[B] & K[C]:integer			*/
	case OP_BORK: /*	A B C	R[A] := R[B] | K[C]:integer			*/
	case OP_BXORK: /*	A B C	R[A] := R[B] ~ K[C]:integer			*/
	case OP_GETFIELD: /*	A B C	R[A] := R[B][K[C]:string]			*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			NULL,
			LUA_REG_PREF, LUA_REG_PREF, LUA_CONST_PREF);
		break;

		/* iABC - k instructions */
		// TODO : In and Out Status
	case OP_TAILCALL: /*	A B C k	return R[A](R[A+1], ... ,R[A+B-1])		*/
	case OP_RETURN: /*	A B C k	return R[A], ... ,R[A+B-2]	(see note)	*/
		asm_string = luaop_new_str_3arg(opnames[opcode], a, b, c, NULL);
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			NULL,
			LUA_NO_PREFIX, LUA_NO_PREFIX, LUA_NO_PREFIX);
		break;

		// TODO : Handle Extra Argc (require data of next instruction)
	case OP_NEWTABLE: /*	A B C k	R[A] := {}					*/
	case OP_SETLIST: /*	A B C k	R[A][C+i] := R[A+i], 1 <= i <= B		*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			LUA_EXTRAARG_MARK,
			LUA_REG_PREF, LUA_NO_PREFIX, LUA_NO_PREFIX);
		break;

	case OP_MMBINK: /*	A B C k		call C metamethod over R[A] and K[B]	*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, c,
			ISFLIP(isk),
			LUA_REG_PREF, LUA_CONST_PREF, LUA_EVENT_PREF);
		break;

		/* iABC - signed B with k instruction */
	case OP_MMBINI: /*	A sB C k	call C metamethod over R[A] and sB	*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, sb, c,
			ISFLIP(isk),
			LUA_REG_PREF, LUA_NO_PREFIX, LUA_EVENT_PREF);
		break;

		/* iABC - c signed instructions */
	case OP_ADDI: /*	A B sC	R[A] := R[B] + sC				*/
	case OP_SHRI: /*	A B sC	R[A] := R[B] >> sC				*/
	case OP_SHLI: /*	A B sC	R[A] := sC << R[B]				*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, sc,
			NULL,
			LUA_REG_PREF, LUA_REG_PREF, LUA_NO_PREFIX);
		break;

		/* iABC - A & B instructions */
	case OP_MOVE: /*	A B	R[A] := R[B]					*/
	case OP_UNM: /*	        A B	R[A] := -R[B]					*/
	case OP_BNOT: /*	A B	R[A] := ~R[B]					*/
	case OP_NOT: /* 	A B	R[A] := not R[B]				*/
	case OP_LEN: /*	        A B	R[A] := #R[B] (length operator)			*/
		asm_string = luaop_new_str_2arg(opnames[opcode], a, b, NULL);
		break;

	case OP_CONCAT: /*	A B	R[A] := R[A].. ... ..R[A + B - 1]		*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, b,
			NULL,
			LUA_NO_PREFIX, LUA_NO_PREFIX);
		break;

		// TODO : In and Out Status
	case OP_LOADNIL: /*	A B	R[A], R[A+1], ..., R[A+B] := nil		*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, b,
			NULL,
			LUA_NO_PREFIX, LUA_NO_PREFIX);
		break;

	case OP_GETUPVAL: /*	A B	R[A] := UpValue[B]				*/
	case OP_SETUPVAL: /*	A B	UpValue[B] := R[A]				*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, b,
			NULL,
			LUA_REG_PREF, LUA_UPVALUE_PREF);
		break;

		/* iABC - A & B with k instructions */
	case OP_EQ: /*	        A B k	if ((R[A] == R[B]) ~= k) then pc++		*/
	case OP_LT: /*	        A B k	if ((R[A] <  R[B]) ~= k) then pc++		*/
	case OP_LE: /*	        A B k	if ((R[A] <= R[B]) ~= k) then pc++		*/
	case OP_TESTSET: /*	A B k	if (not R[B] == k) then pc++ else R[A] := R[B]	*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, isk,
			LUA_KFLAG_MARK,
			LUA_REG_PREF, LUA_REG_PREF, LUA_NO_PREFIX);
		break;

	case OP_EQK: /*	        A B k	if ((R[A] == K[B]) ~= k) then pc++		*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, b, isk,
			LUA_KFLAG_MARK,
			LUA_REG_PREF, LUA_CONST_PREF, LUA_NO_PREFIX);
		break;

		/* iABC - A & sB with k instructions */
	case OP_EQI: /*	        A sB k	if ((R[A] == sB) ~= k) then pc++		*/
	case OP_LTI: /*	        A sB k	if ((R[A] < sB) ~= k) then pc++			*/
	case OP_LEI: /*	        A sB k	if ((R[A] <= sB) ~= k) then pc++		*/
	case OP_GTI: /*	        A sB k	if ((R[A] > sB) ~= k) then pc++			*/
	case OP_GEI: /*	        A sB k	if ((R[A] >= sB) ~= k) then pc++		*/
		asm_string = luaop_new_str_3arg_ex(
			opnames[opcode],
			a, sb, isk,
			LUA_KFLAG_MARK,
			LUA_REG_PREF, LUA_NO_PREFIX, LUA_NO_PREFIX);
		break;

		/* iABC - A & C instructions */
		// TODO : In and Out Status
	case OP_TFORCALL: /*	A C	R[A+4], ... ,R[A+3+C] := R[A](R[A+1], R[A+2]);	*/
	case OP_VARARG: /*	A C	R[A], R[A+1], ..., R[A+C-2] = vararg		*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, c,
			NULL,
			LUA_NO_PREFIX, LUA_NO_PREFIX);
		break;

		/* iABC - single A instructions */
	case OP_LOADKX: /*	A	R[A] := K[extra arg] */
		asm_string = luaop_new_str_1arg(opnames[opcode], a, LUA_KX_MARK);
		break;

	case OP_LOADFALSE: /*	A	R[A] := false					*/
	case OP_LFALSESKIP: /*  A	R[A] := false; pc++				*/
	case OP_LOADTRUE: /*	A	R[A] := true					*/
	case OP_CLOSE: /*	A	close all upvalues >= R[A]			*/
	case OP_TBC: /*	        A	mark variable A "to be closed"			*/
	case OP_RETURN1: /*	A	return R[A]					*/
	case OP_VARARGPREP: /*  A	(adjust vararg parameters)			*/
		asm_string = luaop_new_str_1arg(opnames[opcode], a, NULL);
		break;

		/* iABC - special instructions */
	case OP_TEST: /*	A k	if (not R[A] == k) then pc++			*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, isk,
			NULL,
			LUA_REG_PREF, LUA_NO_PREFIX);
		break;

	case OP_RETURN0: /*		return						*/
		asm_string = rz_str_newf("RETURN0");
		break;

		/* iABx instructions */
	case OP_LOADK: /*	A Bx	R[A] := K[Bx]					*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, bx,
			NULL,
			LUA_REG_PREF, LUA_CONST_PREF);
		break;

		// TODO : PC status
	case OP_FORLOOP: /*	A Bx	update counters; if loop continues then pc-=Bx; */
	case OP_FORPREP: /*	A Bx	<check values and prepare counters>;
                     if not to run then pc+=Bx+1;			*/
	case OP_TFORPREP: /*	A Bx	create upvalue for R[A + 3]; pc+=Bx		*/
	case OP_TFORLOOP: /*	A Bx	if R[A+2] ~= nil then { R[A]=R[A+2]; pc -= Bx }	*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, bx,
			LUA_JMP_MARK,
			LUA_NO_PREFIX, LUA_NO_PREFIX);
		break;

	case OP_CLOSURE: /*	A Bx	R[A] := closure(KPROTO[Bx])			*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, bx,
			LUA_CLOSURE_MARK,
			LUA_REG_PREF, LUA_KPROTO_PREF);
		break;

		/* iAsBx instructions */
	case OP_LOADI: /*	A sBx	R[A] := sBx					*/
	case OP_LOADF: /*	A sBx	R[A] := (lua_Number)sBx				*/
		asm_string = luaop_new_str_2arg_ex(
			opnames[opcode],
			a, sbx,
			NULL,
			LUA_REG_PREF, LUA_NO_PREFIX);
		break;

		/* iAx instructions */
	case OP_EXTRAARG: /*	Ax	extra (larger) argument for previous opcode	*/
		asm_string = luaop_new_str_1arg_ex(
			opnames[opcode],
			ax,
			NULL,
			LUA_NO_PREFIX);
		break;

		/* isJ instructions */
		// TODO : PC status
	case OP_JMP: /*	        sJ	pc += sJ					*/
		asm_string = luaop_new_str_1arg_ex(
			opnames[opcode],
			sj,
			LUA_JMP_MARK,
			LUA_NO_PREFIX);
		break;

	default:
		asm_string = rz_str_newf("INVALID");
	}

	rz_strbuf_append(&op->buf_asm, asm_string);
	RZ_FREE(asm_string);
	return 4;
}
