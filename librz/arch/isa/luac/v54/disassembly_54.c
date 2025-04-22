// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "arch_54.h"

int lua54_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaOpNameList opnames) {
	if (len < 4) {
		RZ_LOG_DEBUG("Cannot disassemble lua54 opcode (truncated).\n");
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

	char *asm_string;

	switch (opcode) {
		/* iABC Instruction */
	case OP_GETI: /*	A B C	R[A] := R[B][C]					*/
	case OP_MMBIN: /*	A B C	call C metamethod over R[A] and R[B]		*/
	case OP_GETTABUP: /*	A B C	R[A] := UpValue[B][K[C]:string]			*/
	case OP_CALL: /*	A B C	R[A], ... ,R[A+C-2] := R[A](R[A+1], ... ,R[A+B-1]) */
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
		asm_string = luaop_new_str_3arg(opnames[opcode], a, b, c);
		break;
		/* iABC - k instructions */
	case OP_TAILCALL: /*	A B C k	return R[A](R[A+1], ... ,R[A+B-1])		*/
	case OP_RETURN: /*	A B C k	return R[A], ... ,R[A+B-2]	(see note)	*/
	case OP_NEWTABLE: /*	A B C k	R[A] := {}					*/
	case OP_SETLIST: /*	A B C k	R[A][C+i] := R[A+i], 1 <= i <= B		*/
	case OP_MMBINK: /*	A B C k		call C metamethod over R[A] and K[B]	*/
	case OP_SETTABUP: /*	A B C	UpValue[A][K[B]:string] := RK(C)		*/
	case OP_SETTABLE: /*	A B C	R[A][R[B]] := RK(C)				*/
	case OP_SETI: /*	A B C	R[A][B] := RK(C)				*/
	case OP_SETFIELD: /*	A B C	R[A][K[B]:string] := RK(C)			*/
	case OP_SELF: /*	A B C	R[A+1] := R[B]; R[A] := R[B][RK(C):string]	*/
		asm_string = luaop_new_str_3arg_ex(opnames[opcode], a, b, c, isk);
		break;
		/* iABC - signed B with k instruction */
	case OP_MMBINI: /*	A sB C k	call C metamethod over R[A] and sB	*/
		asm_string = luaop_new_str_3arg_ex(opnames[opcode], a, sb, c, isk);
		break;
		/* iABC - c signed instructions */
	case OP_ADDI: /*	A B sC	R[A] := R[B] + sC				*/
	case OP_SHRI: /*	A B sC	R[A] := R[B] >> sC				*/
	case OP_SHLI: /*	A B sC	R[A] := sC << R[B]				*/
		asm_string = luaop_new_str_3arg(opnames[opcode], a, b, sc);
		break;
		/* iABC - A & B instructions */
	case OP_MOVE: /*	A B	R[A] := R[B]					*/
	case OP_UNM: /*	        A B	R[A] := -R[B]					*/
	case OP_BNOT: /*	A B	R[A] := ~R[B]					*/
	case OP_NOT: /* 	A B	R[A] := not R[B]				*/
	case OP_LEN: /*	        A B	R[A] := #R[B] (length operator)			*/
	case OP_CONCAT: /*	A B	R[A] := R[A].. ... ..R[A + B - 1]		*/
	case OP_LOADNIL: /*	A B	R[A], R[A+1], ..., R[A+B] := nil		*/
	case OP_GETUPVAL: /*	A B	R[A] := UpValue[B]				*/
	case OP_SETUPVAL: /*	A B	UpValue[B] := R[A]				*/
		asm_string = luaop_new_str_2arg(opnames[opcode], a, b);
		break;

		/* iABC - A & B with k instructions */
	case OP_EQ: /*	        A B k	if ((R[A] == R[B]) ~= k) then pc++		*/
	case OP_LT: /*	        A B k	if ((R[A] <  R[B]) ~= k) then pc++		*/
	case OP_LE: /*	        A B k	if ((R[A] <= R[B]) ~= k) then pc++		*/
	case OP_TESTSET: /*	A B k	if (not R[B] == k) then pc++ else R[A] := R[B]	*/
	case OP_EQK: /*	        A B k	if ((R[A] == K[B]) ~= k) then pc++		*/
		asm_string = luaop_new_str_2arg_ex(opnames[opcode], a, b, isk);
		break;
		/* iABC - A & sB with k instructions */
	case OP_EQI: /*	        A sB k	if ((R[A] == sB) ~= k) then pc++		*/
	case OP_LTI: /*	        A sB k	if ((R[A] < sB) ~= k) then pc++			*/
	case OP_LEI: /*	        A sB k	if ((R[A] <= sB) ~= k) then pc++		*/
	case OP_GTI: /*	        A sB k	if ((R[A] > sB) ~= k) then pc++			*/
	case OP_GEI: /*	        A sB k	if ((R[A] >= sB) ~= k) then pc++		*/
		asm_string = luaop_new_str_2arg_ex(opnames[opcode], a, sb, isk);
		break;

		/* iABC - A & C instructions */
	case OP_TFORCALL: /*	A C	R[A+4], ... ,R[A+3+C] := R[A](R[A+1], R[A+2]);	*/
	case OP_VARARG: /*	A C	R[A], R[A+1], ..., R[A+C-2] = vararg		*/
		asm_string = luaop_new_str_2arg(opnames[opcode], a, c);
		break;

		/* iABC - single A instructions */
	case OP_LOADKX: /*	A	R[A] := K[extra arg] */
	case OP_LOADFALSE: /*	A	R[A] := false					*/
	case OP_LFALSESKIP: /*  A	R[A] := false; pc++				*/
	case OP_LOADTRUE: /*	A	R[A] := true					*/
	case OP_CLOSE: /*	A	close all upvalues >= R[A]			*/
	case OP_TBC: /*	        A	mark variable A "to be closed"			*/
	case OP_RETURN1: /*	A	return R[A]					*/
	case OP_VARARGPREP: /*  A	(adjust vararg parameters)			*/
		asm_string = luaop_new_str_1arg(opnames[opcode], a);
		break;

		/* iABC - special instructions */
	case OP_TEST: /*	A k	if (not R[A] == k) then pc++			*/
		asm_string = luaop_new_str_1arg_ex(opnames[opcode], a, isk);
		break;

	case OP_RETURN0: /*		return						*/
		asm_string = rz_str_newf("RETURN0");
		break;

		/* iABx instructions */
	case OP_LOADK: /*	A Bx	R[A] := K[Bx]					*/
	case OP_FORLOOP: /*	A Bx	update counters; if loop continues then pc-=Bx; */
	case OP_FORPREP: /*	A Bx	<check values and prepare counters>;
		     if not to run then pc+=Bx+1;			*/
	case OP_TFORPREP: /*	A Bx	create upvalue for R[A + 3]; pc+=Bx		*/
	case OP_TFORLOOP: /*	A Bx	if R[A+2] ~= nil then { R[A]=R[A+2]; pc -= Bx }	*/
	case OP_CLOSURE: /*	A Bx	R[A] := closure(KPROTO[Bx])			*/
		asm_string = luaop_new_str_2arg(opnames[opcode], a, bx);
		break;

		/* iAsBx instructions */
	case OP_LOADI: /*	A sBx	R[A] := sBx					*/
	case OP_LOADF: /*	A sBx	R[A] := (lua_Number)sBx				*/
		asm_string = luaop_new_str_2arg(opnames[opcode], a, sbx);
		break;

		/* iAx instructions */
	case OP_EXTRAARG: /*	Ax	extra (larger) argument for previous opcode	*/
		asm_string = luaop_new_str_1arg(opnames[opcode], ax);
		break;

		/* isJ instructions */
	case OP_JMP: /*	        sJ	pc += sJ					*/
		asm_string = luaop_new_str_1arg(opnames[opcode], sj);
		break;

	default:
		asm_string = rz_str_newf("invalid");
	}

	rz_strbuf_append(&op->buf_asm, asm_string);
	op->size = 4;
	RZ_FREE(asm_string);
	return 4;
}
