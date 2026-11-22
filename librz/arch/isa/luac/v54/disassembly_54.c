// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_54.h"
#include "rz_core.h"

bool get_asm_string54(const LuaOpCode54 opcode, const ut32 instruction, RzStrBuf *buf_asm) {
	LuaOpNameList opnames = get_lua54_opnames();
	/* Pre-fetch arguments */
	const int a = GETARG_A4(instruction);
	const int b = GETARG_B4(instruction);
	const int c = GETARG_C4(instruction);
	const int ax = GETARG_Ax4(instruction);
	const int bx = GETARG_Bx4(instruction);
	const int sb = GETARG_sB(instruction);
	const int sc = GETARG_sC(instruction);
	const int sbx = GETARG_sBx4(instruction);
	const int isk = GETARG_k4(instruction);
	const int sj = GETARG_sJ(instruction);

	char tmp_asm_string[DISASM_BUF_SIZE] = { 0 };

	switch (opcode) {
		/* iABC Instruction */
	case OP_MMBIN: /*	A B C	call C metamethod over R[A] and R[B]		*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %" PFMT32d, opnames[opcode], a, b, c);
		break;
	case OP_GETI: /*	A B C	R[A] := R[B][C]					*/
	case OP_GETTABUP: /*	A B C	R[A] := UpValue[B][K[C]:string]			*/
	case OP_CALL: /*	A B C	R[A], ... ,R[A+C-2] := R[A](R[A+1], ... ,R[A+B-1]) */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %" PFMT32d, opnames[opcode], a, b, c);
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
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " r%" PFMT32d, opnames[opcode], a, b, c);
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
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %" PFMT32d, opnames[opcode], a, b, c);
		break;
		/* iABC - k instructions */
	case OP_TAILCALL: /*	A B C k	return R[A](R[A+1], ... ,R[A+B-1])		*/
		rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d " %" PFMT32d "%s", opnames[opcode], a, b, c, print_isk);
		break;
	case OP_RETURN: /*	A B C k	return R[A], ... ,R[A+B-2]	(see note)	*/
	case OP_NEWTABLE: /*	A B C k	R[A] := {}					*/
	case OP_SETLIST: /*	A B C k	R[A][C+i] := R[A+i], 1 <= i <= B		*/
	case OP_MMBINK: /*	A B C k		call C metamethod over R[A] and K[B]	*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %" PFMT32d "%s", opnames[opcode], a, b, c, print_isk);
		break;
	case OP_SETTABUP: /*	A B C	UpValue[A][K[B]:string] := RK(C)		*/
		rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d " %s", opnames[opcode], a, b, RKC4);
		break;
	case OP_SETTABLE: /*	A B C	R[A][R[B]] := RK(C)				*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %s", opnames[opcode], a, b, RKC4);
		break;
	case OP_SETI: /*	A B C	R[A][B] := RK(C)				*/
	case OP_SETFIELD: /*	A B C	R[A][K[B]:string] := RK(C)			*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %s", opnames[opcode], a, b, RKC4);
		break;
	case OP_SELF: /*	A B C	R[A+1] := R[B]; R[A] := R[B][RK(C):string]	*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %s", opnames[opcode], a, b, RKC4);
		break;
		/* iABC - signed B with k instruction */
	case OP_MMBINI: /*	A sB C k	call C metamethod over R[A] and sB	*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %" PFMT32d "%s", opnames[opcode], a, sb, c, print_isk);
		break;
		/* iABC - c signed instructions */
	case OP_ADDI: /*	A B sC	R[A] := R[B] + sC				*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %" PFMT64d, opnames[opcode], a, b, (st64)sc);
		break;
	case OP_SHRI: /*	A B sC	R[A] := R[B] >> sC				*/
	case OP_SHLI: /*	A B sC	R[A] := sC << R[B]				*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %" PFMT32d, opnames[opcode], a, b, sc);
		break;
		/* iABC - A & B instructions */
	case OP_MOVE: /*	A B	R[A] := R[B]					*/
	case OP_UNM: /*	        A B	R[A] := -R[B]					*/
	case OP_BNOT: /*	A B	R[A] := ~R[B]					*/
	case OP_NOT: /* 	A B	R[A] := not R[B]				*/
	case OP_LEN: /*	        A B	R[A] := #R[B] (length operator)			*/
	case OP_CONCAT: /*	A B	R[A] := R[A].. ... ..R[A + B - 1]		*/
	case OP_LOADNIL: /*	A B	R[A], R[A+1], ..., R[A+B] := nil		*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d, opnames[opcode], a, b);
		break;
	case OP_GETUPVAL: /*	A B	R[A] := UpValue[B]				*/
	case OP_SETUPVAL: /*	A B	UpValue[B] := R[A]				*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, b);
		break;
		/* iABC - A & B with k instructions */
	case OP_EQ: /*	        A B k	if ((R[A] == R[B]) ~= k) then pc++		*/
	case OP_LT: /*	        A B k	if ((R[A] <  R[B]) ~= k) then pc++		*/
	case OP_LE: /*	        A B k	if ((R[A] <= R[B]) ~= k) then pc++		*/
	case OP_TESTSET: /*	A B k	if (not R[B] == k) then pc++ else R[A] := R[B]	*/
	case OP_EQK: /*	        A B k	if ((R[A] == K[B]) ~= k) then pc++		*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d "%s", opnames[opcode], a, b, print_isk);
		break;
		/* iABC - A & sB with k instructions */
	case OP_EQI: /*	        A sB k	if ((R[A] == sB) ~= k) then pc++		*/
	case OP_LTI: /*	        A sB k	if ((R[A] < sB) ~= k) then pc++			*/
	case OP_LEI: /*	        A sB k	if ((R[A] <= sB) ~= k) then pc++		*/
	case OP_GTI: /*	        A sB k	if ((R[A] > sB) ~= k) then pc++			*/
	case OP_GEI: /*	        A sB k	if ((R[A] >= sB) ~= k) then pc++		*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %" PFMT32d, opnames[opcode], a, sb, isk);
		break;
		/* iABC - A & C instructions */
	case OP_TFORCALL: /*	A C	R[A+4], ... ,R[A+3+C] := R[A](R[A+1], R[A+2]);	*/
	case OP_VARARG: /*	A C	R[A], R[A+1], ..., R[A+C-2] = vararg		*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, c);
		break;
		/* iABC - single A instructions */
	case OP_LOADKX: /*	A	R[A] := K[extra arg] */
	case OP_LOADFALSE: /*	A	R[A] := false					*/
	case OP_LFALSESKIP: /*  A	R[A] := false; pc++				*/
	case OP_LOADTRUE: /*	A	R[A] := true					*/
	case OP_CLOSE: /*	A	close all upvalues >= R[A]			*/
	case OP_RETURN1: /*	A	return R[A]					*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d, opnames[opcode], a);
		break;
	case OP_TBC: /*	        A	mark variable A "to be closed"			*/
	case OP_VARARGPREP: /*  A	(adjust vararg parameters)			*/
		rz_strf(tmp_asm_string, "%s %" PFMT32d, opnames[opcode], a);
		break;
		/* iABC - special instructions */
	case OP_TEST: /*	A k	if (not R[A] == k) then pc++			*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d "%s", opnames[opcode], a, print_isk);
		break;
	case OP_RETURN0: /*		return						*/
		rz_strf(tmp_asm_string, "%s", opnames[opcode]);
		break;
		/* iABx instructions */
	case OP_LOADK: /*	A Bx	R[A] := K[Bx]					*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, bx);
		break;
	case OP_FORLOOP: /*	A Bx	update counters; if loop continues then pc-=Bx; */
	case OP_FORPREP: /*	A Bx	<check values and prepare counters>;
		     if not to run then pc+=Bx+1;			*/
	case OP_TFORPREP: /*	A Bx	create upvalue for R[A + 3]; pc+=Bx		*/
	case OP_TFORLOOP: /*	A Bx	if R[A+2] ~= nil then { R[A]=R[A+2]; pc -= Bx }	*/
		rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d, opnames[opcode], a, bx);
		break;
	case OP_CLOSURE: /*	A Bx	R[A] := closure(KPROTO[Bx])			*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, bx); // or (bx + 1)
		break;
		/* iAsBx instructions */
	case OP_LOADI: /*	A sBx	R[A] := sBx					*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, sbx);
		break;
	case OP_LOADF: /*	A sBx	R[A] := (lua_Number)sBx				*/
		rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d, opnames[opcode], a, sbx);
		break;
		/* iAx instructions */
	case OP_EXTRAARG: /*	Ax	extra (larger) argument for previous opcode	*/
		rz_strf(tmp_asm_string, "%s %" PFMT32d, opnames[opcode], ax);
		break;
		/* isJ instructions */
	case OP_JMP: /*	        sJ	pc += sJ					*/
		rz_strf(tmp_asm_string, "%s %" PFMT32d, opnames[opcode], sj);
		break;
	default:
		free_lua_opnames(opnames);
		rz_strbuf_append(buf_asm, "invalid");
		return false;
	}
	free_lua_opnames(opnames);
	rz_strbuf_append(buf_asm, tmp_asm_string);
	return true;
}

DISASM(54)