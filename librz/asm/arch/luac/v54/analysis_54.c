// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "arch_54.h"

int lua54_anal_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len) {
	if (!op || len < 4) {
		return 0;
	}

	memset(op, 0, sizeof(RzAnalysisOp));
	LuaInstruction instruction = lua_build_instruction(data);

	op->size = 4;
	op->addr = addr;

	if (LUA_GET_OPCODE(instruction) > OP_EXTRAARG) {
		return op->size;
	}

	switch (LUA_GET_OPCODE(instruction)) {
	case OP_MOVE: /*	A B	R[A] := R[B]					*/
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case OP_LOADI: /*	A sBx	R[A] := sBx					*/
	case OP_LOADF: /*	A sBx	R[A] := (lua_Number)sBx				*/
	case OP_LOADK: /*	A Bx	R[A] := K[Bx]					*/
	case OP_LOADTRUE: /*	A	R[A] := true					*/
	case OP_LOADNIL: /*	A B	R[A], R[A+1], ..., R[A+B] := nil		*/
	case OP_LOADFALSE: /*	A	R[A] := false					*/
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case OP_LOADKX: /*	A	R[A] := K[extra arg]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->size = 4;
		break;
	case OP_LFALSESKIP: /*A	R[A] := false; pc++				*/
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->size = 8;
		break;
	case OP_GETTABUP: /*	A B C	R[A] := UpValue[B][K[C]:string]			*/
	case OP_GETUPVAL: /*	A B	R[A] := UpValue[B]				*/
	case OP_GETI: /*	A B C	R[A] := R[B][C]					*/
	case OP_GETFIELD: /*	A B C	R[A] := R[B][K[C]:string]			*/
	case OP_GETTABLE: /*	A B C	R[A] := R[B][R[C]]				*/
	case OP_SETTABLE: /*	A B C	R[A][R[B]] := RK(C)				*/
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case OP_SETTABUP: /*	A B C	UpValue[A][K[B]:string] := RK(C)		*/
	case OP_SETUPVAL: /*	A B	UpValue[B] := R[A]				*/
	case OP_SETI: /*	A B C	R[A][B] := RK(C)				*/
	case OP_SETFIELD: /*	A B C	R[A][K[B]:string] := RK(C)			*/
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case OP_NEWTABLE: /*	A B C k	R[A] := {}					*/
		op->type = RZ_ANALYSIS_OP_TYPE_NEW;
		op->size = 4;
		break;
	case OP_SELF: /*	A B C	R[A+1] := R[B]; R[A] := R[B][RK(C):string]	*/
		break;
	case OP_ADDI: /*	A B sC	R[A] := R[B] + sC				*/
	case OP_ADDK: /*	A B C	R[A] := R[B] + K[C]				*/
	case OP_ADD: /*	A B C	R[A] := R[B] + R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case OP_SUBK: /*	A B C	R[A] := R[B] - K[C]				*/
	case OP_SUB: /*	A B C	R[A] := R[B] - R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case OP_MULK: /*	A B C	R[A] := R[B] * K[C]				*/
	case OP_MUL: /*	A B C	R[A] := R[B] * R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case OP_MOD: /*	A B C	R[A] := R[B] % R[C]				*/
	case OP_MODK: /*	A B C	R[A] := R[B] % K[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case OP_POW: /*	A B C	R[A] := R[B] ^ R[C]				*/
	case OP_POWK: /*	A B C	R[A] := R[B] ^ K[C]				*/
		break;
	case OP_DIVK: /*	A B C	R[A] := R[B] / K[C]				*/
	case OP_IDIVK: /*	A B C	R[A] := R[B] // K[C]				*/
	case OP_DIV: /*	A B C	R[A] := R[B] / R[C]				*/
	case OP_IDIV: /*	A B C	R[A] := R[B] // R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case OP_BANDK: /*	A B C	R[A] := R[B] & K[C]:integer			*/
	case OP_BAND: /*	A B C	R[A] := R[B] & R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case OP_BOR: /*	A B C	R[A] := R[B] | R[C]				*/
	case OP_BORK: /*	A B C	R[A] := R[B] | K[C]:integer			*/
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case OP_BXOR: /*	A B C	R[A] := R[B] ~ R[C]				*/
	case OP_BXORK: /*	A B C	R[A] := R[B] ~ K[C]:integer			*/
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case OP_NOT: /*	A B	R[A] := not R[B]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case OP_BNOT: /*	A B	R[A] := ~R[B]					*/
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		break;
	case OP_SHRI: /*	A B sC	R[A] := R[B] >> sC				*/
	case OP_SHR: /*	A B C	R[A] := R[B] >> R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case OP_SHLI: /*	A B sC	R[A] := sC << R[B]				*/
	case OP_SHL: /*	A B C	R[A] := R[B] << R[C]				*/
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case OP_MMBIN: /*	A B C	call C metamethod over R[A] and R[B]		*/
	case OP_MMBINI: /*	A sB C k	call C metamethod over R[A] and sB	*/
	case OP_MMBINK: /*	A B C k		call C metamethod over R[A] and K[B]	*/
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case OP_UNM: /*	A B	R[A] := -R[B]					*/
	case OP_LEN: /*	A B	R[A] := #R[B] (length operator)			*/
	case OP_CONCAT: /*	A B	R[A] := R[A].. ... ..R[A + B - 1]		*/
	case OP_CLOSE: /*	A	close all upvalues >= R[A]			*/
	case OP_TBC: /*	A	mark variable A "to be closed"			*/
		break;
	case OP_JMP: /*	sJ	pc += sJ					*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)(4 * (LUA_GETARG_sJ(instruction)));
		op->fail = op->addr + 4;
		break;
	case OP_EQ: /*	A B k	if ((R[A] == R[B]) ~= k) then pc++		*/
	case OP_LT: /*	A B k	if ((R[A] <  R[B]) ~= k) then pc++		*/
	case OP_LE: /*	A B k	if ((R[A] <= R[B]) ~= k) then pc++		*/
	case OP_EQK: /*	A B k	if ((R[A] == K[B]) ~= k) then pc++		*/
	case OP_EQI: /*	A sB k	if ((R[A] == sB) ~= k) then pc++		*/
	case OP_LTI: /*	A sB k	if ((R[A] < sB) ~= k) then pc++			*/
	case OP_LEI: /*	A sB k	if ((R[A] <= sB) ~= k) then pc++		*/
	case OP_GTI: /*	A sB k	if ((R[A] > sB) ~= k) then pc++			*/
	case OP_GEI: /*	A sB k	if ((R[A] >= sB) ~= k) then pc++		*/
	case OP_TEST: /*	A k	if (not R[A] == k) then pc++			*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_TESTSET: /*	A B k	if (not R[B] == k) then pc++ else R[A] := R[B]	*/
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_CALL: /*	A B C	R[A], ... ,R[A+C-2] := R[A](R[A+1], ... ,R[A+B-1]) */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;
	case OP_TAILCALL: /*	A B C k	return R[A](R[A+1], ... ,R[A+B-1])		*/
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->type2 = RZ_ANALYSIS_ADDR_HINT_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_RETURN: /*	A B C k	return R[A], ... ,R[A+B-2]	(see note)	*/
	case OP_RETURN1: /*	A	return R[A]					*/
	case OP_RETURN0: /*		return						*/
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_FORLOOP: /*	A Bx	update counters; if loop continues then pc-=Bx; */
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4 - 4 * (LUA_GETARG_Bx(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_FORPREP: /*	A Bx	<check values and prepare counters>;
	      if not to run then pc+=Bx+1;			*/
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4 + 4 * (LUA_GETARG_Bx(instruction) + 1);
		op->fail = op->addr + 4;
		break;
	case OP_TFORPREP: /*	A Bx	create upvalue for R[A + 3]; pc+=Bx		*/
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4 + 4 * (LUA_GETARG_Bx(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_TFORCALL: /*	A C	R[A+4], ... ,R[A+3+C] := R[A](R[A+1], R[A+2]);	*/
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;
	case OP_TFORLOOP: /*	A Bx	if R[A+2] ~= nil then { R[A]=R[A+2]; pc -= Bx }	*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 4 - 4 * (LUA_GETARG_Bx(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_SETLIST: /*	A B C k	R[A][C+i] := R[A+i], 1 <= i <= B		*/
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case OP_CLOSURE: /*	A Bx	R[A] := closure(KPROTO[Bx])			*/
	case OP_VARARG: /*	A C	R[A], R[A+1], ..., R[A+C-2] = vararg		*/
	case OP_VARARGPREP: /*A	(adjust vararg parameters)			*/
	case OP_EXTRAARG: /*	Ax	extra (larger) argument for previous opcode	*/
		op->size = 4;
		break;
	}
	return op->size;
}