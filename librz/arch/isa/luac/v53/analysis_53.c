// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "arch_53.h"

int lua53_anal_op(RzAnalysis *anal, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len) {
	if (!op) {
		return 0;
	}

	memset(op, 0, sizeof(RzAnalysisOp));
	const ut32 instruction = lua_build_instruction(data);

	ut32 extra_arg = 0;
	op->addr = addr;
	op->size = 4;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->eob = false;

	if (GET_OPCODE(instruction) > OP_EXTRAARG) {
		return op->size;
	}
	// op->mnemonic = rz_str_dup ();

	switch (GET_OPCODE(instruction)) {
	case OP_MOVE: /*      A B     R(A) := R(B)                                    */
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case OP_LOADK: /*     A Bx    R(A) := Kst(Bx)                                 */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case OP_LOADKX: /*    A       R(A) := Kst(extra arg)                          */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		extra_arg = lua_build_instruction(data + 4);
		if (GET_OPCODE(extra_arg) == OP_EXTRAARG) {
			op->size = 8;
		}
		break;
	case OP_LOADBOOL: /*  A B C   R(A) := (Bool)B; if (C) pc++                    */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->val = !!GETARG_B(instruction);
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_LOADNIL: /*   A B     R(A), R(A+1), ..., R(A+B) := nil                */
		break;
	case OP_GETUPVAL: /*  A B     R(A) := UpValue[B]                              */
	case OP_GETTABUP: /*  A B C   R(A) := UpValue[B][RK(C)]                       */
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case OP_GETTABLE: /*  A B C   R(A) := R(B)[RK(C)]                             */
		break;

	case OP_SETTABUP: /*  A B C   UpValue[A][RK(B)] := RK(C)                      */
	case OP_SETUPVAL: /*  A B     UpValue[B] := R(A)                              */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case OP_SETTABLE: /*  A B C   R(A)[RK(B)] := RK(C)                            */
		break;
	case OP_NEWTABLE: /*  A B C   R(A) := {} (size = B,C)                         */
		op->type = RZ_ANALYSIS_OP_TYPE_NEW;
		break;
	case OP_SELF: /*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
		break;
	case OP_ADD: /*       A B C   R(A) := RK(B) + RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case OP_SUB: /*       A B C   R(A) := RK(B) - RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case OP_MUL: /*       A B C   R(A) := RK(B) * RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case OP_MOD: /*       A B C   R(A) := RK(B) % RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case OP_POW: /*       A B C   R(A) := RK(B) ^ RK(C)                           */
		break;
	case OP_DIV: /*       A B C   R(A) := RK(B) / RK(C)                           */
	case OP_IDIV: /*      A B C   R(A) := RK(B) // RK(C)                          */
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case OP_BAND: /*      A B C   R(A) := RK(B) & RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case OP_BOR: /*       A B C   R(A) := RK(B) | RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case OP_BXOR: /*      A B C   R(A) := RK(B) ~ RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case OP_SHL: /*       A B C   R(A) := RK(B) << RK(C)                          */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case OP_SHR: /*       A B C   R(A) := RK(B) >> RK(C)                          */
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case OP_UNM: /*       A B     R(A) := -R(B)                                   */
		break;
	case OP_BNOT: /*      A B     R(A) := ~R(B)                                   */
		op->type = RZ_ANALYSIS_OP_TYPE_CPL;
		break;
	case OP_NOT: /*       A B     R(A) := not R(B)                                */
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case OP_LEN: /*       A B     R(A) := length of R(B)                          */
	case OP_CONCAT: /*    A B C   R(A) := R(B).. ... ..R(C)                       */
		break;
	case OP_JMP: /*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + (st32)(4 * GETARG_sBx(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_EQ: /*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	case OP_LT: /*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	case OP_LE: /*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
	case OP_TEST: /*      A C     if not (R(A) <=> C) then pc++                   */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_TESTSET: /*   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		op->jump = op->addr + 8;
		op->fail = op->addr + 4;
		break;
	case OP_CALL: /*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;
	case OP_TAILCALL: /*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->type2 = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_RETURN: /*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	case OP_FORLOOP: /*   A sBx   R(A)+=R(A+2); if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_FORPREP: /*   A sBx   R(A)-=R(A+2); pc+=sBx                           */
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_TFORCALL: /*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;
	case OP_TFORLOOP: /*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = op->addr + 4 + 4 * (GETARG_sBx(instruction));
		op->fail = op->addr + 4;
		break;
	case OP_SETLIST: /*   A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case OP_CLOSURE: /*   A Bx    R(A) := closure(KPROTO[Bx])                     */
	case OP_VARARG: /*    A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */
	case OP_EXTRAARG: /*   Ax      extra (larger) argument for previous opcode     */
		break;
	}
	return op->size;
}