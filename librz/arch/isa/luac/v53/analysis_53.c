// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_53.h"
#include "../lua_arch.h"

int lua53_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, AnalysisLuacContext *ctx, const ut8 *data, int len) {
	const LuaInstruction instruction = ctx->instruction;
	const ut64 addr = ctx->addr;
	const LuaOpCode53 opcode = GET_OPCODE53(instruction);

	char comment[128] = { 0 };

	if (opcode > OP_EXTRAARG) {
		op->family = RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->nopcode = 1;
		op->cycles = 1;
		op->size = 4;
		op->eob = true;
		ctx->prev_inst = instruction;
		return op->size;
	}
	const int a = GETARG_A1(instruction);
	const int b = GETARG_B1(instruction);
	const int c = GETARG_C1(instruction);
	const int bx = GETARG_Bx1(instruction);
	const int sbx = GETARG_sBx1(instruction);

	op->jump = addr + 4;

	switch (opcode) {
	case OP_MOVE: /*	A B	R[A] := R[B]					*/
		TYPE_CFMT_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_MOV, "r%d = r%d", a, b);
	case OP_GETUPVAL: /*	A B	R[A] := UpValue[B]				*/ {
		const st64 target_upv = VADDRESS_PROTO_BASE(addr) + UPVALUE_OFFSET + (b * 2);
		op->ptr = (st64)target_upv;
		TYPE_CFMT_DST_REG_SRC0_IMM(RZ_ANALYSIS_OP_TYPE_LOAD, "r%d = upvalue[%d]", a, b);
	}
	case OP_SETUPVAL: /*	A B	UpValue[B] := R[A]				*/
		TYPE_DST_IMM_SRC0_REG(RZ_ANALYSIS_OP_TYPE_STORE, "upvalue[%d] = r%d", b, a);
	case OP_UNM: /*	A B	R[A] := -R[B]					*/
		TYPE_CFMT_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_UNK, "r%d = -r%d", a, b);
	case OP_NOT: /*		A B	R[A] := not R[B]				*/
		TYPE_CFMT_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_NOT, "r%d = not r%d", a, b);
	case OP_LOADK: /*	A Bx	R[A] := K[Bx]					*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		rz_strf(comment, "r%d = %s", a, Kst(bx));
		break;
	case OP_LOADNIL: /*	A B	R[A], R[A+1], ..., R[A+B] := nil		*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		op->val = (ut64)0;
		break;
	case OP_CLOSURE: /*	A Bx	R[A] := closure(KPROTO[Bx])			*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		const ut64 child_vaddr = CHILD_VADDRESS(ctx->addr, (bx + 1));
		rz_meta_set(analysis, RZ_META_TYPE_DATA, child_vaddr, 0, "fcn_ptr");
		RzAnalysisFunction *fc = rz_analysis_get_function_at(analysis, child_vaddr);
		if (!fc || !fc->name) {
			rz_strf(comment, "instantiate proto%d at 0x%" PFMT64x, bx + 1, child_vaddr);
		} else {
			rz_strf(comment, "instantiate proto %d `%s` at 0x%" PFMT64x, bx + 1, fc->name, child_vaddr);
		}
		break;
	case OP_RETURN: /*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
		OP_RET(RZ_ANALYSIS_OP_TYPE_RET, a, b);
	case OP_TAILCALL: /*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		OP_RET(RZ_ANALYSIS_OP_TYPE_TAIL, a, b);
	case OP_TEST: /*	A k	if (not R[A] == k) then pc++			*/
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		JUMP_FAIL_OFFSET(8, 4);
		break;
	case OP_SETLIST: /*	A B C k	R[A][C+i] := R[A+i], 1 <= i <= B		*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_STORE, a);
		break;
	case OP_CALL: /*	A B C	R[A], ... ,R[A+C-2] := R[A](R[A+1], ... ,R[A+B-1]) */
		OP_CALL();
	case OP_GETTABLE: /*  A B C   R(A) := R(B)[RK(C)]                             */
		RKC_REG_OR_IMM(c, 1);
		rz_strf(comment, "r%d = r%d[%s]", a, b, ISRKCk);
		TYPE_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a, b);
	case OP_SETTABLE: /*  A B C   R(A)[RK(B)] := RK(C)                            */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_STORE, a);
		RKC_REG_OR_IMM(b, 0);
		RKC_REG_OR_IMM(c, 1);
		rz_strf(comment, "r%d[%s] = %s", a, ISRKBk, ISRKCk);
		break;
	case OP_NEWTABLE: /*  A B C   R(A) := {} (size = B,C)                         */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		break;
	case OP_ADD: /*       A B C   R(A) := RK(B) + RK(C)                           */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_ADD, "r%d = %s + %s");
	case OP_SUB: /*       A B C   R(A) := RK(B) - RK(C)                           */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_SUB, "r%d = %s - %s");
	case OP_MUL: /*       A B C   R(A) := RK(B) * RK(C)                           */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_MUL, "r%d = %s * %s");
	case OP_DIV: /*       A B C   R(A) := RK(B) / RK(C)                           */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_DIV, "r%d = %s / %s");
	case OP_POW: /*       A B C   R(A) := RK(B) ^ RK(C)                           */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_MUL, "r%d = %s ^ %s");
	case OP_LT: /*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	case OP_LE: /*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
	case OP_EQ: /*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		JUMP_FAIL_OFFSET(8, 4);
		if (opcode == OP_EQ) {
			op->cond = RZ_TYPE_COND_EQ;
		} else if (opcode == OP_LT) {
			op->cond = RZ_TYPE_COND_LT;
		} else {
			op->cond = RZ_TYPE_COND_LE;
		}
		RKC_REG_OR_IMM(b, 0);
		RKC_REG_OR_IMM(c, 1);
		break;
	case OP_JMP: /*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */ {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		const ut64 offset = (sbx + 1) * 4; /* (st32)(4 * sbx) */
		const ut64 target = addr + offset;
		JUMP_FAIL_ABS(target, addr + 4);
		op->eob = true;
		rz_strf(comment, "jump to 0x%" PFMT64x, target);
		break;
	}
	case OP_CONCAT: /*    A B C   R(A) := R(B).. ... ..R(C)                       */
		TYPE_DST_SRC_ABC_REG(RZ_ANALYSIS_OP_TYPE_NOP, a, b, c);
		break;
	case OP_LOADBOOL: /*  A B C   R(A) := (Bool)B; if (C) pc++                    */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		JUMP_FAIL_OFFSET(8, 4);
		break;
	case OP_FORLOOP: /*   A sBx   R(A)+=R(A+2); if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_CJMP, a);
		JUMP_FAIL_ABS(addr + 4 + (sbx * 4), addr + 4);
		rz_strf(comment, "to 0x%" PFMT64x, op->jump);
		break;
	case OP_MOD: /*       A B C   R(A) := RK(B) % RK(C)                           */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_MOD, "r%d = %s MOD %s");
	case OP_TESTSET: /*   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
		JUMP_FAIL_OFFSET(8, 4);
		TYPE_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_CMOV, a, b);
	case OP_FORPREP: /*   A sBx   R(A)-=R(A+2); pc+=sBx                           */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_CJMP, a);
		JUMP_FAIL_ABS(addr + 4 + (sbx * 4), addr + 4);
		rz_strf(comment, "to 0x%" PFMT64x, op->jump);
		break;
	case OP_LOADKX: /*    A       R(A) := Kst(extra arg)                          */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a);
		///< read EXTRAARG
		const ut32 next_inst = ctx->next_inst;
		const int ax_prev = GETARG_Ax2(next_inst);
		op->size = 8; ///< 2 instructions (4+4 bytes)
		op->ptr = (st64)CONST_VADDRESS(addr, ax_prev);
		rz_strf(comment, "r%d = constants[%d]", a, ax_prev);
		break;
	case OP_GETTABUP: /*  A B C   R(A) := UpValue[B][RK(C)]                       */ {
		op->ptr = (st64)CONST_VADDRESS(addr, c);
		rz_strf(comment, "r%d = %s['%s']", a, SCOPE(b), Kst(INDEXK(c)));
		TYPE_DST_REG_SRC0_IMM(RZ_ANALYSIS_OP_TYPE_LOAD, a, b);
	}
	case OP_SETTABUP: /*	A B C	UpValue[A][K[B]:string] := RK(C)		*/ {
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_STORE, a);
		op->ptr = (st64)CONST_VADDRESS(addr, b);
		RKC_REG_OR_IMM(c, 0);
		rz_strf(comment, "%s['%s'] = %s", SCOPE(a), Kst(b), ISRKCk);
		break;
	}
	case OP_SELF: /*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
		op->val = get_const_address(analysis, addr, c);
		RKC_REG_OR_IMM(c, 1);
		rz_strf(comment, "r%d=r%d (self), r%d=r%d[%s] self.%s()", a + 1, b, a, b, ISRKCk, ISRKCk);
		TYPE_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_LOAD, a, b);
	case OP_IDIV: /*      A B C   R(A) := RK(B) // RK(C)                          */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_DIV, "r%d := %s // %s");
	case OP_BAND: /*      A B C   R(A) := RK(B) & RK(C)                           */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_AND, "r%d := %s & %s");
	case OP_BOR: /*       A B C   R(A) := RK(B) | RK(C)                           */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_OR, "r%d := %s | %s");
	case OP_BXOR: /*      A B C   R(A) := RK(B) ~ RK(C)                           */
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_XOR, "r%d := %s ~ %s");
	case OP_SHL: /*       A B C   R(A) := RK(B) << RK(C)                          */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_SHL, "r%d := %s << %s");
	case OP_SHR: /*       A B C   R(A) := RK(B) >> RK(C)                          */
		ARITHMETIC_OP_0_3(RZ_ANALYSIS_OP_TYPE_SHR, "r%d := %s >> %s");
	case OP_BNOT: /*      A B     R(A) := ~R(B)                                   */
		TYPE_DST_SRC_AB_REG(RZ_ANALYSIS_OP_TYPE_NOT, "r%d = ~r%d", a, b);
	case OP_LEN: /*       A B     R(A) := length of R(B)                          */
		TYPE_DST_SRC0_REG(RZ_ANALYSIS_OP_TYPE_LENGTH, a, b);
	case OP_TFORCALL: /*  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));  */
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_CALL, a);
		op->val = (ut64)c;
		op->fail = addr + 4;
		break;
	case OP_TFORLOOP: /*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		TYPE_DST_REG(RZ_ANALYSIS_OP_TYPE_CJMP, a);
		JUMP_FAIL_ABS(addr + 4 + (sbx * 4), addr + 4);
		rz_strf(comment, "to 0x%" PFMT64x, op->jump);
		break;
	case OP_VARARG: /*    A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */
	case OP_EXTRAARG: /*   Ax      extra (larger) argument for previous opcode     */
		break;
	default:
		RZ_LOG_DEBUG("OPCODE: %d\n", opcode);
		rz_warn_if_reached();
	}
	if (strlen(comment) > 0) {
		rz_meta_set(analysis, RZ_META_TYPE_COMMENT, addr, 4, comment);
	}
	return op->size;
}