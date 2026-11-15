// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_51.h"

bool get_asm_string51(LuaOpCode51 opcode1, const ut32 instruction, RzStrBuf *buf_asm, const Lua51Versions version) {
	LuaOpNameList opnames = get_lua51_opnames(version);
	/* Pre fetch some args */
	const int a = GETARG_A1(instruction);
	const int b = GETARG_B1(instruction);
	const int c = GETARG_C1(instruction);
	const int bx = GETARG_Bx1(instruction);
	const int sbx = GETARG_sBx1(instruction);

	char tmp_asm_string[DISASM_BUF_SIZE] = { 0 };

	const LuaOpCode51 opcode = get_lua51_shuffled_opcode_by_index(opcode1, version);

	switch (opcode) {
	case OP_UNM: /*       A B     R(A) := -R(B)                                   */
	case OP_NOT: /*       A B     R(A) := not R(B)                                */
	case OP_MOVE: /*      A B     R(A) := R(B)                                    */
	case OP_LEN: /*       A B     R(A) := length of R(B)                          */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d, opnames[opcode], a, b);
		break;
	case OP_LOADNIL: /*   A B     R(A), R(A+1), ..., R(A+B) := nil                */
	case OP_RETURN: /*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
	case OP_VARARG: /*    A B     R(A), R(A+1), ..., R(A+B-2) = vararg            */
	case OP_GETUPVAL: /*  A B     R(A) := UpValue[B]                              */
	case OP_SETUPVAL: /*  A B     UpValue[B] := R(A)                              */
	case OP_TEST: /*      A C     if not (R(A) <=> C) then pc++                   */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, b);
		break;
	case OP_SETGLOBAL: /*    A Bx      Gbl[Kst(Bx)] := R(A)                          */
	case OP_GETGLOBAL: /*    A Bx    R(A) := Gbl[Kst(Bx)]                          */
	case OP_LOADK: /*     A Bx    R(A) := Kst(Bx)                                 */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, MYK(bx));
		break;
	case OP_CLOSURE: /*   A Bx    R(A) := closure(KPROTO[Bx])                     */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, bx);
		break;
	case OP_TESTSET: /*   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %s", opnames[opcode], a, b, ISRKCi);
		break;
	case OP_CONCAT: /*    A B C   R(A) := R(B).. ... ..R(C)                       */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " r%" PFMT32d, opnames[opcode], a, b, c);
		break;
	case OP_CALL: /*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
	case OP_NEWTABLE: /*  A B C   R(A) := {} (size = B,C)                         */
	case OP_SETLIST: /*   A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B        */
	case OP_LOADBOOL: /*  A B C   R(A) := (Bool)B; if (C) pc++                    */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %" PFMT32d, opnames[opcode], a, b, c);
		break;
	case OP_GETTABLE: /*  A B C   R(A) := R(B)[RK(C)]                             */
	case OP_SELF: /*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %s", opnames[opcode], a, b, ISRKCi);
		break;
	case OP_SUB: /*       A B C   R(A) := RK(B) - RK(C)                           */
	case OP_SETTABLE: /*  A B C   R(A)[RK(B)] := RK(C)                            */
	case OP_ADD: /*       A B C   R(A) := RK(B) + RK(C)                           */
	case OP_MUL: /*       A B C   R(A) := RK(B) * RK(C)                           */
	case OP_MOD: /*       A B C   R(A) := RK(B) % RK(C)                           */
	case OP_POW: /*       A B C   R(A) := RK(B) ^ RK(C)                           */
	case OP_DIV: /*       A B C   R(A) := RK(B) / RK(C)                           */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %s %s", opnames[opcode], a, ISRKBi, ISRKCi);
		break;
	case OP_EQ: /*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	case OP_LT: /*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	case OP_LE: /*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
		rz_strf(tmp_asm_string, "%s %" PFMT32d " %s %s", opnames[opcode], a, ISRKBi, ISRKCi);
		break;
	case OP_TAILCALL: /*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %" PFMT32d,
			opnames[opcode], a, b, c);
		break;
	case OP_JMP: /*       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)  */
		rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d, opnames[opcode], a, sbx);
		break;
	case OP_FORLOOP: /*   A sBx   R(A)+=R(A+2);if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }*/
	case OP_FORPREP: /*   A sBx   R(A)-=R(A+2); pc+=sBx                           */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, sbx);
		break;
	case OP_TFORLOOP: /*  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }*/
		rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d, opnames[opcode], a, sbx);
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

int lua51_disasm(RzAsmOp *op, ut32 instruction, const int version) {
	const LuaOpCode51 opcode = GET_OPCODE51(instruction);
	get_asm_string51(opcode, instruction, &op->buf_asm, version);
	return op->size;
}