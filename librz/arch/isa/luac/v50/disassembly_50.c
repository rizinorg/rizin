// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "arch_50.h"

bool get_asm_string50(const LuaOpCode50 opcode, const ut32 instruction, RzStrBuf *buf_asm) {
	LuaOpNameList opnames = get_lua50_opnames();
	/* Pre fetch some args */
	const int a = GETARG_A0(instruction);
	const int b = GETARG_B0(instruction);
	const int c = GETARG_C0(instruction);
	const int bx = GETARG_Bx0(instruction);
	const int sbx = GETARG_sBx0(instruction);

	char tmp_asm_string[DISASM_BUF_SIZE] = { 0 };

	// simplify test flag
	const int is_special_B = b & 0x100;
	const int is_special_C = c & 0x100;

	const int special_c = 0xFF - c;
	const int special_b = 0xFF - b;

	switch (opcode) {
	case OP_CLOSE: /*     A       close all variables in the stack up to (>=) R(A)*/
		rz_strf(tmp_asm_string, "%s r%" PFMT32d, opnames[opcode], a);
		break;
	case OP_JMP: /*       sBx     PC += sBx                                       */
		rz_strf(tmp_asm_string, "%s %" PFMT32d, opnames[opcode], sbx);
		break;
	case OP_SETUPVAL: /*  A B     UpValue[B] := R(A)                              */
	case OP_GETUPVAL: /*  A B     R(A) := UpValue[B]                              */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, b);
		break;
	case OP_UNM: /*       A B     R(A) := -R(B)                                   */
	case OP_NOT: /*       A B     R(A) := not R(B)                                */
	case OP_LOADNIL: /*   A B     R(A) := ... := R(B) := nil                      */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d, opnames[opcode], a, b);
		break;
	case OP_TFORLOOP: /*  A C     R(A+2), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));
			if R(A+2) ~= nil then pc++                      */
		rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d, opnames[opcode], a, c);
		break;
	case OP_SETGLOBAL: /* A Bx    Gbl[Kst(Bx)] := R(A)                            */
	case OP_GETGLOBAL: /* A Bx    R(A) := Gbl[Kst(Bx)]                            */
	case OP_LOADK: /*     A Bx    R(A) := Kst(Bx)                                 */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d,
			opnames[opcode], a, ISK(b) ? (MYK(INDEXK(bx))) : bx);
		break;
	case OP_SETLIST: /*   A Bx    R(A)[Bx-Bx%FPF+i] := R(A+i), 1 <= i <= Bx%FPF+1 */
	case OP_SETLISTO: /*  A Bx                                                    */
	case OP_CLOSURE: /*   A Bx    R(A) := closure(KPROTO[Bx], R(A), ... ,R(A+n))  */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, bx);
		break;
	case OP_RETURN: /*    A B     return R(A), ... ,R(A+B-2)      (see note)      */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d, opnames[opcode], a, b);
		break;
	case OP_MOVE: /*      A B     R(A) := R(B)                                    */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d, opnames[opcode], a, b);
		break;
	case OP_TEST: /*      A B C   if (R(B) <=> C) then R(A) := R(B) else pc++     */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %" PFMT32d, opnames[opcode], a, b, c);
		break;
	case OP_CONCAT: /*    A B C   R(A) := R(B).. ... ..R(C)                       */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " r%" PFMT32d, opnames[opcode], a, b, c);
		break;
	case OP_CALL: /*      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1)) */
	case OP_NEWTABLE: /*  A B C   R(A) := {} (size = B,C)                         */
	case OP_LOADBOOL: /*  A B C   R(A) := (Bool)B; if (C) pc++                    */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %" PFMT32d, opnames[opcode], a, b, c);
		break;
	case OP_SELF: /*      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]             */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %d", opnames[opcode], a, b, c);
		break;
	case OP_GETTABLE: /*  A B C   R(A) := R(B)[RK(C)]                             */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " r%" PFMT32d " %s", opnames[opcode], a, b, ISRKCi);
		break;
	case OP_TAILCALL: /*  A B C   return R(A)(R(A+1), ... ,R(A+B-1))              */
		rz_strf(tmp_asm_string, "%s r%" PFMT32d " %" PFMT32d " %" PFMT32d, opnames[opcode], a, b, c);
		break;
	case OP_SETTABLE: /*  A B C   R(A)[RK(B)] := RK(C)                            */
	case OP_ADD: /*       A B C   R(A) := RK(B) + RK(C)                           */
	case OP_SUB: /*       A B C   R(A) := RK(B) - RK(C)                           */
	case OP_MUL: /*       A B C   R(A) := RK(B) * RK(C)                           */
	case OP_POW: /*       A B C   R(A) := RK(B) ^ RK(C)                           */
	case OP_DIV: /*       A B C   R(A) := RK(B) / RK(C)                           */
	case OP_EQ: /*        A B C   if ((RK(B) == RK(C)) ~= A) then pc++            */
	case OP_LT: /*        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++            */
	case OP_LE: /*        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++            */
		if (is_special_B) {
			if (is_special_C) {
				rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d " %" PFMT32d,
					opnames[opcode], a, special_b, special_c);
			} else {
				rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d " %" PFMT32d,
					opnames[opcode], a, special_b, c);
			}
		} else {
			if (is_special_C) {
				rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d " %" PFMT32d,
					opnames[opcode], a, b, special_c);
			} else {
				rz_strf(tmp_asm_string, "%s %" PFMT32d " %" PFMT32d " %" PFMT32d,
					opnames[opcode], a, b, c);
			}
		}
		break;
	case OP_FORLOOP: /*   A sBx   R(A)+=R(A+2); if R(A) <?= R(A+1) then PC+= sBx  */
	case OP_TFORPREP: /*  A sBx   if type(R(A)) == table then R(A+1):=R(A), R(A):=next;
			PC += sBx                                       */
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

DISASM(50)