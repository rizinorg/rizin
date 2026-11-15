// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#ifndef BUILD_ARCH_53_H
#define BUILD_ARCH_53_H

#include <rz_types.h>
#include <rz_asm.h>
#include <stddef.h>
#include "../lua_arch.h"

/**
 * \file
 * \brief Provides information for lua instructions.
 *
 * We assume that instructions are unsigned numbers.
 * All instructions have an opcode in the first 6 bits.
 * Instructions can have the following fields:
 *	'A' : 8 bits
 *	'B' : 9 bits
 *	'C' : 9 bits
 *	'Bx' : 18 bits ('B' and 'C' together)
 *	'sBx' : signed Bx
 * A signed argument is represented in excess K; that is, the number
 * value is the unsigned value minus K. K is exactly the maximum value
 * for that argument (so that -max is represented by 0, and +max is
 * represented by 2*max), which is half the maximum for the corresponding
 * unsigned argument.
 *
 * Notes:
  (*) In OP_CALL, if (B == 0) then B = top. If (C == 0), then 'top' is
  set to last_result+1, so next open instruction (OP_CALL, OP_RETURN,
  OP_SETLIST) may use 'top'.

  (*) In OP_VARARG, if (B == 0) then use actual number of varargs and
  set top (like in OP_CALL with C == 0).

  (*) In OP_RETURN, if (B == 0) then return up to 'top'.

  (*) In OP_SETLIST, if (B == 0) then B = 'top'; if (C == 0) then next
  'instruction' is EXTRAARG(real C).

  (*) In OP_LOADKX, the next 'instruction' is always EXTRAARG.

  (*) For comparisons, A specifies what condition the test should accept
  (true or false).

  (*) All 'skips' (pc++) assume that next instruction is a jump.
 */

typedef enum {
	// name            args    description
	OP_MOVE, ///<      A B     R(A) := R(B)
	OP_LOADK, ///<     A Bx    R(A) := Kst(Bx)
	OP_LOADKX, ///<    A       R(A) := Kst(extra arg)
	OP_LOADBOOL, ///<  A B C   R(A) := (Bool)B; if (C) pc++
	OP_LOADNIL, ///<   A B     R(A), R(A+1), ..., R(A+B) := nil
	OP_GETUPVAL, ///<  A B     R(A) := UpValue[B]

	OP_GETTABUP, ///<  A B C   R(A) := UpValue[B][RK(C)]
	OP_GETTABLE, ///<  A B C   R(A) := R(B)[RK(C)]

	OP_SETTABUP, ///<  A B C   UpValue[A][RK(B)] := RK(C)
	OP_SETUPVAL, ///<  A B     UpValue[B] := R(A)
	OP_SETTABLE, ///<  A B C   R(A)[RK(B)] := RK(C)

	OP_NEWTABLE, ///<  A B C   R(A) := {} (size = B,C)

	OP_SELF, ///<      A B C   R(A+1) := R(B); R(A) := R(B)[RK(C)]

	OP_ADD, ///<       A B C   R(A) := RK(B) + RK(C)
	OP_SUB, ///<       A B C   R(A) := RK(B) - RK(C)
	OP_MUL, ///<       A B C   R(A) := RK(B) * RK(C)
	OP_MOD, ///<       A B C   R(A) := RK(B) % RK(C)
	OP_POW, ///<       A B C   R(A) := RK(B) ^ RK(C)
	OP_DIV, ///<       A B C   R(A) := RK(B) / RK(C)
	OP_IDIV, ///<      A B C   R(A) := RK(B) // RK(C)
	OP_BAND, ///<      A B C   R(A) := RK(B) & RK(C)
	OP_BOR, ///<       A B C   R(A) := RK(B) | RK(C)
	OP_BXOR, ///<      A B C   R(A) := RK(B) ~ RK(C)
	OP_SHL, ///<       A B C   R(A) := RK(B) << RK(C)
	OP_SHR, ///<       A B C   R(A) := RK(B) >> RK(C)
	OP_UNM, ///<       A B     R(A) := -R(B)
	OP_BNOT, ///<      A B     R(A) := ~R(B)
	OP_NOT, ///<       A B     R(A) := not R(B)
	OP_LEN, ///<       A B     R(A) := length of R(B)

	OP_CONCAT, ///<    A B C   R(A) := R(B).. ... ..R(C)

	OP_JMP, ///<       A sBx   pc+=sBx; if (A) close all upvalues >= R(A - 1)
	OP_EQ, ///<        A B C   if ((RK(B) == RK(C)) ~= A) then pc++
	OP_LT, ///<        A B C   if ((RK(B) <  RK(C)) ~= A) then pc++
	OP_LE, ///<        A B C   if ((RK(B) <= RK(C)) ~= A) then pc++

	OP_TEST, ///<      A C     if not (R(A) <=> C) then pc++
	OP_TESTSET, ///<   A B C   if (R(B) <=> C) then R(A) := R(B) else pc++

	OP_CALL, ///<      A B C   R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1))
	OP_TAILCALL, ///<  A B C   return R(A)(R(A+1), ... ,R(A+B-1))
	OP_RETURN, ///<    A B     return R(A), ... ,R(A+B-2)      (see note)

	OP_FORLOOP, ///<   A sBx   R(A)+=R(A+2); if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }
	OP_FORPREP, ///<   A sBx   R(A)-=R(A+2); pc+=sBx

	OP_TFORCALL, ///<  A C     R(A+3), ... ,R(A+2+C) := R(A)(R(A+1), R(A+2));
	OP_TFORLOOP, ///<  A sBx   if R(A+1) ~= nil then { R(A)=R(A+1); pc += sBx }

	OP_SETLIST, ///<   A B C   R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B

	OP_CLOSURE, ///<   A Bx    R(A) := closure(KPROTO[Bx])

	OP_VARARG, ///<    A B     R(A), R(A+1), ..., R(A+B-2) = vararg

	OP_EXTRAARG ///<   Ax      extra (larger) argument for previous opcode
} LuaOpCode53;

#define LUA_NUM_OPCODES53 ((int)(OP_EXTRAARG) + 1)

#endif // BUILD_ARCH_53_H
