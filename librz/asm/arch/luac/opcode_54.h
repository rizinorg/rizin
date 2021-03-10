// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#ifndef BUILD_OPCODE_54_H
#define BUILD_OPCODE_54_H

#include <rz_types.h>
#include <rz_asm.h>
#include "opcode.h"

/*===========================================================================
  We assume that instructions are unsigned 32-bit integers.
  All instructions have an opcode in the first 7 bits.
  Instructions can have the following formats:

        3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0
        1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
iABC          C(8)     |      B(8)     |k|     A(8)      |   Op(7)     |
iABx                Bx(17)               |     A(8)      |   Op(7)     |
iAsBx              sBx (signed)(17)      |     A(8)      |   Op(7)     |
iAx                           Ax(25)                     |   Op(7)     |
isJ                           sJ(25)                     |   Op(7)     |

  A signed argument is represented in excess K: the represented value is
  the written unsigned value minus K, where K is half the maximum for the
  corresponding unsigned argument.
===========================================================================*/

typedef enum {
        iABC,
        iABx,
        iAsBx,
        iAx,
        isJ
} LuaOpMode;

/* Offset and size of opcode arguments */
#define LUAOP_A_SIZE  8
#define LUAOP_B_SIZE  8
#define LUAOP_C_SIZE  8
#define LUAOP_Bx_SIZE (LUAOP_C_SIZE + LUAOP_B_SIZE + 1)
#define LUAOP_Ax_SIZE (LUAOP_Bx_SIZE + LUAOP_A_SIZE)
#define LUAOP_sJ_SIZE (LUAOP_Bx_SIZE + LUAOP_A_SIZE)
#define LUAOP_OP_SIZE 7

#define LUAOP_OP_OFFSET 0
#define LUAOP_A_OFFSET  (LUAOP_OP_OFFSET + LUAOP_OP_SIZE)
#define LUAOP_k_OFFSET  (LUAOP_A_OFFSET + LUAOP_A_SIZE)
#define LUAOP_B_OFFSET  (LUAOP_k_OFFSET + 1)
#define LUAOP_C_OFFSET  (LUAOP_B_OFFSET + LUAOP_B_SIZE)
#define LUAOP_Bx_OFFSET LUAOP_k_OFFSET
#define LUAOP_Ax_OFFSET LUAOP_A_OFFSET
#define LUAOP_sJ_OFFSET LUAOP_A_OFFSET

/* max value of these args */
#define LUAOP_MAXARG_Bx ((1 << LUAOP_Bx_SIZE) - 1)
#define LUAOP_MAXARG_Ax ((1 << LUAOP_Ax_SIZE) - 1)
#define LUAOP_MAXARG_sJ ((1 << LUAOP_sJ_SIZE) - 1)
#define LUAOP_MAXARG_A  ((1 << LUAOP_A_SIZE) - 1)
#define LUAOP_MAXARG_B  ((1 << LUAOP_B_SIZE) - 1)
#define LUAOP_MAXARG_C  ((1 << LUAOP_C_SIZE) - 1)

/* fix value of signed args */
#define LUAOP_FIX_sBx (LUAOP_MAXARG_Bx >> 1)
#define LUAOP_FIX_sJ  (LUAOP_MAXARG_sJ >> 1)
#define LUAOP_FIX_sC  (LUAOP_MAXARG_C >> 1)


typedef enum {
        /*----------------------------------------------------------------------
  name		args	description
------------------------------------------------------------------------*/
        OP_MOVE, /*	A B	R[A] := R[B]					*/
        OP_LOADI, /*	A sBx	R[A] := sBx					*/
        OP_LOADF, /*	A sBx	R[A] := (lua_Number)sBx				*/
        OP_LOADK, /*	A Bx	R[A] := K[Bx]					*/
        OP_LOADKX, /*	A	R[A] := K[extra arg]				*/
        OP_LOADFALSE, /*	A	R[A] := false					*/
        OP_LFALSESKIP, /*A	R[A] := false; pc++				*/
        OP_LOADTRUE, /*	A	R[A] := true					*/
        OP_LOADNIL, /*	A B	R[A], R[A+1], ..., R[A+B] := nil		*/
        OP_GETUPVAL, /*	A B	R[A] := UpValue[B]				*/
        OP_SETUPVAL, /*	A B	UpValue[B] := R[A]				*/

        OP_GETTABUP, /*	A B C	R[A] := UpValue[B][K[C]:string]			*/
        OP_GETTABLE, /*	A B C	R[A] := R[B][R[C]]				*/
        OP_GETI, /*	A B C	R[A] := R[B][C]					*/
        OP_GETFIELD, /*	A B C	R[A] := R[B][K[C]:string]			*/

        OP_SETTABUP, /*	A B C	UpValue[A][K[B]:string] := RK(C)		*/
        OP_SETTABLE, /*	A B C	R[A][R[B]] := RK(C)				*/
        OP_SETI, /*	A B C	R[A][B] := RK(C)				*/
        OP_SETFIELD, /*	A B C	R[A][K[B]:string] := RK(C)			*/

        OP_NEWTABLE, /*	A B C k	R[A] := {}					*/

        OP_SELF, /*	A B C	R[A+1] := R[B]; R[A] := R[B][RK(C):string]	*/

        OP_ADDI, /*	A B sC	R[A] := R[B] + sC				*/

        OP_ADDK, /*	A B C	R[A] := R[B] + K[C]				*/
        OP_SUBK, /*	A B C	R[A] := R[B] - K[C]				*/
        OP_MULK, /*	A B C	R[A] := R[B] * K[C]				*/
        OP_MODK, /*	A B C	R[A] := R[B] % K[C]				*/
        OP_POWK, /*	A B C	R[A] := R[B] ^ K[C]				*/
        OP_DIVK, /*	A B C	R[A] := R[B] / K[C]				*/
        OP_IDIVK, /*	A B C	R[A] := R[B] // K[C]				*/

        OP_BANDK, /*	A B C	R[A] := R[B] & K[C]:integer			*/
        OP_BORK, /*	A B C	R[A] := R[B] | K[C]:integer			*/
        OP_BXORK, /*	A B C	R[A] := R[B] ~ K[C]:integer			*/

        OP_SHRI, /*	A B sC	R[A] := R[B] >> sC				*/
        OP_SHLI, /*	A B sC	R[A] := sC << R[B]				*/

        OP_ADD, /*	A B C	R[A] := R[B] + R[C]				*/
        OP_SUB, /*	A B C	R[A] := R[B] - R[C]				*/
        OP_MUL, /*	A B C	R[A] := R[B] * R[C]				*/
        OP_MOD, /*	A B C	R[A] := R[B] % R[C]				*/
        OP_POW, /*	A B C	R[A] := R[B] ^ R[C]				*/
        OP_DIV, /*	A B C	R[A] := R[B] / R[C]				*/
        OP_IDIV, /*	A B C	R[A] := R[B] // R[C]				*/

        OP_BAND, /*	A B C	R[A] := R[B] & R[C]				*/
        OP_BOR, /*	A B C	R[A] := R[B] | R[C]				*/
        OP_BXOR, /*	A B C	R[A] := R[B] ~ R[C]				*/
        OP_SHL, /*	A B C	R[A] := R[B] << R[C]				*/
        OP_SHR, /*	A B C	R[A] := R[B] >> R[C]				*/

        OP_MMBIN, /*	A B C	call C metamethod over R[A] and R[B]		*/
        OP_MMBINI, /*	A sB C k	call C metamethod over R[A] and sB	*/
        OP_MMBINK, /*	A B C k		call C metamethod over R[A] and K[B]	*/

        OP_UNM, /*	A B	R[A] := -R[B]					*/
        OP_BNOT, /*	A B	R[A] := ~R[B]					*/
        OP_NOT, /*	A B	R[A] := not R[B]				*/
        OP_LEN, /*	A B	R[A] := #R[B] (length operator)			*/

        OP_CONCAT, /*	A B	R[A] := R[A].. ... ..R[A + B - 1]		*/

        OP_CLOSE, /*	A	close all upvalues >= R[A]			*/
        OP_TBC, /*	A	mark variable A "to be closed"			*/
        OP_JMP, /*	sJ	pc += sJ					*/
        OP_EQ, /*	A B k	if ((R[A] == R[B]) ~= k) then pc++		*/
        OP_LT, /*	A B k	if ((R[A] <  R[B]) ~= k) then pc++		*/
        OP_LE, /*	A B k	if ((R[A] <= R[B]) ~= k) then pc++		*/

        OP_EQK, /*	A B k	if ((R[A] == K[B]) ~= k) then pc++		*/
        OP_EQI, /*	A sB k	if ((R[A] == sB) ~= k) then pc++		*/
        OP_LTI, /*	A sB k	if ((R[A] < sB) ~= k) then pc++			*/
        OP_LEI, /*	A sB k	if ((R[A] <= sB) ~= k) then pc++		*/
        OP_GTI, /*	A sB k	if ((R[A] > sB) ~= k) then pc++			*/
        OP_GEI, /*	A sB k	if ((R[A] >= sB) ~= k) then pc++		*/

        OP_TEST, /*	A k	if (not R[A] == k) then pc++			*/
        OP_TESTSET, /*	A B k	if (not R[B] == k) then pc++ else R[A] := R[B]	*/

        OP_CALL, /*	A B C	R[A], ... ,R[A+C-2] := R[A](R[A+1], ... ,R[A+B-1]) */
        OP_TAILCALL, /*	A B C k	return R[A](R[A+1], ... ,R[A+B-1])		*/

        OP_RETURN, /*	A B C k	return R[A], ... ,R[A+B-2]	(see note)	*/
        OP_RETURN0, /*		return						*/
        OP_RETURN1, /*	A	return R[A]					*/

        OP_FORLOOP, /*	A Bx	update counters; if loop continues then pc-=Bx; */
        OP_FORPREP, /*	A Bx	<check values and prepare counters>;
                        if not to run then pc+=Bx+1;			*/

        OP_TFORPREP, /*	A Bx	create upvalue for R[A + 3]; pc+=Bx		*/
        OP_TFORCALL, /*	A C	R[A+4], ... ,R[A+3+C] := R[A](R[A+1], R[A+2]);	*/
        OP_TFORLOOP, /*	A Bx	if R[A+2] ~= nil then { R[A]=R[A+2]; pc -= Bx }	*/

        OP_SETLIST, /*	A B C k	R[A][C+i] := R[A+i], 1 <= i <= B		*/

        OP_CLOSURE, /*	A Bx	R[A] := closure(KPROTO[Bx])			*/

        OP_VARARG, /*	A C	R[A], R[A+1], ..., R[A+C-2] = vararg		*/

        OP_VARARGPREP, /*A	(adjust vararg parameters)			*/

        OP_EXTRAARG /*	Ax	extra (larger) argument for previous opcode	*/
} LuaOpCode;
#define LUA_NUM_OPCODES ((int)(OP_EXTRAARG) + 1)

/* ===========================================
 * Operation Method Macros
 * =========================================== */

/* Macros Highlight the cast */
#define LUA_CAST(x, y) ((x)y)
#define int2sC(i) ((i) + LUAOP_FIX_sC)
#define sC2int(i) ((i) - LUAOP_FIX_sC)

/* creates a mask with 'n' 1/0 bits at position 'p' */
#define LUA_MASK1(n, p) ((~((~(LuaInstruction)0) << (n))) << (p))
#define LUA_MASK0(n, p) (~LUA_MASK1(n, p))

/* OPCODE getter */
#define LUA_GET_OPCODE(i) (LUA_CAST(LuaOpCode, ((i) >> LUAOP_OP_OFFSET) & LUA_MASK1(LUAOP_OP_SIZE, 0)))

/* Arguments getter */
#define LUA_GETARG(i, offset, size) (LUA_CAST(int, ((i) >> (offset)) & LUA_MASK1(size, 0)))

#define LUA_GETARG_A(i)   LUA_GETARG(i, LUAOP_A_OFFSET, LUAOP_A_SIZE)
#define LUA_GETARG_B(i)   LUA_GETARG(i, LUAOP_B_OFFSET, LUAOP_B_SIZE)
#define LUA_GETARG_C(i)   LUA_GETARG(i, LUAOP_C_OFFSET, LUAOP_C_SIZE)
#define LUA_GETARG_Bx(i)  LUA_GETARG(i, LUAOP_Bx_OFFSET, LUAOP_Bx_SIZE)
#define LUA_GETARG_Ax(i)  LUA_GETARG(i, LUAOP_Ax_OFFSET, LUAOP_Ax_SIZE)
#define LUA_GETARG_sBx(i) (LUA_GETARG_Bx(i) - LUAOP_FIX_sBx)
#define LUA_GETARG_sJ(i)  (LUA_GETARG(i, LUAOP_sJ_OFFSET, LUAOP_sJ_SIZE) - LUAOP_FIX_sJ)
#define LUA_GETARG_sC(i) sC2int(LUA_GETARG_C(i))
#define LUA_GETARG_sB(i) sC2int(LUA_GETARG_B(i))

#define LUA_GETARG_k(i)  LUA_GETARG(i, LUAOP_k_OFFSET, 1)

#define ISK(isk) ((isk) ? "#CONST" : "#R")
#define ISFLIP(isk) ((isk) ? "#FLIP" : "")

/* About OpMode
** masks for instruction properties. The format is:
** bits 0-2: op mode
** bit 3: instruction set register A
** bit 4: operator is a test (next instruction must be a jump)
** bit 5: instruction uses 'L->top' set by previous instruction (when B == 0)
** bit 6: instruction sets 'L->top' for next instruction (when C == 0)
** bit 7: instruction is an MM instruction (call a metamethod)
 *
 * OT - "out top" set top for next instruction
 * IT - "in top" uses top from previous instruction
*/

#define LUA_GET_OPMODE(i) (LUA_CAST(LuaOpMode, (i) & 7))
#define LUA_TEST_AMODE(i)    ((i) & (1 << 3))
#define LUA_TEST_TMODE(i)    ((i) & (1 << 4))
#define LUA_TEST_ITMODE(i)   ((i) & (1 << 5))
#define LUA_TEST_OTMODE(i)   ((i) & (1 << 6))
#define LUA_TEST_MMMODE(i)   ((i) & (1 << 7))

#endif //BUILD_OPCODE_54_H
