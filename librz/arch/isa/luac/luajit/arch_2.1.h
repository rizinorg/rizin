// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef BUILD_LUAJIT_ARCH_H
#define BUILD_LUAJIT_ARCH_H

#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_lib.h>
#include "../lua_arch.h"

/* Opcode Instruction Type */
typedef ut32 LuaJITInstructions;

/* Opcode name */
typedef char *LuaJITOpName;

typedef enum {
	// Reference: https://github.com/aerospike/luajit/blob/master/src/lj_bc.h
	// name            |  args  |    description
	/* -- Comparison ops -- */
	LUAJIT_OP_ISLT = 0, /* A D     if (R(A) <  R(D)) pc++                             */
	LUAJIT_OP_ISGE, /* A D     if (R(A) >= R(D)) pc++                             */
	LUAJIT_OP_ISLE, /* A D     if (R(A) <= R(D)) pc++                             */
	LUAJIT_OP_ISGT, /* A D     if (R(A) >  R(D)) pc++                             */
	LUAJIT_OP_ISEQV, /* A D     if (R(A) == R(D)) pc++                             */
	LUAJIT_OP_ISNEV, /* A D     if (R(A) ~= R(D)) pc++                             */
	LUAJIT_OP_ISEQS, /* A D     if (R(A) == KSTR(D)) pc++                          */
	LUAJIT_OP_ISNES, /* A D     if (R(A) ~= KSTR(D)) pc++                          */
	LUAJIT_OP_ISEQN, /* A D     if (R(A) == KNUM(D)) pc++                          */
	LUAJIT_OP_ISNEN, /* A D     if (R(A) ~= KNUM(D)) pc++                          */
	LUAJIT_OP_ISEQP, /* A D     if (R(A) == KPRI(D)) pc++                          */
	LUAJIT_OP_ISNEP, /* A D     if (R(A) ~= KPRI(D)) pc++                          */

	/* -- Unary test and copy ops -- */
	LUAJIT_OP_ISTC, /* A D     if (R(D)) { R(A) = R(D); pc++ }                    */
	LUAJIT_OP_ISFC, /* A D     if (!R(D)) { R(A) = R(D); pc++ }                   */
	LUAJIT_OP_IST, /* A D     if (R(D)) pc++                                     */
	LUAJIT_OP_ISF, /* A D     if (!R(D)) pc++                                    */
	LUAJIT_OP_ISTYPE, /* A D     if (itype(R(A)) == D) pc++                         */
	LUAJIT_OP_ISNUM, /* A D     if (itype(R(A)) == KNUM) pc++                      */

	/* -- Unary ops -- */
	LUAJIT_OP_MOV, /* A D     R(A) := R(D)                                       */
	LUAJIT_OP_NOT, /* A D     R(A) := ~R(D)                                      */
	LUAJIT_OP_UNM, /* A D     R(A) := -R(D)                                      */
	LUAJIT_OP_LEN, /* A D     R(A) := length of R(D)                             */

	/* -- Binary ops (V = Variable, N = Number constant) -- */
	LUAJIT_OP_ADDVN, /* A B C   R(A) := R(B) + KNUM(C)                             */
	LUAJIT_OP_SUBVN, /* A B C   R(A) := R(B) - KNUM(C)                             */
	LUAJIT_OP_MULVN, /* A B C   R(A) := R(B) * KNUM(C)                             */
	LUAJIT_OP_DIVVN, /* A B C   R(A) := R(B) / KNUM(C)                             */
	LUAJIT_OP_MODVN, /* A B C   R(A) := R(B) % KNUM(C)                             */
	LUAJIT_OP_ADDNV, /* A B C   R(A) := KNUM(C) + R(B)                             */
	LUAJIT_OP_SUBNV, /* A B C   R(A) := KNUM(C) - R(B)                             */
	LUAJIT_OP_MULNV, /* A B C   R(A) := KNUM(C) * R(B)                             */
	LUAJIT_OP_DIVNV, /* A B C   R(A) := KNUM(C) / R(B)                             */
	LUAJIT_OP_MODNV, /* A B C   R(A) := KNUM(C) % R(B)                             */
	LUAJIT_OP_ADDVV, /* A B C   R(A) := R(B) + R(C)                                */
	LUAJIT_OP_SUBVV, /* A B C   R(A) := R(B) - R(C)                                */
	LUAJIT_OP_MULVV, /* A B C   R(A) := R(B) * R(C)                                */
	LUAJIT_OP_DIVVV, /* A B C   R(A) := R(B) / R(C)                                */
	LUAJIT_OP_MODVV, /* A B C   R(A) := R(B) % R(C)                                */
	LUAJIT_OP_POW, /* A B C   R(A) := R(B) ^ R(C)                                */
	LUAJIT_OP_CAT, /* A B C   R(A) := R(B) .. ... .. R(C)                        */

	/* -- Constant loads -- */
	LUAJIT_OP_KSTR, /* A D     R(A) := KSTR(D)                                    */
	LUAJIT_OP_KCDATA, /* A D     R(A) := KCDATA(D)                                  */
	LUAJIT_OP_KSHORT, /* A D     R(A) := (int16_t)D                                 */
	LUAJIT_OP_KNUM, /* A D     R(A) := KNUM(D)                                    */
	LUAJIT_OP_KPRI, /* A D     R(A) := KPRI(D) (nil, false, true)                 */
	LUAJIT_OP_KNIL, /* A D     R(A) ... R(D) := nil                               */

	/* -- Upvalue and function init -- */
	LUAJIT_OP_UGET, /* A D     R(A) := UPVAL(D)                                   */
	LUAJIT_OP_USETV, /* A D     UPVAL(D) := R(A)                                   */
	LUAJIT_OP_USETS, /* A D     UPVAL(D) := KSTR(A)                                */
	LUAJIT_OP_USETN, /* A D     UPVAL(D) := KNUM(A)                                */
	LUAJIT_OP_USETP, /* A D     UPVAL(D) := KPRI(A)                                */
	LUAJIT_OP_UCLO, /* A D     Close upvalues >= R(A); pc += (D - 0x8000)         */
	LUAJIT_OP_FNEW, /* A D     R(A) := closure(KPROTO(D))                         */

	/* -- Table ops -- */
	LUAJIT_OP_TNEW, /* A D     R(A) := new table(size = D)                        */
	LUAJIT_OP_TDUP, /* A D     R(A) := duplicate table(KTAB(D))                   */
	LUAJIT_OP_GGET, /* A D     R(A) := _G[KSTR(D)]                                */
	LUAJIT_OP_GSET, /* A D     _G[KSTR(D)] := R(A)                                */
	LUAJIT_OP_TGETV, /* A B C   R(A) := R(B)[R(C)]                                 */
	LUAJIT_OP_TGETS, /* A B C   R(A) := R(B)[KSTR(C)]                              */
	LUAJIT_OP_TGETB, /* A B C   R(A) := R(B)[C]                                    */
	LUAJIT_OP_TGETR, /* A B C   R(A) := R(B)[R(C)] (fast path)                     */
	LUAJIT_OP_TSETV, /* A B C   R(B)[R(C)] := R(A)                                 */
	LUAJIT_OP_TSETS, /* A B C   R(B)[KSTR(C)] := R(A)                              */
	LUAJIT_OP_TSETB, /* A B C   R(B)[C] := R(A)                                    */
	LUAJIT_OP_TSETM, /* A B C   R(B-1)[...] := R(A) ...                            */
	LUAJIT_OP_TSETR, /* A B C   R(B)[R(C)] := R(A) (fast path)                     */

	/* -- Calls and vararg handling -- */
	LUAJIT_OP_CALLM, /* A B C   R(A)...R(A+B-2) := R(A)(R(A+1)...)                 */
	LUAJIT_OP_CALL, /* A B C   R(A)...R(A+B-2) := R(A)(R(A+1)...R(A+C))           */
	LUAJIT_OP_CALLMT, /* A D     return R(A)(R(A+1)...)                             */
	LUAJIT_OP_CALLT, /* A D     return R(A)(R(A+1)...R(A+D))                       */
	LUAJIT_OP_ITERC, /* A B C   R(A)... := R(A-3)(R(A-2), R(A-1))                  */
	LUAJIT_OP_ITERN, /* A B C   fast loop iterator                                 */
	LUAJIT_OP_VARG, /* A B C   R(A)...R(A+B-2) := vararg                          */
	LUAJIT_OP_ISNEXT, /* A D     verify JFORI target, jump to it if true            */

	/* -- Returns -- */
	LUAJIT_OP_RETM, /* A D     return R(A) ... (multiret)                         */
	LUAJIT_OP_RET, /* A D     return R(A) ... R(A+D-2)                           */
	LUAJIT_OP_RET0, /* A D     return                                             */
	LUAJIT_OP_RET1, /* A D     return R(A)                                        */

	/* -- Loops and branches -- */
	LUAJIT_OP_FORI, /* A D     for loop init, jump to body (pc += (D - 0x8000))   */
	LUAJIT_OP_JFORI, /* A D     JIT-compiled for loop init                         */
	LUAJIT_OP_FORL, /* A D     for loop step, jump to body (pc += (D - 0x8000))   */
	LUAJIT_OP_IFORL, /* A D     interpreted for loop step                          */
	LUAJIT_OP_JFORL, /* A D     JIT-compiled for loop step                         */
	LUAJIT_OP_ITERL, /* A D     iterator loop step (pc += (D - 0x8000))            */
	LUAJIT_OP_IITERL, /* A D     interpreted iterator loop step                     */
	LUAJIT_OP_JITERL, /* A D     JIT-compiled iterator loop step                    */
	LUAJIT_OP_LOOP, /* A D     generic loop body                                  */
	LUAJIT_OP_ILOOP, /* A D     interpreted loop body                              */
	LUAJIT_OP_JLOOP, /* A D     JIT-compiled loop body                             */
	LUAJIT_OP_JMP, /* A D     pc += (D - 0x8000)                                 */

	/* -- Function headers -- */
	LUAJIT_OP_FUNCF, /* A       function header, fixed args                        */
	LUAJIT_OP_IFUNCF, /* A       interpreted function header                        */
	LUAJIT_OP_JFUNCF, /* A       JIT-compiled function header                       */
	LUAJIT_OP_FUNCV, /* A       function header, varargs                           */
	LUAJIT_OP_IFUNCV, /* A       interpreted function header, varargs               */
	LUAJIT_OP_JFUNCV, /* A       JIT-compiled function header, varargs              */
	LUAJIT_OP_FUNCC, /* A       C function header                                  */
	LUAJIT_OP_FUNCCW, /* A       C function header with wrapper                     */

	/* The maximum opcode */
	LUAJIT_OP__MAX
} LuaJITOpCode;

/* Common */
st32 luajitop_get_value(ut32 instr);
LuaJITOpName luajit_get_opname(LuaJITOpCode opcode);

/* Analysis */
int luajit_analysis_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, LuaJITInstructions instr);

/* Asm */
int luajit_disasm(RzAsmOp *op, int len, LuaJITOpName opname, LuaJITInstructions instr, LuaJITOpCode opcode);
char *luajitop_new_str_3arg(char *opname, int a, int b, int c);
char *luajitop_new_str_2arg(char *opname, int a, int b);
char *luajitop_new_str_1arg(char *opname, int a);
char *luajitop_new_str_reg_reg(const char *opname, ut32 a, ut32 d);
char *luajitop_new_str_reg_const(const char *opname, ut32 a, st32 d);

#define LUAJIT_GET_OPCODE(i) (cast(int, (i) & 0xFF))
#define LUAJIT_GET_A(i)      (cast(int, ((i) >> 8) & 0xFF)) /*Get A*/
#define LUAJIT_GET_C(i)      (cast(int, ((i) >> 16) & 0xFF)) /*Get B*/
#define LUAJIT_GET_B(i)      (cast(int, ((i) >> 24) & 0xFF)) /*Get C*/
#define LUAJIT_GET_D(i)      (cast(int, (i) >> 16)) /*Get D*/

#define LUAJIT_NUM_OPCODES ((int)(LUAJIT_OP__MAX) + 1)

#endif