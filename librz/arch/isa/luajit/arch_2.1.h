// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef BUILD_LUAJIT_ARCH_H
#define BUILD_LUAJIT_ARCH_H

#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_lib.h>

/* Opcode Instruction Type */
typedef ut32 LuaJITInstructions;

/* Opcode name */
typedef char **LuaJITOpNameList;

/* Common */
LuaJITInstructions luajit_build_instruction(const ut8 *buf);
st32 luajitop_get_value(ut32 instr);
LuaJITOpNameList get_luajit_opnames(void);

/* Analysis */
int luajit_analysis_op(RzAnalysis *anal, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len);

/* Asm */
int luajit_disasm(RzAsmOp *op, const ut8 *buf, int len, LuaJITOpNameList oplist);
char *luajitop_new_str_3arg(char *opname, int a, int b, int c);
char *luajitop_new_str_2arg(char *opname, int a, int b);
char *luajitop_new_str_1arg(char *opname, int a);
char *luajitop_new_str_reg_reg(const char *opname, ut32 a, ut32 d);
char *luajitop_new_str_reg_const(const char *opname, ut32 a, st32 d);

#define cast(x, y) ((x)(y))

#define LUAJIT_GET_OPCODE(i) (cast(int, (i) & 0xFF))
#define LUAJIT_GET_A(i)      (cast(int, ((i) >> 8) & 0xFF)) /*Get A*/
#define LUAJIT_GET_C(i)      (cast(int, ((i) >> 16) & 0xFF)) /*Get B*/
#define LUAJIT_GET_B(i)      (cast(int, ((i) >> 24) & 0xFF)) /*Get C*/
#define LUAJIT_GET_D(i)      (cast(int, (i) >> 16)) /*Get D*/

typedef enum {
	// Reference: https://github.com/aerospike/luajit/blob/master/src/lj_bc.h
	// name            |  args  |    description
	/* -- Comparison ops -- */
	OP_ISLT = 0, /* A D     if (R(A) <  R(D)) pc++                             */
	OP_ISGE, /* A D     if (R(A) >= R(D)) pc++                             */
	OP_ISLE, /* A D     if (R(A) <= R(D)) pc++                             */
	OP_ISGT, /* A D     if (R(A) >  R(D)) pc++                             */
	OP_ISEQV, /* A D     if (R(A) == R(D)) pc++                             */
	OP_ISNEV, /* A D     if (R(A) ~= R(D)) pc++                             */
	OP_ISEQS, /* A D     if (R(A) == KSTR(D)) pc++                          */
	OP_ISNES, /* A D     if (R(A) ~= KSTR(D)) pc++                          */
	OP_ISEQN, /* A D     if (R(A) == KNUM(D)) pc++                          */
	OP_ISNEN, /* A D     if (R(A) ~= KNUM(D)) pc++                          */
	OP_ISEQP, /* A D     if (R(A) == KPRI(D)) pc++                          */
	OP_ISNEP, /* A D     if (R(A) ~= KPRI(D)) pc++                          */

	/* -- Unary test and copy ops -- */
	OP_ISTC, /* A D     if (R(D)) { R(A) = R(D); pc++ }                    */
	OP_ISFC, /* A D     if (!R(D)) { R(A) = R(D); pc++ }                   */
	OP_IST, /* A D     if (R(D)) pc++                                     */
	OP_ISF, /* A D     if (!R(D)) pc++                                    */
	OP_ISTYPE, /* A D     if (itype(R(A)) == D) pc++                         */
	OP_ISNUM, /* A D     if (itype(R(A)) == KNUM) pc++                      */

	/* -- Unary ops -- */
	OP_MOV, /* A D     R(A) := R(D)                                       */
	OP_NOT, /* A D     R(A) := ~R(D)                                      */
	OP_UNM, /* A D     R(A) := -R(D)                                      */
	OP_LEN, /* A D     R(A) := length of R(D)                             */

	/* -- Binary ops (V = Variable, N = Number constant) -- */
	OP_ADDVN, /* A B C   R(A) := R(B) + KNUM(C)                             */
	OP_SUBVN, /* A B C   R(A) := R(B) - KNUM(C)                             */
	OP_MULVN, /* A B C   R(A) := R(B) * KNUM(C)                             */
	OP_DIVVN, /* A B C   R(A) := R(B) / KNUM(C)                             */
	OP_MODVN, /* A B C   R(A) := R(B) % KNUM(C)                             */
	OP_ADDNV, /* A B C   R(A) := KNUM(C) + R(B)                             */
	OP_SUBNV, /* A B C   R(A) := KNUM(C) - R(B)                             */
	OP_MULNV, /* A B C   R(A) := KNUM(C) * R(B)                             */
	OP_DIVNV, /* A B C   R(A) := KNUM(C) / R(B)                             */
	OP_MODNV, /* A B C   R(A) := KNUM(C) % R(B)                             */
	OP_ADDVV, /* A B C   R(A) := R(B) + R(C)                                */
	OP_SUBVV, /* A B C   R(A) := R(B) - R(C)                                */
	OP_MULVV, /* A B C   R(A) := R(B) * R(C)                                */
	OP_DIVVV, /* A B C   R(A) := R(B) / R(C)                                */
	OP_MODVV, /* A B C   R(A) := R(B) % R(C)                                */
	OP_POW, /* A B C   R(A) := R(B) ^ R(C)                                */
	OP_CAT, /* A B C   R(A) := R(B) .. ... .. R(C)                        */

	/* -- Constant loads -- */
	OP_KSTR, /* A D     R(A) := KSTR(D)                                    */
	OP_KCDATA, /* A D     R(A) := KCDATA(D)                                  */
	OP_KSHORT, /* A D     R(A) := (int16_t)D                                 */
	OP_KNUM, /* A D     R(A) := KNUM(D)                                    */
	OP_KPRI, /* A D     R(A) := KPRI(D) (nil, false, true)                 */
	OP_KNIL, /* A D     R(A) ... R(D) := nil                               */

	/* -- Upvalue and function init -- */
	OP_UGET, /* A D     R(A) := UPVAL(D)                                   */
	OP_USETV, /* A D     UPVAL(D) := R(A)                                   */
	OP_USETS, /* A D     UPVAL(D) := KSTR(A)                                */
	OP_USETN, /* A D     UPVAL(D) := KNUM(A)                                */
	OP_USETP, /* A D     UPVAL(D) := KPRI(A)                                */
	OP_UCLO, /* A D     Close upvalues >= R(A); pc += (D - 0x8000)         */
	OP_FNEW, /* A D     R(A) := closure(KPROTO(D))                         */

	/* -- Table ops -- */
	OP_TNEW, /* A D     R(A) := new table(size = D)                        */
	OP_TDUP, /* A D     R(A) := duplicate table(KTAB(D))                   */
	OP_GGET, /* A D     R(A) := _G[KSTR(D)]                                */
	OP_GSET, /* A D     _G[KSTR(D)] := R(A)                                */
	OP_TGETV, /* A B C   R(A) := R(B)[R(C)]                                 */
	OP_TGETS, /* A B C   R(A) := R(B)[KSTR(C)]                              */
	OP_TGETB, /* A B C   R(A) := R(B)[C]                                    */
	OP_TGETR, /* A B C   R(A) := R(B)[R(C)] (fast path)                     */
	OP_TSETV, /* A B C   R(B)[R(C)] := R(A)                                 */
	OP_TSETS, /* A B C   R(B)[KSTR(C)] := R(A)                              */
	OP_TSETB, /* A B C   R(B)[C] := R(A)                                    */
	OP_TSETM, /* A B C   R(B-1)[...] := R(A) ...                            */
	OP_TSETR, /* A B C   R(B)[R(C)] := R(A) (fast path)                     */

	/* -- Calls and vararg handling -- */
	OP_CALLM, /* A B C   R(A)...R(A+B-2) := R(A)(R(A+1)...)                 */
	OP_CALL, /* A B C   R(A)...R(A+B-2) := R(A)(R(A+1)...R(A+C))           */
	OP_CALLMT, /* A D     return R(A)(R(A+1)...)                             */
	OP_CALLT, /* A D     return R(A)(R(A+1)...R(A+D))                       */
	OP_ITERC, /* A B C   R(A)... := R(A-3)(R(A-2), R(A-1))                  */
	OP_ITERN, /* A B C   fast loop iterator                                 */
	OP_VARG, /* A B C   R(A)...R(A+B-2) := vararg                          */
	OP_ISNEXT, /* A D     verify JFORI target, jump to it if true            */

	/* -- Returns -- */
	OP_RETM, /* A D     return R(A) ... (multiret)                         */
	OP_RET, /* A D     return R(A) ... R(A+D-2)                           */
	OP_RET0, /* A D     return                                             */
	OP_RET1, /* A D     return R(A)                                        */

	/* -- Loops and branches -- */
	OP_FORI, /* A D     for loop init, jump to body (pc += (D - 0x8000))   */
	OP_JFORI, /* A D     JIT-compiled for loop init                         */
	OP_FORL, /* A D     for loop step, jump to body (pc += (D - 0x8000))   */
	OP_IFORL, /* A D     interpreted for loop step                          */
	OP_JFORL, /* A D     JIT-compiled for loop step                         */
	OP_ITERL, /* A D     iterator loop step (pc += (D - 0x8000))            */
	OP_IITERL, /* A D     interpreted iterator loop step                     */
	OP_JITERL, /* A D     JIT-compiled iterator loop step                    */
	OP_LOOP, /* A D     generic loop body                                  */
	OP_ILOOP, /* A D     interpreted loop body                              */
	OP_JLOOP, /* A D     JIT-compiled loop body                             */
	OP_JMP, /* A D     pc += (D - 0x8000)                                 */

	/* -- Function headers -- */
	OP_FUNCF, /* A       function header, fixed args                        */
	OP_IFUNCF, /* A       interpreted function header                        */
	OP_JFUNCF, /* A       JIT-compiled function header                       */
	OP_FUNCV, /* A       function header, varargs                           */
	OP_IFUNCV, /* A       interpreted function header, varargs               */
	OP_JFUNCV, /* A       JIT-compiled function header, varargs              */
	OP_FUNCC, /* A       C function header                                  */
	OP_FUNCCW, /* A       C function header with wrapper                     */

	/* The maximum opcode */
	OP__MAX
} LuaJITOpCode;

#define LUAJIT_NUM_OPCODES ((int)(OP__MAX) + 1)

#endif