// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_2.1.h"

int luajit_disasm(RzAsmOp *op, int len, LuaJITOpName opname, LuaJITInstructions instr, LuaJITOpCode opcode) {
	if (len < 4) {
		RZ_LOG_DEBUG("Cannot disassemble luajit opcode (truncated).\n");
		return 0;
	}

	int a = LUAJIT_GET_A(instr);
	int b = LUAJIT_GET_B(instr);
	int c = LUAJIT_GET_C(instr);
	int d = LUAJIT_GET_D(instr);

	char *asm_str = NULL;

	switch (opcode) {
	// A D FORMAT (2 Operands)

	/* Comparison ops */
	case OP_ISLT: /* A D     if (R(A) <  R(D)) pc++                             */
	case OP_ISGE: /* A D     if (R(A) >= R(D)) pc++                             */
	case OP_ISLE: /* A D     if (R(A) <= R(D)) pc++                             */
	case OP_ISGT: /* A D     if (R(A) >  R(D)) pc++                             */
	case OP_ISEQV: /* A D     if (R(A) == R(D)) pc++                             */
	case OP_ISNEV: /* A D     if (R(A) ~= R(D)) pc++                             */
	case OP_ISEQS: /* A D     if (R(A) == KSTR(D)) pc++                          */
	case OP_ISNES: /* A D     if (R(A) ~= KSTR(D)) pc++                          */
	case OP_ISEQN: /* A D     if (R(A) == KNUM(D)) pc++                          */
	case OP_ISNEN: /* A D     if (R(A) ~= KNUM(D)) pc++                          */
	case OP_ISEQP: /* A D     if (R(A) == KPRI(D)) pc++                          */
	case OP_ISNEP: /* A D     if (R(A) ~= KPRI(D)) pc++                          */
	/* Unary test and copy ops */
	case OP_ISTC: /* A D     if (R(D)) { R(A) = R(D); pc++ }                    */
	case OP_ISFC: /* A D     if (!R(D)) { R(A) = R(D); pc++ }                   */
	case OP_IST: /* A D     if (R(D)) pc++                                     */
	case OP_ISF: /* A D     if (!R(D)) pc++                                    */
	case OP_ISTYPE: /* A D     if (itype(R(A)) == D) pc++                         */
	case OP_ISNUM: /* A D     if (itype(R(A)) == KNUM) pc++                      */
	/* Unary ops */
	case OP_MOV: /* A D     R(A) := R(D)                                       */
	case OP_NOT: /* A D     R(A) := ~R(D)                                      */
	case OP_UNM: /* A D     R(A) := -R(D)                                      */
	case OP_LEN: /* A D     R(A) := length of R(D)                             */
		asm_str = luajitop_new_str_reg_reg(opname, a, d);
		break;
	/* Constant loads */
	case OP_KSTR: /* A D     R(A) := KSTR(D)                                    */
	case OP_KCDATA: /* A D     R(A) := KCDATA(D)                                  */
	case OP_KNUM: /* A D     R(A) := KNUM(D)                                    */
	case OP_KPRI: /* A D     R(A) := KPRI(D) (nil, false, true)                 */
	/* Upvalue and function init */
	case OP_UGET: /* A D     R(A) := UPVAL(D)                                   */
	case OP_USETV: /* A D     UPVAL(D) := R(A)                                   */
	case OP_USETS: /* A D     UPVAL(D) := KSTR(A)                                */
	case OP_USETN: /* A D     UPVAL(D) := KNUM(A)                                */
	case OP_USETP: /* A D     UPVAL(D) := KPRI(A)                                */
	case OP_UCLO: /* A D     Close upvalues >= R(A); pc += (D - 0x8000)         */
	case OP_FNEW: /* A D     R(A) := closure(KPROTO(D))                         */
	/* Table ops (AD only) */
	case OP_TNEW: /* A D     R(A) := new table(size = D)                        */
	case OP_TDUP: /* A D     R(A) := duplicate table(KTAB(D))                   */
	case OP_GGET: /* A D     R(A) := _G[KSTR(D)]                                */
	case OP_GSET: /* A D     _G[KSTR(D)] := R(A)                                */
		asm_str = luajitop_new_str_reg_const(opname, a, d);
		break;
	/* Calls and vararg handling (AD only) */
	case OP_CALLMT: /* A D     return R(A)(R(A+1)...)                             */
	case OP_CALLT: /* A D     return R(A)(R(A+1)...R(A+D))                       */
	case OP_ISNEXT: /* A D     verify JFORI target, jump to it if true            */
	/* Returns */
	case OP_RETM: /* A D     return R(A) ... (multiret)                         */
	case OP_RET: /* A D     return R(A) ... R(A+D-2)                           */
	case OP_RET0: /* A D     return                                             */
	case OP_RET1: /* A D     return R(A)                                        */
	/* Loops and branches */
	case OP_FORI: /* A D     for loop init, jump to body (pc += (D - 0x8000))   */
	case OP_JFORI: /* A D     JIT-compiled for loop init                         */
	case OP_FORL: /* A D     for loop step, jump to body (pc += (D - 0x8000))   */
	case OP_IFORL: /* A D     interpreted for loop step                          */
	case OP_JFORL: /* A D     JIT-compiled for loop step                         */
	case OP_ITERL: /* A D     iterator loop step (pc += (D - 0x8000))            */
	case OP_IITERL: /* A D     interpreted iterator loop step                     */
	case OP_JITERL: /* A D     JIT-compiled iterator loop step                    */
	case OP_LOOP: /* A D     generic loop body                                  */
	case OP_ILOOP: /* A D     interpreted loop body                              */
	case OP_JLOOP: /* A D     JIT-compiled loop body                             */
		asm_str = luajitop_new_str_2arg(opname, a, d);
		break;
	case OP_JMP: /* A D     pc += (D - 0x8000)                                 */
		d = luajitop_get_value(instr);
		asm_str = luajitop_new_str_2arg(opname, a, d);
		break;
	case OP_KSHORT: /* A D     R(A) := (int16_t)D                                 */
		// Note: Needs the cast to signed 16-bit
		asm_str = luajitop_new_str_reg_const(opname, a, (st16)d);
		break;
	case OP_KNIL: /* A D     R(A) ... R(D) := nil                               */
		asm_str = rz_str_newf("%s r%d...r%d", opname, a, d);
		break;
	/* Binary ops (V = Variable, N = Number constant) */
	case OP_ADDVN: /* A B C   R(A) := R(B) + KNUM(C)                             */
	case OP_SUBVN: /* A B C   R(A) := R(B) - KNUM(C)                             */
	case OP_MULVN: /* A B C   R(A) := R(B) * KNUM(C)                             */
	case OP_DIVVN: /* A B C   R(A) := R(B) / KNUM(C)                             */
	case OP_MODVN: /* A B C   R(A) := R(B) % KNUM(C)                             */
	case OP_ADDNV: /* A B C   R(A) := KNUM(C) + R(B)                             */
	case OP_SUBNV: /* A B C   R(A) := KNUM(C) - R(B)                             */
	case OP_MULNV: /* A B C   R(A) := KNUM(C) * R(B)                             */
	case OP_DIVNV: /* A B C   R(A) := KNUM(C) / R(B)                             */
	case OP_MODNV: /* A B C   R(A) := KNUM(C) % R(B)                             */
	case OP_ADDVV: /* A B C   R(A) := R(B) + R(C)                                */
	case OP_SUBVV: /* A B C   R(A) := R(B) - R(C)                                */
	case OP_MULVV: /* A B C   R(A) := R(B) * R(C)                                */
	case OP_DIVVV: /* A B C   R(A) := R(B) / R(C)                                */
	case OP_MODVV: /* A B C   R(A) := R(B) % R(C)                                */
	case OP_POW: /* A B C   R(A) := R(B) ^ R(C)                                */
	case OP_CAT: /* A B C   R(A) := R(B) .. ... .. R(C)                        */
	/* Table ops (ABC only) */
	case OP_TGETV: /* A B C   R(A) := R(B)[R(C)]                                 */
	case OP_TGETS: /* A B C   R(A) := R(B)[KSTR(C)]                              */
	case OP_TGETB: /* A B C   R(A) := R(B)[C]                                    */
	case OP_TGETR: /* A B C   R(A) := R(B)[R(C)] (fast path)                     */
	case OP_TSETV: /* A B C   R(B)[R(C)] := R(A)                                 */
	case OP_TSETS: /* A B C   R(B)[KSTR(C)] := R(A)                              */
	case OP_TSETB: /* A B C   R(B)[C] := R(A)                                    */
	case OP_TSETM: /* A B C   R(B-1)[...] := R(A) ...                            */
	case OP_TSETR: /* A B C   R(B)[R(C)] := R(A) (fast path)                     */
	/* Calls and vararg handling (ABC only) */
	case OP_CALLM: /* A B C   R(A)...R(A+B-2) := R(A)(R(A+1)...)                 */
	case OP_CALL: /* A B C   R(A)...R(A+B-2) := R(A)(R(A+1)...R(A+C))           */
	case OP_ITERC: /* A B C   R(A)... := R(A-3)(R(A-2), R(A-1))                  */
	case OP_ITERN: /* A B C   fast loop iterator                                 */
	case OP_VARG: /* A B C   R(A)...R(A+B-2) := vararg                          */
		asm_str = luajitop_new_str_3arg(opname, a, b, c);
		break;
	/* Function headers */
	case OP_FUNCF: /* A       function header, fixed args                        */
	case OP_IFUNCF: /* A       interpreted function header                        */
	case OP_JFUNCF: /* A       JIT-compiled function header                       */
	case OP_FUNCV: /* A       function header, varargs                           */
	case OP_IFUNCV: /* A       interpreted function header, varargs               */
	case OP_JFUNCV: /* A       JIT-compiled function header, varargs              */
	case OP_FUNCC: /* A       C function header                                  */
	case OP_FUNCCW: /* A       C function header with wrapper                     */
		asm_str = luajitop_new_str_1arg(opname, a);
		break;
	// FALLBACKS
	case OP__MAX: /* The maximum opcode */
		asm_str = rz_str_newf("Max");
		break;
	default:
		asm_str = rz_str_newf("invalid");
	}
	op->size = 4;
	rz_asm_op_set_asm(op, asm_str);
	RZ_FREE(asm_str);
	return 4;
}