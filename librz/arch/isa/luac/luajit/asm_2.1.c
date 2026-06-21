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
	case LUAJIT_OP_ISLT: /* A D     if (R(A) <  R(D)) pc++                             */
	case LUAJIT_OP_ISGE: /* A D     if (R(A) >= R(D)) pc++                             */
	case LUAJIT_OP_ISLE: /* A D     if (R(A) <= R(D)) pc++                             */
	case LUAJIT_OP_ISGT: /* A D     if (R(A) >  R(D)) pc++                             */
	case LUAJIT_OP_ISEQV: /* A D     if (R(A) == R(D)) pc++                             */
	case LUAJIT_OP_ISNEV: /* A D     if (R(A) ~= R(D)) pc++                             */
	case LUAJIT_OP_ISEQS: /* A D     if (R(A) == KSTR(D)) pc++                          */
	case LUAJIT_OP_ISNES: /* A D     if (R(A) ~= KSTR(D)) pc++                          */
	case LUAJIT_OP_ISEQN: /* A D     if (R(A) == KNUM(D)) pc++                          */
	case LUAJIT_OP_ISNEN: /* A D     if (R(A) ~= KNUM(D)) pc++                          */
	case LUAJIT_OP_ISEQP: /* A D     if (R(A) == KPRI(D)) pc++                          */
	case LUAJIT_OP_ISNEP: /* A D     if (R(A) ~= KPRI(D)) pc++                          */
	/* Unary test and copy ops */
	case LUAJIT_OP_ISTC: /* A D     if (R(D)) { R(A) = R(D); pc++ }                    */
	case LUAJIT_OP_ISFC: /* A D     if (!R(D)) { R(A) = R(D); pc++ }                   */
	case LUAJIT_OP_IST: /* A D     if (R(D)) pc++                                     */
	case LUAJIT_OP_ISF: /* A D     if (!R(D)) pc++                                    */
	case LUAJIT_OP_ISTYPE: /* A D     if (itype(R(A)) == D) pc++                         */
	case LUAJIT_OP_ISNUM: /* A D     if (itype(R(A)) == KNUM) pc++                      */
	/* Unary ops */
	case LUAJIT_OP_MOV: /* A D     R(A) := R(D)                                       */
	case LUAJIT_OP_NOT: /* A D     R(A) := ~R(D)                                      */
	case LUAJIT_OP_UNM: /* A D     R(A) := -R(D)                                      */
	case LUAJIT_OP_LEN: /* A D     R(A) := length of R(D)                             */
		asm_str = luajitop_new_str_reg_reg(opname, a, d);
		break;
	/* Constant loads */
	case LUAJIT_OP_KSTR: /* A D     R(A) := KSTR(D)                                    */
	case LUAJIT_OP_KCDATA: /* A D     R(A) := KCDATA(D)                                  */
	case LUAJIT_OP_KNUM: /* A D     R(A) := KNUM(D)                                    */
	case LUAJIT_OP_KPRI: /* A D     R(A) := KPRI(D) (nil, false, true)                 */
	/* Upvalue and function init */
	case LUAJIT_OP_UGET: /* A D     R(A) := UPVAL(D)                                   */
	case LUAJIT_OP_USETV: /* A D     UPVAL(D) := R(A)                                   */
	case LUAJIT_OP_USETS: /* A D     UPVAL(D) := KSTR(A)                                */
	case LUAJIT_OP_USETN: /* A D     UPVAL(D) := KNUM(A)                                */
	case LUAJIT_OP_USETP: /* A D     UPVAL(D) := KPRI(A)                                */
	case LUAJIT_OP_UCLO: /* A D     Close upvalues >= R(A); pc += (D - 0x8000)         */
	case LUAJIT_OP_FNEW: /* A D     R(A) := closure(KPROTO(D))                         */
	/* Table ops (AD only) */
	case LUAJIT_OP_TNEW: /* A D     R(A) := new table(size = D)                        */
	case LUAJIT_OP_TDUP: /* A D     R(A) := duplicate table(KTAB(D))                   */
	case LUAJIT_OP_GGET: /* A D     R(A) := _G[KSTR(D)]                                */
	case LUAJIT_OP_GSET: /* A D     _G[KSTR(D)] := R(A)                                */
		asm_str = luajitop_new_str_reg_const(opname, a, d);
		break;
	/* Calls and vararg handling (AD only) */
	case LUAJIT_OP_CALLMT: /* A D     return R(A)(R(A+1)...)                             */
	case LUAJIT_OP_CALLT: /* A D     return R(A)(R(A+1)...R(A+D))                       */
	case LUAJIT_OP_ISNEXT: /* A D     verify JFORI target, jump to it if true            */
	/* Returns */
	case LUAJIT_OP_RETM: /* A D     return R(A) ... (multiret)                         */
	case LUAJIT_OP_RET: /* A D     return R(A) ... R(A+D-2)                           */
	case LUAJIT_OP_RET0: /* A D     return                                             */
	case LUAJIT_OP_RET1: /* A D     return R(A)                                        */
	/* Loops and branches */
	case LUAJIT_OP_FORI: /* A D     for loop init, jump to body (pc += (D - 0x8000))   */
	case LUAJIT_OP_JFORI: /* A D     JIT-compiled for loop init                         */
	case LUAJIT_OP_FORL: /* A D     for loop step, jump to body (pc += (D - 0x8000))   */
	case LUAJIT_OP_IFORL: /* A D     interpreted for loop step                          */
	case LUAJIT_OP_JFORL: /* A D     JIT-compiled for loop step                         */
	case LUAJIT_OP_ITERL: /* A D     iterator loop step (pc += (D - 0x8000))            */
	case LUAJIT_OP_IITERL: /* A D     interpreted iterator loop step                     */
	case LUAJIT_OP_JITERL: /* A D     JIT-compiled iterator loop step                    */
	case LUAJIT_OP_LOOP: /* A D     generic loop body                                  */
	case LUAJIT_OP_ILOOP: /* A D     interpreted loop body                              */
	case LUAJIT_OP_JLOOP: /* A D     JIT-compiled loop body                             */
		asm_str = luajitop_new_str_2arg(opname, a, d);
		break;
	case LUAJIT_OP_JMP: /* A D     pc += (D - 0x8000)                                 */
		d = luajitop_get_value(instr);
		asm_str = luajitop_new_str_2arg(opname, a, d);
		break;
	case LUAJIT_OP_KSHORT: /* A D     R(A) := (int16_t)D                                 */
		// Note: Needs the cast to signed 16-bit
		asm_str = luajitop_new_str_reg_const(opname, a, (st16)d);
		break;
	case LUAJIT_OP_KNIL: /* A D     R(A) ... R(D) := nil                               */
		asm_str = rz_str_newf("%s r%d...r%d", opname, a, d);
		break;

	// A B C FORMAT (3 Operands)
	/* Binary ops (V = Variable, N = Number constant) */
	case LUAJIT_OP_ADDVN: /* A B C   R(A) := R(B) + KNUM(C)                             */
	case LUAJIT_OP_SUBVN: /* A B C   R(A) := R(B) - KNUM(C)                             */
	case LUAJIT_OP_MULVN: /* A B C   R(A) := R(B) * KNUM(C)                             */
	case LUAJIT_OP_DIVVN: /* A B C   R(A) := R(B) / KNUM(C)                             */
	case LUAJIT_OP_MODVN: /* A B C   R(A) := R(B) % KNUM(C)                             */
	case LUAJIT_OP_ADDNV: /* A B C   R(A) := KNUM(C) + R(B)                             */
	case LUAJIT_OP_SUBNV: /* A B C   R(A) := KNUM(C) - R(B)                             */
	case LUAJIT_OP_MULNV: /* A B C   R(A) := KNUM(C) * R(B)                             */
	case LUAJIT_OP_DIVNV: /* A B C   R(A) := KNUM(C) / R(B)                             */
	case LUAJIT_OP_MODNV: /* A B C   R(A) := KNUM(C) % R(B)                             */
	case LUAJIT_OP_ADDVV: /* A B C   R(A) := R(B) + R(C)                                */
	case LUAJIT_OP_SUBVV: /* A B C   R(A) := R(B) - R(C)                                */
	case LUAJIT_OP_MULVV: /* A B C   R(A) := R(B) * R(C)                                */
	case LUAJIT_OP_DIVVV: /* A B C   R(A) := R(B) / R(C)                                */
	case LUAJIT_OP_MODVV: /* A B C   R(A) := R(B) % R(C)                                */
	case LUAJIT_OP_POW: /* A B C   R(A) := R(B) ^ R(C)                                */
	case LUAJIT_OP_CAT: /* A B C   R(A) := R(B) .. ... .. R(C)                        */
	/* Table ops (ABC only) */
	case LUAJIT_OP_TGETV: /* A B C   R(A) := R(B)[R(C)]                                 */
	case LUAJIT_OP_TGETS: /* A B C   R(A) := R(B)[KSTR(C)]                              */
	case LUAJIT_OP_TGETB: /* A B C   R(A) := R(B)[C]                                    */
	case LUAJIT_OP_TGETR: /* A B C   R(A) := R(B)[R(C)] (fast path)                     */
	case LUAJIT_OP_TSETV: /* A B C   R(B)[R(C)] := R(A)                                 */
	case LUAJIT_OP_TSETS: /* A B C   R(B)[KSTR(C)] := R(A)                              */
	case LUAJIT_OP_TSETB: /* A B C   R(B)[C] := R(A)                                    */
	case LUAJIT_OP_TSETM: /* A B C   R(B-1)[...] := R(A) ...                            */
	case LUAJIT_OP_TSETR: /* A B C   R(B)[R(C)] := R(A) (fast path)                     */
	/* Calls and vararg handling (ABC only) */
	case LUAJIT_OP_CALLM: /* A B C   R(A)...R(A+B-2) := R(A)(R(A+1)...)                 */
	case LUAJIT_OP_CALL: /* A B C   R(A)...R(A+B-2) := R(A)(R(A+1)...R(A+C))           */
	case LUAJIT_OP_ITERC: /* A B C   R(A)... := R(A-3)(R(A-2), R(A-1))                  */
	case LUAJIT_OP_ITERN: /* A B C   fast loop iterator                                 */
	case LUAJIT_OP_VARG: /* A B C   R(A)...R(A+B-2) := vararg                          */
		asm_str = luajitop_new_str_3arg(opname, a, b, c);
		break;

	// A FORMAT (1 Operands)
	/* Function headers */
	case LUAJIT_OP_FUNCF: /* A       function header, fixed args                        */
	case LUAJIT_OP_IFUNCF: /* A       interpreted function header                        */
	case LUAJIT_OP_JFUNCF: /* A       JIT-compiled function header                       */
	case LUAJIT_OP_FUNCV: /* A       function header, varargs                           */
	case LUAJIT_OP_IFUNCV: /* A       interpreted function header, varargs               */
	case LUAJIT_OP_JFUNCV: /* A       JIT-compiled function header, varargs              */
	case LUAJIT_OP_FUNCC: /* A       C function header                                  */
	case LUAJIT_OP_FUNCCW: /* A       C function header with wrapper                     */
		asm_str = luajitop_new_str_1arg(opname, a);
		break;
	// FALLBACKS
	case LUAJIT_OP__MAX: /* The maximum opcode */
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