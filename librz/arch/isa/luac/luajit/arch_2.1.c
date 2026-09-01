// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_2.1.h"

st32 luajitop_get_value(ut32 instr) {
	ut32 d = LUAJIT_GET_D(instr);
	st32 offset = 0;
	offset = (st32)d - 0x8000;
	return offset;
}

void luajitop_setf_asm_3arg(RzAsmOp *op, char *opname, int a, int b, int c) {
	rz_asm_op_setf_asm(op, "%s r%d %d %d", opname, a, b, c);
}

void luajitop_setf_asm_2arg(RzAsmOp *op, char *opname, int a, int b) {
	rz_asm_op_setf_asm(op, "%s r%d %d", opname, a, b);
}

void luajitop_setf_asm_1arg(RzAsmOp *op, char *opname, int a) {
	rz_asm_op_setf_asm(op, "%s r%d", opname, a);
}

// For Register to constant value (e.g., KSHORT r1, 8)
void luajitop_setf_asm_reg_const(RzAsmOp *op, const char *opname, ut32 a, st32 d) {
	rz_asm_op_setf_asm(op, "%s r%d %d", opname, a, d);
}

// For Register to Register (e.g., MOV r5, r4)
void luajitop_setf_asm_reg_reg(RzAsmOp *op, const char *opname, ut32 a, st32 d) {
	rz_asm_op_setf_asm(op, "%s r%d r%d", opname, a, d);
}