// SPDX-FileCopyrightText: 2026 Arya-1-HR
// SPDX-License-Identifier: LGPL-3.0-only

#include "arch_2.1.h"

st32 luajitop_get_value(ut32 instr) {
	ut32 d = LUAJIT_GET_D(instr);
	st32 offset = 0;
	offset = (st32)d - 0x8000;
	return offset;
}

char *luajitop_new_str_3arg(char *opname, int a, int b, int c) {
	return rz_str_newf("%s r%d %d %d", opname, a, b, c);
}

char *luajitop_new_str_2arg(char *opname, int a, int b) {
	return rz_str_newf("%s r%d %d", opname, a, b);
}

char *luajitop_new_str_1arg(char *opname, int a) {
	return rz_str_newf("%s %d", opname, a);
}

// For Register to constant value (e.g., KSHORT r1, 8)
char *luajitop_new_str_reg_const(const char *opname, ut32 a, st32 d) {
	return rz_str_newf("%s r%d %d", opname, a, d);
}

// For Register to Register (e.g., MOV r5, r4)
char *luajitop_new_str_reg_reg(const char *opname, ut32 a, ut32 d) {
	return rz_str_newf("%s r%d r%d", opname, a, d);
}