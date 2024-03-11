// SPDX-FileCopyrightText: 2015-2018 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include <string.h>
#include "snes_op_table.h"

int snesDisass(int M_flag, int X_flag, ut64 pc, RzAsmOp *op, const ut8 *buf, int len) {
	snes_op_t *s_op = &snes_op[buf[0]];
	int op_len = snes_op_get_size(M_flag, X_flag, s_op);
	if (len < op_len) {
		return 0;
	}
	switch (s_op->len) {
	case SNES_OP_8BIT:
		rz_asm_op_set_asm(op, s_op->name);
		break;
	case SNES_OP_16BIT:
		if (*buf % 0x20 == 0x10 || *buf == 0x80) { // relative branch
			rz_asm_op_setf_asm(op, s_op->name, (ut32)(pc + 2 + (st8)buf[1]));
		} else {
			rz_asm_op_setf_asm(op, s_op->name, buf[1]);
		}
		break;
	case SNES_OP_24BIT:
		if (*buf == 0x44 || *buf == 0x54) { // mvp and mvn
			rz_asm_op_setf_asm(op, s_op->name, buf[1], buf[2]);
		} else if (*buf == 0x82) { // brl
			rz_asm_op_setf_asm(op, s_op->name, pc + 3 + (st16)rz_read_le16(buf + 1));
		} else {
			rz_asm_op_setf_asm(op, s_op->name, rz_read_le16(buf + 1));
		}
		break;
	case SNES_OP_32BIT:
		rz_asm_op_setf_asm(op, s_op->name, buf[1] | buf[2] << 8 | buf[3] << 16);
		break;
	case SNES_OP_IMM_M:
		if (M_flag) {
			rz_asm_op_setf_asm(op, "%s #0x%02x", s_op->name, buf[1]);
		} else {
			rz_asm_op_setf_asm(op, "%s #0x%04x", s_op->name, rz_read_le16(buf + 1));
		}
		break;
	case SNES_OP_IMM_X:
		if (X_flag) {
			rz_asm_op_setf_asm(op, "%s #0x%02x", s_op->name, buf[1]);
		} else {
			rz_asm_op_setf_asm(op, "%s #0x%04x", s_op->name, rz_read_le16(buf + 1));
		}
		break;
	default:
		rz_asm_op_set_asm(op, "invalid");
		break;
	}
	return op_len;
}
