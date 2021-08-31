// SPDX-FileCopyrightText: 2015-2018 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include <string.h>
#include "snes_op_table.h"

static int snesDisass(int M_flag, int X_flag, ut64 pc, RzAsmOp *op, const ut8 *buf, int len) {
	snes_op_t *s_op = &snes_op[buf[0]];
	int op_len = snes_op_get_size(M_flag, X_flag, s_op);
	if (len < op_len) {
		return 0;
	}
	const char *buf_asm = "invalid";
	switch (s_op->len) {
	case SNES_OP_8BIT:
		buf_asm = s_op->name;
		break;
	case SNES_OP_16BIT:
		if (*buf % 0x20 == 0x10 || *buf == 0x80) { // relative branch
			buf_asm = sdb_fmt(s_op->name, (ut32)(pc + 2 + (st8)buf[1]));
		} else {
			buf_asm = sdb_fmt(s_op->name, buf[1]);
		}
		break;
	case SNES_OP_24BIT:
		if (*buf == 0x44 || *buf == 0x54) { // mvp and mvn
			buf_asm = sdb_fmt(s_op->name, buf[1], buf[2]);
		} else if (*buf == 0x82) { // brl
			buf_asm = sdb_fmt(s_op->name, pc + 3 + (st16)rz_read_le16(buf + 1));
		} else {
			buf_asm = sdb_fmt(s_op->name, rz_read_le16(buf + 1));
		}
		break;
	case SNES_OP_32BIT:
		buf_asm = sdb_fmt(s_op->name, buf[1] | buf[2] << 8 | buf[3] << 16);
		break;
	case SNES_OP_IMM_M:
		if (M_flag) {
			buf_asm = sdb_fmt("%s #0x%02x", s_op->name, buf[1]);
		} else {
			buf_asm = sdb_fmt("%s #0x%04x", s_op->name, rz_read_le16(buf + 1));
		}
		break;
	case SNES_OP_IMM_X:
		if (X_flag) {
			buf_asm = sdb_fmt("%s #0x%02x", s_op->name, buf[1]);
		} else {
			buf_asm = sdb_fmt("%s #0x%04x", s_op->name, rz_read_le16(buf + 1));
		}
		break;
	}
	rz_strbuf_set(&op->buf_asm, buf_asm);
	return op_len;
}
