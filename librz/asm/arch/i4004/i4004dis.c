// SPDX-FileCopyrightText: 2014-2018 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2014-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_types.h>
#include <string.h>
#include <stdio.h>

/* That 3 is a hack */
static const int i4004_ins_len[16] = {
	1, 2, 3, 1, 2, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1
};

static const char *i4004_e[16] = {
	"wrm",
	"wmp",
	"wrr",
	"wpm",
	"wr0",
	"wr1",
	"wr2",
	"wr3",
	"sbm",
	"rdm",
	"rdr",
	"adm",
	"rd0",
	"rd1",
	"rd2",
	"rd3"
};

static const char *i4004_f[16] = {
	"clb",
	"clc",
	"iac",
	"cmc",
	"cma",
	"ral",
	"rar",
	"tcc",
	"dac",
	"tcs",
	"stc",
	"daa",
	"kbp",
	"dcl",
	"invalid",
	"invalid"
};

static int i4004_get_ins_len(ut8 hex) {
	ut8 high = (hex & 0xf0) >> 4;
	int ret = i4004_ins_len[high];
	if (ret == 3)
		ret = (hex & 1) ? 1 : 2;
	return ret;
}

static int i4004dis(RzAsmOp *op, const ut8 *buf, int len) {
	int rlen = i4004_get_ins_len(*buf);
	ut8 high = (*buf & 0xf0) >> 4;
	ut8 low = (*buf & 0xf);
	if (rlen > len) {
		return op->size = 0;
	}
	switch (high) {
	case 0: rz_asm_op_set_asm(op, low ? "invalid" : "nop"); break;
	case 1: rz_asm_op_setf_asm(op, "jcn %d 0x%02x", low, buf[1]); break;
	case 2:
		if (rlen == 1) {
			rz_asm_op_setf_asm(op, "src r%d", (low & 0xe));
		} else {
			rz_asm_op_setf_asm(op, "fim r%d, 0x%02x", (low & 0xe), buf[1]);
		}
		break;
	case 3:
		if ((low & 1) == 1) {
			rz_asm_op_setf_asm(op, "jin r%d", (low & 0xe));
		} else {
			rz_asm_op_setf_asm(op, "fin r%d", (low & 0xe));
		}
		break;
	case 4: rz_asm_op_setf_asm(op, "jun 0x%03x", ((ut16)(low << 8) | buf[1])); break;
	case 5: rz_asm_op_setf_asm(op, "jms 0x%03x", ((ut16)(low << 8) | buf[1])); break;
	case 6: rz_asm_op_setf_asm(op, "inc r%d", low); break;
	case 7: rz_asm_op_setf_asm(op, "isz r%d, 0x%02x", low, buf[1]); break;
	case 8: rz_asm_op_setf_asm(op, "add r%d", low); break;
	case 9: rz_asm_op_setf_asm(op, "sub r%d", low); break;
	case 10: rz_asm_op_setf_asm(op, "ld r%d", low); break;
	case 11: rz_asm_op_setf_asm(op, "xch r%d", low); break;
	case 12: rz_asm_op_setf_asm(op, "bbl %d", low); break;
	case 13: rz_asm_op_setf_asm(op, "ldm %d", low); break;
	case 14: rz_asm_op_set_asm(op, i4004_e[low]); break;
	case 15: rz_asm_op_set_asm(op, i4004_f[low]); break;
	default: rz_asm_op_set_asm(op, "invalid"); break;
	}
	return op->size = rlen;
}
