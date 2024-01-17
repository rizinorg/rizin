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
	char *buf_asm = rz_str_newf("invalid");
	if (rlen > len) {
		free(buf_asm);
		return op->size = 0;
	}
	switch (high) {
	case 0:
		free(buf_asm);
		buf_asm = rz_str_newf(low ? "invalid" : "nop");
		break;
	case 1:
		free(buf_asm);
		buf_asm = rz_str_newf("jcn %d 0x%02x", low, buf[1]);
		break;
	case 2:
		free(buf_asm);
		if (rlen == 1) {
			buf_asm = rz_str_newf("src r%d", (low & 0xe));
		} else {
			buf_asm = rz_str_newf("fim r%d, 0x%02x", (low & 0xe), buf[1]);
		}
		break;
	case 3:
		free(buf_asm);
		if ((low & 1) == 1) {
			buf_asm = rz_str_newf("jin r%d", (low & 0xe));
		} else {
			buf_asm = rz_str_newf("fin r%d", (low & 0xe));
		}
		break;
	case 4:
		free(buf_asm);
		buf_asm = rz_str_newf("jun 0x%03x", ((ut16)(low << 8) | buf[1]));
		break;
	case 5:
		free(buf_asm);
		buf_asm = rz_str_newf("jms 0x%03x", ((ut16)(low << 8) | buf[1]));
		break;
	case 6:
		free(buf_asm);
		buf_asm = rz_str_newf("inc r%d", low);
		break;
	case 7:
		free(buf_asm);
		buf_asm = rz_str_newf("isz r%d, 0x%02x", low, buf[1]);
		break;
	case 8:
		free(buf_asm);
		buf_asm = rz_str_newf("add r%d", low);
		break;
	case 9:
		free(buf_asm);
		buf_asm = rz_str_newf("sub r%d", low);
		break;
	case 10:
		free(buf_asm);
		buf_asm = rz_str_newf("ld r%d", low);
		break;
	case 11:
		free(buf_asm);
		buf_asm = rz_str_newf("xch r%d", low);
		break;
	case 12:
		free(buf_asm);
		buf_asm = rz_str_newf("bbl %d", low);
		break;
	case 13:
		free(buf_asm);
		buf_asm = rz_str_newf("ldm %d", low);
		break;
	case 14:
		free(buf_asm);
		buf_asm = rz_str_newf("%s", i4004_e[low]);
		break;
	case 15:
		free(buf_asm);
		buf_asm = rz_str_newf("%s", i4004_f[low]);
		break;
	}
	rz_strbuf_set(&op->buf_asm, buf_asm);
	free(buf_asm);
	return op->size = rlen;
}
