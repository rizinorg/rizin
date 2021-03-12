// SPDX-FileCopyrightText: 2014-2018 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_lib.h>
#include <rz_io.h>
#define WS_API static
#include "../../asm/arch/whitespace/wsdis.c"

static ut64 ws_find_label(int l, const RzIOBind *iob) {
	RzIO *io = iob->io;
	ut64 cur = 0, size = iob->desc_size(io->desc);
	ut8 buf[128];
	RzAsmOp aop;
	iob->read_at(iob->io, cur, buf, 128);
	while (cur <= size && wsdis(&aop, buf, 128)) {
		const char *buf_asm = rz_strbuf_get(&aop.buf_asm); // rz_asm_op_get_asm (&aop);
		if (buf_asm && (strlen(buf_asm) > 4) && buf_asm[0] == 'm' && buf_asm[1] == 'a' && l == atoi(buf_asm + 5)) {
			return cur;
		}
		cur = cur + aop.size;
		iob->read_at(iob->io, cur, buf, 128);
	}
	return 0;
}

static int ws_analysis(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	RzAsmOp *aop = RZ_NEW0(RzAsmOp);
	op->size = wsdis(aop, data, len);
	if (op->size) {
		const char *buf_asm = rz_strbuf_get(&aop->buf_asm); // rz_asm_op_get_asm (aop);
		switch (*buf_asm) {
		case 'n':
			op->type = RZ_ANALYSIS_OP_TYPE_NOP;
			break;
		case 'e':
			op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
			break;
		case 'd':
			op->type = (buf_asm[1] == 'u') ? RZ_ANALYSIS_OP_TYPE_UPUSH : RZ_ANALYSIS_OP_TYPE_DIV;
			break;
		case 'i':
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		case 'a':
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case 'm':
			op->type = (buf_asm[1] == 'o') ? RZ_ANALYSIS_OP_TYPE_MOD : RZ_ANALYSIS_OP_TYPE_MUL;
			break;
		case 'r':
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
			break;
		case 'l':
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 'c':
			if (buf_asm[1] == 'a') {
				op->type = RZ_ANALYSIS_OP_TYPE_CALL;
				op->fail = addr + aop->size;
				op->jump = ws_find_label(atoi(buf_asm + 5), &analysis->iob);
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_UPUSH;
			}
			break;
		case 'j':
			if (buf_asm[1] == 'm') {
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				op->jump = ws_find_label(atoi(buf_asm + 4), &analysis->iob);
			} else {
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = ws_find_label(atoi(buf_asm + 3), &analysis->iob);
			}
			op->fail = addr + aop->size;
			break;
		case 'g':
			op->type = RZ_ANALYSIS_OP_TYPE_IO;
			break;
		case 'p':
			if (buf_asm[1] == 'o') {
				op->type = RZ_ANALYSIS_OP_TYPE_POP;
			} else {
				if (buf_asm[2] == 's') {
					op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
					if (127 > atoi(buf_asm + 5) && atoi(buf_asm + 5) >= 33) {
						char c[4];
						c[3] = '\0';
						c[0] = c[2] = '\'';
						c[1] = (char)atoi(buf_asm + 5);
						rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, addr, c);
					}
				} else {
					op->type = RZ_ANALYSIS_OP_TYPE_IO;
				}
			}
			break;
		case 's':
			switch (buf_asm[1]) {
			case 'u':
				op->type = RZ_ANALYSIS_OP_TYPE_SUB;
				break;
			case 't':
				op->type = RZ_ANALYSIS_OP_TYPE_STORE;
				break;
			case 'l':
				op->type = RZ_ANALYSIS_OP_TYPE_LOAD; // XXX
				break;
			case 'w':
				op->type = RZ_ANALYSIS_OP_TYPE_ROR;
			}
			break;
		}
	}
	free(aop);
	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_ws = {
	.name = "ws",
	.desc = "Space, tab and linefeed analysis plugin",
	.license = "LGPL3",
	.arch = "ws",
	.bits = 32,
	.op = &ws_analysis,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_ws,
	.version = RZ_VERSION
};
#endif
