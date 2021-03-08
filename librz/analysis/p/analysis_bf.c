// SPDX-FileCopyrightText: 2011-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

static size_t countChar(const ut8 *buf, int len, char ch) {
	int i;
	for (i = 0; i < len; i++) {
		if (buf[i] != ch) {
			break;
		}
	}
	return i;
}

static int getid(char ch) {
	const char *keys = "[]<>+-,.";
	const char *cidx = strchr(keys, ch);
	return cidx ? cidx - keys + 1 : 0;
}

#define BUFSIZE_INC 32
static int bf_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	ut64 dst = 0LL;
	if (!op) {
		return 1;
	}
	/* Ayeeee! What's inside op? Do we have an initialized RzAnalysisOp? Are we going to have a leak here? :-( */
	memset(op, 0, sizeof(RzAnalysisOp)); /* We need to refactorize this. Something like rz_analysis_op_init would be more appropriate */
	rz_strbuf_init(&op->esil);
	op->size = 1;
	op->id = getid(buf[0]);
	switch (buf[0]) {
	case '[':
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->fail = addr + 1;
		buf = rz_mem_dup((void *)buf, len);
		if (!buf) {
			break;
		}
		{
			const ut8 *p = buf + 1;
			int lev = 0, i = 1;
			len--;
			while (i < len && *p) {
				if (*p == '[') {
					lev++;
				}
				if (*p == ']') {
					lev--;
					if (lev == -1) {
						dst = addr + (size_t)(p - buf);
						dst++;
						op->jump = dst;
						rz_strbuf_setf(&op->esil,
							"$$,brk,=[1],brk,++=,"
							"ptr,[1],!,?{,0x%" PFMT64x ",pc,=,brk,--=,}",
							dst);
						goto beach;
					}
				}
				if (*p == 0x00 || *p == 0xff) {
					op->type = RZ_ANALYSIS_OP_TYPE_ILL;
					goto beach;
				}
				if (i == len - 1 && analysis->read_at) {
					int new_buf_len = len + 1 + BUFSIZE_INC;
					ut8 *new_buf = calloc(new_buf_len, 1);
					if (new_buf) {
						free((ut8 *)buf);
						(void)analysis->read_at(analysis, addr, new_buf, new_buf_len);
						buf = new_buf;
						p = buf + i;
						len += BUFSIZE_INC;
					}
				}
				p++;
				i++;
			}
		}
	beach:
		free((ut8 *)buf);
		break;
	case ']':
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		// XXX This is wrong esil
		rz_strbuf_set(&op->esil, "brk,--=,brk,[1],pc,=");
		break;
	case '>':
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		op->size = countChar(buf, len, '>');
		rz_strbuf_setf(&op->esil, "%d,ptr,+=", op->size);
		break;
	case '<':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->size = countChar(buf, len, '<');
		rz_strbuf_setf(&op->esil, "%d,ptr,-=", op->size);
		break;
	case '+':
		op->size = countChar(buf, len, '+');
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		rz_strbuf_setf(&op->esil, "%d,ptr,+=[1]", op->size);
		break;
	case '-':
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		op->size = countChar(buf, len, '-');
		rz_strbuf_setf(&op->esil, "%d,ptr,-=[1]", op->size);
		break;
	case '.':
		// print element in stack to screen
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		rz_strbuf_set(&op->esil, "ptr,[1],scr,=[1],scr,++=");
		break;
	case ',':
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		rz_strbuf_set(&op->esil, "kbd,[1],ptr,=[1],kbd,++=");
		break;
	case 0x00:
	case 0xff:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		rz_strbuf_set(&op->esil, ",");
		break;
	}
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	return strdup(
		"=PC	pc\n"
		"=BP	brk\n"
		"=SP	ptr\n"
		"=A0	rax\n"
		"=A1	rbx\n"
		"=A2	rcx\n"
		"=A3	rdx\n"
		"gpr	ptr	.32	0	0\n" // data pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	brk	.32	8	0\n" // brackets
		"gpr	scr	.32	12	0\n" // screen
		"gpr	kbd	.32	16	0\n" // keyboard
	);
}

RzAnalysisPlugin rz_analysis_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck code analysis plugin",
	.license = "LGPL3",
	.arch = "bf",
	.bits = 8,
	.esil = true,
	.op = &bf_op,
	.get_reg_profile = get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_bf,
	.version = RZ_VERSION
};
#endif
