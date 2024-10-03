// SPDX-FileCopyrightText: 2008-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include "xap/dis.c"

static int label_off(xap_directive_t *d) {
	int off = d->d_operand;
	int lame = off & 0x80;

	if (!d->d_prefix) {
		off = (char)(off & 0xff);
	} else if (d->d_prefix == 1) {
		off = (short)(off & 0xffff);
		if (lame) {
			off -= 0x100;
		}
	} else {
		off = (int)(off & 0xffffff);
		if (off & 0x800000) {
			off |= 0xff000000;
		}
		if (off & 0x8000) {
			off -= 0x10000;
		}
		if (lame) {
			off -= 0x100;
		}
	}
	return d->d_off + off;
}

static int xap_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	xap_directive_t d = { 0 };
	xap_state_t s = { 0 };
	xap_instruction_t *in = &d.d_inst;
	RzStrBuf sb;

	if (!analysis || !op) {
		return 2;
	}

	rz_strbuf_init(&sb);

	s.s_buf = buf;
	s.s_off = addr;
	d.d_asm = &sb;

	if (xap_read_instruction(&s, &d) > 0) {
		xap_decode(&s, &d);
	} else {
		rz_strbuf_fini(&sb);
		return op->size;
	}
	d.d_operand = get_operand(&s, &d);

	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->size = 2;

	switch (d.opcode) {
	case INST_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case INST_BRK:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case INST_BC:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case INST_BC2:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	case INST_BRXL:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	default:
		switch (in->in_opcode) {
		case 0:
			switch (d.opcode & 0xf) {
			case 1:
			case 2:
			case 3:
			case 0xa:
				op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
				break;
			case 4:
			case 5:
			case 6:
			case 7:
			case 0xe:
				op->type = RZ_ANALYSIS_OP_TYPE_POP;
				break;
			}
			break;
		case 1:
			op->type = RZ_ANALYSIS_OP_TYPE_POP;
			break;
		case 2:
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
			break;
		case 3:
		case 4:
		case 7:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case 5:
		case 6:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case 8:
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
			break;
		case 9:
			switch (in->in_reg) {
			case 0:
				op->type = RZ_ANALYSIS_OP_TYPE_MUL;
				break;
			case 1:
				op->type = RZ_ANALYSIS_OP_TYPE_DIV;
				break;
			case 2:
				op->type = RZ_ANALYSIS_OP_TYPE_CMP;
				break;
			case 3:
				// BSR
				op->type = RZ_ANALYSIS_OP_TYPE_CALL;
				op->jump = label_off(&d);
				if (op->jump & 1) {
					op->jump += 3;
				}
				op->fail = addr + 2;
				op->eob = true;
				break;
			}
			break;
		case 0xb:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break;
		case 0xc:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			break;
		case 0xd:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			break;
		case 0xe:
			switch (in->in_reg) {
			case 0: // BRA
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				op->jump = label_off(&d) + 4;
				if (op->jump & 1) {
					op->jump += 3;
				}
				op->eob = true;
				break;
			case 1:
				// BLT
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = label_off(&d);
				if (op->jump & 1) {
					op->jump += 3;
				}
				op->fail = addr + 2;
				op->eob = true;
				break;
			case 2:
				// BPL
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = label_off(&d);
				if (op->jump & 1) {
					op->jump += 3;
				}
				op->fail = addr + 2;
				op->eob = true;
				break;
			case 3:
				// BMI
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = label_off(&d);
				if (op->jump & 1) {
					op->jump += 3;
				}
				op->fail = addr + 2;
				op->eob = true;
				break;
			}
			break;
		case 0xf:
			switch (in->in_reg) {
			case 0: // BNE
			case 1: // BEQ
			case 2: // BCC
			case 3: // BCS
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = label_off(&d);
				if (op->jump & 1) {
					op->jump += 3;
				}
				op->fail = addr + 2;
				break;
			}
			break;
		}
		break;
	}
	rz_strbuf_fini(&sb);
	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_xap = {
	.name = "xap",
	.desc = "XAP code analysis plugin",
	.license = "LGPL3",
	.arch = "xap",
	.bits = 16,
	.op = &xap_op,
};
