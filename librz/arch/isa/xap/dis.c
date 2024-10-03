// SPDX-FileCopyrightText: 2007 sorbo
// SPDX-FileCopyrightText: 2010-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include "dis.h"

#include <rz_types.h>
#include <rz_util/rz_assert.h>

static int decode_fixed(xap_state_t *s, xap_directive_t *d) {
	switch (d->opcode) {
	case INST_NOP:
		if (s->s_prefix) {
			return 0;
		}
		s->s_nop++;
		rz_strbuf_set(d->d_asm, "nop");
		break;
	case INST_BRK: rz_strbuf_set(d->d_asm, "brk"); break;
	case INST_SLEEP: rz_strbuf_set(d->d_asm, "sleep"); break;
	case INST_SIF: rz_strbuf_set(d->d_asm, "sif"); break;
	case INST_BC: rz_strbuf_set(d->d_asm, "bc"); break;
	case INST_BC2: rz_strbuf_set(d->d_asm, "bc2"); break;
	case INST_BRXL: rz_strbuf_set(d->d_asm, "brxl"); break;
	case INST_U:
		s->s_u = 1;
		break;
	case INST_RTS: rz_strbuf_set(d->d_asm, "rts"); break;
	}
	return rz_strbuf_length(d->d_asm) > 0;
}

static char *regname(int reg) {
	switch (reg) {
	case REG_AH: return "AH";
	case REG_AL: return "AL";
	case REG_X: return "X";
	case REG_Y: return "Y";
	}
	return NULL;
}

static int get_num(int num, int shift) {
	char x = (char)((num >> shift) & 0xff);
	return (int)(x << shift);
}

static int get_operand(xap_state_t *s, xap_directive_t *d) {
	int total = get_num(d->d_inst.in_operand, 0);
	if (s->s_prefix)
		total += get_num(s->s_prefix_val, 8);
	if (s->s_prefix == 2)
		total += get_num(s->s_prefix_val, 16);
	return total;
}

static int decode_known(xap_state_t *s, xap_directive_t *d) {
	char *op = NULL;
	char *regn = NULL;
	int reg = 0;
	int ptr = 1;
	int idx = 1;
	int imm = 0;
	int rel = 0;
	char fmt[16];
	int fmtsz;
	int branch = 0;
	xap_instruction_t *in = &d->d_inst;
	//	int operand;
	char *sign = "";
	int rti = 0;

	switch (in->in_opcode) {
	case 0:
		if (in->in_reg == 0 && in->in_mode == 0) {
			if (s->s_prefix == 0) {
				s->s_prefix_val = 0;
			}
			s->s_prefix++;

			if (s->s_prefix == 2) {
				s->s_prefix_val <<= 8;
			}
#if 0
			/* XXX we need to look ahead more to see if we're
			 * getting a branch instruction */
			if (s->s_nopd && in->in_operand == 0x80)
				strcpy(s->s_nopd->d_asm, "");
#endif
			s->s_prefix_val |= in->in_operand << 8;
			return 1;
		}

		switch (d->opcode & 0xf) {
		case 1:
			op = "st";
			regn = "FLAGS";
			break;
		case 2:
			op = "st";
			regn = "UX";
			break;
		case 3:
			op = "st";
			regn = "UY";
			break;
		case 5:
			op = "ld";
			regn = "FLAGS";
			break;
		case 6:
			op = "ld";
			regn = "UX";
			break;
		case 7:
			op = "ld";
			regn = "UY";
			break;
		case 0xa:
			op = "st";
			regn = "XH";
			break;
		case 0xd:
			op = "rti";
			regn = "";
			rti = 1;
			break;
		case 0xe:
			op = "ld";
			regn = "XH";
			break;
		}
		break;

	case 1:
		op = "ld";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 2:
		if (in->in_mode == DATA_MODE_IMMEDIATE) {
			op = "print";
			imm = 1;
			reg = 1;
		} else {
			op = "st";
			reg = 1;
			ptr = 1;
			idx = 1;
		}
		break;
	case 3:
		op = "add";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 4:
		op = "addc";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 5:
		op = "sub";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 6:
		op = "subc";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 7:
		op = "nadd";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 8:
		op = "cmp";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 0x9:
		switch (in->in_reg) {
		case 0:
			if (s->s_u)
				op = "umult";
			else
				op = "smult";
			imm = 1;
			s->s_u = 0;
			idx = 1;
			ptr = 1;
			break;
		case 1:
			if (s->s_u)
				op = "udiv";
			else
				op = "sdiv";
			s->s_u = 0;
			imm = 1;
			break;
		case 2:
			op = "tst";
			imm = 1;
			ptr = 1;
			idx = 1;
			break;
		case 3:
			branch = 1;
			op = "bsr";
			ptr = 1;
			idx = 1;
			if (in->in_mode == ADDR_MODE_RELATIVE)
				rel = 1;
			break;
		}
		break;
	case 0xa:
		switch (in->in_reg) {
		case 0:
			op = "asl";
			imm = 1;
			break;
		case 1:
			if (s->s_u)
				op = "lsr";
			else
				op = "asr";
			s->s_u = 0;
			imm = 1;
			idx = 1;
			ptr = 1;
			break;
		case 2:
			op = "rol";
			imm = 1;
			break;
		case 3:
			op = "ror";
			imm = 1;
			break;
		}
		break;

	case 0xb:
		op = "or";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 0xc:
		op = "and";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 0xd:
		op = "xor";
		reg = 1;
		ptr = 1;
		idx = 1;
		imm = 1;
		break;
	case 0xe:
		branch = 1;
		if (in->in_mode == ADDR_MODE_RELATIVE)
			rel = 1;
		switch (in->in_reg) {
		case 0:
			op = "bra";
			ptr = 1;
			idx = 1;
#if 0
			if (s->s_nopd) {
				op = "bra2"; /* XXX need bra3 support */
				strcpy(s->s_nopd->d_asm, "");
			}
#endif
			break;

		case 1:
			op = "blt"; /* yummy */
			break;
		case 2:
			op = "bpl";
			break;
		case 3:
			op = "bmi";
			break;
		}
		break;
	case 0xf:
		branch = 1;
		if (in->in_mode == ADDR_MODE_RELATIVE)
			rel = 1;
		switch (in->in_reg) {
		case 0: op = "bne"; break;
		case 1: op = "beq"; break;
		case 2: op = "bcc"; break;
		case 3: op = "bcs"; break;
		}
		break;
	}

	if (!op) {
		return 0;
	}

	if (ptr && in->in_mode == DATA_MODE_IMMEDIATE)
		ptr = 0;

	if (branch && in->in_mode == ADDR_MODE_X_RELATIVE)
		ptr = 0;

	if (idx && (!(in->in_mode & 2))) {
		idx = 0;
	}

	if (regn) {
		ptr = 1;
		idx = 1;
		reg = 1;
	}

	rz_strbuf_setf(d->d_asm, "%s ", op);
	if (reg) {
		char *r = regn;
		if (!r) {
			r = regname(in->in_reg);
		}
		if (r && !rti) {
			rz_strbuf_appendf(d->d_asm, "%s, ", r);
		}
	}
	if (ptr) {
		rz_strbuf_append(d->d_asm, "@");
		rel = 0;
	} else if (imm) {
		rz_strbuf_append(d->d_asm, "#");
	}
	if (idx && ptr) {
		rz_strbuf_append(d->d_asm, "(");
	}

	d->d_prefix = s->s_prefix;
	//	d->d_operand = get_operand(s, d);
	if ((branch && idx) || rti) {
		d->d_operand = get_operand(s, d);
		if (d->d_operand < 0) {
			d->d_operand *= -1;
			sign = "-";
		}
	} else {
		d->d_operand = s->s_prefix_val | in->in_operand;
		if (d->d_operand & 0x80) {
			if (d->d_prefix) {
				if (!rel) {
					d->d_operand -= 0x100;
				}
			} else {
				d->d_operand |= 0xff00;
			}
		}
	}
	fmtsz = 4;
	if (d->d_operand & 0xff0000) {
		fmtsz += 2;
	}

	rz_strf(fmt, "%s0x%%.%dx", sign, fmtsz);
	rz_strbuf_appendf(d->d_asm, fmt, d->d_operand);

	if (idx) {
		char *r = in->in_mode == DATA_MODE_INDEXED_X ? "X" : "Y";
		if (regn) {
			r = "Y";
		}
		rz_strbuf_appendf(d->d_asm, ", %s", r);
		if (ptr)
			rz_strbuf_append(d->d_asm, ")");
	}

	return 1;
}

static void xap_decode(xap_state_t *s, xap_directive_t *d) {
	int prefix = s->s_prefix;
	if (!decode_fixed(s, d) && !decode_known(s, d)) {
		rz_strbuf_setf(d->d_asm, "unknown");
	}
	if (s->s_prefix == prefix)
		s->s_prefix_val = s->s_prefix = 0;
}

static int xap_read_instruction(xap_state_t *s, xap_directive_t *d) {
	d->opcode = rz_read_le16(s->s_buf);
	d->d_inst.in_mode = d->opcode & 0x3; // : 2,
	d->d_inst.in_reg = (d->opcode >> 2) & 0x3; // : 2,
	d->d_inst.in_opcode = (d->opcode >> 4) & 0xF; // : 4,
	d->d_inst.in_operand = (d->opcode >> 8) & 0xFF; // : 8;

	d->d_off = s->s_off++;
	return 1;
}
