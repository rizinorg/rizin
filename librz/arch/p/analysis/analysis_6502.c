// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019-2020 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2019-2020 riq <ricardoquesada@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/* 6502 info taken from http://unusedino.de/ec64/technical/aay/c64/bchrt651.htm
 *
 * Mnemonics logic based on:
 *	http://homepage.ntlworld.com/cyborgsystems/CS_Main/6502/6502.htm
 * and:
 *	http://vice-emu.sourceforge.net/
 */

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include "snes/snes_op_table.h"
#include "6502/6502_il.inc"
#include <6502/6502dis.h>
#include <rz_config.h>

enum {
	_6502_FLAGS_C = (1 << 0),
	_6502_FLAGS_B = (1 << 1),
	_6502_FLAGS_Z = (1 << 2),
	_6502_FLAGS_N = (1 << 3),

	_6502_FLAGS_NZ = (_6502_FLAGS_Z | _6502_FLAGS_N),
	_6502_FLAGS_CNZ = (_6502_FLAGS_C | _6502_FLAGS_Z | _6502_FLAGS_N),
	_6502_FLAGS_BNZ = (_6502_FLAGS_B | _6502_FLAGS_Z | _6502_FLAGS_N),
};

static void _6502_analysis_esil_update_flags(RzAnalysisOp *op, int flags) {
	/* FIXME: 9,$b instead of 8,$b to prevent the bug triggered by: A = 0 - 0xff - 1 */
	if (flags & _6502_FLAGS_B) {
		rz_strbuf_append(&op->esil, ",9,$b,C,:=");
	}
	if (flags & _6502_FLAGS_C) {
		rz_strbuf_append(&op->esil, ",7,$c,C,:=");
	}
	if (flags & _6502_FLAGS_Z) {
		rz_strbuf_append(&op->esil, ",$z,Z,:=");
	}
	if (flags & _6502_FLAGS_N) {
		rz_strbuf_append(&op->esil, ",7,$s,N,:=");
	}
}

/* ORA, AND, EOR, ADC, STA, LDA, CMP and SBC share this pattern */
static void _6502_analysis_esil_get_addr_pattern1(RzAnalysisOp *op, const ut8 *data, size_t len,
	RZ_NULLABLE char *esiladdr_out, int esiladdr_size,
	RZ_NULLABLE _6502ILAddr *il_out) {
	if (len < 1) {
		return;
	}
	// turn off bits 5, 6 and 7
	ut16 imm = 0;
	switch (data[0] & 0x1f) { // 0x1f = b00011111
	case 0x09: // op #$ff
		op->cycles = 2;
		imm = len > 1 ? data[1] : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "0x%02x", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_immediate(il_out, imm);
		}
		break;
	case 0x05: // op $ff
		op->cycles = 3;
		imm = len > 1 ? data[1] : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "0x%02x", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_addr_absolute(il_out, imm);
		}
		break;
	case 0x15: // op $ff,x
		op->cycles = 4;
		imm = len > 1 ? data[1] : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "x,0x%02x,+", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_addr_zero_page_reg(il_out, imm, "x");
		}
		break;
	case 0x0d: // op $ffff
		op->cycles = 4;
		imm = (len > 2) ? ((ut16)data[1] | (ut16)data[2] << 8) : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "0x%04x", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_addr_absolute(il_out, imm);
		}
		break;
	case 0x1d: // op $ffff,x
		op->cycles = 4;
		op->failcycles = 5;
		imm = (len > 2) ? ((ut16)data[1] | (ut16)data[2] << 8) : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "x,0x%04x,+", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_addr_reg(il_out, imm, "x");
		}
		break;
	case 0x19: // op $ffff,y
		op->cycles = 4;
		op->failcycles = 5;
		imm = (len > 2) ? ((ut16)data[1] | (ut16)data[2] << 8) : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "y,0x%04x,+", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_addr_reg(il_out, imm, "y");
		}
		break;
	case 0x01: // op ($ff,x)
		op->cycles = 6;
		imm = (len > 1) ? data[1] : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "x,0x%02x,+,[2]", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_addr_indirect_x(il_out, imm);
		}
		break;
	case 0x11: // op ($ff),y
		op->cycles = 5;
		op->failcycles = 6;
		imm = len > 1 ? data[1] : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "y,0x%02x,[2],+", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_addr_indirect_y(il_out, imm);
		}
		break;
	}
}

/* ASL, ROL, LSR, ROR, STX, LDX, DEC and INC share this pattern */
static void _6502_analysis_esil_get_addr_pattern2(RzAnalysisOp *op, const ut8 *data, size_t len,
	char *addrbuf, int addrsize, const char *reg,
	RZ_NULLABLE _6502ILAddr *il_out) {
	// turn off bits 5, 6 and 7
	if (len < 1) {
		return;
	}
	ut16 imm = 0;
	switch (data[0] & 0x1f) { // 0x1f = b00111111
	case 0x02: // op #$ff
		op->cycles = 2;
		imm = (len > 1) ? data[1] : 0;
		snprintf(addrbuf, addrsize, "0x%02x", (unsigned int)imm);
		if (il_out) {
			_6502_il_immediate(il_out, imm);
		}
		break;
	case 0x0a: // op a
		op->cycles = 2;
		snprintf(addrbuf, addrsize, "a");
		if (il_out) {
			_6502_il_accumulator(il_out);
		}
		break;
	case 0x06: // op $ff
		op->cycles = 5;
		imm = (len > 1) ? data[1] : 0;
		snprintf(addrbuf, addrsize, "0x%02x", (unsigned int)imm);
		if (il_out) {
			_6502_il_addr_absolute(il_out, imm);
		}
		break;
	case 0x16: // op $ff,x (or op $ff,y)
		op->cycles = 6;
		imm = (len > 1) ? data[1] : 0;
		snprintf(addrbuf, addrsize, "%s,0x%02x,+", reg, imm);
		if (il_out) {
			_6502_il_addr_zero_page_reg(il_out, imm, reg);
		}
		break;
	case 0x0e: // op $ffff
		op->cycles = 6;
		imm = (len > 2) ? data[1] | data[2] << 8 : 0;
		snprintf(addrbuf, addrsize, "0x%04x", imm);
		if (il_out) {
			_6502_il_addr_absolute(il_out, imm);
		}
		break;
	case 0x1e: // op $ffff,x (or op $ffff,y)
		op->cycles = 7;
		imm = (len > 2) ? data[1] | data[2] << 8 : 0;
		snprintf(addrbuf, addrsize, "%s,0x%04x,+", reg, imm);
		if (il_out) {
			_6502_il_addr_reg(il_out, imm, reg);
		}
		break;
	}
}

/* BIT, JMP, JMP(), STY, LDY, CPY, and CPX share this pattern */
static void _6502_analysis_esil_get_addr_pattern3(RzAnalysisOp *op, const ut8 *data, size_t len,
	char *addrbuf, int addrsize, const char *reg,
	RZ_NULLABLE _6502ILAddr *il_out) {
	// turn off bits 5, 6 and 7
	if (len < 1) {
		return;
	}
	ut16 imm;
	switch (data[0] & 0x1f) { // 0x1f = b00111111
	case 0x00: // op #$ff
		op->cycles = 2;
		imm = (len > 1) ? data[1] : 0;
		snprintf(addrbuf, addrsize, "0x%02x", imm);
		if (il_out) {
			_6502_il_immediate(il_out, imm);
		}
		break;
	case 0x08: // op a
		op->cycles = 2;
		snprintf(addrbuf, addrsize, "a");
		if (il_out) {
			_6502_il_accumulator(il_out);
		}
		break;
	case 0x04: // op $ff
		op->cycles = 5;
		imm = (len > 1) ? data[1] : 0;
		snprintf(addrbuf, addrsize, "0x%02x", imm);
		if (il_out) {
			_6502_il_addr_absolute(il_out, imm);
		}
		break;
	case 0x14: // op $ff,x
		op->cycles = 6;
		imm = (len > 1) ? data[1] : 0;
		snprintf(addrbuf, addrsize, "%s,0x%02x,+", reg, imm);
		if (il_out) {
			_6502_il_addr_zero_page_reg(il_out, imm, reg);
		}
		break;
	case 0x0c: // op $ffff
		op->cycles = 6;
		imm = (len > 2) ? data[1] | data[2] << 8 : 0;
		snprintf(addrbuf, addrsize, "0x%04x", imm);
		if (il_out) {
			_6502_il_addr_absolute(il_out, imm);
		}
		break;
	case 0x1c: // op $ffff,x
		op->cycles = 7;
		imm = (len > 2) ? data[1] | data[2] << 8 : 0;
		snprintf(addrbuf, addrsize, "%s,0x%04x,+", reg, imm);
		if (il_out) {
			_6502_il_addr_reg(il_out, imm, reg);
		}
		break;
	}
}

static void _6502_analysis_esil_ccall(RzAnalysisOp *op, ut8 data0) {
	char *flag;
	switch (data0) {
	case 0x10: // bpl $ffff
		flag = "N,!";
		break;
	case 0x30: // bmi $ffff
		flag = "N";
		break;
	case 0x50: // bvc $ffff
		flag = "V,!";
		break;
	case 0x70: // bvs $ffff
		flag = "V";
		break;
	case 0x90: // bcc $ffff
		flag = "C,!";
		break;
	case 0xb0: // bcs $ffff
		flag = "C";
		break;
	case 0xd0: // bne $ffff
		flag = "Z,!";
		break;
	case 0xf0: // beq $ffff
		flag = "Z";
		break;
	default:
		// FIXME: should not happen
		flag = "unk";
		rz_warn_if_reached();
		break;
	}
	rz_strbuf_setf(&op->esil, "%s,?{,0x%04x,pc,=,}", flag, (ut32)(op->jump & 0xffff));
}

// inc register
static void _6502_analysis_esil_inc_reg(RzAnalysisOp *op, ut8 data0, char *sign) {
	char *reg = NULL;

	switch (data0) {
	case 0xe8: // inx
	case 0xca: // dex
		reg = "x";
		break;
	case 0xc8: // iny
	case 0x88: // dey
		reg = "y";
		break;
	}
	rz_strbuf_setf(&op->esil, "%s,%s%s=", reg, sign, sign);
	_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
}

static void _6502_analysis_esil_mov(RzAnalysisOp *op, ut8 data0) {
	const char *src = "unk";
	const char *dst = "unk";
	switch (data0) {
	case 0xaa: // tax
		src = "a";
		dst = "x";
		break;
	case 0x8a: // txa
		src = "x";
		dst = "a";
		break;
	case 0xa8: // tay
		src = "a";
		dst = "y";
		break;
	case 0x98: // tya
		src = "y";
		dst = "a";
		break;
	case 0x9a: // txs
		src = "x";
		dst = "sp";
		break;
	case 0xba: // tsx
		src = "sp";
		dst = "x";
		break;
	default:
		// FIXME: should not happen
		rz_warn_if_reached();
		break;
	}
	rz_strbuf_setf(&op->esil, "%s,%s,=", src, dst);

	// don't update NZ on txs
	if (data0 != 0x9a) {
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
	}
}

static void _6502_analysis_esil_push(RzAnalysisOp *op, ut8 data0) {
	// case 0x08: // php
	// case 0x48: // pha
	char *reg = (data0 == 0x08) ? "flags" : "a";
	// stack is on page one: sp + 0x100
	rz_strbuf_setf(&op->esil, "%s,sp,0x100,+,=[1],sp,--=", reg);
}

static void _6502_analysis_esil_pop(RzAnalysisOp *op, ut8 data0) {
	// case 0x28: // plp
	// case 0x68: // pla
	char *reg = (data0 == 0x28) ? "flags" : "a";
	// stack is on page one: sp + 0x100
	rz_strbuf_setf(&op->esil, "sp,++=,sp,0x100,+,[1],%s,=", reg);

	if (data0 == 0x68) {
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
	}
}

static void _6502_analysis_esil_flags(RzAnalysisOp *op, ut8 data0) {
	int enabled = 0;
	char flag = 'u';
	switch (data0) {
	case 0x78: // sei
		enabled = 1;
		flag = 'I';
		break;
	case 0x58: // cli
		enabled = 0;
		flag = 'I';
		break;
	case 0x38: // sec
		enabled = 1;
		flag = 'C';
		break;
	case 0x18: // clc
		enabled = 0;
		flag = 'C';
		break;
	case 0xf8: // sed
		enabled = 1;
		flag = 'D';
		break;
	case 0xd8: // cld
		enabled = 0;
		flag = 'D';
		break;
	case 0xb8: // clv
		enabled = 0;
		flag = 'V';
		break;
	}
	rz_strbuf_setf(&op->esil, "%d,%c,=", enabled, flag);
}

static char *_6502_op_mnemonic(snes_op_t *op) {
	if (!op->name) {
		return NULL;
	}
	const char *end = strchr(op->name, ' ');
	if (!end) {
		return rz_str_dup(op->name);
	}
	return rz_str_ndup(op->name, end - op->name);
}

static int _6502_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	char addrbuf[64];
	const int buffsize = sizeof(addrbuf) - 1;
	if (len < 1) {
		return -1;
	}

	snes_op_t *sop = &snes_op[data[0]];

	op->size = snes_op_get_size(1, 1, sop); // snes-arch is similar to nes/6502
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->id = data[0];
	op->mnemonic = (mask & RZ_ANALYSIS_OP_MASK_DISASM) ? _6502_op_mnemonic(sop) : NULL;
	rz_strbuf_init(&op->esil);
	_6502ILAddr il_addr = { 0 };
	_6502ILAddr *il_addr_ptr = (mask & RZ_ANALYSIS_OP_MASK_IL) ? &il_addr : NULL;
	_6502State *cfg_state = (_6502State *)analysis->plugin_data;

	switch (data[0]) {
	// SLO
	case 0x07: // slo $ff
		op->type = RZ_ANALYSIS_OP_TYPE_SHL | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 5;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1]);
			op->il_op = _6502_il_op_slo(&addr);
		}
		break;
	case 0x17: // slo $ff,x
		op->type = RZ_ANALYSIS_OP_TYPE_SHL | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_zero_page_reg(&addr, data[1], "x");
			op->il_op = _6502_il_op_slo(&addr);
		}
		break;
	case 0x03: // slo ($ff,x)
		op->type = RZ_ANALYSIS_OP_TYPE_SHL | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_x(&addr, data[1]);
			op->il_op = _6502_il_op_slo(&addr);
		}
		break;
	case 0x13: // slo ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_SHL | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_y(&addr, data[1]);
			op->il_op = _6502_il_op_slo(&addr);
		}
		break;
	case 0x0f: // slo $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_SHL | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 6;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1] | data[2] << 8);
			op->il_op = _6502_il_op_slo(&addr);
		}
		break;
	case 0x1f: // slo $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_SHL | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "x");
			op->il_op = _6502_il_op_slo(&addr);
		}
		break;
	case 0x1b: // slo $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_SHL | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_slo(&addr);
		}
		break;
		// RLA
	case 0x27: // rla $ff
		op->type = RZ_ANALYSIS_OP_TYPE_ROL | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 5;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1]);
			op->il_op = _6502_il_op_rla(&addr);
		}
		break;
	case 0x37: // rla $ff,x
		op->type = RZ_ANALYSIS_OP_TYPE_ROL | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_zero_page_reg(&addr, data[1], "x");
			op->il_op = _6502_il_op_rla(&addr);
		}
		break;
	case 0x23: // rla ($ff,x)
		op->type = RZ_ANALYSIS_OP_TYPE_ROL | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_x(&addr, data[1]);
			op->il_op = _6502_il_op_rla(&addr);
		}
		break;
	case 0x33: // rla ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_ROL | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_y(&addr, data[1]);
			op->il_op = _6502_il_op_rla(&addr);
		}
		break;
	case 0x2f: // rla $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_ROL | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 6;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1] | data[2] << 8);
			op->il_op = _6502_il_op_rla(&addr);
		}
		break;
	case 0x3b: // rla $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_ROL | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_rla(&addr);
		}
		break;
	case 0x3f: // rla $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_ROL | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "x");
			op->il_op = _6502_il_op_rla(&addr);
		}
		break;

	// SRE
	case 0x47: // sre $ff
		op->type = RZ_ANALYSIS_OP_TYPE_SHR | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 5;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1]);
			op->il_op = _6502_il_op_sre(&addr);
		}
		break;
	case 0x57: // sre $ff,x
		op->type = RZ_ANALYSIS_OP_TYPE_SHR | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_zero_page_reg(&addr, data[1], "x");
			op->il_op = _6502_il_op_sre(&addr);
		}
		break;
	case 0x43: // sre ($ff,x)
		op->type = RZ_ANALYSIS_OP_TYPE_SHR | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_x(&addr, data[1]);
			op->il_op = _6502_il_op_sre(&addr);
		}
		break;
	case 0x53: // sre ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_SHR | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_y(&addr, data[1]);
			op->il_op = _6502_il_op_sre(&addr);
		}
		break;
	case 0x4f: // sre $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_SHR | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 6;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1] | data[2] << 8);
			op->il_op = _6502_il_op_sre(&addr);
		}
		break;
	case 0x5b: // sre $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_SHR | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_sre(&addr);
		}
		break;
	case 0x5f: // sre $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_SHR | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "x");
			op->il_op = _6502_il_op_sre(&addr);
		}
		break;

	// RRA
	case 0x67: // rra $ff
		op->type = RZ_ANALYSIS_OP_TYPE_ROR | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 5;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1]);
			op->il_op = _6502_il_op_rra(&addr);
		}
		break;
	case 0x77: // rra $ff,x
		op->type = RZ_ANALYSIS_OP_TYPE_ROR | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_zero_page_reg(&addr, data[1], "x");
			op->il_op = _6502_il_op_rra(&addr);
		}
		break;
	case 0x63: // rra ($ff,x)
		op->type = RZ_ANALYSIS_OP_TYPE_ROR | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_x(&addr, data[1]);
			op->il_op = _6502_il_op_rra(&addr);
		}
		break;
	case 0x73: // rra ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_ROR | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_y(&addr, data[1]);
			op->il_op = _6502_il_op_rra(&addr);
		}
		break;
	case 0x6f: // rra $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_ROR | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 6;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1] | data[2] << 8);
			op->il_op = _6502_il_op_rra(&addr);
		}
		break;
	case 0x7f: // rra $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_ROR | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "x");
			op->il_op = _6502_il_op_rra(&addr);
		}
		break;
	case 0x7b: // rra $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_ROR | RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_rra(&addr);
		}
		break;

	// SAX
	case 0x87: // sax $ff
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 3;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1]);
			op->il_op = _6502_il_op_sax(&addr);
		}
		break;
	case 0x97: // sax $ff,y
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 4;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_zero_page_reg(&addr, data[1], "y");
			op->il_op = _6502_il_op_sax(&addr);
		}
		break;
	case 0x83: // sax ($ff,x)
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_x(&addr, data[1]);
			op->il_op = _6502_il_op_sax(&addr);
		}
		break;
	case 0x8f: // sax $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 4;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1] | data[2] << 8);
			op->il_op = _6502_il_op_sax(&addr);
		}
		break;

	// LAX
	case 0xa7: // lax $ff
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->cycles = 3;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1]);
			op->il_op = _6502_il_op_lax(&addr);
		}
		break;
	case 0xb7: // lax $ff,y
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->cycles = 4;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_zero_page_reg(&addr, data[1], "y");
			op->il_op = _6502_il_op_lax(&addr);
		}
		break;
	case 0xa3: // lax ($ff,x)
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->cycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_x(&addr, data[1]);
			op->il_op = _6502_il_op_lax(&addr);
		}
		break;
	case 0xb3: // lax ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->cycles = 5;
		op->failcycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_y(&addr, data[1]);
			op->il_op = _6502_il_op_lax(&addr);
		}
		break;
	case 0xaf: // lax $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->cycles = 4;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1] | data[2] << 8);
			op->il_op = _6502_il_op_lax(&addr);
		}
		break;
	case 0xbf: // lax $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->cycles = 4;
		op->failcycles = 5;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_lax(&addr);
		}
		break;
	case 0xab: // lax #$ff
		op->type = RZ_ANALYSIS_OP_TYPE_AND | RZ_ANALYSIS_OP_TYPE_OR;
		op->cycles = 2;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			ut8 magic = 0xee;
			_6502ILAddr addr;
			_6502_il_immediate(&addr, data[1]);
			if (cfg_state && cfg_state->cfg) {
				magic = (ut8)rz_config_get_i(cfg_state->cfg, "plugins.6502.magic");
			}
			op->il_op = _6502_il_op_laximm(&addr, magic);
		}
		break;

	// DCP
	case 0xc7: // dcp $ff
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 5;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1]);
			op->il_op = _6502_il_op_dcp(&addr);
		}
		break;
	case 0xd7: // dcp $ff,x
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_zero_page_reg(&addr, data[1], "x");
			op->il_op = _6502_il_op_dcp(&addr);
		}
		break;
	case 0xc3: // dcp ($ff,x)
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_x(&addr, data[1]);
			op->il_op = _6502_il_op_dcp(&addr);
		}
		break;
	case 0xd3: // dcp ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_y(&addr, data[1]);
			op->il_op = _6502_il_op_dcp(&addr);
		}
		break;
	case 0xcf: // dcp $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 6;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1] | data[2] << 8);
			op->il_op = _6502_il_op_dcp(&addr);
		}
		break;
	case 0xdf: // dcp $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "x");
			op->il_op = _6502_il_op_dcp(&addr);
		}
		break;
	case 0xdb: // dcp $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_dcp(&addr);
		}
		break;

	// ISC
	case 0xe7: // isc $ff
		op->type = RZ_ANALYSIS_OP_TYPE_STORE | RZ_ANALYSIS_OP_TYPE_SUB;
		op->cycles = 5;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1]);
			op->il_op = _6502_il_op_isc(&addr);
		}
		break;
	case 0xf7: // isc $ff,x
		op->type = RZ_ANALYSIS_OP_TYPE_STORE | RZ_ANALYSIS_OP_TYPE_SUB;
		op->cycles = 6;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_zero_page_reg(&addr, data[1], "x");
			op->il_op = _6502_il_op_isc(&addr);
		}
		break;
	case 0xe3: // isc ($ff,x)
		op->type = RZ_ANALYSIS_OP_TYPE_STORE | RZ_ANALYSIS_OP_TYPE_SUB;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_x(&addr, data[1]);
			op->il_op = _6502_il_op_isc(&addr);
		}
		break;
	case 0xf3: // isc ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_STORE | RZ_ANALYSIS_OP_TYPE_SUB;
		op->cycles = 8;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_y(&addr, data[1]);
			op->il_op = _6502_il_op_isc(&addr);
		}
		break;
	case 0xef: // isc $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_STORE | RZ_ANALYSIS_OP_TYPE_SUB;
		op->cycles = 6;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_absolute(&addr, data[1] | data[2] << 8);
			op->il_op = _6502_il_op_isc(&addr);
		}
		break;
	case 0xff: // isc $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_STORE | RZ_ANALYSIS_OP_TYPE_SUB;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1], "x");
			op->il_op = _6502_il_op_isc(&addr);
		}
		break;
	case 0xfb: // isc $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_STORE | RZ_ANALYSIS_OP_TYPE_SUB;
		op->cycles = 7;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1], "y");
			op->il_op = _6502_il_op_isc(&addr);
		}
		break;
	// ANC
	case 0x0b: // anc #$ff
	case 0x2b: // anc #$ff
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		op->cycles = 2;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_immediate(&addr, data[1]);
			op->il_op = _6502_il_op_anc(&addr);
		}
		break;
	// ALR
	case 0x4b: // alr #$ff
		op->type = RZ_ANALYSIS_OP_TYPE_AND | RZ_ANALYSIS_OP_TYPE_SHR;
		op->cycles = 2;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_immediate(&addr, data[1]);
			op->il_op = _6502_il_op_alr(&addr);
		}
		break;
	// ARR
	case 0x6b: // arr #$ff
		op->type = RZ_ANALYSIS_OP_TYPE_AND | RZ_ANALYSIS_OP_TYPE_ROR;
		op->cycles = 2;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_immediate(&addr, data[1]);
			op->il_op = _6502_il_op_arr(&addr);
		}
		break;
	// SBX
	case 0xcb: // sbx #$ff
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 2;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_immediate(&addr, data[1]);
			op->il_op = _6502_il_op_sbx(&addr);
		}
		break;
	// LAS
	case 0xbb: // las $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_CMP | RZ_ANALYSIS_OP_TYPE_STORE;
		op->cycles = 4;
		op->failcycles = 5;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_las(&addr);
		}
		break;
	// JAM
	case 0x02:
	case 0x12:
	case 0x22:
	case 0x32:
	case 0x42:
	case 0x52:
	case 0x62:
	case 0x72:
	case 0x92:
	case 0xb2:
	case 0xd2:
	case 0xf2:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		op->size = 1;
		op->eob = true;
		// data = NEG(0);
		// addrbuf = NEG(0);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			il_addr_ptr->kind = _6502_ADDR_KIND_ADDR;
			op->il_op = _6502_il_op_jam(il_addr_ptr);
		}
		break;
	// SHA
	case 0x93: // sha ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->size = 2;
		op->cycles = 6;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_indirect_y(&addr, data[1]);
			op->il_op = _6502_il_op_sha(&addr);
		}
		break;
	case 0x9f: // sha $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->size = 3;
		op->cycles = 6;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			ut16 imm = (data[1] | data[2] << 8);
			_6502_il_addr_reg(&addr, imm, "y");
			op->il_op = _6502_il_op_sha(&addr);
		}
		break;
	// SHX
	case 0x9e: // shx $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->size = 3;
		op->cycles = 5;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_shx(&addr);
		}
		break;
	// SHY
	case 0x9c: // shy $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->size = 3;
		op->cycles = 5;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "x");
			op->il_op = _6502_il_op_shy(&addr);
		}
		break;
	// TAS
	case 0x9b: // tas $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->size = 3;
		op->cycles = 5;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_addr_reg(&addr, data[1] | data[2] << 8, "y");
			op->il_op = _6502_il_op_tas(&addr);
		}
		break;
	// ANE
	case 0x8b: // ane #$ff
		op->type = RZ_ANALYSIS_OP_TYPE_AND | RZ_ANALYSIS_OP_TYPE_OR;
		op->size = 2;
		op->cycles = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			ut8 magic = 0xee;
			_6502ILAddr addr;
			_6502_il_immediate(&addr, data[1]);
			if (cfg_state && cfg_state->cfg) {
				magic = (ut8)rz_config_get_i(cfg_state->cfg, "plugins.6502.magic");
			}
			op->il_op = _6502_il_op_ane(&addr, magic);
		}
		break;

	// BRK
	case 0x00: // brk
		op->cycles = 7;
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		// override 65816 code which seems to be wrong: size is 1, but pc = pc + 2
		op->size = 1;
		// PC + 2 to Stack, P to Stack  B=1 D=0 I=1. "B" is not a flag. Only its bit is pushed on the stack
		// PC was already incremented by one at this point. Needs to incremented once more
		// New PC is Interrupt Vector: $fffe. (FIXME: Confirm this is valid for all 6502)
		rz_strbuf_set(&op->esil, ",1,I,=,0,D,=,flags,0x10,|,0x100,sp,+,=[1],pc,1,+,0xfe,sp,+,=[2],3,sp,-=,0xfffe,[2],pc,=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_brk((ut16)addr);
		}
		break;

	// FLAGS
	case 0x78: // sei
	case 0x58: // cli
	case 0x38: // sec
	case 0x18: // clc
	case 0xf8: // sed
	case 0xd8: // cld
	case 0xb8: // clv
		op->cycles = 2;
		// FIXME: what opcode for this?
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		_6502_analysis_esil_flags(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_flag(data[0]);
		}
		break;
	// BIT
	case 0x24: // bit $ff
	case 0x2c: // bit $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		_6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, NULL, il_addr_ptr);
		rz_strbuf_setf(&op->esil, "%s,[1],0x80,&,!,!,N,=,%s,[1],0x40,&,!,!,V,=,a,%s,[1],&,0xff,&,!,Z,=", addrbuf, addrbuf, addrbuf);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_bit(il_addr_ptr);
		}
		break;
	// ADC
	case 0x69: // adc #$ff
	case 0x65: // adc $ff
	case 0x75: // adc $ff,x
	case 0x6d: // adc $ffff
	case 0x7d: // adc $ffff,x
	case 0x79: // adc $ffff,y
	case 0x61: // adc ($ff,x)
	case 0x71: // adc ($ff,y)
		// FIXME: update V
		// FIXME: support BCD mode
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0x69) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,a,+=,7,$c,C,a,+=,7,$c,|,C,:=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],a,+=,7,$c,C,a,+=,7,$c,|,C,:=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		// fix Z
		rz_strbuf_append(&op->esil, ",a,a,=,$z,Z,:=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_adc(il_addr_ptr);
		}
		break;
	// SBC
	case 0xe9: // sbc #$ff
	case 0xe5: // sbc $ff
	case 0xf5: // sbc $ff,x
	case 0xed: // sbc $ffff
	case 0xfd: // sbc $ffff,x
	case 0xf9: // sbc $ffff,y
	case 0xe1: // sbc ($ff,x)
	case 0xf1: // sbc ($ff,y)
		// FIXME: update V
		// FIXME: support BCD mode
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0xe9) { // immediate mode
			rz_strbuf_setf(&op->esil, "C,!,%s,+,a,-=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "C,!,%s,[1],+,a,-=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_BNZ);
		// fix Z and revert C
		rz_strbuf_append(&op->esil, ",a,a,=,$z,Z,:=,C,!=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_sbc(il_addr_ptr);
		}
		break;
	case 0xeb: // sbc #$ff ((sbc,nop) extended opcode)
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			_6502ILAddr addr;
			_6502_il_immediate(&addr, data[1]);
			op->il_op = _6502_il_op_sbc(&addr);
		}
		break;
	// ORA
	case 0x09: // ora #$ff
	case 0x05: // ora $ff
	case 0x15: // ora $ff,x
	case 0x0d: // ora $ffff
	case 0x1d: // ora $ffff,x
	case 0x19: // ora $ffff,y
	case 0x01: // ora ($ff,x)
	case 0x11: { // ora ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		bool is_immediate = data[0] == 0x09;
		if (is_immediate) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,a,|=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],a,|=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_ora(il_addr_ptr);
		}
		break;
	}
	// AND
	case 0x29: // and #$ff
	case 0x25: // and $ff
	case 0x35: // and $ff,x
	case 0x2d: // and $ffff
	case 0x3d: // and $ffff,x
	case 0x39: // and $ffff,y
	case 0x21: // and ($ff,x)
	case 0x31: // and ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		bool is_immediate = data[0] == 0x29;
		if (is_immediate) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,a,&=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],a,&=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_and(il_addr_ptr);
		}
		break;
	// EOR
	case 0x49: // eor #$ff
	case 0x45: // eor $ff
	case 0x55: // eor $ff,x
	case 0x4d: // eor $ffff
	case 0x5d: // eor $ffff,x
	case 0x59: // eor $ffff,y
	case 0x41: // eor ($ff,x)
	case 0x51: // eor ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0x49) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,a,^=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],a,^=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_eor(il_addr_ptr);
		}
		break;
	// ASL
	case 0x0a: // asl a
	case 0x06: // asl $ff
	case 0x16: // asl $ff,x
	case 0x0e: // asl $ffff
	case 0x1e: // asl $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		if (data[0] == 0x0a) {
			rz_strbuf_set(&op->esil, "1,a,<<=,7,$c,C,:=,a,a,=");
		} else {
			rz_strbuf_setf(&op->esil, "1,%s,[1],<<,%s,=[1],7,$c,C,:=", addrbuf, addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_asl(il_addr_ptr);
		}
		break;
	// LSR
	case 0x4a: // lsr a
	case 0x46: // lsr $ff
	case 0x56: // lsr $ff,x
	case 0x4e: // lsr $ffff
	case 0x5e: // lsr $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		if (data[0] == 0x4a) {
			rz_strbuf_set(&op->esil, "1,a,&,C,=,1,a,>>=");
		} else {
			rz_strbuf_setf(&op->esil, "1,%s,[1],&,C,=,1,%s,[1],>>,%s,=[1]", addrbuf, addrbuf, addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_lsr(il_addr_ptr);
		}
		break;
	// ROL
	case 0x2a: // rol a
	case 0x26: // rol $ff
	case 0x36: // rol $ff,x
	case 0x2e: // rol $ffff
	case 0x3e: // rol $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_ROL;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		if (data[0] == 0x2a) {
			rz_strbuf_set(&op->esil, "1,a,<<,C,|,a,=,7,$c,C,:=,a,a,=");
		} else {
			rz_strbuf_setf(&op->esil, "1,%s,[1],<<,C,|,%s,=[1],7,$c,C,:=", addrbuf, addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_rol(il_addr_ptr);
		}
		break;
	// ROR
	case 0x6a: // ror a
	case 0x66: // ror $ff
	case 0x76: // ror $ff,x
	case 0x6e: // ror $ffff
	case 0x7e: // ror $ffff,x
		// uses N as temporary to hold C value. but in fact,
		// it is not temporary since in all ROR ops, N will have the value of C
		op->type = RZ_ANALYSIS_OP_TYPE_ROR;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		if (data[0] == 0x6a) {
			rz_strbuf_set(&op->esil, "C,N,=,1,a,&,C,=,1,a,>>,7,N,<<,|,a,=");
		} else {
			rz_strbuf_setf(&op->esil, "C,N,=,1,%s,[1],&,C,=,1,%s,[1],>>,7,N,<<,|,%s,=[1]", addrbuf, addrbuf, addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_ror(il_addr_ptr);
		}
		break;
	// INC
	case 0xe6: // inc $ff
	case 0xf6: // inc $ff,x
	case 0xee: // inc $ffff
	case 0xfe: // inc $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		rz_strbuf_setf(&op->esil, "%s,++=[1]", addrbuf);
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_inc(il_addr_ptr, true);
		}
		break;
	// DEC
	case 0xc6: // dec $ff
	case 0xd6: // dec $ff,x
	case 0xce: // dec $ffff
	case 0xde: // dec $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		rz_strbuf_setf(&op->esil, "%s,--=[1]", addrbuf);
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_inc(il_addr_ptr, false);
		}
		break;
	// INX, INY
	case 0xe8: // inx
	case 0xc8: // iny
		op->cycles = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_inc_reg(op, data[0], "+");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_inc_reg(data[0] == 0xe8 ? "x" : "y", true);
		}
		break;
	// DEX, DEY
	case 0xca: // dex
	case 0x88: // dey
		op->cycles = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_inc_reg(op, data[0], "-");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_inc_reg(data[0] == 0xca ? "x" : "y", false);
		}
		break;
	// CMP
	case 0xc9: // cmp #$ff
	case 0xc5: // cmp $ff
	case 0xd5: // cmp $ff,x
	case 0xcd: // cmp $ffff
	case 0xdd: // cmp $ffff,x
	case 0xd9: // cmp $ffff,y
	case 0xc1: // cmp ($ff,x)
	case 0xd1: // cmp ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0xc9) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,a,==", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],a,==", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_BNZ);
		// invert C, since C=1 when A-M >= 0
		rz_strbuf_append(&op->esil, ",C,!,C,=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_cmp("a", il_addr_ptr);
		}
		break;
	// CPX
	case 0xe0: // cpx #$ff
	case 0xe4: // cpx $ff
	case 0xec: // cpx $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		_6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, NULL, il_addr_ptr);
		if (data[0] == 0xe0) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,x,==", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],x,==", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_BNZ);
		// invert C, since C=1 when A-M >= 0
		rz_strbuf_append(&op->esil, ",C,!,C,=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_cmp("x", il_addr_ptr);
		}
		break;
	// CPY
	case 0xc0: // cpy #$ff
	case 0xc4: // cpy $ff
	case 0xcc: // cpy $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		_6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, NULL, il_addr_ptr);
		if (data[0] == 0xc0) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,y,==", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],y,==", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_BNZ);
		// invert C, since C=1 when A-M >= 0
		rz_strbuf_append(&op->esil, ",C,!,C,=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_cmp("y", il_addr_ptr);
		}
		break;
	// BRANCHES
	case 0x10: // bpl $ffff
	case 0x30: // bmi $ffff
	case 0x50: // bvc $ffff
	case 0x70: // bvs $ffff
	case 0x90: // bcc $ffff
	case 0xb0: // bcs $ffff
	case 0xd0: // bne $ffff
	case 0xf0: // beq $ffff
		op->cycles = 3;
		op->failcycles = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		if (len > 1) {
			if (data[1] <= 127) {
				op->jump = addr + data[1] + op->size;
			} else {
				op->jump = addr - (256 - data[1]) + op->size;
			}
		} else {
			op->jump = addr;
		}
		op->fail = addr + op->size;
		// FIXME: add a type of conditional
		// op->cond = RZ_TYPE_COND_LE;
		_6502_analysis_esil_ccall(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_branch(data[0], op->jump);
		}
		break;
	// JSR
	case 0x20: // jsr $ffff
		op->cycles = 6;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (len > 2) ? data[1] | data[2] << 8 : 0;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 2;
		// JSR pushes the address-1 of the next operation on to the stack before transferring program
		// control to the following address
		// stack is on page one and sp is an 8-bit reg: operations must be done like: sp + 0x100
		rz_strbuf_setf(&op->esil, "1,pc,-,0xff,sp,+,=[2],0x%04" PFMT64x ",pc,=,2,sp,-=", op->jump);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_jsr(op->jump, addr);
		}
		break;
	// JMP
	case 0x4c: // jmp $ffff
		op->cycles = 3;
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = (len > 2) ? data[1] | data[2] << 8 : 0;
		rz_strbuf_setf(&op->esil, "0x%04" PFMT64x ",pc,=", op->jump);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_jmp(op->jump, false);
		}
		break;
	case 0x6c: { // jmp ($ffff)
		op->cycles = 5;
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		ut16 imm = len > 2 ? data[1] | data[2] << 8 : 0;
		rz_strbuf_setf(&op->esil, "0x%04x,[2],pc,=", imm);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_jmp(imm, true);
		}
		break;
	}
	// RTS
	case 0x60: // rts
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->cycles = 6;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -2;
		// Operation:  PC from Stack, PC + 1 -> PC
		// stack is on page one and sp is an 8-bit reg: operations must be done like: sp + 0x100
		rz_strbuf_set(&op->esil, "0x101,sp,+,[2],pc,=,pc,++=,2,sp,+=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_rts();
		}
		break;
	// RTI
	case 0x40: // rti
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->cycles = 6;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -3;
		// Operation: P from Stack, PC from Stack
		// stack is on page one and sp is an 8-bit reg: operations must be done like: sp + 0x100
		rz_strbuf_set(&op->esil, "0x101,sp,+,[1],flags,=,0x102,sp,+,[2],pc,=,3,sp,+=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_rti();
		}
		break;
	// NOP
	case 0xea: // nop
	// nop (extended opcode)
	case 0x1a:
	case 0x3a:
	case 0x5a:
	case 0x7a:
	case 0xda:
	case 0xfa:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->cycles = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = rz_il_op_new_nop();
		}
		break;
	// nop #$ff (extended opcode)
	case 0x80:
	case 0x82:
	case 0xc2:
	case 0xe2:
	case 0x89:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->cycles = 2;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = rz_il_op_new_nop();
		}
		break;
	// nop $ff (extended opcode)
	case 0x04:
	case 0x44:
	case 0x64:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, NULL, buffsize, il_addr_ptr);
		op->cycles = 3;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = rz_il_op_new_nopzp(il_addr_ptr);
		}
		break;
	case 0x0c: // nop $ffff (extended opcode)
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->cycles = 4;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = rz_il_op_new_nop();
		}
		break;
	case 0x1c: // nop $ffff,x (extended opcode)
	case 0x3c:
	case 0x5c:
	case 0x7c:
	case 0xdc:
	case 0xfc:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		op->cycles = 4;
		op->failcycles = 5;
		op->size = 3;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = rz_il_op_new_nop();
		}
		break;
	case 0x14: // $ff,x
	case 0x34: // $ff,x
	case 0x54: // $ff,x
	case 0x74: // $ff,x
	case 0xd4: // $ff,x
	case 0xf4: // $ff,x
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, NULL, buffsize, il_addr_ptr);
		op->cycles = 4;
		op->size = 2;
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = rz_il_op_new_nopzp(il_addr_ptr);
		}
		break;
	// LDA
	case 0xa9: // lda #$ff
	case 0xa5: // lda $ff
	case 0xb5: // lda $ff,x
	case 0xad: // lda $ffff
	case 0xbd: // lda $ffff,x
	case 0xb9: // lda $ffff,y
	case 0xa1: // lda ($ff,x)
	case 0xb1: // lda ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0xa9) {
			rz_strbuf_setf(&op->esil, "%s,a,=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],a,=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_ld("a", il_addr_ptr);
		}
		break;
	// LDX
	case 0xa2: // ldx #$ff
	case 0xa6: // ldx $ff
	case 0xb6: // ldx $ff,y
	case 0xae: // ldx $ffff
	case 0xbe: // ldx $ffff,y
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "y", il_addr_ptr);
		if (data[0] == 0xa2) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,x,=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],x,=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_ld("x", il_addr_ptr);
		}
		break;
	// LDY
	case 0xa0: // ldy #$ff
	case 0xa4: // ldy $ff
	case 0xb4: // ldy $ff,x
	case 0xac: // ldy $ffff
	case 0xbc: // ldy $ffff,x
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		_6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		if (data[0] == 0xa0) { // immediate mode
			rz_strbuf_setf(&op->esil, "%s,y,=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],y,=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_ld("y", il_addr_ptr);
		}
		break;
	// STA
	case 0x85: // sta $ff
	case 0x95: // sta $ff,x
	case 0x8d: // sta $ffff
	case 0x9d: // sta $ffff,x
	case 0x99: // sta $ffff,y
	case 0x81: // sta ($ff,x)
	case 0x91: // sta ($ff),y
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		rz_strbuf_setf(&op->esil, "a,%s,=[1]", addrbuf);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_st("a", il_addr_ptr);
		}
		break;
	// STX
	case 0x86: // stx $ff
	case 0x96: // stx $ff,y
	case 0x8e: // stx $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "y", il_addr_ptr);
		rz_strbuf_setf(&op->esil, "x,%s,=[1]", addrbuf);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_st("x", il_addr_ptr);
		}
		break;
	// STY
	case 0x84: // sty $ff
	case 0x94: // sty $ff,x
	case 0x8c: // sty $ffff
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		rz_strbuf_setf(&op->esil, "y,%s,=[1]", addrbuf);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_st("y", il_addr_ptr);
		}
		break;
	// PHP/PHA
	case 0x08: // php
	case 0x48: // pha
		op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		op->cycles = 3;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 1;
		_6502_analysis_esil_push(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			if (data[0] == 0x08) {
				op->il_op = _6502_il_op_php();
			} else {
				op->il_op = _6502_il_op_pha();
			}
		}
		break;
	// PLP,PLA
	case 0x28: // plp
	case 0x68: // plp
		op->type = RZ_ANALYSIS_OP_TYPE_POP;
		op->cycles = 4;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -1;
		_6502_analysis_esil_pop(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			if (data[0] == 0x28) {
				op->il_op = _6502_il_op_plp();
			} else {
				op->il_op = _6502_il_op_pla();
			}
		}
		break;
	// TAX,TYA,...
	case 0xaa: // tax
	case 0x8a: // txa
	case 0xa8: // tay
	case 0x98: // tya
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->cycles = 2;
		_6502_analysis_esil_mov(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_transfer(
				data[0] == 0xaa ? "x" : (data[0] == 0xa8 ? "y" : "a"),
				data[0] == 0x8a ? "x" : (data[0] == 0x98 ? "y" : "a"),
				true);
		}
		break;
	case 0x9a: // txs
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->cycles = 2;
		op->stackop = RZ_ANALYSIS_STACK_SET;
		// FIXME: should I get register X a place it here?
		// op->stackptr = get_register_x();
		_6502_analysis_esil_mov(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_transfer("sp", "x", false);
		}
		break;
	case 0xba: // tsx
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->cycles = 2;
		op->stackop = RZ_ANALYSIS_STACK_GET;
		_6502_analysis_esil_mov(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_transfer("x", "sp", true);
		}
		break;
	}
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	y\n"
		"=A1	y\n"
		"gpr	a	.8	0	0\n"
		"gpr	x	.8	1	0\n"
		"gpr	y	.8	2	0\n"

		"gpr	flags	.8	3	0\n"
		"gpr	C	.1	.24	0\n"
		"gpr	Z	.1	.25	0\n"
		"gpr	I	.1	.26	0\n"
		"gpr	D	.1	.27	0\n"
		// bit 4 (.28) is NOT a real flag.
		// "gpr	B	.1	.28	0\n"
		// bit 5 (.29) is not used
		"gpr	V	.1	.30	0\n"
		"gpr	N	.1	.31	0\n"
		"gpr	sp	.8	4	0\n"
		"gpr	pc	.16	5	0\n";
	return rz_str_dup(p);
}

static int esil_6502_init(RzAnalysisEsil *esil) {
	if (esil->analysis && esil->analysis->reg) { // initial values
		rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "pc", -1), 0x0000);
		rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "sp", -1), 0xff);
		rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "a", -1), 0x00);
		rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "x", -1), 0x00);
		rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "y", -1), 0x00);
		rz_reg_set_value(esil->analysis->reg, rz_reg_get(esil->analysis->reg, "flags", -1), 0x00);
	}
	return true;
}

static int esil_6502_fini(RzAnalysisEsil *esil) {
	return true;
}

static int address_bits(RzAnalysis *analysis, int bits) {
	return 16;
}

static RzAnalysisILConfig *_6502_il_config(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	if (!analysis->plugin_data && analysis->core) {
		RzAsm *rasm = rz_analysis_to_rz_asm(analysis);
		if (rasm && rasm->plugin_data) {
			analysis->plugin_data = rasm->plugin_data;
		}
	}
	return rz_analysis_il_config_new(16, false, 16);
}

RzAnalysisPlugin rz_analysis_plugin_6502 = {
	.name = "6502",
	.desc = "6502/NES analysis plugin",
	.license = "LGPL3",
	.arch = "6502",
	.bits = 8,
	.address_bits = address_bits,
	.op = &_6502_op,
	.get_reg_profile = &get_reg_profile,
	.esil = true,
	.esil_init = esil_6502_init,
	.esil_fini = esil_6502_fini,
	.il_config = _6502_il_config

};