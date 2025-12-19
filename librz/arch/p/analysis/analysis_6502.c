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
		// FIXME: Add 1 if page boundary is crossed.
		op->cycles = 4;
		imm = (len > 2) ? ((ut16)data[1] | (ut16)data[2] << 8) : 0;
		if (esiladdr_out) {
			snprintf(esiladdr_out, esiladdr_size, "x,0x%04x,+", (unsigned int)imm);
		}
		if (il_out) {
			_6502_il_addr_reg(il_out, imm, "x");
		}
		break;
	case 0x19: // op $ffff,y
		// FIXME: Add 1 if page boundary is crossed.
		op->cycles = 4;
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
		// FIXME: Add 1 if page boundary is crossed.
		op->cycles = 5;
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
	switch (data[0]) {
	/* KIL / JAM - Instructions that halt the CPU */
	case 0x02: case 0x12: case 0x22: case 0x32:
	case 0x42: case 0x52: case 0x62: case 0x72:
	case 0x92: case 0xb2: case 0xd2: case 0xf2:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->size = 1;
		break;

	/* SLO (Shift Left + ORA) */
	case 0x03: case 0x07: case 0x0f: case 0x13:
	case 0x17: case 0x1b: case 0x1f:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		break;

	/* RLA (Rotate Left + AND) */
	case 0x23: case 0x27: case 0x2f: case 0x33:
	case 0x37: case 0x3b: case 0x3f:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		break;

	/* SAX (Store A AND X) */
	case 0x83: case 0x87: case 0x8f: case 0x97:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		break;

	/* LAX (Load Accumulator and X) */
	case 0xa3: case 0xa7: case 0xaf: case 0xb3:
	case 0xb7: case 0xbf:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		break;

	/* DCP (Decrement + Compare) */
	case 0xc3: case 0xc7: case 0xcf: case 0xd3:
	case 0xd7: case 0xdb: case 0xdf:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		break;

	/* Illegal NOPs - Fixed logic per mentor feedback */
	case 0x1a: case 0x3a: case 0x5a: case 0x7a: case 0xda: case 0xfa:
	case 0x80: case 0x82: case 0x89: case 0xc2: case 0xe2:
	case 0x04: case 0x44: case 0x64: case 0x14: case 0x34:
	case 0x54: case 0x74: case 0xd4: case 0xf4:
	case 0x0c: case 0x1c: case 0x3c: case 0x5c: case 0x7c:
	case 0xdc: case 0xfc:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		if (data[0] == 0x0c || data[0] == 0x1c || data[0] == 0x3c || 
		    data[0] == 0x5c || data[0] == 0x7c || data[0] == 0xdc || data[0] == 0xfc) {
			op->size = 3;
		} else if (data[0] == 0x1a || data[0] == 0x3a || data[0] == 0x5a ||
			   data[0] == 0x7a || data[0] == 0xda || data[0] == 0xfa) {
			op->size = 1;
		} else {
			op->size = 2;
		}
		break;

	// BRK
	case 0x00: // brk
		op->cycles = 7;
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->size = 1;
		rz_strbuf_set(&op->esil, ",1,I,=,0,D,=,flags,0x10,|,0x100,sp,+,=[1],pc,1,+,0xfe,sp,+,=[2],3,sp,-=,0xfffe,[2],pc,=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_brk((ut16)addr);
		}
		break;

	// FLAGS
	case 0x78: case 0x58: case 0x38: case 0x18:
	case 0xf8: case 0xd8: case 0xb8:
		op->cycles = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		_6502_analysis_esil_flags(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_flag(data[0]);
		}
		break;

	// BIT
	case 0x24: case 0x2c:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		_6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, NULL, il_addr_ptr);
		rz_strbuf_setf(&op->esil, "%s,[1],0x80,&,!,!,N,=,%s,[1],0x40,&,!,!,V,=,a,%s,[1],&,0xff,&,!,Z,=", addrbuf, addrbuf, addrbuf);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_bit(il_addr_ptr);
		}
		break;

	// ADC
	case 0x69: case 0x65: case 0x75: case 0x6d:
	case 0x7d: case 0x79: case 0x61: case 0x71:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0x69) {
			rz_strbuf_setf(&op->esil, "%s,a,+=,7,$c,C,a,+=,7,$c,|,C,:=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],a,+=,7,$c,C,a,+=,7,$c,|,C,:=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		rz_strbuf_append(&op->esil, ",a,a,=,$z,Z,:=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_adc(il_addr_ptr);
		}
		break;

	// SBC
	case 0xe9: case 0xe5: case 0xf5: case 0xed:
	case 0xfd: case 0xf9: case 0xe1: case 0xf1:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0xe9) {
			rz_strbuf_setf(&op->esil, "C,!,%s,+,a,-=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "C,!,%s,[1],+,a,-=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_BNZ);
		rz_strbuf_append(&op->esil, ",a,a,=,$z,Z,:=,C,!=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_sbc(il_addr_ptr);
		}
		break;

	// ORA
	case 0x09: case 0x05: case 0x15: case 0x0d:
	case 0x1d: case 0x19: case 0x01: case 0x11:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0x09) {
			rz_strbuf_setf(&op->esil, "%s,a,|=", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,[1],a,|=", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_ora(il_addr_ptr);
		}
		break;

	// AND
	case 0x29: case 0x25: case 0x35: case 0x2d:
	case 0x3d: case 0x39: case 0x21: case 0x31:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0x29) {
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
	case 0x49: case 0x45: case 0x55: case 0x4d:
	case 0x5d: case 0x59: case 0x41: case 0x51:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		if (data[0] == 0x49) {
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
	case 0x0a: case 0x06: case 0x16: case 0x0e: case 0x1e:
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
	case 0x4a: case 0x46: case 0x56: case 0x4e: case 0x5e:
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
	case 0x2a: case 0x26: case 0x36: case 0x2e: case 0x3e:
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
	case 0x6a: case 0x66: case 0x76: case 0x6e: case 0x7e:
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

	// INC/DEC Memory
	case 0xe6: case 0xf6: case 0xee: case 0xfe:
	case 0xc6: case 0xd6: case 0xce: case 0xde:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
		if ((data[0] & 0x20)) {
			rz_strbuf_setf(&op->esil, "%s,++=[1]", addrbuf);
		} else {
			rz_strbuf_setf(&op->esil, "%s,--=[1]", addrbuf);
		}
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_inc(il_addr_ptr, (data[0] & 0x20));
		}
		break;

	// INX, INY, DEX, DEY
	case 0xe8: case 0xc8: case 0xca: case 0x88:
		op->cycles = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		_6502_analysis_esil_inc_reg(op, data[0], (data[0] == 0xe8 || data[0] == 0xc8) ? "+" : "-");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			const char *r = (data[0] == 0xe8 || data[0] == 0xca) ? "x" : "y";
			op->il_op = _6502_il_op_inc_reg(r, (data[0] == 0xe8 || data[0] == 0xc8));
		}
		break;

	// CMP, CPX, CPY
	case 0xc9: case 0xc5: case 0xd5: case 0xcd: case 0xdd: case 0xd9: case 0xc1: case 0xd1:
	case 0xe0: case 0xe4: case 0xec:
	case 0xc0: case 0xc4: case 0xcc:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		const char *r = "a";
		if (data[0] >= 0xe0) {
			r = "x";
			_6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, NULL, il_addr_ptr);
		} else if (data[0] == 0xc0 || data[0] == 0xc4 || data[0] == 0xcc) {
			r = "y";
			_6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, NULL, il_addr_ptr);
		} else {
			_6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
		}
		bool imm_mode = (data[0] == 0xc9 || data[0] == 0xe0 || data[0] == 0xc0);
		rz_strbuf_setf(&op->esil, "%s,%s%s,=", addrbuf, imm_mode ? "" : "[1],", r);
		rz_strbuf_append(&op->esil, ",==");
		_6502_analysis_esil_update_flags(op, _6502_FLAGS_BNZ);
		rz_strbuf_append(&op->esil, ",C,!,C,=");
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_cmp(r, il_addr_ptr);
		}
		break;

	// BRANCHES
	case 0x10: case 0x30: case 0x50: case 0x70:
	case 0x90: case 0xb0: case 0xd0: case 0xf0:
		op->cycles = 2;
		op->failcycles = 3;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		if (len > 1) {
			op->jump = addr + (st8)data[1] + op->size;
		} else {
			op->jump = addr;
		}
		op->fail = addr + op->size;
		_6502_analysis_esil_ccall(op, data[0]);
		if (mask & RZ_ANALYSIS_OP_MASK_IL) {
			op->il_op = _6502_il_op_branch(data[0], op->jump);
		}
		break;

	// JSR, JMP
	case 0x20: case 0x4c: case 0x6c:
		op->jump = (len > 2) ? data[1] | data[2] << 8 : 0;
		if (data[0] == 0x20) {
			op->cycles = 6;
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = 2;
			rz_strbuf_setf(&op->esil, "1,pc,-,0xff,sp,+,=[2],0x%04" PFMT64x ",pc,=,2,sp,-=", op->jump);
			if (mask & RZ_ANALYSIS_OP_MASK_IL) op->il_op = _6502_il_op_jsr(op->jump, addr);
		} else {
			op->cycles = (data[0] == 46) ? 3 : 5;
			op->type = (data[0] == 46) ? RZ_ANALYSIS_OP_TYPE_JMP : RZ_ANALYSIS_OP_TYPE_UJMP;
			if (data[0] == 0x4c) rz_strbuf_setf(&op->esil, "0x%04" PFMT64x ",pc,=", op->jump);
			else rz_strbuf_setf(&op->esil, "0x%04x,[2],pc,=", (ut32)op->jump);
			if (mask & RZ_ANALYSIS_OP_MASK_IL) op->il_op = _6502_il_op_jmp((ut16)op->jump, (data[0] == 0x6c));
		}
		break;

	// RTS, RTI, NOP
	case 0x60: case 0x40: case 0xea:
		op->cycles = (data[0] == 0xea) ? 2 : 6;
		if (data[0] != 0xea) op->eob = true;
		op->type = (data[0] == 0xea) ? RZ_ANALYSIS_OP_TYPE_NOP : RZ_ANALYSIS_OP_TYPE_RET;
		if (data[0] == 0x60) {
			op->stackptr = -2;
			rz_strbuf_set(&op->esil, "0x101,sp,+,[2],pc,=,pc,++=,2,sp,+=");
			if (mask & RZ_ANALYSIS_OP_MASK_IL) op->il_op = _6502_il_op_rts();
		} else if (data[0] == 0x40) {
			op->stackptr = -3;
			rz_strbuf_set(&op->esil, "0x101,sp,+,[1],flags,=,0x102,sp,+,[2],pc,=,3,sp,+=");
			if (mask & RZ_ANALYSIS_OP_MASK_IL) op->il_op = _6502_il_op_rti();
		} else {
			if (mask & RZ_ANALYSIS_OP_MASK_IL) op->il_op = rz_il_op_new_nop();
		}
		break;

	// LDA, LDX, LDY, STA, STX, STY
	case 0xa9: case 0xa5: case 0xb5: case 0xad: case 0xbd: case 0xb9: case 0xa1: case 0xb1:
	case 0xa2: case 0xa6: case 0xb6: case 0xae: case 0xbe:
	case 0xa0: case 0xa4: case 0xb4: case 0xac: case 0xbc:
	case 0x85: case 0x95: case 0x8d: case 0x9d: case 0x99: case 0x81: case 0x91:
	case 0x86: case 0x96: case 0x8e:
	case 0x84: case 0x94: case 0x8c:
		{
			const char *r = (data[0] >= 0x84 && data[0] <= 0x96) || (data[0] >= 0xa0 && data[0] <= 0xbc) ? 
					((data[0] == 0xa2 || data[0] == 0xa6 || data[0] == 0xb6 || data[0] == 0xae || data[0] == 0xbe || data[0] == 0x86 || data[0] == 0x96 || data[0] == 0x8e) ? "x" : "y") : "a";
			op->type = (data[0] < 0xa0) ? RZ_ANALYSIS_OP_TYPE_STORE : RZ_ANALYSIS_OP_TYPE_LOAD;
			if (r[0] == 'y' || (data[0] >= 0x86 && data[0] <= 0x8e)) _6502_analysis_esil_get_addr_pattern2(op, data, len, addrbuf, buffsize, (r[0] == 'x' ? "y" : "x"), il_addr_ptr);
			else if (r[0] == 'x' && data[0] < 0x86) _6502_analysis_esil_get_addr_pattern3(op, data, len, addrbuf, buffsize, "x", il_addr_ptr);
			else _6502_analysis_esil_get_addr_pattern1(op, data, len, addrbuf, buffsize, il_addr_ptr);
			
			if (op->type == RZ_ANALYSIS_OP_TYPE_STORE) rz_strbuf_setf(&op->esil, "%s,%s,=[1]", r, addrbuf);
			else {
				bool imm = (data[0] == 0xa9 || data[0] == 0xa2 || data[0] == 0xa0);
				rz_strbuf_setf(&op->esil, "%s,%s%s,=", addrbuf, imm ? "" : "[1],", r);
				_6502_analysis_esil_update_flags(op, _6502_FLAGS_NZ);
			}
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				if (op->type == RZ_ANALYSIS_OP_TYPE_STORE) op->il_op = _6502_il_op_st(r, il_addr_ptr);
				else op->il_op = _6502_il_op_ld(r, il_addr_ptr);
			}
		}
		break;

	// PHP, PHA, PLP, PLA, TAX, TXA, TAY, TYA, TXS, TSX
	case 0x08: case 0x48: case 0x28: case 0x68:
	case 0xaa: case 0x8a: case 0xa8: case 0x98: case 0x9a: case 0xba:
		if (data[0] <= 0x68) {
			op->type = (data[0] == 0x08 || data[0] == 0x48) ? RZ_ANALYSIS_OP_TYPE_PUSH : RZ_ANALYSIS_OP_TYPE_POP;
			op->cycles = (op->type == RZ_ANALYSIS_OP_TYPE_PUSH) ? 3 : 4;
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = (op->type == RZ_ANALYSIS_OP_TYPE_PUSH) ? 1 : -1;
			if (op->type == RZ_ANALYSIS_OP_TYPE_PUSH) _6502_analysis_esil_push(op, data[0]);
			else _6502_analysis_esil_pop(op, data[0]);
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				if (data[0] == 0x08) op->il_op = _6502_il_op_php();
				else if (data[0] == 0x48) op->il_op = _6502_il_op_pha();
				else if (data[0] == 0x28) op->il_op = _6502_il_op_plp();
				else op->il_op = _6502_il_op_pla();
			}
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			op->cycles = 2;
			if (data[0] == 0x9a) op->stackop = RZ_ANALYSIS_STACK_SET;
			else if (data[0] == 0xba) op->stackop = RZ_ANALYSIS_STACK_GET;
			_6502_analysis_esil_mov(op, data[0]);
			if (mask & RZ_ANALYSIS_OP_MASK_IL) {
				const char *s = (data[0] == 0xaa || data[0] == 0xa8) ? "a" : ((data[0] == 0x8a || data[0] == 0x9a) ? "x" : (data[0] == 0x98 ? "y" : "sp"));
				const char *d = (data[0] == 0x8a || data[0] == 0x98) ? "a" : ((data[0] == 0xaa || data[0] == 0xba) ? "x" : (data[0] == 0xa8 ? "y" : "sp"));
				op->il_op = _6502_il_op_transfer(d, s, (data[0] != 0x9a));
			}
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

static RzAnalysisILConfig *il_config(RzAnalysis *analysis) {
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
	.il_config = il_config
};