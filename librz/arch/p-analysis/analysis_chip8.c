// SPDX-FileCopyrightText: 2017 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

static int chip8_anop(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	ut16 opcode = rz_read_be16(data);
	//	uint8_t x = (opcode >> 8) & 0x0F;
	//	uint8_t y = (opcode >> 4) & 0x0F;
	uint8_t nibble = opcode & 0x0F;
	uint16_t nnn = opcode & 0x0FFF;
	uint8_t kk = opcode & 0xFF;
	op->size = 2;
	op->addr = addr;
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	switch (opcode & 0xF000) {
	case 0x0000:
		if (opcode == 0x00EE) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		}
		break;
	case 0x1000:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = nnn;
		break;
	case 0x2000:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = nnn;
		break;
	case 0x3000:
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		op->jump = addr + op->size * 2;
		op->fail = addr + op->size;
		break;
	case 0x4000:
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		op->jump = addr + op->size * 2;
		op->fail = addr + op->size;
		break;
	case 0x5000:
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		op->jump = addr + op->size * 2;
		op->fail = addr + op->size;
		break;
	case 0x6000:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0x7000:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case 0x8000: {
		switch (nibble) {
		case 0x0:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case 0x1:
			op->type = RZ_ANALYSIS_OP_TYPE_OR;
			break;
		case 0x2:
			op->type = RZ_ANALYSIS_OP_TYPE_AND;
			break;
		case 0x3:
			op->type = RZ_ANALYSIS_OP_TYPE_XOR;
			break;
		case 0x4:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case 0x5:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case 0x6:
			op->type = RZ_ANALYSIS_OP_TYPE_SHR;
			break;
		case 0x7:
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
			break;
		case 0xE:
			op->type = RZ_ANALYSIS_OP_TYPE_SHL;
			break;
		}
	} break;
	case 0x9000:
		if (nibble == 0) {
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
			op->jump = addr + op->size * 2;
			op->fail = addr + op->size;
		}
		break;
	case 0xA000:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case 0xB000:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		/* FIXME: this is wrong as op->jump depends on register V0 */
		op->jump = nnn;
		break;
	case 0xE000:
		if (kk == 0x9E || kk == 0xA1) {
			rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, addr, "KEYPAD");
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = addr + op->size * 2;
			op->fail = addr + op->size;
		}
		break;
	case 0xF000: {
		switch (kk) {
		case 0x07:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case 0x0A:
			rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, addr, "KEYPAD");
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case 0x15:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case 0x18:
			op->type = RZ_ANALYSIS_OP_TYPE_MOV;
			break;
		case 0x1E:
			op->type = RZ_ANALYSIS_OP_TYPE_ADD;
			break;
		case 0x29:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 0x30:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 0x33:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case 0x55:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case 0x65:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		case 0x75:
			op->type = RZ_ANALYSIS_OP_TYPE_STORE;
			break;
		case 0x85:
			op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
			break;
		}
	} break;
	}
	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_chip8 = {
	.name = "chip8",
	.desc = "CHIP8 analysis plugin",
	.license = "LGPL3",
	.arch = "chip8",
	.bits = 32,
	.op = &chip8_anop,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_chip8,
	.version = RZ_VERSION
};
#endif
