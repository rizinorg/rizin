// SPDX-FileCopyrightText: 2017-2018 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>

static int chip8_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *b, int l) {
	ut16 opcode = rz_read_be16(b);
	uint8_t x = (opcode >> 8) & 0x0F;
	uint8_t y = (opcode >> 4) & 0x0F;
	uint8_t nibble = opcode & 0x0F;
	uint16_t nnn = opcode & 0x0FFF;
	uint8_t kk = opcode & 0xFF;
	rz_asm_op_set_asm(op, "invalid");
	switch (opcode & 0xF000) {
	case 0x0000:
		if (opcode == 0x00E0) {
			rz_asm_op_set_asm(op, "cls");
		} else if (opcode == 0x00EE) {
			rz_asm_op_set_asm(op, "ret");
		} else if ((opcode & 0xFFF0) == 0x00C0) {
			rz_asm_op_setf_asm(op, "scd 0x%01x", nibble);
		} else if (opcode == 0x00FB) {
			rz_asm_op_set_asm(op, "scr");
		} else if (opcode == 0x00FC) {
			rz_asm_op_set_asm(op, "scl");
		} else if (opcode == 0x00FD) {
			rz_asm_op_set_asm(op, "exit");
		} else if (opcode == 0x00FE) {
			rz_asm_op_set_asm(op, "low");
		} else if (opcode == 0x00FF) {
			rz_asm_op_set_asm(op, "high");
		}
		break;
	case 0x1000: rz_asm_op_setf_asm(op, "jp 0x%03x", nnn); break;
	case 0x2000: rz_asm_op_setf_asm(op, "call 0x%03x", nnn); break;
	case 0x3000: rz_asm_op_setf_asm(op, "se v%1x, 0x%02x", x, kk); break;
	case 0x4000: rz_asm_op_setf_asm(op, "sne v%1x, 0x%02x", x, kk); break;
	case 0x5000: rz_asm_op_setf_asm(op, "se v%1x, v%1x", x, y); break;
	case 0x6000: rz_asm_op_setf_asm(op, "ld v%1x, 0x%02x", x, kk); break;
	case 0x7000: rz_asm_op_setf_asm(op, "add v%1x, 0x%02x", x, kk); break;
	case 0x8000: {
		switch (nibble) {
		case 0x0: rz_asm_op_setf_asm(op, "ld v%1x, v%1x", x, y); break;
		case 0x1: rz_asm_op_setf_asm(op, "or v%1x, v%1x", x, y); break;
		case 0x2: rz_asm_op_setf_asm(op, "and v%1x, v%1x", x, y); break;
		case 0x3: rz_asm_op_setf_asm(op, "xor v%1x, v%1x", x, y); break;
		case 0x4: rz_asm_op_setf_asm(op, "add v%1x, v%1x", x, y); break;
		case 0x5: rz_asm_op_setf_asm(op, "sub v%1x, v%1x", x, y); break;
		case 0x6: rz_asm_op_setf_asm(op, "shr v%1x, v%1x", x, y); break;
		case 0x7: rz_asm_op_setf_asm(op, "subn v%1x, v%1x", x, y); break;
		case 0xE: rz_asm_op_setf_asm(op, "shl v%1x, v%1x", x, y); break;
		}
	} break;
	case 0x9000: rz_asm_op_setf_asm(op, "sne v%1x, v%1x", x, y); break;
	case 0xA000: rz_asm_op_setf_asm(op, "ld i, 0x%03x", nnn); break;
	case 0xB000: rz_asm_op_setf_asm(op, "jp v0, 0x%03x", nnn); break;
	case 0xC000: rz_asm_op_setf_asm(op, "rnd v%1x, 0x%02x", x, kk); break;
	case 0xD000: rz_asm_op_setf_asm(op, "drw v%1x, v%1x, 0x%01x", x, y, nibble); break;
	case 0xE000: {
		if (kk == 0x9E) {
			rz_asm_op_setf_asm(op, "skp v%1x", x);
		} else if (kk == 0xA1) {
			rz_asm_op_setf_asm(op, "sknp v%1x", x);
		}
	} break;
	case 0xF000: {
		switch (kk) {
		case 0x07: rz_asm_op_setf_asm(op, "ld v%1x, dt", x); break;
		case 0x0A: rz_asm_op_setf_asm(op, "ld v%1x, k", x); break;
		case 0x15: rz_asm_op_setf_asm(op, "ld dt, v%1x", x); break;
		case 0x18: rz_asm_op_setf_asm(op, "ld st, v%1x", x); break;
		case 0x1E: rz_asm_op_setf_asm(op, "add i, v%1x", x); break;
		case 0x29: rz_asm_op_setf_asm(op, "ld f, v%1x", x); break;
		case 0x33: rz_asm_op_setf_asm(op, "ld b, v%1x", x); break;
		case 0x55: rz_asm_op_setf_asm(op, "ld [i], v%1x", x); break;
		case 0x65: rz_asm_op_setf_asm(op, "ld v%1x, [i]", x); break;
		case 0x30: rz_asm_op_setf_asm(op, "ld hf, v%1x", x); break;
		case 0x75: rz_asm_op_setf_asm(op, "ld r, v%1x", x); break;
		case 0x85: rz_asm_op_setf_asm(op, "ld v%1x, r", x); break;
		}
	} break;
	}

	op->size = 2;
	return op->size;
}

RzAsmPlugin rz_asm_plugin_chip8 = {
	.name = "chip8",
	.arch = "chip8",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Chip8 disassembler",
	.disassemble = &chip8_disassemble,
};
