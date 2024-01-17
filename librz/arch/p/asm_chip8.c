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
	char *buf_asm = NULL;
	switch (opcode & 0xF000) {
	case 0x0000:
		if (opcode == 0x00E0) {
			buf_asm = strdup("cls");
		} else if (opcode == 0x00EE) {
			buf_asm = strdup("ret");
		} else if ((opcode & 0xFFF0) == 0x00C0) {
			buf_asm = rz_str_newf("scd 0x%01x", nibble);
		} else if (opcode == 0x00FB) {
			buf_asm = strdup("scr");
		} else if (opcode == 0x00FC) {
			buf_asm = strdup("scl");
		} else if (opcode == 0x00FD) {
			buf_asm = strdup("exit");
		} else if (opcode == 0x00FE) {
			buf_asm = strdup("low");
		} else if (opcode == 0x00FF) {
			buf_asm = strdup("high");
		}
		break;
	case 0x1000: buf_asm = rz_str_newf("jp 0x%03x", nnn); break;
	case 0x2000: buf_asm = rz_str_newf("call 0x%03x", nnn); break;
	case 0x3000: buf_asm = rz_str_newf("se v%1x, 0x%02x", x, kk); break;
	case 0x4000: buf_asm = rz_str_newf("sne v%1x, 0x%02x", x, kk); break;
	case 0x5000: buf_asm = rz_str_newf("se v%1x, v%1x", x, y); break;
	case 0x6000: buf_asm = rz_str_newf("ld v%1x, 0x%02x", x, kk); break;
	case 0x7000: buf_asm = rz_str_newf("add v%1x, 0x%02x", x, kk); break;
	case 0x8000: {
		switch (nibble) {
		case 0x0: buf_asm = rz_str_newf("ld v%1x, v%1x", x, y); break;
		case 0x1: buf_asm = rz_str_newf("or v%1x, v%1x", x, y); break;
		case 0x2: buf_asm = rz_str_newf("and v%1x, v%1x", x, y); break;
		case 0x3: buf_asm = rz_str_newf("xor v%1x, v%1x", x, y); break;
		case 0x4: buf_asm = rz_str_newf("add v%1x, v%1x", x, y); break;
		case 0x5: buf_asm = rz_str_newf("sub v%1x, v%1x", x, y); break;
		case 0x6: buf_asm = rz_str_newf("shr v%1x, v%1x", x, y); break;
		case 0x7: buf_asm = rz_str_newf("subn v%1x, v%1x", x, y); break;
		case 0xE: buf_asm = rz_str_newf("shl v%1x, v%1x", x, y); break;
		}
	} break;
	case 0x9000: buf_asm = rz_str_newf("sne v%1x, v%1x", x, y); break;
	case 0xA000: buf_asm = rz_str_newf("ld i, 0x%03x", nnn); break;
	case 0xB000: buf_asm = rz_str_newf("jp v0, 0x%03x", nnn); break;
	case 0xC000: buf_asm = rz_str_newf("rnd v%1x, 0x%02x", x, kk); break;
	case 0xD000: buf_asm = rz_str_newf("drw v%1x, v%1x, 0x%01x", x, y, nibble); break;
	case 0xE000: {
		if (kk == 0x9E) {
			buf_asm = rz_str_newf("skp v%1x", x);
		} else if (kk == 0xA1) {
			buf_asm = rz_str_newf("sknp v%1x", x);
		}
	} break;
	case 0xF000: {
		switch (kk) {
		case 0x07: buf_asm = rz_str_newf("ld v%1x, dt", x); break;
		case 0x0A: buf_asm = rz_str_newf("ld v%1x, k", x); break;
		case 0x15: buf_asm = rz_str_newf("ld dt, v%1x", x); break;
		case 0x18: buf_asm = rz_str_newf("ld st, v%1x", x); break;
		case 0x1E: buf_asm = rz_str_newf("add i, v%1x", x); break;
		case 0x29: buf_asm = rz_str_newf("ld f, v%1x", x); break;
		case 0x33: buf_asm = rz_str_newf("ld b, v%1x", x); break;
		case 0x55: buf_asm = rz_str_newf("ld [i], v%1x", x); break;
		case 0x65: buf_asm = rz_str_newf("ld v%1x, [i]", x); break;
		case 0x30: buf_asm = rz_str_newf("ld hf, v%1x", x); break;
		case 0x75: buf_asm = rz_str_newf("ld r, v%1x", x); break;
		case 0x85: buf_asm = rz_str_newf("ld v%1x, r", x); break;
		}
	} break;
	}
	if (!buf_asm) {
		rz_strbuf_set(&op->buf_asm, "invalid");
	} else {
		rz_strbuf_set(&op->buf_asm, buf_asm);
		free(buf_asm);
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

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_chip8,
	.version = RZ_VERSION
};
#endif
