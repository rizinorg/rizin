// SPDX-FileCopyrightText: 2013-2018 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2013-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_asm.h>
#include <rz_lib.h>
#include <stdio.h>
#include <string.h>
#include "gb_op_table.h"

static int gbOpLength(int gboptype) {
	switch (gboptype) {
	case GB_8BIT:
		return 1;
	case GB_8BIT + ARG_8 + GB_IO:
	case GB_8BIT + ARG_8:
	case GB_16BIT:
		return 2;
	case GB_8BIT + ARG_16:
		return 3;
	default:
		return 0;
	}
}

static void gb_hardware_register_name(char *reg, size_t reg_sz, ut8 offset) {
	switch (offset) {
	case 0x00: // Joy pad info
		rz_str_ncpy(reg, "rP1", reg_sz);
		break;
	case 0x01: // Serial Transfer Data
		rz_str_ncpy(reg, "rSB", reg_sz);
		break;
	case 0x02: // Serial I/O Control
		rz_str_ncpy(reg, "rSC", reg_sz);
		break;
	case 0x04: // Divider register
		rz_str_ncpy(reg, "rDIV", reg_sz);
		break;
	case 0x05: // Timer Counter
		rz_str_ncpy(reg, "rTIMA", reg_sz);
		break;
	case 0x06: // Timer modulo
		rz_str_ncpy(reg, "rTMA", reg_sz);
		break;
	case 0x07: // Timer control
		rz_str_ncpy(reg, "rTAC", reg_sz);
		break;
	case 0x0f: // Interrupt Flag
		rz_str_ncpy(reg, "rIF", reg_sz);
		break;
		// Audio Channel #1
	case 0x10: // Sweep Register
		rz_str_ncpy(reg, "rAUD1SWEEP", reg_sz);
		break;
	case 0x11: // Sound length/Wave pattern duty
		rz_str_ncpy(reg, "rAUD1LEN", reg_sz);
		break;
	case 0x12: // Envelope
		rz_str_ncpy(reg, "rAUD1ENV", reg_sz);
		break;
	case 0x13: // Frequency low
		rz_str_ncpy(reg, "rAUD1LOW", reg_sz);
		break;
	case 0x14: // Frequency high
		rz_str_ncpy(reg, "rAUD1HIGH", reg_sz);
		break;
		// Audio Channel #2
	case 0x16: // Sound length/Wave pattern duty
		rz_str_ncpy(reg, "rAUD2LEN", reg_sz);
		break;
	case 0x17: // Envelope
		rz_str_ncpy(reg, "rAUD2ENV", reg_sz);
		break;
	case 0x18: // Frequency low
		rz_str_ncpy(reg, "rAUD2LOW", reg_sz);
		break;
	case 0x19: // Frequency high
		rz_str_ncpy(reg, "rAUD2HIGH", reg_sz);
		break;
		// Sound Channel #3
	case 0x1a: // Sound on/off
		rz_str_ncpy(reg, "rAUD3ENA", reg_sz);
		break;
	case 0x1b: // Sound length
		rz_str_ncpy(reg, "rAUD3LEN", reg_sz);
		break;
	case 0x1c: // Select output level
		rz_str_ncpy(reg, "rAUD3LEVEL", reg_sz);
		break;
	case 0x1d: // Frequency low
		rz_str_ncpy(reg, "rAUD3LOW", reg_sz);
		break;
	case 0x1e: // Frequency high
		rz_str_ncpy(reg, "rAUD3HIGH", reg_sz);
		break;
		// Sound Channel #4
	case 0x20: // Sound length
		rz_str_ncpy(reg, "rAUD4LEN", reg_sz);
		break;
	case 0x21: // Envelope
		rz_str_ncpy(reg, "rAUD4ENV", reg_sz);
		break;
	case 0x22: // Polynomial counter
		rz_str_ncpy(reg, "rAUD4POLY", reg_sz);
		break;
		// Sound (general)
	case 0x23:
		rz_str_ncpy(reg, "rAUD4GO", reg_sz);
		break;
	case 0x24: // Channel control / ON-OFF / Volume
		rz_str_ncpy(reg, "rAUDVOL", reg_sz);
		break;
	case 0x25: // Selection of Sound output terminal
		rz_str_ncpy(reg, "rAUDTERM", reg_sz);
		break;
	case 0x26: // Sound on/off
		rz_str_ncpy(reg, "rAUDENA", reg_sz);
		break;
	case 0x76: // Sound Channel 1&2 PCM amplitude
		rz_str_ncpy(reg, "rPCM12", reg_sz);
		break;
	case 0x77: // Sound Channel 3&4 PCM amplitude
		rz_str_ncpy(reg, "rPCM34", reg_sz);
		break;
	case 0x40: // LCD Control
		rz_str_ncpy(reg, "rLCDC", reg_sz);
		break;
	case 0x41: // LCD Status
		rz_str_ncpy(reg, "rSTAT", reg_sz);
		break;
	case 0x42: // Scroll Y
		rz_str_ncpy(reg, "rSCY", reg_sz);
		break;
	case 0x43: // Scroll X
		rz_str_ncpy(reg, "rSCX", reg_sz);
		break;
	case 0x44: // Y-Coordinate
		rz_str_ncpy(reg, "rLY", reg_sz);
		break;
	case 0x45: // Y-Coordinate Compare
		rz_str_ncpy(reg, "rLYC", reg_sz);
		break;
	case 0x46: // Transfer and Start Address
		rz_str_ncpy(reg, "rDMA", reg_sz);
		break;
	case 0x47: // BG Palette Data
		rz_str_ncpy(reg, "rBGP", reg_sz);
		break;
	case 0x48: // Object Palette 0 Data
		rz_str_ncpy(reg, "rOBP0", reg_sz);
		break;
	case 0x49: // Object Palette 1 Data
		rz_str_ncpy(reg, "rOBP1", reg_sz);
		break;
	case 0x4a: // Window Y Position
		rz_str_ncpy(reg, "rWY", reg_sz);
		break;
	case 0x4b: // Window X Position
		rz_str_ncpy(reg, "rWX", reg_sz);
		break;
	case 0x4d: // Select CPU Speed
		rz_str_ncpy(reg, "rKEY1", reg_sz);
		break;
	case 0x4f: // Select Video RAM Bank
		rz_str_ncpy(reg, "rVBK", reg_sz);
		break;
	case 0x51: // Horizontal Blanking, General Purpose DMA
	case 0x52: // Horizontal Blanking, General Purpose DMA
	case 0x53: // Horizontal Blanking, General Purpose DMA
	case 0x54: // Horizontal Blanking, General Purpose DMA
	case 0x55: // Horizontal Blanking, General Purpose DMA
		snprintf(reg, reg_sz, "rHDMA%d", offset - 0x50);
		break;
	case 0x56: // Infrared Communications Port
		rz_str_ncpy(reg, "rRP", reg_sz);
		break;
	case 0x68: // Background Color Palette Specification
		rz_str_ncpy(reg, "rBCPS", reg_sz);
		break;
	case 0x69: // Background Color Palette Data
		rz_str_ncpy(reg, "rBCPD", reg_sz);
		break;
	case 0x6a: // Object Color Palette Specification
		rz_str_ncpy(reg, "rOCPS", reg_sz);
		break;
	case 0x6b: // Object Color Palette Data
		rz_str_ncpy(reg, "rOCPD", reg_sz);
		break;
	case 0x70: // Select Main RAM Bank
		rz_str_ncpy(reg, "rSVBK", reg_sz);
		break;
	case 0xff: // Interrupt Enable Flag
		rz_str_ncpy(reg, "rIE", reg_sz);
		break;
	default:
		// If unknown, return the original address
		snprintf(reg, reg_sz, "0xff%02x", (unsigned int)offset);
		break;
	}
}

RZ_IPI int gbDisass(RzAsmOp *op, const ut8 *buf, int len) {
	int foo = gbOpLength(gb_op[buf[0]].type);
	if (len < foo) {
		return 0;
	}
	char reg[32];
	memset(reg, '\0', sizeof(reg));
	switch (gb_op[buf[0]].type) {
	case GB_8BIT:
		rz_asm_op_setf_asm(op, "%s", gb_op[buf[0]].name);
		break;
	case GB_16BIT:
		rz_asm_op_setf_asm(op, "%s %s", cb_ops[buf[1] >> 3u], cb_regs[buf[1] & 7u]);
		break;
	case GB_8BIT + ARG_8:
		rz_asm_op_setf_asm(op, gb_op[buf[0]].name, buf[1]);
		break;
	case GB_8BIT + ARG_16:
		rz_asm_op_setf_asm(op, gb_op[buf[0]].name, buf[1] + 0x100 * buf[2]);
		break;
	case GB_8BIT + ARG_8 + GB_IO:
		gb_hardware_register_name(reg, sizeof(reg), buf[1]);
		rz_asm_op_setf_asm(op, gb_op[buf[0]].name, reg);
		break;
	default:
		rz_asm_op_set_asm(op, "invalid");
		break;
	}
	return foo;
}
