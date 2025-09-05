// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "h8500.h"

/**
 * *1 Sz: Operand size
 * Sz = 0: byte operand
 * Sz = 1: word operand
 * *2 rrr (register number field): General register number
 * 000: R0 001: R1 010: R2 011: R3
 * 100: R4 101: R5 110: R6 111: R7
 */
typedef enum {
	Rrr = 1 << 8,
	Disp8 = 2 << 8,
	Disp16 = 3 << 8,
	Addr8 = 3 << 8,
	Addr16 = 3 << 8,
	Data8 = 3 << 8,
	Data16 = 3 << 8,
	Sz = 0b1 << 16,
	END = 0b1 << 31,
} H8500OperandNibbleFlag;

typedef struct {
	H8500AddrssingMode addr_mode;
	const char *mnemonic;
	uint32_t nibbles[4];
	uint8_t size;
} H8500EADescribe;

static const H8500EADescribe h8500_eas[] = {
	{ H8500_RD, "Rn", { 0b1010, Sz &Rrr, END }, 1 },
	{ H8500_RI, "@Rn", { 0b1101, Sz &Rrr, END }, 1 },
	{ H8500_RI_DISP, "(d:8,Rn)", { 0b1110, Sz &Rrr, Disp8, END }, 2 },
	{ H8500_RI_DISP, "(d:16,Rn)", { 0b1111, Sz &Rrr, Disp16, END }, 3 },
	{ H8500_RI_PRE_DEC, "@-Rn", { 0b1111, Sz &Rrr, END }, 1 },
	{ H8500_RI_POST_INC, "@Rn+", { 0b1100, Sz &Rrr, END }, 1 },
	{ H8500_ABS_ADDR, "@aa:8", { 0b0000, Sz & 0b101, Addr8, END }, 2 },
	{ H8500_ABS_ADDR, "@aa:16", { 0b0001, Sz & 0b101, Addr16, END }, 3 },
	{ H8500_IMM, "@xx:8", { 0b0000, 0b0100, Data8, END }, 2 },
	{ H8500_IMM, "@xx:16", { 0b0000, 0b1100, Data16, END }, 3 },
	{ H8500_PC_REL, "disp", { END }, 1 /* or 2  */ },
};

void h8500_instruction_parse(const ut8 *buf, ut8 len, H8500Instruction *ins) {
	for (int i = 0; i < RZ_ARRAY_SIZE(h8500_eas); ++i) {
		printf("%s", h8500_eas[i].mnemonic);
	}
}
