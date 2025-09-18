// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "h8500.h"

static const H8500EADescribe h8500_eas[] = {
	{ H8500_RD, 16, "Rn", { 0b1010, Sz &Rrr, END }, 1 },
	{ H8500_RI, 16, "@Rn", { 0b1101, Sz &Rrr, END }, 1 },
	{ H8500_RI_DISP, 8, "(d:8,Rn)", { 0b1110, Sz &Rrr, Disp8, END }, 2 },
	{ H8500_RI_DISP, 16, "(d:16,Rn)", { 0b1111, Sz &Rrr, Disp16, END }, 3 },
	{ H8500_RI_PRE_DEC, 16, "@-Rn", { 0b1111, Sz &Rrr, END }, 1 },
	{ H8500_RI_POST_INC, 16, "@Rn+", { 0b1100, Sz &Rrr, END }, 1 },
	{ H8500_ABS_ADDR, 8, "@aa:8", { 0b0000, Sz & 0b101, Addr8, END }, 2 },
	{ H8500_ABS_ADDR, 16, "@aa:16", { 0b0001, Sz & 0b101, Addr16, END }, 3 },
	{ H8500_IMM, 8, "@xx:8", { 0b0000, 0b0100, Data8, END }, 2 },
	{ H8500_IMM, 16, "@xx:16", { 0b0000, 0b1100, Data16, END }, 3 },
	{ H8500_PC_REL, 16, "disp", { END }, 1 /* or 2  */ },
};

static const H8500OpcodeDescribe h8500_opcodes[] = {
	{ ADD_Q, "add:q", "#1,<EAd>", 1, { 0b0000, 0b1000, END }, { 1 } },
	{ ADD_Q, "add:q", "#2,<EAd>", 1, { 0b0000, 0b1001, END }, { 2 } },
	{ ADD_Q, "add:q", "#-1,<EAd>", 1, { 0b0000, 0b1100, END }, { -1 } },
	{ ADD_Q, "add:q", "#-2,<EAd>", 1, { 0b0000, 0b1101, END }, { -2 } },
};

static bool h8500_ea_parse(const ut8 *buf, ut8 len, H8500Instruction *ins) {
	for (int i = 0; i < RZ_ARRAY_SIZE(h8500_eas); ++i) {
		const H8500EADescribe *ea = &h8500_eas[i];
		uint8_t b = buf[0];
		if ((ea->nibbles[0] & MASK_CONST) == (b >> 4) &&
			(ea->nibbles[1] & MASK_CONST) == (b & 0xf)) {
			ins->ea_describe = ea;
			return true;
		}
	}
	return false;
}

static bool h8500_opcode_parse(const ut8 *buf, size_t offset, ut8 len, H8500Instruction *ins) {
	if (len < offset + 1) {
		return false;
	}
	for (int i = 0; i < RZ_ARRAY_SIZE(h8500_opcodes); ++i) {
		const H8500OpcodeDescribe *opcode_describe = &h8500_opcodes[i];
		uint8_t b = buf[offset];
		if ((opcode_describe->nibbles[0] & MASK_CONST) == (b >> 4) &&
			(opcode_describe->nibbles[1] & MASK_CONST) == (b & 0xf)) {
			ins->opcode_describe = opcode_describe;
			return true;
		}
	}
	return false;
}

bool h8500_instruction_parse(const ut8 *buf, ut8 len, H8500Instruction *ins) {
	if (len < 2 || !ins) {
		return false;
	}
	H8500Instruction ins_in = { 0 };
	if (!h8500_ea_parse(buf, len, &ins_in)) {
		return false;
	}
	if (!h8500_opcode_parse(buf, ins_in.ea_describe->size, len, &ins_in)) {
		return false;
	}
	memcpy(ins, &ins_in, sizeof(H8500Instruction));
	ins->size = ins_in.ea_describe->size + ins_in.opcode_describe->size;
	memcpy(ins->bytes, buf, ins_in.size);
	return true;
}
