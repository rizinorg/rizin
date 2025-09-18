// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "h8500.h"
#include <rz_util/rz_str.h>

static const H8500EADescribe h8500_eas[] = {
	{ H8500_RD, 16, "Rn", { (0b1010 << 4) | Sz | Rrr, END }, 1 },
	{ H8500_RI, 16, "@Rn", { (0b1101 << 4) | Sz | Rrr, END }, 1 },
	{ H8500_RI_DISP, 8, "(d:8,Rn)", { (0b1110 << 4) | Sz | Rrr, Disp8, END }, 2 },
	{ H8500_RI_DISP, 16, "(d:16,Rn)", { (0b1111 << 4) | Sz | Rrr, Placeholder, Disp16, END }, 3 },
	{ H8500_RI_PRE_DEC, 16, "@-Rn", { (0b1111 << 4) | Sz | Rrr, END }, 1 },
	{ H8500_RI_POST_INC, 16, "@Rn+", { (0b1100 << 4) | Sz | Rrr, END }, 1 },
	{ H8500_ABS_ADDR, 8, "@aa:8", { 0b00000101 | Sz, Addr8, END }, 2 },
	{ H8500_ABS_ADDR, 16, "@aa:16", { 0b00010101 | Sz, Placeholder, Addr16, END }, 3 },
	{ H8500_IMM, 8, "@xx:8", { 0b00000100, Data8, END }, 2 },
	{ H8500_IMM, 16, "@xx:16", { 0b00001100, Placeholder, Data16, END }, 3 },
	//{ H8500_PC_REL, 16, "disp", { END }, 1 /* or 2  */ },
};

static const H8500OpcodeDescribe h8500_opcodes[] = {
	{ ADD_Q, "add:q", "#1,<EAd>", 1, { 0b00001000, END }, { 1 } },
	{ ADD_Q, "add:q", "#2,<EAd>", 1, { 0b00001001, END }, { 2 } },
	{ ADD_Q, "add:q", "#-1,<EAd>", 1, { 0b00001100, END }, { -1 } },
	{ ADD_Q, "add:q", "#-2,<EAd>", 1, { 0b00001101, END }, { -2 } },
};

static bool check_pat(const ut8 *buf, size_t pat_index, ut8 len,
	const H8500EADescribe *ea, H8500Instruction *ins) {
	if (len < 1) {
		return false;
	}
	ut8 b = buf[pat_index];
	H8500Pat pat = ea->pats[pat_index];
	if ((pat & MASK_CONST) != b) {
		return false;
	}
	if (pat & Rrr) {
		if (ea->addr_mode != H8500_RI_DISP) {
			ins->ea.rn = b & MASK_Rrr;
		} else {
			ins->ea.ri_disp.rn = b & MASK_Rrr;
		}
	}
	if (pat & Sz) {
		ins->ea.operand_size = (b & MASK_Sz) ? WORD_OPERAND : BYTE_OPERAND;
	}
	if (pat & Placeholder) {
		if (len < 2) {
			return false;
		}
		H8500Pat patl = ea->pats[pat_index + 1];
		ut16 val16 = (b << 8) | buf[pat_index + 1];
		if (patl & Disp16 && ea->addr_mode == H8500_RI_DISP) {
			ins->ea.ri_disp.disp = (st16)val16;
		}
		if (patl & Addr16) {
			ins->ea.aa = val16;
		}
		if (patl & Data16) {
			ins->ea.imm = val16;
		}
	}
	if (pat & Disp8 && ea->addr_mode == H8500_RI_DISP) {
		ins->ea.ri_disp.disp = (st8)b;
	}
	if (pat & Addr8) {
		ins->ea.aa = b;
	}
	if (pat & Data8) {
		ins->ea.imm = b;
	}
	return true;
}

static bool h8500_ea_parse(const ut8 *buf, ut8 len, H8500Instruction *ins) {
	for (int i = 0; i < RZ_ARRAY_SIZE(h8500_eas);) {
		const H8500EADescribe *ea = &h8500_eas[i];
		for (int j = 0;; j += 1) {
			if (!check_pat(buf + j, j, len - j, ea, ins)) {
				goto next_ea_describe;
			}
			if (ea->pats[j] == END) {
				strcpy(ins->ea.op_str, ea->mnemonic);
				char nummber_buf[16] = { 0 };
				switch (ea->addr_mode) {
				case H8500_RD:
				case H8500_RI:
				case H8500_RI_PRE_DEC:
				case H8500_RI_POST_INC:
					snprintf(nummber_buf, RZ_ARRAY_SIZE(nummber_buf), "r%d", ins->ea.rn);
					rz_str_replace(ins->ea.op_str, "Rn", nummber_buf, 0);
					break;
				case H8500_RI_DISP:
					snprintf(nummber_buf, RZ_ARRAY_SIZE(nummber_buf), "r%d", ins->ea.ri_disp.rn);
					rz_str_replace(ins->ea.op_str, "Rn", nummber_buf, 0);
					snprintf(nummber_buf, RZ_ARRAY_SIZE(nummber_buf), "%d", ins->ea.ri_disp.disp);
					rz_str_replace(ins->ea.op_str, "d", nummber_buf, 0);
					break;
				case H8500_ABS_ADDR:
					snprintf(nummber_buf, RZ_ARRAY_SIZE(nummber_buf), "0x%x", ins->ea.aa);
					rz_str_replace(ins->ea.op_str, "aa", nummber_buf, 0);
					break;
				case H8500_IMM:
					snprintf(nummber_buf, RZ_ARRAY_SIZE(nummber_buf), "0x%x", ins->ea.imm);
					rz_str_replace(ins->ea.op_str, "xx", nummber_buf, 0);
					break;
				case H8500_PC_REL: break;
				}
				ins->ea_describe = ea;
				return true;
			}
		}
	next_ea_describe:
		++i;
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
		if ((opcode_describe->pats[0] & MASK_CONST) != b) {
			continue;
		}
		ins->opcode_describe = opcode_describe;
		strcpy(ins->ops_str, opcode_describe->op_mnemonic);
		rz_str_replace(ins->ops_str, "<EAd>", ins->ea.op_str, 0);
		return true;
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
