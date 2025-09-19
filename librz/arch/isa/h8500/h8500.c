// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "h8500.h"
#include <rz_util/rz_str.h>

#define H(X)     ((X << 4) | (0xf0 << MASK_CONST_OFF))
#define BM(X, M) ((X) | M << MASK_CONST_OFF)
#define B(X)     BM(X, 0xff)

static const H8500EADescribe h8500_eas[] = {
	{ H8500_RD, 16, "Rn", { H(0b1010) | Sz | Rrr, END }, 1 },
	{ H8500_RI, 16, "@Rn", { H(0b1101) | Sz | Rrr, END }, 1 },
	{ H8500_RI_DISP, 8, "(d:8,Rn)", { H(0b1110) | Sz | Rrr, Disp8, END }, 2 },
	{ H8500_RI_DISP, 16, "(d:16,Rn)", { H(0b1111) | Sz | Rrr, Placeholder, Disp16, END }, 3 },
	{ H8500_RI_PRE_DEC, 16, "@-Rn", { H(0b1011) | Sz | Rrr, END }, 1 },
	{ H8500_RI_POST_INC, 16, "@Rn+", { H(0b1100) | Sz | Rrr, END }, 1 },
	{ H8500_ABS_ADDR, 8, "@aa:8", { BM(0b00000101, 0xf7) | Sz, Addr8, END }, 2 },
	{ H8500_ABS_ADDR, 16, "@aa:16", { BM(0b00010101, 0xf7) | Sz, Placeholder, Addr16, END }, 3 },
	{ H8500_IMM, 8, "#xx:8", { B(0b00000100), Data8, END }, 2 },
	{ H8500_IMM, 16, "#xx:16", { B(0b00001100), Placeholder, Data16, END }, 3 },
	//{ H8500_PC_REL, 16, "disp", { END }, 1 /* or 2  */ },
};

static const H8500OpcodeDescribe h8500_opcodes[] = {
	{ ADD_Q, "add:q.<Sz>", "#1,<EA>", 1, { B(0b00001000), END }, { 1 } },
	{ ADD_Q, "add:q.<Sz>", "#2,<EA>", 1, { B(0b00001001), END }, { 2 } },
	{ ADD_Q, "add:q.<Sz>", "#-1,<EA>", 1, { B(0b00001100), END }, { -1 } },
	{ ADD_Q, "add:q.<Sz>", "#-2,<EA>", 1, { B(0b00001101), END }, { -2 } },
	{ ADDS, "adds.<Sz>", "<EA>,Rn", 1, { BM(0b00101000, 0xf8) | Rrr | HasOperand, END }, { 0 } },
	{ ADDX, "addx.<Sz>", "<EA>,Rn", 1, { BM(0b10100000, 0xf8) | Rrr | HasOperand, END }, { 0 } },
	{ AND, "and.<Sz>", "<EA>,Rn", 1, { BM(0b01010000, 0xf8) | Rrr | HasOperand, END }, { 0 } },
	// Some instructions only accept specific EA types, and it may be necessary to add some constraints.
	{ ANDC, "andc.<Sz>", "<EA>,CR", 1, { BM(0b01011000, 0xf8) | Crr | HasOperand, END }, { 0 } },
	/*8*/ { ANDC, "andc.<Sz>", "<EA>,CR", 1, { BM(0b01011000, 0xf8) | Crr | HasOperand, END }, { 0 } },
};

typedef struct {
	const char *name;
	H8500OperandSize sz;
} CCRDescribe;

static const CCRDescribe h8500_ccrs[] = {
	[0] = { "sr", WORD_OPERAND },
	[1] = { "ccr", BYTE_OPERAND },
	[2] = { 0 },
	[3] = { "br", BYTE_OPERAND },
	[4] = { "ep", BYTE_OPERAND },
	[5] = { "dp", BYTE_OPERAND },
	[6] = { 0 },
	[7] = { "tp", BYTE_OPERAND },
};

static const char *h8500_rns[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
};

static const CCRDescribe *get_ccr_describe(ut8 crr) {
	if (crr >= RZ_ARRAY_SIZE(h8500_ccrs)) {
		goto branch_fail;
	}
	const CCRDescribe *ccr = h8500_ccrs + crr;
	if (RZ_STR_ISEMPTY(ccr->name)) {
		goto branch_fail;
	}
	return ccr;
branch_fail:
	rz_warn_if_reached();
	return NULL;
}

static const char *Rn_to_string(ut8 i) {
	if (i >= RZ_ARRAY_SIZE(h8500_rns)) {
		goto branch_fail;
	}
	return h8500_rns[i];
branch_fail:
	rz_warn_if_reached();
	return NULL;
}

#define CONST_CHECK(pat, b) ((pat & ((pat & MASK_CONST) >> MASK_CONST_OFF)) == (b & ((pat & MASK_CONST) >> MASK_CONST_OFF)))

static bool EA_check_pat(const ut8 *buf, size_t pat_index, ut8 len,
	const H8500EADescribe *ea_describe, H8500Instruction *ins) {
	if (len < 1) {
		return false;
	}
	H8500Operand *op = &ins->ea;
	const H8500Pat *pats = ea_describe->pats;
	H8500OperandFlags mode = ea_describe->flags & MASK_AddressingMode;
	ut8 b = buf[pat_index];
	H8500Pat pat = pats[pat_index];
	if (!CONST_CHECK(pat, b)) {
		return false;
	}
	if (pat & Rrr) {
		if (mode != H8500_RI_DISP) {
			op->rn = b & MASK_Rrr;
		} else {
			op->ri_disp.rn = b & MASK_Rrr;
		}
	}
	if (pat & Sz) {
		ins->operand_size = (b & MASK_Sz) ? WORD_OPERAND : BYTE_OPERAND;
	}
	if (pat & Placeholder) {
		if (len < 2) {
			return false;
		}
		H8500Pat patl = pats[pat_index + 1];
		ut16 val16 = (b << 8) | buf[pat_index + 1];
		if (patl & Disp16 && mode == H8500_RI_DISP) {
			op->ri_disp.disp = (st16)val16;
		}
		if (patl & Addr16) {
			op->aa = val16;
		}
		if (patl & Data16) {
			op->imm = val16;
		}
	}
	if (pat & Disp8 && mode == H8500_RI_DISP) {
		op->ri_disp.disp = (st8)b;
	}
	if (pat & Addr8) {
		op->aa = b;
	}
	if (pat & Data8) {
		op->imm = b;
	}
	return true;
}

static bool generate_opstr(char *out, size_t len, H8500Operand *op) {
	char buf[16] = { 0 };
	switch (op->flags & MASK_AddressingMode) {
	case H8500_RD:
	case H8500_RI:
	case H8500_RI_PRE_DEC:
	case H8500_RI_POST_INC:
		if (op->flags & Crr) {
			if (!get_ccr_describe(op->rn)) {
				rz_warn_if_reached();
				return false;
			}
			rz_str_replace_in(out, len, "CR", get_ccr_describe(op->rn)->name, 0);
		} else {
			rz_str_replace(out, "Rn", Rn_to_string(op->rn), 0);
		}

		break;
	case H8500_RI_DISP:
		rz_str_replace(out, "Rn", Rn_to_string(op->ri_disp.rn), 0);
		snprintf(buf, RZ_ARRAY_SIZE(buf), "%d", op->ri_disp.disp);
		rz_str_replace_in(out, len, "d", buf, 0);
		break;
	case H8500_ABS_ADDR:
		snprintf(buf, RZ_ARRAY_SIZE(buf), "0x%x", op->aa);
		rz_str_replace_in(out, len, "aa", buf, 0);
		break;
	case H8500_IMM:
		snprintf(buf, RZ_ARRAY_SIZE(buf), "0x%x", op->imm);
		rz_str_replace_in(out, len, "xx", buf, 0);
		break;
	case H8500_PC_REL:
	default: break;
	}
	return true;
}

static bool h8500_ea_parse(const ut8 *buf, ut8 len, H8500Instruction *ins) {
	const H8500EADescribe *ea_describe = NULL;
	for (int i = 0; i < RZ_ARRAY_SIZE(h8500_eas); ++i) {
		ea_describe = &h8500_eas[i];
		for (int j = 0;; j += 1) {
			if (ea_describe->pats[j] == END) {
				ins->ea_describe = ea_describe;
				ins->ea.flags = ea_describe->flags;
				goto branch_ok;
			}
			if (!EA_check_pat(buf, j, len - j, ea_describe, ins)) {
				goto branch_next_ea;
			}
		}
	branch_next_ea:
		continue;
	}
	return false;
branch_ok:
	return true;
}

static bool opcode_check_pat(const ut8 *buf, size_t pat_index, ut8 len,
	const H8500OpcodeDescribe *opcode_describe, H8500Instruction *ins) {
	if (len < 1) {
		return false;
	}
	const H8500Pat *pats = opcode_describe->pats;
	ut8 b = buf[pat_index];
	H8500Pat pat = pats[pat_index];
	H8500Operand *op = &ins->operands[ins->num_operands];

	if (!CONST_CHECK(pat, b)) {
		return false;
	}
	if (pat & Rrr) {
		op->rn = b & MASK_Rrr;
		op->flags = H8500_RD;
	}

	if (pat & Crr) {
		op->rn = b & MASK_Rrr;
		ins->operand_size = get_ccr_describe(op->rn)->sz;
		op->flags = H8500_RD | Crr;
	}

	if (pat & Sz) {
		ins->operand_size = (b & MASK_Sz) ? WORD_OPERAND : BYTE_OPERAND;
	}
	if (pat & Placeholder) {
		if (len < 2) {
			return false;
		}
		H8500Pat patl = pats[pat_index + 1];
		ut16 val16 = (b << 8) | buf[pat_index + 1];
		if (patl & Addr16) {
			op->aa = val16;
			op->flags = H8500_ABS_ADDR;
		}
		if (patl & Data16) {
			op->imm = val16;
			op->flags = H8500_IMM;
		}
	}
	if (pat & Addr8) {
		op->aa = b;
		op->flags = H8500_ABS_ADDR;
	}
	if (pat & Data8) {
		op->imm = b;
		op->flags = H8500_IMM;
	}
	if (pat & HasOperand) {
		ins->num_operands++;
	}
	return true;
}

static bool h8500_opcode_parse(const ut8 *buf, size_t offset, ut8 len, H8500Instruction *ins) {
	if (len < offset + 1) {
		return false;
	}
	const H8500OpcodeDescribe *opcode_describe = NULL;
	char ea_str_buf[16] = { 0 };
	for (int i = 0; i < RZ_ARRAY_SIZE(h8500_opcodes); ++i) {
		opcode_describe = &h8500_opcodes[i];
		for (int j = 0;; j += 1) {
			if (opcode_describe->pats[j] == END) {
				ins->opcode_describe = opcode_describe;
				goto branch_ok;
			}
			if (!opcode_check_pat(buf + offset, j, len - offset - j, opcode_describe, ins)) {
				goto branch_next_ea;
			}
		}
	branch_next_ea:
		continue;
	}
	return false;
branch_ok:
	strcpy(ins->mnemonic, opcode_describe->mnemonic);
	rz_str_replace(ins->mnemonic, "<Sz>", (ins->operand_size == WORD_OPERAND) ? "w" : "b", 0);

	strcpy(ins->ops_str, opcode_describe->op_mnemonic);
	strcpy(ea_str_buf, ins->ea_describe->mnemonic);
	generate_opstr(ea_str_buf, RZ_ARRAY_SIZE(ea_str_buf), &ins->ea);
	rz_str_replace_in(ins->ops_str, RZ_ARRAY_SIZE(ins->ops_str), "<EA>", ea_str_buf, 0);
	for (int i = 0; i < ins->num_operands; ++i) {
		generate_opstr(ins->ops_str, RZ_ARRAY_SIZE(ins->ops_str), &ins->operands[i]);
	}
	return true;
}

bool h8500_instruction_parse(const ut8 *buf, ut8 len, H8500Instruction *ins) {
	if (len < 2 || !ins) {
		return false;
	}
	H8500Instruction ins_in = { 0 };
	h8500_ea_parse(buf, len, &ins_in);
	if (!h8500_opcode_parse(buf, ins_in.ea_describe ? ins_in.ea_describe->size : 0, len, &ins_in)) {
		return false;
	}
	memcpy(ins, &ins_in, sizeof(H8500Instruction));
	ins->size = (ins_in.ea_describe ? ins_in.ea_describe->size : 0) + ins_in.opcode_describe->size;
	memcpy(ins->bytes, buf, ins_in.size);
	return true;
}
