// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "h8500.h"
#include <rz_util/rz_str.h>
#include <rz_util/rz_strbuf.h>

#define H(X)     ((X << 4) | (0xf0ull << MASK_CONST_OFF))
#define BM(X, M) ((X) | (ut64)M << MASK_CONST_OFF)
#define B(X)     BM(X, 0xffull)

static const H8500EADescribe h8500_eas[] = {
	{ AddrREG, 16, "Rn", { H(0b1010) | Sz | Rrr, END }, 1 },
	{ AddrRI, 16, "@Rn", { H(0b1101) | Sz | Rrr, END }, 1 },
	{ AddrRIDisp, 8, "(d:8,Rn)", { H(0b1110) | Sz | Rrr, Disp8, END }, 2 },
	{ AddrRIDisp, 16, "(d:16,Rn)", { H(0b1111) | Sz | Rrr, Placeholder, Disp16, END }, 3 },
	{ AddrRIPreDec, 16, "@-Rn", { H(0b1011) | Sz | Rrr, END }, 1 },
	{ AddrRIPostInc, 16, "@Rn+", { H(0b1100) | Sz | Rrr, END }, 1 },
	{ AddrAbs, 8, "@aa:8", { BM(0b00000101, 0xf7) | Sz, AA8, END }, 2 },
	{ AddrAbs, 16, "@aa:16", { BM(0b00010101, 0xf7) | Sz, Placeholder, AA16, END }, 3 },
	{ AddrIMM, 8, "#xx:8", { B(0b00000100), Data8, END }, 2 },
	{ AddrIMM, 16, "#xx:16", { B(0b00001100), Placeholder, Data16, END }, 3 },
	//{ H8500_PC_REL, 16, "disp", { END }, 1 /* or 2  */ },
};

#define RrrOp    (Rrr | HasOperand)
#define CrrOp    (Crr | HasOperand)
#define Disp8Op  (Disp8 | HasOperand)
#define Disp16Op Placeholder, Disp16 | HasOperand
#define Data4Op  (Data4 | HasOperand)
#define Data8Op  (Data8 | HasOperand)
#define Data16Op Placeholder, Data16 | HasOperand
#define ccOp     (cc | HasOperand)
#define AA8Op    (AA8 | HasOperand)
#define AA16Op   Placeholder, AA16 | HasOperand
#define AA24Op   Placeholder, Placeholder, AA24 | HasOperand

#define HR(X)    (BM(X << 3, 0xf8) | RrrOp)
#define HC(X)    (BM(X << 3, 0xf8) | CrrOp)
#define HRD8(X)  (BM(X << 3, 0xf8) | Rrr), Disp8Op
#define HRD16(X) (BM(X << 3, 0xf8) | Rrr), Disp16Op
#define HSR(X)   (H(X) | Sz | RrrOp)

#define IDX(I) (((ut64)I << MASK_INDEX_OFF) | HasINDEX)

#define AddrREGcr (Crr | AddrREG)

static const H8500OpcodeDescribe h8500_opcodes[] = {
	{ ADD_Q, "add:q.<Sz>", "<EA>,Rn", 1, { HR(0b00100), END }, { 1 } },
	{ ADD_Q, "add:q.<Sz>", "#1,<EA>", 1, { B(0b00001000), END }, { 1 }, EA_BanIMM },
	{ ADD_Q, "add:q.<Sz>", "#2,<EA>", 1, { B(0b00001001), END }, { 2 }, EA_BanIMM },
	{ ADD_Q, "add:q.<Sz>", "#-1,<EA>", 1, { B(0b00001100), END }, { -1 }, EA_BanIMM },
	{ ADD_Q, "add:q.<Sz>", "#-2,<EA>", 1, { B(0b00001101), END }, { -2 }, EA_BanIMM },
	{ ADDS, "adds.<Sz>", "<EA>,Rn", 1, { HR(0b00101), END }, { 0 } },
	{ ADDX, "addx.<Sz>", "<EA>,Rn", 1, { HR(0b10100), END }, { 0 } },
	{ AND, "and.<Sz>", "<EA>,Rn", 1, { HR(0b01010), END }, { 0 } },
	{ BCLR, "bclr.<Sz>", "#xx,<EA>", 1, { H(0b1101) | Data4Op, END }, { 0 }, EA_BanIMM },
	{ BCLR, "bclr.<Sz>", "Rn,<EA>", 1, { HR(0b01011), END }, { 0 }, EA_BanIMM },
	{ BNOT, "bnot.<Sz>", "#xx,<EA>", 1, { H(0b1110) | Data4Op, END }, { 0 }, EA_BanIMM },
	{ BNOT, "bnot.<Sz>", "Rn,<EA>", 1, { HR(0b01101), END }, { 0 }, EA_BanIMM },
	{ BSET, "bset.<Sz>", "#xx,<EA>", 1, { H(0b1100) | Data4Op, END }, { 0 }, EA_BanIMM },
	{ BSET, "bset.<Sz>", "Rn,<EA>", 1, { HR(0b01001), END }, { 0 }, EA_BanIMM },
	{ BTST, "btst.<Sz>", "#xx,<EA>", 1, { H(0b1111) | Data4Op, END }, { 0 }, EA_BanIMM },
	{ BTST, "btst.<Sz>", "Rn,<EA>", 1, { HR(0b01111), END }, { 0 }, EA_BanIMM },

	{ CLR, "clr.<Sz>", "<EA>", 1, { B(0b00010011), END }, { 0 }, EA_BanIMM },
	{ CMP, "cmp:g.<Sz>", "#xx,<EA>", 2, { B(0b00000100), Data8Op, END }, { 0 }, EA_BanIMM },
	{ CMP, "cmp:g.<Sz>", "#xx,<EA>", 3, { B(0b00000101), Data16Op, END }, { 0 }, EA_BanIMM },
	{ CMP, "cmp:g.<Sz>", "<EA>,Rn", 1, { HR(0b01110), END }, { 0 } },
	{ DIVXU, "divxu.<Sz>", "<EA>,Rn", 1, { HR(0b10111), END }, { 0 } },
	{ LDC, "ldc.<Sz>", "<EA>,CR", 1, { HC(0b10001), END }, { 0 } },
	{ MOV, "mov:g.<Sz>", "<EA>,Rn", 1, { HR(0b10000), END }, { 0 } },
	{ MOV, "mov:g.<Sz>", "Rn,<EA>", 1, { HR(0b10010), END }, { 0 }, EA_BanIMM },
	{ MOV, "mov:g.<Sz>", "#xx,<EA>", 2, { B(0x06), Data8Op, END }, { 0 }, EA_BanIMM },
	{ MOV, "mov:g.<Sz>", "#xx,<EA>", 3, { B(0x07), Data16Op, END }, { 0 }, EA_BanIMM },
	{ MOVFPE, "movfpe", "<EA>,Rn", 2, { B(0x00), HR(0b10000), END }, { 0 }, EA_BanIMM },
	{ MOVTPE, "movtpe", "Rn,<EA>", 2, { B(0x00), HR(0b10010), END }, { 0 }, EA_BanIMM },
	{ MULXU, "mulxu.<Sz>", "<EA>,Rn", 1, { HR(0b10101), END }, { 0 } },
	{ NEG, "neg.<Sz>", "<EA>", 1, { B(0x14), END }, { 0 }, EA_BanIMM },
	{ NOT, "not.<Sz>", "<EA>", 1, { B(0x15), END }, { 0 }, EA_BanIMM },
	{ OR, "or.<Sz>", "<EA>,Rn", 1, { HR(0b01000), END }, { 0 } },
	{ ROTL, "rotl.<Sz>", "<EA>", 1, { B(0x1c), END }, { 0 }, EA_BanIMM },
	{ ROTR, "rotr.<Sz>", "<EA>", 1, { B(0x1d), END }, { 0 }, EA_BanIMM },
	{ ROTL, "rotxl.<Sz>", "<EA>", 1, { B(0x1e), END }, { 0 }, EA_BanIMM },
	{ ROTR, "rotxr.<Sz>", "<EA>", 1, { B(0x1f), END }, { 0 }, EA_BanIMM },
	{ SHAL, "shal.<Sz>", "<EA>", 1, { B(0x18), END }, { 0 }, EA_BanIMM },
	{ SHAR, "shar.<Sz>", "<EA>", 1, { B(0x19), END }, { 0 }, EA_BanIMM },
	{ SHLL, "shll.<Sz>", "<EA>", 1, { B(0x1a), END }, { 0 }, EA_BanIMM },
	{ SHLR, "shlr.<Sz>", "<EA>", 1, { B(0x1b), END }, { 0 }, EA_BanIMM },
	{ STC, "stc.<Sz>", "CR,<EA>", 1, { HC(0b10011), END }, { AddrREGcr, EA }, EA_BanIMM },
	{ SUB, "sub.<Sz>", "<EA>,Rn", 1, { HR(0b00110), END }, { EA, AddrREG } },
	{ SUBS, "subs.<Sz>", "<EA>,Rn", 1, { HR(0b00111), END }, { EA, AddrREG } },
	{ SUBX, "subx.<Sz>", "<EA>,Rn", 1, { HR(0b10110), END }, { EA, AddrREG } },
	{ TAS, "tas", "<EA>", 1, { B(0x17), END }, { 0 }, EA_BanIMM },
	{ TST, "tst", "<EA>", 1, { B(0x16), END }, { 0 }, EA_BanIMM },
	{ XOR, "xor", "<EA>,Rn", 1, { HR(0b01100), END }, { EA, AddrREG } },
};

static const H8500OpcodeDescribe h8500_opcodes_without_ea[] = {
	{ ANDC, "andc.<Sz>", "#xx:8,CR", 3, { B(0x04), Data8Op, HC(0b01011), END }, { AddrIMM, AddrREGcr } },
	{ ANDC, "andc.<Sz>", "#xx:16,CR", 4, { B(0x0c), Data16Op, HC(0b01011), END }, { AddrIMM, AddrREGcr } },
	// TODO: Bcc also support 16-bit displacement
	{ Bcc, "<cc>", "disp", 2, { H(0b0010) | cc, Disp8Op, END }, { AddrPCRel } },
	{ BSR, "bsr", "disp", 2, { B(0b00001110), Disp8Op, END }, { AddrPCRel } },
	{ BSR, "bsr", "disp", 3, { B(0b00011110), Disp16Op, END }, { AddrPCRel } },
	{ DADD, "dadd", "Rn,Rn", 3, { HR(0b10100), B(0x00), HR(0b10100), END }, { AddrREG, AddrREG } },
	{ EXTS, "exts", "Rn", 2, { HR(0b10100), B(0x11), END }, { AddrREG } },
	{ EXTU, "extu", "Rn", 2, { HR(0b10100), B(0x12), END }, { AddrREG } },
	{ JMP, "jmp", "@Rn", 2, { B(0x11), HR(0b11010), END }, { AddrRI } },
	{ JMP, "jmp", "@(d:8,Rn)", 3, { B(0x11), HRD8(0b11100), END }, { AddrRIDisp } },
	{ JMP, "jmp", "@(d:16,Rn)", 4, { B(0x11), HRD16(0b11110), END }, { AddrRIDisp } },
	{ JMP, "jmp", "@aa:16", 3, { B(0x10), AA16Op, END }, { AddrAbs } },
	{ JSR, "jsr", "@Rn", 2, { B(0x11), HR(0b11011), END }, { AddrRI } },
	{ JSR, "jsr", "@(d:8,Rn)", 3, { B(0x11), HRD8(0b11101), END }, { AddrRIDisp } },
	{ JSR, "jsr", "@(d:16,Rn)", 4, { B(0x11), HRD16(0b11111), END }, { AddrRIDisp } },
	{ JSR, "jsr", "@aa:16", 3, { B(0x18), AA16Op, END }, { AddrAbs } },
	{ LDM, "ldm", "@SP+,<register list>", 2, { B(0x02), RegList | HasOperand, END }, { RegList } },
	{ LINK, "link", "fp,#xx:8", 2, { B(0x17), Data8Op, END }, { AddrIMM } },
	{ LINK, "link", "fp,#xx:16", 3, { B(0x1f), Data16Op, END }, { AddrIMM } },
	{ MOV, "mov:e", "#xx:8,Rn", 2, { HR(0b01010) | IDX(1), Data8Op | IDX(0), END }, { AddrIMM, AddrREG } },
	{ MOV, "mov:f.<Sz>", "@(d:8,Rn),Rn", 2, { HSR(0b1000) | IDX(1), Disp8Op | ImpliedR6 | IDX(0), END }, { AddrRIDisp, AddrREG } },
	{ MOV, "mov:f.<Sz>", "Rn,@(d:8,Rn)", 2, { HSR(0b1001), Disp8Op | ImpliedR6, END }, { AddrREG, AddrRIDisp } },
	{ MOV, "mov:i", "#xx:16,Rn", 3, { HR(0b01011) | IDX(1), Data16Op | IDX(0), END }, { AddrIMM, AddrREG } },
	{ MOV, "mov:l.<Sz>", "@aa:8,Rn", 2, { HSR(0b0110) | IDX(1), AA8Op | IDX(0), END }, { AddrAbs, AddrREG } },
	{ MOV, "mov:s.<Sz>", "Rn,@aa:8", 2, { HSR(0b0111), AA8Op, END }, { AddrREG, AddrAbs } },
	{ NOP, "nop", "", 1, { B(0x00), END }, { 0 } },
	{ ORC, "orc.<Sz>", "#xx:8,CR", 3, { B(0x04), Data8Op, HC(0b01001), END }, { AddrIMM, AddrREGcr } },
	{ ORC, "orc.<Sz>", "#xx:16,CR", 4, { B(0x0c), Data16Op, HC(0b01001), END }, { AddrIMM, AddrREGcr } },
	{ PJMP, "pjmp", "#aa:24", 4, { B(0x13), AA24Op, END }, { AddrIMM } },
	{ PJMP, "pjmp", "@Rn", 2, { B(0x11), HR(0b11000), END }, { AddrRI } },
	{ PJSR, "pjsr", "#aa:24", 4, { B(0x03), AA24Op, END }, { AddrIMM } },
	{ PJSR, "pjsr", "@Rn", 2, { B(0x11), HR(0b11001), END }, { AddrRI } },
	{ PRTD, "prtd", "#xx:8", 3, { B(0x11), B(0x14), Data8Op, END }, { AddrIMM } },
	{ PRTD, "prtd", "#xx:16", 4, { B(0x11), B(0x1c), Data16Op, END }, { AddrIMM } },
	{ PRTS, "prts", "", 2, { B(0x11), B(0x19), END }, {} },
	{ RTD, "rtd", "#xx:8", 2, { B(0x14), Data8Op, END }, { AddrIMM } },
	{ RTD, "rtd", "#xx:16", 3, { B(0x1c), Data16Op, END }, { AddrIMM } },
	{ RTE, "rte", "", 1, { B(0x0a), END }, {} },
	{ RTS, "rts", "", 1, { B(0x19), END }, {} },
	{ SCB_F, "scb/f", "Rn,disp", 3, { B(0x01), HR(0b10111), Disp8, END }, { AddrREG, AddrPCRel } },
	{ SCB_NE, "scb/ne", "Rn,disp", 3, { B(0x06), HR(0b10111), Disp8, END }, { AddrREG, AddrPCRel } },
	{ SCB_EQ, "scb/eq", "Rn,disp", 3, { B(0x07), HR(0b10111), Disp8, END }, { AddrREG, AddrPCRel } },
	{ SLEEP, "sleep", "", 1, { B(0x1a), END }, {} },
	{ STM, "stm.<Sz>", "<register list>,@-SP", 2, { B(0x12), RegList | HasOperand, END }, { RegList, AddrRIPreDec }, EA_BanIMM },
	{ SWAP, "swap", "Rn", 2, { HR(0b10100), B(0x10), END }, { AddrREG } },
	{ TRAPA, "trapa", "#xx", 2, { B(0x08), H(0x1) | VEC | Data4 | HasOperand, END }, { AddrIMM } },
	{ TRAP_VS, "trap/vs", "", 1, { B(0x09), END }, {} },
	{ UNLK, "unlk", "fp", 1, { B(0x0f), END }, {} },
	{ XCH, "xch", "Rn,Rn", 2, { HR(0b10101), HR(0b10010), END }, { AddrREG, AddrREG } },
	{ XORC, "xorc.<Sz>", "#xx:8,CR", 3, { B(0x04), Data8Op, HC(0b01101), END }, { AddrIMM, AddrREGcr } },
	{ XORC, "xorc.<Sz>", "#xx:16,CR", 4, { B(0x0c), Data16Op, HC(0b01101), END }, { AddrIMM, AddrREGcr } },

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

static const char *h8500_cc_mnemonics[] = {
	"bra",
	"brn",
	"bhi",
	"bls",
	"bcc",
	"bcs",
	"bne",
	"beq",
	"bvc",
	"bvs",
	"bpl",
	"bmi",
	"bge",
	"blt",
	"bgt",
	"ble",
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

static const char *cc_mnemonic(ut8 i) {
	if (i >= RZ_ARRAY_SIZE(h8500_cc_mnemonics)) {
		goto branch_fail;
	}
	return h8500_cc_mnemonics[i];
branch_fail:
	rz_warn_if_reached();
	return NULL;
}

static bool pat_const_check(ut32 pat, ut32 b) {
	const ut32 mask = (pat & MASK_CONST) >> MASK_CONST_OFF;
	return (pat & mask) == (b & mask);
}

static bool EA_parse(const ut8 *buf, size_t pat_index, ut8 len,
	const H8500EADescribe *ea_describe, H8500Instruction *ins) {
	if (len < 1) {
		return false;
	}
	H8500Operand *op = &ins->ea;
	const H8500Pat *pats = ea_describe->pats;
	ut64 mode = ea_describe->flags & MASK_AddressingMode;
	ut8 b = buf[pat_index];
	H8500Pat pat = pats[pat_index];
	if (!pat_const_check(pat, b)) {
		return false;
	}
	if (pat & Rrr) {
		ut8 index = b & MASK_Rrr;
		if (mode != AddrRIDisp) {
			op->rn = index;
		} else {
			op->ri_disp.rn = index;
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
		if (patl & Disp16 && mode == AddrRIDisp) {
			op->ri_disp.disp = (st16)val16;
		}
		if (patl & AA16) {
			op->aa = val16;
		}
		if (patl & Data16) {
			op->imm = val16;
		}
	}
	if (pat & Disp8 && mode == AddrRIDisp) {
		op->ri_disp.disp = (st8)b;
	}
	if (pat & AA8) {
		op->aa = b;
	}
	if (pat & Data8) {
		op->imm = b;
	}
	return true;
}

static bool operand_to_string(char *out, size_t len, H8500Operand *op) {
	char buf[16] = { 0 };
	switch (op->flags & MASK_AddressingMode) {
	case AddrREG:
	case AddrRI:
	case AddrRIPreDec:
	case AddrRIPostInc:
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
	case AddrRIDisp:
		rz_str_replace(out, "Rn", Rn_to_string(op->ri_disp.rn), 0);
		snprintf(buf, RZ_ARRAY_SIZE(buf), "%d", op->ri_disp.disp);
		rz_str_replace_in(out, len, "d", buf, 0);
		break;
	case AddrAbs:
		snprintf(buf, RZ_ARRAY_SIZE(buf), "0x%x", op->aa);
		rz_str_replace_in(out, len, "aa", buf, 0);
		break;
	case AddrIMM:
		snprintf(buf, RZ_ARRAY_SIZE(buf), "0x%x", op->imm);
		rz_str_replace_in(out, len, "xx", buf, 0);
		break;
	case AddrPCRel:
		snprintf(buf, RZ_ARRAY_SIZE(buf), "%+d", op->disp);
		rz_str_replace_in(out, len, "disp", buf, 0);
		break;
	default: break;
	}
	if (op->flags & RegList) {
		RzStrBuf sb = { 0 };
		rz_strbuf_init(&sb);
		rz_strbuf_append(&sb, "(");
		st8 l = -1;
		st8 r = -1;
		ut8 group_count = 0;
		for (st8 i = 0; i < 9; ++i) {
			if ((op->rn & 0xff) & (1 << i)) {
				if (l == -1 && r == -1) {
					if (group_count > 0) {
						rz_strbuf_append(&sb, ",");
					}
					rz_strbuf_append(&sb, Rn_to_string(i));
					l = r = i;
					group_count++;
				} else {
					r = i;
				}
			} else {
				if (r > l) {
					rz_strbuf_appendf(&sb, "-%s", Rn_to_string(i - 1));
				}
				l = r = -1;
			}
		}
		rz_strbuf_append(&sb, ")");
		rz_str_replace_in(out, len, "<register list>", rz_strbuf_get(&sb), 0);
		rz_strbuf_fini(&sb);
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
			if (!EA_parse(buf, j, len - j, ea_describe, ins)) {
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

static ut8 operand_index(H8500Pat pat, H8500Instruction *ins) {
	ut8 operand_index = (pat & HasINDEX)
		? ((pat & MASK_INDEX) >> MASK_INDEX_OFF)
		: ins->num_operands;
	rz_warn_if_fail(operand_index < RZ_ARRAY_SIZE(ins->operands));
	return operand_index;
}

static bool operand_parse(const ut8 *buf, size_t pat_index, ut8 len,
	const H8500OpcodeDescribe *opcode_describe, H8500Instruction *ins) {
	if (len < 1) {
		return false;
	}
	const H8500Pat *pats = opcode_describe->pats;
	ut8 b = buf[pat_index];
	H8500Pat pat = pats[pat_index];
	if (!pat_const_check(pat, b)) {
		return false;
	}

	H8500Operand *op = &ins->operands[operand_index(pat, ins)];
	ut64 mode = opcode_describe->args[operand_index(pat, ins)] & MASK_AddressingMode;

	if (pat & cc) {
		ins->condition_code = b & MASK_cc;
	}

	if (pat & Rrr) {
		ut8 index = b & MASK_Rrr;
		if (mode != AddrRIDisp) {
			op->rn = index;
			op->flags = AddrREG;
		} else {
			op->ri_disp.rn = index;
			op->flags = AddrRIDisp;
		}
	}

	if (pat & Crr) {
		op->rn = b & MASK_Rrr;
		ins->operand_size = get_ccr_describe(op->rn)->sz;
		op->flags = AddrREG | Crr;
	}

	if (pat & Sz) {
		ins->operand_size = (b & MASK_Sz) ? WORD_OPERAND : BYTE_OPERAND;
	}
	if (pat & Placeholder) {
		if (len < 2) {
			return false;
		}
		H8500Pat patl = pats[pat_index + 1];
		op = &ins->operands[operand_index(patl, ins)];
		ut16 val16 = (b << 8) | buf[pat_index + 1];
		if (patl & AA16) {
			op->aa = val16;
			op->flags = AddrAbs;
		}
		if (patl & Data16) {
			op->imm = val16;
			op->flags = AddrIMM;
		}
		if (patl & Disp16) {
			if (mode == AddrRIDisp) {
				op->ri_disp.disp = (st16)val16;
				op->flags = AddrRIDisp;
			} else {
				op->disp = (st16)val16;
				op->flags = AddrPCRel;
			}
		}
	}
	if (pat & AA24) {
		if (pat_index < 3) {
			return false;
		}
		op->aa = b | (buf[pat_index - 1] << 8) | (buf[pat_index - 2] << 16);
		op->flags = AddrAbs;
	}
	if (pat & AA8) {
		op->aa = b;
		op->flags = AddrAbs;
	}
	if (pat & Data4) {
		op->aa = b & MASK_Data4;
		op->flags = AddrIMM;
	}
	if (pat & Data8) {
		op->imm = b;
		op->flags = AddrIMM;
	}
	if (pat & Disp8) {
		if (mode == AddrRIDisp) {
			op->ri_disp.disp = (st16)b;
			op->flags = AddrRIDisp;
		} else {
			op->disp = (st16)b;
			op->flags = AddrPCRel;
		}
	}
	if (pat & RegList) {
		op->rn = b;
		op->flags = RegList;
	}
	if (pat & HasOperand) {
		ins->num_operands++;
	}
	if ((op->flags & AddrRIDisp) && (pat & ImpliedR6)) {
		op->ri_disp.rn = 6;
	}
	return true;
}

static bool h8500_opcode_parse(const ut8 *buf, size_t offset, ut8 len, H8500Instruction *ins, const H8500OpcodeDescribe *tbl, ut32 tbl_size) {
	if (len < offset + 1) {
		return false;
	}
	const H8500OpcodeDescribe *opcode_describe = NULL;
	char ea_str_buf[16] = { 0 };
	for (int i = 0; i < tbl_size; ++i) {
		opcode_describe = &tbl[i];
		for (int j = 0;; j += 1) {
			if (opcode_describe->pats[j] == END) {
				if ((opcode_describe->ea_flags & EA_BanIMM) &&
					ins->ea_describe &&
					((ins->ea_describe->flags & MASK_AddressingMode) == AddrIMM)) {
					goto branch_next;
				}
				ins->opcode_describe = opcode_describe;
				goto branch_ok;
			}
			if (!operand_parse(buf + offset, j, len - offset, opcode_describe, ins)) {
				goto branch_next;
			}
		}
	branch_next:
		if (ins->num_operands > 0) {
			memset(ins->operands, 0, sizeof(ins->operands));
			ins->num_operands = 0;
		}
	}
	return false;
branch_ok:
	strcpy(ins->mnemonic, opcode_describe->mnemonic);
	rz_str_replace(ins->mnemonic, "<Sz>", (ins->operand_size == WORD_OPERAND) ? "w" : "b", 0);
	rz_str_replace(ins->mnemonic, "<cc>", cc_mnemonic(ins->condition_code), 0);

	strcpy(ins->ops_str, opcode_describe->op_mnemonic);
	if (ins->ea_describe) {
		strcpy(ea_str_buf, ins->ea_describe->mnemonic);
		operand_to_string(ea_str_buf, RZ_ARRAY_SIZE(ea_str_buf), &ins->ea);
		rz_str_replace_in(ins->ops_str, RZ_ARRAY_SIZE(ins->ops_str), "<EA>", ea_str_buf, 0);
	}
	for (int i = 0; i < ins->num_operands; ++i) {
		operand_to_string(ins->ops_str, RZ_ARRAY_SIZE(ins->ops_str), &ins->operands[i]);
	}
	return true;
}

bool h8500_instruction_parse(const ut8 *buf, ut8 len, H8500Instruction *ins) {
	if (len < 1 || !ins) {
		return false;
	}
	H8500Instruction ins_in = { 0 };

	if (h8500_opcode_parse(buf, ins_in.ea_describe ? ins_in.ea_describe->size : 0, len, &ins_in,
		    h8500_opcodes_without_ea, RZ_ARRAY_SIZE(h8500_opcodes_without_ea))) {
		goto branch_ok;
	}
	memset(&ins_in, 0, sizeof(H8500Instruction));
	if (!(h8500_ea_parse(buf, len, &ins_in) &&
		    h8500_opcode_parse(buf, ins_in.ea_describe ? ins_in.ea_describe->size : 0, len, &ins_in,
			    h8500_opcodes, RZ_ARRAY_SIZE(h8500_opcodes)))) {
		return false;
	}

branch_ok:
	memcpy(ins, &ins_in, sizeof(H8500Instruction));
	ins->size = (ins_in.ea_describe ? ins_in.ea_describe->size : 0) + ins_in.opcode_describe->size;
	memcpy(ins->bytes, buf, ins->size);
	return true;
}
