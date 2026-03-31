// SPDX-FileCopyrightText: 2025 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file h8500.c
 * \brief H8/500 (H8500) instruction decoding tables and parser.
 * \details Implements effective-address parsing, opcode pattern matching,
 *          operand formatting, and mnemonic rendering for the Renesas H8/500 family.
 * \see H8/5xx Programming Manual:
 *      https://evoecu.logic.net/mirror/cpudocs/h8539f/H8%205XX%20Programming.pdf
 */

#include "h8500.h"
#include <rz_util/rz_str.h>
#include <rz_util/rz_strbuf.h>

#define H(X)     ((X << 4) | (0xf0ull << MASK_CONST_OFF))
#define BM(X, M) ((X) | (ut64)M << MASK_CONST_OFF)
#define B(X)     BM(X, 0xffull)

#define SEP ", "

static const H8500EADescribe h8500_eas[] = {
	{ AddrREG, "Rn", { H(0xA) | Sz | Rrr, END }, 16, 1 },
	{ AddrRI, "@Rn", { H(0xD) | Sz | Rrr, END }, 16, 1 },
	{ AddrRIDisp, "@(d:8" SEP "Rn)", { H(0xE) | Sz | Rrr, Disp8, END }, 8, 2 },
	{ AddrRIDisp, "@(d:16" SEP "Rn)", { H(0xF) | Sz | Rrr, Placeholder, Disp16, END }, 16, 3 },
	{ AddrRIPreDec, "@-Rn", { H(0xB) | Sz | Rrr, END }, 16, 1 },
	{ AddrRIPostInc, "@Rn+", { H(0xC) | Sz | Rrr, END }, 16, 1 },
	{ AddrAbs, "@aa:8", { BM(0x05, 0xf7) | Sz, AA8, END }, 8, 2 },
	{ AddrAbs, "@aa:16", { BM(0x15, 0xf7) | Sz, Placeholder, AA16, END }, 16, 3 },
	{ AddrIMM, "#xx:8", { B(0x04), Data8, END }, 8, 2 },
	{ AddrIMM, "#xx:16", { B(0x0C), Placeholder, Data16, END }, 16, 3 },
	/**
	 * Although the EA in PC-relative mode is classified as an EA in the documentation,
	 * it lacks a pattern for matching and cannot be parsed as EA+Opcode.
	 * In practice, it can only be processed by parsing the Opcode+EA format.
	 */
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
#define SP_IDX 7

#define AddrREGcr (Crr | AddrREG)

static const H8500OpcodeDescribe h8500_opcodes[] = {
	{ ADD_Q, "add:q.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x04), END }, { EA, AddrREG } },
	{ ADD_Q, "add:q.<Sz>", "#1" SEP "<EA>", 1, { B(0x08), END }, { ARG_PACK_DATA(1) | AddrIMM, EA }, EA_BanIMM },
	{ ADD_Q, "add:q.<Sz>", "#2" SEP "<EA>", 1, { B(0x09), END }, { ARG_PACK_DATA(2) | AddrIMM, EA }, EA_BanIMM },
	{ ADD_Q, "add:q.<Sz>", "#-1" SEP "<EA>", 1, { B(0x0C), END }, { ARG_PACK_DATA(1) | AddrIMM, EA }, EA_BanIMM },
	{ ADD_Q, "add:q.<Sz>", "#-2" SEP "<EA>", 1, { B(0x0D), END }, { ARG_PACK_DATA(2) | AddrIMM, EA }, EA_BanIMM },
	{ ADDS, "adds.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x05), END }, { EA, AddrREG } },
	{ ADDX, "addx.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x14), END }, { EA, AddrREG } },
	{ AND, "and.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x0A), END }, { EA, AddrREG } },
	{ BCLR, "bclr.<Sz>", "#xx" SEP "<EA>", 1, { H(0xD) | Data4Op, END }, { AddrIMM, EA }, EA_BanIMM },
	{ BCLR, "bclr.<Sz>", "Rn" SEP "<EA>", 1, { HR(0x0B), END }, { AddrREG, EA }, EA_BanIMM },
	{ BNOT, "bnot.<Sz>", "#xx" SEP "<EA>", 1, { H(0xE) | Data4Op, END }, { AddrIMM, EA }, EA_BanIMM },
	{ BNOT, "bnot.<Sz>", "Rn" SEP "<EA>", 1, { HR(0x0D), END }, { AddrREG, EA }, EA_BanIMM },
	{ BSET, "bset.<Sz>", "#xx" SEP "<EA>", 1, { H(0xC) | Data4Op, END }, { AddrIMM, EA }, EA_BanIMM },
	{ BSET, "bset.<Sz>", "Rn" SEP "<EA>", 1, { HR(0x09), END }, { AddrREG, EA }, EA_BanIMM },
	{ BTST, "btst.<Sz>", "#xx" SEP "<EA>", 1, { H(0xF) | Data4Op, END }, { AddrIMM, EA }, EA_BanIMM },
	{ BTST, "btst.<Sz>", "Rn" SEP "<EA>", 1, { HR(0x0F), END }, { AddrREG, EA }, EA_BanIMM },

	{ CLR, "clr.<Sz>", "<EA>", 1, { B(0x13), END }, { EA }, EA_BanIMM },
	{ CMP, "cmp:g.<Sz>", "#xx" SEP "<EA>", 2, { B(0x04), Data8Op, END }, { AddrIMM, EA }, EA_BanIMM },
	{ CMP, "cmp:g.<Sz>", "#xx" SEP "<EA>", 3, { B(0x05), Data16Op, END }, { AddrIMM, EA }, EA_BanIMM },
	{ CMP, "cmp:g.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x0E), END }, { EA, AddrREG } },
	{ DIVXU, "divxu.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x17), END }, { EA, AddrREG } },
	{ LDC, "ldc.<Sz>", "<EA>" SEP "CR", 1, { HC(0x11), END }, { EA, AddrREGcr } },
	{ MOV, "mov:g.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x10), END }, { EA, AddrREG } },
	{ MOV, "mov:g.<Sz>", "Rn" SEP "<EA>", 1, { HR(0x12), END }, { AddrREG, EA }, EA_BanIMM },
	{ MOV, "mov:g.<Sz>", "#xx" SEP "<EA>", 2, { B(0x06), Data8Op, END }, { AddrIMM, EA }, EA_BanIMM },
	{ MOV, "mov:g.<Sz>", "#xx" SEP "<EA>", 3, { B(0x07), Data16Op, END }, { AddrIMM, EA }, EA_BanIMM },
	{ MOVFPE, "movfpe", "<EA>" SEP "Rn", 2, { B(0x00), HR(0x10), END }, { EA, AddrREG }, EA_BanIMM },
	{ MOVTPE, "movtpe", "Rn" SEP "<EA>", 2, { B(0x00), HR(0x12), END }, { AddrREG, EA }, EA_BanIMM },
	{ MULXU, "mulxu.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x15), END }, { EA, AddrREG } },
	{ NEG, "neg.<Sz>", "<EA>", 1, { B(0x14), END }, { EA }, EA_BanIMM },
	{ NOT, "not.<Sz>", "<EA>", 1, { B(0x15), END }, { EA }, EA_BanIMM },
	{ OR, "or.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x08), END }, { EA, AddrREG } },
	{ ROTL, "rotl.<Sz>", "<EA>", 1, { B(0x1c), END }, { EA }, EA_BanIMM },
	{ ROTR, "rotr.<Sz>", "<EA>", 1, { B(0x1d), END }, { EA }, EA_BanIMM },
	{ ROTL, "rotxl.<Sz>", "<EA>", 1, { B(0x1e), END }, { EA }, EA_BanIMM },
	{ ROTR, "rotxr.<Sz>", "<EA>", 1, { B(0x1f), END }, { EA }, EA_BanIMM },
	{ SHAL, "shal.<Sz>", "<EA>", 1, { B(0x18), END }, { EA }, EA_BanIMM },
	{ SHAR, "shar.<Sz>", "<EA>", 1, { B(0x19), END }, { EA }, EA_BanIMM },
	{ SHLL, "shll.<Sz>", "<EA>", 1, { B(0x1a), END }, { EA }, EA_BanIMM },
	{ SHLR, "shlr.<Sz>", "<EA>", 1, { B(0x1b), END }, { EA }, EA_BanIMM },
	{ STC, "stc.<Sz>", "CR" SEP "<EA>", 1, { HC(0x13), END }, { AddrREGcr, EA }, EA_BanIMM },
	{ SUB, "sub.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x06), END }, { EA, AddrREG } },
	{ SUBS, "subs.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x07), END }, { EA, AddrREG } },
	{ SUBX, "subx.<Sz>", "<EA>" SEP "Rn", 1, { HR(0x16), END }, { EA, AddrREG } },
	{ TAS, "tas", "<EA>", 1, { B(0x17), END }, { EA }, EA_BanIMM },
	{ TST, "tst", "<EA>", 1, { B(0x16), END }, { EA }, EA_BanIMM },
	{ XOR, "xor", "<EA>" SEP "Rn", 1, { HR(0x0C), END }, { EA, AddrREG } },
};

static const H8500OpcodeDescribe h8500_opcodes_without_ea[] = {
	{ ANDC, "andc.<Sz>", "#xx:8" SEP "CR", 3, { B(0x04), Data8Op, HC(0x0B), END }, { AddrIMM, AddrREGcr } },
	{ ANDC, "andc.<Sz>", "#xx:16" SEP "CR", 4, { B(0x0c), Data16Op, HC(0x0B), END }, { AddrIMM, AddrREGcr } },
	{ Bcc, "<cc>", "disp", 2, { H(0x2) | cc, Disp8Op, END }, { AddrPCRel } },
	{ Bcc, "<cc>", "disp", 3, { H(0x3) | cc, Disp16Op, END }, { AddrPCRel } },
	{ BSR, "bsr", "disp", 2, { B(0x0E), Disp8Op, END }, { AddrPCRel } },
	{ BSR, "bsr", "disp", 3, { B(0x1E), Disp16Op, END }, { AddrPCRel } },
	{ CMP, "cmp.b", "#xx:8" SEP "Rn", 2, { HR(0x08) | IDX(1), Data8Op | IDX(0), END }, { AddrIMM, AddrREG } },
	{ CMP, "cmp.w", "#xx:16" SEP "Rn", 3, { HR(0x09) | IDX(1), Data16Op | IDX(0), END }, { AddrIMM, AddrREG } },
	{ DADD, "dadd", "Rn" SEP "Rn", 3, { HR(0x14), B(0x00), HR(0x14), END }, { AddrREG, AddrREG } },
	{ DSUB, "dsub", "Rn" SEP "Rn", 3, { HR(0x14), B(0x00), HR(0x16), END }, { AddrREG, AddrREG } },
	{ EXTS, "exts", "Rn", 2, { HR(0x14), B(0x11), END }, { AddrREG } },
	{ EXTU, "extu", "Rn", 2, { HR(0x14), B(0x12), END }, { AddrREG } },
	{ JMP, "jmp", "@Rn", 2, { B(0x11), HR(0x1A), END }, { AddrRI } },
	{ JMP, "jmp", "@(d:8" SEP "Rn)", 3, { B(0x11), HRD8(0x1C), END }, { AddrRIDisp } },
	{ JMP, "jmp", "@(d:16" SEP "Rn)", 4, { B(0x11), HRD16(0x1E), END }, { AddrRIDisp } },
	{ JMP, "jmp", "@aa:16", 3, { B(0x10), AA16Op, END }, { AddrAbs } },
	{ JSR, "jsr", "@Rn", 2, { B(0x11), HR(0x1B), END }, { AddrRI } },
	{ JSR, "jsr", "@(d:8" SEP "Rn)", 3, { B(0x11), HRD8(0x1D), END }, { AddrRIDisp } },
	{ JSR, "jsr", "@(d:16" SEP "Rn)", 4, { B(0x11), HRD16(0x1F), END }, { AddrRIDisp } },
	{ JSR, "jsr", "@aa:16", 3, { B(0x18), AA16Op, END }, { AddrAbs } },
	{ LDM, "ldm", "@SP+" SEP "<register list>", 2, { B(0x02), RegList | HasOperand, END }, { ARG_PACK_DATA(SP_IDX) | AddrRIPostInc, RegList } },
	{ LINK, "link", "fp" SEP "#xx:8", 2, { B(0x17), Data8Op, END }, { AddrIMM } },
	{ LINK, "link", "fp" SEP "#xx:16", 3, { B(0x1f), Data16Op, END }, { AddrIMM } },
	{ MOV, "mov:e", "#xx:8" SEP "Rn", 2, { HR(0x0A) | IDX(1), Data8Op | IDX(0), END }, { AddrIMM, AddrREG } },
	{ MOV, "mov:f.<Sz>", "@(d:8" SEP "Rn)" SEP "Rn", 2, { HSR(0x8) | IDX(1), Disp8Op | ImpliedR6 | IDX(0), END }, { AddrRIDisp, AddrREG } },
	{ MOV, "mov:f.<Sz>", "Rn" SEP "@(d:8" SEP "Rn)", 2, { HSR(0x9), Disp8Op | ImpliedR6, END }, { AddrREG, AddrRIDisp } },
	{ MOV, "mov:i", "#xx:16" SEP "Rn", 3, { HR(0x0B) | IDX(1), Data16Op | IDX(0), END }, { AddrIMM, AddrREG } },
	{ MOV, "mov:l.<Sz>", "@aa:8" SEP "Rn", 2, { HSR(0x6) | IDX(1), AA8Op | IDX(0), END }, { AddrAbs, AddrREG } },
	{ MOV, "mov:s.<Sz>", "Rn" SEP "@aa:8", 2, { HSR(0x7), AA8Op, END }, { AddrREG, AddrAbs } },
	{ NOP, "nop", "", 1, { B(0x00), END }, { 0 } },
	{ ORC, "orc.<Sz>", "#xx:8" SEP "CR", 3, { B(0x04), Data8Op, HC(0x09), END }, { AddrIMM, AddrREGcr } },
	{ ORC, "orc.<Sz>", "#xx:16" SEP "CR", 4, { B(0x0c), Data16Op, HC(0x09), END }, { AddrIMM, AddrREGcr } },
	{ PJMP, "pjmp", "@aa:24", 4, { B(0x13), AA24Op, END }, { AddrAbs } },
	{ PJMP, "pjmp", "@Rn", 2, { B(0x11), HR(0x18), END }, { AddrRI } },
	{ PJSR, "pjsr", "@aa:24", 4, { B(0x03), AA24Op, END }, { AddrAbs } },
	{ PJSR, "pjsr", "@Rn", 2, { B(0x11), HR(0x19), END }, { AddrRI } },
	{ PRTD, "prtd", "#xx:8", 3, { B(0x11), B(0x14), Data8Op, END }, { AddrIMM } },
	{ PRTD, "prtd", "#xx:16", 4, { B(0x11), B(0x1c), Data16Op, END }, { AddrIMM } },
	{ PRTS, "prts", "", 2, { B(0x11), B(0x19), END }, { AddrINVALID } },
	{ RTD, "rtd", "#xx:8", 2, { B(0x14), Data8Op, END }, { AddrIMM } },
	{ RTD, "rtd", "#xx:16", 3, { B(0x1c), Data16Op, END }, { AddrIMM } },
	{ RTE, "rte", "", 1, { B(0x0a), END }, { AddrINVALID } },
	{ RTS, "rts", "", 1, { B(0x19), END }, { AddrINVALID } },
	{ SCB_F, "scb/f", "Rn" SEP "disp", 3, { B(0x01), HR(0x17), Disp8Op, END }, { AddrREG, AddrPCRel } },
	{ SCB_NE, "scb/ne", "Rn" SEP "disp", 3, { B(0x06), HR(0x17), Disp8Op, END }, { AddrREG, AddrPCRel } },
	{ SCB_EQ, "scb/eq", "Rn" SEP "disp", 3, { B(0x07), HR(0x17), Disp8Op, END }, { AddrREG, AddrPCRel } },
	{ SLEEP, "sleep", "", 1, { B(0x1a), END }, { AddrINVALID } },
	{ STM, "stm.<Sz>", "<register list>" SEP "@-SP", 2, { B(0x12), RegList | HasOperand, END }, { RegList, ARG_PACK_DATA(SP_IDX) | AddrRIPreDec }, EA_BanIMM },
	{ SWAP, "swap", "Rn", 2, { HR(0x14), B(0x10), END }, { AddrREG } },
	{ TRAPA, "trapa", "#xx", 2, { B(0x08), H(0x1) | VEC | Data4 | HasOperand, END }, { AddrIMM } },
	{ TRAP_VS, "trap/vs", "", 1, { B(0x09), END }, { AddrINVALID } },
	{ UNLK, "unlk", "fp", 1, { B(0x0f), END }, { AddrINVALID } },
	{ XCH, "xch", "Rn" SEP "Rn", 2, { HR(0x15), HR(0x12), END }, { AddrREG, AddrREG } },
	{ XORC, "xorc.<Sz>", "#xx:8" SEP "CR", 3, { B(0x04), Data8Op, HC(0x0D), END }, { AddrIMM, AddrREGcr } },
	{ XORC, "xorc.<Sz>", "#xx:16" SEP "CR", 4, { B(0x0c), Data16Op, HC(0x0D), END }, { AddrIMM, AddrREGcr } },

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
	const CCRDescribe *ccr = &h8500_ccrs[crr];
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
		rz_warn_if_reached();
		return NULL;
	}
	return h8500_rns[i];
}

const char *h8500_reg_name(const H8500Operand *op, ut8 reg) {
	if (!(op->flags & Crr))
		return Rn_to_string(reg);
	const CCRDescribe *ccr = get_ccr_describe(reg);
	if (!ccr) {
		return NULL;
	}
	return ccr->name;
}

static const char *cc_mnemonic(ut8 i) {
	if (i >= RZ_ARRAY_SIZE(h8500_cc_mnemonics)) {
		rz_warn_if_reached();
		return NULL;
	}
	return h8500_cc_mnemonics[i];
}

static bool pat_const_check(ut64 pat, ut32 b) {
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
	ut64 mode = ea_describe->flags & ARG_MASK_AddressingMode;
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

static bool str_replace_once_no_heap(const char *str, const char *key, const char *val, ut64 sz) {
	rz_return_val_if_fail(str && key && val, false);
	char *p = strstr(str, key);
	if (!p) {
		return false;
	}
	size_t key_len = strlen(key);
	size_t val_len = strlen(val);
	size_t tail_len = strlen(p + key_len);
	if (strlen(str) + val_len - key_len + 1 > sz) {
		rz_warn_if_reached();
		return false;
	}
	// Move the tail part to make space for the new value
	memmove(p + val_len, p + key_len, tail_len + 1);
	memcpy(p, val, val_len);
	return true;
}

static bool operand_to_string(char *out, size_t len, H8500Operand *op) {
	char buf[16] = { 0 };
	switch (op->flags & ARG_MASK_AddressingMode) {
	case AddrREG:
	case AddrRI:
	case AddrRIPreDec:
	case AddrRIPostInc:
		if (op->flags & Crr) {
			if (!get_ccr_describe(op->rn)) {
				rz_warn_if_reached();
				return false;
			}
			str_replace_once_no_heap(out, "CR", get_ccr_describe(op->rn)->name, len);
		} else {
			str_replace_once_no_heap(out, "Rn", Rn_to_string(op->rn), len);
		}

		break;
	case AddrRIDisp:
		str_replace_once_no_heap(out, "Rn", Rn_to_string(op->ri_disp.rn), len);
		rz_strf(buf, "%d", op->ri_disp.disp);
		str_replace_once_no_heap(out, "d", buf, len);
		break;
	case AddrAbs:
		rz_strf(buf, "0x%x", op->aa);
		str_replace_once_no_heap(out, "aa", buf, len);
		break;
	case AddrIMM:
		rz_strf(buf, "0x%x", op->imm);
		str_replace_once_no_heap(out, "xx", buf, len);
		break;
	case AddrPCRel:
		rz_strf(buf, "%+d", op->disp);
		str_replace_once_no_heap(out, "disp", buf, len);
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
		str_replace_once_no_heap(out, "<register list>", rz_strbuf_get(&sb), len);
		rz_strbuf_fini(&sb);
	}
	return true;
}

static bool h8500_ea_parse(const ut8 *buf, int len, H8500Instruction *ins) {
	const H8500EADescribe *ea_describe = NULL;
	for (int i = 0; i < RZ_ARRAY_SIZE(h8500_eas); ++i) {
		ea_describe = &h8500_eas[i];
		for (int j = 0;; j += 1) {
			if (ea_describe->pats[j] == END) {
				ins->ea_describe = ea_describe;
				ins->ea.flags = ea_describe->flags;
				return true;
			}
			if (!EA_parse(buf, j, len - j, ea_describe, ins)) {
				break;
			}
		}
	}
	return false;
}

static ut8 operand_index(H8500Pat pat, H8500Instruction *ins) {
	ut8 operand_index = (pat & HasINDEX)
		? ((pat & MASK_INDEX) >> MASK_INDEX_OFF)
		: ins->num_operands;
	rz_warn_if_fail(operand_index < RZ_ARRAY_SIZE(ins->operands));
	return operand_index;
}

static bool operand_parse(const ut8 *buf, size_t pat_index, int len,
	const H8500OpcodeDescribe *opcode_describe, H8500Instruction *ins) {
	if (len <= pat_index) {
		return false;
	}
	const H8500Pat *pats = opcode_describe->pats;
	ut8 b = buf[pat_index];
	H8500Pat pat = pats[pat_index];
	if (!pat_const_check(pat, b)) {
		return false;
	}

	H8500Operand *op = &ins->operands[operand_index(pat, ins)];
	ut64 mode = opcode_describe->args[operand_index(pat, ins)] & ARG_MASK_AddressingMode;

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
		if (len <= pat_index + 1) {
			return false;
		}
		H8500Pat patl = pats[pat_index + 1];
		ut8 new_pat_index = operand_index(patl, ins);
		if (new_pat_index >= RZ_ARRAY_SIZE(ins->operands)) {
			rz_warn_if_reached();
			return false;
		}
		op = &ins->operands[new_pat_index];
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

bool h8500_instruction_get_opstr(H8500Instruction *ins, H8500InstructionOpstr *opstr) {
	rz_return_val_if_fail(ins && opstr, false);
	memset(opstr, 0, sizeof(H8500InstructionOpstr));
	const H8500OpcodeDescribe *opcode_describe = ins->opcode_describe;
	char ea_str_buf[16] = { 0 };
	rz_str_ncpy(opstr->mnemonic, opcode_describe->mnemonic, RZ_ARRAY_SIZE(opstr->mnemonic));
	if (ins->opcode_describe->id == Bcc) {
		str_replace_once_no_heap(opstr->mnemonic, "<cc>",
			cc_mnemonic(ins->condition_code), RZ_ARRAY_SIZE(opstr->mnemonic));
	} else {
		str_replace_once_no_heap(opstr->mnemonic, "<Sz>",
			(ins->operand_size == WORD_OPERAND) ? "w" : "b", RZ_ARRAY_SIZE(opstr->mnemonic));
	}

	rz_str_ncpy(opstr->ops_str, opcode_describe->op_mnemonic, RZ_ARRAY_SIZE(opstr->ops_str));
	if (ins->ea_describe) {
		rz_str_ncpy(ea_str_buf, ins->ea_describe->mnemonic, RZ_ARRAY_SIZE(ea_str_buf));
		operand_to_string(ea_str_buf, RZ_ARRAY_SIZE(ea_str_buf), &ins->ea);
		str_replace_once_no_heap(opstr->ops_str, "<EA>", ea_str_buf, RZ_ARRAY_SIZE(opstr->ops_str));
	}
	for (int i = 0; i < ins->num_operands; ++i) {
		operand_to_string(opstr->ops_str, RZ_ARRAY_SIZE(opstr->ops_str), &ins->operands[i]);
	}
	return true;
}

static H8500Operand *insert_operand(H8500Instruction *ins, int index) {
	if (ins->num_operands + 1 >= RZ_ARRAY_SIZE(ins->operands) || index > ins->num_operands + 1) {
		rz_warn_if_reached();
		return NULL;
	}
	if (index < ins->num_operands && ins->num_operands > 0) {
		memmove(ins->operands + index + 1, ins->operands + index, sizeof(H8500Operand) * (ins->num_operands - index));
		memset(&ins->operands[index], 0, sizeof(H8500Operand));
	}
	ins->num_operands++;
	return &ins->operands[index];
}

static bool h8500_opcode_parse(const ut8 *buf, size_t offset, int len, H8500Instruction *ins, const H8500OpcodeDescribe *tbl, ut32 tbl_size) {
	if (len < offset + 1) {
		return false;
	}
	const H8500OpcodeDescribe *opcode_describe = NULL;
	for (int i = 0; i < tbl_size; ++i) {
		opcode_describe = &tbl[i];
		for (int j = 0;; j += 1) {
			if (opcode_describe->pats[j] == END) {
				if ((opcode_describe->ea_flags & EA_BanIMM) &&
					ins->ea_describe &&
					((ins->ea_describe->flags & ARG_MASK_AddressingMode) == AddrIMM)) {
					goto branch_next;
				}
				// All patterns for this opcode match,
				// but I want to use the hint in `args` to verify whether the operands are correct and modify the operands accordingly.
				int ops_count = 0;
				for (int k = 0; k < RZ_ARRAY_SIZE(opcode_describe->args); ++k) {
					H8500Pat arg = opcode_describe->args[k];
					if (arg == AddrINVALID) {
						break;
					}
					if (arg == EA) {
						continue;
					}
#define INS_OP(I) (&ins->operands[I])
					if (INS_OP(ops_count)->flags != ARG_FLAGS(arg)) {
						if (ARG_DATA(arg) != 0) {
							H8500Operand *op = insert_operand(ins, ops_count);
							op->flags = ARG_FLAGS(arg);
							switch (ARG_MODE(arg)) {
							case AddrIMM:
								op->imm = ARG_DATA(arg);
								break;
							case AddrRIPostInc:
							case AddrRIPreDec:
								op->rn = ARG_DATA(arg);
								break;
							default:
								rz_warn_if_reached();
								break;
							}
						} else if (ARG_MODE(INS_OP(ops_count)->flags) == AddrREG && ARG_MODE(arg) == AddrRI) {
							INS_OP(ops_count)->flags = ARG_FLAGS(arg);
						} else {
							rz_warn_if_reached();
						}
					}
					ops_count++;
				}
				if (ins->num_operands != ops_count) {
					RZ_LOG_ERROR("invalid number of %s %s operands: %d, expect: %d\n",
						opcode_describe->mnemonic, opcode_describe->op_mnemonic, ins->num_operands, ops_count);
				}
				ins->opcode_describe = opcode_describe;
				return true;
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
}

bool h8500_instruction_parse(const ut8 *buf, int len, H8500Instruction *ins) {
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
	return true;
}
