// SPDX-FileCopyrightText: 2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pic16.h"

const char *pic16_regname(ut32 reg) {
	const char *Pic16Bank0[] = {
		"indf0",
		"indf1",
		"pcl",
		"status",
		"fsr0l",
		"fsr0h",
		"fsr1l",
		"fsr1h",
		"bsr",
		"wreg",
		"pclath",
		"intcon",
		"porta",
		"portb",
		"portc",
		"portd",
		"porte",
		"pir1",
		"pir2",
		"pir3",
		"---",
		"tmr0",
		"tmr1l",
		"tmr1h",
		"t1con",
		"t1con",
		"tmr2",
		"pr2",
		"t2con",
		"---",
		"cpscon0",
		"cpscon1",
	};

	if (reg >= RZ_ARRAY_SIZE(Pic16Bank0)) {
		return NULL;
	}
	return Pic16Bank0[reg];
}

static const Pic16OpAsmInfo pic16_op_info[PIC16_OPCODE_INVALID] = {
	{ "nop", PIC16_OP_ARGS_NONE },
	{ "return", PIC16_OP_ARGS_NONE },
	{ "retfie", PIC16_OP_ARGS_NONE },
	{ "option", PIC16_OP_ARGS_NONE },
	{ "sleep", PIC16_OP_ARGS_NONE },
	{ "clrwdt", PIC16_OP_ARGS_NONE },
	{ "clrf", PIC16_OP_ARGS_7F },
	{ "clrw", PIC16_OP_ARGS_NONE },
	{ "tris", PIC16_OP_ARGS_2F },
	{ "movwf", PIC16_OP_ARGS_7F },
	{ "subwf", PIC16_OP_ARGS_1D_7F },
	{ "decf", PIC16_OP_ARGS_1D_7F },
	{ "iorwf", PIC16_OP_ARGS_1D_7F },
	{ "andwf", PIC16_OP_ARGS_1D_7F },
	{ "xorwf", PIC16_OP_ARGS_1D_7F },
	{ "addwf", PIC16_OP_ARGS_1D_7F },
	{ "movf", PIC16_OP_ARGS_1D_7F },
	{ "comf", PIC16_OP_ARGS_1D_7F },
	{ "incf", PIC16_OP_ARGS_1D_7F },
	{ "decfsz", PIC16_OP_ARGS_1D_7F },
	{ "rrf", PIC16_OP_ARGS_1D_7F },
	{ "rlf", PIC16_OP_ARGS_1D_7F },
	{ "swapf", PIC16_OP_ARGS_1D_7F },
	{ "incfsz", PIC16_OP_ARGS_1D_7F },
	{ "bcf", PIC16_OP_ARGS_3B_7F },
	{ "bsf", PIC16_OP_ARGS_3B_7F },
	{ "btfsc", PIC16_OP_ARGS_3B_7F },
	{ "btfss", PIC16_OP_ARGS_3B_7F },
	{ "call", PIC16_OP_ARGS_11K },
	{ "goto", PIC16_OP_ARGS_11K },
	{ "movlw", PIC16_OP_ARGS_8K },
	{ "retlw", PIC16_OP_ARGS_8K },
	{ "iorlw", PIC16_OP_ARGS_8K },
	{ "andlw", PIC16_OP_ARGS_8K },
	{ "xorlw", PIC16_OP_ARGS_8K },
	{ "sublw", PIC16_OP_ARGS_8K },
	{ "addlw", PIC16_OP_ARGS_8K },
	{ "reset", PIC16_OP_ARGS_NONE },
	{ "callw", PIC16_OP_ARGS_NONE },
	{ "brw", PIC16_OP_ARGS_NONE },
	{ "moviw", PIC16_OP_ARGS_1N_2M },
	{ "movwi", PIC16_OP_ARGS_1N_2M },
	{ "movlb", PIC16_OP_ARGS_4K },
	{ "lslf", PIC16_OP_ARGS_1D_7F },
	{ "lsrf", PIC16_OP_ARGS_1D_7F },
	{ "asrf", PIC16_OP_ARGS_1D_7F },
	{ "subwfb", PIC16_OP_ARGS_1D_7F },
	{ "addwfc", PIC16_OP_ARGS_1D_7F },
	{ "addfsr", PIC16_OP_ARGS_1N_6K },
	{ "movlp", PIC16_OP_ARGS_7F },
	{ "bra", PIC16_OP_ARGS_9K },
	{ "moviw", PIC16_OP_ARGS_1N_6K },
	{ "movwi", PIC16_OP_ARGS_1N_6K }
};

static const char *Pic16FsrOps[] = { "++FSR%d", "--FSR%d", "FSR%d++",
	"FSR%d--" };

/**
 * \brief Decode a Pic 16 instruction to it's corresponding opcode enum.
 * */
Pic16Opcode pic16_get_opcode(ut16 instr) {
	switch (instr >> 11) { // 3 first MSB bits
	case 0x4: return PIC16_OPCODE_CALL;
	case 0x5: return PIC16_OPCODE_GOTO;
	}

	switch (instr >> 10) { // 4 first MSB bits
	case 0x4: return PIC16_OPCODE_BCF;
	case 0x5: return PIC16_OPCODE_BSF;
	case 0x6: return PIC16_OPCODE_BTFSC;
	case 0x7: return PIC16_OPCODE_BTFSS;
	}

	switch (instr >> 9) { // 5 first MSB bits
	case 0x19: return PIC16_OPCODE_BRA;
	}

	switch (instr >> 8) { // 6 first MSB bits
	case 0x2: return PIC16_OPCODE_SUBWF;
	case 0x3: return PIC16_OPCODE_DECF;
	case 0x4: return PIC16_OPCODE_IORWF;
	case 0x5: return PIC16_OPCODE_ANDWF;
	case 0x6: return PIC16_OPCODE_XORWF;
	case 0x7: return PIC16_OPCODE_ADDWF;
	case 0x8: return PIC16_OPCODE_MOVF;
	case 0x9: return PIC16_OPCODE_COMF;
	case 0xa: return PIC16_OPCODE_INCF;
	case 0xb: return PIC16_OPCODE_DECFSZ;
	case 0xc: return PIC16_OPCODE_RRF;
	case 0xd: return PIC16_OPCODE_RLF;
	case 0xe: return PIC16_OPCODE_SWAPF;
	case 0xf: return PIC16_OPCODE_INCFSZ;
	case 0x38: return PIC16_OPCODE_IORLW;
	case 0x39: return PIC16_OPCODE_ANDLW;
	case 0x3a: return PIC16_OPCODE_XORLW;
	case 0x30: return PIC16_OPCODE_MOVLW;
	case 0x34: return PIC16_OPCODE_RETLW;
	case 0x3c: return PIC16_OPCODE_SUBLW;
	case 0x3e: return PIC16_OPCODE_ADDLW;
	case 0x35: return PIC16_OPCODE_LSLF;
	case 0x36: return PIC16_OPCODE_LSRF;
	case 0x37: return PIC16_OPCODE_ASRF;
	case 0x3b: return PIC16_OPCODE_SUBWFB;
	case 0x3d: return PIC16_OPCODE_ADDWFC;
	}

	switch (instr >> 7) { // 7 first MSB bits
	case 0x1: return PIC16_OPCODE_MOVWF;
	case 0x2: return PIC16_OPCODE_CLRW;
	case 0x3: return PIC16_OPCODE_CLRF;
	case 0x62: return PIC16_OPCODE_ADDFSR;
	case 0x63: return PIC16_OPCODE_MOVLP;
	case 0x7e: return PIC16_OPCODE_MOVIW_2;
	case 0x7f: return PIC16_OPCODE_MOVWI_2;
	}

	switch (instr >> 5) { // 9 first MSB bits
	case 0x1: return PIC16_OPCODE_MOVLB;
	}

	switch (instr >> 3) { // 11 first MSB bits
	case 0x2: return PIC16_OPCODE_MOVIW_1;
	case 0x3: return PIC16_OPCODE_MOVWI_1;
	}

	switch (instr >> 2) { // 12 first MSB bits
	case 0x19: return PIC16_OPCODE_TRIS;
	}

	switch (instr) {
	case 0x0: return PIC16_OPCODE_NOP;
	case 0x1: return PIC16_OPCODE_RESET;
	case 0xa: return PIC16_OPCODE_CALLW;
	case 0xb: return PIC16_OPCODE_BRW;
	case 0x8: return PIC16_OPCODE_RETURN;
	case 0x9: return PIC16_OPCODE_RETFIE;
	case 0x62: return PIC16_OPCODE_OPTION;
	case 0x63: return PIC16_OPCODE_SLEEP;
	case 0x64: return PIC16_OPCODE_CLRWDT;
	}

	return PIC16_OPCODE_INVALID;
}

static void analysis_pic16_extract_args(
	ut16 instr,
	Pic16OpArgs args,
	Pic16OpArgsVal *args_val) {

	memset(args_val, 0, sizeof(Pic16OpArgsVal));

	switch (args) {
	case PIC16_OP_ARGS_NONE: return;
	case PIC16_OP_ARGS_2F:
		args_val->f = instr & PIC16_OP_ARGS_2F_MASK_F;
		return;
	case PIC16_OP_ARGS_7F:
		args_val->f = instr & PIC16_OP_ARGS_7F_MASK_F;
		return;
	case PIC16_OP_ARGS_1D_7F:
		args_val->f = instr & PIC16_OP_ARGS_1D_7F_MASK_F;
		args_val->d =
			(instr & PIC16_OP_ARGS_1D_7F_MASK_D) >> 7;
		return;
	case PIC16_OP_ARGS_1N_6K:
		args_val->n = (instr & PIC16_OP_ARGS_1N_6K_MASK_N) >> 6;
		args_val->k = instr & PIC16_OP_ARGS_1N_6K_MASK_K;
		return;
	case PIC16_OP_ARGS_3B_7F:
		args_val->b = (instr & PIC16_OP_ARGS_3B_7F_MASK_B) >> 7;
		args_val->f = instr & PIC16_OP_ARGS_3B_7F_MASK_F;
		return;
	case PIC16_OP_ARGS_4K:
		args_val->k = instr & PIC16_OP_ARGS_4K_MASK_K;
		return;
	case PIC16_OP_ARGS_8K:
		args_val->k = instr & PIC16_OP_ARGS_8K_MASK_K;
		return;
	case PIC16_OP_ARGS_9K:
		args_val->k = instr & PIC16_OP_ARGS_9K_MASK_K;
		return;
	case PIC16_OP_ARGS_11K:
		args_val->k = instr & PIC16_OP_ARGS_11K_MASK_K;
		return;
	case PIC16_OP_ARGS_1N_2M:
		args_val->n = (instr & PIC16_OP_ARGS_1N_2M_MASK_N) >> 2;
		args_val->m = instr & PIC16_OP_ARGS_1N_2M_MASK_M;
		return;
	}
}

/**
 * \brief Get opcode information (mnemonic and arguments) corresponding
 * to a given \c Pic16Opcode.
 *
 * \param opcode
 * \return \c Pic16OpInfo pointer.
 * */
const Pic16OpAsmInfo *pic16_get_op_info(Pic16Opcode opcode) {
	if (opcode >= PIC16_OPCODE_INVALID) {
		return NULL;
	}
	return &pic16_op_info[opcode];
}

#define F pic16_regname(op->args.f)

bool pic16_disasm_op(Pic16Op *op, ut64 addr, const ut8 *b, ut64 l) {
	if (!b || l < 2) {
		return false;
	}

	op->instr = rz_read_le16(b) & 0x3fff;
	Pic16Opcode opcode = pic16_get_opcode(op->instr);
	if (opcode == PIC16_OPCODE_INVALID) {
		return false;
	}
	const Pic16OpAsmInfo *op_info = pic16_get_op_info(opcode);
	if (!op_info) {
		return false;
	}

	op->opcode = opcode;
	op->size = 2;
	op->addr = addr;
	op->mnemonic = op_info->mnemonic;
	op->args_tag = op_info->args;
	analysis_pic16_extract_args(op->instr, op_info->args, &op->args);

	st16 branch;
	switch (op_info->args) {
	case PIC16_OP_ARGS_NONE:
		break;
	case PIC16_OP_ARGS_2F:
	case PIC16_OP_ARGS_7F:
		if (F) {
			rz_strf(op->operands, "%s", F);
		} else {
			rz_strf(op->operands, "0x%x", op->args.f);
		}
		break;
	case PIC16_OP_ARGS_1D_7F:
		if (F) {
			rz_strf(op->operands, "%s, %d", F, op->args.d);
		} else {
			rz_strf(op->operands, "0x%x, %d", op->args.f, op->args.d);
		}
		break;
	case PIC16_OP_ARGS_1N_6K:
		if (opcode == PIC16_OPCODE_ADDFSR) {
			rz_strf(op->operands, "FSR%d, 0x%x", op->args.n, op->args.k);
		} else {
			rz_strf(op->operands, "0x%x[FSR%d]", op->args.k, op->args.n);
		}
		break;
	case PIC16_OP_ARGS_3B_7F:
		if (F) {
			rz_strf(op->operands, "%s, %d", F, op->args.b);
		} else {
			rz_strf(op->operands, "0x%x, %d", op->args.f, op->args.b);
		}
		break;
	case PIC16_OP_ARGS_4K:
	case PIC16_OP_ARGS_8K:
	case PIC16_OP_ARGS_11K:
		rz_strf(op->operands, "0x%x", op->args.k);
		break;
	case PIC16_OP_ARGS_9K:
		branch = op->args.k;
		branch |= ((branch & 0x100) ? 0xfe00 : 0);
		rz_strf(op->operands, "%s0x%x",
			branch < 0 ? "-" : "",
			(branch < 0 ? -branch : branch));
		break;
	case PIC16_OP_ARGS_1N_2M:
		rz_strf(op->operands, Pic16FsrOps[op->args.m], op->args.n);
		break;
	default:
		break;
	}
	return true;
}

/**
 * \brief Disassemble a PIC 16 instruction.
 *
 * \param op RzAsmOp to tell number of instructions decoded.
 * \param opbuf Decoded instruction mnemonic will be stored in this before return.
 * \param b Opcode buffer containing Pic16 opcodes.
 * \param l Length of opcode buffer \p b.
 *
 * \return Number of decoded bytes (2 on success, 1 on failure).
 * */
int pic16_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *b, int l) {
#define EMIT_INVALID \
	{ \
		op->size = 2; \
		rz_asm_op_set_asm(op, "invalid"); \
		return 1; \
	}

	Pic16Op x = { 0 };
	if (!pic16_disasm_op(&x, a->pc, b, l)) {
		EMIT_INVALID;
	}

	op->size = x.size;
	if (x.operands[0]) {
		rz_asm_op_setf_asm(op, "%s %s", x.mnemonic, x.operands);
	} else {
		rz_asm_op_setf_asm(op, x.mnemonic);
	}

	return op->size;
}
