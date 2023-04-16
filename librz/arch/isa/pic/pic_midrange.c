// SPDX-FileCopyrightText: 2018 courk <courk@courk.cc>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pic_midrange.h"

static const PicMidrangeOpInfo
	pic_midrange_op_info[PIC_MIDRANGE_OPCODE_INVALID] = {
		{ "nop", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "return", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "retfie", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "option", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "sleep", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "clrwdt", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "tris", PIC_MIDRANGE_OP_ARGS_2F },
		{ "movwf", PIC_MIDRANGE_OP_ARGS_7F },
		{ "clr", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "subwf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "decf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "iorwf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "andwf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "xorwf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "addwf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "movf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "comf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "incf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "decfsz", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "rrf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "rlf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "swapf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "incfsz", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "bcf", PIC_MIDRANGE_OP_ARGS_3B_7F },
		{ "bsf", PIC_MIDRANGE_OP_ARGS_3B_7F },
		{ "btfsc", PIC_MIDRANGE_OP_ARGS_3B_7F },
		{ "btfss", PIC_MIDRANGE_OP_ARGS_3B_7F },
		{ "call", PIC_MIDRANGE_OP_ARGS_11K },
		{ "goto", PIC_MIDRANGE_OP_ARGS_11K },
		{ "movlw", PIC_MIDRANGE_OP_ARGS_8K },
		{ "retlw", PIC_MIDRANGE_OP_ARGS_8K },
		{ "iorlw", PIC_MIDRANGE_OP_ARGS_8K },
		{ "andlw", PIC_MIDRANGE_OP_ARGS_8K },
		{ "xorlw", PIC_MIDRANGE_OP_ARGS_8K },
		{ "sublw", PIC_MIDRANGE_OP_ARGS_8K },
		{ "addlw", PIC_MIDRANGE_OP_ARGS_8K },
		{ "reset", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "callw", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "brw", PIC_MIDRANGE_OP_ARGS_NONE },
		{ "moviw", PIC_MIDRANGE_OP_ARGS_1N_2M },
		{ "movwi", PIC_MIDRANGE_OP_ARGS_1N_2M },
		{ "movlb", PIC_MIDRANGE_OP_ARGS_4K },
		{ "lslf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "lsrf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "asrf", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "subwfb", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "addwfc", PIC_MIDRANGE_OP_ARGS_1D_7F },
		{ "addfsr", PIC_MIDRANGE_OP_ARGS_1N_6K },
		{ "movlp", PIC_MIDRANGE_OP_ARGS_7F },
		{ "bra", PIC_MIDRANGE_OP_ARGS_9K },
		{ "moviw", PIC_MIDRANGE_OP_ARGS_1N_6K },
		{ "movwi", PIC_MIDRANGE_OP_ARGS_1N_6K }
	};

static const char *PicMidrangeFsrOps[] = { "++FSR%d", "--FSR%d", "FSR%d++",
	"FSR%d--" };

/**
 * \brief Decode a Pic Midrange instruction to it's corresponding opcode enum.
 * */
PicMidrangeOpcode pic_midrange_get_opcode(ut16 instr) {
	if (instr & (1 << 14)) {
		return PIC_MIDRANGE_OPCODE_INVALID;
	}

	switch (instr >> 11) { // 3 first MSB bits
	case 0x4: return PIC_MIDRANGE_OPCODE_CALL;
	case 0x5: return PIC_MIDRANGE_OPCODE_GOTO;
	}

	switch (instr >> 10) { // 4 first MSB bits
	case 0x4: return PIC_MIDRANGE_OPCODE_BCF;
	case 0x5: return PIC_MIDRANGE_OPCODE_BSF;
	case 0x6: return PIC_MIDRANGE_OPCODE_BTFSC;
	case 0x7: return PIC_MIDRANGE_OPCODE_BTFSS;
	}

	switch (instr >> 9) { // 5 first MSB bits
	case 0x19: return PIC_MIDRANGE_OPCODE_BRA;
	}

	switch (instr >> 8) { // 6 first MSB bits
	case 0x1: return PIC_MIDRANGE_OPCODE_CLR;
	case 0x2: return PIC_MIDRANGE_OPCODE_SUBWF;
	case 0x3: return PIC_MIDRANGE_OPCODE_DECF;
	case 0x4: return PIC_MIDRANGE_OPCODE_IORWF;
	case 0x5: return PIC_MIDRANGE_OPCODE_ANDWF;
	case 0x6: return PIC_MIDRANGE_OPCODE_XORWF;
	case 0x7: return PIC_MIDRANGE_OPCODE_ADDWF;
	case 0x8: return PIC_MIDRANGE_OPCODE_MOVF;
	case 0x9: return PIC_MIDRANGE_OPCODE_COMF;
	case 0xa: return PIC_MIDRANGE_OPCODE_INCF;
	case 0xb: return PIC_MIDRANGE_OPCODE_DECFSZ;
	case 0xc: return PIC_MIDRANGE_OPCODE_RRF;
	case 0xd: return PIC_MIDRANGE_OPCODE_RLF;
	case 0xe: return PIC_MIDRANGE_OPCODE_SWAPF;
	case 0xf: return PIC_MIDRANGE_OPCODE_INCFSZ;
	case 0x38: return PIC_MIDRANGE_OPCODE_IORLW;
	case 0x39: return PIC_MIDRANGE_OPCODE_ANDLW;
	case 0x3a: return PIC_MIDRANGE_OPCODE_XORLW;
	case 0x30: return PIC_MIDRANGE_OPCODE_MOVLW;
	case 0x34: return PIC_MIDRANGE_OPCODE_RETLW;
	case 0x3c: return PIC_MIDRANGE_OPCODE_SUBLW;
	case 0x3e: return PIC_MIDRANGE_OPCODE_ADDLW;
	case 0x35: return PIC_MIDRANGE_OPCODE_LSLF;
	case 0x36: return PIC_MIDRANGE_OPCODE_LSRF;
	case 0x37: return PIC_MIDRANGE_OPCODE_ASRF;
	case 0x3b: return PIC_MIDRANGE_OPCODE_SUBWFB;
	case 0x3d: return PIC_MIDRANGE_OPCODE_ADDWFC;
	}

	switch (instr >> 7) { // 7 first MSB bits
	case 0x1: return PIC_MIDRANGE_OPCODE_MOVWF;
	case 0x62: return PIC_MIDRANGE_OPCODE_ADDFSR;
	case 0x63: return PIC_MIDRANGE_OPCODE_MOVLP;
	case 0x7e: return PIC_MIDRANGE_OPCODE_MOVIW_2;
	case 0x7f: return PIC_MIDRANGE_OPCODE_MOVWI_2;
	}

	switch (instr >> 5) { // 9 first MSB bits
	case 0x1: return PIC_MIDRANGE_OPCODE_MOVLB;
	}

	switch (instr >> 3) { // 11 first MSB bits
	case 0x2: return PIC_MIDRANGE_OPCODE_MOVIW_1;
	case 0x3: return PIC_MIDRANGE_OPCODE_MOVWI_1;
	}

	switch (instr >> 2) { // 12 first MSB bits
	case 0x19: return PIC_MIDRANGE_OPCODE_TRIS;
	}

	switch (instr) {
	case 0x0: return PIC_MIDRANGE_OPCODE_NOP;
	case 0x1: return PIC_MIDRANGE_OPCODE_RESET;
	case 0xa: return PIC_MIDRANGE_OPCODE_CALLW;
	case 0xb: return PIC_MIDRANGE_OPCODE_BRW;
	case 0x8: return PIC_MIDRANGE_OPCODE_RETURN;
	case 0x9: return PIC_MIDRANGE_OPCODE_RETFIE;
	case 0x62: return PIC_MIDRANGE_OPCODE_OPTION;
	case 0x63: return PIC_MIDRANGE_OPCODE_SLEEP;
	case 0x64: return PIC_MIDRANGE_OPCODE_CLRWDT;
	}

	return PIC_MIDRANGE_OPCODE_INVALID;
}

/**
 * \brief Get \c PicMidrangeOpArgs corresponding to given \c PicMidrangeOpcode.
 *
 * \param opcode
 * \return Corresponding \c OpArgs enum, -1 on failure.
 * */
PicMidrangeOpArgs pic_midrange_get_opargs(PicMidrangeOpcode opcode) {
	if (opcode >= PIC_MIDRANGE_OPCODE_INVALID) {
		return -1;
	}
	return pic_midrange_op_info[opcode].args;
}

/**
 * \brief Get opcode information (mnemonic and arguments) corresponding
 * to a given \c PicMidrangeOpcode.
 *
 * \param opcode
 * \return \c PicMidrangeOpInfo pointer.
 * */
const PicMidrangeOpInfo *pic_midrange_get_op_info(PicMidrangeOpcode opcode) {
	if (opcode >= PIC_MIDRANGE_OPCODE_INVALID) {
		return NULL;
	}
	return &pic_midrange_op_info[opcode];
}

/**
 * \brief Disassemble a PIC Midrange instruction.
 *
 * \param op RzAsmOp to tell number of instructions decoded.
 * \param opbuf Decoded instruction mnemonic will be stored in this before return.
 * \param b Opcode buffer containing PicMidrange opcodes.
 * \param l Length of opcode buffer \p b.
 *
 * \return Number of decoded bytes (2 on success, 1 on failure).
 * */
int pic_midrange_disassemble(RzAsmOp *op, const ut8 *b, int l) {
	char fsr_op[6];
	st16 branch;

#define EMIT_INVALID \
	{ \
		op->size = 2; \
		rz_asm_op_set_asm(op, "invalid"); \
		return 1; \
	}
	if (!b || l < 2) {
		EMIT_INVALID
	}

	ut16 instr = rz_read_le16(b);
	PicMidrangeOpcode opcode = pic_midrange_get_opcode(instr);
	if (opcode == PIC_MIDRANGE_OPCODE_INVALID) {
		EMIT_INVALID
	}

	const PicMidrangeOpInfo *op_info = pic_midrange_get_op_info(opcode);
	if (!op_info) {
		EMIT_INVALID
	}

#undef EMIT_INVALID

	op->size = 2;

	switch (op_info->args) {
	case PIC_MIDRANGE_OP_ARGS_NONE:
		rz_asm_op_set_asm(op, op_info->mnemonic);
		break;
	case PIC_MIDRANGE_OP_ARGS_2F:
		rz_asm_op_setf_asm(op, "%s 0x%x", op_info->mnemonic,
			PIC_MIDRANGE_OP_ARGS_2F_GET_F(instr));
		break;
	case PIC_MIDRANGE_OP_ARGS_7F:
		rz_asm_op_setf_asm(op, "%s 0x%x", op_info->mnemonic,
			PIC_MIDRANGE_OP_ARGS_7F_GET_F(instr));
		break;
	case PIC_MIDRANGE_OP_ARGS_1D_7F:
		rz_asm_op_setf_asm(op, "%s 0x%x, %c", op_info->mnemonic,
			PIC_MIDRANGE_OP_ARGS_7F_GET_F(instr));
		break;
	case PIC_MIDRANGE_OP_ARGS_1N_6K:
		if (opcode == PIC_MIDRANGE_OPCODE_ADDFSR) {
			rz_asm_op_setf_asm(op, "%s FSR%d, 0x%x",
				op_info->mnemonic,
				PIC_MIDRANGE_OP_ARGS_1N_6K_GET_N(instr) >> 6,
				PIC_MIDRANGE_OP_ARGS_1N_6K_GET_K(instr));
		} else {
			rz_asm_op_setf_asm(op, "%s 0x%x[FSR%d]",
				op_info->mnemonic,
				PIC_MIDRANGE_OP_ARGS_1N_6K_GET_K(instr),
				PIC_MIDRANGE_OP_ARGS_1N_6K_GET_N(instr) >> 6);
		}
		break;
	case PIC_MIDRANGE_OP_ARGS_3B_7F:
		rz_asm_op_setf_asm(op, "%s 0x%x, %d",
			op_info->mnemonic,
			PIC_MIDRANGE_OP_ARGS_3B_7F_GET_F(instr),
			PIC_MIDRANGE_OP_ARGS_3B_7F_GET_B(instr));
		break;
	case PIC_MIDRANGE_OP_ARGS_4K:
		rz_asm_op_setf_asm(op, "%s 0x%x",
			op_info->mnemonic,
			PIC_MIDRANGE_OP_ARGS_4K_GET_K(instr));
		break;
	case PIC_MIDRANGE_OP_ARGS_8K:
		rz_asm_op_setf_asm(op, "%s 0x%x",
			op_info->mnemonic,
			PIC_MIDRANGE_OP_ARGS_8K_GET_K(instr));
		break;
	case PIC_MIDRANGE_OP_ARGS_9K:
		branch = PIC_MIDRANGE_OP_ARGS_9K_GET_K(instr);
		branch |= ((branch & 0x100) ? 0xfe00 : 0);
		rz_asm_op_setf_asm(op, "%s %s0x%x",
			op_info->mnemonic,
			branch < 0 ? "-" : "",
			(branch < 0 ? -branch : branch));
		break;
	case PIC_MIDRANGE_OP_ARGS_11K:
		rz_asm_op_setf_asm(op, "%s 0x%x",
			op_info->mnemonic,
			PIC_MIDRANGE_OP_ARGS_11K_GET_K(instr));
		break;
	case PIC_MIDRANGE_OP_ARGS_1N_2M:
		snprintf(fsr_op, sizeof(fsr_op),
			PicMidrangeFsrOps[instr & PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_M],
			PIC_MIDRANGE_OP_ARGS_1N_2M_GET_N(instr) >> 2);
		rz_asm_op_setf_asm(op, "%s %s", op_info->mnemonic, fsr_op);
		break;
	default:
		rz_asm_op_set_asm(op, "invalid");
		break;
	}

	return op->size;
}
