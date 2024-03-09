// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>

#include "pic_pic18.h"

// PIC18CXXX instruction set

// instruction classification according to the argument types

static char *fsr[] = { "fsr0", "fsr1", "fsr2", "reserved" };

typedef struct {
	Pic18Opcode code;
	ut16 opmin;
	ut16 opmax;
	char *name;
	Pic18ArgsKind optype;
	// and some magical hocus pocus ;)
} Pic18OpDesc;

static const Pic18OpDesc ops[] = {
	{ PIC18_OPCODE_NOP, 0xf000, 0xffff, "nop", NO_ARG },
	{ PIC18_OPCODE_GOTO, 0xef00, 0xefff, "goto", K20_T },
	{ PIC18_OPCODE_LFSR, 0xee00, 0xee3f, "lfsr", FK_T },
	{ PIC18_OPCODE_CALL, 0xec00, 0xedff, "call", K20S_T },
	{ PIC18_OPCODE_BNN, 0xe700, 0xe7ff, "bnn", N8_T },
	{ PIC18_OPCODE_BN, 0xe600, 0xe6ff, "bn", N8_T },
	{ PIC18_OPCODE_BNOV, 0xe500, 0xe5ff, "bnov", N8_T },
	{ PIC18_OPCODE_BOV, 0xe400, 0xe4ff, "bov", N8_T },
	{ PIC18_OPCODE_BNC, 0xe300, 0xe3ff, "bnc", N8_T },
	{ PIC18_OPCODE_BC, 0xe200, 0xe2ff, "bc", N8_T },
	{ PIC18_OPCODE_BNZ, 0xe100, 0xe1ff, "bnz", N8_T },
	{ PIC18_OPCODE_BZ, 0xe000, 0xe0ff, "bz", N8_T },
	{ PIC18_OPCODE_RCALL, 0xd800, 0xdfff, "rcall", N11_T },
	{ PIC18_OPCODE_BRA, 0xd000, 0xd7ff, "bra", N11_T },
	{ PIC18_OPCODE_MOVFF, 0xc000, 0xcfff, "movff", SD_T },
	{ PIC18_OPCODE_BTFSC, 0xb000, 0xbfff, "btfsc", BAF_T },
	{ PIC18_OPCODE_BTFSS, 0xa000, 0xafff, "btfss", BAF_T },
	{ PIC18_OPCODE_BCF, 0x9000, 0x9fff, "bcf", BAF_T },
	{ PIC18_OPCODE_BSF, 0x8000, 0x8fff, "bsf", BAF_T },
	{ PIC18_OPCODE_BTG, 0x7000, 0x7fff, "btg", BAF_T },
	{ PIC18_OPCODE_MOVWF, 0x6e00, 0x6fff, "movwf", FA_T },
	{ PIC18_OPCODE_NEGF, 0x6c00, 0x6dff, "negf", FA_T },
	{ PIC18_OPCODE_CLRF, 0x6a00, 0x6bff, "clrf", FA_T },
	{ PIC18_OPCODE_SETF, 0x6800, 0x69ff, "setf", FA_T },
	{ PIC18_OPCODE_TSTFSZ, 0x6600, 0x67ff, "tstfsz", FA_T },
	{ PIC18_OPCODE_CPFSQT, 0x6400, 0x65ff, "cpfsgt", FA_T },
	{ PIC18_OPCODE_CPFSEQ, 0x6200, 0x63ff, "cpfseq", FA_T },
	{ PIC18_OPCODE_CPFSLT, 0x6000, 0x61ff, "cpfslt", FA_T },
	{ PIC18_OPCODE_SUBWF, 0x5c00, 0x5fff, "subwf", FDA_T },
	{ PIC18_OPCODE_SUBWFB, 0x5800, 0x5bff, "subwfb", FDA_T },
	{ PIC18_OPCODE_SUBFWB, 0x5400, 0x57ff, "subfwb", FDA_T },
	{ PIC18_OPCODE_MOVF, 0x5000, 0x53ff, "movf", FDA_T },
	{ PIC18_OPCODE_DCFSNZ, 0x4c00, 0x4fff, "dcfsnz", FDA_T },
	{ PIC18_OPCODE_INFSNZ, 0x4800, 0x4bff, "infsnz", FDA_T },
	{ PIC18_OPCODE_RLNCF, 0x4400, 0x47ff, "rlncf", FDA_T },
	{ PIC18_OPCODE_RRNCF, 0x4000, 0x43ff, "rrncf", FDA_T },
	{ PIC18_OPCODE_INCFSZ, 0x3c00, 0x3fff, "incfsz", FDA_T },
	{ PIC18_OPCODE_SWAPF, 0x3800, 0x3bff, "swapf", FDA_T },
	{ PIC18_OPCODE_RLCF, 0x3400, 0x37ff, "rlcf", FDA_T },
	{ PIC18_OPCODE_RRCF, 0x3000, 0x33ff, "rrcf", FDA_T },
	{ PIC18_OPCODE_DECFSZ, 0x2c00, 0x2fff, "decfsz", FDA_T },
	{ PIC18_OPCODE_INCF, 0x2800, 0x2bff, "incf", FDA_T },
	{ PIC18_OPCODE_ADDWF, 0x2400, 0x27ff, "addwf", FDA_T },
	{ PIC18_OPCODE_ADDWFC, 0x2000, 0x23ff, "addwfc", FDA_T },
	{ PIC18_OPCODE_COMF, 0x1c00, 0x1fff, "comf", FDA_T },
	{ PIC18_OPCODE_XORWF, 0x1800, 0x1bff, "xorwf", FDA_T },
	{ PIC18_OPCODE_ANDWF, 0x1400, 0x17ff, "andwf", FDA_T },
	{ PIC18_OPCODE_IORWF, 0x1000, 0x13ff, "iorwf", FDA_T },
	{ PIC18_OPCODE_ADDLW, 0xf00, 0xfff, "addlw", K8_T },
	{ PIC18_OPCODE_MOVLW, 0xe00, 0xeff, "movlw", K8_T },
	{ PIC18_OPCODE_MULLW, 0xd00, 0xdff, "mullw", K8_T },
	{ PIC18_OPCODE_RETLW, 0xc00, 0xcff, "retlw", K8_T },
	{ PIC18_OPCODE_ANDLW, 0xb00, 0xbff, "andlw", K8_T },
	{ PIC18_OPCODE_XORLW, 0xa00, 0xaff, "xorlw", K8_T },
	{ PIC18_OPCODE_IORLW, 0x900, 0x9ff, "iorlw", K8_T },
	{ PIC18_OPCODE_SUBLW, 0x800, 0x8ff, "sublw", K8_T },
	{ PIC18_OPCODE_DECF, 0x400, 0x7ff, "decf", FDA_T },
	{ PIC18_OPCODE_MULWF, 0x200, 0x3ff, "mulwf", FA_T },
	{ PIC18_OPCODE_MOVLB, 0x100, 0x10f, "movlb", K4_T },
	{ PIC18_OPCODE_RESET, 0xff, 0xff, "reset", NO_ARG },
	{ PIC18_OPCODE_RETURN, 0x12, 0x13, "return", S_T },
	{ PIC18_OPCODE_RETFIE, 0x10, 0x11, "retfie", S_T },
	{ PIC18_OPCODE_TBLWTam, 0xf, 0xf, "tblwt+*", NO_ARG },
	{ PIC18_OPCODE_TBLWTMms, 0xe, 0xe, "tblwt*-", NO_ARG },
	{ PIC18_OPCODE_TBLWTMma, 0xd, 0xd, "tblwt*+", NO_ARG },
	{ PIC18_OPCODE_TBLWTMm, 0xc, 0xc, "tblwt*", NO_ARG },
	{ PIC18_OPCODE_TBLRDam, 0xb, 0xb, "tblrd+*", NO_ARG },
	{ PIC18_OPCODE_TBLRDms, 0xa, 0xa, "tblrd*-", NO_ARG },
	{ PIC18_OPCODE_TBLRDma, 0x9, 0x9, "tblrd*+", NO_ARG },
	{ PIC18_OPCODE_TBLRDm, 0x8, 0x8, "tblrd*", NO_ARG },
	{ PIC18_OPCODE_DAW, 0x7, 0x7, "daw", NO_ARG },
	{ PIC18_OPCODE_POP, 0x6, 0x6, "pop", NO_ARG },
	{ PIC18_OPCODE_PUSH, 0x5, 0x5, "push", NO_ARG },
	{ PIC18_OPCODE_CLRWDT, 0x4, 0x4, "clrwdt", NO_ARG },
	{ PIC18_OPCODE_SLEEP, 0x3, 0x3, "sleep", NO_ARG },
	{ PIC18_OPCODE_NOP, 0x0, 0x0, "nop", NO_ARG },
	{ PIC18_OPCODE_INVALID, 0x0, 0xffff, "invalid", NO_ARG },
};

bool pic18_disasm_op(Pic18Op *op, ut64 addr, const ut8 *buff, ut64 len) {
#define check_len(x) \
	if (len < x) { \
		op->code = PIC18_OPCODE_INVALID; \
		return false; \
	} \
	op->size = x;

	op->addr = addr;
	check_len(2);
	ut16 word = rz_read_le16(buff);
	Pic18OpDesc *desc = (Pic18OpDesc *)ops;
	for (; desc->opmin != (desc->opmin & word) ||
		desc->opmax != (desc->opmax | word);
		desc++) {
	}
	op->code = desc->code;
	op->mnemonic = desc->name;
	op->args_kind = desc->optype;

	switch (op->args_kind) {
	case N8_T:
		op->n = word & 0xff;
		break;
	case K8_T:
		op->k = word & 0xff;
		break;
	case FDA_T:
		op->f = word & 0xff;
		op->d = (word >> 9) & 1;
		op->a = (word >> 8) & 1;
		break;
	case FA_T:
		op->f = word & 0xff;
		op->d = (word >> 8) & 1;
		break;
	case BAF_T:
		op->f = word & 0xff;
		op->a = (word >> 8) & 1;
		op->b = (word >> 9) & 0x7;
		break;
	case N11_T:
		op->n = word & 0x7ff;
		break;
	case K4_T:
		op->k = word & 0xf;
		break;
	case S_T:
		op->s = word & 0x1;
		break;
#define check_dword_inst \
	check_len(4); \
	ut32 dword = rz_read_le32(buff); \
	if (dword >> 28 != 0xf) { \
		return false; \
	}
	case K20S_T: {
		check_dword_inst;
		op->k = (dword & 0xff) | (dword >> 16 & 0xfff);
		op->s = (dword >> 8) & 0x1;
		break;
	}
	case K20_T: {
		check_dword_inst;
		op->k = (dword & 0xff) | ((dword >> 16 & 0xfff) << 8);
		break;
	}
	case SD_T: {
		check_dword_inst;
		op->s = dword & 0xfff;
		op->d = (dword >> 16) & 0xfff;
		break;
	}
	case FK_T: {
		check_dword_inst;
		op->f = (dword >> 4) & 0x3;
		op->k = (dword & 0xf) << 8 | ((dword >> 16) & 0xff);
		break;
	}
	default:
		break;
	}
	return true;
}

int pic_pic18_disassemble(RzAsm *a, RzAsmOp *asm_op, const ut8 *b, int blen) {
	asm_op->size = 2;
	Pic18Op op = { 0 };
	if (!pic18_disasm_op(&op, a->pc, b, blen) ||
		op.code == PIC18_OPCODE_INVALID) {
		rz_asm_op_set_asm(asm_op, op.mnemonic);
		return -1;
	}
	asm_op->size = op.size;
	switch (op.args_kind) {
	case NO_ARG:
		rz_asm_op_set_asm(asm_op, op.mnemonic);
		break;
	case N8_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x", op.mnemonic, op.n);
		break;
	case K8_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x", op.mnemonic, op.k);
		break;
	case FDA_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x, %d, %d", op.mnemonic, op.f, op.d, op.a);
		break;
	case FA_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x, %d", op.mnemonic, op.f, op.a);
		break;
	case BAF_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x, %d, %d", op.mnemonic, op.f, op.b, op.a);
		break;
	case N11_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x", op.mnemonic, op.n);
		break;
	case K20S_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x, %d", op.mnemonic, op.k, op.s);
		break;
	case K20_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x", op.mnemonic, op.k);
		break;
	case SD_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x, 0x%x", op.mnemonic, op.s, op.d);
		break;
	case K4_T:
		rz_asm_op_setf_asm(asm_op, "%s 0x%x", op.mnemonic, op.k);
		break;
	case S_T:
		rz_asm_op_setf_asm(asm_op, "%s %d", op.mnemonic, op.s);
		break;
	case FK_T: {
		rz_asm_op_setf_asm(asm_op, "%s %s, %d", op.mnemonic, fsr[op.n], op.k);
		break;
	}
	default:
		rz_asm_op_set_asm(asm_op, "unknown args");
	}
	return asm_op->size;
}
