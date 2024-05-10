// SPDX-FileCopyrightText: 2015-2018 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2015-2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>

#include "pic18.h"

/**
 * \file PIC18CXXX instruction set
 */

// instruction classification according to the argument types

static char *fsr[] = { "fsr0", "fsr1", "fsr2" };

typedef struct {
	Pic18Opcode code;
	ut16 opmin;
	ut16 opmax;
	char *name;
	Pic18ArgsKind optype;
	// and some magical hocus pocus ;)
} Pic18OpDesc;

static const Pic18OpDesc pic18_ops[] = {
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
	{ PIC18_OPCODE_BTFSC, 0xb000, 0xbfff, "btfsc", FBA_T },
	{ PIC18_OPCODE_BTFSS, 0xa000, 0xafff, "btfss", FBA_T },
	{ PIC18_OPCODE_BCF, 0x9000, 0x9fff, "bcf", FBA_T },
	{ PIC18_OPCODE_BSF, 0x8000, 0x8fff, "bsf", FBA_T },
	{ PIC18_OPCODE_BTG, 0x7000, 0x7fff, "btg", FBA_T },
	{ PIC18_OPCODE_MOVWF, 0x6e00, 0x6fff, "movwf", FA_T },
	{ PIC18_OPCODE_NEGF, 0x6c00, 0x6dff, "negf", FA_T },
	{ PIC18_OPCODE_CLRF, 0x6a00, 0x6bff, "clrf", FA_T },
	{ PIC18_OPCODE_SETF, 0x6800, 0x69ff, "setf", FA_T },
	{ PIC18_OPCODE_TSTFSZ, 0x6600, 0x67ff, "tstfsz", FA_T },
	{ PIC18_OPCODE_CPFSGT, 0x6400, 0x65ff, "cpfsgt", FA_T },
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
	{ PIC18_OPCODE_TBLWTis, 0xf, 0xf, "tblwt+*", NO_ARG },
	{ PIC18_OPCODE_TBLWTMsd, 0xe, 0xe, "tblwt*-", NO_ARG },
	{ PIC18_OPCODE_TBLWTMsi, 0xd, 0xd, "tblwt*+", NO_ARG },
	{ PIC18_OPCODE_TBLWTMs, 0xc, 0xc, "tblwt*", NO_ARG },
	{ PIC18_OPCODE_TBLRDis, 0xb, 0xb, "tblrd+*", NO_ARG },
	{ PIC18_OPCODE_TBLRDsd, 0xa, 0xa, "tblrd*-", NO_ARG },
	{ PIC18_OPCODE_TBLRDsi, 0x9, 0x9, "tblrd*+", NO_ARG },
	{ PIC18_OPCODE_TBLRDs, 0x8, 0x8, "tblrd*", NO_ARG },
	{ PIC18_OPCODE_DAW, 0x7, 0x7, "daw", NO_ARG },
	{ PIC18_OPCODE_POP, 0x6, 0x6, "pop", NO_ARG },
	{ PIC18_OPCODE_PUSH, 0x5, 0x5, "push", NO_ARG },
	{ PIC18_OPCODE_CLRWDT, 0x4, 0x4, "clrwdt", NO_ARG },
	{ PIC18_OPCODE_SLEEP, 0x3, 0x3, "sleep", NO_ARG },
	{ PIC18_OPCODE_NOP, 0x0, 0x0, "nop", NO_ARG },
};

static const char *pic18_SFRs[] = {
	[0xFFF - 0xF80] = "tosu",
	[0xFFE - 0xF80] = "tosh",
	[0xFFD - 0xF80] = "tosl",
	[0xFFC - 0xF80] = "stkptr",
	[0xFFB - 0xF80] = "pclatu",
	[0xFFA - 0xF80] = "pclath",
	[0xFF9 - 0xF80] = "pcl",
	[0xFF8 - 0xF80] = "tblptru",
	[0xFF7 - 0xF80] = "tblptrh",
	[0xFF6 - 0xF80] = "tblptrl",
	[0xFF5 - 0xF80] = "tablat",
	[0xFF4 - 0xF80] = "prodh",
	[0xFF3 - 0xF80] = "prodl",
	[0xFF2 - 0xF80] = "intcon",
	[0xFF1 - 0xF80] = "intcon2",
	[0xFF0 - 0xF80] = "intcon3",
	[0xFEF - 0xF80] = "indf0",
	[0xFEE - 0xF80] = "postinc0",
	[0xFED - 0xF80] = "postdec0",
	[0xFEC - 0xF80] = "preinc0",
	[0xFEB - 0xF80] = "plusw0",
	[0xFEA - 0xF80] = "fsr0h",
	[0xFE9 - 0xF80] = "fsr0l",
	[0xFE8 - 0xF80] = "wreg",
	[0xFE7 - 0xF80] = "indf1",
	[0xFE6 - 0xF80] = "postinc1",
	[0xFE5 - 0xF80] = "postdec1",
	[0xFE4 - 0xF80] = "preinc1",
	[0xFE3 - 0xF80] = "plusw1",
	[0xFE2 - 0xF80] = "fsr1h",
	[0xFE1 - 0xF80] = "fsr1l",
	[0xFE0 - 0xF80] = "bsr",
	[0xFDF - 0xF80] = "indf2",
	[0xFDE - 0xF80] = "postinc2",
	[0xFDD - 0xF80] = "postdec2",
	[0xFDC - 0xF80] = "preinc2",
	[0xFDB - 0xF80] = "plusw2",
	[0xFDA - 0xF80] = "fsr2h",
	[0xFD9 - 0xF80] = "fsr2l",
	[0xFD8 - 0xF80] = "status",
	[0xFD7 - 0xF80] = "tmr0h",
	[0xFD6 - 0xF80] = "tmr0l",
	[0xFD5 - 0xF80] = "t0con",
	[0xFD4 - 0xF80] = "0xd4",
	[0xFD3 - 0xF80] = "osccon",
	[0xFD2 - 0xF80] = "lvdcon",
	[0xFD1 - 0xF80] = "wdtcon",
	[0xFD0 - 0xF80] = "rcon",
	[0xFCF - 0xF80] = "tmr1h",
	[0xFCE - 0xF80] = "tmr1l",
	[0xFCD - 0xF80] = "t1con",
	[0xFCC - 0xF80] = "tmr2",
	[0xFCB - 0xF80] = "pr2",
	[0xFCA - 0xF80] = "t2con",
	[0xFC9 - 0xF80] = "sspbuf",
	[0xFC8 - 0xF80] = "sspadd",
	[0xFC7 - 0xF80] = "sspstat",
	[0xFC6 - 0xF80] = "sspcon1",
	[0xFC5 - 0xF80] = "sspcon2",
	[0xFC4 - 0xF80] = "adresh",
	[0xFC3 - 0xF80] = "adresl",
	[0xFC2 - 0xF80] = "adcon0",
	[0xFC1 - 0xF80] = "adcon1",
	[0xFC0 - 0xF80] = "0xc0",
	[0xFBF - 0xF80] = "ccpr1h",
	[0xFBE - 0xF80] = "ccpr1l",
	[0xFBD - 0xF80] = "ccp1con",
	[0xFBC - 0xF80] = "ccpr2h",
	[0xFBB - 0xF80] = "ccpr2l",
	[0xFBA - 0xF80] = "ccp2con",
	[0xFB9 - 0xF80] = "0xb9",
	[0xFB8 - 0xF80] = "0xb8",
	[0xFB7 - 0xF80] = "0xb7",
	[0xFB6 - 0xF80] = "0xb6",
	[0xFB5 - 0xF80] = "0xb5",
	[0xFB4 - 0xF80] = "0xb4",
	[0xFB3 - 0xF80] = "tmr3h",
	[0xFB2 - 0xF80] = "tmr3l",
	[0xFB1 - 0xF80] = "t3con",
	[0xFB0 - 0xF80] = "0xb0",
	[0xFAF - 0xF80] = "spbrg",
	[0xFAE - 0xF80] = "rcreg",
	[0xFAD - 0xF80] = "txreg",
	[0xFAC - 0xF80] = "txsta",
	[0xFAB - 0xF80] = "rcsta",
	[0xFAA - 0xF80] = "0xaa",
	[0xFA9 - 0xF80] = "0xa9",
	[0xFA8 - 0xF80] = "0xa8",
	[0xFA7 - 0xF80] = "0xa7",
	[0xFA6 - 0xF80] = "0xa6",
	[0xFA5 - 0xF80] = "0xa5",
	[0xFA4 - 0xF80] = "0xa4",
	[0xFA3 - 0xF80] = "0xa3",
	[0xFA2 - 0xF80] = "ipr2",
	[0xFA1 - 0xF80] = "pir2",
	[0xFA0 - 0xF80] = "pie2",
	[0xF9F - 0xF80] = "ipr1",
	[0xF9E - 0xF80] = "pir1",
	[0xF9D - 0xF80] = "pie1",
	[0xF9C - 0xF80] = "0x9c",
	[0xF9B - 0xF80] = "0x9b",
	[0xF9A - 0xF80] = "0x9a",
	[0xF99 - 0xF80] = "0x99",
	[0xF98 - 0xF80] = "0x98",
	[0xF97 - 0xF80] = "0x97",
	[0xF96 - 0xF80] = "trise",
	[0xF95 - 0xF80] = "trisd",
	[0xF94 - 0xF80] = "trisc",
	[0xF93 - 0xF80] = "trisb",
	[0xF92 - 0xF80] = "trisa",
	[0xF91 - 0xF80] = "0x91",
	[0xF90 - 0xF80] = "0x90",
	[0xF8F - 0xF80] = "0x8f",
	[0xF8E - 0xF80] = "0x8e",
	[0xF8D - 0xF80] = "late",
	[0xF8C - 0xF80] = "latd",
	[0xF8B - 0xF80] = "latc",
	[0xF8A - 0xF80] = "latb",
	[0xF89 - 0xF80] = "lata",
	[0xF88 - 0xF80] = "0x88",
	[0xF87 - 0xF80] = "0x87",
	[0xF86 - 0xF80] = "0x86",
	[0xF85 - 0xF80] = "0x85",
	[0xF84 - 0xF80] = "porte",
	[0xF83 - 0xF80] = "portd",
	[0xF82 - 0xF80] = "portc",
	[0xF81 - 0xF80] = "portb",
	[0xF80 - 0xF80] = "porta",
};

static const char *pic18_GPRs[] = {
	"0x00",
	"0x01",
	"0x02",
	"0x03",
	"0x04",
	"0x05",
	"0x06",
	"0x07",
	"0x08",
	"0x09",
	"0x0a",
	"0x0b",
	"0x0c",
	"0x0d",
	"0x0e",
	"0x0f",
	"0x10",
	"0x11",
	"0x12",
	"0x13",
	"0x14",
	"0x15",
	"0x16",
	"0x17",
	"0x18",
	"0x19",
	"0x1a",
	"0x1b",
	"0x1c",
	"0x1d",
	"0x1e",
	"0x1f",
	"0x20",
	"0x21",
	"0x22",
	"0x23",
	"0x24",
	"0x25",
	"0x26",
	"0x27",
	"0x28",
	"0x29",
	"0x2a",
	"0x2b",
	"0x2c",
	"0x2d",
	"0x2e",
	"0x2f",
	"0x30",
	"0x31",
	"0x32",
	"0x33",
	"0x34",
	"0x35",
	"0x36",
	"0x37",
	"0x38",
	"0x39",
	"0x3a",
	"0x3b",
	"0x3c",
	"0x3d",
	"0x3e",
	"0x3f",
	"0x40",
	"0x41",
	"0x42",
	"0x43",
	"0x44",
	"0x45",
	"0x46",
	"0x47",
	"0x48",
	"0x49",
	"0x4a",
	"0x4b",
	"0x4c",
	"0x4d",
	"0x4e",
	"0x4f",
	"0x50",
	"0x51",
	"0x52",
	"0x53",
	"0x54",
	"0x55",
	"0x56",
	"0x57",
	"0x58",
	"0x59",
	"0x5a",
	"0x5b",
	"0x5c",
	"0x5d",
	"0x5e",
	"0x5f",
	"0x60",
	"0x61",
	"0x62",
	"0x63",
	"0x64",
	"0x65",
	"0x66",
	"0x67",
	"0x68",
	"0x69",
	"0x6a",
	"0x6b",
	"0x6c",
	"0x6d",
	"0x6e",
	"0x6f",
	"0x70",
	"0x71",
	"0x72",
	"0x73",
	"0x74",
	"0x75",
	"0x76",
	"0x77",
	"0x78",
	"0x79",
	"0x7a",
	"0x7b",
	"0x7c",
	"0x7d",
	"0x7e",
	"0x7f"
};

const char *pic18_regname(size_t index) {
	if (index <= 0xff && index >= 0x80) {
		return pic18_SFRs[index - 0x80];
	}
	if (index < 0x80) {
		return pic18_GPRs[index];
	}
	rz_warn_if_reached();
	return NULL;
}

const char *pic18_regname_extra(size_t index) {
	if (index <= 0xff) {
		return pic18_regname(index);
	}
	if (index >= 0xf80 && index <= 0xfff) {
		return pic18_regname(index % 0x100);
	}
	return NULL;
}

#define STATUS_BIT_IMPL(DECL, X) \
	ut8 pic18_##X(const char *name) { \
		for (int i = 0; i < RZ_ARRAY_SIZE(DECL); ++i) { \
			if (RZ_STR_EQ(name, DECL[i])) { \
				return i; \
			} \
		} \
		return 0xff; \
	}

static const char *status_bits[] = {
	"c",
	"dc",
	"z",
	"ov",
	"n"
};

static const char *rcon_bits[] = {
	"bor",
	"por",
	"pd",
	"to",
	"ri",
	NULL,
	"lwrt",
	"ipen",
};

static const char *intcon_bits[] = {
	"brif",
	"int0if",
	"tmr0if",
	"brie",
	"int0ie",
	"tmr0ie",
	"peie",
	"gie",
};

STATUS_BIT_IMPL(status_bits, status);
STATUS_BIT_IMPL(rcon_bits, rcon);
ut8 pic18_intcon(const char *name) {
	for (int i = 0; i < RZ_ARRAY_SIZE(intcon_bits); ++i) {
		if (RZ_STR_EQ(name, intcon_bits[i])) {
			return i;
		}
	}
	if (RZ_STR_EQ(name, "gieh")) {
		return 7;
	}
	if (RZ_STR_EQ(name, "giel")) {
		return 6;
	}
	return 0xff;
}

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
	Pic18OpDesc *desc = (Pic18OpDesc *)pic18_ops;
	for (; desc - pic18_ops < RZ_ARRAY_SIZE(pic18_ops) &&
		(desc->opmin != (desc->opmin & word) ||
			desc->opmax != (desc->opmax | word));
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
		op->a = (word >> 8) & 1;
		break;
	case FBA_T:
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
		op->k = (dword & 0xff) | ((dword >> 16 & 0xfff) << 8);
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

	switch (op->args_kind) {
	case NO_ARG:
	default:
		break;
	case N8_T:
	case N11_T:
		rz_strf(op->operands, "0x%x", op->n);
		break;
	case K4_T:
	case K8_T:
		rz_strf(op->operands, "0x%x", op->k);
		break;
	case K20_T:
		rz_strf(op->operands, "0x%x", op->k << 1);
		break;
	case FDA_T:
		rz_strf(op->operands, "%s, %d, %d", pic18_regname(op->f), op->d, op->a);
		break;
	case FA_T:
		rz_strf(op->operands, "%s, %d", pic18_regname(op->f), op->a);
		break;
	case FBA_T:
		rz_strf(op->operands, "%s, %d, %d", pic18_regname(op->f), op->b, op->a);
		break;
	case K20S_T:
		rz_strf(op->operands, "0x%x, %d", op->k << 1, op->s);
		break;
	case SD_T: {
		const char *rs = pic18_regname_extra(op->s);
		const char *rd = pic18_regname_extra(op->d);
		if (rs && rd) {
			rz_strf(op->operands, "%s, %s", rs, rd);
		} else if (rs) {
			rz_strf(op->operands, "%s, 0x%x", rs, op->d);
		} else if (rd) {
			rz_strf(op->operands, "0x%x, %s", op->s, rd);
		} else {
			rz_strf(op->operands, "0x%x, 0x%x", op->s, op->d);
		}
		break;
	}
	case S_T:
		rz_strf(op->operands, "%d", op->s);
		break;
	case FK_T: {
		rz_strf(op->operands, "%s, %d", fsr[op->f], op->k);
		break;
	}
	}

	return true;
}

int pic18_disassemble(RzAsm *a, RzAsmOp *asm_op, const ut8 *b, int blen) {
	asm_op->size = 2;
	Pic18Op op = { 0 };
	if (!pic18_disasm_op(&op, a->pc, b, blen) ||
		op.code == PIC18_OPCODE_INVALID) {
		rz_asm_op_set_asm(asm_op, "invalid");
		return -1;
	}
	asm_op->size = op.size;
	if (RZ_STR_ISEMPTY(op.operands)) {
		rz_asm_op_set_asm(asm_op, op.mnemonic);
	} else {
		rz_asm_op_setf_asm(asm_op, "%s %s", op.mnemonic, op.operands);
	}
	return asm_op->size;
}
