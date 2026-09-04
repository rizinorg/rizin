// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef C166_DISAS_H
#define C166_DISAS_H

#include <rz_types.h>
#include "c166/c166_common.h"

#define C166_INSTR_MAXLEN    (16 + 16) // ?
#define C166_OPERANDS_MAXLEN 32

// clang-format off
#define SBUF_16 \
	(char[C166_INSTR_MAXLEN]) RZ_EMPTY /* CI linter gives an error */
#define SBUF_7 (char[7]) RZ_EMPTY
#define SBUF_9 (char[9]) RZ_EMPTY
// clang-format on

#define INSTR(...)    rz_snprintf(instr->instr, C166_INSTR_MAXLEN - 1, __VA_ARGS__);
#define OPERANDS(...) rz_snprintf(instr->operands, C166_OPERANDS_MAXLEN - 1, __VA_ARGS__);
#define PRINT_INSTR   INSTR("%s", c166_instr_name(instr->id))

#define SEG (op->addr & 0xFF0000)

#define H_NIB(x) (((x) & 0xF0) >> 4) ///< High nibble
#define L_NIB(x) ((x) & 0x0F) ///< Low nibble

#define print_hex_word(b, v) snprintf(b, 7, WORD_FMT, v) < 0 ? NULL : buf;

#define BYTE_FMT           "0x%02x"
#define WORD_FMT           "0x%04x"
#define FMT_BYTE           ".byte 0x%02x"
#define FMT_WORD           ".word 0x%02x%02x"
#define FMT_2WORD          ".word 0x%02x%02x .word 0x%02x%02x"
#define FMT_DWORD_ADDR     "0x%04x:0x%04x"
#define FMT_DWORD_ADDR_LEN 19
#define FMT0               "%s, [%s]"
#define FMT1               "%s, [%s+]"
#define FMT2               "[%s], %s"
#define FMT3               "[-%s], %s"
#define FMT4               "[%s], [%s]"
#define FMT5               "[%s+], [%s]"
#define FMT6               "[%s], [%s+]"
#define FMT7               "%s %s"
#define FMT8               "%s, #0x%04x"
#define FMT9               "%s, %s"
#define FMT10              "%s, #%i"

#define SHORT_TO_LONG_ADDR(base, ind) ((base) + (2 * (ind))) ///< [0..15] -> 0xFXXX
#define REG_R(n)                      SHORT_TO_LONG_ADDR(BASE_GPR_ADDR, n)

#define GPR4_TO_8(n)   (0xF0 + (n)) ///< [0..15] -> 0xFX
#define GPRw4_TO_16(n) (REG_CP + (2 * (n))) ///< [0..15] -> 0xFXXX
#define GPRw8_TO_16(n) GPR4_TO_16((n) & 0x0F) ///< [0xF0..0xFF] -> 0xFXXX

#define GPRb4_TO_16(n) (REG_CP + (n)) ///< [0..15] -> 0xFXXX
#define GPRb8_TO_16(n) GPRb4_TO_16((n) & 0x0F) ///< [0xF0..0xFF] -> 0xFXXX

/*
ADDRSEL1 EQU    0EE1EH
ADDRSEL2 EQU    0EE26H
ADDRSEL3 EQU    0EE2EH
ADDRSEL4 EQU    0EE36H
ADDRSEL5 EQU    0EE3EH
ADDRSEL6 EQU    0EE46H
ADDRSEL7 EQU    0EE4EH
EBCMOD0  EQU    0EE00H
EBCMOD1  EQU    0EE02H
FOCON    DEFR   0FFAAH
FCONCS0  EQU    0EE12H
FCONCS1  EQU    0EE1AH
FCONCS2  EQU    0EE22H
FCONCS3  EQU    0EE2AH
FCONCS4  EQU    0EE32H
FCONCS5  EQU    0EE3AH
FCONCS6  EQU    0EE42H
FCONCS7  EQU    0EE4AH
IMBCTR   DEFR   0F0FEH
RSTCON   EQU    0F1E0H
SYSCON1  DEFR   0F1DCH
SYSCON3  DEFR   0F1D4H
PLLCON   DEFR   0F1D0H
TCONCS0  EQU    0EE10H
TCONCS1  EQU    0EE18H
TCONCS2  EQU    0EE20H
TCONCS3  EQU    0EE28H
TCONCS4  EQU    0EE30H
TCONCS5  EQU    0EE38H
TCONCS6  EQU    0EE40H
TCONCS7  EQU    0EE48H
WDTCON   DEFR   0FFAEH
*/

#define R_IP      (op->addr)
#define NEXT_ADDR (R_IP + op->size)

#define XXXX(b) (NEXT_ADDR + (2 * ((st8)(b))))
#define FAIL    (op->fail = NEXT_ADDR)

/**
 * C166 Register definitions
 * Defines all general-purpose and special registers for the C166 architecture
 */
// clang-format off
typedef enum {
	C166_R0,  C166_R1,  C166_R2,  C166_R3,
	C166_R4,  C166_R5,  C166_R6,  C166_R7,
	C166_R8,  C166_R9,  C166_R10, C166_R11,
	C166_R12, C166_R13, C166_R14, C166_R15,
	C166_RL0, C166_RH0, C166_RL1, C166_RH1,
	C166_RL2, C166_RH2, C166_RL3, C166_RH3,
	C166_RL4, C166_RH4, C166_RL5, C166_RH5,
	C166_RL6, C166_RH6, C166_RL7, C166_RH7,

	C166_IP,

	C166_SP,  C166_PSW, C166_CSP,
	C166_MDL, C166_MDH, C166_MDC,
	C166_STKOV, C166_STKUN,

	C166_CPUCON1, C166_CPUCON2,
	C166_VECSEG,  C166_SPSEG, C166_CP
} C166Register;

/*
	ADCIC, ADCON, ADDAT,
	ADDRSEL1, ADDRSEL2, ADDRSEL3, ADDRSEL4,
	ADEIC,
	BUSCON0, BUSCON1, BUSCON2, BUSCON3, BUSCON4,
	C1UMLM, // No 8-bit addr
	C1UGML, // No 8-bit addr
	C1LMLM, // No 8-bit addr
	C1LGML, // No 8-bit addr
	C1IR, // No 8-bit addr
	C1GMS, // No 8-bit addr
	C1BTR, // No 8-bit addr
	C1CSR, // No 8-bit addr
	CAPREL,
	CC0,  CC0IC,
	CC1,  CC1IC,
	CC2,  CC2IC,
	CC3,  CC3IC,
	CC4,  CC4IC,
	CC5,  CC5IC,
	CC6,  CC6IC,
	CC7,  CC7IC,
	CC8,  CC8IC,
	CC9,  CC9IC,
	CC10, CC10IC,
	CC11, CC11IC,
	CC12, CC12IC,
	CC13, CC13IC,
	CC14, CC14IC,
	CC15, CC15IC,
	CC16, CC17,
	CC18, CC19,
	CC20, CC21,
	CC22, CC23,
	CC24, CC25,
	CC26, CC27,
	CC28, CC29,
	CC30, CC31,

	CCM0, CCM1,
	CCM2, CCM3,
	CCM4, CCM5,
	CCM6, CCM7,
	// CP,
	CRIC,
	// CSP,
	DP2,  DP3,
	DP4,  DP6,
	DP7,  DP8,
	DPP0, DPP1,
	DPP2, DPP3,
	// MDC,
	// MDH,
	// MDL,
	ONES,
	P0L, P0H,
	P1L, P1H,
	P2,  P3,
	P4,  P5,
	P6,  P7,
	P8,
	PECC0, PECC1,
	PECC2, PECC3,
	PECC4, PECC5,
	PECC6, PECC7,
	// PSW,
	PW0, PW1,
	PW2, PW3,
	PWMCON0, PWMCON1,
	S0BG,
	S0CON,
	S0EIC,
	S0RBUF,
	S0RIC,
	S0TBUF,
	S0TIC,
	// SP,
	SSCCON,
	SSCEIC,
	SSCRIC,
	SSCTIC,
	// STKOV,
	// STKUN,
	SYSCON,
	T0,
	T01CON,
	T0IC,
	T0REL,
	T1, T1IC,  T1REL,
	T2, T2CON, T2IC,
	T3, T3CON, T3IC,
	T4, T4CON, T4IC,
	T5, T5CON, T5IC,
	T6, T6CON, T6IC,
	T78CON,
	TFR,
	WDT, WDTCON,
	ZEROS,

	ADDAT2,
	CC16IC,  CC17IC,
	CC18IC,  CC19IC,
	CC20IC,  CC21IC,
	CC22IC,  CC23IC,
	CC24IC,  CC25IC,
	CC26IC,  CC27IC,
	CC28IC,  CC29IC,
	CC30IC,  CC31IC,
	DP0L,    DP0H,
	DP1L,    DP1H,
	EXICON,
	ODP2,    ODP3,
	ODP6,    ODP7,
	ODP8,
	PICON,
	PP0, PP1, PP2, PP3,
	PT0, PT1, PT2, PT3,
	PWMIC,
	RP0H,
	S0TBIC,
	SSCBR,
	SSCRB,
	SSCTB,
	T7,
	T7IC,
	T7REL,
	T8,
	T8IC,
	T8REL,
	XP0IC, XP1IC, XP2IC, XP3IC,
*/
// clang-format on

typedef struct {
	ut64 d;
	ut32 imm;
	union {
		ut32 disp;
		st32 sdisp;
	};
	c166_opcodes id;
	ut32 addr;
	ut8 byte_size : 4;
	unsigned type;
	char instr[C166_INSTR_MAXLEN];
	char operands[C166_OPERANDS_MAXLEN];
	C166ExtState ext;
} C166_Inst;

static inline ut16 get_byte(const C166_Inst *i, const ut8 index) {
	rz_warn_if_fail(index <= 3);
	return rz_read_at_le8(&i->d, index);
}

static inline ut16 get_operand(const C166_Inst *i, const ut8 index) {
	rz_warn_if_fail(index >= 1 && index <= 3);
	return get_byte(i, index);
}

RZ_IPI st32 c166_decode_command(RZ_NONNULL C166State *state, RZ_NONNULL C166_Inst *instr, RZ_NONNULL const ut8 *bytes, st32 len);
RZ_API void c166_maybe_deactivate_ext(RZ_NONNULL C166State *state, ut32 addr);
#endif /* C166_DISAS_H */
