// SPDX-FileCopyrightText: 2023 Jairus Martin <frmdstryr@protonmail.com>
// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef C166_DISAS_H
#define C166_DISAS_H

#include <rz_vector.h>
#include <rz_types.h>

#define C166_INSTR_MAXLEN    (16 + 16) // ?
#define C166_OPERANDS_MAXLEN 32

#define C166_BYTESIZE_2 2
#define C166_BYTESIZE_4 4

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

#define BYTE_FMT  "0x%02x"
#define WORD_FMT  "0x%04x"
#define FMT_BYTE  ".byte 0x%02x"
#define FMT_WORD  ".word 0x%02x%02x"
#define FMT_2WORD ".word 0x%02x%02x .word 0x%02x%02x"
#define FMT0      "%s, [%s]"
#define FMT1      "%s, [%s+]"
#define FMT2      "[%s], %s"
#define FMT3      "[-%s], %s"
#define FMT4      "[%s], [%s]"
#define FMT5      "[%s+], [%s]"
#define FMT6      "[%s], [%s+]"
#define FMT7      "%s %s"
#define FMT8      "%s, #0x%04x"
#define FMT9      "%s, %s"
#define FMT10     "%s, #%i"

// Core Special Function Registers (CSFR)
#define BASE_GPR_ADDR    0xFE10 ///< Base address for calculate GPR phisical address (also REG_CP)
#define BASE_SFR_ADDR    0xFE00 ///< Base address for calculate SFR phisical address (also REG_DPP0)
#define BASE_ESFR_ADDR   0xF000 ///< Base address for calculate ESFR phisical address
#define BASE_RAM_B_ADDR  0xFD00 ///< Base address for calculate RAM phisical address (bit)
#define BASE_SFR_B_ADDR  0xFF00 ///< Base address for calculate SFR phisical address (bit)
#define BASE_ESFR_B_ADDR 0xF100 ///< Base address for calculate ESFR phisical address (bit)

#define QX0   0xF000 ///< MAC Offset Register X0 (ESFRs)
#define QX1   0xF002 ///< MAC Offset Register X1 (ESFRs)
#define QR0   0xF004 ///< MAC Offset Register R0 (ESFRs)
#define QR1   0xF006 ///< MAC Offset Register R1 (ESFRs)
#define CPUID 0xF00C ///< CPU Identification Register (ESFRs)

#define REG_PSW 0xFF10 ///< Processor Status Word

#define REG_DPP0    (BASE_SFR_ADDR + 0x00) ///< CPU Data Page Pointer 0 Register (10 bits)
#define REG_DPP1    (BASE_SFR_ADDR + 0x02) ///< CPU Data Page Pointer 1 Register (10 bits)
#define REG_DPP2    (BASE_SFR_ADDR + 0x04) ///< CPU Data Page Pointer 2 Register (10 bits)
#define REG_DPP3    (BASE_SFR_ADDR + 0x06) ///< CPU Data Page Pointer 3 Register (10 bits)
#define REG_CSP     (BASE_SFR_ADDR + 0x08) ///< Code Segment Pointer
#define REG_MDH     (BASE_SFR_ADDR + 0x0c) ///< Multiply Divide High Word
#define REG_MDL     (BASE_SFR_ADDR + 0x0e) ///< Multiply Divide Low Word
#define REG_CP      (BASE_SFR_ADDR + 0x10) ///< CPU Context Pointer Register
#define REG_SP      (BASE_SFR_ADDR + 0x12) ///< Stack Pointer Register
#define REG_STKOV   (BASE_SFR_ADDR + 0x14) ///< Stack Overflow Pointer
#define REG_STKUN   (BASE_SFR_ADDR + 0x16) ///< Stack Underflow Pointer
#define REG_CPUCON1 (BASE_SFR_ADDR + 0x18) ///< Core Control Register
#define REG_CPUCON2 (BASE_SFR_ADDR + 0x1A) ///< Core Control Register
#define REG_MAL     (BASE_SFR_ADDR + 0x5C) ///< MAC Accumulator – Low Word
#define REG_MAH     (BASE_SFR_ADDR + 0x5E) ///< MAC Accumulator – High Word

#define IDX0   0xFF08 ///< Address Pointer IDX0
#define IDX1   0xFF0A ///< Address Pointer IDX1
#define SPSEG  0xFF0C ///< Stack Pointer Segment Register
#define MDC    0xFF0E ///< (Bit addressable) Multiply Divide Control Register
#define PSW    0xFF10 ///< (Bit addressable) Program Status Word
#define VECSEG 0xFF12 ///< (Bit addressable) Vector Table Segment Register
#define ZEROS  0xFF1C ///< (Bit addressable) Constant Value 0s Register (read only)
#define ONES   0xFF1E ///< (Bit addressable) Constant Value 1s Register (read only)
#define TFR    0xFFAC ///< (Bit addressable) Trap Flag Register
#define MRW    0xFFDA ///< (Bit addressable) MAC Repeat Word
#define MCW    0xFFDC ///< (Bit addressable) MAC Control Word
#define MSW    0xFFDE ///< (Bit addressable) MAC Status Word

#define REG_ASC0_TIC 0xFF6C ///< Serial Channel 0 Transmit Interrupt Control Register
#define REG_ASC0_RIC 0xFF6E ///< Serial Channel 0 Receive Interrupt Control Register

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
static inline bool IS_GPR(ut8 addr) {
	return addr >= 0xF0 && addr <= 0xFF;
}

static inline bool IS_RAM(ut8 addr) {
	return addr <= 0x7F;
}

static inline bool IS_rSFR(ut8 addr) {
	return addr <= 0xEF;
}

static inline bool IS_bSFR(ut8 addr) {
	return addr >= 0x80 && addr <= 0xEF;
}

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

/**
 * C166 Operation Types
 * Defines all instruction types supported by the C166 architecture
 */
typedef enum {
	C166_ADD_Rwn_Rwm = 0x00, ///< <b>[0x00]</b> Add direct word GPR to direct GPR <b>(2 bytes)</b>
	C166_ADDB_Rbn_Rbm = 0x01, ///< <b>[0x01]</b> Add direct byte GPR to direct GPR <b>(2 bytes)</b>
	C166_ADD_reg_mem = 0x02, ///< <b>[0x02]</b> Add direct word memory to direct register <b>(4 bytes)</b>
	C166_ADDB_reg_mem = 0x03, ///< <b>[0x03]</b> Add direct byte memory to direct register <b>(4 bytes)</b>
	C166_ADD_mem_reg = 0x04, ///< <b>[0x04]</b> Add direct word register to direct memory <b>(4 bytes)</b>
	C166_ADDB_mem_reg = 0x05, ///< <b>[0x05]</b> Add direct byte register to direct memory <b>(4 bytes)</b>
	C166_ADD_reg_data16 = 0x06, ///< <b>[0x06]</b> Add immediate word data to direct register <b>(4 bytes)</b>
	C166_ADDB_reg_data8 = 0x07, ///< <b>[0x07]</b> Add immediate byte data to direct register <b>(4 bytes)</b>
	C166_ADD_Rwn_x = 0x08, /**< <b>[0x08]</b><br>
								ADD Rw, [Rw +] - Add indirect word memory to direct GPR and post-increment source pointer by 2 <b>(2 bytes)</b><br>
								ADD Rw, [Rw] - Add indirect word memory to direct GPR <b>(2 bytes)</b><br>
								ADD Rw, #data3 - Add immediate word data to direct GPR <b>(2 bytes)</b> */
	C166_ADDB_Rbn_x = 0x09, /**< <b>[0x09]</b><br>
								ADDB Rb, [Rw +] - Add indirect byte memory to direct GPR and post-increment source pointer by 1 <b>(2 bytes)</b><br>
								ADDB Rb, [Rw] - Add indirect byte memory to direct GPR <b>(2 bytes)</b><br>
								ADDB Rb, #data3 - Add immediate byte data to direct GPR <b>(2 bytes)</b> */
	C166_BFLDL_bitoff_x = 0x0A, ///< <b>[0x0A]</b> Bitwise modify masked low byte of bit-addressable direct word memory with immediate data <b>(4 bytes)</b>
	C166_MUL_Rwn_Rwm = 0x0B, ///< <b>[0x0B]</b> Signed multiply direct GPR by direct GPR (16-bit × 16-bit) <b>(2 bytes)</b>
	C166_ROL_Rwn_Rwm = 0x0C, ///< <b>[0x0C]</b> Rotate left direct word GPR; number of shift cycles specified by direct GPR <b>(2 bytes)</b>
	C166_JMPR_cc_UC_rel = 0x0D, ///< <b>[0x0D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff0 = 0x0E, ///< <b>[0x0E]</b> Clear direct bit (x.0) <b>(2 bytes)</b>
	C166_BSET_bitoff0 = 0x0F, ///< <b>[0x0F]</b> Set direct bit (x.0) <b>(2 bytes)</b>

	C166_ADDC_Rwn_Rwm = 0x10, ///< <b>[0x10]</b> Add direct word GPR to direct GPR with Carry <b>(2 bytes)</b>
	C166_ADDCB_Rbn_Rbm = 0x11, ///< <b>[0x11]</b> Add direct byte GPR to direct GPR with Carry <b>(2 bytes)</b>
	C166_ADDC_reg_mem = 0x12, ///< <b>[0x12]</b> Add direct word memory to direct register with Carry <b>(4 bytes)</b>
	C166_ADDCB_reg_mem = 0x13, ///< <b>[0x13]</b> Add direct byte memory to direct register with Carry <b>(4 bytes)</b>
	C166_ADDC_mem_reg = 0x14, ///< <b>[0x14]</b> Add direct word register to direct memory with Carry <b>(4 bytes)</b>
	C166_ADDCB_mem_reg = 0x15, ///< <b>[0x15]</b> Add direct byte register to direct memory with Carry <b>(4 bytes)</b>
	C166_ADDC_reg_data16 = 0x16, ///< <b>[0x16]</b> Add immediate word data to direct register with Carry <b>(4 bytes)</b>
	C166_ADDCB_reg_data8 = 0x17, ///< <b>[0x17]</b> Add immediate byte data to direct register with Carry <b>(4 bytes)</b>
	C166_ADDC_Rwn_x = 0x18, /**< <b>[0x18]</b><br>
								ADDC Rw, [Rw+] - Add indirect word memory to direct GPR with Carry and post-increment source pointer by 2 <b>(2 bytes)</b><br>
								ADDC Rw, [Rw] - Add indirect word memory to direct GPR with Carry <b>(2 bytes)</b><br>
								ADDC Rw, #data3 - Add immediate word data to direct GPR with Carry <b>(2 bytes)</b> */
	C166_ADDCB_Rbn_x = 0x19, /**< <b>[0x19]</b><br>
								ADDCB Rb, [Rw+] - Add indirect byte memory to direct GPR with Carry and post-increment source pointer by 1 <b>(2 bytes)</b><br>
								ADDCB Rb, [Rw] - Add indirect byte memory to direct GPR with Carry <b>(2 bytes)</b><br>
								ADDCB Rb, #data3 - Add immediate byte data to direct GPR with Carry <b>(2 bytes)</b> */
	C166_BFLDH_bitoff_x = 0x1A, ///< <b>[0x1A]</b> Bitwise modify masked high byte of bit-addressable direct word memory with immediate data <b>(4 bytes)</b>
	C166_MULU_Rwn_Rwm = 0x1B, ///< <b>[0x1B]</b> Unsigned multiply direct GPR by direct GPR (16-bit × 16-bit) <b>(2 bytes)</b>
	C166_ROL_Rwn_data4 = 0x1C, ///< <b>[0x1C]</b> Rotate left direct word GPR; number of shift cycles specified by immediate data <b>(2 bytes)</b>
	C166_JMPR_cc_NET_rel = 0x1D, ///< <b>[0x1D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff1 = 0x1E, ///< <b>[0x1E]</b> Clear direct bit (x.1) <b>(2 bytes)</b>
	C166_BSET_bitoff1 = 0x1F, ///< <b>[0x1F]</b> Set direct bit (x.1) <b>(2 bytes)</b>
	C166_SUB_Rwn_Rwm = 0x20, ///< <b>[0x20]</b> Subtract direct word GPR from direct GPR <b>(2 bytes)</b>
	C166_SUBB_Rbn_Rbm = 0x21, ///< <b>[0x21]</b> Subtract direct byte GPR from direct GPR <b>(2 bytes)</b>
	C166_SUB_reg_mem = 0x22, ///< <b>[0x22]</b> Subtract direct word memory from direct register <b>(4 bytes)</b>
	C166_SUBB_reg_mem = 0x23, ///< <b>[0x23]</b> Subtract direct byte memory from direct register <b>(4 bytes)</b>
	C166_SUB_mem_reg = 0x24, ///< <b>[0x24]</b> Subtract direct word register from direct memory <b>(4 bytes)</b>
	C166_SUBB_mem_reg = 0x25, ///< <b>[0x25]</b> Subtract direct byte register from direct memory <b>(4 bytes)</b>
	C166_SUB_reg_data16 = 0x26, ///< <b>[0x26]</b> Subtract immediate word data from direct register <b>(4 bytes)</b>
	C166_SUBB_reg_data8 = 0x27, ///< <b>[0x27]</b> Subtract immediate byte data from direct register <b>(4 bytes)</b>
	C166_SUB_Rwn_x = 0x28, /**< <b>[0x28]</b><br>
								SUB Rw, [Rw+] - Subtract indirect word memory from direct GPR and post-increment source pointer by 2 <b>(2 bytes)</b><br>
								SUB Rw, [Rw] - Subtract indirect word memory from direct GPR <b>(2 bytes)</b><br>
								SUB Rw, #data3 - Subtract immediate word data from direct GPR <b>(2 bytes)</b> */
	C166_SUBB_Rbn_x = 0x29, /**< <b>[0x29]</b><br>
								SUBB Rb, [Rw+] - Subtract indirect byte memory from direct GPR and post-increment source pointer by 1 <b>(2 bytes)</b><br>
								SUBB Rb, [Rw] - Subtract indirect byte memory from direct GPR <b>(2 bytes)</b><br>
								SUBB Rb, #data3 - Subtract immediate byte data from direct GPR <b>(2 bytes)</b> */
	C166_BCMP_bitaddr_bitaddr = 0x2A, ///< <b>[0x2A]</b> Compare direct bit to direct bit <b>(4 bytes)</b>
	C166_PRIOR_Rwn_Rwm = 0x2B, ///< <b>[0x2B]</b> Determine number of shift cycles to normalize direct word GPR and store result in direct word GPR <b>(2 bytes)</b>
	C166_ROR_Rwn_Rwm = 0x2C, ///< <b>[0x2C]</b> Rotate right direct word GPR; number of shift cycles specified by direct GPR <b>(2 bytes)</b>
	C166_JMPR_cc_EQ_or_Z_rel = 0x2D, ///< <b>[0x2D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff2 = 0x2E, ///< <b>[0x2E]</b> Clear direct bit (x.2) <b>(2 bytes)</b>
	C166_BSET_bitoff2 = 0x2F, ///< <b>[0x2F]</b> Set direct bit (x.2) <b>(2 bytes)</b>

	C166_SUBC_Rwn_Rwm = 0x30, ///< <b>[0x30]</b> Subtract direct word GPR from direct GPR with Carry <b>(2 bytes)</b>
	C166_SUBCB_Rbn_Rbm = 0x31, ///< <b>[0x31]</b> Subtract direct byte GPR from direct GPR with Carry <b>(2 bytes)</b>
	C166_SUBC_reg_mem = 0x32, ///< <b>[0x32]</b> Subtract direct word memory from direct register with Carry <b>(4 bytes)</b>
	C166_SUBCB_reg_mem = 0x33, ///< <b>[0x33]</b> Subtract direct byte memory from direct register with Carry <b>(4 bytes)</b>
	C166_SUBC_mem_reg = 0x34, ///< <b>[0x34]</b> Subtract direct word register from direct memory with Carry <b>(4 bytes)</b>
	C166_SUBCB_mem_reg = 0x35, ///< <b>[0x35]</b> Subtract direct byte register from direct memory with Carry <b>(4 bytes)</b>
	C166_SUBC_reg_data16 = 0x36, ///< <b>[0x36]</b> Subtract immediate word data from direct register with Carry <b>(4 bytes)</b>
	C166_SUBCB_reg_data8 = 0x37, ///< <b>[0x37]</b> Subtract immediate byte data from direct register with Carry <b>(4 bytes)</b>
	C166_SUBC_Rwn_x = 0x38, /**< <b>[0x38]</b><br>
								SUBC Rw, [Rw+] - Subtract indirect word memory from direct GPR with Carry and post-increment source pointer by 2 <b>(2 bytes)</b><br>
								SUBC Rw, [Rw] - Subtract immediate word data from direct GPR with Carry <b>(2 bytes)</b><br>
								SUBC Rw, #data3 - Subtract immediate word data from direct GPR with Carry <b>(2 bytes)</b> */
	C166_SUBCB_Rbn_x = 0x39, /**< <b>[0x39]</b><br>
								SUBCB Rb, [Rw+] - Subtract indirect byte memory from direct GPR with Carry and post-increment source pointer by 1 <b>(2 bytes)</b><br>
								SUBCB Rb, [Rw] - Subtract indirect byte memory from direct GPR with Carry <b>(2 bytes)</b><br>
								SUBCB Rb, #data3 - Subtract immediate byte data from direct GPR with Carry <b>(2 bytes)</b> */
	C166_BMOVN_bitaddr_bitaddr = 0x3A, ///< <b>[0x3A]</b> Move negated direct bit to direct bit <b>(4 bytes)</b>
	// 0x3B,
	C166_ROR_Rwn_data4 = 0x3C, ///< <b>[0x3C]</b> Rotate right direct word GPR; number of shift cycles specified by immediate data <b>(2 bytes)</b>
	C166_JMPR_cc_NE_or_NZ_rel = 0x3D, ///< <b>[0x3D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff3 = 0x3E, ///< <b>[0x3E]</b> Clear direct bit (x.3) <b>(2 bytes)</b>
	C166_BSET_bitoff3 = 0x3F, ///< <b>[0x3F]</b> Set direct bit (x.3) <b>(2 bytes)</b>

	C166_CMP_Rwn_Rwm = 0x40, ///< <b>[0x40]</b> Compare direct word GPR to direct GPR <b>(2 bytes)</b>
	C166_CMPB_Rbn_Rbm = 0x41, ///< <b>[0x41]</b> Compare direct byte GPR to direct GPR <b>(2 bytes)</b>
	C166_CMP_reg_mem = 0x42, ///< <b>[0x42]</b> Compare direct word memory to direct register <b>(4 bytes)</b>
	C166_CMPB_reg_mem = 0x43, ///< <b>[0x43]</b> Compare direct byte memory to direct register <b>(4 bytes)</b>
	// 0x44,
	// 0x45,
	C166_CMP_reg_data16 = 0x46, ///< <b>[0x46]</b> Compare immediate word data to direct register <b>(4 bytes)</b>
	C166_CMPB_reg_data8 = 0x47, ///< <b>[0x47]</b> Compare immediate byte data to direct register <b>(4 bytes)</b>
	C166_CMP_Rwn_x = 0x48, /**< <b>[0x48]</b><br>
								CMP Rw, [Rw+] - Compare indirect word memory to direct GPR and post-increment source pointer by 2 <b>(2 bytes)</b><br>
								CMP Rw, [Rw] - Compare indirect word memory to direct GPR <b>(2 bytes)</b><br>
								CMP Rw, #data3 - Compare immediate word data to direct GPR <b>(2 bytes)</b> */
	C166_CMPB_Rbn_x = 0x49, /**< <b>[0x49]</b><br>
								CMPB Rb, [Rw+] - Compare indirect word memory to direct GPR and post-increment source pointer by 2 <b>(2 bytes)</b><br>
								CMPB Rb, [Rw] - Compare indirect word memory to direct GPR <b>(2 bytes)</b><br>
								CMPB Rb, #data3 - Compare immediate byte data to direct GPR <b>(2 bytes)</b> */
	C166_BMOV_bitaddr_bitaddr = 0x4A, ///< <b>[0x4A]</b> Move direct bit to direct bit <b>(4 bytes)</b>
	C166_DIV_Rwn = 0x4B, ///< <b>[0x4B]</b> Signed divide register MDL by direct GPR (16-bit ÷ 16-bit) <b>(2 bytes)</b>
	C166_SHL_Rwn_Rwm = 0x4C, ///< <b>[0x4C]</b> Shift left direct word GPR; number of shift cycles specified by direct GPR <b>(2 bytes)</b>
	C166_JMPR_cc_V_rel = 0x4D, ///< <b>[0x4D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff4 = 0x4E, ///< <b>[0x4E]</b> Clear direct bit (x.4) <b>(2 bytes)</b>
	C166_BSET_bitoff4 = 0x4F, ///< <b>[0x4F]</b> Set direct bit (x.4) <b>(2 bytes)</b>
	C166_XOR_Rwn_Rwm = 0x50, ///< <b>[0x50]</b> Bitwise XOR direct word GPR with direct GPR <b>(2 bytes)</b>
	C166_XORB_Rbn_Rbm = 0x51, ///< <b>[0x51]</b> Bitwise XOR direct byte GPR with direct GPR <b>(2 bytes)</b>
	C166_XOR_reg_mem = 0x52, ///< <b>[0x52]</b> Bitwise XOR direct word memory with direct register <b>(4 bytes)</b>
	C166_XORB_reg_mem = 0x53, ///< <b>[0x53]</b> Bitwise XOR direct byte memory with direct register <b>(4 bytes)</b>
	C166_XOR_mem_reg = 0x54, ///< <b>[0x54]</b> Bitwise XOR direct word register with direct memory <b>(4 bytes)</b>
	C166_XORB_mem_reg = 0x55, ///< <b>[0x55]</b> Bitwise XOR direct byte register with direct memory <b>(4 bytes)</b>
	C166_XOR_reg_data16 = 0x56, ///< <b>[0x56]</b> Bitwise XOR immediate word data with direct register <b>(4 bytes)</b>
	C166_XORB_reg_data8 = 0x57, ///< <b>[0x57]</b> Bitwise XOR immediate byte data with direct register <b>(4 bytes)</b>
	C166_XOR_Rwn_x = 0x58, /**< <b>[0x58]</b><br>
								XOR Rw, [Rw+] - Bitwise XOR indirect word memory with direct GPR and post-increment source pointer by 2 <b>(2 bytes)</b><br>
								XOR Rw, [Rw] - Bitwise XOR indirect word memory with direct GPR <b>(2 bytes)</b><br>
								XOR Rw, #data3 - Bitwise XOR immediate word data with direct GPR <b>(2 bytes)</b> */
	C166_XORB_Rbn_x = 0x59, /**< <b>[0x59]</b><br>
								XORB Rb, [Rw+] - Bitwise XOR indirect byte memory with direct GPR and post-increment source pointer by 1 <b>(2 bytes)</b><br>
								XORB Rb, [Rw] - Bitwise XOR indirect byte memory with direct GPR <b>(2 bytes)</b><br>
								XORB Rb, #data3 - Bitwise XOR immediate byte data with direct GPR <b>(2 bytes)</b> */
	C166_BOR_bitaddr_bitaddr = 0x5A, ///< <b>[0x5A]</b> OR direct bit with direct bit <b>(4 bytes)</b>
	C166_DIVU_Rwn = 0x5B, ///< <b>[0x5B]</b> Unsigned long divide register MD by direct GPR (32-bit ÷ 16-bit) <b>(2 bytes)</b>
	C166_SHL_Rwn_data4 = 0x5C, ///< <b>[0x5C]</b> Shift left direct word GPR; number of shift cycles specified by immediate data <b>(2 bytes)</b>
	C166_JMPR_cc_NV_rel = 0x5D, ///< <b>[0x5D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff5 = 0x5E, ///< <b>[0x5E]</b> Clear direct bit (x.5) <b>(2 bytes)</b>
	C166_BSET_bitoff5 = 0x5F, ///< <b>[0x5F]</b> Set direct bit (x.5) <b>(2 bytes)</b>

	C166_AND_Rwn_Rwm = 0x60, ///< <b>[0x60]</b> Bitwise AND direct word GPR with direct GPR <b>(2 bytes)</b>
	C166_ANDB_Rbn_Rbm = 0x61, ///< <b>[0x61]</b> Bitwise AND direct byte GPR with direct GPR <b>(2 bytes)</b>
	C166_AND_reg_mem = 0x62, ///< <b>[0x62]</b> Bitwise AND direct word memory with direct register <b>(2 bytes)</b>
	C166_ANDB_reg_mem = 0x63, ///< <b>[0x63]</b> Bitwise AND direct byte memory with direct register <b>(2 bytes)</b>
	C166_AND_mem_reg = 0x64, ///< <b>[0x64]</b> Bitwise AND direct word register with direct memory <b>(4 bytes)</b>
	C166_ANDB_mem_reg = 0x65, ///< <b>[0x65]</b> Bitwise AND direct byte register with direct memory <b>(4 bytes)</b>
	C166_AND_reg_data16 = 0x66, ///< <b>[0x66]</b> Bitwise AND immediate word data with direct register <b>(4 bytes)</b>
	C166_ANDB_reg_data8 = 0x67, ///< <b>[0x67]</b> Bitwise AND immediate byte data with direct register <b>(4 bytes)</b>
	C166_AND_Rwn_x = 0x68, /**< <b>[0x68]</b><br>
								AND Rw, [Rw+] - BBitwise AND indirect word memory with direct GPR and post-increment source pointer by 2 <b>(2 bytes)</b><br>
								AND Rw, [Rw] - Bitwise AND indirect word memory with direct GPR <b>(2 bytes)</b><br>
								AND Rw, #data3 - Bitwise AND immediate word data with direct GPR <b>(2 bytes)</b> */
	C166_ANDB_Rbn_x = 0x69, /**< <b>[0x69]</b><br>
								ANDB Rw, [Rw+] - Bitwise ANDB indirect byte memory with direct GPR and post-increment source pointer by 1 <b>(2 bytes)</b><br>
								ANDB Rw, [Rw] - Bitwise ANDB indirect byte memory with direct GPR <b>(2 bytes)</b><br>
								ANDB Rw, #data3 - Bitwise ANDB immediate byte data with direct GPR <b>(2 bytes)</b> */
	C166_BAND_bitaddr_bitaddr = 0x6A, ///< <b>[0x6A]</b> AND direct bit with direct bit <b>(4 bytes)</b>
	C166_DIVL_Rwn = 0x6B, ///< <b>[0x6B]</b> Signed long divide register MD by direct GPR (32-bit ÷ 16-bit) <b>(2 bytes)</b>
	C166_SHR_Rwn_Rwm = 0x6C, ///< <b>[0x6C]</b> Shift right direct word GPR; number of shift cycles specified by direct GPR <b>(2 bytes)</b>
	C166_JMPR_cc_N_rel = 0x6D, ///< <b>[0x6D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff6 = 0x6E, ///< <b>[0x6E]</b> Clear direct bit (x.6) <b>(2 bytes)</b>
	C166_BSET_bitoff6 = 0x6F, ///< <b>[0x6F]</b> Set direct bit (x.6) <b>(2 bytes)</b>
	C166_OR_Rwn_Rwm = 0x70, ///< <b>[0x70]</b> Bitwise OR direct word GPR with direct GPR <b>(2 bytes)</b>
	C166_ORB_Rbn_Rbm = 0x71, ///< <b>[0x71]</b> Bitwise OR direct byte GPR with direct GPR <b>(2 bytes)</b>
	C166_OR_reg_mem = 0x72, ///< <b>[0x72]</b> Bitwise OR direct word memory with direct register <b>(4 bytes)</b>
	C166_ORB_reg_mem = 0x73, ///< <b>[0x73]</b> Bitwise OR direct byte memory with direct register <b>(4 bytes)</b>
	C166_OR_mem_reg = 0x74, ///< <b>[0x74]</b> Bitwise OR direct word register with direct memory <b>(4 bytes)</b>
	C166_ORB_mem_reg = 0x75, ///< <b>[0x75]</b> Bitwise OR direct byte register with direct memory <b>(4 bytes)</b>
	C166_OR_reg_data16 = 0x76, ///< <b>[0x76]</b> Bitwise OR immediate word data with direct register <b>(4 bytes)</b>
	C166_ORB_reg_data8 = 0x77, ///< <b>[0x77]</b> Bitwise OR immediate byte data with direct register <b>(4 bytes)</b>
	C166_OR_Rwn_x = 0x78, /**< <b>[0x78]</b><br>
								OR Rw, [Rw+] - Bitwise OR indirect byte memory with direct GPR and post-increment source pointer by 1 <b>(2 bytes)</b><br>
								OR Rw, [Rw] - Bitwise OR indirect byte memory with direct GPR <b>(2 bytes)</b><br>
								OR Rw, #data3 - Bitwise OR immediate word data with direct GPR <b>(2 bytes)</b> */
	C166_ORB_Rbn_x = 0x79, /**< <b>[0x79]</b><br>
								ORB Rb, [Rw+] - Bitwise OR indirect byte memory with direct GPR and post-increment source pointer by 1 <b>(2 bytes)</b><br>
								ORB Rb, [Rw] - Bitwise OR indirect byte memory with direct GPR <b>(2 bytes)</b><br>
								ORB Rb, #data3 - Bitwise OR immediate byte data with direct GPR <b>(2 bytes)</b> */
	C166_BXOR_bitaddr_bitaddr = 0x7A, ///< <b>[0x7A]</b> XOR direct bit with direct bit <b>(4 bytes)</b>
	C166_DIVLU_Rwn = 0x7B, ///< <b>[0x7B]</b> Unsigned long divide register MD by direct GPR (32-bit ÷ 16-bit) <b>(2 bytes)</b>
	C166_SHR_Rwn_data4 = 0x7C, ///< <b>[0x7C]</b> Shift right direct word GPR; number of shift cycles specified by immediate data <b>(2 bytes)</b>
	C166_JMPR_cc_NN_rel = 0x7D, ///< <b>[0x7D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff7 = 0x7E, ///< <b>[0x7E]</b> Clear direct bit (x.7) <b>(2 bytes)</b>
	C166_BSET_bitoff7 = 0x7F, ///< <b>[0x7F]</b> Set direct bit (x.7) <b>(2 bytes)</b>
	C166_CMPI1_Rwn_data4 = 0x80, ///< <b>[0x80]</b> Compare immediate word data to direct GPR and increment GPR by 1 <b>(2 bytes)</b>
	C166_NEG_Rwn = 0x81, ///< <b>[0x81]</b> Negate direct word GPR <b>(2 bytes)</b>
	C166_CMPI1_Rwn_mem = 0x82, ///< <b>[0x82]</b> Compare direct word memory to direct GPR and increment GPR by 1 <b>(4 bytes)</b>
	C166_CoXXX_83 = 0x83, ///< <b>[0x83]</b> CoXXX <b>(v2 family)</b> <b>(4 bytes)</b>
	C166_MOV_oRwn_mem = 0x84, ///< <b>[0x84]</b> Move direct word memory to indirect memory <b>(4 bytes)</b>
	C166_ENWDT = 0x85, ///< <b>[0x85]</b> Enable Watchdog Timer <b>(4 bytes)</b> <b>(v2 family)</b>
	C166_CMPI1_Rwn_data16 = 0x86, ///< <b>[0x86]</b> Compare immediate word data to direct GPR and increment GPR by 1 <b>(4 bytes)</b>
	C166_IDLE = 0x87, ///< <b>[0x87]</b> Enter Idle Mode <b>(4 bytes)</b>
	C166_MOV_noRwm_Rwn = 0x88, ///< <b>[0x88]</b> Pre-decrement destination pointer by 2 and move direct word GPR to indirect memory <b>(2 bytes)</b>
	C166_MOVB_noRwm_Rbn = 0x89, ///< <b>[0x89]</b> Pre-decrement destination pointer by 1 and move direct byte GPR to indirect memory <b>(2 bytes)</b>
	C166_JB_bitaddr_rel = 0x8A, ///< <b>[0x8A]</b> Jump relative if direct bit is set <b>(4 bytes)</b>
	// 0x8B
	C166_SBRK = 0x8C, ///< <b>[0x8C] May be not implemented on some chip versions</b>
	C166_JMPR_cc_C_or_ULT_rel = 0x8D, ///< <b>[0x8D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff8 = 0x8E, ///< <b>[0x8E]</b> Clear direct bit (x.8) <b>(2 bytes)</b>
	C166_BSET_bitoff8 = 0x8F, ///< <b>[0x8F]</b> Set direct bit (x.8) <b>(2 bytes)</b>
	C166_CMPI2_Rwn_data4 = 0x90, ///< <b>[0x90]</b> Compare immediate word data to direct GPR and increment GPR by 2 <b>(2 bytes)</b>
	C166_CPL_Rwn = 0x91, ///< <b>[0x91]</b> Complement direct word GPR <b>(2 bytes)</b>
	C166_CMPI2_Rwn_mem = 0x92, ///< <b>[0x92]</b> Compare direct word memory to direct GPR and increment GPR by 2 <b>(4 bytes)</b>
	C166_CoXXX_93 = 0x93, ///< <b>[0x93]</b> CoXXX <b>(v2 family)</b> <b>(4 bytes)</b>
	C166_MOV_mem_oRwn = 0x94, ///< <b>[0x94]</b> Move indirect word memory to direct memory <b>(4 bytes)</b>
	// 0x95
	C166_CMPI2_Rwn_data16 = 0x96, ///< <b>[0x96]</b> Compare immediate word data to direct GPR and increment GPR by 2 <b>(4 bytes)</b>
	C166_PWRDN = 0x97, ///< <b>[0x97]</b> Enter Power Down Mode (supposes NMI-pin being low) <b>(4 bytes)</b>
	C166_MOV_Rwn_oRwmp = 0x98, ///< <b>[0x98]</b> Move indirect word memory to direct GPR and post-increment source pointer by 2 <b>(2 bytes)</b>
	C166_MOVB_Rbn_oRwmp = 0x99, ///< <b>[0x99]</b> Move indirect byte memory to direct GPR and post-increment source pointer by 1 <b>(2 bytes)</b>
	C166_JNB_bitaddr_rel = 0x9A, ///< <b>[0x9A]</b> Jump relative if direct bit is not set <b>(4 bytes)</b>
	C166_TRAP_trap7 = 0x9B, ///< <b>[0x9B]</b> Call interrupt service routine via immediate trap number <b>(2 bytes)</b>
	C166_JMPI_cc_oRwn = 0x9C, ///< <b>[0x9C]</b> Jump indirect if condition is met <b>(2 bytes)</b>
	C166_JMPR_cc_NC_or_NGE_rel = 0x9D, ///< <b>[0x9D]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff9 = 0x9E, ///< <b>[0x9E]</b> Clear direct bit (x.9) <b>(2 bytes)</b>
	C166_BSET_bitoff9 = 0x9F, ///< <b>[0x9F]</b> Set direct bit (x.9) <b>(2 bytes)</b>
	C166_CMPD1_Rwn_data4 = 0xA0, ///< <b>[0xA0]</b> Compare immediate word data to direct GPR and decrement GPR by 1 <b>(2 bytes)</b>
	C166_NEGB_Rbn = 0xA1, ///< <b>[0xA1]</b> Negate direct byte GPR <b>(2 bytes)</b>
	C166_CMPD1_Rwn_mem = 0xA2, ///< <b>[0xA2]</b> Compare direct word memory to direct GPR and decrement GPR by 1 <b>(4 bytes)</b>
	C166_CoXXX_A3 = 0xA3, ///< <b>[0xA3]</b> CoXXX <b>(v2 family)</b> <b>(4 bytes)</b>
	C166_MOVB_oRwn_mem = 0xA4, ///< <b>[0xA4]</b> Move direct byte memory to indirect memory <b>(4 bytes)</b>
	C166_DISWDT = 0xA5, ///< <b>[0xA5]</b> Disable Watchdog Timer <b>(4 bytes)</b>
	C166_CMPD1_Rwn_data16 = 0xA6, ///< <b>[0xA6]</b> Compare immediate word data to direct GPR and decrement GPR by 1 <b>(4 bytes)</b>
	C166_SRVWDT = 0xA7, ///< <b>[0xA7]</b> Service Watchdog Timer <b>(4 bytes)</b>
	C166_MOV_Rwn_oRwm = 0xA8, ///< <b>[0xA8]</b> Move indirect word memory to direct GPR <b>(2 bytes)</b>
	C166_MOVB_Rbn_oRwm = 0xA9, ///< <b>[0xA9]</b> Move indirect byte memory to direct GPR <b>(2 bytes)</b>
	C166_JBC_bitaddr_rel = 0xAA, ///< <b>[0xAA]</b> Jump relative and clear bit if direct bit is set <b>(4 bytes)</b>
	C166_CALLI_cc_Rwn = 0xAB, ///< <b>[0xAB]</b> Call indirect subroutine if condition is met <b>(2 bytes)</b>
	C166_ASHR_Rwn_Rwm = 0xAC, ///< <b>[0xAC]</b> Arithmetic (sign bit) shift right direct word GPR; number of shift cycles specified by direct GPR <b>(2 bytes)</b>
	C166_JMPR_cc_SGT_rel = 0xAD, ///< <b>[0xAD]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff10 = 0xAE, ///< <b>[0xAE]</b> Clear direct bit (x.10) <b>(2 bytes)</b>
	C166_BSET_bitoff10 = 0xAF, ///< <b>[0xAF]</b> Set direct bit (x.10) <b>(2 bytes)</b>
	C166_CMPD2_Rwn_data4 = 0xB0, ///< <b>[0xB0]</b> Compare immediate word data to direct GPR and decrement GPR by 2 <b>(2 bytes)</b>
	C166_CPLB_Rbn = 0xB1, ///< <b>[0xB1]</b> Complement direct byte GPR <b>(2 bytes)</b>
	C166_CMPD2_Rwn_mem = 0xB2, ///< <b>[0xB2]</b> Compare direct word memory to direct GPR and decrement GPR by 2 <b>(4 bytes)</b>
	C166_CoSTORE_B3 = 0xB3, // 0xB3, // CoSTORE
	C166_MOVB_mem_oRwn = 0xB4, ///< <b>[0xB4]</b> Move indirect word memory to direct memory <b>(4 bytes)</b>
	C166_EINIT = 0xB5, ///< <b>[0xB5]</b> Signify End-of-Initialization on RSTOUT-pin <b>(4 bytes)</b>
	C166_CMPD2_Rwn_data16 = 0xB6, ///< <b>[0xB6]</b> Compare immediate word data to direct GPR and decrement GPR by 2 <b>(4 bytes)</b>
	C166_SRST = 0xB7, ///< <b>[0xB7]</b> Software Reset <b>(4 bytes)</b>
	C166_MOV_oRwm_Rwn = 0xB8, ///< <b>[0xB8]</b> Move direct word GPR to indirect memory <b>(2 bytes)</b>
	C166_MOVB_oRwm_Rbn = 0xB9, ///< <b>[0xB9]</b> Move direct byte GPR to indirect memory <b>(2 bytes)</b>
	C166_JNBS_bitaddr_rel = 0xBA, ///< <b>[0xBA]</b> Jump relative and set bit if direct bit is not set <b>(4 bytes)</b>
	C166_CALLR_rel = 0xBB, ///< <b>[0xBB]</b> Call relative subroutine <b>(2 bytes)</b>
	C166_ASHR_Rwn_data4 = 0xBC, ///< <b>[0xBC]</b> Arithmetic (sign bit) shift right direct word GPR; number of shift cycles specified by immediate data <b>(2 bytes)</b>
	C166_JMPR_cc_SLE_rel = 0xBD, ///< <b>[0xBD]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff11 = 0xBE, ///< <b>[0xBE]</b> Clear direct bit (x.11) <b>(2 bytes)</b>
	C166_BSET_bitoff11 = 0xBF, ///< <b>[0xBF]</b> Set direct bit (x.11) <b>(2 bytes)</b>
	C166_MOVBZ_Rwn_Rbm = 0xC0, ///< <b>[0xC0]</b> Move direct byte GPR with zero extension to direct word GPR <b>(2 bytes)</b>
	// 0xC1
	C166_MOVBZ_reg_mem = 0xC2, ///< <b>[0xC2]</b> Move direct byte memory with zero extension to direct word register <b>(4 bytes)</b>
	C166_CoSTORE_C3 = 0xC3, // CoSTORE
	C166_MOV_oRwm_data16_Rwn = 0xC4, ///< <b>[0xC4]</b> Move direct word GPR to indirect memory by base plus constant <b>(4 bytes)</b>
	C166_MOVBZ_mem_reg = 0xC5, ///< <b>[0xC5]</b> Move direct byte register with zero extension to direct word memory <b>(4 bytes)</b>
	C166_SCXT_reg_data16 = 0xC6, ///< <b>[0xBE]</b> Push direct word register onto system stack and update register with immediate data <b>(4 bytes)</b>
	// 0xC7
	C166_MOV_oRwn_oRwm = 0xC8, ///< <b>[0xC8]</b> Move indirect word memory to indirect memory <b>(2 bytes)</b>
	C166_MOVB_oRwn_oRwm = 0xC9, ///< <b>[0xC9]</b> Move indirect byte memory to indirect memory <b>(2 bytes)</b>
	C166_CALLA_cc_caddr = 0xCA, ///< <b>[0xCA]</b> Call absolute subroutine if condition is met <b>(4 bytes)</b>
	C166_RET = 0xCB, ///< <b>[0xCB]</b> Return from intra-segment subroutine <b>(2 bytes)</b>
	C166_NOP = 0xCC, ///< <b>[0xCC]</b> Null operation <b>(2 bytes)</b>
	C166_JMPR_cc_SLT_rel = 0xCD, ///< <b>[0xCD]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff12 = 0xCE, ///< <b>[0xCE]</b> Clear direct bit (x.12) <b>(2 bytes)</b>
	C166_BSET_bitoff12 = 0xCF, ///< <b>[0xCF]</b> Set direct bit (x.12) <b>(2 bytes)</b>
	C166_MOVBS_Rwn_Rbm = 0xD0, ///< <b>[0xD0]</b> Move direct byte GPR with sign extension to direct word GPR <b>(2 bytes)</b>
	C166_ATOMIC_or_EXTR_irang2 = 0xD1, /**< <b>[0xD1]</b><br>
								ATOMIC #irang2 - Begin ATOMIC sequence <b>(2 bytes)</b><br>
								EXTR #irang2 - Begin EXTended Register sequence <b>(2 bytes)</b><br>*/
	C166_MOVBS_reg_mem = 0xD2, ///< <b>[0xD2]</b> Move direct byte memory with sign extension to direct word register <b>(4 bytes)</b>
	C166_CoMOV = 0xD3, // CoMOV
	C166_MOV_Rwn_oRwm_data16 = 0xD4, ///< <b>[0xD4]</b> Move indirect word memory by base plus constant to direct word GPR <b>(4 bytes)</b>
	C166_MOVBS_mem_reg = 0xD5, ///< <b>[0xD5]</b> Move direct byte register with sign extension to direct word memory <b>(4 bytes)</b>
	C166_SCXT_reg_mem = 0xD6, ///< <b>[0xD6]</b> Push direct word register onto system stack and update register with immediate data <b>(4 bytes)</b>
	C166_EXTP_or_EXTS_pag10_or_seg8_irang2 = 0xD7, /**< <b>[0xD7]</b><br>
								EXTP #pag10, #irang2 - Begin EXTended Page sequence <b>(4 bytes)</b><br>
								EXTPR #pag10, #irang2 - Begin EXTended Page and Register sequence <b>(4 bytes)</b><br>
								EXTS #seg8, #irang2 - Begin EXTended Segment sequence <b>(4 bytes)</b><br>
								EXTSR #seg8, #irang2 - Begin EXTended Segment and Register sequence <b>(4 bytes)</b><br> */
	C166_MOV_oRwnp_oRwm = 0xD8, ///< <b>[0xD8]</b> Move indirect word memory to indirect memory and post-increment destination pointer by 2 <b>(2 bytes)</b>
	C166_MOVB_oRwnp_oRwm = 0xD9, ///< <b>[0xD9]</b> Move indirect byte memory to indirect memory and post-increment destination pointer by 1 <b>(2 bytes)</b>
	C166_CALLS_seg_caddr = 0xDA, ///< <b>[0xDA]</b> Call absolute subroutine in any code segment <b>(4 bytes)</b>
	C166_RETS = 0xDB, ///< <b>[0xDB]</b> Return from inter-segment subroutine <b>(2 bytes)</b>
	C166_EXTP_or_EXTS_Rwm_irang2 = 0xDC, /**< <b>[0xDC]</b><br>
								EXTP Rw, #irang2 - Begin EXTended Page sequence <b>(2 bytes)</b><br>
								EXTPR Rw, #irang2 - Begin EXTended Page and Register sequence <b>(2 bytes)</b><br>
								EXTS Rw, #irang2 - Begin EXTended Segment sequence <b>(2 bytes)</b><br>
								EXTSR Rw, #irang2 - Begin EXTended Segment and Register sequence <b>(2 bytes)</b><br> */
	C166_JMPR_cc_SGE_rel = 0xDD, ///< <b>[0xDD]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff13 = 0xDE, ///< <b>[0xDE]</b> Clear direct bit (x.13) <b>(2 bytes)</b>
	C166_BSET_bitoff13 = 0xDF, ///< <b>[0xDF]</b> Set direct bit (x.13) <b>(2 bytes)</b>
	C166_MOV_Rwn_data4 = 0xE0, ///< <b>[0xE0]</b> Move immediate word data to direct GPR <b>(2 bytes)</b>
	C166_MOVB_Rbn_data4 = 0xE1, ///< <b>[0xE1]</b> Move immediate byte data to direct GPR <b>(2 bytes)</b>
	C166_PCALL_reg_caddr = 0xE2, ///< <b>[0xE2]</b> Push direct word register onto system stack and call absolute subroutine <b>(4 bytes)</b>
	// 0xE3
	C166_MOVB_oRwm_data16_Rbn = 0xE4, ///< <b>[0xE4]</b> Move direct byte GPR to indirect memory by base plus constant <b>(4 bytes)</b>
	// 0xE5
	C166_MOV_reg_data16 = 0xE6, ///< <b>[0xE6]</b> Move immediate word data to direct register <b>(4 bytes)</b>
	C166_MOVB_reg_data8 = 0xE7, ///< <b>[0xE7]</b> Move immediate byte data to direct register <b>(4 bytes)</b>
	C166_MOV_oRwn_oRwmp = 0xE8, ///< <b>[0xE8]</b> Move indirect word memory to indirect memory and post-increment source pointer by 2 <b>(2 bytes)</b>
	C166_MOVB_oRwn_oRwmp = 0xE9, ///< <b>[0xE9]</b> Move indirect byte memory to indirect memory and post-increment source pointer by 1 <b>(2 bytes)</b>
	C166_JMPA_cc_caddr = 0xEA, ///< <b>[0xEA]</b> Jump absolute if condition is met <b>(4 bytes)</b>
	C166_RETP_reg = 0xEB, ///< <b>[0xEB]</b> Return from intra-segment subroutine and pop direct word register from system stack <b>(2 bytes)</b>
	C166_PUSH_reg = 0xEC, ///< <b>[0xEC]</b> Push direct word register onto system stack <b>(2 bytes)</b>
	C166_JMPR_cc_UGT_rel = 0xED, ///< <b>[0xED]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff14 = 0xEE, ///< <b>[0xEE]</b> Clear direct bit (x.14) <b>(2 bytes)</b>
	C166_BSET_bitoff14 = 0xEF, ///< <b>[0xEF]</b> Set direct bit (x.14) <b>(2 bytes)</b>
	C166_MOV_Rwn_Rwm = 0xF0, ///< <b>[0xF0]</b> Move direct word GPR to direct GPR <b>(2 bytes)</b>
	C166_MOVB_Rbn_Rbm = 0xF1, ///< <b>[0xF1]</b> Move direct byte GPR to direct GPR <b>(2 bytes)</b>
	C166_MOV_reg_mem = 0xF2, ///< <b>[0xF2]</b> Move direct word memory to direct register <b>(4 bytes)</b>
	C166_MOVB_reg_mem = 0xF3, ///< <b>[0xF3]</b> Move direct byte memory to direct register <b>(4 bytes)</b>
	C166_MOVB_Rbn_oRwm_data16 = 0xF4, ///< <b>[0xF4]</b> Move indirect byte memory by base plus constant to direct byte GPR <b>(4 bytes)</b>
	// 0xF5
	C166_MOV_mem_reg = 0xF6, ///< <b>[0xF6]</b> Move direct word register to direct memory <b>(4 bytes)</b>
	C166_MOVB_mem_reg = 0xF7, ///< <b>[0xF7]</b> Move direct byte register to direct memory <b>(4 bytes)</b>
	// 0xF8
	// 0xF9
	C166_JMPS_seg_caddr = 0xFA, ///< <b>[0xFA]</b> Jump absolute to a code segment <b>(4 bytes)</b>
	C166_RETI = 0xFB, ///< <b>[0xFB]</b> Return from interrupt service subroutine <b>(2 bytes)</b>
	C166_POP_reg = 0xFC, ///< <b>[0xFC]</b> Pop direct word register from system stack <b>(2 bytes)</b>
	C166_JMPR_cc_ULE_rel = 0xFD, ///< <b>[0xFD]</b> Jump relative if condition is met <b>(2 bytes)</b>
	C166_BCLR_bitoff15 = 0xFE, ///< <b>[0xFE]</b> Clear direct bit (x.15) <b>(2 bytes)</b>
	C166_BSET_bitoff15 = 0xFF, ///< <b>[0xFF]</b> Set direct bit (x.15) <b>(2 bytes)</b>
} c166_opcodes;

/*!
 * \brief C166 Branch Condition Codes
 *
 * Defines condition codes used for conditional branching instructions
 * Datasheet page 39
 * (*) Only usable with the JMPA and CALLA instructions
 */
// clang-format off
typedef enum {
	C166_CC_UC = 0x00,	///< CCNc = 0x00; [0D] Unconditional
	C166_CC_NET = 0x02,	///< CCNc = 0x01; [1D] Not equal AND not end of table
	// C166_CC_Z = 0x04,	///< CCNc = 0x02; [2D] Zero
	C166_CC_EQ = 0x04,	///< CCNc = 0x02; [2D] Equal
	// C166_CC_NZ = 0x06,	///< CCNc = 0x03; [3D] Not zero
	C166_CC_NE = 0x06,	///< CCNc = 0x03; [3D] Not equal
	C166_CC_V = 0x08,	///< CCNc = 0x04; [4D] Overflow
	C166_CC_NV = 0x0A,	///< CCNc = 0x05; [5D] No overflow
	C166_CC_N = 0x0C,	///< CCNc = 0x06; [6D] Negative
	C166_CC_NN = 0x0E,	///< CCNc = 0x07; [7D] Not negative
	C166_CC_C = 0x10,	///< CCNc = 0x08; [8D] Carry
	// C166_CC_ULT = 0x10,	///< CCNc = 0x08; [8D] Unsigned less than
	C166_CC_NC = 0x12,	///< CCNc = 0x09; [9D] No carry
	// C166_CC_UGE = 0x12,	///< CCNc = 0x09; [9D] Unsigned greater than or equal
	C166_CC_SGT = 0x14,	///< CCNc = 0x0A; [AD] Signed greater than
	C166_CC_SLE = 0x16,	///< CCNc = 0x0B; [BD] Signed less than or equal
	C166_CC_SLT = 0x18,	///< CCNc = 0x0C; [CD] Signed less than
	C166_CC_SGE = 0x1A,	///< CCNc = 0x0D; [DD] Signed greater than or equal
	C166_CC_UGT = 0x1C,	///< CCNc = 0x0E; [ED] Unsigned greater than
	C166_CC_ULE = 0x1E,	///< CCNc = 0x0F; [FD] Unsigned less than or equal

	C166_CC_NUSR0 = 0x01,     ///< USR-bit 0 is cleared (*)
	C166_CC_NUSR1 = 0x03,     ///< USR-bit 1 is cleared (*)
	C166_CC_USR0 = 0x05,      ///< USR-bit 0 is set 1
	C166_CC_USR1 = 0x07       ///< USR-bit 1 is set 1
} C166CondCode;

const char *c166_rw[] = {
	"r0", "r1", "r2", "r3",
	"r4", "r5", "r6", "r7",
	"r8", "r9", "r10", "r11",
	"r12", "r13", "r14", "r15",
};

const char *c166_rb[] = {
	"rl0", "rh0",
	"rl1", "rh1",
	"rl2", "rh2",
	"rl3", "rh3",
	"rl4", "rh4",
	"rl5", "rh5",
	"rl6", "rh6",
	"rl7", "rh7",
};

/**
 * Maps hexcodes to condition codes for JMPR instructions
 * Used to determine the condition code for conditional jump instructions
 */
// C166 condition code names
static const char *conds_names[] = {
	[C166_CC_UC]    = "cc_UC",      ///< Unconditional
	[C166_CC_V]     = "cc_V",       ///< Overflow
	[C166_CC_NV]    = "cc_NV",      ///< No Overflow
	[C166_CC_N]     = "cc_N",       ///< Negative
	[C166_CC_NN]    = "cc_NN",      ///< Not Negative
	[C166_CC_C]     = "cc_C/ULT",   ///< Carry
	[C166_CC_NC]    = "cc_NC/UGE",  ///< No Carry
	[C166_CC_EQ]    = "cc_Z/EQ",    ///< Equal
	[C166_CC_NE]    = "cc_NZ/NE",   ///< Not Equal
	[C166_CC_ULE]   = "cc_ULE",     ///< Unsigned Less Than or Equal
	[C166_CC_UGT]   = "cc_UGT",     ///< Unsigned Greater Than
	[C166_CC_SLE]   = "cc_SLE",     ///< Signed Less Than or Equal
	[C166_CC_SGE]   = "cc_SGE",     ///< Signed Greater Than or Equal
	[C166_CC_SGT]   = "cc_SGT",     ///< Signed Greater Than
	[C166_CC_NET]   = "cc_NET",     ///< Not Equal and Not End-of-Table

	[C166_CC_SLT]   = "cc_SLT",     ///< Signed Less Than

	[C166_CC_NUSR0] = "cc_NUSR0",   ///< USR-bit 0 is cleared (*)
	[C166_CC_NUSR1] = "cc_NUSR1",   ///< USR-bit 1 is cleared (*)
	[C166_CC_USR0]  = "cc_USR0",    ///< USR-bit 0 is set 1
	[C166_CC_USR1]  = "cc_USR1"     ///< USR-bit 1 is set 1
};
// clang-format on

static const char *conds(ut8 cc) {
	return conds_names[cc << 1];
}
static const char *conds_extended(ut8 cc) {
	return conds_names[cc];
}

typedef enum {
	C166_EXT_MODE_NONE,
	C166_EXT_MODE_PAGE,
	C166_EXT_MODE_SEG,
} C166ExtMode;

// clang-format off
typedef struct {
	bool esfr;  		///< Extended register sequence active
	C166ExtMode mode; 	///< Extended page/seq mode
	ut8 i; 			///< Number of unstructions remaining until state exits
	ut16 value; 		///< Value of ext
} C166ExtState;

typedef struct {
	ut32 last_addr; 	///< State of last addr dissassembled
	C166ExtState ext;
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns;
} C166State;
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
static bool check_unused_opcode(ut8 opcode);
#endif /* C166_DISAS_H */
