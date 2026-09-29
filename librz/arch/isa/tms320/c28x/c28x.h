// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TMS320_C28X_H
#define RZ_TMS320_C28X_H

#include <rz_types.h>
#include <rz_analysis.h> // RzAnalysisOp, _RzAnalysisOpType

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * Decoder and formatter for the TMS320C28x (C2000) fixed-point core.
 *
 * Registers: ACC (AH:AL), P (PH:PL), XT (T:TL), XAR0-XAR7 (low halves AR0-AR7),
 * SP and DP. Memory is 16-bit words and an instruction is one or two words.
 * Encodings are from TI SPRU430F.
 *
 * Most instructions address memory through the 8-bit loc16/loc32 field
 * (SPRU430F Table 5-1). c28x_decode() decodes it once into a \ref C28xInsn,
 * which c28x_format(), c28x_fill_analysis() and c28x_opex() read.
 *
 * The field is decoded as AMODE = 0, the reset default and what the compiler
 * emits. AMODE = 1 reads 0x00-0x7F and 0xC0-0xFF the C2xLP way; 0x80-0xBF is
 * the same in both modes.
 */

/** Named register operands. */
typedef enum {
	C28X_REG_NONE = 0,
	C28X_REG_ACC, ///< 32-bit accumulator
	C28X_REG_AH, ///< accumulator high half
	C28X_REG_AL, ///< accumulator low half
	C28X_REG_P, ///< 32-bit product register
	C28X_REG_PH, ///< product high half
	C28X_REG_PL, ///< product low half
	C28X_REG_XT, ///< 32-bit multiplicand register
	C28X_REG_T, ///< XT high half (multiplicand / shift count)
	C28X_REG_TL, ///< XT low half
	C28X_REG_XAR0, ///< 32-bit auxiliary registers
	C28X_REG_XAR1,
	C28X_REG_XAR2,
	C28X_REG_XAR3,
	C28X_REG_XAR4,
	C28X_REG_XAR5,
	C28X_REG_XAR6,
	C28X_REG_XAR7,
	C28X_REG_AR0, ///< low halves of XAR0-XAR7
	C28X_REG_AR1,
	C28X_REG_AR2,
	C28X_REG_AR3,
	C28X_REG_AR4,
	C28X_REG_AR5,
	C28X_REG_AR6,
	C28X_REG_AR7,
	C28X_REG_SP, ///< stack pointer
	C28X_REG_DP, ///< data page pointer
	C28X_REG_PC, ///< program counter
	C28X_REG_RPC, ///< return program counter
	C28X_REG_ST0, ///< status register 0
	C28X_REG_ST1, ///< status register 1
	C28X_REG_IER, ///< interrupt enable register
	C28X_REG_IFR, ///< interrupt flag register
	C28X_REG_DBGIER, ///< debug interrupt enable register
	C28X_REG_OVC, ///< overflow counter (ST0 field)
	// VCU (SPRUHS1): eight result registers and two status/shift registers,
	// present on the F2806x and F2837x parts that carry the co-processor
	C28X_REG_VR0,
	C28X_REG_VR1,
	C28X_REG_VR2,
	C28X_REG_VR3,
	C28X_REG_VR4,
	C28X_REG_VR5,
	C28X_REG_VR6,
	C28X_REG_VR7,
	C28X_REG_VR8,
	C28X_REG_VT0,
	C28X_REG_VT1,
	C28X_REG_PM, ///< product shift mode (ST0 field)
	C28X_REG_ARP, ///< auxiliary register pointer (ST1 field)
	C28X_REG_ACC_P, ///< the ACC:P 64-bit pair
	C28X_REG_AR1_AR0, ///< register pairs pushed/popped as one
	C28X_REG_AR3_AR2,
	C28X_REG_AR5_AR4,
	C28X_REG_AR1H_AR0H,
	C28X_REG_DP_ST1,
	C28X_REG_T_ST0,
	// Operand names that are not architectural registers: single status bits
	// that SETC/CLRC address by name, and the two interrupt sources INTR takes
	// as a name rather than a vector number.
	C28X_REG_AMODE,
	C28X_REG_OBJMODE,
	C28X_REG_M0M1MAP,
	C28X_REG_XF,
	C28X_REG_NMI,
	C28X_REG_EMUINT,
	// FPU32: result registers R0H-R7H, the status register and the repeat-block
	// register. R0H-R7H stay consecutive for a 3-bit field.
	C28X_REG_R0H,
	C28X_REG_R1H,
	C28X_REG_R2H,
	C28X_REG_R3H,
	C28X_REG_R4H,
	C28X_REG_R5H,
	C28X_REG_R6H,
	C28X_REG_R7H,
	C28X_REG_STF,
	C28X_REG_RB,
	// FPU64 splits each result register into RaH:RaL and names the 64-bit whole
	// Ra. The fast integer division works on fixed pairs of result registers.
	C28X_REG_R0L,
	C28X_REG_R1L,
	C28X_REG_R2L,
	C28X_REG_R3L,
	C28X_REG_R4L,
	C28X_REG_R5L,
	C28X_REG_R6L,
	C28X_REG_R7L,
	C28X_REG_R0,
	C28X_REG_R1,
	C28X_REG_R2,
	C28X_REG_R3,
	C28X_REG_R4,
	C28X_REG_R5,
	C28X_REG_R6,
	C28X_REG_R7,
	C28X_REG_R1H_R0H,
	C28X_REG_R2H_R4H,
	C28X_REG_R3H_R5H,
	// VCU registers that only moves and CRC set-up name
	C28X_REG_VCRC,
	C28X_REG_VSTATUS,
	C28X_REG_VCRCPOLY,
	C28X_REG_VCRCDSIZE,
	C28X_REG_VCRCPSIZE,
	C28X_REG_VCRCSIZE,
} C28xReg;

/** loc16/loc32 addressing modes, AMODE = 0 (SPRU430F Table 5-1). */
typedef enum {
	C28X_AM_NONE = 0,
	C28X_AM_DP, ///< \@6bit: DP-relative direct
	C28X_AM_SP, ///< *-SP[6bit]: stack-relative
	C28X_AM_SP_POSTINC, ///< *SP++
	C28X_AM_SP_PREDEC, ///< *--SP
	C28X_AM_XAR_NONE, ///< *XARn with no modification
	C28X_AM_XAR_POSTINC, ///< *XARn++
	C28X_AM_XAR_POSTDEC, ///< *XARn--
	C28X_AM_XAR_MOD_INC, ///< XARn++ -- NORM adjusts the register, it does not read through it
	C28X_AM_XAR_MOD_DEC, ///< XARn--
	C28X_AM_XAR_PREDEC, ///< *--XARn
	C28X_AM_XAR_AR0, ///< *+XARn[AR0]
	C28X_AM_XAR_AR1, ///< *+XARn[AR1]
	C28X_AM_XAR_IMM, ///< *+XARn[3bit]
	C28X_AM_ARP, ///< * (C2xLP indirect through ARP)
	C28X_AM_ARP_POSTINC, ///< *++
	C28X_AM_ARP_POSTDEC, ///< *--
	C28X_AM_ARP_IDX_INC, ///< *0++
	C28X_AM_ARP_IDX_DEC, ///< *0--
	C28X_AM_ARP_BR_INC, ///< *BR0++
	C28X_AM_ARP_BR_DEC, ///< *BR0--
	C28X_AM_ARP_SET, ///< *,ARPn
	C28X_AM_CIRC, ///< *AR6%++ circular
	C28X_AM_REG, ///< \@reg: register-direct (see \ref C28xOperand::reg)
} C28xAddrMode;

/** Operand kind within a decoded instruction. */
typedef enum {
	C28X_OP_NONE = 0,
	C28X_OP_REG_LOW, ///< low half of a VCU register, spelled VRnL
	C28X_OP_REG, ///< named register in \ref C28xOperand::reg
	C28X_OP_MEM, ///< loc16/loc32 access (see \ref C28xAddrMode)
	C28X_OP_IMM, ///< immediate constant in \ref C28xOperand::imm
	C28X_OP_SHIFT, ///< shift amount, rendered as "<< #n"
	C28X_OP_COND, ///< condition code in \ref C28xOperand::imm
	C28X_OP_PCREL, ///< branch target, absolute address in \ref C28xOperand::imm
	C28X_OP_PMA, ///< program-memory address, absolute
	C28X_OP_PMA_IND, ///< program memory read as data, "*(pma)"
	C28X_OP_PMA_DP, ///< the same through the page pointer, "0:pma"
	C28X_OP_DMA, ///< data-memory address, absolute
	C28X_OP_PORT, ///< I/O space port address, rendered as "*(PA)"
	C28X_OP_MODE, ///< ST0/ST1 mode bit mask for SETC/CLRC
	C28X_OP_INTR, ///< interrupt selector for INTR, rendered by name
	C28X_OP_FCOND, ///< FPU condition code in \ref C28xOperand::imm
	C28X_OP_FFLAGS, ///< MOVST0 flag mask in \ref C28xOperand::imm
	C28X_OP_FSETFLG, ///< SETFLG/SAVE flag values, for the flags in \ref C28xOperand::mask
	C28X_OP_FZERO, ///< the constant #0.0
	C28X_OP_PAR, ///< start of the parallel half; its \ref C28xInsnId in \ref C28xOperand::imm
	C28X_OP_REG_HIGH, ///< high half of a VCU register, spelled VRnH
	C28X_OP_VSMPAIR, ///< state-metric pair VSM(2n+1):VSM(2n), n in \ref C28xOperand::imm
	C28X_OP_VSHL, ///< "<< #n" after the register it shifts, zero included
	C28X_OP_VSHR, ///< ">> #n" after the register it shifts, zero included
	C28X_OP_IMMDEC, ///< immediate written in decimal
	C28X_OP_IMMCOLON, ///< decimal immediate joined to the one before it by ":"
} C28xOpKind;

/** One decoded operand. */
typedef struct {
	C28xOpKind kind;
	C28xReg reg; ///< register operand, or the register named by C28X_AM_REG
	st64 imm; ///< immediate / offset / branch target / condition code
	bool is_signed; ///< the immediate was sign-extended from its field
	ut8 byte_sel; ///< 1 = the operand is the register's ".LSB", 2 = its ".MSB"
	// memory operands (kind == C28X_OP_MEM)
	C28xAddrMode mode; ///< addressing mode
	ut8 arn; ///< XARn / ARPn selected by the mode
	ut8 off; ///< 6-bit DP or SP offset, or the 3-bit XARn index
	bool wide; ///< loc32 (32-bit) rather than loc16 (16-bit) access
	ut16 mask; ///< SETFLG/SAVE: the flags whose values \ref imm holds
} C28xOperand;

/**
 * \brief Enough for the widest rows: a VCU FFT butterfly with its parallel
 * VMOV32.
 */
#define C28X_MAX_OPS 10

/**
 * \brief Every C28x mnemonic, in alphabetical order, as X(ID, "name").
 *
 * One list gives both \ref C28xInsnId and the names table rows are mapped to,
 * so the two cannot drift apart.
 */
#define C28X_INSN_LIST(X) \
	X(A_VCLROVFI, "a_vclrovfi") \
	X(A_VCLROVFR, "a_vclrovfr") \
	X(ABORTI, "aborti") \
	X(ABS, "abs") \
	X(ABSF32, "absf32") \
	X(ABSF64, "absf64") \
	X(ABSI32DIV32, "absi32div32") \
	X(ABSI32DIV32U, "absi32div32u") \
	X(ABSI64DIV32, "absi64div32") \
	X(ABSI64DIV32U, "absi64div32u") \
	X(ABSI64DIV64, "absi64div64") \
	X(ABSI64DIV64U, "absi64div64u") \
	X(ABSTC, "abstc") \
	X(ADD, "add") \
	X(ADDB, "addb") \
	X(ADDCL, "addcl") \
	X(ADDCU, "addcu") \
	X(ADDF32, "addf32") \
	X(ADDF64, "addf64") \
	X(ADDL, "addl") \
	X(ADDU, "addu") \
	X(ADDUL, "addul") \
	X(ADRK, "adrk") \
	X(AND, "and") \
	X(ANDB, "andb") \
	X(ASP, "asp") \
	X(ASR, "asr") \
	X(ASR64, "asr64") \
	X(ASRL, "asrl") \
	X(ATANPUF32, "atanpuf32") \
	X(B, "b") \
	X(BANZ, "banz") \
	X(BAR, "bar") \
	X(BF, "bf") \
	X(CLRC, "clrc") \
	X(CMP, "cmp") \
	X(CMP64, "cmp64") \
	X(CMPB, "cmpb") \
	X(CMPF32, "cmpf32") \
	X(CMPF64, "cmpf64") \
	X(CMPL, "cmpl") \
	X(CMPR, "cmpr") \
	X(COSPUF32, "cospuf32") \
	X(CSB, "csb") \
	X(DEC, "dec") \
	X(DINT, "dint") \
	X(DIV2PIF32, "div2pif32") \
	X(DIVF32, "divf32") \
	X(DMAC, "dmac") \
	X(DMOV, "dmov") \
	X(EALLOW, "eallow") \
	X(EDIS, "edis") \
	X(EINT, "eint") \
	X(EINVF32, "einvf32") \
	X(EINVF64, "einvf64") \
	X(EISQRTF32, "eisqrtf32") \
	X(EISQRTF64, "eisqrtf64") \
	X(ENEGI32DIV32, "enegi32div32") \
	X(ENEGI64DIV32, "enegi64div32") \
	X(ENEGI64DIV64, "enegi64div64") \
	X(ESTOP0, "estop0") \
	X(ESTOP1, "estop1") \
	X(F32DTOF64, "f32dtof64") \
	X(F32TOF64, "f32tof64") \
	X(F32TOI16, "f32toi16") \
	X(F32TOI16R, "f32toi16r") \
	X(F32TOI32, "f32toi32") \
	X(F32TOUI16, "f32toui16") \
	X(F32TOUI16R, "f32toui16r") \
	X(F32TOUI32, "f32toui32") \
	X(F64TOF32, "f64tof32") \
	X(F64TOI32, "f64toi32") \
	X(F64TOI64, "f64toi64") \
	X(F64TOUI32, "f64toui32") \
	X(F64TOUI64, "f64toui64") \
	X(FFC, "ffc") \
	X(FLIP, "flip") \
	X(FRACF32, "fracf32") \
	X(FRACF64, "fracf64") \
	X(I16TOF32, "i16tof32") \
	X(I32TOF32, "i32tof32") \
	X(I32TOF64, "i32tof64") \
	X(I64TOF64, "i64tof64") \
	X(IACK, "iack") \
	X(IDLE, "idle") \
	X(IEXP2F32, "iexp2f32") \
	X(IMACL, "imacl") \
	X(IMPYAL, "impyal") \
	X(IMPYL, "impyl") \
	X(IMPYSL, "impysl") \
	X(IMPYXUL, "impyxul") \
	X(IN, "in") \
	X(INC, "inc") \
	X(INTR, "intr") \
	X(IRET, "iret") \
	X(LB, "lb") \
	X(LC, "lc") \
	X(LCR, "lcr") \
	X(LOG2F32, "log2f32") \
	X(LOOPNZ, "loopnz") \
	X(LOOPZ, "loopz") \
	X(LPADDR, "lpaddr") \
	X(LRET, "lret") \
	X(LRETE, "lrete") \
	X(LRETR, "lretr") \
	X(LSL, "lsl") \
	X(LSL64, "lsl64") \
	X(LSLL, "lsll") \
	X(LSR, "lsr") \
	X(LSR64, "lsr64") \
	X(LSRL, "lsrl") \
	X(MAC, "mac") \
	X(MACF32, "macf32") \
	X(MACF64, "macf64") \
	X(MAX, "max") \
	X(MAXCUL, "maxcul") \
	X(MAXF32, "maxf32") \
	X(MAXF64, "maxf64") \
	X(MAXL, "maxl") \
	X(MIN, "min") \
	X(MINCUL, "mincul") \
	X(MINF32, "minf32") \
	X(MINF64, "minf64") \
	X(MINL, "minl") \
	X(MNEGI32DIV32, "mnegi32div32") \
	X(MNEGI64DIV32, "mnegi64div32") \
	X(MNEGI64DIV64, "mnegi64div64") \
	X(MOV, "mov") \
	X(MOV16, "mov16") \
	X(MOV32, "mov32") \
	X(MOV64, "mov64") \
	X(MOVA, "mova") \
	X(MOVAD, "movad") \
	X(MOVB, "movb") \
	X(MOVD32, "movd32") \
	X(MOVDD32, "movdd32") \
	X(MOVDL, "movdl") \
	X(MOVH, "movh") \
	X(MOVIX, "movix") \
	X(MOVIZ, "moviz") \
	X(MOVL, "movl") \
	X(MOVP, "movp") \
	X(MOVS, "movs") \
	X(MOVST0, "movst0") \
	X(MOVU, "movu") \
	X(MOVW, "movw") \
	X(MOVX, "movx") \
	X(MOVXI, "movxi") \
	X(MOVZ, "movz") \
	X(MPY, "mpy") \
	X(MPY2PIF32, "mpy2pif32") \
	X(MPYA, "mpya") \
	X(MPYB, "mpyb") \
	X(MPYF32, "mpyf32") \
	X(MPYF64, "mpyf64") \
	X(MPYS, "mpys") \
	X(MPYU, "mpyu") \
	X(MPYXU, "mpyxu") \
	X(NASP, "nasp") \
	X(NEG, "neg") \
	X(NEG64, "neg64") \
	X(NEGF32, "negf32") \
	X(NEGF64, "negf64") \
	X(NEGI32DIV32, "negi32div32") \
	X(NEGI64DIV32, "negi64div32") \
	X(NEGI64DIV64, "negi64div64") \
	X(NEGTC, "negtc") \
	X(NOP, "nop") \
	X(NORM, "norm") \
	X(NOT, "not") \
	X(OR, "or") \
	X(ORB, "orb") \
	X(OUT, "out") \
	X(POP, "pop") \
	X(POSTDIVF64, "postdivf64") \
	X(PREAD, "pread") \
	X(PREDIVF64, "predivf64") \
	X(PUSH, "push") \
	X(PWRITE, "pwrite") \
	X(QMACL, "qmacl") \
	X(QMPYAL, "qmpyal") \
	X(QMPYL, "qmpyl") \
	X(QMPYSL, "qmpysl") \
	X(QMPYUL, "qmpyul") \
	X(QMPYXUL, "qmpyxul") \
	X(QUADF32, "quadf32") \
	X(RESTORE, "restore") \
	X(ROL, "rol") \
	X(ROR, "ror") \
	X(RPT, "rpt") \
	X(RPTB, "rptb") \
	X(SAT, "sat") \
	X(SAT64, "sat64") \
	X(SAVE, "save") \
	X(SB, "sb") \
	X(SBBU, "sbbu") \
	X(SBF, "sbf") \
	X(SBRK, "sbrk") \
	X(SETC, "setc") \
	X(SETFLG, "setflg") \
	X(SFR, "sfr") \
	X(SINPUF32, "sinpuf32") \
	X(SPM, "spm") \
	X(SQRA, "sqra") \
	X(SQRS, "sqrs") \
	X(SQRTF32, "sqrtf32") \
	X(SUB, "sub") \
	X(SUBB, "subb") \
	X(SUBBL, "subbl") \
	X(SUBC2UI64, "subc2ui64") \
	X(SUBC3F64, "subc3f64") \
	X(SUBC4UI32, "subc4ui32") \
	X(SUBCU, "subcu") \
	X(SUBCUL, "subcul") \
	X(SUBF32, "subf32") \
	X(SUBF64, "subf64") \
	X(SUBL, "subl") \
	X(SUBR, "subr") \
	X(SUBRL, "subrl") \
	X(SUBU, "subu") \
	X(SUBUL, "subul") \
	X(SWAPF, "swapf") \
	X(SXTB, "sxtb") \
	X(TBIT, "tbit") \
	X(TCLR, "tclr") \
	X(TEST, "test") \
	X(TESTTF, "testtf") \
	X(TRAP, "trap") \
	X(TSET, "tset") \
	X(UI16TOF32, "ui16tof32") \
	X(UI32TOF32, "ui32tof32") \
	X(UI32TOF64, "ui32tof64") \
	X(UI64TOF64, "ui64tof64") \
	X(UOUT, "uout") \
	X(VASHL32, "vashl32") \
	X(VASHR32, "vashr32") \
	X(VBITFLIP, "vbitflip") \
	X(VCADD, "vcadd") \
	X(VCCMAC, "vccmac") \
	X(VCCMPY, "vccmpy") \
	X(VCCON, "vccon") \
	X(VCDADD16, "vcdadd16") \
	X(VCDSUB16, "vcdsub16") \
	X(VCFFT1, "vcfft1") \
	X(VCFFT10, "vcfft10") \
	X(VCFFT2, "vcfft2") \
	X(VCFFT3, "vcfft3") \
	X(VCFFT4, "vcfft4") \
	X(VCFFT5, "vcfft5") \
	X(VCFFT6, "vcfft6") \
	X(VCFFT7, "vcfft7") \
	X(VCFFT8, "vcfft8") \
	X(VCFFT9, "vcfft9") \
	X(VCFLIP, "vcflip") \
	X(VCLEAR, "vclear") \
	X(VCLEARALL, "vclearall") \
	X(VCLRCPACK, "vclrcpack") \
	X(VCLRCRCMSGFLIP, "vclrcrcmsgflip") \
	X(VCLRDIVE, "vclrdive") \
	X(VCLROPACK, "vclropack") \
	X(VCMAC, "vcmac") \
	X(VCMAG, "vcmag") \
	X(VCMPY, "vcmpy") \
	X(VCRC16P1H_1, "vcrc16p1h_1") \
	X(VCRC16P1L_1, "vcrc16p1l_1") \
	X(VCRC16P2H_1, "vcrc16p2h_1") \
	X(VCRC16P2L_1, "vcrc16p2l_1") \
	X(VCRC24H_1, "vcrc24h_1") \
	X(VCRC24L_1, "vcrc24l_1") \
	X(VCRC32H_1, "vcrc32h_1") \
	X(VCRC32L_1, "vcrc32l_1") \
	X(VCRC32P2H_1, "vcrc32p2h_1") \
	X(VCRC32P2L_1, "vcrc32p2l_1") \
	X(VCRC8H_1, "vcrc8h_1") \
	X(VCRC8L_1, "vcrc8l_1") \
	X(VCRCCLR, "vcrcclr") \
	X(VCRCH, "vcrch") \
	X(VCRCL, "vcrcl") \
	X(VCSHL16, "vcshl16") \
	X(VCSHR16, "vcshr16") \
	X(VCSUB, "vcsub") \
	X(VDEC, "vdec") \
	X(VGFACC, "vgfacc") \
	X(VGFADD4, "vgfadd4") \
	X(VGFINIT, "vgfinit") \
	X(VGFMAC4, "vgfmac4") \
	X(VGFMPY4, "vgfmpy4") \
	X(VINC, "vinc") \
	X(VITBM2, "vitbm2") \
	X(VITBM3, "vitbm3") \
	X(VITDHADDSUB, "vitdhaddsub") \
	X(VITDHSUBADD, "vitdhsubadd") \
	X(VITDLADDSUB, "vitdladdsub") \
	X(VITDLSUBADD, "vitdlsubadd") \
	X(VITHSEL, "vithsel") \
	X(VITLSEL, "vitlsel") \
	X(VITSTAGE, "vitstage") \
	X(VLSHL32, "vlshl32") \
	X(VLSHR32, "vlshr32") \
	X(VMOD32, "vmod32") \
	X(VMOV16, "vmov16") \
	X(VMOV32, "vmov32") \
	X(VMOVD32, "vmovd32") \
	X(VMOVIX, "vmovix") \
	X(VMOVXI, "vmovxi") \
	X(VMOVZI, "vmovzi") \
	X(VMPYADD, "vmpyadd") \
	X(VNEG, "vneg") \
	X(VNOP, "vnop") \
	X(VPACK4, "vpack4") \
	X(VREVB, "vrevb") \
	X(VRNDOFF, "vrndoff") \
	X(VRNDON, "vrndon") \
	X(VSATOFF, "vsatoff") \
	X(VSATON, "vsaton") \
	X(VSETCPACK, "vsetcpack") \
	X(VSETCRCMSGFLIP, "vsetcrcmsgflip") \
	X(VSETCRCSIZE, "vsetcrcsize") \
	X(VSETK, "vsetk") \
	X(VSETOPACK, "vsetopack") \
	X(VSETSHL, "vsetshl") \
	X(VSETSHR, "vsetshr") \
	X(VSHLMB, "vshlmb") \
	X(VSMINIT, "vsminit") \
	X(VSWAP32, "vswap32") \
	X(VSWAPCRC, "vswapcrc") \
	X(VTCLEAR, "vtclear") \
	X(VTRACE, "vtrace") \
	X(VXORMOV32, "vxormov32") \
	X(XB, "xb") \
	X(XBANZ, "xbanz") \
	X(XCALL, "xcall") \
	X(XMAC, "xmac") \
	X(XMACD, "xmacd") \
	X(XOR, "xor") \
	X(XORB, "xorb") \
	X(XPREAD, "xpread") \
	X(XPWRITE, "xpwrite") \
	X(XRET, "xret") \
	X(XRETC, "xretc") \
	X(ZALR, "zalr") \
	X(ZAP, "zap") \
	X(ZAPA, "zapa") \
	X(ZERO, "zero") \
	X(ZEROA, "zeroa")

/**
 * \brief Instruction identifier, one per mnemonic.
 */
typedef enum {
	C28X_INS_INVALID = 0,
#define C28X_INS_ENUM(id, name) C28X_INS_##id,
	C28X_INSN_LIST(C28X_INS_ENUM)
#undef C28X_INS_ENUM
		C28X_INS_COUNT
} C28xInsnId;

/** A fully decoded C28x instruction. */
typedef struct {
	ut32 word; ///< raw opcode, word0 in bits 31:16 and word1 in bits 15:0
	ut32 size; ///< instruction size in bytes (2 or 4)
	C28xInsnId id; ///< which instruction this is; dispatch on this, not the mnemonic
	const char *mnemonic; ///< base mnemonic ("add", "movl", "sb", ...)
	_RzAnalysisOpType op_type; ///< analysis classification
	C28xOperand ops[C28X_MAX_OPS];
	ut8 nops; ///< number of valid operands
	ut8 cond; ///< condition code when the row carries one, else C28X_COND_UNC
	bool repeatable; ///< the instruction may be prefixed by RPT
} C28xInsn;

/** Condition-code field values (SPRU430F, "B 16bitOffset,COND"). */
typedef enum {
	C28X_COND_NEQ = 0x0,
	C28X_COND_EQ,
	C28X_COND_GT,
	C28X_COND_GEQ,
	C28X_COND_LT,
	C28X_COND_LEQ,
	C28X_COND_HI,
	C28X_COND_HIS,
	C28X_COND_LO,
	C28X_COND_LOS,
	C28X_COND_NOV,
	C28X_COND_OV,
	C28X_COND_NTC,
	C28X_COND_TC,
	C28X_COND_NBIO,
	C28X_COND_UNC,
} C28xCond;

/**
 * The C28x addresses 16-bit words. Rizin addresses bytes, so every program
 * address the decoder reports is scaled by this and every immediate word count
 * (branch displacements, instruction sizes) is multiplied by it.
 */
#define C28X_WORD_BYTES 2

/**
 * \brief Lookup structure over the decode table, built once per plugin instance.
 */
typedef struct c28x_index_t C28xIndex;

RZ_IPI RZ_OWN C28xIndex *c28x_index_new(void);

RZ_IPI void c28x_index_free(RZ_NULLABLE C28xIndex *idx);

RZ_IPI bool c28x_decode(RZ_NONNULL const C28xIndex *idx, RZ_NONNULL const ut8 *buf, int len,
	ut64 pc, RZ_OUT C28xInsn *insn);

RZ_IPI RZ_OWN char *c28x_format(RZ_NONNULL const C28xInsn *insn, ut64 pc);

RZ_IPI void c28x_fill_analysis(RZ_NONNULL const C28xInsn *insn, ut64 addr, RZ_OUT RzAnalysisOp *op);

RZ_IPI RZ_OWN RzILOpEffect *c28x_lift(RZ_NONNULL const C28xInsn *insn, ut64 pc);

RZ_IPI RZ_OWN RzAnalysisILConfig *c28x_il_config(void);

RZ_IPI RZ_OWN RzStructuredData *c28x_opex(RZ_NONNULL const C28xInsn *insn);

RZ_IPI RZ_BORROW const char *c28x_reg_name(C28xReg reg);

RZ_IPI RZ_BORROW const char *c28x_cond_name(ut8 cond);
RZ_IPI RZ_BORROW const char *c28x_fcond_name(ut8 cond);

RZ_IPI RZ_BORROW const char *c28x_insn_name(C28xInsnId id);
RZ_IPI RZ_OWN RzPVector /*<const char *>*/ *c28x_mnemonics(void);

#ifdef __cplusplus
}
#endif

#endif /* RZ_TMS320_C28X_H */
