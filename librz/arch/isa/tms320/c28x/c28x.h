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
} C28xOperand;

/**
 * \brief Enough for the widest rows: BAR, with its target, two registers and
 * condition.
 */
#define C28X_MAX_OPS 4

/**
 * \brief Every C28x mnemonic, in alphabetical order, as X(ID, "name").
 *
 * One list gives both \ref C28xInsnId and the names table rows are mapped to,
 * so the two cannot drift apart.
 */
#define C28X_INSN_LIST(X) \
	X(ABORTI, "aborti") \
	X(ABS, "abs") \
	X(ABSTC, "abstc") \
	X(ADD, "add") \
	X(ADDB, "addb") \
	X(ADDCL, "addcl") \
	X(ADDCU, "addcu") \
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
	X(B, "b") \
	X(BANZ, "banz") \
	X(BAR, "bar") \
	X(BF, "bf") \
	X(CLRC, "clrc") \
	X(CMP, "cmp") \
	X(CMP64, "cmp64") \
	X(CMPB, "cmpb") \
	X(CMPL, "cmpl") \
	X(CMPR, "cmpr") \
	X(CSB, "csb") \
	X(DEC, "dec") \
	X(DINT, "dint") \
	X(DMAC, "dmac") \
	X(DMOV, "dmov") \
	X(EALLOW, "eallow") \
	X(EDIS, "edis") \
	X(EINT, "eint") \
	X(ESTOP0, "estop0") \
	X(ESTOP1, "estop1") \
	X(FFC, "ffc") \
	X(FLIP, "flip") \
	X(IACK, "iack") \
	X(IDLE, "idle") \
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
	X(MAX, "max") \
	X(MAXCUL, "maxcul") \
	X(MAXL, "maxl") \
	X(MIN, "min") \
	X(MINCUL, "mincul") \
	X(MINL, "minl") \
	X(MOV, "mov") \
	X(MOVA, "mova") \
	X(MOVAD, "movad") \
	X(MOVB, "movb") \
	X(MOVDL, "movdl") \
	X(MOVH, "movh") \
	X(MOVL, "movl") \
	X(MOVP, "movp") \
	X(MOVS, "movs") \
	X(MOVU, "movu") \
	X(MOVW, "movw") \
	X(MOVX, "movx") \
	X(MOVZ, "movz") \
	X(MPY, "mpy") \
	X(MPYA, "mpya") \
	X(MPYB, "mpyb") \
	X(MPYS, "mpys") \
	X(MPYU, "mpyu") \
	X(MPYXU, "mpyxu") \
	X(NASP, "nasp") \
	X(NEG, "neg") \
	X(NEG64, "neg64") \
	X(NEGTC, "negtc") \
	X(NOP, "nop") \
	X(NORM, "norm") \
	X(NOT, "not") \
	X(OR, "or") \
	X(ORB, "orb") \
	X(OUT, "out") \
	X(POP, "pop") \
	X(PREAD, "pread") \
	X(PUSH, "push") \
	X(PWRITE, "pwrite") \
	X(QMACL, "qmacl") \
	X(QMPYAL, "qmpyal") \
	X(QMPYL, "qmpyl") \
	X(QMPYSL, "qmpysl") \
	X(QMPYUL, "qmpyul") \
	X(QMPYXUL, "qmpyxul") \
	X(ROL, "rol") \
	X(ROR, "ror") \
	X(RPT, "rpt") \
	X(RPTB, "rptb") \
	X(SAT, "sat") \
	X(SAT64, "sat64") \
	X(SB, "sb") \
	X(SBBU, "sbbu") \
	X(SBF, "sbf") \
	X(SBRK, "sbrk") \
	X(SETC, "setc") \
	X(SFR, "sfr") \
	X(SPM, "spm") \
	X(SQRA, "sqra") \
	X(SQRS, "sqrs") \
	X(SUB, "sub") \
	X(SUBB, "subb") \
	X(SUBBL, "subbl") \
	X(SUBCU, "subcu") \
	X(SUBCUL, "subcul") \
	X(SUBL, "subl") \
	X(SUBR, "subr") \
	X(SUBRL, "subrl") \
	X(SUBU, "subu") \
	X(SUBUL, "subul") \
	X(SXTB, "sxtb") \
	X(TBIT, "tbit") \
	X(TCLR, "tclr") \
	X(TEST, "test") \
	X(TRAP, "trap") \
	X(TSET, "tset") \
	X(UOUT, "uout") \
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
	X(ZAPA, "zapa")

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

RZ_IPI RZ_OWN RzPVector /*<const char *>*/ *c28x_mnemonics(void);

#ifdef __cplusplus
}
#endif

#endif /* RZ_TMS320_C28X_H */
