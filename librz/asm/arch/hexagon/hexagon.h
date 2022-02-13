// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: 96e220e6886868d6663d966ecc396befffc355e7
// LLVM commit date: 2022-01-05 11:01:52 +0000 (ISO 8601 format)
// Date of code generation: 2022-01-24 07:53:55-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#ifndef HEXAGON_H
#define HEXAGON_H

#define MAX_CONST_EXT      512
#define HEXAGON_STATE_PKTS 8

// Predicates - declare the predicate state
typedef enum {
	HEX_NOPRED, // no conditional execution
	HEX_PRED_TRUE, // if (Pd) ...
	HEX_PRED_FALSE, // if (!Pd) ...
	HEX_PRED_NEW, // if (Pd.new) or if (!Pd.new)
} HexPred;

// TODO NOT IN USE
// Pre/post-fixes, different types
typedef enum {
	HEX_PF_RND = 1, // :rnd
	HEX_PF_CRND = 1 << 1, // :crnd
	HEX_PF_RAW = 1 << 2, // :raw
	HEX_PF_CHOP = 1 << 3, // :chop
	HEX_PF_SAT = 1 << 4, // :sat
	HEX_PF_HI = 1 << 5, // :hi
	HEX_PF_LO = 1 << 6, // :lo
	HEX_PF_LSH1 = 1 << 7, // :<<1
	HEX_PF_LSH16 = 1 << 8, // :<<16
	HEX_PF_RSH1 = 1 << 9, // :>>1
	HEX_PF_NEG = 1 << 10, // :neg
	HEX_PF_POS = 1 << 11, // :pos
	HEX_PF_SCALE = 1 << 12, // :scale, for FMA instructions
	HEX_PF_DEPRECATED = 1 << 15, // :deprecated
} HexPf;

typedef enum {
	HEX_OP_TYPE_IMM,
	HEX_OP_TYPE_REG,
	// TODO It might be useful to differ between control, HVX, guest regs etc. Also see HexOp
} HexOpType;

// Attributes - .H/.L, const extender
typedef enum {
	HEX_OP_CONST_EXT = 1 << 0, // Constant extender marker for Immediate
	HEX_OP_REG_HI = 1 << 1, // Rn.H marker
	HEX_OP_REG_LO = 1 << 2, // Rn.L marker
	HEX_OP_REG_PAIR = 1 << 3, // Is this a register pair?
	HEX_OP_REG_QUADRUPLE = 1 << 4, // Is it a register with 4 sub registers?
	HEX_OP_REG_OUT = 1 << 5, // Is the register the destination register?
	HEX_OP_IMM_SCALED = 1 << 6 // Is the immediate shifted?
} HexOpAttr;

typedef enum {
	HEX_NO_LOOP = 0,
	HEX_LOOP_0 = 1, // Is packet of loop0
	HEX_LOOP_1 = 1 << 1, // Is packet of loop1
	HEX_LOOP_01 = 1 << 2 // Belongs to loop 0 and 1
} HexLoopAttr;

typedef struct {
	bool first_insn;
	bool last_insn;
	char mnem_prefix[16]; // Package indicator
	char mnem_postfix[24]; // for ":endloop" string.
} HexPktInfo;

typedef struct {
	ut8 type;
	union {
		ut8 reg; // + additional Hi or Lo selector // + additional shift // + additional :brev //
		st64 imm;
	} op;
	HexOpAttr attr;
	ut8 shift;
} HexOp;

typedef struct {
	ut32 opcode;
	ut8 parse_bits;
	int instruction;
	ut32 mask;
	HexPred pred; // Predicate type
	bool duplex; // is part of duplex container?
	bool compound; // is part of compound instruction?
	int shift; // Optional shift left is it true?
	HexPktInfo pkt_info; // Packet related information. First/last instr., prefix and postfix for mnemonic etc.
	ut8 op_count;
	HexOp ops[6];
	char mnem_infix[128]; // The mnemonic without the pre- and postfix.
	char mnem[192]; // Instruction mnemonic
	ut32 addr; // Memory address the instruction is located.
	RzAsmOp asm_op;
	RzAnalysisOp ana_op;
} HexInsn;

typedef struct {
	RzList *insn; // List of instructions.
	bool last_instr_present; // Has an instruction the parsing bits 0b11 set (is last instruction).
	bool is_valid; // Is it a valid packet? Do we know which instruction is the first?
	ut32 hw_loop0_addr; // Start address of hardware loop 0
	ut32 hw_loop1_addr; // Start address of hardware loop 1
	ut64 last_access; // Last time accessed in milliseconds
	ut32 pkt_addr; // Address of the packet. Equals the address of the first instruction.
	bool is_eob; // Is this packet the end of a code block? E.g. contains unconditional jmp.
} HexPkt;

typedef struct {
	ut32 addr; // Address of the instruction which gets the extender applied.
	ut32 const_ext; // The constant extender value.
} HexConstExt;

/**
 * \brief Buffer packets for reversed instructions.
 *
 */
typedef struct {
	HexPkt pkts[HEXAGON_STATE_PKTS]; // buffered instructions
	RzList *const_ext_l; // Constant extender values.
	RzAsm rz_asm; // Copy of RzAsm struct. Holds certain flags of interesed for disassembly formatting.
} HexState;
typedef enum {
	HEX_REG_CTR_REGS_SA0 = 0, // c0
	HEX_REG_CTR_REGS_LC0 = 1, // c1
	HEX_REG_CTR_REGS_SA1 = 2, // c2
	HEX_REG_CTR_REGS_LC1 = 3, // c3
	HEX_REG_CTR_REGS_P3_0 = 4, // c4
	HEX_REG_CTR_REGS_C5 = 5, // c5
	HEX_REG_CTR_REGS_M0 = 6, // c6
	HEX_REG_CTR_REGS_M1 = 7, // c7
	HEX_REG_CTR_REGS_USR = 8, // c8
	HEX_REG_CTR_REGS_PC = 9, // c9
	HEX_REG_CTR_REGS_UGP = 10, // c10
	HEX_REG_CTR_REGS_GP = 11, // c11
	HEX_REG_CTR_REGS_CS0 = 12, // c12
	HEX_REG_CTR_REGS_CS1 = 13, // c13
	HEX_REG_CTR_REGS_UPCYCLELO = 14, // c14
	HEX_REG_CTR_REGS_UPCYCLEHI = 15, // c15
	HEX_REG_CTR_REGS_FRAMELIMIT = 16, // c16
	HEX_REG_CTR_REGS_FRAMEKEY = 17, // c17
	HEX_REG_CTR_REGS_PKTCOUNTLO = 18, // c18
	HEX_REG_CTR_REGS_PKTCOUNTHI = 19, // c19
	HEX_REG_CTR_REGS_UTIMERLO = 30, // c30
	HEX_REG_CTR_REGS_UTIMERHI = 31, // c31
} HEX_CTR_REGS; // CtrRegs

typedef enum {
	HEX_REG_CTR_REGS64_C1_0 = 0, // lc0:sa0
	HEX_REG_CTR_REGS64_C3_2 = 2, // lc1:sa1
	HEX_REG_CTR_REGS64_C5_4 = 4,
	HEX_REG_CTR_REGS64_C7_6 = 6, // m1:0
	HEX_REG_CTR_REGS64_C9_8 = 8,
	HEX_REG_CTR_REGS64_C11_10 = 10,
	HEX_REG_CTR_REGS64_CS = 12, // cs1:0
	HEX_REG_CTR_REGS64_UPCYCLE = 14, // upcycle
	HEX_REG_CTR_REGS64_C17_16 = 16,
	HEX_REG_CTR_REGS64_PKTCOUNT = 18, // pktcount
	HEX_REG_CTR_REGS64_UTIMER = 30, // utimer
} HEX_CTR_REGS64; // CtrRegs64

typedef enum {
	HEX_REG_DOUBLE_REGS_D0 = 0,
	HEX_REG_DOUBLE_REGS_D1 = 2,
	HEX_REG_DOUBLE_REGS_D2 = 4,
	HEX_REG_DOUBLE_REGS_D3 = 6,
	HEX_REG_DOUBLE_REGS_D4 = 8,
	HEX_REG_DOUBLE_REGS_D5 = 10,
	HEX_REG_DOUBLE_REGS_D6 = 12,
	HEX_REG_DOUBLE_REGS_D7 = 14,
	HEX_REG_DOUBLE_REGS_D8 = 16,
	HEX_REG_DOUBLE_REGS_D9 = 18,
	HEX_REG_DOUBLE_REGS_D10 = 20,
	HEX_REG_DOUBLE_REGS_D11 = 22,
	HEX_REG_DOUBLE_REGS_D12 = 24,
	HEX_REG_DOUBLE_REGS_D13 = 26,
	HEX_REG_DOUBLE_REGS_D14 = 28,
	HEX_REG_DOUBLE_REGS_D15 = 30, // lr:fp
} HEX_DOUBLE_REGS; // DoubleRegs

typedef enum {
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D0 = 0,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D1 = 2,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D2 = 4,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D3 = 6,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D8 = 16,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D9 = 18,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D10 = 20,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_D11 = 22,
} HEX_GENERAL_DOUBLE_LOW8_REGS; // GeneralDoubleLow8Regs

typedef enum {
	HEX_REG_GENERAL_SUB_REGS_R0 = 0,
	HEX_REG_GENERAL_SUB_REGS_R1 = 1,
	HEX_REG_GENERAL_SUB_REGS_R2 = 2,
	HEX_REG_GENERAL_SUB_REGS_R3 = 3,
	HEX_REG_GENERAL_SUB_REGS_R4 = 4,
	HEX_REG_GENERAL_SUB_REGS_R5 = 5,
	HEX_REG_GENERAL_SUB_REGS_R6 = 6,
	HEX_REG_GENERAL_SUB_REGS_R7 = 7,
	HEX_REG_GENERAL_SUB_REGS_R16 = 16,
	HEX_REG_GENERAL_SUB_REGS_R17 = 17,
	HEX_REG_GENERAL_SUB_REGS_R18 = 18,
	HEX_REG_GENERAL_SUB_REGS_R19 = 19,
	HEX_REG_GENERAL_SUB_REGS_R20 = 20,
	HEX_REG_GENERAL_SUB_REGS_R21 = 21,
	HEX_REG_GENERAL_SUB_REGS_R22 = 22,
	HEX_REG_GENERAL_SUB_REGS_R23 = 23,
} HEX_GENERAL_SUB_REGS; // GeneralSubRegs

typedef enum {
	HEX_REG_GUEST_REGS_GELR = 0, // g0
	HEX_REG_GUEST_REGS_GSR = 1, // g1
	HEX_REG_GUEST_REGS_GOSP = 2, // g2
	HEX_REG_GUEST_REGS_G3 = 3, // g3
	HEX_REG_GUEST_REGS_G4 = 4,
	HEX_REG_GUEST_REGS_G5 = 5,
	HEX_REG_GUEST_REGS_G6 = 6,
	HEX_REG_GUEST_REGS_G7 = 7,
	HEX_REG_GUEST_REGS_G8 = 8,
	HEX_REG_GUEST_REGS_G9 = 9,
	HEX_REG_GUEST_REGS_G10 = 10,
	HEX_REG_GUEST_REGS_G11 = 11,
	HEX_REG_GUEST_REGS_G12 = 12,
	HEX_REG_GUEST_REGS_G13 = 13,
	HEX_REG_GUEST_REGS_G14 = 14,
	HEX_REG_GUEST_REGS_G15 = 15,
	HEX_REG_GUEST_REGS_GPMUCNT4 = 16, // g16
	HEX_REG_GUEST_REGS_GPMUCNT5 = 17, // g17
	HEX_REG_GUEST_REGS_GPMUCNT6 = 18, // g18
	HEX_REG_GUEST_REGS_GPMUCNT7 = 19, // g19
	HEX_REG_GUEST_REGS_G20 = 20,
	HEX_REG_GUEST_REGS_G21 = 21,
	HEX_REG_GUEST_REGS_G22 = 22,
	HEX_REG_GUEST_REGS_G23 = 23,
	HEX_REG_GUEST_REGS_GPCYCLELO = 24, // g24
	HEX_REG_GUEST_REGS_GPCYCLEHI = 25, // g25
	HEX_REG_GUEST_REGS_GPMUCNT0 = 26, // g26
	HEX_REG_GUEST_REGS_GPMUCNT1 = 27, // g27
	HEX_REG_GUEST_REGS_GPMUCNT2 = 28, // g28
	HEX_REG_GUEST_REGS_GPMUCNT3 = 29, // g29
	HEX_REG_GUEST_REGS_G30 = 30,
	HEX_REG_GUEST_REGS_G31 = 31,
} HEX_GUEST_REGS; // GuestRegs

typedef enum {
	HEX_REG_GUEST_REGS64_G1_0 = 0,
	HEX_REG_GUEST_REGS64_G3_2 = 2,
	HEX_REG_GUEST_REGS64_G5_4 = 4,
	HEX_REG_GUEST_REGS64_G7_6 = 6,
	HEX_REG_GUEST_REGS64_G9_8 = 8,
	HEX_REG_GUEST_REGS64_G11_10 = 10,
	HEX_REG_GUEST_REGS64_G13_12 = 12,
	HEX_REG_GUEST_REGS64_G15_14 = 14,
	HEX_REG_GUEST_REGS64_G17_16 = 16,
	HEX_REG_GUEST_REGS64_G19_18 = 18,
	HEX_REG_GUEST_REGS64_G21_20 = 20,
	HEX_REG_GUEST_REGS64_G23_22 = 22,
	HEX_REG_GUEST_REGS64_G25_24 = 24,
	HEX_REG_GUEST_REGS64_G27_26 = 26,
	HEX_REG_GUEST_REGS64_G29_28 = 28,
	HEX_REG_GUEST_REGS64_G31_30 = 30,
} HEX_GUEST_REGS64; // GuestRegs64

typedef enum {
	HEX_REG_HVX_QR_Q0 = 0,
	HEX_REG_HVX_QR_Q1 = 1,
	HEX_REG_HVX_QR_Q2 = 2,
	HEX_REG_HVX_QR_Q3 = 3,
} HEX_HVX_QR; // HvxQR

typedef enum {
	HEX_REG_HVX_VQR_VQ0 = 0,
	HEX_REG_HVX_VQR_VQ1 = 4,
	HEX_REG_HVX_VQR_VQ2 = 8,
	HEX_REG_HVX_VQR_VQ3 = 12,
	HEX_REG_HVX_VQR_VQ4 = 16,
	HEX_REG_HVX_VQR_VQ5 = 20,
	HEX_REG_HVX_VQR_VQ6 = 24,
	HEX_REG_HVX_VQR_VQ7 = 28,
} HEX_HVX_VQR; // HvxVQR

typedef enum {
	HEX_REG_HVX_VR_V0 = 0,
	HEX_REG_HVX_VR_V1 = 1,
	HEX_REG_HVX_VR_V2 = 2,
	HEX_REG_HVX_VR_V3 = 3,
	HEX_REG_HVX_VR_V4 = 4,
	HEX_REG_HVX_VR_V5 = 5,
	HEX_REG_HVX_VR_V6 = 6,
	HEX_REG_HVX_VR_V7 = 7,
	HEX_REG_HVX_VR_V8 = 8,
	HEX_REG_HVX_VR_V9 = 9,
	HEX_REG_HVX_VR_V10 = 10,
	HEX_REG_HVX_VR_V11 = 11,
	HEX_REG_HVX_VR_V12 = 12,
	HEX_REG_HVX_VR_V13 = 13,
	HEX_REG_HVX_VR_V14 = 14,
	HEX_REG_HVX_VR_V15 = 15,
	HEX_REG_HVX_VR_V16 = 16,
	HEX_REG_HVX_VR_V17 = 17,
	HEX_REG_HVX_VR_V18 = 18,
	HEX_REG_HVX_VR_V19 = 19,
	HEX_REG_HVX_VR_V20 = 20,
	HEX_REG_HVX_VR_V21 = 21,
	HEX_REG_HVX_VR_V22 = 22,
	HEX_REG_HVX_VR_V23 = 23,
	HEX_REG_HVX_VR_V24 = 24,
	HEX_REG_HVX_VR_V25 = 25,
	HEX_REG_HVX_VR_V26 = 26,
	HEX_REG_HVX_VR_V27 = 27,
	HEX_REG_HVX_VR_V28 = 28,
	HEX_REG_HVX_VR_V29 = 29,
	HEX_REG_HVX_VR_V30 = 30,
	HEX_REG_HVX_VR_V31 = 31,
} HEX_HVX_VR; // HvxVR

typedef enum {
	HEX_REG_HVX_WR_W0 = 0,
	HEX_REG_HVX_WR_W1 = 2,
	HEX_REG_HVX_WR_W2 = 4,
	HEX_REG_HVX_WR_W3 = 6,
	HEX_REG_HVX_WR_W4 = 8,
	HEX_REG_HVX_WR_W5 = 10,
	HEX_REG_HVX_WR_W6 = 12,
	HEX_REG_HVX_WR_W7 = 14,
	HEX_REG_HVX_WR_W8 = 16,
	HEX_REG_HVX_WR_W9 = 18,
	HEX_REG_HVX_WR_W10 = 20,
	HEX_REG_HVX_WR_W11 = 22,
	HEX_REG_HVX_WR_W12 = 24,
	HEX_REG_HVX_WR_W13 = 26,
	HEX_REG_HVX_WR_W14 = 28,
	HEX_REG_HVX_WR_W15 = 30,
} HEX_HVX_WR; // HvxWR

typedef enum {
	HEX_REG_INT_REGS_R0 = 0,
	HEX_REG_INT_REGS_R1 = 1,
	HEX_REG_INT_REGS_R2 = 2,
	HEX_REG_INT_REGS_R3 = 3,
	HEX_REG_INT_REGS_R4 = 4,
	HEX_REG_INT_REGS_R5 = 5,
	HEX_REG_INT_REGS_R6 = 6,
	HEX_REG_INT_REGS_R7 = 7,
	HEX_REG_INT_REGS_R8 = 8,
	HEX_REG_INT_REGS_R9 = 9,
	HEX_REG_INT_REGS_R10 = 10,
	HEX_REG_INT_REGS_R11 = 11,
	HEX_REG_INT_REGS_R12 = 12,
	HEX_REG_INT_REGS_R13 = 13,
	HEX_REG_INT_REGS_R14 = 14,
	HEX_REG_INT_REGS_R15 = 15,
	HEX_REG_INT_REGS_R16 = 16,
	HEX_REG_INT_REGS_R17 = 17,
	HEX_REG_INT_REGS_R18 = 18,
	HEX_REG_INT_REGS_R19 = 19,
	HEX_REG_INT_REGS_R20 = 20,
	HEX_REG_INT_REGS_R21 = 21,
	HEX_REG_INT_REGS_R22 = 22,
	HEX_REG_INT_REGS_R23 = 23,
	HEX_REG_INT_REGS_R24 = 24,
	HEX_REG_INT_REGS_R25 = 25,
	HEX_REG_INT_REGS_R26 = 26,
	HEX_REG_INT_REGS_R27 = 27,
	HEX_REG_INT_REGS_R28 = 28,
	HEX_REG_INT_REGS_R29 = 29, // sp
	HEX_REG_INT_REGS_R30 = 30, // fp
	HEX_REG_INT_REGS_R31 = 31, // lr
} HEX_INT_REGS; // IntRegs

typedef enum {
	HEX_REG_INT_REGS_LOW8_R0 = 0,
	HEX_REG_INT_REGS_LOW8_R1 = 1,
	HEX_REG_INT_REGS_LOW8_R2 = 2,
	HEX_REG_INT_REGS_LOW8_R3 = 3,
	HEX_REG_INT_REGS_LOW8_R4 = 4,
	HEX_REG_INT_REGS_LOW8_R5 = 5,
	HEX_REG_INT_REGS_LOW8_R6 = 6,
	HEX_REG_INT_REGS_LOW8_R7 = 7,
} HEX_INT_REGS_LOW8; // IntRegsLow8

typedef enum {
	HEX_REG_MOD_REGS_M0 = 6, // c6
	HEX_REG_MOD_REGS_M1 = 7, // c7
} HEX_MOD_REGS; // ModRegs

typedef enum {
	HEX_REG_PRED_REGS_P0 = 0,
	HEX_REG_PRED_REGS_P1 = 1,
	HEX_REG_PRED_REGS_P2 = 2,
	HEX_REG_PRED_REGS_P3 = 3,
} HEX_PRED_REGS; // PredRegs

typedef enum {
	HEX_REG_SYS_REGS_SGP0 = 0, // s0
	HEX_REG_SYS_REGS_SGP1 = 1, // s1
	HEX_REG_SYS_REGS_STID = 2, // s2
	HEX_REG_SYS_REGS_ELR = 3, // s3
	HEX_REG_SYS_REGS_BADVA0 = 4, // s4
	HEX_REG_SYS_REGS_BADVA1 = 5, // s5
	HEX_REG_SYS_REGS_SSR = 6, // s6
	HEX_REG_SYS_REGS_CCR = 7, // s7
	HEX_REG_SYS_REGS_HTID = 8, // s8
	HEX_REG_SYS_REGS_BADVA = 9, // s9
	HEX_REG_SYS_REGS_IMASK = 10, // s10
	HEX_REG_SYS_REGS_S11 = 11,
	HEX_REG_SYS_REGS_S12 = 12,
	HEX_REG_SYS_REGS_S13 = 13,
	HEX_REG_SYS_REGS_S14 = 14,
	HEX_REG_SYS_REGS_S15 = 15,
	HEX_REG_SYS_REGS_EVB = 16, // s16
	HEX_REG_SYS_REGS_MODECTL = 17, // s17
	HEX_REG_SYS_REGS_SYSCFG = 18, // s18
	HEX_REG_SYS_REGS_S19 = 19, // s19
	HEX_REG_SYS_REGS_S20 = 20, // s20
	HEX_REG_SYS_REGS_VID = 21, // s21
	HEX_REG_SYS_REGS_S22 = 22, // s22
	HEX_REG_SYS_REGS_S23 = 23,
	HEX_REG_SYS_REGS_S24 = 24,
	HEX_REG_SYS_REGS_S25 = 25,
	HEX_REG_SYS_REGS_S26 = 26,
	HEX_REG_SYS_REGS_CFGBASE = 27, // s27
	HEX_REG_SYS_REGS_DIAG = 28, // s28
	HEX_REG_SYS_REGS_REV = 29, // s29
	HEX_REG_SYS_REGS_PCYCLELO = 30, // s30
	HEX_REG_SYS_REGS_PCYCLEHI = 31, // s31
	HEX_REG_SYS_REGS_ISDBST = 32, // s32
	HEX_REG_SYS_REGS_ISDBCFG0 = 33, // s33
	HEX_REG_SYS_REGS_ISDBCFG1 = 34, // s34
	HEX_REG_SYS_REGS_S35 = 35,
	HEX_REG_SYS_REGS_BRKPTPC0 = 36, // s36
	HEX_REG_SYS_REGS_BRKPTCFG0 = 37, // s37
	HEX_REG_SYS_REGS_BRKPTPC1 = 38, // s38
	HEX_REG_SYS_REGS_BRKPTCFG1 = 39, // s39
	HEX_REG_SYS_REGS_ISDBMBXIN = 40, // s40
	HEX_REG_SYS_REGS_ISDBMBXOUT = 41, // s41
	HEX_REG_SYS_REGS_ISDBEN = 42, // s42
	HEX_REG_SYS_REGS_ISDBGPR = 43, // s43
	HEX_REG_SYS_REGS_S44 = 44,
	HEX_REG_SYS_REGS_S45 = 45,
	HEX_REG_SYS_REGS_S46 = 46,
	HEX_REG_SYS_REGS_S47 = 47,
	HEX_REG_SYS_REGS_PMUCNT0 = 48, // s48
	HEX_REG_SYS_REGS_PMUCNT1 = 49, // s49
	HEX_REG_SYS_REGS_PMUCNT2 = 50, // s50
	HEX_REG_SYS_REGS_PMUCNT3 = 51, // s51
	HEX_REG_SYS_REGS_PMUEVTCFG = 52, // s52
	HEX_REG_SYS_REGS_PMUCFG = 53, // s53
	HEX_REG_SYS_REGS_S54 = 54,
	HEX_REG_SYS_REGS_S55 = 55,
	HEX_REG_SYS_REGS_S56 = 56,
	HEX_REG_SYS_REGS_S57 = 57,
	HEX_REG_SYS_REGS_S58 = 58,
	HEX_REG_SYS_REGS_S59 = 59,
	HEX_REG_SYS_REGS_S60 = 60,
	HEX_REG_SYS_REGS_S61 = 61,
	HEX_REG_SYS_REGS_S62 = 62,
	HEX_REG_SYS_REGS_S63 = 63,
	HEX_REG_SYS_REGS_S64 = 64,
	HEX_REG_SYS_REGS_S65 = 65,
	HEX_REG_SYS_REGS_S66 = 66,
	HEX_REG_SYS_REGS_S67 = 67,
	HEX_REG_SYS_REGS_S68 = 68,
	HEX_REG_SYS_REGS_S69 = 69,
	HEX_REG_SYS_REGS_S70 = 70,
	HEX_REG_SYS_REGS_S71 = 71,
	HEX_REG_SYS_REGS_S72 = 72,
	HEX_REG_SYS_REGS_S73 = 73,
	HEX_REG_SYS_REGS_S74 = 74,
	HEX_REG_SYS_REGS_S75 = 75,
	HEX_REG_SYS_REGS_S76 = 76,
	HEX_REG_SYS_REGS_S77 = 77,
	HEX_REG_SYS_REGS_S78 = 78,
	HEX_REG_SYS_REGS_S79 = 79,
	HEX_REG_SYS_REGS_S80 = 80,
} HEX_SYS_REGS; // SysRegs

typedef enum {
	HEX_REG_SYS_REGS64_SGP1_0 = 0, // sgp1:0
	HEX_REG_SYS_REGS64_S3_2 = 2,
	HEX_REG_SYS_REGS64_S5_4 = 4, // badva1:0
	HEX_REG_SYS_REGS64_S7_6 = 6, // ccr:ssr
	HEX_REG_SYS_REGS64_S9_8 = 8,
	HEX_REG_SYS_REGS64_S11_10 = 10,
	HEX_REG_SYS_REGS64_S13_12 = 12,
	HEX_REG_SYS_REGS64_S15_14 = 14,
	HEX_REG_SYS_REGS64_S17_16 = 16,
	HEX_REG_SYS_REGS64_S19_18 = 18,
	HEX_REG_SYS_REGS64_S21_20 = 20,
	HEX_REG_SYS_REGS64_S23_22 = 22,
	HEX_REG_SYS_REGS64_S25_24 = 24,
	HEX_REG_SYS_REGS64_S27_26 = 26,
	HEX_REG_SYS_REGS64_S29_28 = 28,
	HEX_REG_SYS_REGS64_S31_30 = 30, // pcycle
	HEX_REG_SYS_REGS64_S33_32 = 32,
	HEX_REG_SYS_REGS64_S35_34 = 34,
	HEX_REG_SYS_REGS64_S37_36 = 36,
	HEX_REG_SYS_REGS64_S39_38 = 38,
	HEX_REG_SYS_REGS64_S41_40 = 40,
	HEX_REG_SYS_REGS64_S43_42 = 42,
	HEX_REG_SYS_REGS64_S45_44 = 44,
	HEX_REG_SYS_REGS64_S47_46 = 46,
	HEX_REG_SYS_REGS64_S49_48 = 48,
	HEX_REG_SYS_REGS64_S51_50 = 50,
	HEX_REG_SYS_REGS64_S53_52 = 52,
	HEX_REG_SYS_REGS64_S55_54 = 54,
	HEX_REG_SYS_REGS64_S57_56 = 56,
	HEX_REG_SYS_REGS64_S59_58 = 58,
	HEX_REG_SYS_REGS64_S61_60 = 60,
	HEX_REG_SYS_REGS64_S63_62 = 62,
	HEX_REG_SYS_REGS64_S65_64 = 64,
	HEX_REG_SYS_REGS64_S67_66 = 66,
	HEX_REG_SYS_REGS64_S69_68 = 68,
	HEX_REG_SYS_REGS64_S71_70 = 70,
	HEX_REG_SYS_REGS64_S73_72 = 72,
	HEX_REG_SYS_REGS64_S75_74 = 74,
	HEX_REG_SYS_REGS64_S77_76 = 76,
	HEX_REG_SYS_REGS64_S79_78 = 78,
} HEX_SYS_REGS64; // SysRegs64

#define BIT_MASK(len)          (BIT(len) - 1)
#define BF_MASK(start, len)    (BIT_MASK(len) << (start))
#define BF_PREP(x, start, len) (((x)&BIT_MASK(len)) << (start))
#define BF_GET(y, start, len)  (((y) >> (start)) & BIT_MASK(len))
#define BF_GETB(y, start, end) (BF_GET((y), (start), (end) - (start) + 1)

char *hex_get_ctr_regs(int opcode_reg);
char *hex_get_ctr_regs64(int opcode_reg);
char *hex_get_double_regs(int opcode_reg);
char *hex_get_general_double_low8_regs(int opcode_reg);
char *hex_get_general_sub_regs(int opcode_reg);
char *hex_get_guest_regs(int opcode_reg);
char *hex_get_guest_regs64(int opcode_reg);
char *hex_get_hvx_qr(int opcode_reg);
char *hex_get_hvx_vqr(int opcode_reg);
char *hex_get_hvx_vr(int opcode_reg);
char *hex_get_hvx_wr(int opcode_reg);
char *hex_get_int_regs(int opcode_reg);
char *hex_get_int_regs_low8(int opcode_reg);
char *hex_get_mod_regs(int opcode_reg);
char *hex_get_pred_regs(int opcode_reg);
char *hex_get_sys_regs(int opcode_reg);
char *hex_get_sys_regs64(int opcode_reg);

RZ_API void hex_extend_op(HexState *state, RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr);
int resolve_n_register(const int reg_num, const ut32 addr, const HexPkt *p);
int hexagon_disasm_instruction(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, HexPkt *pkt);
void hexagon_disasm_0x0(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x1(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x2(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x3(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x4(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x5(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x6(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x7(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x8(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0x9(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xa(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xb(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xc(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xd(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_0xe(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x0(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x1(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x2(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x3(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x4(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x5(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x6(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x7(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x8(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0x9(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xa(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xb(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xc(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xd(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
void hexagon_disasm_duplex_0xe(const RzAsm *rz_asm, HexState *state, const ut32 hi_u32, RZ_INOUT HexInsn *hi, const ut32 addr, HexPkt *pkt);
#endif