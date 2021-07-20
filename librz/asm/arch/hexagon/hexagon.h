// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
//
// SPDX-License-Identifier: LGPL-3.0-only

//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#ifndef HEXAGON_H
#define HEXAGON_H

// TODO NOT IN USE
// Predicates - declare the predicate state
typedef enum {
	HEX_NOPRED, // no conditional execution
	HEX_PRED_TRUE, // if (Pd) ...
	HEX_PRED_FALSE, // if (!Pd) ...
	HEX_PRED_TRUE_NEW, // if (Pd.new) ...
	HEX_PRED_FALSE_NEW, // if (!Pd.new) ...
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
	HEX_OP_IMM_SCALED = 1 << 4 // Is the immediate shifted?
} HexOpAttr;

typedef enum {
	HEX_NO_LOOP = 0,
	HEX_LOOP_0 = 1, // Is packet of loop0
	HEX_LOOP_1 = 1 << 1, // Is packet of loop1
	HEX_ENDS_LOOP_0 = 1 << 2, // Packet ends loop0?
	HEX_ENDS_LOOP_1 = 1 << 3, // Packet ends loop1?
} HexLoopAttr;

typedef struct {
	bool first_insn;
	bool last_insn;
	char syntax_prefix[8]; // Package indicator
	char syntax_postfix[16]; // for ":endloop" string.
	unsigned int parse_bits;
	HexLoopAttr loop_attr;
} HexPktInfo;

typedef struct {
	ut8 type;
	union {
		ut8 reg; // + additional Hi or Lo selector // + additional shift // + additional :brev //
		ut32 imm;
	} op;
	ut8 attr;
	ut8 shift;
} HexOp;

typedef struct {
	int instruction;
	ut32 mask;
	// TODO
	// ut16 pf; // additional prefixes (bitmap)
	// TODO
	// HexPred pred; // Predicate type
	bool duplex; // is part of duplex container?
	bool compound; // is part of compound instruction?
	int shift; // Optional shift left is it true?
	HexPktInfo pkt_info;
	ut8 op_count;
	HexOp ops[6];
	char mnem[128]; // Instruction mnemonic
} HexInsn;

typedef struct {
	HexPktInfo i_infos[4];
} HexPkt;

// Instruction container (currently only 2 instructions)
// Can handle duplexes
typedef struct {
	bool duplex;
	HexInsn ins[2]; // Or make it pointer + size?
} HexInsnCont;

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

bool hex_if_duplex(ut32 insn_word);
void hex_op_extend(HexOp *op, bool set_new_extender);
void hex_set_pkt_info(RZ_INOUT HexPktInfo *pkt_info);
int hexagon_disasm_instruction(ut32 hi_u32, HexInsn *hi, ut32 addr);

#endif