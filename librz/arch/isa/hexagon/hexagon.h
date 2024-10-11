// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// LLVM commit: b6f51787f6c8e77143f0aef6b58ddc7c55741d5c
// LLVM commit date: 2023-11-15 07:10:59 -0800 (ISO 8601 format)
// Date of code generation: 2024-03-16 06:22:39-05:00
//========================================
// The following code is generated.
// Do not edit. Repository of code generator:
// https://github.com/rizinorg/rz-hexagon

#ifndef HEXAGON_H
#define HEXAGON_H

#include <rz_asm.h>
#include <rz_config.h>
#include <rz_list.h>
#include <rz_types.h>
#include <rz_util/rz_print.h>
#include <hexagon/hexagon_insn.h>

#define HEX_INSN_SIZE        4
#define HEX_MAX_INSN_PER_PKT 4

#define HEX_PC_ALIGNMENT 0x4

#define HEX_PRED_WIDTH  8
#define HEX_GPR_WIDTH   32
#define HEX_GPR64_WIDTH 64
#define HEX_CTR_WIDTH   32
#define HEX_CTR64_WIDTH 64

#define HEX_INVALID_INSN_0 0x00000000
#define HEX_INVALID_INSN_F 0xffffffff

#define MAX_CONST_EXT      512
#define HEXAGON_STATE_PKTS 8
#define ARRAY_LEN(a)       (sizeof(a) / sizeof((a)[0]))

#define ALIAS2OP(alias, is_new)         hex_alias_to_op(alias, is_new)
#define EXPLICIT2OP(num, class, is_new) hex_explicit_to_op(num, class, is_new)
#define NREG2OP(bundle, isa_id)         hex_nreg_to_op(bundle, isa_id)
#define HEX_MAX_OPERANDS                6
#define HEX_PARSE_BITS_MASK             0xc000

typedef struct {
	const char *name;
	const char *alias;
	const char *name_tmp;
	const char *alias_tmp;
} HexRegNames;

typedef struct {
	ut32 /* Reg class */ cls;
	ut32 /* Reg Enum */ reg_enum;
} HexRegAliasMapping;

typedef enum {
	HEX_OP_TYPE_IMM,
	HEX_OP_TYPE_REG,
} HexOpType;

/**
 * \brief Flags to mark which kind of predicates instructions use.
 */
typedef enum {
	HEX_NOPRED, ///< no conditional execution
	HEX_PRED_TRUE, ///< if (Pd) ...
	HEX_PRED_FALSE, ///< if (!Pd) ...
	HEX_PRED_NEW, ///< if (Pd.new) or if (!Pd.new)
} HexPred;

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
	char text_prefix[16]; // Package indicator
	char text_postfix[24]; // for ":endloop" string.
} HexPktInfo;

typedef struct {
	ut8 /* HexOpType */ type; ///< Operand type: Immediate or register
	ut8 class; ///< Equivalent to: HexRegClass (for registers) OR HexOpTemplateFlag (for immediate values).
	char isa_id; ///< The identifier character in the ISA of this instruction: 'd' for Rdd, I for Ii etc. 0x0 if not known.
	union {
		ut8 reg; ///< Register number. E.g. 3 for R3 etc.
		st64 imm; ///< Immediate value.
	} op; ///< Actual value of the operand.
	HexOpAttr attr; ///< Attributes of the operand.
	ut8 shift; ///< Number of bits to shift the bits in the opcode to retrieve the operand value.
} HexOp;

typedef RzILOpEffect *(*HexILOpGetter)(void /* HexInsnPktBundle */ *);

typedef enum {
	HEX_IL_INSN_ATTR_INVALID = 0, ///< Operation was not set or implemented.
	HEX_IL_INSN_ATTR_NONE = 1 << 0, ///< Nothing special about this operation.
	HEX_IL_INSN_ATTR_COND = 1 << 1, ///< Executes differently if a certain condition is met.
	HEX_IL_INSN_ATTR_SUB = 1 << 2, ///< Operation is a sub-instruction.
	HEX_IL_INSN_ATTR_BRANCH = 1 << 3, ///< Operation contains a branch.
	HEX_IL_INSN_ATTR_MEM_READ = 1 << 4, ///< Operation reads from the memory.
	HEX_IL_INSN_ATTR_MEM_WRITE = 1 << 5, ///< Operation writes to the memory.
	HEX_IL_INSN_ATTR_NEW = 1 << 6, ///< Operation reads a .new value.
	HEX_IL_INSN_ATTR_WPRED = 1 << 7, ///< Operation writes a predicate register.
	HEX_IL_INSN_ATTR_WRITE_P0 = 1 << 8, ///< Writes predicate register P0
	HEX_IL_INSN_ATTR_WRITE_P1 = 1 << 9, ///< Writes predicate register P1
	HEX_IL_INSN_ATTR_WRITE_P2 = 1 << 10, ///< Writes predicate register P2
	HEX_IL_INSN_ATTR_WRITE_P3 = 1 << 11, ///< Writes predicate register P3
} HexILInsnAttr;

/**
 * \brief Represents a single operation of an instruction.
 */
typedef struct {
	HexILOpGetter get_il_op; ///< Pointer to the getter to retrieve the RzILOpEffects of this operation.
	HexILInsnAttr attr; ///< Attributes to shuffle it to the correct position in the packets IL ops.
	void /* HexInsn */ *hi; ///< The instruction this op belongs to.
} HexILOp;

/**
 * \brief Struct of instruction operations. Usually an instruction has only one operation
 * but duplex and compound instructions can have more.
 * The last op in this struct has all members set to NULL/0.
 */
typedef struct {
	HexILOp op0;
	HexILOp op1;
	HexILOp end;
} HexILInsn;

typedef struct {
	bool is_sub; ///< Flag for sub-instructions.
	ut8 op_count; ///< The number of operands this instruction has.
	ut32 addr; ///< Memory address the instruction is located (high sub-instruction is unaligned by 2 byte!).
	ut32 opcode; ///< The instruction opcode.
	HexPred pred; ///< The instruction predicate.
	HexInsnID identifier; ///< The instruction identifier
	char text_infix[128]; ///< Textual disassembly of the instruction.
	HexOp ops[HEX_MAX_OPERANDS]; ///< The operands of the instructions.
	HexILInsn il_insn; ///< RZIL instruction. These are not meant for execution! Use the packet ops for that.
	ut8 slot; ///< The slot the instruction occupies.
	RzFloatRMode fround_mode; ///< The float rounding mode of the instruction.
} HexInsn;

/**
 * \brief The instruction container holds one instruction or two sub-instructions if it is a duplex.
 * It stores meta information about those instruction(s) like opcode, packet information or the parse bits.
 */
typedef struct {
	ut8 parse_bits; ///< Parse bits of instruction.
	bool is_duplex; ///< Does this container hold two sub-instructions?
	ut32 identifier; ///< Equals instruction ID if is_duplex = false. Otherwise: (high.id << 16) | (low.id & 0xffff)
	union {
		HexInsn *sub[2]; ///< Pointer to sub-instructions if is_duplex = true. sub[0] = high, sub[1] = low
		HexInsn *insn; ///< Pointer to instruction if is_duplex = false.
	} bin;
	ut32 addr; ///< Address of container. Equals address of instruction or of the high sub-instruction if this is a duplex.
	ut32 bytes; ///< The instruction bytes.
	HexPktInfo pkt_info; ///< Packet related information. First/last instr., prefix and postfix for text etc.
	// Deprecated members will be removed on RzArch introduction.
	RZ_DEPRECATE RzAsmOp asm_op; ///< Private copy of AsmOp. Currently only of interest because it holds the utf8 flag.
	RZ_DEPRECATE RzAnalysisOp ana_op; ///< Private copy of AnalysisOp. Analysis info is written into it.
	char text[296]; ///< Textual disassembly
} HexInsnContainer;

#define HEX_LOG_SLOT_BIT_OFF   4
#define HEX_LOG_SLOT_LOG_WIDTH 2
#define HEX_LOG_SLOT_LOG_MASK  0b11

/**
 * \brief Holds information about the execution of the packet.
 */
typedef struct {
	RzBitVector *slot_cancelled; ///< Flags for cancelled slots. If bit at (1 << slot i) is set, slot i is cancelled.
	RzBitVector *pred_read; ///< Predicate register (P0-P3) read, if flags set at (1 << reg_num) are set.
	RzBitVector *pred_tmp_read; ///< Tmp predicate register (P0-P3) read, if flags set at (1 << reg_num) are set.
	RzBitVector *pred_written; ///< Predicate register (P0-P3) written, if flags (3:0) are set at (1 << pred_num).
				   ///< The bits[11:4] are used to indicate the last slot which wrote to the predicate (2bit each).
				   ///< Details are necessary because, if instructions in different slots
				   ///< write to the same predicate, the result is ANDed.
	RzBitVector *gpr_read; ///< GPR register (R0-R31) read, if flags set at (1 << reg_num) are set.
	RzBitVector *gpr_tmp_read; ///< Tmp GPR register (R0-R31) read, if flags set at (1 << reg_num) are set.
	RzBitVector *gpr_written; ///< GPR register (R0-R31) written, if flags set at (1 << reg_num) are set.
	RzBitVector *ctr_read; ///< Control register (C0-C31) read, if flags set at (1 << reg_num) are set.
	RzBitVector *ctr_tmp_read; ///< Tmp control register (C0-C31) read, if flags set at (1 << reg_num) are set.
	RzBitVector *ctr_written; ///< Control register (C0-C31) written, if flags set at (1 << reg_num) are set.
} HexILExecData;

/**
 * \brief Represents an Hexagon instruction packet.
 * We do not assign instructions to slots, but the order of instructions matters nonetheless.
 * The layout of a real packet is:
 *
 * low addr | Slot 3
 * ---------+----------
 *          | Slot 2
 * ---------+----------
 *          | Slot 1    -> High Sub-Instruction of Duplex is always in Slot 1
 * ---------+----------
 * high addr| Slot 0    -> Low Sub-Instruction of Duplex is always in Slot 0
 *
 * Because of this order the textual disassembly of duplex instructions is: "<high-text> ; <low-text>".
 * Also, the high sub-instruction is located at the _lower_ memory address (aligned to 4 bytes).
 * The low sub-instruction at <high.addr + 2>.
 *
 * This said: The HexPkt.bin holds only instruction container, no instructions!
 * The container holds a normal instruction or two sub-instructions.
 */
typedef struct {
	bool last_instr_present; ///< Has an instruction the parsing bits 0b11 set (is last instruction).
	bool is_valid; ///< Is it a valid packet? Do we know which instruction is the first?
	bool is_eob; ///< Is this packet the end of a code block? E.g. contains unconditional jmp.
	HexLoopAttr hw_loop; ///< If the packet is the end of a hardware loop, it stores here from which one.s
	ut32 hw_loop0_addr; ///< Start address of hardware loop 0
	ut32 hw_loop1_addr; ///< Start address of hardware loop 1
	ut32 pkt_addr; ///< Address of the packet. Equals the address of the first instruction.
	ut64 last_access; ///< Last time accessed in milliseconds
	RzList /*<HexInsnContainer *>*/ *bin; ///< Descending by address sorted list of instruction containers.
	RzPVector /*<HexILOp *>*/ *il_ops; ///< Pointer to RZIL ops of the packet. If empty the il ops were not shuffled into order yet.
	HexILExecData il_op_stats; ///< Meta information about the IL operations executed (register read/written etc.)
} HexPkt;

/**
 * \brief This struct is given to the IL getter of each instruction.
 * They use it for resolving register names, alias and the like.
 */
typedef struct {
	const HexInsn *insn;
	HexPkt *pkt;
} HexInsnPktBundle;

typedef struct {
	ut32 addr; ///< Address of the instruction which gets the extender applied.
	ut32 const_ext; ///< The constant extender value.
} HexConstExt;

/**
 * \brief Flags for the debug printing about the state packet buffer.
 */
typedef enum {
	HEX_BUF_ADD = 0, ///< Instruction is added to a specific packet i.
	HEX_BUF_STALE = 1, ///< Instruction is written to a stale packet (overwrites old one).
	HEX_BUF_NEW = 2, ///< Instruction is written to a new packet (overwrites old one).
} HexBufferAction;

/**
 * \brief Buffer packets for reversed instructions.
 */
typedef struct {
	bool just_init; ///< Flag indicates if IL VM was just initialized.
	HexPkt pkts[HEXAGON_STATE_PKTS]; // buffered instructions
	RzList /*<HexConstExt *>*/ *const_ext_l; // Constant extender values.
	RzConfig *cfg;
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns; ///< PVector with token patterns. Priority ordered.
	bool utf8_enabled; ///< If set, print UTF-8 characters.
} HexState;

/**
 * \brief Register fields of different registers.
 */
typedef enum {
	HEX_REG_FIELD_USR_LPCFG, ///< The LPCFG field of the USR register
	HEX_REG_FIELD_USR_OVF, ///< The OVF field of the USR register
} HexRegField;

typedef enum {
	HEX_RF_WIDTH,
	HEX_RF_OFFSET,
} HexRegFieldProperty;

typedef enum {
	HEX_REG_CLASS_CTR_REGS,
	HEX_REG_CLASS_CTR_REGS64,
	HEX_REG_CLASS_DOUBLE_REGS,
	HEX_REG_CLASS_GENERAL_DOUBLE_LOW8_REGS,
	HEX_REG_CLASS_GENERAL_SUB_REGS,
	HEX_REG_CLASS_GUEST_REGS,
	HEX_REG_CLASS_GUEST_REGS64,
	HEX_REG_CLASS_HVX_QR,
	HEX_REG_CLASS_HVX_VQR,
	HEX_REG_CLASS_HVX_VR,
	HEX_REG_CLASS_HVX_WR,
	HEX_REG_CLASS_INT_REGS,
	HEX_REG_CLASS_INT_REGS_LOW8,
	HEX_REG_CLASS_MOD_REGS,
	HEX_REG_CLASS_PRED_REGS,
	HEX_REG_CLASS_SYS_REGS,
	HEX_REG_CLASS_SYS_REGS64
} HexRegClass;

typedef enum {
	HEX_REG_CTR_REGS_C0 = 0, // sa0
	HEX_REG_CTR_REGS_C1 = 1, // lc0
	HEX_REG_CTR_REGS_C2 = 2, // sa1
	HEX_REG_CTR_REGS_C3 = 3, // lc1
	HEX_REG_CTR_REGS_C4 = 4, // p3:0
	HEX_REG_CTR_REGS_C5 = 5, // c5
	HEX_REG_CTR_REGS_C6 = 6, // m0
	HEX_REG_CTR_REGS_C7 = 7, // m1
	HEX_REG_CTR_REGS_C8 = 8, // usr
	HEX_REG_CTR_REGS_C9 = 9, // pc
	HEX_REG_CTR_REGS_C10 = 10, // ugp
	HEX_REG_CTR_REGS_C11 = 11, // gp
	HEX_REG_CTR_REGS_C12 = 12, // cs0
	HEX_REG_CTR_REGS_C13 = 13, // cs1
	HEX_REG_CTR_REGS_C14 = 14, // upcyclelo
	HEX_REG_CTR_REGS_C15 = 15, // upcyclehi
	HEX_REG_CTR_REGS_C16 = 16, // framelimit
	HEX_REG_CTR_REGS_C17 = 17, // framekey
	HEX_REG_CTR_REGS_C18 = 18, // pktcountlo
	HEX_REG_CTR_REGS_C19 = 19, // pktcounthi
	HEX_REG_CTR_REGS_C20 = 20, // C20
	HEX_REG_CTR_REGS_C21 = 21,
	HEX_REG_CTR_REGS_C22 = 22,
	HEX_REG_CTR_REGS_C23 = 23,
	HEX_REG_CTR_REGS_C24 = 24,
	HEX_REG_CTR_REGS_C25 = 25,
	HEX_REG_CTR_REGS_C26 = 26,
	HEX_REG_CTR_REGS_C27 = 27,
	HEX_REG_CTR_REGS_C28 = 28,
	HEX_REG_CTR_REGS_C29 = 29,
	HEX_REG_CTR_REGS_C30 = 30, // utimerlo
	HEX_REG_CTR_REGS_C31 = 31, // utimerhi
} HEX_CTR_REGS; // CtrRegs

typedef enum {
	HEX_REG_CTR_REGS64_C1_0 = 0, // lc0:sa0
	HEX_REG_CTR_REGS64_C3_2 = 2, // lc1:sa1
	HEX_REG_CTR_REGS64_C5_4 = 4,
	HEX_REG_CTR_REGS64_C7_6 = 6, // m1:0
	HEX_REG_CTR_REGS64_C9_8 = 8,
	HEX_REG_CTR_REGS64_C11_10 = 10,
	HEX_REG_CTR_REGS64_C13_12 = 12, // cs1:0
	HEX_REG_CTR_REGS64_C15_14 = 14, // upcycle
	HEX_REG_CTR_REGS64_C17_16 = 16,
	HEX_REG_CTR_REGS64_C19_18 = 18, // pktcount
	HEX_REG_CTR_REGS64_C21_20 = 20,
	HEX_REG_CTR_REGS64_C23_22 = 22,
	HEX_REG_CTR_REGS64_C25_24 = 24,
	HEX_REG_CTR_REGS64_C27_26 = 26,
	HEX_REG_CTR_REGS64_C29_28 = 28,
	HEX_REG_CTR_REGS64_C31_30 = 30, // utimer
} HEX_CTR_REGS64; // CtrRegs64

typedef enum {
	HEX_REG_DOUBLE_REGS_R1_0 = 0,
	HEX_REG_DOUBLE_REGS_R3_2 = 2,
	HEX_REG_DOUBLE_REGS_R5_4 = 4,
	HEX_REG_DOUBLE_REGS_R7_6 = 6,
	HEX_REG_DOUBLE_REGS_R9_8 = 8,
	HEX_REG_DOUBLE_REGS_R11_10 = 10,
	HEX_REG_DOUBLE_REGS_R13_12 = 12,
	HEX_REG_DOUBLE_REGS_R15_14 = 14,
	HEX_REG_DOUBLE_REGS_R17_16 = 16,
	HEX_REG_DOUBLE_REGS_R19_18 = 18,
	HEX_REG_DOUBLE_REGS_R21_20 = 20,
	HEX_REG_DOUBLE_REGS_R23_22 = 22,
	HEX_REG_DOUBLE_REGS_R25_24 = 24,
	HEX_REG_DOUBLE_REGS_R27_26 = 26,
	HEX_REG_DOUBLE_REGS_R29_28 = 28,
	HEX_REG_DOUBLE_REGS_R31_30 = 30, // lr:fp
} HEX_DOUBLE_REGS; // DoubleRegs

typedef enum {
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R1_0 = 0,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R3_2 = 2,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R5_4 = 4,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R7_6 = 6,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R17_16 = 16,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R19_18 = 18,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R21_20 = 20,
	HEX_REG_GENERAL_DOUBLE_LOW8_REGS_R23_22 = 22,
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
	HEX_REG_GUEST_REGS_G0 = 0, // gelr
	HEX_REG_GUEST_REGS_G1 = 1, // gsr
	HEX_REG_GUEST_REGS_G2 = 2, // gosp
	HEX_REG_GUEST_REGS_G3 = 3, // gbadva
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
	HEX_REG_GUEST_REGS_G16 = 16, // gpmucnt4
	HEX_REG_GUEST_REGS_G17 = 17, // gpmucnt5
	HEX_REG_GUEST_REGS_G18 = 18, // gpmucnt6
	HEX_REG_GUEST_REGS_G19 = 19, // gpmucnt7
	HEX_REG_GUEST_REGS_G20 = 20,
	HEX_REG_GUEST_REGS_G21 = 21,
	HEX_REG_GUEST_REGS_G22 = 22,
	HEX_REG_GUEST_REGS_G23 = 23,
	HEX_REG_GUEST_REGS_G24 = 24, // gpcyclelo
	HEX_REG_GUEST_REGS_G25 = 25, // gpcyclehi
	HEX_REG_GUEST_REGS_G26 = 26, // gpmucnt0
	HEX_REG_GUEST_REGS_G27 = 27, // gpmucnt1
	HEX_REG_GUEST_REGS_G28 = 28, // gpmucnt2
	HEX_REG_GUEST_REGS_G29 = 29, // gpmucnt3
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
	HEX_REG_HVX_VQR_V3_0 = 0,
	HEX_REG_HVX_VQR_V7_4 = 4,
	HEX_REG_HVX_VQR_V11_8 = 8,
	HEX_REG_HVX_VQR_V15_12 = 12,
	HEX_REG_HVX_VQR_V19_16 = 16,
	HEX_REG_HVX_VQR_V23_20 = 20,
	HEX_REG_HVX_VQR_V27_24 = 24,
	HEX_REG_HVX_VQR_V31_28 = 28,
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
	HEX_REG_HVX_WR_V1_0 = 0,
	HEX_REG_HVX_WR_V3_2 = 2,
	HEX_REG_HVX_WR_V5_4 = 4,
	HEX_REG_HVX_WR_V7_6 = 6,
	HEX_REG_HVX_WR_V9_8 = 8,
	HEX_REG_HVX_WR_V11_10 = 10,
	HEX_REG_HVX_WR_V13_12 = 12,
	HEX_REG_HVX_WR_V15_14 = 14,
	HEX_REG_HVX_WR_V17_16 = 16,
	HEX_REG_HVX_WR_V19_18 = 18,
	HEX_REG_HVX_WR_V21_20 = 20,
	HEX_REG_HVX_WR_V23_22 = 22,
	HEX_REG_HVX_WR_V25_24 = 24,
	HEX_REG_HVX_WR_V27_26 = 26,
	HEX_REG_HVX_WR_V29_28 = 28,
	HEX_REG_HVX_WR_V31_30 = 30,
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
	HEX_REG_MOD_REGS_C6 = 6, // m0
	HEX_REG_MOD_REGS_C7 = 7, // m1
} HEX_MOD_REGS; // ModRegs

typedef enum {
	HEX_REG_PRED_REGS_P0 = 0,
	HEX_REG_PRED_REGS_P1 = 1,
	HEX_REG_PRED_REGS_P2 = 2,
	HEX_REG_PRED_REGS_P3 = 3,
} HEX_PRED_REGS; // PredRegs

typedef enum {
	HEX_REG_SYS_REGS_S0 = 0, // sgp0
	HEX_REG_SYS_REGS_S1 = 1, // sgp1
	HEX_REG_SYS_REGS_S2 = 2, // stid
	HEX_REG_SYS_REGS_S3 = 3, // elr
	HEX_REG_SYS_REGS_S4 = 4, // badva0
	HEX_REG_SYS_REGS_S5 = 5, // badva1
	HEX_REG_SYS_REGS_S6 = 6, // ssr
	HEX_REG_SYS_REGS_S7 = 7, // ccr
	HEX_REG_SYS_REGS_S8 = 8, // htid
	HEX_REG_SYS_REGS_S9 = 9, // badva
	HEX_REG_SYS_REGS_S10 = 10, // imask
	HEX_REG_SYS_REGS_S11 = 11,
	HEX_REG_SYS_REGS_S12 = 12,
	HEX_REG_SYS_REGS_S13 = 13,
	HEX_REG_SYS_REGS_S14 = 14,
	HEX_REG_SYS_REGS_S15 = 15,
	HEX_REG_SYS_REGS_S16 = 16, // evb
	HEX_REG_SYS_REGS_S17 = 17, // modectl
	HEX_REG_SYS_REGS_S18 = 18, // syscfg
	HEX_REG_SYS_REGS_S19 = 19, // s19
	HEX_REG_SYS_REGS_S20 = 20, // s20
	HEX_REG_SYS_REGS_S21 = 21, // vid
	HEX_REG_SYS_REGS_S22 = 22, // s22
	HEX_REG_SYS_REGS_S23 = 23,
	HEX_REG_SYS_REGS_S24 = 24,
	HEX_REG_SYS_REGS_S25 = 25,
	HEX_REG_SYS_REGS_S26 = 26,
	HEX_REG_SYS_REGS_S27 = 27, // cfgbase
	HEX_REG_SYS_REGS_S28 = 28, // diag
	HEX_REG_SYS_REGS_S29 = 29, // rev
	HEX_REG_SYS_REGS_S30 = 30, // pcyclelo
	HEX_REG_SYS_REGS_S31 = 31, // pcyclehi
	HEX_REG_SYS_REGS_S32 = 32, // isdbst
	HEX_REG_SYS_REGS_S33 = 33, // isdbcfg0
	HEX_REG_SYS_REGS_S34 = 34, // isdbcfg1
	HEX_REG_SYS_REGS_S35 = 35,
	HEX_REG_SYS_REGS_S36 = 36, // brkptpc0
	HEX_REG_SYS_REGS_S37 = 37, // brkptcfg0
	HEX_REG_SYS_REGS_S38 = 38, // brkptpc1
	HEX_REG_SYS_REGS_S39 = 39, // brkptcfg1
	HEX_REG_SYS_REGS_S40 = 40, // isdbmbxin
	HEX_REG_SYS_REGS_S41 = 41, // isdbmbxout
	HEX_REG_SYS_REGS_S42 = 42, // isdben
	HEX_REG_SYS_REGS_S43 = 43, // isdbgpr
	HEX_REG_SYS_REGS_S44 = 44,
	HEX_REG_SYS_REGS_S45 = 45,
	HEX_REG_SYS_REGS_S46 = 46,
	HEX_REG_SYS_REGS_S47 = 47,
	HEX_REG_SYS_REGS_S48 = 48, // pmucnt0
	HEX_REG_SYS_REGS_S49 = 49, // pmucnt1
	HEX_REG_SYS_REGS_S50 = 50, // pmucnt2
	HEX_REG_SYS_REGS_S51 = 51, // pmucnt3
	HEX_REG_SYS_REGS_S52 = 52, // pmuevtcfg
	HEX_REG_SYS_REGS_S53 = 53, // pmucfg
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
	HEX_REG_SYS_REGS64_S1_0 = 0, // sgp1:0
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

typedef enum {
	HEX_REG_ALIAS_SA0 = 0,
	HEX_REG_ALIAS_LC0 = 1,
	HEX_REG_ALIAS_SA1 = 2,
	HEX_REG_ALIAS_LC1 = 3,
	HEX_REG_ALIAS_P3_0 = 4,
	HEX_REG_ALIAS_C5 = 5,
	HEX_REG_ALIAS_M0 = 6,
	HEX_REG_ALIAS_M1 = 7,
	HEX_REG_ALIAS_USR = 8,
	HEX_REG_ALIAS_PC = 9,
	HEX_REG_ALIAS_UGP = 10,
	HEX_REG_ALIAS_GP = 11,
	HEX_REG_ALIAS_CS0 = 12,
	HEX_REG_ALIAS_CS1 = 13,
	HEX_REG_ALIAS_UPCYCLELO = 14,
	HEX_REG_ALIAS_UPCYCLEHI = 15,
	HEX_REG_ALIAS_FRAMELIMIT = 16,
	HEX_REG_ALIAS_FRAMEKEY = 17,
	HEX_REG_ALIAS_PKTCOUNTLO = 18,
	HEX_REG_ALIAS_PKTCOUNTHI = 19,
	HEX_REG_ALIAS_C20 = 20,
	HEX_REG_ALIAS_UTIMERLO = 21,
	HEX_REG_ALIAS_UTIMERHI = 22,
	HEX_REG_ALIAS_LC0_SA0 = 23,
	HEX_REG_ALIAS_LC1_SA1 = 24,
	HEX_REG_ALIAS_M1_0 = 25,
	HEX_REG_ALIAS_CS1_0 = 26,
	HEX_REG_ALIAS_UPCYCLE = 27,
	HEX_REG_ALIAS_PKTCOUNT = 28,
	HEX_REG_ALIAS_UTIMER = 29,
	HEX_REG_ALIAS_LR_FP = 30,
	HEX_REG_ALIAS_GELR = 31,
	HEX_REG_ALIAS_GSR = 32,
	HEX_REG_ALIAS_GOSP = 33,
	HEX_REG_ALIAS_GBADVA = 34,
	HEX_REG_ALIAS_GPMUCNT4 = 35,
	HEX_REG_ALIAS_GPMUCNT5 = 36,
	HEX_REG_ALIAS_GPMUCNT6 = 37,
	HEX_REG_ALIAS_GPMUCNT7 = 38,
	HEX_REG_ALIAS_GPCYCLELO = 39,
	HEX_REG_ALIAS_GPCYCLEHI = 40,
	HEX_REG_ALIAS_GPMUCNT0 = 41,
	HEX_REG_ALIAS_GPMUCNT1 = 42,
	HEX_REG_ALIAS_GPMUCNT2 = 43,
	HEX_REG_ALIAS_GPMUCNT3 = 44,
	HEX_REG_ALIAS_SP = 45,
	HEX_REG_ALIAS_FP = 46,
	HEX_REG_ALIAS_LR = 47,
	HEX_REG_ALIAS_SGP0 = 48,
	HEX_REG_ALIAS_SGP1 = 49,
	HEX_REG_ALIAS_STID = 50,
	HEX_REG_ALIAS_ELR = 51,
	HEX_REG_ALIAS_BADVA0 = 52,
	HEX_REG_ALIAS_BADVA1 = 53,
	HEX_REG_ALIAS_SSR = 54,
	HEX_REG_ALIAS_CCR = 55,
	HEX_REG_ALIAS_HTID = 56,
	HEX_REG_ALIAS_BADVA = 57,
	HEX_REG_ALIAS_IMASK = 58,
	HEX_REG_ALIAS_EVB = 59,
	HEX_REG_ALIAS_MODECTL = 60,
	HEX_REG_ALIAS_SYSCFG = 61,
	HEX_REG_ALIAS_S19 = 62,
	HEX_REG_ALIAS_S20 = 63,
	HEX_REG_ALIAS_VID = 64,
	HEX_REG_ALIAS_S22 = 65,
	HEX_REG_ALIAS_CFGBASE = 66,
	HEX_REG_ALIAS_DIAG = 67,
	HEX_REG_ALIAS_REV = 68,
	HEX_REG_ALIAS_PCYCLELO = 69,
	HEX_REG_ALIAS_PCYCLEHI = 70,
	HEX_REG_ALIAS_ISDBST = 71,
	HEX_REG_ALIAS_ISDBCFG0 = 72,
	HEX_REG_ALIAS_ISDBCFG1 = 73,
	HEX_REG_ALIAS_BRKPTPC0 = 74,
	HEX_REG_ALIAS_BRKPTCFG0 = 75,
	HEX_REG_ALIAS_BRKPTPC1 = 76,
	HEX_REG_ALIAS_BRKPTCFG1 = 77,
	HEX_REG_ALIAS_ISDBMBXIN = 78,
	HEX_REG_ALIAS_ISDBMBXOUT = 79,
	HEX_REG_ALIAS_ISDBEN = 80,
	HEX_REG_ALIAS_ISDBGPR = 81,
	HEX_REG_ALIAS_PMUCNT0 = 82,
	HEX_REG_ALIAS_PMUCNT1 = 83,
	HEX_REG_ALIAS_PMUCNT2 = 84,
	HEX_REG_ALIAS_PMUCNT3 = 85,
	HEX_REG_ALIAS_PMUEVTCFG = 86,
	HEX_REG_ALIAS_PMUCFG = 87,
	HEX_REG_ALIAS_SGP1_0 = 88,
	HEX_REG_ALIAS_BADVA1_0 = 89,
	HEX_REG_ALIAS_CCR_SSR = 90,
	HEX_REG_ALIAS_PCYCLE = 91,
} HexRegAlias;

RZ_API ut32 hex_resolve_reg_enum_id(HexRegClass class, ut32 reg_num);
const char *hex_get_ctr_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_ctr_regs64(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_double_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_general_double_low8_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_general_sub_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_guest_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_guest_regs64(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_hvx_qr(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_hvx_vqr(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_hvx_vr(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_hvx_wr(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_int_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_int_regs_low8(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_mod_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_pred_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_sys_regs(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
const char *hex_get_sys_regs64(int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);
RZ_API const char *hex_get_reg_in_class(HexRegClass cls, int reg_num, bool get_alias, bool get_new, bool reg_num_is_enum);

RZ_API RZ_BORROW RzConfig *hexagon_get_config(void *plugin_data);
RZ_API void hex_extend_op(HexState *state, RZ_INOUT HexOp *op, const bool set_new_extender, const ut32 addr);
int resolve_n_register(const int reg_num, const ut32 addr, const HexPkt *p);
int hexagon_disasm_instruction(HexState *state, const ut32 hi_u32, RZ_INOUT HexInsnContainer *hi, HexPkt *pkt);
RZ_API const HexOp hex_alias_to_op(HexRegAlias alias, bool tmp_reg);
RZ_API const char *hex_alias_to_reg_name(HexRegAlias alias, bool tmp_reg);
RZ_API const HexOp hex_explicit_to_op(ut32 reg_num, HexRegClass reg_class, bool tmp_reg);

#endif
