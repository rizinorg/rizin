// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARCH_H
#define RZ_ARCH_H

#include <rz_util/rz_bitvector.h>
#include <rz_util/rz_iterator.h>
#include <rz_types.h>
#include <rz_vector.h>
#include <rz_util.h>

// Deprecated includes.
#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_parse.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_arch);

typedef enum {
	RZ_ARCH_XCODE_MEMBER_INVALID = 0, ///< Invalid member
	RZ_ARCH_XCODE_MEMBER_BYTES, ///< Member are bytes provided by a RzBuffer.
	RZ_ARCH_XCODE_MEMBER_ASSEMBLY, ///< Member is assembly
	RZ_ARCH_XCODE_MEMBER_PACKET, ///< Member is RzArchPacket
	RZ_ARCH_XCODE_MEMBER_HINT, ///< Member is RzArchHint
	RZ_ARCH_XCODE_MEMBER_DETAIL, ///< Member is RzArchDetail
	RZ_ARCH_XCODE_MEMBER_IL, ///< Member is RzILEffect
	RZ_ARCH_XCODE_MEMBER_TOKEN, ///< Member is RzArchToken
	RZ_ARCH_XCODE_MEMBER_PARSE, ///< [Deprecated] Member is parsed string (pseudo code)
	RZ_ARCH_XCODE_MEMBER_ESIL, ///< [Deprecated] Member is ESIL
} RzArchXCodeMember;

typedef ut64 RzAddress;

typedef struct rz_arch_xcode_t {
	RzArchXCodeMember member_type; ///< Describes the content of array
	RzPVector /*<void>*/ *members; ///< Array of variable size, containing one or more structures of type member.
} RzArchXCode;

/// This needs to be redone, copied for reference from RzAnalysisOp
typedef struct rz_arch_insn_t {
	char *mnemonic; /* mnemonic.. it actually contains the args too, we should replace rasm with this */
	RzAddress addr; /* address */
	ut32 type; /* type of opcode */
	RzAnalysisOpPrefix prefix; /* type of opcode prefix (rep,lock,..) */
	ut32 type2; /* used by java */
	RzAnalysisStackOp stackop; /* operation on stack? */
	RzTypeCond cond; /* condition type */
	int size; /* size in bytes of opcode */
	int nopcode; /* number of bytes representing the opcode (not the arguments) TODO: find better name */
	int cycles; /* cpu-cycles taken by instruction */
	int failcycles; /* conditional cpu-cycles */
	RzAnalysisOpFamily family; /* family of opcode */
	int id; /* instruction id */
	bool eob; /* end of block (boolean) */
	bool sign; /* operates on signed values, false by default */
	/* Run N instructions before executing the current one */
	int delay; /* delay N slots (mips, ..)*/
	RzAddress jump; /* true jmp */
	RzAddress fail; /* false jmp */
	RzAnalysisOpDirection direction;
	st64 ptr; /* reference to memory */ /* XXX signed? */
	ut64 val; /* reference to value */ /* XXX signed? */
	RzAnalysisValue analysis_vals[6]; /* Analyzable values */
	int ptrsize; /* f.ex: zero extends for 8, 16 or 32 bits only */
	st64 stackptr; /* stack pointer */
	int refptr; /* if (0) ptr = "reference" else ptr = "load memory of refptr bytes" */
	ut64 mmio_address; // mmio address
	RzAnalysisValue *src[6];
	RzAnalysisValue *dst;
	RzList /*<RzAnalysisValue *>*/ *access; /* RzAnalysisValue access information */
	RzStrBuf esil;
	RzStrBuf opex;
	const char *reg; /* destination register */
	const char *ireg; /* register used for indirect memory computation*/
	int scale;
	ut64 disp;
	RzAnalysisSwitchOp *switch_op;
	RzAnalysisHint hint;
	RzAnalysisDataType datatype;
} RzArchInsn;

typedef enum {
	RZ_ARCH_OPERAND_ACCESS_UNDEF = 0, ///< Undefined access
	RZ_ARCH_OPERAND_ACCESS_READ, ///< Read access
	RZ_ARCH_OPERAND_ACCESS_WRITE, ///< Write access
} RzArchOperandAccess;

#define RZ_ARCH_OPERAND_MEMBER_ATOMIC 0xffff
#define RZ_ARCH_OPERAND_MEMBER_CLASS 0xff0000

/**
 * \brief Memberships of operands.
 */
typedef enum {
	RZ_ARCH_OPERAND_MEMBER_INVALID = 0,
	RZ_ARCH_OPERAND_MEMBER_REGISTER, ///< Register operand
	RZ_ARCH_OPERAND_MEMBER_IMMEDIATE, ///< Immediate value of any sign operand.
	RZ_ARCH_OPERAND_MEMBER_UNSIGNED, ///< Unsigned immediate value operand.
	RZ_ARCH_OPERAND_MEMBER_SIGNED, ///< Signed immediate value operand.
	RZ_ARCH_OPERAND_MEMBER_COMPLEX = 0x10000, ///< This operand consists of multiple other operands.
	RZ_ARCH_OPERAND_MEMBER_ADDRESS = 0x20000, ///< This operand should be interpreted as an address.
} RzArchOperandMember;

/// The bitvecor must be initialized with rz_bv_fini. In case it holds a value >64bits.
typedef struct rz_arch_operand_value_t {
	RzArchOperandMember member; ///< Details about the operand membership.
	RzArchOperandAccess access; ///< Access to this operand.
	union {
		size_t register_id; ///< A register
		RzBitVector imm; ///< An immediate value.
	};
	RzPVector /*<RzArchOperandValue>*/ *components; ///< Components of complex operands.
} RzArchOperand;

static inline bool rz_arch_op_val_is_reg(RZ_NONNULL const RzArchOperand *op) {
	return op->member & RZ_ARCH_OPERAND_MEMBER_REGISTER;
}

static inline bool rz_arch_op_val_is_imm(RZ_NONNULL const RzArchOperand *op) {
	return op->member & RZ_ARCH_OPERAND_MEMBER_IMMEDIATE;
}

static inline bool rz_arch_op_val_is_signed(RZ_NONNULL const RzArchOperand *op) {
	return op->member & RZ_ARCH_OPERAND_MEMBER_SIGNED;
}

static inline bool rz_arch_op_val_is_unsigned(RZ_NONNULL const RzArchOperand *op) {
	return op->member & RZ_ARCH_OPERAND_MEMBER_UNSIGNED;
}

static inline bool rz_arch_op_val_is_complex(RZ_NONNULL const RzArchOperand *op) {
	return op->member & RZ_ARCH_OPERAND_MEMBER_COMPLEX;
}

/**
 * \brief Returns the member a complex operand was reduced to.
 *
 * E.g.: a complex address operand consisting of two immediate values `base` and `offset`.
 * If the plugin already reduced them to their final value (`base + offset`), this function
 * returns RZ_ARCH_OPERAND_MEMBER_IMMEDIATE.
 *
 * \return The member the combined operands are reduced to. The reduced value is stored in the suitable field.
 * It returns RZ_ARCH_OPERAND_MEMBER_INVALID, if the plugin cannot reduce complex operand.
 */
static inline RzArchOperandMember rz_arch_op_val_is_complex_reduced(RZ_NONNULL const RzArchOperand *op) {
	return (RzArchOperandMember) (op->member & RZ_ARCH_OPERAND_MEMBER_ATOMIC);
}

static inline bool rz_arch_op_val_is_address(RZ_NONNULL const RzArchOperand *op) {
	return op->member & RZ_ARCH_OPERAND_MEMBER_ADDRESS;
}

static inline RzArchOperandMember rz_arch_op_val_member_atmoic(RZ_NONNULL const RzArchOperand *op) {
	return (RzArchOperandMember) (op->member & RZ_ARCH_OPERAND_MEMBER_ATOMIC);
}

static inline RzArchOperandMember rz_arch_op_val_member_class(RZ_NONNULL const RzArchOperand *op) {
	return (RzArchOperandMember) (op->member & RZ_ARCH_OPERAND_MEMBER_CLASS);
}

/**
 * \brief Values a packet can contain.
 */
typedef enum {
	RZ_ARCH_PACKET_ITER_KIND_INVALID = 0,
	RZ_ARCH_PACKET_ITER_KIND_CALL_TARGETS,
	RZ_ARCH_PACKET_ITER_KIND_JUMP_TARGETS,
	RZ_ARCH_PACKET_ITER_KIND_DATA_REFS,
	RZ_ARCH_PACKET_ITER_KIND_CODE_REFS,
	RZ_ARCH_PACKET_ITER_KIND_IMMS,
	RZ_ARCH_PACKET_ITER_KIND_REGS,
	RZ_ARCH_PACKET_ITER_KIND_OPERANDS,
} RzArchPacketIterKind;

typedef enum {
	RZ_ARCH_PACKET_ITER_GROUPED_NONE = 0, ///< The iterator iterates over all requested elements in a packet.
	RZ_ARCH_PACKET_ITER_GROUPED_INSN, ///< The iterator groups the requested elements by instuctions (iterator over iterators).
} RzArchPacketIterGrouped;

typedef enum {
	RZ_ARCH_PACKET_INSN_ORDER_INVALID = 0,
	RZ_ARCH_PACKET_INSN_ORDER_LOW_ADDR_FIRST,
	RZ_ARCH_PACKET_INSN_ORDER_HIGH_ADDR_FIRST,
} RzArchPacketInsnOrder;

/// We should implement an enum for each of it though.
typedef _RzAnalysisOpType RzArchPacketType;
typedef _RzAnalysisOpType RzArchInsnType;

struct rz_arch_packet_t;

/**
 * \brief Get an iterator over elements of type \p kind from all instructions in the packet.
 * The order of values follows RzArchPacket.order. Values of the first instruction are returned first.
 *
 * \param packet The instruction packet.
 * \param kind The kind of values the iterator should yield.
 *
 * \return Returns an iterator over the \p kind elements.
 * Or NULL if the architecture doesn't support this iterator kind. Or has no elements to iterate over.
 */
typedef RZ_OWN RzIterator /*<void>*/ *(*rz_arch_packet_iter)(const struct rz_arch_packet_t *packet, RzArchPacketIterKind kind, RzArchPacketIterGrouped grouped_by);

/**
 * \brief Get an iterator instructions with \p property.
 * The order of instrctions follows RzArchPacket.order.
 *
 * \param packet The instruction packet.
 * \param kind The kind of values the iterator should yield.
 *
 * \return Returns an iterator over the insturctions with \p insn_type.
 * Or NULL if the packet has no instructions of such type.
 */
typedef RZ_OWN RzIterator /*<RzArchInsn>*/ *(*rz_arch_packet_iter_insn)(const struct rz_arch_packet_t *packet, RzArchInsnType insn_type);

/**
 * \brief An atomically executed unit. Can contain 1-n instructions.
 */
typedef struct rz_arch_packet_t {
	RzArchPacketInsnOrder order; ///< Order the instructions.
	RzPVector /*<RzArchInsn>*/ *insns; ///< All instructions of a packet. Sorted according to order.
	rz_arch_packet_iter value_iter;
	rz_arch_packet_iter_insn insn_iter;
} RzArchPacket;

/// This needs to be redone, copied for reference from RzAnalysisHint
typedef struct rz_arch_hint_t {
	ut64 addr;
	ut64 ptr;
	ut64 val; // used to hint jmp rax
	ut64 jump;
	ut64 fail;
	ut64 ret; // hint for function ret values
	char *arch;
	char *opcode;
	char *syntax;
	char *esil;
	char *offset;
	ut32 type;
	ut64 size;
	int bits;
	int new_bits; // change asm.bits after evaluating this instruction
	int immbase;
	bool high; // highlight hint
	int nword;
	ut64 stackframe;
} RzArchHint;

typedef void RzArchPluginContext;

typedef struct rz_arch_plugin_t {
	RZ_DEPRECATE RzAsmPlugin *p_asm; ///< [Deprecated] Assembly Plugin
	RZ_DEPRECATE RzAnalysisPlugin *p_analysis; ///< [Deprecated] Analysis Plugin
	RZ_DEPRECATE RzParsePlugin *p_parse; ///< [Deprecated] Parse Plugin

	bool (*init)(RZ_NONNULL RzConfig *config); ///< Global constructor for the plugin to fill the configuration values.
	bool (*fini)(); ///< Global destructor for the plugin
	bool (*can_xcode_in)(RZ_NONNULL RzArchXCodeMember input); ///< Returns true if the plugin can support the given RzArchXCodeMember in input.
	bool (*can_xcode_out)(RZ_NONNULL RzArchXCodeMember output); ///< Returns true if the plugin can support the given RzArchXCodeMember in ouput.
	bool (*context_init)(RZ_NONNULL RzConfig *config, RZ_OUT RzArchPluginContext **context); ///< Create a new context for a given configuration
	void (*context_fini)(RZ_NULLABLE RzArchPluginContext *context); ///< Free the given context
	void (*context_update)(RZ_NULLABLE RzArchPluginContext *context, RZ_NONNULL RzConfig *config); ///< Updates the given context with the given configuration.
	bool (*context_xcode)(RZ_NULLABLE RzArchPluginContext *context, RZ_NONNULL RzArchXCode *input, RZ_NONNULL RzArchXCode *output); ///< Updates the given context with the given configuration.
} RzArchPlugin;

typedef struct rz_arch_t {
	RzPVector /*<RzArchPlugin*>*/ *plugins;
	HtSP /*<char*, RzConfig*>*/ plugins_config;
} RzArch;

RZ_DEPRECATE RZ_API const size_t rz_arch_get_n_plugins();
RZ_DEPRECATE RZ_API RZ_BORROW RzAsmPlugin *rz_arch_get_asm_plugin(size_t index);
RZ_DEPRECATE RZ_API RZ_BORROW RzAnalysisPlugin *rz_arch_get_analysis_plugin(size_t index);
RZ_DEPRECATE RZ_API RZ_BORROW RzParsePlugin *rz_arch_get_parse_plugin(size_t index);

#ifdef __cplusplus
}
#endif

#endif /* RZ_ARCH_H */
