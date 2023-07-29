// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_OP_H
#define RIZIN_OP_H

typedef enum {
	OPERATION_KIND_DEREF,
	OPERATION_KIND_DROP,
	OPERATION_KIND_PICK,
	OPERATION_KIND_SWAP,
	OPERATION_KIND_ROT,
	OPERATION_KIND_ABS,
	OPERATION_KIND_AND,
	OPERATION_KIND_DIV,
	OPERATION_KIND_MINUS,
	OPERATION_KIND_MOD,
	OPERATION_KIND_MUL,
	OPERATION_KIND_NEG,
	OPERATION_KIND_NOT,
	OPERATION_KIND_OR,
	OPERATION_KIND_PLUS,
	OPERATION_KIND_PLUS_CONSTANT,
	OPERATION_KIND_SHL,
	OPERATION_KIND_SHR,
	OPERATION_KIND_SHRA,
	OPERATION_KIND_XOR,
	OPERATION_KIND_BRA,
	OPERATION_KIND_EQ,
	OPERATION_KIND_GE,
	OPERATION_KIND_GT,
	OPERATION_KIND_LE,
	OPERATION_KIND_LT,
	OPERATION_KIND_NE,
	OPERATION_KIND_SKIP,
	OPERATION_KIND_UNSIGNED_CONSTANT,
	OPERATION_KIND_SIGNED_CONSTANT,
	OPERATION_KIND_REGISTER,
	OPERATION_KIND_REGISTER_OFFSET,
	OPERATION_KIND_FRAME_OFFSET,
	OPERATION_KIND_NOP,
	OPERATION_KIND_PUSH_OBJECT_ADDRESS,
	OPERATION_KIND_CALL,
	OPERATION_KIND_TLS,
	OPERATION_KIND_CALL_FRAME_CFA,
	OPERATION_KIND_PIECE,
	OPERATION_KIND_IMPLICIT_VALUE,
	OPERATION_KIND_STACK_VALUE,
	OPERATION_KIND_IMPLICIT_POINTER,
	OPERATION_KIND_ENTRY_VALUE,
	OPERATION_KIND_PARAMETER_REF,
	OPERATION_KIND_ADDRESS,
	OPERATION_KIND_ADDRESS_INDEX,
	OPERATION_KIND_CONSTANT_INDEX,
	OPERATION_KIND_TYPED_LITERAL,
	OPERATION_KIND_CONVERT,
	OPERATION_KIND_REINTERPRET,
	OPERATION_KIND_WASM_LOCAL,
	OPERATION_KIND_WASM_GLOBAL,
	OPERATION_KIND_WASM_STACK
} OperationKind;

/// DWARF expression evaluation is done in two parts: first the raw
/// bytes of the next part of the expression are decoded; and then the
/// decoded operation is evaluated.  This approach lets other
/// consumers inspect the DWARF expression without reimplementing the
/// decoding operation.
typedef struct {
	enum DW_OP opcode;
	OperationKind kind;
	/// Dereference the topmost value of the stack.
	union {
		struct {
			UnitOffset base_type; /// The DIE of the base type or 0 to indicate the generic type
			ut8 size; /// The size of the data to dereference.
			bool space; /// True if the dereference operation takes an address space argument from the stack; false otherwise.
		} deref; /// DW_OP_deref DW_OP_xderef
		/// Pick an item from the stack and push it on top of the stack.
		/// This operation handles `DW_OP_pick`, `DW_OP_dup`, and
		/// `DW_OP_over`.
		struct {
			/// The index, from the top of the stack, of the item to copy.
			ut8 index;
		} pick;
		struct {
			/// The value to add.
			ut64 value;
		} plus_constant;
		/// Branch to the target location if the top of stack is nonzero.
		struct {
			/// The relative offset to the target bytecode.
			st16 target;
		} bra;
		/// Unconditional branch to the target location.
		struct {
			/// The relative offset to the target bytecode.
			st16 target;
		} skip;
		/// Push an unsigned constant value on the stack.  This handles multiple
		/// DWARF opcodes.
		struct {
			/// The value to push.
			ut64 value;
		} unsigned_constant;
		/// Push a signed constant value on the stack.  This handles multiple
		/// DWARF opcodes.
		struct {
			/// The value to push.
			st64 value;
		} signed_constant;
		/// Indicate that this piece's location is in the given register.
		///
		/// Completes the piece or expression.
		struct {
			/// The register number.
			ut16 register_number;
		} reg;
		/// Find the value of the given register, add the offset, and then
		/// push the resulting sum on the stack.
		struct {
			/// The register number.
			ut16 register_number;
			/// The offset to add.
			st64 offset;
			/// The DIE of the base type or 0 to indicate the generic type
			UnitOffset base_type;
		} register_offset;
		/// Compute the frame base (using `DW_AT_frame_base`), add the
		/// given offset, and then push the resulting sum on the stack.
		struct {
			/// The offset to add.
			st64 offset;
		} frame_offset;
		/// Evaluate a DWARF expression as a subroutine.  The expression
		/// comes from the `DW_AT_location` attribute of the indicated
		/// DIE.
		struct {
			/// The DIE to use.
			ut64 offset;
		} call;
		/// Terminate a piece.
		struct {
			/// The size of this piece in bits.
			ut64 size_in_bits;
			/// The bit offset of this piece.  If `None`, then this piece
			/// was specified using `DW_OP_piece` and should start at the
			/// next byte boundary.
			bool has_bit_offset;
			ut64 bit_offset;
		} piece;
		/// For IMPLICIT_VALUE
		RzBinDwarfBlock implicit_value;

		struct { /// For IMPLICIT_POINTER
			ut64 value;
			st64 byte_offset;
		} implicit_pointer;

		struct { /// For PARAMETER_REF
			ut64 offset;
		} parameter_ref;

		struct { /// For ADDRESS
			ut64 address;
		} address;

		struct { /// For ADDRESS_INDEX
			ut64 index;
		} address_index;

		struct { /// For CONSTANT_INDEX
			ut64 index;
		} constant_index;

		struct {
			RzBinDwarfBlock expression;
		} entry_value;

		struct {
			ut64 base_type;
			RzBinDwarfBlock value; // for TYPED_LITERAL
		} typed_literal;

		struct {
			ut64 base_type;
		} convert;

		struct {
			ut64 base_type;
		} reinterpret;

		struct {
			ut32 index;
		} wasm_local;

		struct {
			ut32 index;
		} wasm_global;

		struct {
			ut32 index;
		} wasm_stack;
	};
} Operation;

RZ_IPI bool Operation_parse(Operation *self, RzBuffer *buffer, const RzBinDwarfEncoding *encoding);

typedef ut16 Register;
typedef char *Error;

typedef struct operation_evaluation_result_t {
	enum {
		OperationEvaluationResult_COMPLETE,
		OperationEvaluationResult_INCOMPLETE,
		OperationEvaluationResult_PIECE,
		OperationEvaluationResult_WAITING,
		OperationEvaluationResult_WAITING_RESOLVE,
	} kind;

	union {
		RzBinDwarfLocation complete;
		struct {
			RzBinDwarfEvaluationStateWaiting _1;
			RzBinDwarfEvaluationResult _2;
		} waiting;
	};
} OperationEvaluationResult;

typedef struct {
	RzBuffer *pc;
	RzBuffer *bytecode;
} RzBinDwarfExprStackItem;

RZ_IPI void RzBinDwarfEvaluationResult_fini(RzBinDwarfEvaluationResult *self);

#endif // RIZIN_OP_H
