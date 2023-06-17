// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

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
			ut64 base_type; /// The DIE of the base type or 0 to indicate the generic type
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
			st64 base_type;
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
		struct { /// For IMPLICIT_VALUE
			RzBinDwarfBlock data;
		} implicit_value;

		struct { /// For IMPLICIT_POINTER
			ut64 value;
			int64_t byte_offset;
		} implicit_pointer;

		struct { /// For PARAMETER_REF
			ut64 offset;
		} parameter_ref;

		struct { /// For ADDRESS
			uint64_t address;
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

static bool Operation_parse(Operation *self, RzBuffer *buffer, const RzBinDwarfEncoding *encoding) {
	RET_FALSE_IF_FAIL(self && buffer && encoding);
	ut8 opcode;
	U8_OR_RET_FALSE(opcode);
	self->opcode = opcode;
	bool big_endian = encoding->big_endian;
	switch (self->opcode) {
	case DW_OP_addr:
		self->kind = OPERATION_KIND_ADDRESS;
		UX_OR_RET_FALSE(self->address.address, encoding->address_size);
		break;
	case DW_OP_deref:
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = 0; // TODO: generic_type
		self->deref.size = encoding->address_size;
		self->deref.space = false;
		break;
	case DW_OP_const1u:
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		U8_OR_RET_FALSE(self->unsigned_constant.value);
		break;
	case DW_OP_const1s: {
		ut8 value;
		U8_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st8)value;
		break;
	}
	case DW_OP_const2u:
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		U16_OR_RET_FALSE(self->unsigned_constant.value);
		break;
	case DW_OP_const2s: {
		ut16 value;
		U16_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st16)value;
		break;
	}
	case DW_OP_const4u:
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		U32_OR_RET_FALSE(self->unsigned_constant.value);
		break;
	case DW_OP_const4s: {
		ut32 value;
		U32_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st32)value;
		break;
	}
	case DW_OP_const8u:
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		U64_OR_RET_FALSE(self->unsigned_constant.value);
		break;
	case DW_OP_const8s: {
		ut64 value;
		U64_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st64)value;
		break;
	}
	case DW_OP_constu:
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		ULE128_OR_RET_FALSE(self->unsigned_constant.value);
		break;
	case DW_OP_consts: {
		ut64 value;
		ULE128_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st64)value;
		break;
	}
	case DW_OP_dup:
		self->kind = OPERATION_KIND_PICK;
		self->pick.index = 0;
		break;
	case DW_OP_drop:
		self->kind = OPERATION_KIND_DROP;
		break;
	case DW_OP_over:
		self->kind = OPERATION_KIND_PICK;
		self->pick.index = 1;
		break;
	case DW_OP_pick:
		U8_OR_RET_FALSE(self->pick.index);
		self->kind = OPERATION_KIND_PICK;
		break;
	case DW_OP_swap:
		self->kind = OPERATION_KIND_SWAP;
		break;
	case DW_OP_rot:
		self->kind = OPERATION_KIND_ROT;
		break;
	case DW_OP_xderef:
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = 0; // TODO: generic_type
		self->deref.size = encoding->address_size;
		break;
	case DW_OP_abs:
		self->kind = OPERATION_KIND_ABS;
		break;
	case DW_OP_and:
		self->kind = OPERATION_KIND_AND;
		break;
	case DW_OP_div:
		self->kind = OPERATION_KIND_DIV;
		break;
	case DW_OP_minus:
		self->kind = OPERATION_KIND_MINUS;
		break;
	case DW_OP_mod:
		self->kind = OPERATION_KIND_MOD;
		break;
	case DW_OP_mul:
		self->kind = OPERATION_KIND_MUL;
		break;
	case DW_OP_neg:
		self->kind = OPERATION_KIND_NEG;
		break;
	case DW_OP_not:
		self->kind = OPERATION_KIND_NOT;
		break;
	case DW_OP_or:
		self->kind = OPERATION_KIND_OR;
		break;
	case DW_OP_plus:
		self->kind = OPERATION_KIND_PLUS;
		break;
	case DW_OP_plus_uconst:
		ULE128_OR_RET_FALSE(self->plus_constant.value);
		self->kind = OPERATION_KIND_PLUS_CONSTANT;
		break;
	case DW_OP_shl:
		self->kind = OPERATION_KIND_SHL;
		break;
	case DW_OP_shr:
		self->kind = OPERATION_KIND_SHR;
		break;
	case DW_OP_shra:
		self->kind = OPERATION_KIND_SHRA;
		break;
	case DW_OP_xor:
		self->kind = OPERATION_KIND_XOR;
		break;
	case DW_OP_skip:
		self->kind = OPERATION_KIND_SKIP;
		break;
	case DW_OP_bra: {
		ut16 value;
		U16_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_BRA;
		self->bra.target = (st16)value;
		break;
	}
	case DW_OP_eq:
		self->kind = OPERATION_KIND_EQ;
		break;
	case DW_OP_ge:
		self->kind = OPERATION_KIND_GE;
		break;
	case DW_OP_gt:
		self->kind = OPERATION_KIND_GT;
		break;
	case DW_OP_le:
		self->kind = OPERATION_KIND_LE;
		break;
	case DW_OP_lt:
		self->kind = OPERATION_KIND_LT;
		break;
	case DW_OP_ne:
		self->kind = OPERATION_KIND_NE;
		break;
	case DW_OP_lit0:
	case DW_OP_lit1:
	case DW_OP_lit2:
	case DW_OP_lit3:
	case DW_OP_lit4:
	case DW_OP_lit5:
	case DW_OP_lit6:
	case DW_OP_lit7:
	case DW_OP_lit8:
	case DW_OP_lit9:
	case DW_OP_lit10:
	case DW_OP_lit11:
	case DW_OP_lit12:
	case DW_OP_lit13:
	case DW_OP_lit14:
	case DW_OP_lit15:
	case DW_OP_lit16:
	case DW_OP_lit17:
	case DW_OP_lit18:
	case DW_OP_lit19:
	case DW_OP_lit20:
	case DW_OP_lit21:
	case DW_OP_lit22:
	case DW_OP_lit23:
	case DW_OP_lit24:
	case DW_OP_lit25:
	case DW_OP_lit26:
	case DW_OP_lit27:
	case DW_OP_lit28:
	case DW_OP_lit29:
	case DW_OP_lit30:
	case DW_OP_lit31:
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		self->unsigned_constant.value = (ut64)opcode - DW_OP_lit0;
		break;
	case DW_OP_reg0:
	case DW_OP_reg1:
	case DW_OP_reg2:
	case DW_OP_reg3:
	case DW_OP_reg4:
	case DW_OP_reg5:
	case DW_OP_reg6:
	case DW_OP_reg7:
	case DW_OP_reg8:
	case DW_OP_reg9:
	case DW_OP_reg10:
	case DW_OP_reg11:
	case DW_OP_reg12:
	case DW_OP_reg13:
	case DW_OP_reg14:
	case DW_OP_reg15:
	case DW_OP_reg16:
	case DW_OP_reg17:
	case DW_OP_reg18:
	case DW_OP_reg19:
	case DW_OP_reg20:
	case DW_OP_reg21:
	case DW_OP_reg22:
	case DW_OP_reg23:
	case DW_OP_reg24:
	case DW_OP_reg25:
	case DW_OP_reg26:
	case DW_OP_reg27:
	case DW_OP_reg28:
	case DW_OP_reg29:
	case DW_OP_reg30:
	case DW_OP_reg31:
		self->kind = OPERATION_KIND_REGISTER;
		self->reg.register_number = (ut16)opcode - DW_OP_reg0;
		break;
	case DW_OP_breg0:
	case DW_OP_breg1:
	case DW_OP_breg2:
	case DW_OP_breg3:
	case DW_OP_breg4:
	case DW_OP_breg5:
	case DW_OP_breg6:
	case DW_OP_breg7:
	case DW_OP_breg8:
	case DW_OP_breg9:
	case DW_OP_breg10:
	case DW_OP_breg11:
	case DW_OP_breg12:
	case DW_OP_breg13:
	case DW_OP_breg14:
	case DW_OP_breg15:
	case DW_OP_breg16:
	case DW_OP_breg17:
	case DW_OP_breg18:
	case DW_OP_breg19:
	case DW_OP_breg20:
	case DW_OP_breg21:
	case DW_OP_breg22:
	case DW_OP_breg23:
	case DW_OP_breg24:
	case DW_OP_breg25:
	case DW_OP_breg26:
	case DW_OP_breg27:
	case DW_OP_breg28:
	case DW_OP_breg29:
	case DW_OP_breg30:
	case DW_OP_breg31:
		SLE128_OR_RET_FALSE(self->register_offset.register_number);
		self->kind = OPERATION_KIND_REGISTER_OFFSET;
		self->register_offset.register_number = (ut16)opcode - DW_OP_breg0;
		break;

	case DW_OP_regx: {
		ut64 value;
		ULE128_OR_RET_FALSE(value);
		self->reg.register_number = (ut16)value;
		break;
	}
	case DW_OP_fbreg: {
		st64 value;
		SLE128_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_FRAME_OFFSET;
		self->frame_offset.offset = value;
		break;
	}
	case DW_OP_bregx: {
		ut64 register_number;
		ULE128_OR_RET_FALSE(register_number);
		st64 value;
		SLE128_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_REGISTER_OFFSET;
		self->register_offset.register_number = (ut16)register_number;
		self->register_offset.offset = value;
		break;
	}
	case DW_OP_piece: {
		ut64 size;
		ULE128_OR_RET_FALSE(size);
		self->kind = OPERATION_KIND_PIECE;
		self->piece.size_in_bits = size * 8;
		self->piece.bit_offset = 0;
		self->piece.has_bit_offset = false;
		break;
	}
	case DW_OP_deref_size: {
		ut64 size;
		U8_OR_RET_FALSE(size);
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = 0; // TODO: generic type
		self->deref.size = size;
		self->deref.space = false;
		break;
	}
	case DW_OP_xderef_size: {
		ut64 size;
		U8_OR_RET_FALSE(size);
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = 0; // TODO: generic type
		self->deref.size = size;
		self->deref.space = true;
		break;
	}
	case DW_OP_nop:
		self->kind = OPERATION_KIND_NOP;
		break;
	case DW_OP_push_object_address:
		self->kind = OPERATION_KIND_PUSH_OBJECT_ADDRESS;
		break;
	case DW_OP_call2: {
		ut16 value;
		U16_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_CALL;
		self->call.offset = value;
		break;
	}
	case DW_OP_call4: {
		ut32 value;
		U32_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_CALL;
		self->call.offset = value;
		break;
	}
	case DW_OP_call_ref: {
		ut64 value;
		UX_OR_RET_FALSE(value, encoding->address_size);
		self->kind = OPERATION_KIND_CALL;
		self->call.offset = value;
		break;
	}
	case DW_OP_form_tls_address:
		self->kind = OPERATION_KIND_TLS;
		break;
	case DW_OP_call_frame_cfa:
		self->kind = OPERATION_KIND_CALL_FRAME_CFA;
		break;
	case DW_OP_bit_piece: {
		ut64 size;
		ULE128_OR_RET_FALSE(size);
		ut64 offset;
		ULE128_OR_RET_FALSE(offset);
		self->kind = OPERATION_KIND_PIECE;
		self->piece.size_in_bits = size;
		self->piece.bit_offset = offset;
		self->piece.has_bit_offset = true;
		break;
	}
	case DW_OP_implicit_value: {
		ULE128_OR_RET_FALSE(self->implicit_value.data.length);
		buf_read_block(buffer, &self->implicit_value.data);
		self->kind = OPERATION_KIND_IMPLICIT_VALUE;
		break;
	}
	case DW_OP_stack_value:
		self->kind = OPERATION_KIND_STACK_VALUE;
		break;
	case DW_OP_implicit_pointer:
	case DW_OP_GNU_implicit_pointer: {
		ut64 value = 0;
		if (encoding->version == 2) {
			UX_OR_RET_FALSE(value, encoding->address_size);
		} else {
			read_offset(buffer, &value, encoding->address_size, encoding->big_endian);
		}
		st64 byte_offset;
		SLE128_OR_RET_FALSE(byte_offset);
		self->kind = OPERATION_KIND_IMPLICIT_POINTER;
		self->implicit_pointer.value = value;
		self->implicit_pointer.byte_offset = byte_offset;
		break;
	}
	case DW_OP_addrx:
	case DW_OP_GNU_addr_index:
		ULE128_OR_RET_FALSE(self->address_index.index);
		self->kind = OPERATION_KIND_ADDRESS_INDEX;
		break;
	case DW_OP_constx:
	case DW_OP_GNU_const_index:
		ULE128_OR_RET_FALSE(self->constant_index.index);
		self->kind = OPERATION_KIND_CONSTANT_INDEX;
		break;
	case DW_OP_entry_value:
	case DW_OP_GNU_entry_value: {
		ULE128_OR_RET_FALSE(self->entry_value.expression.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &self->entry_value.expression));
		self->kind = OPERATION_KIND_ENTRY_VALUE;
		break;
	}
	case DW_OP_const_type:
	case DW_OP_GNU_const_type: {
		ut64 base_type;
		ULE128_OR_RET_FALSE(base_type);
		ut8 len;
		U8_OR_RET_FALSE(len);
		self->kind = OPERATION_KIND_TYPED_LITERAL;
		self->typed_literal.base_type = base_type;
		self->typed_literal.value.length = len;
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &self->typed_literal.value));
		break;
	}
	case DW_OP_regval_type:
	case DW_OP_GNU_regval_type: {
		ut64 reg;
		ULE128_OR_RET_FALSE(reg);
		ut64 base_type;
		ULE128_OR_RET_FALSE(base_type);
		self->kind = OPERATION_KIND_REGISTER_OFFSET;
		self->register_offset.offset = 0;
		self->register_offset.base_type = base_type;
		self->register_offset.register_number = reg;
		break;
	}
	case DW_OP_deref_type:
	case DW_OP_GNU_deref_type: {
		ut8 size;
		U8_OR_RET_FALSE(size);
		ut64 base_type;
		ULE128_OR_RET_FALSE(base_type);
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = base_type;
		self->deref.size = size;
		self->deref.space = false;
		break;
	}
	case DW_OP_xderef_type: {
		ut8 size;
		U8_OR_RET_FALSE(size);
		ut64 base_type;
		ULE128_OR_RET_FALSE(base_type);
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = base_type;
		self->deref.size = size;
		self->deref.space = true;
		break;
	}
	case DW_OP_convert:
	case DW_OP_GNU_convert:
		ULE128_OR_RET_FALSE(self->convert.base_type);
		self->kind = OPERATION_KIND_CONVERT;
		break;
	case DW_OP_reinterpret:
	case DW_OP_GNU_reinterpret:
		ULE128_OR_RET_FALSE(self->reinterpret.base_type);
		self->kind = OPERATION_KIND_REINTERPRET;
		break;

	case DW_OP_GNU_parameter_ref:
		U32_OR_RET_FALSE(self->parameter_ref.offset);
		self->kind = OPERATION_KIND_PARAMETER_REF;
		break;

	case DW_OP_WASM_location: {
		ut8 byte;
		U8_OR_RET_FALSE(byte);
		switch (byte) {
		case 0: {
			ut64 index;
			ULE128_OR_RET_FALSE(index);
			self->kind = OPERATION_KIND_WASM_LOCAL;
			self->wasm_local.index = index;
			break;
		}
		case 1: {
			ut64 index;
			ULE128_OR_RET_FALSE(index);
			self->kind = OPERATION_KIND_WASM_GLOBAL;
			self->wasm_global.index = index;
			break;
		}
		case 2: {
			ut64 index;
			ULE128_OR_RET_FALSE(index);
			self->kind = OPERATION_KIND_WASM_STACK;
			self->wasm_stack.index = index;
			break;
		}
		case 3: {
			ut32 index;
			U32_OR_RET_FALSE(index);
			self->kind = OPERATION_KIND_WASM_GLOBAL;
			self->wasm_global.index = index;
			break;
		}
		}
		break;
	}

	case DW_OP_lo_user:
	case DW_OP_hi_user:
		RZ_LOG_WARN("Unsupported opcode %d\n", opcode);
		break;
	}
}

typedef ut16 Register;
typedef char *Error;

typedef struct {
	enum {
		EVALUATION_STATE_START,
		EVALUATION_STATE_READY,
		EVALUATION_STATE_ERROR,
		EVALUATION_STATE_COMPLETE,
	} state;

	union {
		struct { // START
			uint64_t *value; // nullable
		} start;
		Error error;
	};
} EvaluationState;

typedef struct {
	st64 value;
} Value;

typedef struct {
	ut64 offset;
} DebugInfoOffset;

typedef struct {
	enum {
		EMPTY,
		REGISTER,
		ADDRESS,
		VALUE,
		BYTES,
		IMPLICIT_POINTER,
	} kind;

	union {
		Register register_number;
		uint64_t address;
		Value value;
		struct { // BYTES
			RzBinDwarfBlock value;
		} bytes;
		struct { // IMPLICIT_POINTER
			DebugInfoOffset value;
			int64_t byte_offset;
		} implicit_pointer;
	};
} Location;

typedef struct operation_evaluation_result_t {
	enum {
		EVALUATION_RESULT_COMPLETE,
		EVALUATION_RESULT_PIECE,
	} kind;

	union {
		Location complete;
	};
} OperationEvaluationResult;

typedef struct {
	bool has_bit_offset;
	ut64 bit_offset;
	Location location;
	bool has_size_in_bits;
	ut64 size_in_bits;
} Piece;

typedef st64 StackValue;

typedef struct {
	const RzBuffer *bytecode;
	const RzBinDwarfEncoding *encoding;
	ut64 object_address;
	ut32 max_iterations;
	ut32 iteration;
	EvaluationState state;

	// Stack operations are done on word-sized values.  We do all
	// operations on 64-bit values, and then mask the results
	// appropriately when popping.
	ut64 addr_mask;
	// The stack.
	RzVector /*<StackValue>*/ stack;

	// The next operation to decode and evaluate.
	RzBuffer *pc;

	// If we see a DW_OP_call* operation, the previous PC and bytecode
	// is stored here while evaluating the subroutine.
	RzVector expression_stack;

	RzVector /*Piece*/ result;
} Evaluation;

typedef struct {
	enum {
		Complete,
		Incomplete,
	} kind;
	union {
		StackValue stack_value;
		Piece piece;
		Location location;
	};
} EvaluationResult;

bool Evaluation_pop(Evaluation *self, StackValue **value) {
	if (rz_vector_len(&self->stack) <= 0) {
		*value = NULL;
		return false;
	}
	if (value) {
		*value = RZ_NEW0(StackValue);
		rz_vector_pop(&self->stack, *value);
	} else {
		rz_vector_pop(&self->stack, NULL);
	}
	return true;
}

bool Evaluation_push(Evaluation *self, StackValue *value) {
	rz_vector_push(&self->stack, value);
	return true;
}

bool Evaluation_evaluate_one_operation(Evaluation *self, RzBinDwarf *dw, EvaluationResult *out) {
	Operation *operation = RZ_NEW(Operation);
	RET_FALSE_IF_FAIL(operation);
	RET_FALSE_IF_FAIL(Operation_parse(operation, self->pc, self->encoding));

	switch (operation->kind) {
	case OPERATION_KIND_DEREF: {
		StackValue *entry = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &entry));
		RET_FALSE_IF_FAIL(entry);
		*entry &= self->addr_mask;
		ut64 *addr_space = NULL;
		if (operation->deref.space) {
			StackValue *space = NULL;
			RET_FALSE_IF_FAIL(Evaluation_pop(self, &space));
			RET_FALSE_IF_FAIL(space);
			*addr_space = *space & self->addr_mask;
		}
		// TODO: eval memory?
		break;
	}
	case OPERATION_KIND_DROP:
		RET_FALSE_IF_FAIL(Evaluation_pop(self, NULL));
		break;
	case OPERATION_KIND_PICK: {
		ut64 len = rz_vector_len(&self->stack);
		if (operation->pick.index >= len) {
			RZ_LOG_WARN("Pick index %d out of range\n", operation->pick.index);
			break;
		}
		StackValue *value = rz_vector_index_ptr(&self->stack, len - operation->pick.index - 1);
		RET_FALSE_IF_FAIL(value);
		RET_FALSE_IF_FAIL(Evaluation_push(self, value));
		break;
	}
	case OPERATION_KIND_SWAP: {
		StackValue *top = NULL;
		StackValue *second = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &top));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &second));
		RET_FALSE_IF_FAIL(Evaluation_push(self, top));
		RET_FALSE_IF_FAIL(Evaluation_push(self, second));
		break;
	}
	case OPERATION_KIND_ROT: {
		StackValue *top = NULL;
		StackValue *second = NULL;
		StackValue *third = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &top));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &second));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &third));
		RET_FALSE_IF_FAIL(Evaluation_push(self, top));
		RET_FALSE_IF_FAIL(Evaluation_push(self, second));
		RET_FALSE_IF_FAIL(Evaluation_push(self, third));
		break;
	}
	case OPERATION_KIND_ABS: {
		StackValue *top = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &top));
		*top = llabs(*top);
		*top &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, top));
		break;
	}
	case OPERATION_KIND_AND: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs & *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_DIV: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs / *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_MINUS: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs - *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_MOD: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs % *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_MUL: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs * *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_NEG: {
		StackValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		StackValue result = -*v;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_NOT: {
		StackValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		StackValue result = ~*v;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_OR: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs | *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_PLUS: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs + *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_PLUS_CONSTANT: {
		StackValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		StackValue result = *v + operation->plus_constant.value;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_SHL: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs << *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_SHR: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs >> *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_SHRA: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs >> *rhs; // TODO: OPERATION_KIND_SHRA
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_XOR: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs ^ *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_BRA: {
		StackValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		ut64 entry = *v & self->addr_mask;
		if (entry != 0) {
			// TODO: compute pc
			//			self->pc = entry;
		}
		break;
	}
	case OPERATION_KIND_EQ: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs == *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_GE: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs >= *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_GT: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs > *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_LE: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs <= *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_LT: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs < *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_NE: {
		StackValue *rhs = NULL;
		StackValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		StackValue result = *lhs != *rhs;
		result &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result));
		break;
	}
	case OPERATION_KIND_SKIP: {
		// TODO: compute pc
		break;
	}
	case OPERATION_KIND_UNSIGNED_CONSTANT: {
		StackValue v = operation->unsigned_constant.value;
		v &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &v));
		break;
	}
	case OPERATION_KIND_SIGNED_CONSTANT: {
		StackValue v = operation->signed_constant.value;
		v &= self->addr_mask;
		RET_FALSE_IF_FAIL(Evaluation_push(self, &v));
		break;
	}
	case OPERATION_KIND_REGISTER: {
		// TODO: register
		break;
	}
	case OPERATION_KIND_REGISTER_OFFSET: {
		// TODO: register
		break;
	}
	case OPERATION_KIND_FRAME_OFFSET: {
		// TODO: frame base
		break;
	}
	case OPERATION_KIND_NOP: break;
	case OPERATION_KIND_PUSH_OBJECT_ADDRESS: break; // TODO: object address
	case OPERATION_KIND_CALL: break; // TODO: call
	case OPERATION_KIND_TLS: break; // TODO: tls
	case OPERATION_KIND_CALL_FRAME_CFA: break; // TODO: cfa
	case OPERATION_KIND_PIECE: {
		Location location = { 0 };
		if (rz_vector_empty(&self->stack)) {
			location.kind = EMPTY;
		} else {
			StackValue *v = NULL;
			RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
			location.kind = ADDRESS;
			location.address = *v;
		}
		Piece piece = {
			.location = location,
			.has_bit_offset = operation->piece.has_bit_offset,
			.bit_offset = operation->piece.bit_offset,
			.has_size_in_bits = true,
			.size_in_bits = operation->piece.size_in_bits,
		};
		rz_vector_push(&self->result, &piece);
		break;
	}
	case OPERATION_KIND_IMPLICIT_VALUE: {
		Location location = {
			.kind = IMPLICIT_POINTER,
			.implicit_pointer = {
				.value = { operation->implicit_pointer.value },
				.byte_offset = operation->implicit_pointer.byte_offset,
			}
		};
		out->kind = Complete;
		out->location = location;
		return true;
	}
	case OPERATION_KIND_STACK_VALUE: {
		StackValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		Location location = {
			.kind = VALUE,
			.value = { *v },
		};
		out->kind = Complete;
		out->location = location;
		return true;
	}
	case OPERATION_KIND_IMPLICIT_POINTER: {
		Location location = {
			.kind = IMPLICIT_POINTER,
			.implicit_pointer = {
				.value = { operation->implicit_pointer.value },
				.byte_offset = operation->implicit_pointer.byte_offset,
			},
		};
		out->kind = Complete;
		out->location = location;
		return true;
	}
	case OPERATION_KIND_ENTRY_VALUE: break; // TODO: entry value
	case OPERATION_KIND_PARAMETER_REF: break; // TODO: parameter ref
	case OPERATION_KIND_ADDRESS: break; // TODO: address
	case OPERATION_KIND_ADDRESS_INDEX: break; // TODO: address index
	case OPERATION_KIND_CONSTANT_INDEX: break; // TODO: constant index
	case OPERATION_KIND_TYPED_LITERAL: break; // TODO: typed literal
	case OPERATION_KIND_CONVERT: break; // TODO: convert
	case OPERATION_KIND_REINTERPRET: break; // TODO: reinterpret
	case OPERATION_KIND_WASM_LOCAL:
	case OPERATION_KIND_WASM_GLOBAL:
	case OPERATION_KIND_WASM_STACK:
		RZ_LOG_ERROR("DWARF WASM operation not supported\n");
		return false;
	}
	out->kind = Incomplete;
	return true;
}
