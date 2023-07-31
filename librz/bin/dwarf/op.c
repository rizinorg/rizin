// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static bool RzBinDwarfLocation_move(RzBinDwarfLocation *self, RzBinDwarfLocation *out) {
	rz_return_val_if_fail(self && out, false);
	memcpy(out, self, sizeof(RzBinDwarfLocation));
	switch (self->kind) {
	case RzBinDwarfLocationKind_EMPTY:
	case RzBinDwarfLocationKind_DECODE_ERROR:
	case RzBinDwarfLocationKind_REGISTER:
	case RzBinDwarfLocationKind_REGISTER_OFFSET:
	case RzBinDwarfLocationKind_IMPLICIT_POINTER:
	case RzBinDwarfLocationKind_CFA_OFFSET:
	case RzBinDwarfLocationKind_FB_OFFSET:
	case RzBinDwarfLocationKind_ADDRESS: break;
	case RzBinDwarfLocationKind_VALUE:
		self->value.location = NULL;
		break;
	case RzBinDwarfLocationKind_BYTES:
		RzBinDwarfBlock_move(&self->bytes, &out->bytes);
		break;
	case RzBinDwarfLocationKind_COMPOSITE:
		self->composite = NULL;
		break;
	case RzBinDwarfLocationKind_EVALUATION_WAITING:
		self->eval_waiting.result = NULL;
		self->eval_waiting.eval = NULL;
		break;
	case RzBinDwarfLocationKind_LOCLIST:
		self->loclist = NULL;
		break;
	}
	return true;
}

static void OperationEvaluationResult_fini(OperationEvaluationResult *self) {
	rz_bin_dwarf_location_fini(&self->complete);
	RzBinDwarfEvaluationResult_fini(&self->waiting._2);
}

RZ_IPI bool Operation_parse(Operation *self, RzBuffer *buffer, const RzBinDwarfEncoding *encoding) {
	rz_return_val_if_fail(self && buffer && encoding, false);
	memset(self, 0, sizeof(Operation));
	U8_OR_RET_FALSE(self->opcode);
	bool big_endian = encoding->big_endian;
	switch (self->opcode) {
	case DW_OP_addr:
		U_ADDR_SIZE_OR_RET_FALSE(self->address.address);
		self->kind = OPERATION_KIND_ADDRESS;
		break;
	case DW_OP_deref:
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = 0;
		self->deref.size = encoding->address_size;
		self->deref.space = false;
		break;
	case DW_OP_const1u:
		U8_OR_RET_FALSE(self->unsigned_constant.value);
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		break;
	case DW_OP_const1s: {
		ut8 value;
		U8_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st8)value;
		break;
	}
	case DW_OP_const2u:
		U_OR_RET_FALSE(16, self->unsigned_constant.value);
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		break;
	case DW_OP_const2s: {
		ut16 value;
		U_OR_RET_FALSE(16, value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st16)value;
		break;
	}
	case DW_OP_const4u:
		U_OR_RET_FALSE(32, self->unsigned_constant.value);
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		break;
	case DW_OP_const4s: {
		ut32 value;
		U_OR_RET_FALSE(32, value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st32)value;
		break;
	}
	case DW_OP_const8u:
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		U_OR_RET_FALSE(64, self->unsigned_constant.value);
		break;
	case DW_OP_const8s: {
		ut64 value;
		U_OR_RET_FALSE(64, value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
		self->signed_constant.value = (st64)value;
		break;
	}
	case DW_OP_constu:
		ULE128_OR_RET_FALSE(self->unsigned_constant.value);
		self->kind = OPERATION_KIND_UNSIGNED_CONSTANT;
		break;
	case DW_OP_consts: {
		ULE128_OR_RET_FALSE(self->signed_constant.value);
		self->kind = OPERATION_KIND_SIGNED_CONSTANT;
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
		self->deref.base_type = 0;
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
		U_OR_RET_FALSE(16, value);
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
		self->unsigned_constant.value = self->opcode - DW_OP_lit0;
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
		self->reg.register_number = self->opcode - DW_OP_reg0;
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
		SLE128_OR_RET_FALSE(self->register_offset.offset);
		self->kind = OPERATION_KIND_REGISTER_OFFSET;
		self->register_offset.register_number = self->opcode - DW_OP_breg0;
		break;

	case DW_OP_regx: {
		ULE128_OR_RET_FALSE(self->reg.register_number);
		self->kind = OPERATION_KIND_REGISTER;
		break;
	}
	case DW_OP_fbreg: {
		SLE128_OR_RET_FALSE(self->frame_offset.offset);
		self->kind = OPERATION_KIND_FRAME_OFFSET;
		break;
	}
	case DW_OP_bregx: {
		ULE128_OR_RET_FALSE(self->register_offset.register_number);
		SLE128_OR_RET_FALSE(self->register_offset.offset);
		self->kind = OPERATION_KIND_REGISTER_OFFSET;
		break;
	}
	case DW_OP_piece: {
		ULE128_OR_RET_FALSE(self->piece.size_in_bits);
		self->piece.size_in_bits *= 8;
		self->kind = OPERATION_KIND_PIECE;
		self->piece.bit_offset = 0;
		self->piece.has_bit_offset = false;
		break;
	}
	case DW_OP_deref_size: {
		U8_OR_RET_FALSE(self->deref.size);
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = 0;
		self->deref.space = false;
		break;
	}
	case DW_OP_xderef_size: {
		U8_OR_RET_FALSE(self->deref.size);
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = 0;
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
		U_OR_RET_FALSE(16, self->call.offset);
		self->kind = OPERATION_KIND_CALL;
		break;
	}
	case DW_OP_call4: {
		U_OR_RET_FALSE(32, self->call.offset);
		self->kind = OPERATION_KIND_CALL;
		break;
	}
	case DW_OP_call_ref: {
		U_ADDR_SIZE_OR_RET_FALSE(self->call.offset);
		self->kind = OPERATION_KIND_CALL;
		break;
	}
	case DW_OP_form_tls_address:
	case DW_OP_GNU_push_tls_address:
		self->kind = OPERATION_KIND_TLS;
		break;
	case DW_OP_call_frame_cfa:
		self->kind = OPERATION_KIND_CALL_FRAME_CFA;
		break;
	case DW_OP_bit_piece: {
		ULE128_OR_RET_FALSE(self->piece.size_in_bits);
		ULE128_OR_RET_FALSE(self->piece.bit_offset);
		self->kind = OPERATION_KIND_PIECE;
		self->piece.has_bit_offset = true;
		break;
	}
	case DW_OP_implicit_value: {
		ULE128_OR_RET_FALSE(self->implicit_value.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &self->implicit_value));
		self->kind = OPERATION_KIND_IMPLICIT_VALUE;
		break;
	}
	case DW_OP_stack_value:
		self->kind = OPERATION_KIND_STACK_VALUE;
		break;
	case DW_OP_implicit_pointer:
	case DW_OP_GNU_implicit_pointer: {
		if (encoding->version == 2) {
			U_ADDR_SIZE_OR_RET_FALSE(self->implicit_pointer.value);
		} else {
			RET_FALSE_IF_FAIL(buf_read_offset(buffer, &self->implicit_pointer.value, encoding->is_64bit, encoding->big_endian));
		}
		SLE128_OR_RET_FALSE(self->implicit_pointer.byte_offset);
		self->kind = OPERATION_KIND_IMPLICIT_POINTER;
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
		ULE128_OR_RET_FALSE(self->typed_literal.base_type);
		U8_OR_RET_FALSE(self->typed_literal.value.length);
		RET_FALSE_IF_FAIL(buf_read_block(buffer, &self->typed_literal.value));
		self->kind = OPERATION_KIND_TYPED_LITERAL;
		break;
	}
	case DW_OP_regval_type:
	case DW_OP_GNU_regval_type: {
		ULE128_OR_RET_FALSE(self->register_offset.register_number);
		ULE128_OR_RET_FALSE(self->register_offset.base_type);
		self->kind = OPERATION_KIND_REGISTER_OFFSET;
		self->register_offset.offset = 0;
		break;
	}
	case DW_OP_deref_type:
	case DW_OP_GNU_deref_type: {
		U8_OR_RET_FALSE(self->deref.size);
		ULE128_OR_RET_FALSE(self->deref.base_type);
		self->kind = OPERATION_KIND_DEREF;
		self->deref.space = false;
		break;
	}
	case DW_OP_xderef_type: {
		U8_OR_RET_FALSE(self->deref.size);
		ULE128_OR_RET_FALSE(self->deref.base_type);
		self->kind = OPERATION_KIND_DEREF;
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
		U_OR_RET_FALSE(32, self->parameter_ref.offset);
		self->kind = OPERATION_KIND_PARAMETER_REF;
		break;

	case DW_OP_WASM_location: {
		ut8 byte;
		U8_OR_RET_FALSE(byte);
		switch (byte) {
		case 0: {
			ULE128_OR_RET_FALSE(self->wasm_local.index);
			self->kind = OPERATION_KIND_WASM_LOCAL;
			break;
		}
		case 1: {
			ULE128_OR_RET_FALSE(self->wasm_global.index);
			self->kind = OPERATION_KIND_WASM_GLOBAL;
			break;
		}
		case 2: {
			ULE128_OR_RET_FALSE(self->wasm_stack.index);
			self->kind = OPERATION_KIND_WASM_STACK;
			break;
		}
		case 3: {
			U_OR_RET_FALSE(32, self->wasm_global.index);
			self->kind = OPERATION_KIND_WASM_GLOBAL;
			break;
		default:
			RZ_LOG_WARN("Unsupported wasm location index %d\n", byte);
			return false;
		}
		}
		break;
	}
	case DW_OP_hi_user:
		RZ_LOG_WARN("Unsupported opcode %s\n", rz_bin_dwarf_op(self->opcode));
		return false;
	}
	return true;
}

static void Operation_fini(Operation *self) {
	if (!self) {
		return;
	}
	if (self->kind == OPERATION_KIND_IMPLICIT_VALUE) {
		RzBinDwarfBlock_fini(&self->implicit_value);
	} else if (self->kind == OPERATION_KIND_ENTRY_VALUE) {
		RzBinDwarfBlock_fini(&self->entry_value.expression);
	} else if (self->kind == OPERATION_KIND_TYPED_LITERAL) {
		RzBinDwarfBlock_fini(&self->typed_literal.value);
	}
}

static bool Evaluation_pop(RzBinDwarfEvaluation *self, RzBinDwarfValue **value) {
	if (rz_vector_len(&self->stack) <= 0) {
		*value = NULL;
		return false;
	}
	if (value) {
		*value = RZ_NEW0(RzBinDwarfValue);
		rz_vector_pop(&self->stack, *value);
	} else {
		rz_vector_pop(&self->stack, NULL);
	}
	return true;
}

static bool Evaluation_push(RzBinDwarfEvaluation *self, RzBinDwarfValue *value) {
	return rz_vector_push(&self->stack, value) != NULL;
}

static bool compute_pc(RzBuffer *pc, const RzBuffer *bytecode, st16 offset) {
	return rz_buf_seek(pc, offset, RZ_BUF_CUR) >= 0;
}

static RzBinDwarfValueType ValueType_from_name(const char *name, ut8 byte_size) {
	if (strcmp(name, "int") == 0) {
		switch (byte_size) {
		case 1: return RzBinDwarfValueType_I8;
		case 2: return RzBinDwarfValueType_I16;
		case 4: return RzBinDwarfValueType_I32;
		case 8: return RzBinDwarfValueType_I64;
		default: break;
		}
	}
	if (strcmp(name, "unsigned") == 0) {
		switch (byte_size) {
		case 1: return RzBinDwarfValueType_U8;
		case 2: return RzBinDwarfValueType_U16;
		case 4: return RzBinDwarfValueType_U32;
		case 8: return RzBinDwarfValueType_U64;
		default: break;
		}
	}
	if (strcmp(name, "size_t") == 0) {
		switch (byte_size) {
		case 1: return RzBinDwarfValueType_U8;
		case 2: return RzBinDwarfValueType_U16;
		case 4: return RzBinDwarfValueType_U32;
		case 8: return RzBinDwarfValueType_U64;
		default: break;
		}
	}
	if (strcmp(name, "int8_t") == 0) {
		return RzBinDwarfValueType_I8;
	}
	if (strcmp(name, "int16_t") == 0) {
		return RzBinDwarfValueType_I16;
	}
	if (strcmp(name, "int32_t") == 0) {
		return RzBinDwarfValueType_I32;
	}
	if (strcmp(name, "int64_t") == 0) {
		return RzBinDwarfValueType_I64;
	}
	if (strcmp(name, "uint8_t") == 0) {
		return RzBinDwarfValueType_U8;
	}
	if (strcmp(name, "uint16_t") == 0) {
		return RzBinDwarfValueType_U16;
	}
	if (strcmp(name, "uint32_t") == 0) {
		return RzBinDwarfValueType_U32;
	}
	if (strcmp(name, "uint64_t") == 0) {
		return RzBinDwarfValueType_U64;
	}
	return RzBinDwarfValueType_GENERIC;
}

static RzBinDwarfValueType ValueType_from_die(RzBinDwarfEvaluation *eval, const RzBinDwarf *dw, UnitOffset offset) {
	RzBinDwarfDie *die = ht_up_find(dw->info->die_tbl, eval->unit->offset + offset, NULL);
	if (!die) {
		return RzBinDwarfValueType_GENERIC;
	}
	assert(die->tag == DW_TAG_base_type);
	RzBinDwarfAttr *attr;
	RzBinDwarfValueType value_type = RzBinDwarfValueType_GENERIC;
	ut8 byte_size = 0;
	const char *name = NULL;
	enum DW_ATE ate = 0;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->name) {
		case DW_AT_name:
			name = attr->string.content;
			break;
		case DW_AT_byte_size:
			byte_size = attr->uconstant;
			break;
		case DW_AT_encoding:
			ate = attr->uconstant;
			break;
		default: break;
		}
	}
	if (RZ_STR_ISNOTEMPTY(name)) {
		value_type = ValueType_from_name(name, byte_size);
		if (value_type != RzBinDwarfValueType_GENERIC) {
			return value_type;
		}
	}

#define CHECK_TYPED(nbyte, nbit) \
	if (byte_size == (nbyte) && ate == DW_ATE_unsigned) { \
		return RzBinDwarfValueType_U##nbit; \
	} \
	if (byte_size == (nbyte) && ate == DW_ATE_signed) { \
		return RzBinDwarfValueType_I##nbit; \
	}

	CHECK_TYPED(1, 8);
	CHECK_TYPED(2, 16);
	CHECK_TYPED(4, 32);
	CHECK_TYPED(8, 64);
	CHECK_TYPED(16, 128);
	return value_type;
}

static void RzBinDwarfPiece_fini(RzBinDwarfPiece *x) {
	if (!x) {
		return;
	}
	rz_bin_dwarf_location_free(x->location);
}

static inline ut64 addrmask_from_size(uint8_t size) {
	return size == 0 ? 0xffffffffffffffffULL
			 : (size == 8 ? 0xffffffffffffffffULL
				      : (1ULL << (size * 8)) - 1);
}

static void vec_Value_fini(void *v, void *u) {
	Value_fini(v);
}

static void RzBinDwarfExprStackItem_fini(RzBinDwarfExprStackItem *self) {
	if (!self) {
		return;
	}
	rz_buf_free(self->bytecode);
	rz_buf_free(self->pc);
}

static void vec_RzBinDwarfExprStackItem_fini(void *v, void *u) {
	RzBinDwarfExprStackItem_fini(v);
}

RZ_API RZ_OWN RzBinDwarfEvaluation *rz_bin_dwarf_evaluation_new(RZ_OWN RZ_NONNULL RzBuffer *byte_code, RZ_BORROW RZ_NONNULL const RzBinDwarf *dw, RZ_BORROW RZ_NULLABLE const RzBinDwarfCompUnit *unit, RZ_BORROW RZ_NULLABLE const RzBinDwarfDie *die) {
	rz_return_val_if_fail(byte_code && dw, NULL);
	RzBinDwarfEvaluation *self = RZ_NEW0(RzBinDwarfEvaluation);
	RET_NULL_IF_FAIL(self);
	const RzBinDwarfEncoding *encoding = unit ? &unit->hdr.encoding : &dw->encoding;
	ut64 addr_mask = addrmask_from_size(encoding->address_size);
	self->addr_mask = addr_mask;
	self->bytecode = byte_code;
	self->encoding = encoding;
	self->pc = rz_buf_new_with_buf(byte_code);
	self->dw = dw;
	self->unit = unit;
	self->die = die;
	rz_vector_init(&self->stack, sizeof(RzBinDwarfValue), vec_Value_fini, NULL);
	rz_vector_init(&self->expression_stack, sizeof(RzBinDwarfExprStackItem), vec_RzBinDwarfExprStackItem_fini, NULL);
	rz_vector_init(&self->result, sizeof(RzBinDwarfPiece), (RzVectorFree)RzBinDwarfPiece_fini, NULL);
	return self;
}

RZ_API RZ_OWN RzBinDwarfEvaluation *rz_bin_dwarf_evaluation_new_from_block(RZ_BORROW RZ_NONNULL const RzBinDwarfBlock *block, RZ_BORROW RZ_NONNULL const RzBinDwarf *dw, RZ_BORROW RZ_NULLABLE const RzBinDwarfCompUnit *unit, RZ_BORROW RZ_NULLABLE const RzBinDwarfDie *die) {
	rz_return_val_if_fail(block && dw, NULL);
	RzBuffer *expr = RzBinDwarfBlock_as_buf(block);
	RET_NULL_IF_FAIL(expr);
	RzBinDwarfEvaluation *self = rz_bin_dwarf_evaluation_new(expr, dw, unit, die);
	RET_NULL_IF_FAIL(self);
	return self;
}

RZ_API void rz_bin_dwarf_evaluation_free(RZ_OWN RzBinDwarfEvaluation *self) {
	if (!self) {
		return;
	}
	rz_buf_free(self->pc);
	rz_buf_free(self->bytecode);
	rz_vector_fini(&self->stack);
	rz_vector_fini(&self->expression_stack);
	rz_vector_fini(&self->result);
	free(self);
}

RZ_IPI void RzBinDwarfEvaluationResult_fini(RzBinDwarfEvaluationResult *self) {
	if (self->kind == EvaluationResult_REQUIRES_ENTRY_VALUE) {
		RzBinDwarfBlock_fini(&self->requires_entry_value.expression);
	}
}

RZ_API void RzBinDwarfEvaluationResult_free(RZ_OWN RzBinDwarfEvaluationResult *self) {
	if (!self) {
		return;
	}
	RzBinDwarfEvaluationResult_fini(self);
	free(self);
}

static bool Evaluation_evaluate_one_operation(RzBinDwarfEvaluation *self, OperationEvaluationResult *out) {
	Operation operation = { 0 };
	ut64 offset = rz_buf_tell(self->pc);
	ERR_IF_FAIL(Operation_parse(&operation, self->pc, self->encoding));
	/// need to resolve delayed value in stack
#define CHECK_DEFER \
	do { \
		if (rz_vector_len(&self->stack) >= 1) { \
			RzBinDwarfValue *val = rz_vector_tail(&self->stack); \
			if (val->type == RzBinDwarfValueType_LOCATION) { \
				rz_buf_seek(self->pc, offset, RZ_BUF_SET); \
				out->kind = OperationEvaluationResult_WAITING_RESOLVE; \
				goto ok; \
			} \
		} \
	} while (0)
#define CHECK_DEFER2 \
	do { \
		if (rz_vector_len(&self->stack) >= 2) { \
			RzBinDwarfValue *a = rz_vector_tail(&self->stack); \
			RzBinDwarfValue *b = rz_vector_index_ptr(&self->stack, rz_vector_len(&self->stack) - 2); \
			if (a->type == RzBinDwarfValueType_LOCATION || b->type == RzBinDwarfValueType_LOCATION) { \
				rz_buf_seek(self->pc, offset, RZ_BUF_SET); \
				out->kind = OperationEvaluationResult_WAITING_RESOLVE; \
				goto ok; \
			} \
		} \
	} while (0)

	switch (operation.kind) {
	case OPERATION_KIND_DEREF: {
		CHECK_DEFER;
		RzBinDwarfValue *entry = NULL;
		ERR_IF_FAIL(Evaluation_pop(self, &entry));
		ut64 addr = 0;
		ERR_IF_FAIL(Value_to_u64(entry, self->addr_mask, &addr));
		ut64 addr_space = 0;
		bool has_addr_space = false;
		if (operation.deref.space) {
			RzBinDwarfValue *space = NULL;
			ERR_IF_FAIL(Evaluation_pop(self, &space));
			ERR_IF_FAIL(space);
			ERR_IF_FAIL(Value_to_u64(space, self->addr_mask, &addr_space));
			has_addr_space = true;
		}
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_MEMORY;
		out->waiting._2.requires_memory.address = addr;
		out->waiting._2.requires_memory.size = operation.deref.size;
		out->waiting._2.requires_memory.has_space = has_addr_space;
		out->waiting._2.requires_memory.space = addr_space;
		out->waiting._2.requires_memory.base_type = operation.deref.base_type;
		return true;
	}
	case OPERATION_KIND_DROP:
		ERR_IF_FAIL(Evaluation_pop(self, NULL));
		break;
	case OPERATION_KIND_PICK: {
		ut64 len = rz_vector_len(&self->stack);
		if (operation.pick.index >= len) {
			RZ_LOG_WARN("Pick index %d out of range\n", operation.pick.index);
			break;
		}
		RzBinDwarfValue *value = rz_vector_index_ptr(&self->stack, len - operation.pick.index - 1);
		ERR_IF_FAIL(value);
		RzBinDwarfValue *clone = Value_clone(value);
		if (!Evaluation_push(self, clone)) {
			Value_free(clone);
		}
		free(clone);
		break;
	}
	case OPERATION_KIND_SWAP: {
		RzBinDwarfValue *top = NULL;
		RzBinDwarfValue *second = NULL;
		ERR_IF_FAIL(Evaluation_pop(self, &top));
		ERR_IF_FAIL(Evaluation_pop(self, &second));
		ERR_IF_FAIL(Evaluation_push(self, top));
		ERR_IF_FAIL(Evaluation_push(self, second));
		break;
	}
	case OPERATION_KIND_ROT: {
		RzBinDwarfValue *top = NULL;
		RzBinDwarfValue *second = NULL;
		RzBinDwarfValue *third = NULL;
		ERR_IF_FAIL(Evaluation_pop(self, &top));
		ERR_IF_FAIL(Evaluation_pop(self, &second));
		ERR_IF_FAIL(Evaluation_pop(self, &third));
		ERR_IF_FAIL(Evaluation_push(self, top));
		ERR_IF_FAIL(Evaluation_push(self, second));
		ERR_IF_FAIL(Evaluation_push(self, third));
		break;
	}
#define BINARY_OP(fcn) \
	{ \
		CHECK_DEFER2; \
		RzBinDwarfValue *rhs = NULL; \
		RzBinDwarfValue *lhs = NULL; \
		ERR_IF_FAIL(Evaluation_pop(self, &rhs)); \
		ERR_IF_FAIL(Evaluation_pop(self, &lhs)); \
		RzBinDwarfValue result = { 0 }; \
		fcn(lhs, rhs, self->addr_mask, &result); \
		Value_free(lhs); \
		Value_free(rhs); \
		ERR_IF_FAIL(Evaluation_push(self, &result)); \
		break; \
	}
#define UNITARY_OP(fcn) \
	{ \
		CHECK_DEFER; \
		RzBinDwarfValue *top = NULL; \
		ERR_IF_FAIL(Evaluation_pop(self, &top)); \
		RzBinDwarfValue result = { 0 }; \
		ERR_IF_FAIL(fcn(top, self->addr_mask, &result)); \
		Value_free(top); \
		ERR_IF_FAIL(Evaluation_push(self, &result)); \
		break; \
	}

	case OPERATION_KIND_ABS: UNITARY_OP(Value_abs);
	case OPERATION_KIND_AND: BINARY_OP(Value_and);
	case OPERATION_KIND_DIV: BINARY_OP(Value_div);
	case OPERATION_KIND_MINUS: BINARY_OP(Value_sub);
	case OPERATION_KIND_MOD: BINARY_OP(Value_rem);
	case OPERATION_KIND_MUL: BINARY_OP(Value_mul);
	case OPERATION_KIND_NEG: UNITARY_OP(Value_neg);
	case OPERATION_KIND_NOT: UNITARY_OP(Value_not);
	case OPERATION_KIND_OR: BINARY_OP(Value_or);
	case OPERATION_KIND_PLUS: BINARY_OP(Value_add);
	case OPERATION_KIND_PLUS_CONSTANT: {
		CHECK_DEFER;
		RzBinDwarfValue *lhs = NULL;
		ERR_IF_FAIL(Evaluation_pop(self, &lhs));
		RzBinDwarfValue rhs = { 0 };
		ERR_IF_FAIL(Value_from_u64(lhs->type, operation.plus_constant.value, &rhs));
		ERR_IF_FAIL(Value_add(lhs, &rhs, self->addr_mask, lhs));
		ERR_IF_FAIL(Evaluation_push(self, lhs));
		break;
	}
	case OPERATION_KIND_SHL: BINARY_OP(Value_shl);
	case OPERATION_KIND_SHR: BINARY_OP(Value_shr);
	case OPERATION_KIND_SHRA: BINARY_OP(Value_shra);
	case OPERATION_KIND_XOR: BINARY_OP(Value_xor);
	case OPERATION_KIND_BRA: {
		CHECK_DEFER;
		RzBinDwarfValue *v = NULL;
		ERR_IF_FAIL(Evaluation_pop(self, &v));
		ut64 entry = 0;
		ERR_IF_FAIL(Value_to_u64(v, self->addr_mask, &entry));
		if (entry != 0) {
			RET_FALSE_IF_FAIL(compute_pc(self->pc, self->bytecode, operation.bra.target));
		}
		break;
	}
	case OPERATION_KIND_EQ: BINARY_OP(Value_eq);
	case OPERATION_KIND_GE: BINARY_OP(Value_ge);
	case OPERATION_KIND_GT: BINARY_OP(Value_gt);
	case OPERATION_KIND_LE: BINARY_OP(Value_le);
	case OPERATION_KIND_LT: BINARY_OP(Value_lt);
	case OPERATION_KIND_NE: BINARY_OP(Value_ne);
	case OPERATION_KIND_SKIP: {
		ERR_IF_FAIL(compute_pc(self->pc, self->bytecode, operation.skip.target));
		break;
	}
	case OPERATION_KIND_UNSIGNED_CONSTANT: {
		RzBinDwarfValue v = { .type = RzBinDwarfValueType_GENERIC, .generic = operation.unsigned_constant.value };
		ERR_IF_FAIL(Evaluation_push(self, &v));
		break;
	}
	case OPERATION_KIND_SIGNED_CONSTANT: {
		RzBinDwarfValue v = { .type = RzBinDwarfValueType_GENERIC, .generic = (ut64)operation.signed_constant.value };
		ERR_IF_FAIL(Evaluation_push(self, &v));
		break;
	}
	case OPERATION_KIND_REGISTER: {
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete.kind = RzBinDwarfLocationKind_REGISTER;
		out->complete.register_number = operation.reg.register_number;
		return true;
	}
	case OPERATION_KIND_REGISTER_OFFSET: {
		RzBinDwarfValue value = {
			.type = RzBinDwarfValueType_LOCATION,
			.location = RZ_NEW0(RzBinDwarfLocation),
		};
		ERR_IF_FAIL(value.location);
		value.location->kind = RzBinDwarfLocationKind_REGISTER_OFFSET;
		value.location->register_number = operation.register_offset.register_number;
		value.location->offset = operation.register_offset.offset;
		// TODO: Location base_type
		// value.location->base_type = operation.register_offset.base_type;
		if (!Evaluation_push(self, &value)) {
			rz_bin_dwarf_location_free(value.location);
			goto err;
		}
		break;
	}
	case OPERATION_KIND_FRAME_OFFSET: {
		RzBinDwarfAttr *fb_attr = rz_bin_dwarf_die_get_attr(self->die, DW_AT_frame_base);
		ERR_IF_FAIL(fb_attr);
		if (fb_attr->kind == DW_AT_KIND_UCONSTANT) {
			RzBinDwarfValue v = {
				.type = RzBinDwarfValueType_LOCATION,
				.location = NULL,
			};
			v.location = RZ_NEW0(RzBinDwarfLocation);
			ERR_IF_FAIL(v.location);
			v.location->kind = RzBinDwarfLocationKind_FB_OFFSET;
			v.location->offset = (st64)fb_attr->uconstant;
			if (!Evaluation_push(self, &v)) {
				rz_bin_dwarf_location_free(v.location);
				goto err;
			}
			break;
		}
		RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(&fb_attr->block, self->dw, self->unit, self->die);
		if (!loc) {
			char *expr_str = rz_bin_dwarf_expression_to_string(&self->dw->encoding, &fb_attr->block);
			RZ_LOG_ERROR("Failed eval frame base: [%s]\n", rz_str_get_null(expr_str));
			free(expr_str);
			goto err;
		}
		if (loc->kind == RzBinDwarfLocationKind_CFA_OFFSET) {
			loc->offset += operation.frame_offset.offset;
			RzBinDwarfValue v = {
				.type = RzBinDwarfValueType_LOCATION,
				.location = loc,
			};
			ERR_IF_FAIL(Evaluation_push(self, &v));
		} else if (loc->kind == RzBinDwarfLocationKind_REGISTER || loc->kind == RzBinDwarfLocationKind_REGISTER_OFFSET) {
			loc->kind = RzBinDwarfLocationKind_REGISTER_OFFSET;
			loc->offset += operation.frame_offset.offset;
			RzBinDwarfValue v = {
				.type = RzBinDwarfValueType_LOCATION,
				.location = loc,
			};
			ERR_IF_FAIL(Evaluation_push(self, &v));
		} else {
			RZ_LOG_ERROR("Unsupported frame base location kind: %d\n", loc->kind);
			goto err;
		}
		break;
	}
	case OPERATION_KIND_NOP: break;
	case OPERATION_KIND_PUSH_OBJECT_ADDRESS: {
		if (self->object_address) {
			RzBinDwarfValue v = {
				.type = RzBinDwarfValueType_GENERIC,
				.generic = *self->object_address,
			};
			ERR_IF_FAIL(Evaluation_push(self, &v));
		} else {
			RZ_LOG_ERROR("object address not set");
			goto err;
		}
		break;
	}
	case OPERATION_KIND_CALL_FRAME_CFA: {
		RzBinDwarfLocation loc = {
			.kind = RzBinDwarfLocationKind_CFA_OFFSET,
			.offset = 0,
		};
		RzBinDwarfValue v = {
			.type = RzBinDwarfValueType_LOCATION,
			.location = RZ_NEW0(RzBinDwarfLocation),
		};
		ERR_IF_FAIL(v.location);
		memcpy(v.location, &loc, sizeof(RzBinDwarfLocation));
		Evaluation_push(self, &v);
		break;
	}
	case OPERATION_KIND_PIECE: {
		RzBinDwarfLocation *location = NULL;
		if (rz_vector_empty(&self->stack)) {
			location = RZ_NEW0(RzBinDwarfLocation);
			ERR_IF_FAIL(location);
			location->kind = RzBinDwarfLocationKind_EMPTY;
		} else {
			RzBinDwarfValue *v = NULL;
			ERR_IF_FAIL(Evaluation_pop(self, &v));
			if (v->type == RzBinDwarfValueType_LOCATION) {
				location = v->location;
				v->location = NULL;
			} else {
				location = RZ_NEW0(RzBinDwarfLocation);
				ERR_IF_FAIL(location);
				if (!Value_to_u64(v, self->addr_mask, &location->address)) {
					rz_bin_dwarf_location_free(location);
					goto err;
				}
				location->kind = RzBinDwarfLocationKind_ADDRESS;
			}
			Value_free(v);
		}
		ERR_IF_FAIL(location);
		RzBinDwarfPiece piece = {
			.location = location,
			.has_bit_offset = operation.piece.has_bit_offset,
			.bit_offset = operation.piece.bit_offset,
			.has_size_in_bits = true,
			.size_in_bits = operation.piece.size_in_bits,
		};
		ERR_IF_FAIL(rz_vector_push(&self->result, &piece));
		out->kind = OperationEvaluationResult_PIECE;
		goto ok;
	}
	case OPERATION_KIND_IMPLICIT_VALUE: {
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete.kind = RzBinDwarfLocationKind_BYTES;
		ERR_IF_FAIL(RzBinDwarfBlock_move(&operation.implicit_value, &out->complete.bytes));
		goto ok;
	}
	case OPERATION_KIND_STACK_VALUE: {
		RzBinDwarfValue *v = NULL;
		ERR_IF_FAIL(Evaluation_pop(self, &v));
		out->kind = OperationEvaluationResult_COMPLETE;
		if (v->type == RzBinDwarfValueType_LOCATION) {
			memcpy(&out->complete, v->location, sizeof(RzBinDwarfLocation));
			v->location = NULL;
		} else {
			out->complete.kind = RzBinDwarfLocationKind_VALUE;
			out->complete.value = *v;
		}
		Value_free(v);
		goto ok;
	}
	case OPERATION_KIND_IMPLICIT_POINTER: {
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete.kind = RzBinDwarfLocationKind_IMPLICIT_POINTER;
		out->complete.implicit_pointer = operation.implicit_pointer.value;
		out->complete.offset = operation.implicit_pointer.byte_offset;
		goto ok;
	}
	case OPERATION_KIND_ENTRY_VALUE: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_ENTRY_VALUE;
		ERR_IF_FAIL(RzBinDwarfBlock_move(&operation.entry_value.expression,
			&out->waiting._2.requires_entry_value.expression));
		goto ok;
	}
	case OPERATION_KIND_ADDRESS: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_RelocatedAddress;
		out->waiting._2.requires_relocated_address = operation.address.address;
		goto ok;
	}
	case OPERATION_KIND_ADDRESS_INDEX: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_IndexedAddress;
		out->waiting._2.requires_indexed_address.index = operation.address_index.index;
		out->waiting._2.requires_indexed_address.relocate = true;
		goto ok;
	}
	case OPERATION_KIND_CONSTANT_INDEX: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_IndexedAddress;
		out->waiting._2.requires_indexed_address.index = operation.constant_index.index;
		out->waiting._2.requires_indexed_address.relocate = false;
		goto ok;
	}

	case OPERATION_KIND_TYPED_LITERAL: {
		RzBinDwarfValueType typ = ValueType_from_die(self, self->dw, operation.typed_literal.base_type);
		RzBuffer *buf = RzBinDwarfBlock_as_buf(&operation.typed_literal.value);
		ERR_IF_FAIL(buf);
		RzBinDwarfValue *val = Value_parse(typ, buf, self->encoding->big_endian);
		rz_buf_free(buf);
		ERR_IF_FAIL(val);
		if (Evaluation_push(self, val)) {
			Value_free(val);
			goto err;
		}
		Value_free(val);
		break;
	}
	case OPERATION_KIND_CONVERT: {
		CHECK_DEFER;
		RzBinDwarfValue *val = NULL;
		ERR_IF_FAIL(Evaluation_pop(self, &val));
		RzBinDwarfValueType typ = ValueType_from_die(self, self->dw, operation.convert.base_type);
		ERR_IF_FAIL(Value_convert(val, typ, self->addr_mask, val));
		ERR_IF_FAIL(Evaluation_push(self, val));
		break;
	}
	case OPERATION_KIND_REINTERPRET: {
		CHECK_DEFER;
		RzBinDwarfValue *val = NULL;
		ERR_IF_FAIL(Evaluation_pop(self, &val));
		RzBinDwarfValueType typ = ValueType_from_die(self, self->dw, operation.reinterpret.base_type);
		ERR_IF_FAIL(Value_reinterpret(val, typ, self->addr_mask, val));
		ERR_IF_FAIL(Evaluation_push(self, val));
		break;
	}
	case OPERATION_KIND_TLS: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_TLS;
		goto ok;
	}
	case OPERATION_KIND_CALL:
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_AtLocation;
		out->waiting._2.requires_at_location.offset = operation.call.offset;
		goto ok;
	case OPERATION_KIND_PARAMETER_REF:
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_ParameterRef;
		out->waiting._2.requires_parameter_ref.offset = operation.call.offset;
		goto ok;

	case OPERATION_KIND_WASM_LOCAL:
	case OPERATION_KIND_WASM_GLOBAL:
	case OPERATION_KIND_WASM_STACK: {
		RZ_LOG_ERROR("DWARF %s operation not supported\n", rz_bin_dwarf_op(operation.opcode));
		goto err;
	}
	}
	out->kind = EvaluationResult_INCOMPLETE;
ok:
	Operation_fini(&operation);
	return true;
err:
	Operation_fini(&operation);
	return false;
}

static bool Evaluation_end_of_expression(RzBinDwarfEvaluation *self) {
	if (rz_buf_tell(self->pc) >= rz_buf_size(self->pc)) {
		if (rz_vector_empty(&self->expression_stack)) {
			return true;
		}
		RzBinDwarfExprStackItem *item = NULL;
		rz_vector_pop(&self->expression_stack, item);
		RET_FALSE_IF_FAIL(item);
		self->pc = item->pc;
		self->bytecode = item->bytecode;
	}
	return false;
}

RZ_API bool rz_bin_dwarf_evaluation_evaluate(RZ_BORROW RZ_NONNULL RzBinDwarfEvaluation *self, RZ_BORROW RZ_NONNULL RzBinDwarfEvaluationResult *out) {
	rz_return_val_if_fail(self && out, false);
	if (self->state.kind == EVALUATION_STATE_START) {
		if (self->state.start) {
			Evaluation_push(self, self->state.start);
		}
		self->state.kind = EVALUATION_STATE_READY;
	} else if (self->state.kind == EVALUATION_STATE_ERROR) {
		return false;
	} else if (self->state.kind == EVALUATION_STATE_COMPLETE) {
		return true;
	}
	while (!Evaluation_end_of_expression(self)) {
		self->iteration += 1;
		if (self->max_iterations != UT32_MAX && self->max_iterations) {
			if (self->iteration > self->max_iterations) {
				self->state.kind = EVALUATION_STATE_ERROR;
				goto err;
			}
		}
		OperationEvaluationResult op_result = { 0 };
		ERR_IF_FAIL(Evaluation_evaluate_one_operation(self, &op_result));

		switch (op_result.kind) {
		case OperationEvaluationResult_PIECE:
			break;
		case OperationEvaluationResult_INCOMPLETE:
			if (Evaluation_end_of_expression(self) && !rz_vector_empty(&self->result)) {
				self->state.kind = EVALUATION_STATE_ERROR;
				goto err;
			}
			break;
		case OperationEvaluationResult_WAITING: {
			self->state.kind = EVALUATION_STATE_WAITING;
			self->state.waiting = op_result.waiting._1;
			memcpy(out, &op_result.waiting._2, sizeof(RzBinDwarfEvaluationResult));
			memset(&op_result.waiting._2, 0, sizeof(RzBinDwarfEvaluationResult));
			return true;
		}
		case OperationEvaluationResult_WAITING_RESOLVE: {
			self->state.kind = EVALUATION_STATE_WAITING_RESOLVE;
			out->kind = EvaluationResult_REQUIRES_RESOLVE;
			return true;
		}
		case OperationEvaluationResult_COMPLETE: {
			if (Evaluation_end_of_expression(self)) {
				if (!rz_vector_empty(&self->result)) {
					self->state.kind = EVALUATION_STATE_ERROR;
					goto err;
				}
				RzBinDwarfPiece piece = {
					.location = NULL,
					.has_size_in_bits = false,
					.has_bit_offset = false,
				};
				piece.location = RZ_NEW0(RzBinDwarfLocation);
				ERR_IF_FAIL(piece.location);
				ERR_IF_FAIL(RzBinDwarfLocation_move(&op_result.complete, piece.location));
				ERR_IF_FAIL(rz_vector_push(&self->result, &piece));
			} else {
				Operation operation = { 0 };
				RET_FALSE_IF_FAIL(Operation_parse(&operation, self->pc, self->encoding));
				if (operation.kind != OPERATION_KIND_PIECE) {
					self->state.kind = EVALUATION_STATE_ERROR;
					goto err;
				}
				RzBinDwarfPiece piece = {
					.location = NULL,
					.has_size_in_bits = true,
					.size_in_bits = operation.piece.size_in_bits,
					.has_bit_offset = operation.piece.has_bit_offset,
					.bit_offset = operation.piece.bit_offset,
				};
				piece.location = RZ_NEW0(RzBinDwarfLocation);
				ERR_IF_FAIL(piece.location);
				ERR_IF_FAIL(RzBinDwarfLocation_move(&op_result.complete, piece.location));
				ERR_IF_FAIL(rz_vector_push(&self->result, &piece));
			}
			break;
		}
		};
		continue;
	err:
		OperationEvaluationResult_fini(&op_result);
		return false;
	}

	if (rz_vector_empty(&self->result)) {
		RzBinDwarfValue *entry = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &entry));
		RzBinDwarfLocation *location = NULL;
		switch (entry->type) {
		case RzBinDwarfValueType_LOCATION:
			location = entry->location;
			entry->location = NULL;
			Value_free(entry);
			break;
		default: {
			ut64 addr;
			if (!Value_to_u64(entry, self->addr_mask, &addr)) {
				Value_free(entry);
				return false;
			}
			Value_free(entry);
			location = RZ_NEW0(RzBinDwarfLocation);
			RET_FALSE_IF_FAIL(location);
			location->kind = RzBinDwarfLocationKind_ADDRESS;
			location->address = addr;
			break;
		}
		}
		RET_FALSE_IF_FAIL(location);
		RzBinDwarfPiece piece = {
			.has_size_in_bits = false,
			.has_bit_offset = false,
			.location = location,
		};
		RET_FALSE_IF_FAIL(rz_vector_push(&self->result, &piece));
	}

	self->state.kind = EVALUATION_STATE_COMPLETE;
	out->kind = EvaluationResult_COMPLETE;
	return true;
}

RZ_API RZ_BORROW RzVector /*<RzBinDwarfPiece>*/ *rz_bin_dwarf_evaluation_result(RZ_BORROW RZ_NONNULL RzBinDwarfEvaluation *self) {
	if (self->state.kind == EVALUATION_STATE_COMPLETE) {
		return &self->result;
	}
	RZ_LOG_ERROR("Called `Evaluation::result` on an `Evaluation` that has not been completed");
	return NULL;
}

static RzBinDwarfLocation *RzBinDwarfEvaluationResult_to_loc(RzBinDwarfEvaluation *eval, RzBinDwarfEvaluationResult *result) {
	RzBinDwarfLocation *loc = NULL;
	if (eval->state.kind == EVALUATION_STATE_COMPLETE && result->kind == EvaluationResult_COMPLETE) {
		RzVector *pieces = rz_bin_dwarf_evaluation_result(eval);
		if (!pieces || rz_vector_empty(pieces)) {
			return NULL; // TODO: or empty location?
		}
		if (rz_vector_len(pieces) == 1) {
			RzBinDwarfPiece *piece = rz_vector_index_ptr(pieces, 0);
			loc = piece->location;
			piece->location = NULL;
		} else {
			loc = RZ_NEW0(RzBinDwarfLocation);
			loc->kind = RzBinDwarfLocationKind_COMPOSITE;
			loc->composite = rz_vector_clone(pieces);
			RzBinDwarfPiece *piece = NULL;
			rz_vector_foreach(pieces, piece) {
				piece->location = NULL;
			}
		}
		rz_bin_dwarf_evaluation_free(eval);
		RzBinDwarfEvaluationResult_free(result);
		return loc;
	}

	loc = RZ_NEW0(RzBinDwarfLocation);
	if (!loc) {
		rz_bin_dwarf_evaluation_free(eval);
		RzBinDwarfEvaluationResult_free(result);
		return NULL;
	}
	loc->kind = RzBinDwarfLocationKind_EVALUATION_WAITING;
	loc->eval_waiting.eval = eval;
	loc->eval_waiting.result = result;
	return loc;
}

/**
 * \brief Evaluates a DWARF expression in the context of a DIE
 * \param block The block containing the expression
 * \param dw RzBinDwarf instance
 * \param unit RzBinDwarfCompUnit instance
 * \param die RzBinDwarfDie instance
 * \return RzBinDwarfLocation instance or NULL on error
 */
RZ_API RZ_OWN RzBinDwarfLocation *rz_bin_dwarf_location_from_block(
	RZ_BORROW RZ_NULLABLE const RzBinDwarfBlock *block,
	RZ_BORROW RZ_NULLABLE const RzBinDwarf *dw,
	RZ_BORROW RZ_NULLABLE const RzBinDwarfCompUnit *unit,
	RZ_BORROW RZ_NULLABLE const RzBinDwarfDie *die) {
	rz_return_val_if_fail(block && dw, NULL);
	RzBinDwarfEvaluationResult *result = RZ_NEW0(RzBinDwarfEvaluationResult);
	RET_NULL_IF_FAIL(result);
	RzBinDwarfEvaluation *eval = rz_bin_dwarf_evaluation_new_from_block(block, dw, unit, die);
	ERR_IF_FAIL(eval);
	ERR_IF_FAIL(rz_bin_dwarf_evaluation_evaluate(eval, result));

	return RzBinDwarfEvaluationResult_to_loc(eval, result);
err:
	rz_bin_dwarf_evaluation_free(eval);
	RzBinDwarfEvaluationResult_free(result);
	return NULL;
}

static void Operation_dump(Operation *op, RzStrBuf *buf) {
	rz_strbuf_append(buf, rz_str_get_null(rz_bin_dwarf_op(op->opcode)));
	switch (op->kind) {
	case OPERATION_KIND_DROP:
	case OPERATION_KIND_SWAP:
	case OPERATION_KIND_ROT:
	case OPERATION_KIND_ABS:
	case OPERATION_KIND_AND:
	case OPERATION_KIND_DIV:
	case OPERATION_KIND_MINUS:
	case OPERATION_KIND_MOD:
	case OPERATION_KIND_MUL:
	case OPERATION_KIND_NEG:
	case OPERATION_KIND_NOT:
	case OPERATION_KIND_OR:
	case OPERATION_KIND_PLUS:
	case OPERATION_KIND_SHL:
	case OPERATION_KIND_SHR:
	case OPERATION_KIND_SHRA:
	case OPERATION_KIND_XOR:
	case OPERATION_KIND_EQ:
	case OPERATION_KIND_GE:
	case OPERATION_KIND_GT:
	case OPERATION_KIND_LE:
	case OPERATION_KIND_LT:
	case OPERATION_KIND_NE:
	case OPERATION_KIND_TLS:
	case OPERATION_KIND_CALL_FRAME_CFA:
	case OPERATION_KIND_NOP:
	case OPERATION_KIND_PUSH_OBJECT_ADDRESS:
	case OPERATION_KIND_STACK_VALUE: break;
	case OPERATION_KIND_DEREF:
		rz_strbuf_appendf(buf, " base_type: 0x%" PFMT64x ", size: %d, space: %d", op->deref.base_type, op->deref.size, op->deref.space);
		break;
	case OPERATION_KIND_PICK:
		rz_strbuf_appendf(buf, " 0x%x", op->pick.index);
		break;
	case OPERATION_KIND_PLUS_CONSTANT:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->plus_constant.value);
		break;
	case OPERATION_KIND_BRA:
		rz_strbuf_appendf(buf, " %d", op->bra.target);
		break;
	case OPERATION_KIND_SKIP:
		rz_strbuf_appendf(buf, " %d", op->skip.target);
		break;
	case OPERATION_KIND_UNSIGNED_CONSTANT:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->unsigned_constant.value);
		break;
	case OPERATION_KIND_SIGNED_CONSTANT:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->signed_constant.value);
		break;
	case OPERATION_KIND_REGISTER:
		rz_strbuf_appendf(buf, " %u", op->reg.register_number);
		break;
	case OPERATION_KIND_REGISTER_OFFSET:
		rz_strbuf_appendf(buf, " %u %" PFMT64d " 0x%" PFMT64x,
			op->register_offset.register_number,
			op->register_offset.offset,
			op->register_offset.base_type);
		break;
	case OPERATION_KIND_FRAME_OFFSET:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->frame_offset.offset);
		break;
	case OPERATION_KIND_CALL:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->call.offset);
		break;
	case OPERATION_KIND_PIECE:
		rz_strbuf_appendf(buf, " %" PFMT64u, op->piece.size_in_bits);
		if (op->piece.has_bit_offset) {
			rz_strbuf_appendf(buf, " %" PFMT64u, op->piece.bit_offset);
		}
		break;
	case OPERATION_KIND_IMPLICIT_VALUE:
		rz_bin_dwarf_block_dump(&op->implicit_value, buf);
		break;
	case OPERATION_KIND_IMPLICIT_POINTER:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x " %" PFMT64d, op->implicit_pointer.value, op->implicit_pointer.byte_offset);
		break;
	case OPERATION_KIND_ENTRY_VALUE:
		rz_bin_dwarf_block_dump(&op->entry_value.expression, buf);
		break;
	case OPERATION_KIND_PARAMETER_REF:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->parameter_ref.offset);
		break;
	case OPERATION_KIND_ADDRESS:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->address.address);
		break;
	case OPERATION_KIND_ADDRESS_INDEX:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->address_index.index);
		break;
	case OPERATION_KIND_CONSTANT_INDEX:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->constant_index.index);
		break;
	case OPERATION_KIND_TYPED_LITERAL:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->typed_literal.base_type);
		rz_bin_dwarf_block_dump(&op->typed_literal.value, buf);
		break;
	case OPERATION_KIND_CONVERT:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->convert.base_type);
		break;
	case OPERATION_KIND_REINTERPRET:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->reinterpret.base_type);
		break;
	case OPERATION_KIND_WASM_LOCAL:
		rz_strbuf_appendf(buf, " 0x%" PFMT32x, op->wasm_local.index);
		break;
	case OPERATION_KIND_WASM_GLOBAL:
		rz_strbuf_appendf(buf, " 0x%" PFMT32x, op->wasm_global.index);
		break;
	case OPERATION_KIND_WASM_STACK:
		rz_strbuf_appendf(buf, " 0x%" PFMT32x, op->wasm_stack.index);
		break;
	}
}

static void vec_Operation_free(void *e, void *u) {
	Operation_fini(e);
}

static RzVector /*<Operation>*/ *rz_bin_dwarf_expression_parse(RzBuffer *expr, const RzBinDwarfEncoding *encoding) {
	RzVector *exprs = rz_vector_new(sizeof(Operation), vec_Operation_free, NULL);
	Operation op = { 0 };
	while (Operation_parse(&op, expr, encoding)) {
		rz_vector_push(exprs, &op);
	}
	return exprs;
}

RZ_API void
rz_bin_dwarf_expression_dump(
	RZ_BORROW RZ_NONNULL const RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NONNULL const RzBinDwarfBlock *block,
	RZ_BORROW RZ_NONNULL RzStrBuf *str_buf,
	RZ_BORROW RZ_NULLABLE const char *sep,
	RZ_BORROW RZ_NULLABLE const char *indent) {
	RzBuffer *buffer = RzBinDwarfBlock_as_buf(block);
	RzVector *exprs = rz_bin_dwarf_expression_parse(buffer, encoding);
	rz_buf_free(buffer);

	Operation *op = NULL;
	ut32 i;
	ut32 end = rz_vector_len(exprs) - 1;
	rz_vector_enumerate(exprs, op, i) {
		rz_strbuf_append(str_buf, indent);
		Operation_dump(op, str_buf);
		if (i < end) {
			rz_strbuf_append(str_buf, sep);
		}
	}
	rz_vector_free(exprs);
}

RZ_API char *rz_bin_dwarf_expression_to_string(
	RZ_BORROW RZ_NONNULL const RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NONNULL const RzBinDwarfBlock *block) {
	RzStrBuf sb = { 0 };
	rz_strbuf_init(&sb);
	rz_bin_dwarf_expression_dump(encoding, block, &sb, ",\t", "");
	return rz_strbuf_drain_nofree(&sb);
}

RZ_API void rz_bin_dwarf_loclist_dump(
	RZ_BORROW RZ_NONNULL const RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NONNULL const DWARF_RegisterMapping dwarf_register_mapping,
	RZ_BORROW RZ_NONNULL const RzBinDwarfLocList *loclist,
	RZ_BORROW RZ_NONNULL RzStrBuf *sb,
	RZ_BORROW RZ_NULLABLE const char *sep,
	RZ_BORROW RZ_NULLABLE const char *indent) {
	rz_return_if_fail(encoding && dwarf_register_mapping && loclist && sb);
	if (rz_pvector_empty(&loclist->entries)) {
		rz_strbuf_append(sb, "loclist: [ ]");
		return;
	}

	rz_strbuf_append(sb, "loclist: [\n");

	ut32 i = 0;
	ut32 end = rz_pvector_len(&loclist->entries) - 1;
	void **it = NULL;
	rz_pvector_foreach (&loclist->entries, it) {
		RzBinDwarfLocationListEntry *entry = *it;
		rz_strbuf_appendf(sb, "%s(0x%" PFMT64x ", 0x%" PFMT64x ")", rz_str_get(indent), entry->range->begin, entry->range->end);

		if (encoding) {
			rz_strbuf_append(sb, " [");
			rz_bin_dwarf_expression_dump(encoding, entry->expression, sb, ", ", "");
			rz_strbuf_append(sb, "]");
		} else {
			rz_bin_dwarf_block_dump(entry->expression, sb);
		}

		if (entry->location) {
			rz_strbuf_append(sb, " ");
			rz_bin_dwarf_location_dump(encoding, dwarf_register_mapping, entry->location, sb, sep, "");
		} else if (entry->expression->length > 0) {
			rz_strbuf_append(sb, " <decoding error>");
		}

		if (i++ < end) {
			rz_strbuf_append(sb, rz_str_get(sep));
		}
	}
	rz_strbuf_appendf(sb, "\n%s]", rz_str_get(indent));
}

RZ_API void rz_bin_dwarf_location_composite_dump(
	RZ_BORROW RZ_NONNULL const RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NONNULL const DWARF_RegisterMapping dwarf_register_mapping,
	RZ_BORROW RZ_NONNULL RzVector /*<RzBinDwarfPiece>*/ *composite,
	RZ_BORROW RZ_NONNULL RzStrBuf *sb,
	RZ_BORROW RZ_NULLABLE const char *sep,
	RZ_BORROW RZ_NULLABLE const char *indent) {
	rz_return_if_fail(encoding && dwarf_register_mapping && composite && sb);
	rz_strbuf_append(sb, "composite: [");
	ut32 i;
	ut32 end = rz_vector_len(composite) - 1;
	RzBinDwarfPiece *piece = NULL;
	rz_vector_enumerate(composite, piece, i) {
		rz_strbuf_append(sb, rz_str_get(indent));
		rz_strbuf_appendf(sb, "(.%" PFMT64u ", %" PFMT64u "): ", piece->bit_offset, piece->size_in_bits);

		rz_bin_dwarf_location_dump(encoding, dwarf_register_mapping, piece->location, sb, sep, "");
		if (i < end) {
			rz_strbuf_append(sb, rz_str_get(sep));
		}
	}
	rz_strbuf_appendf(sb, "%s]", rz_str_get(indent));
}

RZ_API void rz_bin_dwarf_location_dump(
	RZ_BORROW RZ_NONNULL const RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NONNULL const DWARF_RegisterMapping dwarf_register_mapping,
	RZ_BORROW RZ_NONNULL const RzBinDwarfLocation *loc,
	RZ_BORROW RZ_NONNULL RzStrBuf *sb,
	RZ_BORROW RZ_NULLABLE const char *sep,
	RZ_BORROW RZ_NULLABLE const char *indent) {
	rz_return_if_fail(loc && sb && encoding && dwarf_register_mapping);
	rz_strbuf_append(sb, rz_str_get(indent));
	switch (loc->kind) {
	case RzBinDwarfLocationKind_EMPTY:
		rz_strbuf_append(sb, "empty");
		break;
	case RzBinDwarfLocationKind_DECODE_ERROR:
		rz_strbuf_append(sb, "<decoding error>");
		break;
	case RzBinDwarfLocationKind_REGISTER:
		rz_strbuf_append(sb, dwarf_register_mapping(loc->register_number));
		break;
	case RzBinDwarfLocationKind_REGISTER_OFFSET:
		rz_strbuf_appendf(sb, "%s%+" PFMT64d, dwarf_register_mapping(loc->register_number), loc->offset);
		break;
	case RzBinDwarfLocationKind_ADDRESS:
		rz_strbuf_appendf(sb, "address 0x%" PFMT64x, loc->address);
		break;
	case RzBinDwarfLocationKind_VALUE:
		Value_dump(encoding, dwarf_register_mapping, &loc->value, sb, sep, indent);
		break;
	case RzBinDwarfLocationKind_BYTES:
		rz_bin_dwarf_block_dump(&loc->bytes, sb);
		break;
	case RzBinDwarfLocationKind_IMPLICIT_POINTER:
		rz_strbuf_appendf(sb, "implicit_pointer 0x%" PFMT64x, loc->implicit_pointer);
		break;
	case RzBinDwarfLocationKind_COMPOSITE:
		rz_bin_dwarf_location_composite_dump(encoding, dwarf_register_mapping, loc->composite, sb, ", ", "");
		break;
	case RzBinDwarfLocationKind_EVALUATION_WAITING:
		rz_strbuf_append(sb, "<evaluation waiting>");
		break;
	case RzBinDwarfLocationKind_CFA_OFFSET:
		rz_strbuf_appendf(sb, "CFA%+" PFMT64d, loc->offset);
		break;
	case RzBinDwarfLocationKind_FB_OFFSET:
		rz_strbuf_appendf(sb, "FB%+" PFMT64d, loc->offset);
		break;
	case RzBinDwarfLocationKind_LOCLIST:
		rz_bin_dwarf_loclist_dump(encoding, dwarf_register_mapping, loc->loclist, sb, sep, indent);
		break;
	default:
		rz_strbuf_appendf(sb, "<unknown location kind: %d>", loc->kind);
		break;
	}
}
