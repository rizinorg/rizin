// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static RzBuffer *buf_from_block(RzBinDwarfBlock *block) {
	return rz_buf_new_with_bytes(block->data, block->length);
}

RZ_IPI bool Operation_parse(Operation *self, RzBuffer *buffer, const RzBinDwarfEncoding *encoding) {
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
		self->deref.base_type = 0;
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
		SLE128_OR_RET_FALSE(self->register_offset.offset);
		self->kind = OPERATION_KIND_REGISTER_OFFSET;
		self->register_offset.register_number = (ut16)opcode - DW_OP_breg0;
		break;

	case DW_OP_regx: {
		ut64 value;
		ULE128_OR_RET_FALSE(value);
		self->kind = OPERATION_KIND_REGISTER;
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
		self->deref.base_type = 0;
		self->deref.size = size;
		self->deref.space = false;
		break;
	}
	case DW_OP_xderef_size: {
		ut64 size;
		U8_OR_RET_FALSE(size);
		self->kind = OPERATION_KIND_DEREF;
		self->deref.base_type = 0;
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
	default:
		RZ_LOG_WARN("Unsupported opcode %d\n", opcode);
		break;
	}
	return true;
}

void Operation_fini(Operation *self) {
	if (!self) {
		return;
	}
	if (self->kind == OPERATION_KIND_IMPLICIT_VALUE) {
		RzBinDwarfBlock_fini(&self->implicit_value.data);
	} else if (self->kind == OPERATION_KIND_ENTRY_VALUE) {
		RzBinDwarfBlock_fini(&self->entry_value.expression);
	} else if (self->kind == OPERATION_KIND_TYPED_LITERAL) {
		RzBinDwarfBlock_fini(&self->typed_literal.value);
	}
}

bool Evaluation_pop(RzBinDwarfEvaluation *self, RzBinDwarfValue **value) {
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

bool Evaluation_push(RzBinDwarfEvaluation *self, RzBinDwarfValue *value) {
	rz_vector_push(&self->stack, value);
	return true;
}

bool compute_pc(RzBuffer *pc, const RzBuffer *bytecode, st16 offset) {
	return rz_buf_seek(pc, offset, RZ_BUF_CUR) >= 0;
}

RzBinDwarfValueType ValueType_from_name(const char *name, ut8 byte_size) {
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

RzBinDwarfValueType ValueType_from_die(RzBinDwarfEvaluation *eval, RzBinDwarf *dw, UnitOffset offset) {
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

void RzBinDwarfPiece_fini(RzBinDwarfPiece *x) {
	if (!x) {
		return;
	}
	RzBinDwarfLocation_free(x->location);
}

static inline ut64
addrmask_from_size(uint8_t size) {
	return size == 0 ? 0xffffffffffffffffULL
			 : (size == 8 ? 0xffffffffffffffffULL
				      : (1ULL << (size * 8)) - 1);
}

RZ_API RzBinDwarfEvaluation *rz_bin_dwarf_evaluation_new(RzBuffer *byte_code, const RzBinDwarf *dw, const RzBinDwarfCompUnit *unit, const RzBinDwarfDie *die) {
	rz_return_val_if_fail(byte_code && dw, NULL);
	RzBinDwarfEvaluation *self = RZ_NEW0(RzBinDwarfEvaluation);
	RET_NULL_IF_FAIL(self);
	RzBinDwarfEncoding *encoding = unit ? &unit->hdr.encoding : &dw->encoding;
	ut64 addr_mask = addrmask_from_size(encoding->address_size);
	self->addr_mask = addr_mask;
	self->bytecode = byte_code;
	self->encoding = encoding;
	self->pc = rz_buf_new_with_buf(byte_code);
	self->dw = dw;
	self->unit = unit;
	self->die = die;
	// TODO: add free fn
	rz_vector_init(&self->stack, sizeof(RzBinDwarfValue), NULL, NULL);
	rz_vector_init(&self->expression_stack, sizeof(RzBinDwarfExprStackItem), NULL, NULL);
	rz_vector_init(&self->result, sizeof(RzBinDwarfPiece), (RzVectorFree)RzBinDwarfPiece_fini, NULL);
	return self;
}

RZ_API RzBinDwarfEvaluation *rz_bin_dwarf_evaluation_new_from_block(const RzBinDwarfBlock *block, const RzBinDwarf *dw, const RzBinDwarfCompUnit *unit, const RzBinDwarfDie *die) {
	rz_return_val_if_fail(block && dw, NULL);
	RzBuffer *expr = rz_buf_new_with_bytes(block->data, block->length);
	RET_NULL_IF_FAIL(expr);
	RzBinDwarfEvaluation *self = rz_bin_dwarf_evaluation_new(expr, dw, unit, die);
	RET_NULL_IF_FAIL(self);
	return self;
}

RZ_API void rz_bin_dwarf_evaluation_free(RzBinDwarfEvaluation *self) {
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

bool Evaluation_evaluate_one_operation(RzBinDwarfEvaluation *self, OperationEvaluationResult *out) {
	Operation operation = { 0 };
	ut64 offset = rz_buf_tell(self->pc);
	RET_FALSE_IF_FAIL(Operation_parse(&operation, self->pc, self->encoding));

	/// need to resolve delayed value in stack
#define CHECK_DEFER \
	do { \
		if (rz_vector_len(&self->stack) >= 1) { \
			RzBinDwarfValue *val = rz_vector_tail(&self->stack); \
			if (val->type == RzBinDwarfValueType_LOCATION) { \
				rz_buf_seek(self->pc, offset, RZ_BUF_SET); \
				out->kind = OperationEvaluationResult_WAITING_RESOLVE; \
				return true; \
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
				return true; \
			} \
		} \
	} while (0)

	switch (operation.kind) {
	case OPERATION_KIND_DEREF: {
		CHECK_DEFER;
		RzBinDwarfValue *entry = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &entry));
		RET_FALSE_IF_FAIL(entry);
		ut64 addr = 0;
		RET_FALSE_IF_FAIL(Value_to_u64(entry, self->addr_mask, &addr));
		ut64 addr_space = 0;
		bool has_addr_space = false;
		if (operation.deref.space) {
			RzBinDwarfValue *space = NULL;
			RET_FALSE_IF_FAIL(Evaluation_pop(self, &space));
			RET_FALSE_IF_FAIL(space);
			RET_FALSE_IF_FAIL(Value_to_u64(space, self->addr_mask, &addr_space));
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
		RET_FALSE_IF_FAIL(Evaluation_pop(self, NULL));
		break;
	case OPERATION_KIND_PICK: {
		ut64 len = rz_vector_len(&self->stack);
		if (operation.pick.index >= len) {
			RZ_LOG_WARN("Pick index %d out of range\n", operation.pick.index);
			break;
		}
		RzBinDwarfValue *value = rz_vector_index_ptr(&self->stack, len - operation.pick.index - 1);
		RET_FALSE_IF_FAIL(value);
		RET_FALSE_IF_FAIL(Evaluation_push(self, Value_clone(value)));
		break;
	}
	case OPERATION_KIND_SWAP: {
		RzBinDwarfValue *top = NULL;
		RzBinDwarfValue *second = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &top));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &second));
		RET_FALSE_IF_FAIL(Evaluation_push(self, top));
		RET_FALSE_IF_FAIL(Evaluation_push(self, second));
		break;
	}
	case OPERATION_KIND_ROT: {
		RzBinDwarfValue *top = NULL;
		RzBinDwarfValue *second = NULL;
		RzBinDwarfValue *third = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &top));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &second));
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &third));
		RET_FALSE_IF_FAIL(Evaluation_push(self, top));
		RET_FALSE_IF_FAIL(Evaluation_push(self, second));
		RET_FALSE_IF_FAIL(Evaluation_push(self, third));
		break;
	}
#define BINARY_OP(fcn) \
	{ \
		CHECK_DEFER2; \
		RzBinDwarfValue *rhs = NULL; \
		RzBinDwarfValue *lhs = NULL; \
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &rhs)); \
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs)); \
		RzBinDwarfValue result = { 0 }; \
		fcn(lhs, rhs, self->addr_mask, &result); \
		Value_free(lhs); \
		Value_free(rhs); \
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result)); \
		break; \
	}
#define UNITARY_OP(fcn) \
	{ \
		CHECK_DEFER; \
		RzBinDwarfValue *top = NULL; \
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &top)); \
		RzBinDwarfValue result = { 0 }; \
		RET_FALSE_IF_FAIL(fcn(top, self->addr_mask, &result)); \
		Value_free(top); \
		RET_FALSE_IF_FAIL(Evaluation_push(self, &result)); \
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
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		RzBinDwarfValue rhs = { 0 };
		RET_FALSE_IF_FAIL(Value_from_u64(lhs->type, operation.plus_constant.value, &rhs));
		RET_FALSE_IF_FAIL(Value_add(lhs, &rhs, self->addr_mask, lhs));
		RET_FALSE_IF_FAIL(Evaluation_push(self, lhs));
		break;
	}
	case OPERATION_KIND_SHL: BINARY_OP(Value_shl);
	case OPERATION_KIND_SHR: BINARY_OP(Value_shr);
	case OPERATION_KIND_SHRA: BINARY_OP(Value_shra);
	case OPERATION_KIND_XOR: BINARY_OP(Value_xor);
	case OPERATION_KIND_BRA: {
		CHECK_DEFER;
		RzBinDwarfValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		ut64 entry = 0;
		RET_FALSE_IF_FAIL(Value_to_u64(v, self->addr_mask, &entry));
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
		RET_FALSE_IF_FAIL(compute_pc(self->pc, self->bytecode, operation.skip.target));
		break;
	}
	case OPERATION_KIND_UNSIGNED_CONSTANT: {
		RzBinDwarfValue v = { .type = RzBinDwarfValueType_GENERIC, .generic = operation.unsigned_constant.value };
		RET_FALSE_IF_FAIL(Evaluation_push(self, &v));
		break;
	}
	case OPERATION_KIND_SIGNED_CONSTANT: {
		RzBinDwarfValue v = { .type = RzBinDwarfValueType_GENERIC, .generic = (ut64)operation.signed_constant.value };
		RET_FALSE_IF_FAIL(Evaluation_push(self, &v));
		break;
	}
	case OPERATION_KIND_REGISTER: {
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete.kind = RzBinDwarfLocationKind_REGISTER;
		out->complete.register_number = operation.reg.register_number;
		return true;
	}
	case OPERATION_KIND_REGISTER_OFFSET: {
		RzBinDwarfLocation location = {
			.kind = RzBinDwarfLocationKind_REGISTER_OFFSET,
			.register_offset = {
				.register_number = operation.register_offset.register_number,
				.offset = operation.register_offset.offset,
			},
		};
		RzBinDwarfValue value = {
			.type = RzBinDwarfValueType_LOCATION,
			.location = NULL,
		};
		value.location = RZ_NEW0(RzBinDwarfLocation);
		memcpy(value.location, &location, sizeof(RzBinDwarfLocation));
		RET_FALSE_IF_FAIL(Evaluation_push(self, &value));
		break;
	}
	case OPERATION_KIND_FRAME_OFFSET: {
		RzBinDwarfAttr *fb_attr = rz_bin_dwarf_die_get_attr(self->die, DW_AT_frame_base);
		RET_FALSE_IF_FAIL(fb_attr);
		if (fb_attr->kind == DW_AT_KIND_UCONSTANT) {
			RzBinDwarfValue v = {
				.type = RzBinDwarfValueType_LOCATION,
				.location = NULL,
			};
			v.location = RZ_NEW0(RzBinDwarfLocation);
			v.location->kind = RzBinDwarfLocationKind_FB_OFFSET;
			v.location->fb_offset = (st64)fb_attr->uconstant;
			Evaluation_push(self, &v);
			break;
		}
		RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(&fb_attr->block, self->dw, self->unit, self->die);
		if (!loc) {
			char *expr_str = rz_bin_dwarf_expression_to_string(self->dw, &fb_attr->block);
			RZ_LOG_ERROR("Failed eval frame base: [%s]\n", rz_str_get_null(expr_str));
			free(expr_str);
			return false;
		}
		if (loc->kind == RzBinDwarfLocationKind_CFA_OFFSET) {
			loc->cfa_offset += operation.frame_offset.offset;
			RzBinDwarfValue v = {
				.type = RzBinDwarfValueType_LOCATION,
				.location = loc,
			};
			Evaluation_push(self, &v);
		} else if (loc->kind == RzBinDwarfLocationKind_REGISTER || loc->kind == RzBinDwarfLocationKind_REGISTER_OFFSET) {
			loc->kind = RzBinDwarfLocationKind_REGISTER_OFFSET;
			loc->register_offset.offset += operation.frame_offset.offset;
			RzBinDwarfValue v = {
				.type = RzBinDwarfValueType_LOCATION,
				.location = loc,
			};
			Evaluation_push(self, &v);
		} else {
			RZ_LOG_ERROR("Unsupported frame base location kind: %d\n", loc->kind);
			return false;
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
			Evaluation_push(self, &v);
		} else {
			RZ_LOG_ERROR("object address not set");
			return false;
		}
		break;
	}
	case OPERATION_KIND_CALL_FRAME_CFA: {
		RzBinDwarfLocation loc = {
			.kind = RzBinDwarfLocationKind_CFA_OFFSET,
			.cfa_offset = 0,
		};
		RzBinDwarfValue v = {
			.type = RzBinDwarfValueType_LOCATION,
			.location = RZ_NEW0(RzBinDwarfLocation),
		};
		memcpy(v.location, &loc, sizeof(RzBinDwarfLocation));
		Evaluation_push(self, &v);
		break;
	}
	case OPERATION_KIND_PIECE: {
		RzBinDwarfLocation *location = NULL;
		if (rz_vector_empty(&self->stack)) {
			location = RZ_NEW0(RzBinDwarfLocation);
			location->kind = RzBinDwarfLocationKind_EMPTY;
		} else {
			RzBinDwarfValue *v = NULL;
			RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
			if (v->type == RzBinDwarfValueType_LOCATION) {
				location = v->location;
				v->location = NULL;
			} else {
				location = RZ_NEW0(RzBinDwarfLocation);
				RET_FALSE_IF_FAIL(Value_to_u64(v, self->addr_mask, &location->address));
				location->kind = RzBinDwarfLocationKind_ADDRESS;
			}
			Value_free(v);
		}
		RzBinDwarfPiece piece = {
			.location = location,
			.has_bit_offset = operation.piece.has_bit_offset,
			.bit_offset = operation.piece.bit_offset,
			.has_size_in_bits = true,
			.size_in_bits = operation.piece.size_in_bits,
		};
		rz_vector_push(&self->result, &piece);
		out->kind = OperationEvaluationResult_PIECE;
		return true;
	}
	case OPERATION_KIND_IMPLICIT_VALUE: {
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete.kind = RzBinDwarfLocationKind_IMPLICIT_POINTER;
		out->complete.implicit_pointer.value = operation.implicit_pointer.value;
		out->complete.implicit_pointer.byte_offset = operation.implicit_pointer.byte_offset;
		return true;
	}
	case OPERATION_KIND_STACK_VALUE: {
		RzBinDwarfValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		out->kind = OperationEvaluationResult_COMPLETE;
		if (v->type == RzBinDwarfValueType_LOCATION) {
			memcpy(&out->complete, v->location, sizeof(RzBinDwarfLocation));
			return true;
		} else {
			out->complete.kind = RzBinDwarfLocationKind_VALUE;
			out->complete.value = *v;
		}
		Value_free(v);
		return true;
	}
	case OPERATION_KIND_IMPLICIT_POINTER: {
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete.kind = RzBinDwarfLocationKind_IMPLICIT_POINTER;
		out->complete.implicit_pointer.value = operation.implicit_pointer.value;
		out->complete.implicit_pointer.byte_offset = operation.implicit_pointer.byte_offset;
		return true;
	}
	case OPERATION_KIND_ENTRY_VALUE: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_ENTRY_VALUE;
		out->waiting._2.requires_entry_value.expression = RzBinDwarfBlock_clone(&operation.entry_value.expression);
		return true;
	}
	case OPERATION_KIND_ADDRESS: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_RelocatedAddress;
		out->waiting._2.requires_relocated_address = operation.address.address;
		return true;
	}
	case OPERATION_KIND_ADDRESS_INDEX: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_IndexedAddress;
		out->waiting._2.requires_indexed_address.index = operation.address_index.index;
		out->waiting._2.requires_indexed_address.relocate = true;
		return true;
	}
	case OPERATION_KIND_CONSTANT_INDEX: {
		out->kind = OperationEvaluationResult_WAITING;
		out->waiting._1 = EvaluationStateWaiting_IndexedAddress;
		out->waiting._2.requires_indexed_address.index = operation.constant_index.index;
		out->waiting._2.requires_indexed_address.relocate = false;
		return true;
	}

	case OPERATION_KIND_TYPED_LITERAL: {
		RzBinDwarfValueType typ = ValueType_from_die(self, self->dw, operation.typed_literal.base_type);
		RzBuffer *buf = buf_from_block(&operation.typed_literal.value);
		RzBinDwarfValue *val = Value_parse(typ, buf, self->encoding->big_endian);
		rz_buf_free(buf);
		RET_FALSE_IF_FAIL(val);
		RET_FALSE_IF_FAIL(Evaluation_push(self, val));
		break;
	}
	case OPERATION_KIND_CONVERT: {
		CHECK_DEFER;
		RzBinDwarfValue *val = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &val));
		RzBinDwarfValueType typ = ValueType_from_die(self, self->dw, operation.convert.base_type);
		RET_FALSE_IF_FAIL(Value_convert(val, typ, self->addr_mask, val));
		RET_FALSE_IF_FAIL(Evaluation_push(self, val));
		break;
	}
	case OPERATION_KIND_REINTERPRET: {
		CHECK_DEFER;
		RzBinDwarfValue *val = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &val));
		RzBinDwarfValueType typ = ValueType_from_die(self, self->dw, operation.reinterpret.base_type);
		RET_FALSE_IF_FAIL(Value_reinterpret(val, typ, self->addr_mask, val));
		RET_FALSE_IF_FAIL(Evaluation_push(self, val));
		break;
	}

	case OPERATION_KIND_CALL: // TODO: call
	case OPERATION_KIND_TLS: // TODO: tls
	case OPERATION_KIND_PARAMETER_REF: // TODO: parameter ref

	case OPERATION_KIND_WASM_LOCAL:
	case OPERATION_KIND_WASM_GLOBAL:
	case OPERATION_KIND_WASM_STACK: {
		RZ_LOG_ERROR("DWARF %s operation not supported\n", rz_bin_dwarf_op(operation.opcode));
		return false;
	}
	}
	out->kind = EvaluationResult_INCOMPLETE;
	return true;
}

bool Evaluation_end_of_expression(RzBinDwarfEvaluation *self) {
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

RZ_API bool rz_bin_dwarf_evaluation_evaluate(RzBinDwarfEvaluation *self, RzBinDwarfEvaluationResult *out) {
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
				return false;
			}
		}
		OperationEvaluationResult op_result = { 0 };
		RET_FALSE_IF_FAIL(Evaluation_evaluate_one_operation(self, &op_result));

		switch (op_result.kind) {
		case OperationEvaluationResult_PIECE:
			break;
		case OperationEvaluationResult_INCOMPLETE:
			if (Evaluation_end_of_expression(self) && !rz_vector_empty(&self->result)) {
				self->state.kind = EVALUATION_STATE_ERROR;
				return false;
			}
			break;
		case OperationEvaluationResult_WAITING: {
			self->state.kind = EVALUATION_STATE_WAITING;
			self->state.waiting = op_result.waiting._1;
			memcpy(out, &op_result.waiting._2, sizeof(RzBinDwarfEvaluationResult));
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
					return false;
				}
				RzBinDwarfPiece piece = {
					.location = NULL,
					.has_size_in_bits = false,
					.has_bit_offset = false,
				};
				piece.location = RZ_NEW0(RzBinDwarfLocation);
				memcpy(piece.location, &op_result.complete, sizeof(RzBinDwarfLocation));
				RET_FALSE_IF_FAIL(rz_vector_push(&self->result, &piece));
			} else {
				Operation operation = { 0 };
				RET_FALSE_IF_FAIL(Operation_parse(&operation, self->pc, self->encoding));
				if (operation.kind == OPERATION_KIND_PIECE) {
					RzBinDwarfPiece piece = {
						.location = NULL,
						.has_size_in_bits = true,
						.size_in_bits = operation.piece.size_in_bits,
						.has_bit_offset = false,
						.bit_offset = operation.piece.bit_offset,
					};
					piece.location = RZ_NEW0(RzBinDwarfLocation);
					memcpy(piece.location, &op_result.complete, sizeof(RzBinDwarfLocation));
					RET_FALSE_IF_FAIL(rz_vector_push(&self->result, &piece));
				} else {
					self->state.kind = EVALUATION_STATE_ERROR;
					return false;
				}
			}
			break;
		}
		};
	}

	if (rz_vector_empty(&self->result)) {
		RzBinDwarfValue *entry = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &entry));
		RzBinDwarfLocation *location = NULL;
		switch (entry->type) {
		case RzBinDwarfValueType_LOCATION:
			location = entry->location;
			entry->location = NULL;
			break;
		default: {
			ut64 addr;
			RET_FALSE_IF_FAIL(Value_to_u64(entry, self->addr_mask, &addr));
			location = RZ_NEW0(RzBinDwarfLocation);
			location->kind = RzBinDwarfLocationKind_ADDRESS;
			location->address = addr;
			break;
		}
		}
		Value_free(entry);
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

RZ_API RzVector * /*Piece*/ rz_bin_dwarf_evaluation_result(RzBinDwarfEvaluation *self) {
	if (self->state.kind == EVALUATION_STATE_COMPLETE) {
		return &self->result;
	}
	RZ_LOG_ERROR("Called `Evaluation::result` on an `Evaluation` that has not been completed");
	return NULL;
}

RzBinDwarfLocation *RzBinDwarfEvaluationResult_to_loc(RzBinDwarfEvaluation *eval, RzBinDwarfEvaluationResult *result) {
	if (eval->state.kind == EVALUATION_STATE_COMPLETE && result->kind == EvaluationResult_COMPLETE) {
		RzVector *pieces = rz_bin_dwarf_evaluation_result(eval);
		if (!pieces || rz_vector_empty(pieces)) {
			return NULL; // TODO: or empty location?
		}
		if (rz_vector_len(pieces) == 1) {
			RzBinDwarfPiece *piece = rz_vector_index_ptr(pieces, 0);
			return piece->location;
		}
		RzBinDwarfLocation *loc = RZ_NEW0(RzBinDwarfLocation);
		loc->kind = RzBinDwarfLocationKind_COMPOSITE;
		loc->compose = rz_vector_clone(pieces);
		rz_bin_dwarf_evaluation_free(eval);
		return loc;
	}

	RzBinDwarfLocation *loc = RZ_NEW0(RzBinDwarfLocation);
	loc->kind = RzBinDwarfLocationKind_EVALUATION_WAITING;
	loc->eval_waiting.eval = eval;
	loc->eval_waiting.result = result;
	return loc;
}

RZ_API RzBinDwarfLocation *rz_bin_dwarf_location_from_block(const RzBinDwarfBlock *block, const RzBinDwarf *dw, const RzBinDwarfCompUnit *unit, const RzBinDwarfDie *die) {
	rz_return_val_if_fail(block && dw, NULL);
	RzBinDwarfEvaluationResult *result = RZ_NEW0(RzBinDwarfEvaluationResult);
	RET_NULL_IF_FAIL(result);
	RzBinDwarfEvaluation *eval = rz_bin_dwarf_evaluation_new_from_block(block, dw, unit, die);
	RET_NULL_IF_FAIL(eval);
	if (!rz_bin_dwarf_evaluation_evaluate(eval, result)) {
		goto beach;
	}

	return RzBinDwarfEvaluationResult_to_loc(eval, result);
beach:
	rz_bin_dwarf_evaluation_free(eval);
	return NULL;
}

void Operation_dump(Operation *op, RzStrBuf *buf) {
	rz_strbuf_append(buf, rz_bin_dwarf_op(op->opcode));
	switch (op->kind) {
	case OPERATION_KIND_DEREF:
		rz_strbuf_appendf(buf, " base_type: 0x%" PFMT64x ", size: %d, space: %d", op->deref.base_type, op->deref.size, op->deref.space);
		break;
	case OPERATION_KIND_DROP: break;
	case OPERATION_KIND_PICK:
		rz_strbuf_appendf(buf, " 0x%x", op->pick.index);
		break;
	case OPERATION_KIND_SWAP: break;
	case OPERATION_KIND_ROT: break;
	case OPERATION_KIND_ABS: break;
	case OPERATION_KIND_AND: break;
	case OPERATION_KIND_DIV: break;
	case OPERATION_KIND_MINUS: break;
	case OPERATION_KIND_MOD: break;
	case OPERATION_KIND_MUL: break;
	case OPERATION_KIND_NEG: break;
	case OPERATION_KIND_NOT: break;
	case OPERATION_KIND_OR: break;
	case OPERATION_KIND_PLUS: break;
	case OPERATION_KIND_PLUS_CONSTANT:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->plus_constant.value);
		break;
	case OPERATION_KIND_SHL: break;
	case OPERATION_KIND_SHR: break;
	case OPERATION_KIND_SHRA: break;
	case OPERATION_KIND_XOR: break;
	case OPERATION_KIND_BRA:
		rz_strbuf_appendf(buf, " %d", op->bra.target);
		break;
	case OPERATION_KIND_EQ: break;
	case OPERATION_KIND_GE: break;
	case OPERATION_KIND_GT: break;
	case OPERATION_KIND_LE: break;
	case OPERATION_KIND_LT: break;
	case OPERATION_KIND_NE: break;
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
		rz_strbuf_appendf(buf, " %u %" PFMT64d " 0x%" PFMT64x, op->register_offset.register_number, op->register_offset.offset, op->register_offset.base_type);
		break;
	case OPERATION_KIND_FRAME_OFFSET:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->frame_offset.offset);
		break;
	case OPERATION_KIND_NOP: break;
	case OPERATION_KIND_PUSH_OBJECT_ADDRESS: break;
	case OPERATION_KIND_CALL:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x, op->call.offset);
		break;
	case OPERATION_KIND_TLS: break;
	case OPERATION_KIND_CALL_FRAME_CFA: break;
	case OPERATION_KIND_PIECE:
		rz_strbuf_appendf(buf, " %" PFMT64u, op->piece.size_in_bits);
		if (op->piece.has_bit_offset) {
			rz_strbuf_appendf(buf, " %" PFMT64u, op->piece.bit_offset);
		}
		break;
	case OPERATION_KIND_IMPLICIT_VALUE: {
		RzBinDwarfBlock_dump(&op->implicit_value.data, buf);
		break;
	}
	case OPERATION_KIND_STACK_VALUE: break;
	case OPERATION_KIND_IMPLICIT_POINTER:
		rz_strbuf_appendf(buf, " 0x%" PFMT64x " %" PFMT64d, op->implicit_pointer.value, op->implicit_pointer.byte_offset);
		break;
	case OPERATION_KIND_ENTRY_VALUE:
		RzBinDwarfBlock_dump(&op->entry_value.expression, buf);
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
		RzBinDwarfBlock_dump(&op->typed_literal.value, buf);
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

static RzVector *rz_bin_dwarf_expression_parse(RzBuffer *expr, const RzBinDwarfEncoding *encoding) {
	RzVector *exprs = rz_vector_new(sizeof(Operation), vec_Operation_free, NULL);
	Operation op = { 0 };
	while (Operation_parse(&op, expr, encoding)) {
		rz_vector_push(exprs, &op);
	}
	return exprs;
}

RZ_API void
rz_bin_dwarf_expression_dump(const RzBinDwarf *dw, const RzBinDwarfBlock *block, RzStrBuf *str_buf, const char *sep, const char *indent) {
	RzBuffer *buffer = rz_buf_new_with_bytes(block->data, block->length);
	RzVector *exprs = rz_bin_dwarf_expression_parse(buffer, &dw->encoding);

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

RZ_API char *rz_bin_dwarf_expression_to_string(const RzBinDwarf *dw, const RzBinDwarfBlock *block) {
	RzStrBuf sb = { 0 };
	rz_strbuf_init(&sb);
	rz_bin_dwarf_expression_dump(dw, block, &sb, ",\t", "");
	return rz_strbuf_drain_nofree(&sb);
}
