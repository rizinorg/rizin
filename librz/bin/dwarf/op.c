// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

bool Evaluation_pop(Evaluation *self, RzBinDwarfValue **value) {
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

bool Evaluation_push(Evaluation *self, RzBinDwarfValue *value) {
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

RzBinDwarfValueType ValueType_from_die(RzBinDwarf *dw, UnitOffset offset) {
	RzBinDwarfDie *die = ht_up_find(dw->info->die_tbl, offset, NULL);
	if (!die) {
		return RzBinDwarfValueType_GENERIC;
	}
	assert(die->tag == DW_TAG_base_type);
	RzBinDwarfAttr *attr;
	RzBinDwarfValueType value_type = RzBinDwarfValueType_GENERIC;
	ut8 byte_size = 0;
	const char *name = NULL;
	rz_vector_foreach(&die->attrs, attr) {
		switch (attr->name) {
		case DW_AT_name:
			name = attr->string.content;
			break;
		case DW_AT_byte_size:
			byte_size = attr->uconstant;
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
	switch (byte_size) {
	case 1: value_type = RzBinDwarfValueType_U8; break;
	case 2: value_type = RzBinDwarfValueType_U16; break;
	case 4: value_type = RzBinDwarfValueType_U32; break;
	case 8: value_type = RzBinDwarfValueType_U64; break;
	default: break;
	}
	return value_type;
}

Evaluation *Evaluation_new(RzBuffer *byte_code, ut64 addr_mask, const RzBinDwarfEncoding *encoding) {
	Evaluation *self = RZ_NEW0(Evaluation);
	RET_NULL_IF_FAIL(self);
	self->addr_mask = addr_mask;
	self->bytecode = byte_code;
	self->encoding = encoding;
	self->pc = rz_buf_new_with_buf(byte_code);
	// TODO: add free fn
	rz_vector_init(&self->stack, sizeof(RzBinDwarfValue), NULL, NULL);
	rz_vector_init(&self->expression_stack, sizeof(ExprStackItem), NULL, NULL);
	rz_vector_init(&self->result, sizeof(RzBinDwarfPiece), NULL, NULL);
	return self;
}

void Evaluation_free(Evaluation *self) {
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

bool Evaluation_evaluate_one_operation(Evaluation *self, OperationEvaluationResult *out, RzBinDwarf *dw, RzBinDwarfDie *fn) {
	Operation *operation = RZ_NEW(Operation);
	RET_FALSE_IF_FAIL(operation);
	RET_FALSE_IF_FAIL(Operation_parse(operation, self->pc, self->encoding));

	switch (operation->kind) {
	case OPERATION_KIND_DEREF: {
		RzBinDwarfValue *entry = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &entry));
		RET_FALSE_IF_FAIL(entry);
		ut64 addr = 0;
		RET_FALSE_IF_FAIL(Value_to_u64(entry, self->addr_mask, &addr));
		Option /*<ut64>*/ *addr_space = NULL;
		if (operation->deref.space) {
			RzBinDwarfValue *space = NULL;
			RET_FALSE_IF_FAIL(Evaluation_pop(self, &space));
			RET_FALSE_IF_FAIL(space);
			ut64 addr_space_value = 0;
			RET_FALSE_IF_FAIL(Value_to_u64(space, self->addr_mask, &addr_space_value));
			addr_space = some(&addr_space_value);
		} else {
			addr_space = none();
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
		RzBinDwarfValue *value = rz_vector_index_ptr(&self->stack, len - operation->pick.index - 1);
		RET_FALSE_IF_FAIL(value);
		RET_FALSE_IF_FAIL(Evaluation_push(self, value));
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
		RzBinDwarfValue *lhs = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &lhs));
		RzBinDwarfValue rhs = { 0 };
		RET_FALSE_IF_FAIL(Value_from_u64(lhs->type, operation->plus_constant.value, &rhs));
		RET_FALSE_IF_FAIL(Value_add(lhs, &rhs, self->addr_mask, lhs));
		RET_FALSE_IF_FAIL(Evaluation_push(self, lhs));
		break;
	}
	case OPERATION_KIND_SHL: BINARY_OP(Value_shl);
	case OPERATION_KIND_SHR: BINARY_OP(Value_shr);
	case OPERATION_KIND_SHRA: BINARY_OP(Value_shra);
	case OPERATION_KIND_XOR: BINARY_OP(Value_xor);
	case OPERATION_KIND_BRA: {
		RzBinDwarfValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		ut64 entry = 0;
		RET_FALSE_IF_FAIL(Value_to_u64(v, self->addr_mask, &entry));
		if (entry != 0) {
			RET_FALSE_IF_FAIL(compute_pc(self->pc, self->bytecode, operation->bra.target));
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
		RET_FALSE_IF_FAIL(compute_pc(self->pc, self->bytecode, operation->skip.target));
		break;
	}
	case OPERATION_KIND_UNSIGNED_CONSTANT: {
		RzBinDwarfValue v = { .type = RzBinDwarfValueType_GENERIC, .generic = operation->unsigned_constant.value };
		RET_FALSE_IF_FAIL(Evaluation_push(self, &v));
		break;
	}
	case OPERATION_KIND_SIGNED_CONSTANT: {
		RzBinDwarfValue v = { .type = RzBinDwarfValueType_GENERIC, .generic = (ut64)operation->signed_constant.value };
		RET_FALSE_IF_FAIL(Evaluation_push(self, &v));
		break;
	}
	case OPERATION_KIND_REGISTER: {
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete = RZ_NEW0(RzBinDwarfLocation);
		out->complete->kind = RzBinDwarfLocationKind_REGISTER;
		out->complete->register_number = operation->reg.register_number;
		return true;
	}
	case OPERATION_KIND_REGISTER_OFFSET: {
		//		RzBinDwarfValueType value_type = operation->register_offset.base_type != 0 ? ValueType_from_die(dw, operation->register_offset.base_type) : RzBinDwarfValueType_GENERIC;
		//		RzBinDwarfValue offset;
		//		RET_FALSE_IF_FAIL(Value_from_u64(value_type, operation->register_offset.offset, &offset));
		//		RzBinDwarfValue value;
		//		RET_FALSE_IF_FAIL(Value_from_u64(value_type, operation->register_offset.register_number, &value));
		//		RET_FALSE_IF_FAIL(Value_add(&value, &offset, self->addr_mask, &value));
		//		RET_FALSE_IF_FAIL(Evaluation_push(self, &value));
		RzBinDwarfLocation location = {
			.kind = RzBinDwarfLocationKind_REGISTER_OFFSET,
			.register_offset = {
				.register_number = operation->register_offset.register_number,
				.offset = operation->register_offset.offset,
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
		RzBinDwarfAttr *fb = rz_bin_dwarf_die_get_attr(fn, DW_AT_frame_base);
		RET_FALSE_IF_FAIL(fb);
		RzBuffer *fb_buf = rz_buf_new_with_bytes(fb->block.data, fb->block.length);
		Evaluation *fb_eval = Evaluation_new(fb_buf, self->addr_mask, self->encoding);
		OperationEvaluationResult fb_result = { 0 };
		RET_FALSE_IF_FAIL(Evaluation_evaluate_one_operation(fb_eval, &fb_result, dw, fn));
		rz_buf_free(fb_buf);
		Evaluation_free(fb_eval);
		RET_FALSE_IF_FAIL(fb_result.kind == OperationEvaluationResult_COMPLETE && fb_result.complete);
		RzBinDwarfValue v = {
			.type = RzBinDwarfValueType_LOCATION,
			.location = fb_result.complete,
		};
		Evaluation_push(self, &v);
		// TODO: frame base loclist
		break;
	}
	case OPERATION_KIND_NOP: break;
	case OPERATION_KIND_PUSH_OBJECT_ADDRESS: break; // TODO: object address
	case OPERATION_KIND_CALL: break; // TODO: call
	case OPERATION_KIND_TLS: break; // TODO: tls
	case OPERATION_KIND_CALL_FRAME_CFA: break; // TODO: cfa
	case OPERATION_KIND_PIECE: {
		RzBinDwarfLocation *location = RZ_NEW0(RzBinDwarfLocation);
		if (rz_vector_empty(&self->stack)) {
			location->kind = RzBinDwarfLocationKind_EMPTY;
		} else {
			RzBinDwarfValue *v = NULL;
			RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
			RET_FALSE_IF_FAIL(Value_to_u64(v, self->addr_mask, &location->address));
			location->kind = RzBinDwarfLocationKind_ADDRESS;
		}
		RzBinDwarfPiece piece = {
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
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete = RZ_NEW0(RzBinDwarfLocation);
		out->complete->kind = RzBinDwarfLocationKind_IMPLICIT_POINTER;
		out->complete->implicit_pointer.value = operation->implicit_pointer.value;
		out->complete->implicit_pointer.byte_offset = operation->implicit_pointer.byte_offset;
		return true;
	}
	case OPERATION_KIND_STACK_VALUE: {
		RzBinDwarfValue *v = NULL;
		RET_FALSE_IF_FAIL(Evaluation_pop(self, &v));
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete = RZ_NEW0(RzBinDwarfLocation);
		out->complete->kind = RzBinDwarfLocationKind_VALUE;
		out->complete->value = *v;
		Value_free(v);
		return true;
	}
	case OPERATION_KIND_IMPLICIT_POINTER: {
		out->kind = OperationEvaluationResult_COMPLETE;
		out->complete = RZ_NEW0(RzBinDwarfLocation);
		out->complete->kind = RzBinDwarfLocationKind_IMPLICIT_POINTER;
		out->complete->implicit_pointer.value = operation->implicit_pointer.value;
		out->complete->implicit_pointer.byte_offset = operation->implicit_pointer.byte_offset;
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
	out->kind = EvaluationResultIncomplete;
	return true;
}

bool Evaluation_end_of_expression(Evaluation *self) {
	if (rz_buf_tell(self->pc) >= rz_buf_size(self->pc)) {
		if (rz_vector_empty(&self->expression_stack)) {
			return true;
		}
		ExprStackItem *item = NULL;
		rz_vector_pop(&self->expression_stack, item);
		RET_FALSE_IF_FAIL(item);
		self->pc = item->pc;
		self->bytecode = item->bytecode;
	}
	return false;
}

bool Evaluation_evaluate(Evaluation *self, RzBinDwarf *dw, RzBinDwarfDie *fn) {
	if (self->state.state == EVALUATION_STATE_START) {
		if (self->state.start) {
			Evaluation_push(self, self->state.start);
		}
		self->state.state = EVALUATION_STATE_READY;
	} else if (self->state.state == EVALUATION_STATE_ERROR) {
		return false;
	} else if (self->state.state == EVALUATION_STATE_COMPLETE) {
		return true;
	}
	while (!Evaluation_end_of_expression(self)) {
		self->iteration += 1;
		if (self->max_iterations != UT32_MAX && self->max_iterations) {
			if (self->iteration > self->max_iterations) {
				self->state.state = EVALUATION_STATE_ERROR;
				return false;
			}
		}
		OperationEvaluationResult op_result = { 0 };
		RET_FALSE_IF_FAIL(Evaluation_evaluate_one_operation(self, &op_result, dw, fn));

		switch (op_result.kind) {
		case OperationEvaluationResult_PIECE:
			break;
		case OperationEvaluationResult_INCOMPLETE:
			if (Evaluation_end_of_expression(self) && !rz_vector_empty(&self->result)) {
				self->state.state = EVALUATION_STATE_ERROR;
				return false;
			}
			break;
		case OperationEvaluationResult_COMPLETE:
			if (Evaluation_end_of_expression(self)) {
				if (!rz_vector_empty(&self->result)) {
					self->state.state = EVALUATION_STATE_ERROR;
					return false;
				}
				RzBinDwarfPiece piece = {
					.location = op_result.complete,
					.has_size_in_bits = false,
					.has_bit_offset = false,
				};
				RET_FALSE_IF_FAIL(rz_vector_push(&self->result, &piece));
			} else {
				Operation operation = { 0 };
				RET_FALSE_IF_FAIL(Operation_parse(&operation, self->pc, self->encoding));
				if (operation.kind == OPERATION_KIND_PIECE) {
					RzBinDwarfPiece piece = {
						.location = op_result.complete,
						.has_size_in_bits = true,
						.size_in_bits = operation.piece.size_in_bits,
						.has_bit_offset = false,
						.bit_offset = operation.piece.bit_offset,
					};
					RET_FALSE_IF_FAIL(rz_vector_push(&self->result, &piece));
				} else {
					// int64_t value = self->bytecode->len - self->pc->len - 1;
					self->state.state = EVALUATION_STATE_ERROR;
					return false;
				}
			}
			break;
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
			uint64_t addr;
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

	self->state.state = EVALUATION_STATE_COMPLETE;
	return true;
}

static inline ut64 addrmask_from_size(uint8_t size) {
	return size == 0 ? 0xffffffffffffffffULL
			 : (size == 8 ? 0xffffffffffffffffULL
				      : (1ULL << (size * 8)) - 1);
}

RZ_API RzVector *rz_bin_dwarf_evaluate(RzBinDwarf *dw, RzBuffer *expr, const RzBinDwarfDie *fn) {
	ut64 addr_mask = addrmask_from_size(dw->encoding.address_size);
	Evaluation *eval = Evaluation_new(expr, addr_mask, &dw->encoding);
	if (!Evaluation_evaluate(eval, dw, fn)) {
		return NULL;
	}
	RzVector *result = NULL;
	if (eval->state.state == EVALUATION_STATE_COMPLETE && !rz_vector_empty(&eval->result)) {
		result = rz_vector_clone(&eval->result);
	}
	Evaluation_free(eval);
	return result;
}
