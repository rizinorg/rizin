// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

static inline int64_t sign_extend(ut64 value, ut64 mask) {
	int64_t masked_value = (int64_t)(value & mask);
	int64_t sign = (int64_t)((mask >> 1) + 1);
	return (masked_value ^ sign) - sign;
}

static inline uint32_t mask_bit_size(ut64 addr_mask) {
	return 64 - rz_bits_leading_zeros(addr_mask);
}

static uint32_t bit_size(RzBinDwarfValueType type, ut64 addr_mask) {
	switch (type) {
	case RzBinDwarfValueType_GENERIC:
		return mask_bit_size(addr_mask);
	case RzBinDwarfValueType_I8:
	case RzBinDwarfValueType_U8:
		return 8;
	case RzBinDwarfValueType_I16:
	case RzBinDwarfValueType_U16:
		return 16;
	case RzBinDwarfValueType_I32:
	case RzBinDwarfValueType_U32:
	case RzBinDwarfValueType_F32:
		return 32;
	case RzBinDwarfValueType_I64:
	case RzBinDwarfValueType_U64:
	case RzBinDwarfValueType_F64:
		return 64;
	default:
		return 0; // Undefined ValueType
	}
}

RZ_IPI bool ValueType_from_encoding(DW_ATE encoding, ut64 byte_size, RzBinDwarfValueType *out_type) {
	RzBinDwarfValueType value_type = -1;
	switch (encoding) {
	case DW_ATE_signed:
		switch (byte_size) {
		case 1: value_type = RzBinDwarfValueType_I8; break;
		case 2: value_type = RzBinDwarfValueType_I16; break;
		case 4: value_type = RzBinDwarfValueType_I32; break;
		case 8: value_type = RzBinDwarfValueType_I64; break;
		default: rz_warn_if_reached();
		}
		break;
	case DW_ATE_unsigned:
		switch (byte_size) {
		case 1: value_type = RzBinDwarfValueType_U8; break;
		case 2: value_type = RzBinDwarfValueType_U16; break;
		case 4: value_type = RzBinDwarfValueType_U32; break;
		case 8: value_type = RzBinDwarfValueType_U64; break;
		default: rz_warn_if_reached();
		}
		break;
	case DW_ATE_float:
		switch (byte_size) {
		case 4: value_type = RzBinDwarfValueType_F32; break;
		case 8: value_type = RzBinDwarfValueType_F64; break;
		default: rz_warn_if_reached();
		}
		break;
	case DW_ATE_address:
	case DW_ATE_boolean:
	case DW_ATE_complex_float:
	case DW_ATE_signed_char:
	case DW_ATE_unsigned_char:
	case DW_ATE_imaginary_float:
	case DW_ATE_packed_decimal:
	case DW_ATE_numeric_string:
	case DW_ATE_edited:
	case DW_ATE_signed_fixed:
	case DW_ATE_unsigned_fixed:
	case DW_ATE_decimal_float:
	case DW_ATE_UTF:
	case DW_ATE_lo_user:
	case DW_ATE_hi_user:
	default:
		RZ_LOG_VERBOSE("Unsupported encoding: %d\n", encoding);
		return false;
	}
	if (value_type == -1) {
		return false;
	}
	*out_type = value_type;
	return true;
}

RZ_IPI bool ValueType_from_entry(RzBinDwarfDie *entry, RzBinDwarfValueType *out) {
	if (entry->tag != DW_TAG_base_type) {
		return false; // Represents Option::None in Rust
	}

	DW_ATE encoding = -1;
	ut64 byte_size = 0;
	int endianity = DW_END_default;

	RzBinDwarfAttr *attr; // Assuming Attribute is defined elsewhere

	rz_vector_foreach (&entry->attrs, attr) {
		switch (attr->at) {
		case DW_AT_byte_size:
			byte_size = rz_bin_dwarf_attr_udata(attr);
			break;
		case DW_AT_encoding:
			encoding = rz_bin_dwarf_attr_udata(attr); // Assuming value contains the encoding
			break;
		case DW_AT_endianity:
			endianity = rz_bin_dwarf_attr_udata(attr); // Assuming value contains the endianity
			break;
		default:
			break;
		}
	}

	if (endianity != DW_END_default) {
		return false;
	}

	if (encoding == -1 || byte_size == 0) {
		return false;
	}
	return ValueType_from_encoding(encoding, byte_size, out);
}

RZ_IPI bool Value_parse_into(
	RzBinDwarfValue *value, RzBinDwarfValueType value_type, RzBinEndianReader *R) {

	RET_FALSE_IF_FAIL(value);
	value->type = value_type;
	switch (value_type) {
	case RzBinDwarfValueType_I8:
		READ8_OR(st8, value->i8, return false);
		break;
	case RzBinDwarfValueType_U8:
		READ8_OR(ut8, value->u8, return false);
		break;
	case RzBinDwarfValueType_I16:
		READ_T_OR(16, st16, value->i16, return false);
		break;
	case RzBinDwarfValueType_U16:
		READ_T_OR(16, ut16, value->u16, return false);
		break;
	case RzBinDwarfValueType_I32:
		READ_T_OR(32, st32, value->i32, return false);
		break;
	case RzBinDwarfValueType_U32:
		READ_T_OR(32, ut32, value->u32, return false);
		break;
	case RzBinDwarfValueType_I64:
		READ_T_OR(64, st64, value->i64, return false);
		break;
	case RzBinDwarfValueType_U64:
		READ_UT_OR(64, value->u64, return false);
		break;
	case RzBinDwarfValueType_I128:
	case RzBinDwarfValueType_U128:
		RZ_LOG_ERROR("I128/U128 not supported\n")
		return false;
	case RzBinDwarfValueType_F32:
		READ_T_OR(32, float, value->f32, return false);
		break;
	case RzBinDwarfValueType_F64:
		READ_T_OR(64, double, value->f64, return false);
		break;
	default:
		return false;
	}

	return true;
}

RZ_IPI RzBinDwarfValue *Value_from_location(RzBinDwarfLocation *loc) {
	RzBinDwarfValue *v = RZ_NEW0(RzBinDwarfValue);
	RET_NULL_IF_FAIL(v);
	v->type = RzBinDwarfValueType_LOCATION;
	v->location = loc;
	return v;
}

RZ_IPI RzBinDwarfValueType Value_type(RzBinDwarfValue *ptr) {
	if (ptr == NULL) {
		return -1;
	}
	return ptr->type;
}

RZ_IPI bool Value_to_u64(RzBinDwarfValue *self, ut64 addr_mask, ut64 *result) {
	switch (Value_type(self)) {
	case RzBinDwarfValueType_GENERIC:
		*result = self->generic & addr_mask;
		break;
	case RzBinDwarfValueType_I8:
		*result = (ut64)self->i8;
		break;
	case RzBinDwarfValueType_U8:
		*result = self->u8;
		break;
	case RzBinDwarfValueType_I16:
		*result = (ut64)self->i16;
		break;
	case RzBinDwarfValueType_U16:
		*result = self->u16;
		break;
	case RzBinDwarfValueType_I32:
		*result = (ut64)self->i32;
		break;
	case RzBinDwarfValueType_U32:
		*result = self->u32;
		break;
	case RzBinDwarfValueType_I64:
		*result = (ut64)self->i64;
		break;
	case RzBinDwarfValueType_U64:
		*result = self->u64;
		break;
	default:
		// Handle integral type required error
		return false;
	}
	return true;
}

RZ_IPI bool Value_from_u64(RzBinDwarfValueType value_type, ut64 value, RzBinDwarfValue *result) {
	result->type = value_type;
	switch (value_type) {
	case RzBinDwarfValueType_GENERIC:
		result->generic = value;
		break;
	case RzBinDwarfValueType_I8:
		result->i8 = (int8_t)value;
		break;
	case RzBinDwarfValueType_U8:
		result->u8 = (uint8_t)value;
		break;
	case RzBinDwarfValueType_I16:
		result->i16 = (int16_t)value;
		break;
	case RzBinDwarfValueType_U16:
		result->u16 = (uint16_t)value;
		break;
	case RzBinDwarfValueType_I32:
		result->i32 = (int32_t)value;
		break;
	case RzBinDwarfValueType_U32:
		result->u32 = (uint32_t)value;
		break;
	case RzBinDwarfValueType_I64:
		result->i64 = (int64_t)value;
		break;
	case RzBinDwarfValueType_U64:
		result->u64 = value;
		break;
	case RzBinDwarfValueType_F32:
		result->f32 = (float)value;
		break;
	case RzBinDwarfValueType_F64:
		result->f64 = (double)value;
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_from_f32(RzBinDwarfValueType value_type, float value, RzBinDwarfValue *result) {
	result->type = value_type;
	switch (value_type) {
	case RzBinDwarfValueType_GENERIC:
		result->generic = (ut64)value;
		break;
	case RzBinDwarfValueType_I8:
		result->i8 = (int8_t)value;
		break;
	case RzBinDwarfValueType_U8:
		result->u8 = (uint8_t)value;
		break;
	case RzBinDwarfValueType_I16:
		result->i16 = (int16_t)value;
		break;
	case RzBinDwarfValueType_U16:
		result->u16 = (uint16_t)value;
		break;
	case RzBinDwarfValueType_I32:
		result->i32 = (int32_t)value;
		break;
	case RzBinDwarfValueType_U32:
		result->u32 = (uint32_t)value;
		break;
	case RzBinDwarfValueType_I64:
		result->i64 = (int64_t)value;
		break;
	case RzBinDwarfValueType_U64:
		result->u64 = (ut64)value;
		break;
	case RzBinDwarfValueType_F32:
		result->f32 = value;
		break;
	case RzBinDwarfValueType_F64:
		result->f64 = (double)value;
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_from_f64(RzBinDwarfValueType value_type, double value, RzBinDwarfValue *result) {
	result->type = value_type;
	switch (value_type) {
	case RzBinDwarfValueType_GENERIC:
		result->generic = (ut64)value;
		break;
	case RzBinDwarfValueType_I8:
		result->i8 = (int8_t)value;
		break;
	case RzBinDwarfValueType_U8:
		result->u8 = (uint8_t)value;
		break;
	case RzBinDwarfValueType_I16:
		result->i16 = (int16_t)value;
		break;
	case RzBinDwarfValueType_U16:
		result->u16 = (uint16_t)value;
		break;
	case RzBinDwarfValueType_I32:
		result->i32 = (int32_t)value;
		break;
	case RzBinDwarfValueType_U32:
		result->u32 = (uint32_t)value;
		break;
	case RzBinDwarfValueType_I64:
		result->i64 = (int64_t)value;
		break;
	case RzBinDwarfValueType_U64:
		result->u64 = (ut64)value;
		break;
	case RzBinDwarfValueType_F32:
		result->f32 = (float)value;
		break;
	case RzBinDwarfValueType_F64:
		result->f64 = value;
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_convert(RzBinDwarfValue *self, RzBinDwarfValueType typ, ut64 addr_mask, RzBinDwarfValue *result) {
	switch (self->type) {
	case RzBinDwarfValueType_F32:
		return Value_from_f32(typ, self->f32, result);
	case RzBinDwarfValueType_F64:
		return Value_from_f64(typ, self->f64, result);
	default: {
		ut64 temp = 0;
		Value_to_u64(self, addr_mask, &temp);
		return Value_from_u64(typ, temp, result);
	}
	}
}

RZ_IPI bool Value_reinterpret(
	RzBinDwarfValue *self, RzBinDwarfValueType value_type, ut64 addr_mask, RzBinDwarfValue *result) {
	if (bit_size(self->type, addr_mask) != bit_size(value_type, addr_mask)) {
		return false;
	}

	ut64 bits;
	RET_FALSE_IF_FAIL(Value_to_u64(self, addr_mask, &bits));
	return Value_from_u64(value_type, bits, result);
}

RZ_IPI bool Value_abs(RzBinDwarfValue *self, ut64 addr_mask, RzBinDwarfValue *result) {
	switch (self->type) {
	case RzBinDwarfValueType_GENERIC:
		result->generic = (ut64)llabs(sign_extend(self->generic, addr_mask));
		break;
	case RzBinDwarfValueType_I8:
		result->i8 = abs(self->i8);
		break;
	case RzBinDwarfValueType_I16:
		result->i16 = abs(self->i16);
		break;
	case RzBinDwarfValueType_I32:
		result->i32 = abs(self->i32);
		break;
	case RzBinDwarfValueType_I64:
		result->i64 = llabs(self->i64);
		break;
	case RzBinDwarfValueType_F32:
		result->f32 = fabsf(self->f32);
		break;
	case RzBinDwarfValueType_F64:
		result->f64 = fabs(self->f64);
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_neg(RzBinDwarfValue *self, ut64 addr_mask, RzBinDwarfValue *result) {
	switch (self->type) {
	case RzBinDwarfValueType_GENERIC:
		result->generic = (ut64)(-sign_extend(self->generic, addr_mask));
		break;
	case RzBinDwarfValueType_I8:
		result->i8 = -self->i8;
		break;
	case RzBinDwarfValueType_I16:
		result->i16 = -self->i16;
		break;
	case RzBinDwarfValueType_I32:
		result->i32 = -self->i32;
		break;
	case RzBinDwarfValueType_I64:
		result->i64 = -self->i64;
		break;
	case RzBinDwarfValueType_F32:
		result->f32 = -self->f32;
		break;
	case RzBinDwarfValueType_F64:
		result->f64 = -self->f64;
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_add(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	if (lhs->type != rhs->type) {
		return false;
	}

	switch (lhs->type) {
	case RzBinDwarfValueType_GENERIC:
		result->generic = (lhs->generic + rhs->generic) & addr_mask;
		break;
	case RzBinDwarfValueType_I8:
		result->i8 = lhs->i8 + rhs->i8;
		break;
	case RzBinDwarfValueType_U8:
		result->u8 = lhs->u8 + rhs->u8;
		break;
	case RzBinDwarfValueType_I16:
		result->i16 = lhs->i16 + rhs->i16;
		break;
	case RzBinDwarfValueType_U16:
		result->u16 = lhs->u16 + rhs->u16;
		break;
	case RzBinDwarfValueType_I32:
		result->i32 = lhs->i32 + rhs->i32;
		break;
	case RzBinDwarfValueType_U32:
		result->u32 = lhs->u32 + rhs->u32;
		break;
	case RzBinDwarfValueType_I64:
		result->i64 = lhs->i64 + rhs->i64;
		break;
	case RzBinDwarfValueType_U64:
		result->u64 = lhs->u64 + rhs->u64;
		break;
	case RzBinDwarfValueType_F32:
		result->f32 = lhs->f32 + rhs->f32;
		break;
	case RzBinDwarfValueType_F64:
		result->f64 = lhs->f64 + rhs->f64;
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_sub(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	if (lhs->type != rhs->type) {
		return false;
	}

	switch (lhs->type) {
	case RzBinDwarfValueType_GENERIC:
		result->generic = (lhs->generic - rhs->generic) & addr_mask;
		break;
	case RzBinDwarfValueType_I8:
		result->i8 = lhs->i8 - rhs->i8;
		break;
	case RzBinDwarfValueType_U8:
		result->u8 = lhs->u8 - rhs->u8;
		break;
	case RzBinDwarfValueType_I16:
		result->i16 = lhs->i16 - rhs->i16;
		break;
	case RzBinDwarfValueType_U16:
		result->u16 = lhs->u16 - rhs->u16;
		break;
	case RzBinDwarfValueType_I32:
		result->i32 = lhs->i32 - rhs->i32;
		break;
	case RzBinDwarfValueType_U32:
		result->u32 = lhs->u32 - rhs->u32;
		break;
	case RzBinDwarfValueType_I64:
		result->i64 = lhs->i64 - rhs->i64;
		break;
	case RzBinDwarfValueType_U64:
		result->u64 = lhs->u64 - rhs->u64;
		break;
	case RzBinDwarfValueType_F32:
		result->f32 = lhs->f32 - rhs->f32;
		break;
	case RzBinDwarfValueType_F64:
		result->f64 = lhs->f64 - rhs->f64;
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_mul(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	if (lhs->type != rhs->type) {
		return false;
	}

	switch (lhs->type) {
	case RzBinDwarfValueType_GENERIC:
		result->generic = (lhs->generic * rhs->generic) & addr_mask;
		break;
	case RzBinDwarfValueType_I8:
		result->i8 = lhs->i8 * rhs->i8;
		break;
	case RzBinDwarfValueType_U8:
		result->u8 = lhs->u8 * rhs->u8;
		break;
	case RzBinDwarfValueType_I16:
		result->i16 = lhs->i16 * rhs->i16;
		break;
	case RzBinDwarfValueType_U16:
		result->u16 = lhs->u16 * rhs->u16;
		break;
	case RzBinDwarfValueType_I32:
		result->i32 = lhs->i32 * rhs->i32;
		break;
	case RzBinDwarfValueType_U32:
		result->u32 = lhs->u32 * rhs->u32;
		break;
	case RzBinDwarfValueType_I64:
		result->i64 = lhs->i64 * rhs->i64;
		break;
	case RzBinDwarfValueType_U64:
		result->u64 = lhs->u64 * rhs->u64;
		break;
	case RzBinDwarfValueType_F32:
		result->f32 = lhs->f32 * rhs->f32;
		break;
	case RzBinDwarfValueType_F64:
		result->f64 = lhs->f64 * rhs->f64;
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_div(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	if (lhs->type != rhs->type) {
		return false;
	}

	switch (lhs->type) {
	case RzBinDwarfValueType_GENERIC:
		if (sign_extend(rhs->generic, addr_mask) == 0) {
			return false;
		}
		result->generic = sign_extend(lhs->generic, addr_mask) / sign_extend(rhs->generic, addr_mask);
		break;
	case RzBinDwarfValueType_I8:
		if (rhs->i8 == 0) {
			return false;
		}
		result->i8 = lhs->i8 / rhs->i8;
		break;
	case RzBinDwarfValueType_U8:
		if (rhs->u8 == 0) {
			return false;
		}
		result->u8 = lhs->u8 / rhs->u8;
		break;
	case RzBinDwarfValueType_I16:
		if (rhs->i16 == 0) {
			return false;
		}
		result->i16 = lhs->i16 / rhs->i16;
		break;
	case RzBinDwarfValueType_U16:
		if (rhs->u16 == 0) {
			return false;
		}
		result->u16 = lhs->u16 / rhs->u16;
		break;
	case RzBinDwarfValueType_I32:
		if (rhs->i32 == 0) {
			return false;
		}
		result->i32 = lhs->i32 / rhs->i32;
		break;
	case RzBinDwarfValueType_U32:
		if (rhs->u32 == 0) {
			return false;
		}
		result->u32 = lhs->u32 / rhs->u32;
		break;
	case RzBinDwarfValueType_I64:
		if (rhs->i64 == 0) {
			return false;
		}
		result->i64 = lhs->i64 / rhs->i64;
		break;
	case RzBinDwarfValueType_U64:
		if (rhs->u64 == 0) {
			return false;
		}
		result->u64 = lhs->u64 / rhs->u64;
		break;
	case RzBinDwarfValueType_F32:
		if (rhs->f32 == 0) {
			return false;
		}
		result->f32 = lhs->f32 / rhs->f32;
		break;
	case RzBinDwarfValueType_F64:
		if (rhs->f64 == 0) {
			return false;
		}
		result->f64 = lhs->f64 / rhs->f64;
		break;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_rem(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	if (lhs->type != rhs->type) {
		return false;
	}

	switch (lhs->type) {
	case RzBinDwarfValueType_GENERIC:
		if ((rhs->generic & addr_mask) == 0) {
			return false;
		}
		result->generic = (lhs->generic & addr_mask) % (rhs->generic & addr_mask);
		break;
	case RzBinDwarfValueType_I8:
		if (rhs->i8 == 0) {
			return false;
		}
		result->i8 = lhs->i8 % rhs->i8;
		break;
	case RzBinDwarfValueType_U8:
		if (rhs->u8 == 0) {
			return false;
		}
		result->u8 = lhs->u8 % rhs->u8;
		break;
	case RzBinDwarfValueType_I16:
		if (rhs->i16 == 0) {
			return false;
		}
		result->i16 = lhs->i16 % rhs->i16;
		break;
	case RzBinDwarfValueType_U16:
		if (rhs->u16 == 0) {
			return false;
		}
		result->u16 = lhs->u16 % rhs->u16;
		break;
	case RzBinDwarfValueType_I32:
		if (rhs->i32 == 0) {
			return false;
		}
		result->i32 = lhs->i32 % rhs->i32;
		break;
	case RzBinDwarfValueType_U32:
		if (rhs->u32 == 0) {
			return false;
		}
		result->u32 = lhs->u32 % rhs->u32;
		break;
	case RzBinDwarfValueType_I64:
		if (rhs->i64 == 0) {
			return false;
		}
		result->i64 = lhs->i64 % rhs->i64;
		break;
	case RzBinDwarfValueType_U64:
		if (rhs->u64 == 0) {
			return false;
		}
		result->u64 = lhs->u64 % rhs->u64;
		break;
	case RzBinDwarfValueType_F32:
	case RzBinDwarfValueType_F64:
		return false;
	default:
		return false;
	}
	return true;
}

RZ_IPI bool Value_not(RzBinDwarfValue *self, ut64 addr_mask, RzBinDwarfValue *result) {
	RzBinDwarfValueType value_type = result->type;
	ut64 v;
	if (!Value_to_u64(self, addr_mask, &v)) {
		return false;
	}
	if (!Value_from_u64(value_type, ~v, result)) {
		return false;
	}
	return true;
}

RZ_IPI bool Value_and(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	RzBinDwarfValueType lhs_type = lhs->type;
	RzBinDwarfValueType rhs_type = rhs->type;
	if (lhs_type != rhs_type) {
		return false;
	}
	ut64 v1, v2;
	if (!Value_to_u64(lhs, addr_mask, &v1) || !Value_to_u64(rhs, addr_mask, &v2)) {
		return false;
	}
	if (!Value_from_u64(lhs_type, v1 & v2, result)) {
		return false;
	}
	return true;
}

RZ_IPI bool Value_or(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	RzBinDwarfValueType lhs_type = lhs->type;
	RzBinDwarfValueType rhs_type = rhs->type;
	if (lhs_type != rhs_type) {
		return false;
	}
	ut64 v1, v2;
	if (!Value_to_u64(lhs, addr_mask, &v1) || !Value_to_u64(rhs, addr_mask, &v2)) {
		return false;
	}
	if (!Value_from_u64(lhs_type, v1 | v2, result)) {
		return false;
	}
	return true;
}

RZ_IPI bool Value_xor(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	RzBinDwarfValueType lhs_type = lhs->type;
	RzBinDwarfValueType rhs_type = rhs->type;
	if (lhs_type != rhs_type) {
		return false;
	}
	ut64 v1, v2;
	if (!Value_to_u64(lhs, addr_mask, &v1) || !Value_to_u64(rhs, addr_mask, &v2)) {
		return false;
	}
	if (!Value_from_u64(lhs_type, v1 ^ v2, result)) {
		return false;
	}
	return true;
}

RZ_IPI bool Value_shift_length(RzBinDwarfValue *self, ut64 *result) {
	ut64 value = 0;
	switch (self->type) {
	case RzBinDwarfValueType_GENERIC:
		value = self->generic;
		break;
	case RzBinDwarfValueType_I8:
		if (self->i8 >= 0) {
			value = (ut64)self->i8;
		} else {
			return false;
		}
		break;
	case RzBinDwarfValueType_U8:
		value = (ut64)self->u8;
		break;
	case RzBinDwarfValueType_I16:
		if (self->i16 >= 0) {
			value = (ut64)self->i16;
		} else {
			return false;
		}
		break;
	case RzBinDwarfValueType_U16:
		value = (ut64)self->u16;
		break;
	case RzBinDwarfValueType_I32:
		if (self->i32 >= 0) {
			value = (ut64)self->i32;
		} else {
			return false;
		}
		break;
	case RzBinDwarfValueType_U32:
		value = (ut64)self->u32;
		break;
	case RzBinDwarfValueType_I64:
		if (self->i64 >= 0) {
			value = (ut64)self->i64;
		} else {
			return false;
		}
		break;
	case RzBinDwarfValueType_U64:
		value = self->u64;
		break;
	default:
		return false;
	}
	*result = value;
	return true;
}

RZ_IPI bool Value_shl(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	ut64 v2;
	RET_FALSE_IF_FAIL(Value_shift_length(rhs, &v2));

	switch (self->type) {
	case RzBinDwarfValueType_GENERIC:
		if (v2 >= mask_bit_size(addr_mask)) {
			result->type = RzBinDwarfValueType_GENERIC;
			result->generic = 0;
		} else {
			result->type = RzBinDwarfValueType_GENERIC;
			result->generic = (self->generic & addr_mask) << v2;
		}
		break;
	case RzBinDwarfValueType_I8:
		result->type = RzBinDwarfValueType_I8;
		result->i8 = (v2 >= 8) ? 0 : self->i8 << v2;
		break;
	case RzBinDwarfValueType_U8:
		result->type = RzBinDwarfValueType_U8;
		result->u8 = (v2 >= 8) ? 0 : self->u8 << v2;
		break;
	case RzBinDwarfValueType_I16:
		result->type = RzBinDwarfValueType_I16;
		result->i16 = (v2 >= 16) ? 0 : self->i16 << v2;
		break;
	case RzBinDwarfValueType_U16:
		result->type = RzBinDwarfValueType_U16;
		result->u16 = (v2 >= 16) ? 0 : self->u16 << v2;
		break;
	case RzBinDwarfValueType_I32:
		result->type = RzBinDwarfValueType_I32;
		result->i32 = (v2 >= 32) ? 0 : self->i32 << v2;
		break;
	case RzBinDwarfValueType_U32:
		result->type = RzBinDwarfValueType_U32;
		result->u32 = (v2 >= 32) ? 0 : self->u32 << v2;
		break;
	case RzBinDwarfValueType_I64:
		result->type = RzBinDwarfValueType_I64;
		result->i64 = (v2 >= 64) ? 0 : self->i64 << v2;
		break;
	case RzBinDwarfValueType_U64:
		result->type = RzBinDwarfValueType_U64;
		result->u64 = (v2 >= 64) ? 0 : self->u64 << v2;
		break;
	default:
		RZ_LOG_VERBOSE("Value_shl: unknown type %d\n", self->type)
		return false; // error handling (integral type required)
	}
	return true;
}

RZ_IPI bool Value_shr(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	ut64 v2;
	RET_FALSE_IF_FAIL(Value_shift_length(rhs, &v2));

	switch (self->type) {
	case RzBinDwarfValueType_GENERIC:
		result->type = RzBinDwarfValueType_GENERIC;
		result->generic = v2 >= 64 ? 0 : (self->generic & addr_mask) >> v2;
		break;
	case RzBinDwarfValueType_U8:
		result->type = RzBinDwarfValueType_U8;
		result->u8 = v2 >= 8 ? 0 : self->u8 >> v2;
		break;
	case RzBinDwarfValueType_U16:
		result->type = RzBinDwarfValueType_U16;
		result->u16 = v2 >= 16 ? 0 : self->u16 >> v2;
		break;
	case RzBinDwarfValueType_U32:
		result->type = RzBinDwarfValueType_U32;
		result->u32 = v2 >= 32 ? 0 : self->u32 >> v2;
		break;
	case RzBinDwarfValueType_U64:
		result->type = RzBinDwarfValueType_U64;
		result->u64 = v2 >= 64 ? 0 : self->u64 >> v2;
		break;
	default:
		return false;
	}
	return result;
}

RZ_IPI bool Value_shra(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) {
	ut64 v2;
	RET_FALSE_IF_FAIL(Value_shift_length(rhs, &v2));

	switch (self->type) {
	case RzBinDwarfValueType_GENERIC: {
		int64_t v1 = sign_extend(self->generic, addr_mask);
		result->type = RzBinDwarfValueType_GENERIC;
		result->generic = v2 >= 64 ? (v1 < 0 ? ~0 : 0) : (v1 >> v2);
	} break;
	case RzBinDwarfValueType_I8:
		result->type = RzBinDwarfValueType_I8;
		result->i8 = v2 >= 8 ? (self->i8 < 0 ? ~0 : 0) : (self->i8 >> v2);
		break;
	case RzBinDwarfValueType_I16:
		result->type = RzBinDwarfValueType_I16;
		result->i16 = v2 >= 16 ? (self->i16 < 0 ? ~0 : 0) : (self->i16 >> v2);
		break;
	case RzBinDwarfValueType_I32:
		result->type = RzBinDwarfValueType_I32;
		result->i32 = v2 >= 32 ? (self->i32 < 0 ? ~0 : 0) : (self->i32 >> v2);
		break;
	case RzBinDwarfValueType_I64:
		result->type = RzBinDwarfValueType_I64;
		result->i64 = v2 >= 64 ? (self->i64 < 0 ? ~0 : 0) : (self->i64 >> v2);
		break;
	default:
		return false;
	}
	return result;
}

#define VALUE_IMPL_LOGICAL_OP(name, op) \
	RZ_IPI bool Value_##name(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result) { \
		result->type = RzBinDwarfValueType_GENERIC; \
		result->generic = 0; \
		if (self->type != rhs->type) { \
			return result; \
		} \
		switch (self->type) { \
		case RzBinDwarfValueType_GENERIC: \
			result->generic = sign_extend(self->generic, addr_mask) op \
				sign_extend(rhs->generic, addr_mask); \
			break; \
		case RzBinDwarfValueType_I8: \
			result->generic = self->i8 op rhs->i8; \
			break; \
		case RzBinDwarfValueType_U8: \
			result->generic = self->u8 op rhs->u8; \
			break; \
		case RzBinDwarfValueType_I16: \
			result->generic = self->i16 op rhs->i16; \
			break; \
		case RzBinDwarfValueType_U16: \
			result->generic = self->u16 op rhs->u16; \
			break; \
		case RzBinDwarfValueType_I32: \
			result->generic = self->i32 op rhs->i32; \
			break; \
		case RzBinDwarfValueType_U32: \
			result->generic = self->u32 op rhs->u32; \
			break; \
		case RzBinDwarfValueType_I64: \
			result->generic = self->i64 op rhs->i64; \
			break; \
		case RzBinDwarfValueType_U64: \
			result->generic = self->u64 op rhs->u64; \
			break; \
		case RzBinDwarfValueType_F32: \
			result->generic = self->f32 op rhs->f32; \
			break; \
		case RzBinDwarfValueType_F64: \
			result->generic = self->f64 op rhs->f64; \
			break; \
		default: rz_warn_if_reached(); break; \
		} \
		return result; \
	}

VALUE_IMPL_LOGICAL_OP(eq, ==);
VALUE_IMPL_LOGICAL_OP(ge, >=);
VALUE_IMPL_LOGICAL_OP(gt, >);
VALUE_IMPL_LOGICAL_OP(le, <=);
VALUE_IMPL_LOGICAL_OP(lt, <);
VALUE_IMPL_LOGICAL_OP(ne, !=);

RZ_IPI void Value_fini(RzBinDwarfValue *self) {
	if (!self) {
		return;
	}
	if (self->type == RzBinDwarfValueType_LOCATION) {
		rz_bin_dwarf_location_free(self->location);
		self->location = NULL;
	}
}

RZ_IPI void Value_free(RzBinDwarfValue *self) {
	if (!self) {
		return;
	}
	Value_fini(self);
	free(self);
}

RZ_IPI bool Value_clone_into(RzBinDwarfValue *self, RzBinDwarfValue *val) {
	rz_return_val_if_fail(self && val, false);
	rz_mem_copy(val, sizeof(RzBinDwarfValue), self, sizeof(RzBinDwarfValue));
	if (val->type == RzBinDwarfValueType_LOCATION) {
		val->location = rz_bin_dwarf_location_clone(self->location);
	}
	return true;
}

static const char *Value_strings[] = {
	[RzBinDwarfValueType_GENERIC] = "GENERIC",
	[RzBinDwarfValueType_I8] = "I8",
	[RzBinDwarfValueType_U8] = "U8",
	[RzBinDwarfValueType_I16] = "I16",
	[RzBinDwarfValueType_U16] = "U16",
	[RzBinDwarfValueType_I32] = "I32",
	[RzBinDwarfValueType_U32] = "U32",
	[RzBinDwarfValueType_F32] = "F32",
	[RzBinDwarfValueType_I64] = "I64",
	[RzBinDwarfValueType_U64] = "U64",
	[RzBinDwarfValueType_F64] = "F64",
	[RzBinDwarfValueType_I128] = "I128",
	[RzBinDwarfValueType_U128] = "U128",
	[RzBinDwarfValueType_LOCATION] = "LOCATION",
};

RZ_IPI void Value_dump(
	const RzBinDwarfValue *self,
	RzStrBuf *sb,
	const RzBinDWARFDumpOption *opt) {
	rz_warn_if_fail(self && sb);
	if (self->type < 0 || self->type >= RZ_ARRAY_SIZE(Value_strings)) {
		rz_strbuf_append(sb, "<err:invalid value type>");
		return;
	}
	switch (self->type) {
	case RzBinDwarfValueType_GENERIC:
		rz_strbuf_appendf(sb, "+%" PFMT64x, self->generic);
		break;
	case RzBinDwarfValueType_I8:
	case RzBinDwarfValueType_I16:
	case RzBinDwarfValueType_I32:
		rz_strbuf_appendf(sb, "%+" PFMT32d, self->i32);
		break;
	case RzBinDwarfValueType_U8:
	case RzBinDwarfValueType_U16:
	case RzBinDwarfValueType_U32:
		rz_strbuf_appendf(sb, "+%" PFMT32u, self->u32);
		break;
	case RzBinDwarfValueType_I64:
		rz_strbuf_appendf(sb, "%+" PFMT64d, self->i64);
		break;
	case RzBinDwarfValueType_U64:
		rz_strbuf_appendf(sb, "+%" PFMT64u, self->u64);
		break;
	case RzBinDwarfValueType_F32:
	case RzBinDwarfValueType_F64:
		rz_strbuf_appendf(sb, "%+f", self->f64);
		break;
	case RzBinDwarfValueType_LOCATION:
		rz_bin_dwarf_location_dump(self->location, sb, opt);
		break;
	default:
		rz_strbuf_append(sb, "<unimplemented>");
		break;
	}
	if (opt->value_detail) {
		rz_strbuf_appendf(sb, " : %s", Value_strings[self->type]);
	}
}
