static inline int leading_zeros(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
	return __builtin_clzll(x);
#else
	int n = 0;
	if (x == 0)
		return 64;

	if (x <= 0x00000000FFFFFFFFULL) {
		n = n + 32;
		x = x << 32;
	}
	if (x <= 0x0000FFFFFFFFFFFFULL) {
		n = n + 16;
		x = x << 16;
	}
	if (x <= 0x00FFFFFFFFFFFFFFULL) {
		n = n + 8;
		x = x << 8;
	}
	if (x <= 0x0FFFFFFFFFFFFFFFULL) {
		n = n + 4;
		x = x << 4;
	}
	if (x <= 0x3FFFFFFFFFFFFFFFULL) {
		n = n + 2;
		x = x << 2;
	}
	if (x <= 0x7FFFFFFFFFFFFFFFULL) {
		n = n + 1;
	}

	return n;
#endif
}

static inline int64_t sign_extend(uint64_t value, uint64_t mask) {
	int64_t masked_value = (int64_t)(value & mask);
	int64_t sign = (int64_t)((mask >> 1) + 1);
	return (masked_value ^ sign) - sign;
}

static inline uint32_t mask_bit_size(uint64_t addr_mask) {
	return 64 - leading_zeros(addr_mask);
}

// Assuming ValueType is an enum defined elsewhere
typedef enum {
	ValueType_GENERIC,
	I8,
	U8,
	I16,
	U16,
	I32,
	U32,
	F32,
	I64,
	U64,
	F64
} ValueType;

typedef struct {
	ValueType type;
	union {
		ut64 generic;
		ut8 u8;
		st8 i8;
		ut16 u16;
		st16 i16;
		ut32 u32;
		st32 i32;
		ut64 u64;
		st64 i64;
		float f32;
		double f64;
	};
} Value;

void value_type(Value *ptr);
// Assuming constants are defined elsewhere
// and mask_bit_size is defined elsewhere
uint32_t bit_size(ValueType type, uint64_t addr_mask) {
	switch (type) {
	case ValueType_GENERIC:
		return mask_bit_size(addr_mask);
	case I8:
	case U8:
		return 8;
	case I16:
	case U16:
		return 16;
	case I32:
	case U32:
	case F32:
		return 32;
	case I64:
	case U64:
	case F64:
		return 64;
	default:
		return 0; // Undefined ValueType
	}
}

Option * /*<ValueType>*/ ValueType_from_encoding(enum DW_ATE encoding, uint64_t byte_size) {
	st16 value_type = -1;
	switch (encoding) {
	case DW_ATE_signed:
		switch (byte_size) {
		case 1: value_type = I8; break;
		case 2: value_type = I16; break;
		case 4: value_type = I32; break;
		case 8: value_type = I64; break;
		}
		break;
	case DW_ATE_unsigned:
		switch (byte_size) {
		case 1: value_type = U8; break;
		case 2: value_type = U16; break;
		case 4: value_type = U32; break;
		case 8: value_type = U64; break;
		}
		break;
	case DW_ATE_float:
		switch (byte_size) {
		case 4: value_type = F32; break;
		case 8: value_type = F64; break;
		}
		break;
	case DW_ATE_address: break;
	case DW_ATE_boolean: break;
	case DW_ATE_complex_float: break;
	case DW_ATE_signed_char: break;
	case DW_ATE_unsigned_char: break;
	case DW_ATE_imaginary_float: break;
	case DW_ATE_packed_decimal: break;
	case DW_ATE_numeric_string: break;
	case DW_ATE_edited: break;
	case DW_ATE_signed_fixed: break;
	case DW_ATE_unsigned_fixed: break;
	case DW_ATE_decimal_float: break;
	case DW_ATE_UTF: break;
	case DW_ATE_lo_user: break;
	case DW_ATE_hi_user: break;
	}
	if (value_type == -1) {
		return none();
	}
	return some(&value_type);
}

Option * /*<ValueType>*/ ValueType_from_entry(RzBinDwarfDie *entry) {
	if (entry->tag != DW_TAG_base_type) {
		return none(); // Represents Option::None in Rust
	}

	enum DW_ATE encoding = -1;
	uint64_t byte_size = 0;
	int endianity = DW_END_default;

	RzBinDwarfAttr *attr; // Assuming Attribute is defined elsewhere

	rz_vector_foreach(&entry->attrs, attr) switch (attr->name) {
	case DW_AT_byte_size:
		byte_size = attr->uconstant;
		break;
	case DW_AT_encoding:
		encoding = attr->uconstant; // Assuming value contains the encoding
		break;
	case DW_AT_endianity:
		endianity = attr->uconstant; // Assuming value contains the endianity
		break;
	default:
		break;
	}

	if (endianity != DW_END_default) {
		return none(); // Represents Option::None in Rust
	}

	if (encoding != -1 && byte_size != 0) {
		return ValueType_from_encoding(encoding, byte_size);
	} else {
		return none(); // Represents Option::None in Rust
	}
}

Value *Value_parse(ValueType value_type, RzBuffer *buffer, bool big_endian) {
	Value *value = (Value *)malloc(sizeof(Value));
	if (!value) {
		// handle allocation error
		return NULL;
	}

	switch (value_type) {
	case I8:
		U8_OR_RET_NULL(value->i8);
		value->i8 = (st8)value->i8;
		break;
	case U8:
		U8_OR_RET_NULL(value->u8);
		break;
	case I16:
		U16_OR_RET_NULL(value->u16);
		value->i16 = (st16)value->u16;
		break;
	case U16:
		U16_OR_RET_NULL(value->u16);
		break;
	case I32:
		U32_OR_RET_NULL(value->u32);
		value->i32 = (st32)value->u32;
		break;
	case U32:
		U8_OR_RET_NULL(value->u32);
		break;
	case I64:
		U8_OR_RET_NULL(value->u64);
		value->i64 = (st64)value->u64;
		break;
	case U64:
		U8_OR_RET_NULL(value->u64);
		break;
	case F32:
		U8_OR_RET_NULL(value->u32);
		value->f32 = (float)value->u32;
		break;
	case F64:
		U8_OR_RET_NULL(value->u64);
		value->f64 = (float)value->u64;
		break;
	default:
		free(value);
		return NULL;
	}

	return value;
}

ValueType Value_type(Value *ptr) {
	if (ptr == NULL) {
		return -1;
	}
	return ptr->type;
}

bool to_u64(Value value, uint64_t addr_mask, uint64_t *result) {
	switch (Value_type(&value)) {
	case ValueType_GENERIC:
		*result = value.generic & addr_mask;
		break;
	case I8:
		*result = (uint64_t)value.i8;
		break;
	case U8:
		*result = value.u8;
		break;
	case I16:
		*result = (uint64_t)value.i16;
		break;
	case U16:
		*result = value.u16;
		break;
	case I32:
		*result = (uint64_t)value.i32;
		break;
	case U32:
		*result = value.u32;
		break;
	case I64:
		*result = (uint64_t)value.i64;
		break;
	case U64:
		*result = value.u64;
		break;
	default:
		// Handle integral type required error
		return false;
	}
	return true;
}

bool from_u64(ValueType value_type, uint64_t value, Value *result) {
	switch (value_type) {
	case ValueType_GENERIC:
		result->generic = value;
		break;
	case I8:
		result->i8 = (int8_t)value;
		break;
	case U8:
		result->u8 = (uint8_t)value;
		break;
	case I16:
		result->i16 = (int16_t)value;
		break;
	case U16:
		result->u16 = (uint16_t)value;
		break;
	case I32:
		result->i32 = (int32_t)value;
		break;
	case U32:
		result->u32 = (uint32_t)value;
		break;
	case I64:
		result->i64 = (int64_t)value;
		break;
	case U64:
		result->u64 = value;
		break;
	case F32:
		result->f32 = (float)value;
		break;
	case F64:
		result->f64 = (double)value;
		break;
	default:
		return false;
	}
	return true;
}

bool from_f32(ValueType value_type, float value, Value *result) {
	switch (value_type) {
	case ValueType_GENERIC:
		result->generic = (uint64_t)value;
		break;
	case I8:
		result->i8 = (int8_t)value;
		break;
	case U8:
		result->u8 = (uint8_t)value;
		break;
	case I16:
		result->i16 = (int16_t)value;
		break;
	case U16:
		result->u16 = (uint16_t)value;
		break;
	case I32:
		result->i32 = (int32_t)value;
		break;
	case U32:
		result->u32 = (uint32_t)value;
		break;
	case I64:
		result->i64 = (int64_t)value;
		break;
	case U64:
		result->u64 = (uint64_t)value;
		break;
	case F32:
		result->f32 = value;
		break;
	case F64:
		result->f64 = (double)value;
		break;
	default:
		return false;
	}
	return true;
}

bool from_f64(ValueType value_type, double value, Value *result) {
	switch (value_type) {
	case ValueType_GENERIC:
		result->generic = (uint64_t)value;
		break;
	case I8:
		result->i8 = (int8_t)value;
		break;
	case U8:
		result->u8 = (uint8_t)value;
		break;
	case I16:
		result->i16 = (int16_t)value;
		break;
	case U16:
		result->u16 = (uint16_t)value;
		break;
	case I32:
		result->i32 = (int32_t)value;
		break;
	case U32:
		result->u32 = (uint32_t)value;
		break;
	case I64:
		result->i64 = (int64_t)value;
		break;
	case U64:
		result->u64 = (uint64_t)value;
		break;
	case F32:
		result->f32 = (float)value;
		break;
	case F64:
		result->f64 = value;
		break;
	default:
		return false;
	}
	return true;
}

bool convert(Value *self, ValueType value_type, uint64_t addr_mask, Value *result) {
	switch (value_type) {
	case F32:
		return from_f32(value_type, self->f32, result);
	case F64:
		return from_f64(value_type, self->f64, result);
	default:
		return from_u64(value_type, self->u64 & addr_mask, result);
	}
}

bool reinterpret(Value *self, ValueType value_type, uint64_t addr_mask, Value *result) {
	uint64_t bits;

	// Assuming that you have functions `value_type_bit_size` and `sign_extend` implemented elsewhere

	if (bit_size(self->type, addr_mask) != bit_size(value_type, addr_mask)) {
		return false;
	}

	// You need to define logic for copying bits from one type to another
	// Similar to how it is done in Rust (e.g. u64::from(f32::to_bits(value)))

	// After setting `bits`, create the value
	return from_u64(value_type, bits, result);
}

bool abs_value(Value *self, uint64_t addr_mask, Value *result) {
	switch (self->type) {
	case ValueType_GENERIC:
		result->generic = (uint64_t)llabs(sign_extend(self->generic, addr_mask));
		break;
	case I8:
		result->i8 = abs(self->i8);
		break;
	case I16:
		result->i16 = abs(self->i16);
		break;
	case I32:
		result->i32 = abs(self->i32);
		break;
	case I64:
		result->i64 = llabs(self->i64);
		break;
	case F32:
		result->f32 = fabsf(self->f32);
		break;
	case F64:
		result->f64 = fabs(self->f64);
		break;
	default:
		return false;
	}
	return true;
}

bool neg_value(Value *self, uint64_t addr_mask, Value *result) {
	switch (self->type) {
	case ValueType_GENERIC:
		result->generic = (uint64_t)(-sign_extend(self->generic, addr_mask));
		break;
	case I8:
		result->i8 = -self->i8;
		break;
	case I16:
		result->i16 = -self->i16;
		break;
	case I32:
		result->i32 = -self->i32;
		break;
	case I64:
		result->i64 = -self->i64;
		break;
	case F32:
		result->f32 = -self->f32;
		break;
	case F64:
		result->f64 = -self->f64;
		break;
	default:
		return false;
	}
	return true;
}
