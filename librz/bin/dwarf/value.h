// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef VALUE_H
#define VALUE_H

RZ_IPI bool ValueType_from_encoding(DW_ATE encoding, ut64 byte_size, RzBinDwarfValueType *out_type);
RZ_IPI bool ValueType_from_entry(RzBinDwarfDie *entry, RzBinDwarfValueType *out);
RZ_IPI bool Value_parse_into(
	RzBinDwarfValue *value, RzBinDwarfValueType value_type, RzBinEndianReader *R);
RZ_IPI RzBinDwarfValueType Value_type(RzBinDwarfValue *ptr);
RZ_IPI bool Value_to_u64(RzBinDwarfValue *self, ut64 addr_mask, ut64 *result);
RZ_IPI bool Value_from_u64(RzBinDwarfValueType value_type, ut64 value, RzBinDwarfValue *result);
RZ_IPI bool Value_from_f32(RzBinDwarfValueType value_type, float value, RzBinDwarfValue *result);
RZ_IPI bool Value_from_f64(RzBinDwarfValueType value_type, double value, RzBinDwarfValue *result);

RZ_IPI bool Value_convert(RzBinDwarfValue *self, RzBinDwarfValueType typ, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_reinterpret(RzBinDwarfValue *self, RzBinDwarfValueType value_type, ut64 addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_abs(RzBinDwarfValue *self, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_neg(RzBinDwarfValue *self, ut64 addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_add(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_sub(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_mul(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_div(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_rem(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_not(RzBinDwarfValue *self, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_and(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_or(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_xor(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_shift_length(RzBinDwarfValue *self, ut64 *result);
RZ_IPI bool Value_shl(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_shr(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_shra(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_eq(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_ge(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_gt(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_le(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_lt(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_ne(RzBinDwarfValue *self, RzBinDwarfValue *rhs, ut64 addr_mask, RzBinDwarfValue *result);

RZ_IPI void Value_fini(RzBinDwarfValue *self);
RZ_IPI void Value_free(RzBinDwarfValue *self);
RZ_IPI bool Value_clone_into(RzBinDwarfValue *self, RzBinDwarfValue *val);
static inline void Value_cpy(RzBinDwarfValue *dst, RzBinDwarfValue *src) {
	Value_clone_into(src, dst);
}
RZ_IPI void Value_dump(
	const RzBinDwarfValue *self,
	RzStrBuf *sb,
	const RzBinDWARFDumpOption *opt);

#endif // VALUE_H
