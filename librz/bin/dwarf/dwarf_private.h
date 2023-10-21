// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DWARF_PRIVATE_H
#define RZ_DWARF_PRIVATE_H

#include <rz_util.h>
#include <rz_bin_dwarf.h>
#include "macro.inc"

typedef struct {
	ut64 unit_offset;
	RzBinDwarfEncoding *encoding;
	DW_AT at;
	DW_FORM form;
	ut64 implicit_const;
	RzBinDWARF *dw;
} AttrOption;

typedef RzBinDwarfValue Value;
typedef RzBinDwarfLocation Location;

RZ_IPI bool ListsHdr_parse(RzBinDwarfListsHdr *hdr, RzBinEndianReader *reader);

RZ_IPI bool RzBinDwarfBlock_move(RzBinDwarfBlock *self, RzBinDwarfBlock *out);
RZ_IPI RzBinDwarfBlock *RzBinDwarfBlock_cpy(RzBinDwarfBlock *self, RzBinDwarfBlock *out);
RZ_IPI RzBinDwarfBlock *RzBinDwarfBlock_clone(RzBinDwarfBlock *self);
RZ_IPI RzBinEndianReader *RzBinDwarfBlock_as_reader(const RzBinDwarfBlock *self);
RZ_IPI void RzBinDwarfBlock_fini(RzBinDwarfBlock *self);
RZ_IPI void RzBinDwarfBlock_free(RzBinDwarfBlock *self);

RZ_IPI RzBinSection *rz_bin_dwarf_section_by_name(RzBinFile *binfile, const char *sn, bool is_dwo);
RZ_IPI RzBuffer *rz_bin_dwarf_section_buf(RzBinFile *binfile, RzBinSection *section);

RZ_IPI bool read_initial_length(RzBinEndianReader *reader, RZ_OUT bool *is_64bit, ut64 *out);
RZ_IPI bool read_offset(RzBinEndianReader *reader, ut64 *out, bool is_64bit);
RZ_IPI bool read_address(RzBinEndianReader *reader, ut64 *out, ut8 address_size);
RZ_IPI bool read_block(RzBinEndianReader *reader, RzBinDwarfBlock *block);
RZ_IPI char *read_string(RzBinEndianReader *reader);
RZ_IPI char *read_string_not_empty(RzBinEndianReader *reader);
RZ_IPI void RzBinEndianReader_free(RzBinEndianReader *r);
RZ_IPI RzBinEndianReader *RzBinEndianReader_clone(RzBinEndianReader *x);

RZ_IPI bool RzBinDwarfAttr_parse(RzBinEndianReader *reader, RzBinDwarfAttr *attr, AttrOption *opt);
RZ_IPI void RzBinDwarfAttr_fini(RzBinDwarfAttr *attr);

RZ_IPI RzBinEndianReader *RzBinEndianReader_from_file(
	RzBinFile *binfile, const char *sect_name, bool is_dwo);

static inline bool bf_bigendian(RzBinFile *bf) {
	return bf->o && bf->o->info && bf->o->info->big_endian;
}

RZ_IPI bool RzBinDwarfEncoding_from_file(RzBinDwarfEncoding *encoding, RzBinFile *bf);
/// addr

RZ_IPI bool DebugAddr_get_address(const RzBinDwarfAddr *self, ut64 *address,
	ut8 address_size, ut64 base, ut64 index);
RZ_IPI void DebugAddr_free(RzBinDwarfAddr *self);
RZ_IPI RzBinDwarfAddr *DebugAddr_new(RzBinEndianReader *reader);
RZ_IPI RzBinDwarfAddr *DebugAddr_from_file(RzBinFile *bf);

/// range

RZ_IPI bool Range_parse(RzBinDwarfRange *self, RzBinEndianReader *reader, ut8 address_size);
RZ_IPI bool Range_is_end(RzBinDwarfRange *self);
RZ_IPI bool Range_is_base_address(RzBinDwarfRange *self, ut8 address_size);
RZ_IPI void Range_add_base_address(RzBinDwarfRange *self, ut64 base_address, ut8 address_size);
RZ_IPI void Range_free(RzBinDwarfRange *self);

RZ_IPI void DebugRngLists_free(RzBinDwarfRngLists *self);

/// value

RZ_IPI bool ValueType_from_encoding(DW_ATE encoding, ut64 byte_size, RzBinDwarfValueType *out_type);
RZ_IPI bool ValueType_from_entry(RzBinDwarfDie *entry, RzBinDwarfValueType *out);
RZ_IPI bool Value_parse_into(
	RzBinDwarfValue *value, RzBinDwarfValueType value_type, RzBinEndianReader *reader);
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
RZ_IPI RzBinDwarfValue *Value_clone(RzBinDwarfValue *self);
RZ_IPI bool Value_clone_into(RzBinDwarfValue *self, RzBinDwarfValue *val);
RZ_IPI void Value_dump(
	RZ_BORROW RZ_NONNULL const RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NULLABLE DWARF_RegisterMapping dwarf_register_mapping,
	const RzBinDwarfValue *self,
	RzStrBuf *sb,
	const char *sep,
	const char *indent);
/// op

#include "op.h"

#endif
