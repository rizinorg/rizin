// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DWARF_PRIVATE_H
#define RZ_DWARF_PRIVATE_H

#include <rz_util.h>
#include <rz_bin_dwarf.h>
#include "macro.inc"

typedef enum {
	DW_ATTR_TYPE_DEF,
	DW_ATTR_TYPE_FILE_ENTRY_FORMAT,
} DwAttrType;

typedef struct {
	DwAttrType type;
	union {
		RzBinDwarfAttrDef *def;
		RzBinDwarfFileEntryFormat *format;
	};
	union {
		RzBinDwarfLineHeader *line_hdr;
		RzBinDwarfCompUnitHdr *comp_unit_hdr;
	};
	RzBinDwarfDebugStr *debug_str;
	RzBinDwarfEncoding encoding;
} DwAttrOption;

RZ_IPI bool ListsHeader_parse(RzBinDwarfListsHeader *hdr, RzBuffer *buffer, bool big_endian);

RZ_IPI bool RzBinDwarfBlock_move(RzBinDwarfBlock *self, RzBinDwarfBlock *out);
RZ_IPI RzBinDwarfBlock *RzBinDwarfBlock_cpy(RzBinDwarfBlock *self, RzBinDwarfBlock *out);
RZ_IPI RzBinDwarfBlock *RzBinDwarfBlock_clone(RzBinDwarfBlock *self);
RZ_IPI RzBuffer *RzBinDwarfBlock_as_buf(const RzBinDwarfBlock *self);
RZ_IPI void RzBinDwarfBlock_fini(RzBinDwarfBlock *self);
RZ_IPI void RzBinDwarfBlock_free(RzBinDwarfBlock *self);

RZ_IPI bool buf_read_initial_length(RzBuffer *buffer, RZ_OUT bool *is_64bit, ut64 *out, bool big_endian);
RZ_IPI bool buf_read_offset(RzBuffer *buffer, ut64 *out, bool is_64bit, bool big_endian);
RZ_IPI bool buf_read_block(RzBuffer *buffer, RzBinDwarfBlock *block);
RZ_IPI char *buf_get_string(RzBuffer *buffer);

RZ_IPI bool RzBinDwarfAttr_parse(RzBuffer *buffer, RzBinDwarfAttr *value, DwAttrOption *opt);
RZ_IPI void RzBinDwarfAttr_fini(RzBinDwarfAttr *val);
RZ_IPI char *RzBinDwarfAttr_to_string(RzBinDwarfAttr *attr);

RZ_IPI RzBinSection *get_section(RzBinFile *binfile, const char *sn);
RZ_IPI RzBuffer *get_section_buf(RzBinFile *binfile, const char *sect_name);
RZ_IPI bool RzBinDwarfEncoding_from_file(RzBinDwarfEncoding *encoding, RzBinFile *bf);

static inline bool bf_bigendian(RzBinFile *bf) {
	return bf->o && bf->o->info && bf->o->info->big_endian;
}
/// addr

RZ_IPI bool DebugAddr_get_address(const RzBinDwarfDebugAddr *self, ut64 *address,
	ut8 address_size, bool big_endian, ut64 base, ut64 index);
RZ_IPI void DebugAddr_free(RzBinDwarfDebugAddr *self);
RZ_IPI RzBinDwarfDebugAddr *DebugAddr_from_buf(RzBuffer *buffer);
RZ_IPI RzBinDwarfDebugAddr *DebugAddr_from_file(RzBinFile *bf);

/// range

RZ_IPI bool Range_parse(RzBinDwarfRange *self, RzBuffer *buffer, RzBinDwarfEncoding *encoding);
RZ_IPI bool Range_is_end(RzBinDwarfRange *self);
RZ_IPI bool Range_is_base_address(RzBinDwarfRange *self, ut8 address_size);
RZ_IPI void Range_add_base_address(RzBinDwarfRange *self, ut64 base_address, ut8 address_size);
RZ_IPI void Range_free(RzBinDwarfRange *self);

RZ_IPI bool RzBinDwarfRawRngListEntry_parse(RzBinDwarfRawRngListEntry *out, RzBuffer *buffer, RzBinDwarfEncoding *encoding, RzBinDwarfRngListsFormat format);
RZ_IPI void RzBinDwarfRngListTable_free(RzBinDwarfRngListTable *self);

/// value

RZ_IPI bool ValueType_from_encoding(DW_ATE encoding, ut64 byte_size, RzBinDwarfValueType *out_type);
RZ_IPI bool ValueType_from_entry(RzBinDwarfDie *entry, RzBinDwarfValueType *out);
RZ_IPI RzBinDwarfValue *Value_parse(RzBinDwarfValueType value_type, RzBuffer *buffer, bool big_endian);
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
RZ_IPI void Value_dump(
	RZ_BORROW RZ_NONNULL const RzBinDwarfEncoding *encoding,
	RZ_BORROW RZ_NULLABLE DWARF_RegisterMapping dwarf_register_mapping,
	const RzBinDwarfValue *self,
	RzStrBuf *sb,
	const char *sep,
	const char *indent);
/// op

#include "op.h"

/// debug_lines

/**
 * \brief Opaque cache for fully resolved filenames during Dwarf Line Info Generation
 * This cache stores full file paths to be optionally used in RzBinDwarfLineOp_run().
 * It is strictly associated with the RzBinDwarfLineHeader it has been created with in rz_bin_dwarf_line_header_new_file_cache()
 * and must be freed with the same header in rz_bin_dwarf_line_header_free_file_cache().
 */
typedef RzPVector /*<char *>*/ RzBinDwarfLineFilePathCache;

typedef struct {
	const RzBinDwarfLineHeader *hdr;
	RzBinDwarfSMRegisters *regs;
	RzBinSourceLineInfoBuilder *source_line_info_builder;
	RzBinDwarfDebugInfo *debug_info;
	RzBinDwarfLineFilePathCache *file_path_cache;
} DWLineOpEvalContext;

RZ_IPI char *RzBinDwarfLineHeader_full_file_path(DWLineOpEvalContext *ctx, ut64 file_index);
RZ_IPI ut64 RzBinDwarfLineHeader_adj_opcode(const RzBinDwarfLineHeader *hdr, ut8 opcode);
RZ_IPI ut64 RzBinDwarfLineHeader_spec_op_advance_pc(const RzBinDwarfLineHeader *hdr, ut8 opcode);
RZ_IPI st64 RzBinDwarfLineHeader_spec_op_advance_line(const RzBinDwarfLineHeader *hdr, ut8 opcode);
RZ_IPI void RzBinDwarfSMRegisters_reset(const RzBinDwarfLineHeader *hdr, RzBinDwarfSMRegisters *regs);
RZ_IPI bool RzBinDwarfLineOp_run(RZ_NONNULL RZ_BORROW RzBinDwarfLineOp *op, RZ_NONNULL RZ_BORROW RZ_INOUT DWLineOpEvalContext *ctx);

/// debug_str
RZ_IPI void RzBinDwarfDebugStr_free(RzBinDwarfDebugStr *debug_str);
RZ_IPI char *RzBinDwarfDebugStr_get(RzBinDwarfDebugStr *debug_str, ut64 offset);
RZ_IPI RzBinDwarfDebugStr *RzBinDwarfDebugStr_from_buf(RZ_NONNULL RZ_OWN RzBuffer *buffer);
RZ_IPI RzBinDwarfDebugStr *RzBinDwarfDebugStr_from_file(RZ_NONNULL RZ_BORROW RzBinFile *bf);

#endif
