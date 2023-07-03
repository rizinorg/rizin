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
	RzBuffer *str_buffer;
	RzBinDwarfEncoding encoding;
} DwAttrOption;

RZ_IPI bool ListsHeader_parse(RzBinDwarfListsHeader *hdr, RzBuffer *buffer, bool big_endian);

RZ_IPI RzBinDwarfBlock *RzBinDwarfBlock_clone(RzBinDwarfBlock *self);
RZ_IPI void RzBinDwarfBlock_free(RzBinDwarfBlock *self);
RZ_IPI ut64 dwarf_read_initial_length(RZ_OUT bool *is_64bit, bool big_endian, const ut8 **buf, const ut8 *buf_end);

RZ_IPI bool buf_read_initial_length(RzBuffer *buffer, RZ_OUT bool *is_64bit, ut64 *out, bool big_endian);
RZ_IPI ut64 dwarf_read_offset(bool is_64bit, bool big_endian, const ut8 **buf, const ut8 *buf_end);
RZ_IPI bool read_offset(RzBuffer *buffer, ut64 *out, bool is_64bit, bool big_endian);
RZ_IPI ut64 dwarf_read_address(size_t size, bool big_endian, const ut8 **buf, const ut8 *buf_end);
RZ_IPI bool buf_read_block(RzBuffer *buffer, RzBinDwarfBlock *block);
RZ_IPI const char *indent_str(int indent);

RZ_IPI bool attr_parse(RzBuffer *buffer, RzBinDwarfAttr *value, DwAttrOption *in);
RZ_IPI void attr_fini(RzBinDwarfAttr *val);
RZ_IPI char *attr_to_string(RzBinDwarfAttr *attr);

RZ_IPI RzBinSection *getsection(RzBinFile *binfile, const char *sn);
RZ_IPI ut8 *get_section_bytes(RzBinFile *binfile, const char *sect_name, size_t *len);
RZ_IPI RzBuffer *get_section_buf(RzBinFile *binfile, const char *sect_name);

/// addr

RZ_IPI bool DebugAddr_get_address(const RzBinDwarfDebugAddr *self, ut64 *address,
	ut8 address_size, bool big_endian, ut64 base, ut64 index);
RZ_API RzBinDwarfDebugAddr *DebugAddr_parse(RzBinFile *bf);

/// option

typedef void (*OptionFree)(void *);

typedef struct {
	int valid; // A flag to indicate if the value is present (1) or not (0)
	void *data; // The actual value (as a void pointer)
	size_t size; // Size of the data pointed to by value
	OptionFree free;
} Option;

typedef Option *(*OptionAction)(void *);
RZ_IPI Option *Option_new(void *data, size_t size, OptionFree free_func);
#define some(x) Option_new(x, sizeof(*x), (OptionFree)free)
RZ_IPI Option *none();
RZ_IPI void Option_free(Option *opt);
RZ_IPI Option *Option_map(Option *option, OptionAction action);

/// range

RZ_IPI bool Range_parse(RzBinDwarfRange *self, RzBuffer *buffer, RzBinDwarfEncoding *encoding);
RZ_IPI inline bool Range_is_end(RzBinDwarfRange *self);
RZ_IPI inline bool Range_is_base_address(RzBinDwarfRange *self, ut8 address_size);
RZ_IPI inline void Range_add_base_address(RzBinDwarfRange *self, ut64 base_address, ut8 address_size);

RZ_IPI bool RawRngListEntry_parse(RzBinDwarfRawRngListEntry *out, RzBuffer *buffer, enum RzBinDwarfRangeListsFormat format, RzBinDwarfEncoding *encoding);

/// value

RZ_IPI Option * /*<ValueType>*/ ValueType_from_encoding(enum DW_ATE encoding, uint64_t byte_size);
RZ_IPI Option * /*<ValueType>*/ ValueType_from_entry(RzBinDwarfDie *entry);
RZ_IPI RzBinDwarfValue *Value_parse(ValueType value_type, RzBuffer *buffer, bool big_endian);
RZ_IPI ValueType Value_type(RzBinDwarfValue *ptr);
RZ_IPI bool Value_to_u64(RzBinDwarfValue *self, uint64_t addr_mask, uint64_t *result);
RZ_IPI bool Value_from_u64(ValueType value_type, uint64_t value, RzBinDwarfValue *result);
RZ_IPI bool Value_from_f32(ValueType value_type, float value, RzBinDwarfValue *result);
RZ_IPI bool Value_from_f64(ValueType value_type, double value, RzBinDwarfValue *result);

RZ_IPI bool Value_convert(RzBinDwarfValue *self, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_reinterpret(RzBinDwarfValue *self, ValueType value_type, uint64_t addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_abs(RzBinDwarfValue *self, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_neg(RzBinDwarfValue *self, uint64_t addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_add(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_sub(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_mul(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_div(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_rem(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_not(RzBinDwarfValue *self, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_and(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_or(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_xor(RzBinDwarfValue *lhs, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);

RZ_IPI bool shift_length(RzBinDwarfValue *self, uint64_t *result);
RZ_IPI bool Value_shl(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_shr(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_shra(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);

RZ_IPI bool Value_eq(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_ge(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_gt(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_le(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_lt(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);
RZ_IPI bool Value_ne(RzBinDwarfValue *self, RzBinDwarfValue *rhs, uint64_t addr_mask, RzBinDwarfValue *result);

RZ_IPI void Value_free(RzBinDwarfValue *self);

/// op

#include "op.h"

// loclists

#endif
