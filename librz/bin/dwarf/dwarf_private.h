// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DWARF_PRIVATE_H
#define RZ_DWARF_PRIVATE_H

#include <rz_util.h>
#include <rz_bin_dwarf.h>
#include "macro.h"

static inline char *str_escape_copy(const char *p) {
	if (!p) {
		return NULL;
	}
	RzStrEscOptions opt = {
		.dot_nl = true,
		.esc_bslash = true,
		.esc_double_quotes = true,
		.show_asciidot = false
	};
	return rz_str_escape_utf8(p, &opt);
}

static inline void str_escape(char **p) {
	if (!(p && *p)) {
		return;
	}
	char *out = str_escape_copy(*p);
	free(*p);
	*p = out;
}

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

/// range

RZ_IPI bool Range_parse(RzBinDwarfRange *self, RzBinEndianReader *reader, ut8 address_size);
RZ_IPI bool Range_is_end(RzBinDwarfRange *self);
RZ_IPI bool Range_is_base_address(RzBinDwarfRange *self, ut8 address_size);
RZ_IPI void Range_add_base_address(RzBinDwarfRange *self, ut64 base_address, ut8 address_size);
RZ_IPI void Range_free(RzBinDwarfRange *self);

RZ_IPI void DebugRngLists_free(RzBinDwarfRngLists *self);

#include "value.h"
#include "op.h"

RZ_IPI void rz_bin_dwarf_evaluation_cpy(RzBinDwarfEvaluation *dst, RzBinDwarfEvaluation *src);
RZ_IPI void RzBinDwarfEvaluationResult_cpy(RzBinDwarfEvaluationResult *dst, RzBinDwarfEvaluationResult *src);

#endif
