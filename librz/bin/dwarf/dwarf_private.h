// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DWARF_PRIVATE_H
#define RZ_DWARF_PRIVATE_H

#include <rz_util.h>
#include <rz_bin_dwarf.h>
#include "macro.h"
#include "endian_reader.h"

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

RZ_IPI bool ListsHdr_parse(RzBinDwarfListsHdr *hdr, RzBinEndianReader *R);

RZ_IPI RzBinSection *rz_bin_dwarf_section_by_name(RzBinFile *binfile, const char *sn);

RZ_IPI bool RzBinDwarfAttr_parse(RzBinEndianReader *R, RzBinDwarfAttr *attr, AttrOption *opt);

RZ_IPI RzBinEndianReader *RzBinEndianReader_from_file(
	RzBinFile *binfile, const char *sect_name);

static inline bool bf_bigendian(RzBinFile *bf) {
	return bf->o && bf->o->info && bf->o->info->big_endian;
}

RZ_IPI bool RzBinDwarfEncoding_from_file(RzBinDwarfEncoding *encoding, RzBinFile *bf);

/// range

RZ_IPI bool Range_parse(RzBinDwarfRange *self, RzBinEndianReader *R, ut8 address_size);
RZ_IPI bool Range_is_end(RzBinDwarfRange *self);
RZ_IPI bool Range_is_base_address(RzBinDwarfRange *self, ut8 address_size);
RZ_IPI void Range_add_base_address(RzBinDwarfRange *self, ut64 base_address, ut8 address_size);
RZ_IPI void Range_free(RzBinDwarfRange *self);

RZ_IPI void RngLists_free(RzBinDwarfRngLists *self);

#include "value.h"
#include "op.h"

RZ_IPI void rz_bin_dwarf_evaluation_cpy(RzBinDwarfEvaluation *dst, RzBinDwarfEvaluation *src);
RZ_IPI void RzBinDwarfEvaluationResult_cpy(RzBinDwarfEvaluationResult *dst, RzBinDwarfEvaluationResult *src);

static inline char *str_escape_utf8_copy(const char *p) {
	rz_return_val_if_fail(p, NULL);
	RzStrEscOptions opt = {
		.dot_nl = true,
		.esc_bslash = true,
		.esc_double_quotes = true,
		.show_asciidot = false,
		.keep_printable = true
	};
	return rz_str_escape_utf8(p, &opt);
}

static inline void strbuf_append_string_own(RzStrBuf *b, char *own) {
	if (!own) {
		return;
	}
	rz_strbuf_append(b, own);
	free(own);
}

#endif
