// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_API RZ_OWN RzBinDwarfStrOffsets *rz_bin_dwarf_str_offsets_from_buf(
	RZ_NONNULL RZ_OWN RzBinEndianReader *reader) {
	rz_return_val_if_fail(reader, NULL);
	RzBinDwarfStrOffsets *str_offsets = RZ_NEW0(RzBinDwarfStrOffsets);
	RET_NULL_IF_FAIL(str_offsets);
	str_offsets->reader = reader;
	str_offsets->offsets = rz_vector_new(sizeof(ut64), NULL, NULL);
	ERR_IF_FAIL(str_offsets->offsets);

	ERR_IF_FAIL(read_initial_length(
		reader, &str_offsets->encoding.is_64bit, &str_offsets->unit_length));
	U_OR_GOTO(16, str_offsets->encoding.version, err);
	U_OR_GOTO(16, str_offsets->padding, err);
	return str_offsets;
err:
	rz_bin_dwarf_str_offsets_free(str_offsets);
	return NULL;
}

RZ_API RZ_OWN RzBinDwarfStrOffsets *rz_bin_dwarf_str_offsets_from_file(
	RZ_NONNULL RZ_BORROW RzBinFile *bf, bool is_dwo) {
	rz_return_val_if_fail(bf, NULL);
	RzBinEndianReader *r = RzBinEndianReader_from_file(
		bf, ".debug_str_offsets", is_dwo);
	RET_NULL_IF_FAIL(r);
	return rz_bin_dwarf_str_offsets_from_buf(r);
}

RZ_API void rz_bin_dwarf_str_offsets_free(RZ_NULLABLE RzBinDwarfStrOffsets *str_offsets) {
	if (!str_offsets) {
		return;
	}
	rz_vector_free(str_offsets->offsets);
	RzBinEndianReader_free(str_offsets->reader);
	free(str_offsets);
}

RZ_API RZ_BORROW const char *rz_bin_dwarf_str_offsets_get(
	RZ_NONNULL RZ_BORROW RzBinDwarfStr *str,
	RZ_NONNULL RZ_BORROW RzBinDwarfStrOffsets *str_offsets,
	ut64 base, ut64 index) {
	rz_return_val_if_fail(str && str_offsets && index >= 0, NULL);
	RzBinEndianReader *reader = str_offsets->reader;
	ut64 offset = 0;
	OK_OR(rz_buf_seek(reader->buffer, (st64)base, RZ_BUF_SET) >= 0, return NULL);
	OK_OR(rz_buf_seek(reader->buffer,
		      (st64)index * (str_offsets->encoding.is_64bit ? 8 : 4), RZ_BUF_CUR) >= 0,
		return NULL);
	OK_OR(read_offset(reader, &offset, str_offsets->encoding.is_64bit), return NULL);
	return rz_bin_dwarf_str_get(str, offset);
}
