// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_API RZ_OWN RzBinDwarfStrOffsets *rz_bin_dwarf_str_offsets_from_buf(
	RZ_NONNULL RZ_OWN RzBinEndianReader *R) {
	rz_return_val_if_fail(R, NULL);
	RzBinDwarfStrOffsets *str_offsets = RZ_NEW0(RzBinDwarfStrOffsets);
	RET_NULL_IF_FAIL(str_offsets);
	str_offsets->R = R;

	ERR_IF_FAIL(R_read_initial_length(
		R, &str_offsets->encoding.is_64bit, &str_offsets->unit_length));
	U_OR_GOTO(16, str_offsets->encoding.version, err);
	U_OR_GOTO(16, str_offsets->padding, err);
	return str_offsets;
err:
	rz_bin_dwarf_str_offsets_free(str_offsets);
	return NULL;
}

RZ_API RZ_OWN RzBinDwarfStrOffsets *rz_bin_dwarf_str_offsets_from_file(
	RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinEndianReader *r = RzBinEndianReader_from_file(
		bf, ".debug_str_offsets");
	RET_NULL_IF_FAIL(r);
	return rz_bin_dwarf_str_offsets_from_buf(r);
}

RZ_API void rz_bin_dwarf_str_offsets_free(RZ_NULLABLE RzBinDwarfStrOffsets *str_offsets) {
	if (!str_offsets) {
		return;
	}
	R_free(str_offsets->R);
	free(str_offsets);
}

RZ_API RZ_BORROW const char *rz_bin_dwarf_str_offsets_get(
	RZ_NONNULL RZ_BORROW RzBinDwarfStr *str,
	RZ_NONNULL RZ_BORROW RzBinDwarfStrOffsets *str_offsets,
	ut64 base, ut64 index) {
	rz_return_val_if_fail(str && str_offsets && index >= 0, NULL);
	st64 offsets_offset = (st64)(base + index * (str_offsets->encoding.is_64bit ? 8 : 4));
	OK_OR(R_seek(str_offsets->R, offsets_offset, SEEK_SET), return NULL);
	ut64 offset = 0;
	OK_OR(R_read_offset(str_offsets->R, &offset, str_offsets->encoding.is_64bit), return NULL);
	return rz_bin_dwarf_str_get(str, offset);
}
