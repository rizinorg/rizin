// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

Ht_FREE_IMPL(UP, string, free);

RZ_IPI void RzBinDwarfStr_free(RzBinDwarfStr *str) {
	if (!str) {
		return;
	}
	ht_up_free(str->str_by_offset);
	RzBinEndianReader_free(str->reader);
	free(str);
}

RZ_IPI RzBinDwarfStr *RzBinDwarfStr_new(RZ_NONNULL RZ_OWN RzBinEndianReader *reader) {
	rz_return_val_if_fail(reader, NULL);
	RzBinDwarfStr *str = RZ_NEW0(RzBinDwarfStr);
	RET_NULL_IF_FAIL(str);
	str->reader = reader;
	str->str_by_offset = ht_up_new(NULL, HtUP_string_free, NULL);
	if (!str->str_by_offset) {
		free(str);
		return NULL;
	}
	return str;
}

RZ_IPI RzBinDwarfStr *RzBinDwarfStr_from_file(RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinEndianReader *r = RzBinEndianReader_from_file(bf, ".debug_str");
	RET_NULL_IF_FAIL(r);
	return RzBinDwarfStr_new(r);
}

RZ_IPI char *RzBinDwarfStr_get(RzBinDwarfStr *str, ut64 offset) {
	rz_return_val_if_fail(str, NULL);
	char *string = ht_up_find(str->str_by_offset, offset, NULL);
	if (!string) {
		rz_buf_seek(str->reader->buffer, (st64)offset, RZ_BUF_SET);
		string = read_string(str->reader);
		if (string) {
			ht_up_update(str->str_by_offset, offset, string);
		}
	}
	return string;
}

RZ_IPI void RzBinDwarfStr_read_all(RzBinDwarfStr *str) {
	rz_return_if_fail(str);
	while (rz_buf_tell(str->reader->buffer) < rz_buf_size(str->reader->buffer)) {
		RzBinDwarfStr_get(str, rz_buf_tell(str->reader->buffer));
	}
}

RZ_API RZ_OWN RzBinDwarfStr *rz_bin_dwarf_str_new(RZ_NONNULL RZ_OWN RzBinEndianReader *reader) {
	return RzBinDwarfStr_new(reader);
}
RZ_API RZ_OWN RzBinDwarfStr *rz_bin_dwarf_str_from_file(RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	return RzBinDwarfStr_from_file(bf);
}
RZ_API void rz_bin_dwarf_str_free(RzBinDwarfStr *str) {
	RzBinDwarfStr_free(str);
}
RZ_API RZ_BORROW const char *rz_bin_dwarf_str_get(RZ_NONNULL RZ_BORROW RzBinDwarfStr *str, ut64 offset) {
	return RzBinDwarfStr_get(str, offset);
}
