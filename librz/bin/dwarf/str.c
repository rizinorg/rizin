// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

Ht_FREE_IMPL(UP, string, free);

RZ_IPI void RzBinDwarfDebugStr_free(RzBinDwarfDebugStr *debug_str) {
	if (!debug_str) {
		return;
	}
	ht_up_free(debug_str->str_by_offset);
	rz_buf_free(debug_str->buffer);
	free(debug_str);
}

RZ_IPI RzBinDwarfDebugStr *RzBinDwarfDebugStr_from_buf(RZ_NONNULL RZ_OWN RzBuffer *buffer) {
	rz_return_val_if_fail(buffer, NULL);
	RzBinDwarfDebugStr *debug_str = RZ_NEW0(RzBinDwarfDebugStr);
	RET_NULL_IF_FAIL(debug_str);
	debug_str->buffer = buffer;
	debug_str->str_by_offset = ht_up_new(NULL, HtUP_string_free, NULL);
	if (!debug_str->str_by_offset) {
		free(debug_str);
		return NULL;
	}
	return debug_str;
}

RZ_IPI RzBinDwarfDebugStr *RzBinDwarfDebugStr_from_file(RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBuffer *buffer = get_section_buf(bf, "debug_str");
	RET_NULL_IF_FAIL(buffer);
	return RzBinDwarfDebugStr_from_buf(buffer);
}

RZ_IPI char *RzBinDwarfDebugStr_get(RzBinDwarfDebugStr *debug_str, ut64 offset) {
	rz_return_val_if_fail(debug_str, NULL);
	char *string = ht_up_find(debug_str->str_by_offset, offset, NULL);
	if (!string) {
		rz_buf_seek(debug_str->buffer, (st64)offset, RZ_BUF_SET);
		string = buf_get_string(debug_str->buffer);
		if (string) {
			ht_up_update(debug_str->str_by_offset, offset, string);
		}
	}
	return string;
}

RZ_API RZ_OWN RzBinDwarfDebugStr *rz_bin_dwarf_str_from_buf(RZ_NONNULL RZ_OWN RzBuffer *buffer) {
	return RzBinDwarfDebugStr_from_buf(buffer);
}
RZ_API RZ_OWN RzBinDwarfDebugStr *rz_bin_dwarf_str_from_file(RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	return RzBinDwarfDebugStr_from_file(bf);
}
RZ_API void rz_bin_dwarf_str_free(RzBinDwarfDebugStr *str) {
	RzBinDwarfDebugStr_free(str);
}
RZ_API RZ_BORROW const char *rz_bin_dwarf_str_get(RZ_NONNULL RZ_BORROW RzBinDwarfDebugStr *str, ut64 offset) {
	return RzBinDwarfDebugStr_get(str, offset);
}