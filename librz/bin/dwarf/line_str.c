// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_API RZ_OWN RzBinDwarfLineStr *rz_bin_dwarf_line_str_new(RZ_NONNULL RZ_OWN RzBinEndianReader *reader) {
	return RzBinDwarfStr_new(reader);
}
RZ_API RZ_OWN RzBinDwarfLineStr *rz_bin_dwarf_line_str_from_file(RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	RzBinEndianReader *r = RzBinEndianReader_from_file(bf, ".debug_line_str");
	RET_NULL_IF_FAIL(r);
	return RzBinDwarfStr_new(r);
}
RZ_API void rz_bin_dwarf_line_str_free(RzBinDwarfLineStr *str) {
	RzBinDwarfStr_free(str);
}
RZ_API RZ_BORROW const char *rz_bin_dwarf_line_str_get(RZ_NONNULL RZ_BORROW RzBinDwarfLineStr *str, ut64 offset) {
	return RzBinDwarfStr_get(str, offset);
}
