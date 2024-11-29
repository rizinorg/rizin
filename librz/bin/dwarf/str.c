// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_API RZ_OWN RzBinDwarfStr *rz_bin_dwarf_str_new(RZ_NONNULL RZ_OWN RzBinEndianReader *R) {
	rz_return_val_if_fail(R, NULL);
	RzBinDwarfStr *str = RZ_NEW0(RzBinDwarfStr);
	RET_NULL_IF_FAIL(str);
	str->R = R;
	return str;
}

RZ_API RZ_OWN RzBinDwarfStr *rz_bin_dwarf_str_from_file(RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinEndianReader *r = RzBinEndianReader_from_file(
		bf, ".debug_str");
	RET_NULL_IF_FAIL(r);
	return rz_bin_dwarf_str_new(r);
}

RZ_API void rz_bin_dwarf_str_free(RZ_NULLABLE RzBinDwarfStr *str) {
	if (!str) {
		return;
	}
	R_free(str->R);
	free(str);
}

RZ_API RZ_BORROW const char *rz_bin_dwarf_str_get(RZ_NONNULL RZ_BORROW RzBinDwarfStr *str, ut64 offset) {
	rz_return_val_if_fail(str, NULL);
	const char *x = NULL;
	RET_NULL_IF_FAIL(R_seek(str->R, (st64)offset, RZ_BUF_SET) && R_read_cstring(str->R, &x));
	return x;
}
