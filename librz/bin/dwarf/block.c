// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>

RZ_API RZ_BORROW const ut8 *rz_bin_dwarf_block_data(RZ_NONNULL const RzBinDwarfBlock *self) {
	rz_return_val_if_fail(self, NULL);
	return self->data;
}

RZ_API bool rz_bin_dwarf_block_empty(RZ_NULLABLE const RzBinDwarfBlock *self) {
	return !self || self->length == 0;
}

RZ_API void rz_bin_dwarf_block_dump(RZ_NONNULL const RzBinDwarfBlock *self, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(self && sb);
	if (self->length == 0) {
		rz_strbuf_appendf(sb, " <null>");
		return;
	}
	char *str = rz_hex_bin2strdup(rz_bin_dwarf_block_data(self), (int)self->length);
	if (!str) {
		rz_strbuf_append(sb, " <error>");
		return;
	}
	rz_strbuf_appendf(sb, " 0x%s", str);
	free(str);
}
