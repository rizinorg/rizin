// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_API const ut8 *rz_bin_dwarf_block_data(const RzBinDwarfBlock *self) {
	return self->length < RZ_ARRAY_SIZE(self->data) ? self->data : self->ptr;
}

RZ_IPI RzBinDwarfBlock *RzBinDwarfBlock_clone(RzBinDwarfBlock *self) {
	RzBinDwarfBlock *clone = rz_new_copy(sizeof(RzBinDwarfBlock), self);
	if (!clone) {
		return NULL;
	}
	RzBinDwarfBlock_cpy(self, clone);
	return clone;
}

RZ_IPI RzBinDwarfBlock *RzBinDwarfBlock_cpy(RzBinDwarfBlock *self, RzBinDwarfBlock *out) {
	rz_return_val_if_fail(self && out, NULL);
	if (self->length == 0) {
		return out;
	}
	if (self->length >= RZ_ARRAY_SIZE(self->data)) {
		out->ptr = RZ_NEWS0(ut8, self->length);
		if (!out->ptr) {
			return NULL;
		}
	}
	out->length = self->length;
	memcpy((ut8 *)rz_bin_dwarf_block_data(out), rz_bin_dwarf_block_data(self), self->length);
	return out;
}

RZ_API bool rz_bin_dwarf_block_valid(const RzBinDwarfBlock *self) {
	rz_return_val_if_fail(self, NULL);
	if (self->length == 0) {
		return true;
	}
	if (self->length >= RZ_ARRAY_SIZE(self->data)) {
		return self->ptr != NULL;
	}
	return true;
}

RZ_API bool rz_bin_dwarf_block_empty(const RzBinDwarfBlock *self) {
	rz_return_val_if_fail(self, NULL);
	return self->length == 0;
}

RZ_IPI RzBuffer *RzBinDwarfBlock_as_buf(const RzBinDwarfBlock *self) {
	return rz_buf_new_with_bytes(rz_bin_dwarf_block_data(self), self->length);
}

RZ_IPI bool RzBinDwarfBlock_move(RzBinDwarfBlock *self, RzBinDwarfBlock *out) {
	rz_return_val_if_fail(self && out, false);
	if (self->length == 0) {
		return out;
	}
	RzBinDwarfBlock_cpy(self, out);
	self->ptr = NULL;
	self->length = 0;
	return true;
}

RZ_API void rz_bin_dwarf_block_dump(const RzBinDwarfBlock *self, RzStrBuf *sb) {
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

RZ_IPI void RzBinDwarfBlock_fini(RzBinDwarfBlock *self) {
	if (!self) {
		return;
	}
	if (self->length >= RZ_ARRAY_SIZE(self->data)) {
		RZ_FREE(self->ptr);
	}
	self->length = 0;
}

RZ_IPI void RzBinDwarfBlock_free(RzBinDwarfBlock *self) {
	if (!self) {
		return;
	}
	RzBinDwarfBlock_fini(self);
	free(self);
}
