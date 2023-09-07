// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI bool DebugAddr_get_address(const RzBinDwarfAddr *self, ut64 *address,
	ut8 address_size, bool big_endian, ut64 base, ut64 index) {
	RzBuffer *buffer = self->buffer;
	RET_FALSE_IF_FAIL(buffer);
	rz_buf_seek(buffer, (st64)(base + (index * address_size)), RZ_BUF_SET);
	UX_OR_RET_FALSE(address_size, *address);
	return true;
}

RZ_IPI void DebugAddr_free(RzBinDwarfAddr *self) {
	if (!self) {
		return;
	}
	rz_buf_free(self->buffer);
	free(self);
}

RZ_IPI RzBinDwarfAddr *DebugAddr_from_buf(RzBuffer *buffer) {
	rz_return_val_if_fail(buffer, NULL);
	RzBinDwarfAddr *self = RZ_NEW0(RzBinDwarfAddr);
	RET_NULL_IF_FAIL(self);
	self->buffer = buffer;
	return self;
}

RZ_IPI RzBinDwarfAddr *DebugAddr_from_file(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBuffer *buffer = get_section_buf(bf, "debug_addr");
	RET_NULL_IF_FAIL(buffer);
	return DebugAddr_from_buf(buffer);
}
