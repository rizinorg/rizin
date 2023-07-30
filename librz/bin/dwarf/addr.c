// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI bool DebugAddr_get_address(const RzBinDwarfDebugAddr *self, ut64 *address,
	ut8 address_size, bool big_endian, ut64 base, ut64 index) {
	RzBuffer *buffer = rz_buf_new_with_buf(self->buffer);
	RET_FALSE_IF_FAIL(buffer);
	rz_buf_seek(buffer, (st64)base, RZ_BUF_CUR);
	rz_buf_seek(buffer, (st64)(index * address_size), RZ_BUF_CUR);
	ut64 addr = 0;
	UX_OR_RET_FALSE(address_size, addr);
	*address = addr;
	return true;
}

RZ_IPI void DebugAddr_free(RzBinDwarfDebugAddr *self) {
	if (!self) {
		return;
	}
	rz_buf_free(self->buffer);
	free(self);
}

RZ_IPI RzBinDwarfDebugAddr *DebugAddr_parse(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}

	RzBuffer *buffer = get_section_buf(bf, ".debug_addr");
	RET_NULL_IF_FAIL(buffer);
	RzBinDwarfDebugAddr *self = RZ_NEW0(RzBinDwarfDebugAddr);
	if (!self) {
		rz_buf_free(buffer);
		return NULL;
	}
	self->buffer = buffer;
	return self;
}
