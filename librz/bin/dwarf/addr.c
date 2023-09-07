// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI bool DebugAddr_get_address(const RzBinDwarfAddr *self, ut64 *address,
	ut8 address_size, ut64 base, ut64 index) {
	RzBinEndianReader *reader = self->reader;
	RET_FALSE_IF_FAIL(reader);
	rz_buf_seek(reader->buffer, (st64)(base + (index * address_size)), RZ_BUF_SET);
	UX_OR_RET_FALSE(address_size, *address);
	return true;
}

RZ_IPI void DebugAddr_free(RzBinDwarfAddr *self) {
	if (!self) {
		return;
	}
	rz_buf_free(self->reader->buffer);
	free(self);
}

RZ_IPI RzBinDwarfAddr *DebugAddr_new(RzBinEndianReader *reader) {
	rz_return_val_if_fail(reader, NULL);
	RzBinDwarfAddr *self = RZ_NEW0(RzBinDwarfAddr);
	RET_NULL_IF_FAIL(self);
	self->reader = reader;
	return self;
}

RZ_IPI RzBinDwarfAddr *DebugAddr_from_file(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinEndianReader *r = RzBinEndianReader_from_file(bf, ".debug_addr");
	RET_NULL_IF_FAIL(r);
	return DebugAddr_new(r);
}
