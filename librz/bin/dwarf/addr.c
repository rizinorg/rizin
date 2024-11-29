// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_API bool rz_bin_dwarf_addr_get(
	RZ_BORROW RZ_NONNULL const RzBinDwarfAddr *self,
	RZ_BORROW RZ_NONNULL ut64 *address,
	ut8 address_size, ut64 base, ut64 index) {
	rz_return_val_if_fail(self && self->R && address, false);
	RzBinEndianReader *R = self->R;
	RET_FALSE_IF_FAIL(R);
	R_seek(R, (st64)(base + (index * address_size)), RZ_BUF_SET);
	RET_FALSE_IF_FAIL(R_read_address(self->R, address, address_size));
	return true;
}

RZ_API void rz_bin_dwarf_addr_free(RzBinDwarfAddr *self) {
	if (!self) {
		return;
	}
	R_free(self->R);
	free(self);
}

RZ_API RZ_OWN RzBinDwarfAddr *rz_bin_dwarf_addr_new(RZ_OWN RZ_NONNULL RzBinEndianReader *R) {
	rz_return_val_if_fail(R, NULL);
	RzBinDwarfAddr *self = RZ_NEW0(RzBinDwarfAddr);
	RET_NULL_IF_FAIL(self);
	self->R = R;
	return self;
}

RZ_API RZ_OWN RzBinDwarfAddr *rz_bin_dwarf_addr_from_file(RZ_BORROW RZ_NONNULL RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBinEndianReader *r = RzBinEndianReader_from_file(bf, ".debug_addr");
	RET_NULL_IF_FAIL(r);
	return rz_bin_dwarf_addr_new(r);
}
