// SPDX-FileCopyrightText: 2017-2019 condret <condr3t@protonmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_util.h>
#include <rz_types.h>
#include "io_private.h"

//This helper function only check if the given vaddr is mapped, it does not account
//for map perms
RZ_API bool rz_io_addr_is_mapped(RzIO *io, ut64 vaddr) {
	rz_return_val_if_fail(io, false);
	return (io->va && rz_io_map_get(io, vaddr));
}

// when io.va is true this checks if the highest priorized map at this
// offset has the same or high permissions set. When there is no map it
// check for the current desc permissions and size.
// when io.va is false it only checks for the desc
RZ_API bool rz_io_is_valid_offset(RzIO *io, ut64 offset, int hasperm) {
	rz_return_val_if_fail(io, false);
	if (io->va) {
		if (!hasperm) {
			// return rz_io_map_is_mapped (io, offset);
			RzIOMap *map = rz_io_map_get(io, offset);
			return map ? map->perm & RZ_PERM_R : false;
		}
		RzIOMap *map = rz_io_map_get(io, offset);
		return map ? (map->perm & hasperm) == hasperm : false;
	}
	if (!io->desc) {
		return false;
	}
	if (offset > rz_io_desc_size(io->desc)) {
		return false;
	}
	return ((io->desc->perm & hasperm) == hasperm);
}

// this is wrong, there is more than big and little endian
RZ_API bool rz_io_read_i(RzIO *io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	rz_return_val_if_fail(io && val, false);
	size = RZ_DIM(size, 1, 8);
	if (!rz_io_read_at(io, addr, buf, size)) {
		return false;
	}
	//size says the number of bytes to read transform to bits for rz_read_ble
	*val = rz_read_ble(buf, endian, size * 8);
	return true;
}

RZ_API bool rz_io_write_i(RzIO *io, ut64 addr, ut64 *val, int size, bool endian) {
	ut8 buf[8];
	rz_return_val_if_fail(io && val, false);
	size = RZ_DIM(size, 1, 8);
	//size says the number of bytes to read transform to bits for rz_read_ble
	rz_write_ble(buf, *val, endian, size * 8);
	return rz_io_write_at(io, addr, buf, size) == size;
}
