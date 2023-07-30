// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

/**
 * \brief Read an "initial length" value, as specified by dwarf.
 * This also determines whether it is 64bit or 32bit and reads 4 or 12 bytes respectively.
 */
RZ_IPI bool buf_read_initial_length(RzBuffer *buffer, RZ_OUT bool *is_64bit, ut64 *out, bool big_endian) {
	static const ut64 DWARF32_UNIT_LENGTH_MAX = 0xfffffff0;
	static const ut64 DWARF64_UNIT_LENGTH_INI = 0xffffffff;
	ut32 x32;
	if (!rz_buf_read_ble32(buffer, &x32, big_endian)) {
		return false;
	}
	if (x32 <= DWARF32_UNIT_LENGTH_MAX) {
		*is_64bit = false;
		*out = x32;
	} else if (x32 == DWARF64_UNIT_LENGTH_INI) {
		ut64 x64;
		if (!rz_buf_read_ble64(buffer, &x64, big_endian)) {
			return false;
		}
		*is_64bit = true;
		*out = x64;
	} else {
		RZ_LOG_ERROR("Invalid initial length: 0x%" PFMT32x "\n", x32);
	}
	return true;
}

/**
 * \brief Reads 64/32 bit unsigned based on format
 *
 * \param is_64bit Format of the comp unit
 * \return ut64 Read value
 */
RZ_IPI bool buf_read_offset(RzBuffer *buffer, ut64 *out, bool is_64bit, bool big_endian) {
	if (is_64bit) {
		U_OR_RET_FALSE(64, *out);
	} else {
		U_OR_RET_FALSE(32, *out);
	}
	return true;
}

RZ_IPI bool buf_read_block(RzBuffer *buffer, RzBinDwarfBlock *block) {
	if (block->length == 0) {
		return true;
	}
	if (block->length >= RZ_ARRAY_SIZE(block->data)) {
		block->ptr = RZ_NEWS0(ut8, block->length);
		RET_FALSE_IF_FAIL(block->ptr);
		ut16 len = rz_buf_read(buffer, block->ptr, block->length);
		if (len != block->length) {
			RZ_FREE(block->ptr);
			return false;
		}
		return true;
	}
	return rz_buf_read(buffer, block->data, block->length) == block->length;
}

RZ_IPI char *buf_get_string(RzBuffer *buffer) {
	st64 offset = (st64)rz_buf_tell(buffer);
	RET_NULL_IF_FAIL(offset != -1);
	char *x = rz_buf_get_string(buffer, offset);
	RET_NULL_IF_FAIL(x);
	ut64 len = strlen(x) + 1;
	rz_buf_seek(buffer, (st64)len, SEEK_CUR);
	if (len <= 1) {
		free(x);
		return NULL;
	}
	return x;
}
