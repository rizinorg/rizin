// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include <string.h>

#ifndef RZ_ENDIAN_READER_H
#define RZ_ENDIAN_READER_H

RZ_IPI RZ_OWN RzBinEndianReader *rz_bin_dwarf_section_reader(
	RZ_BORROW RZ_NONNULL RzBinFile *binfile,
	RZ_BORROW RZ_NONNULL RzBinSection *section);
RZ_IPI ut64 R_relocate(RzBinEndianReader *R, ut64 offset, ut64 value);

static inline RzBinEndianReader *RzBinEndianReader_new(
	ut8 *data, ut64 len, bool big_endian, bool owned, HtUP *relocations) {
	rz_return_val_if_fail(data, NULL);
	RzBinEndianReader *R = RZ_NEW0(RzBinEndianReader);
	if (!R) {
		return NULL;
	}
	R->data = data;
	R->owned = owned;
	R->length = len;
	R->big_endian = big_endian;
	R->relocations = relocations;
	return R;
}

static inline ut8 *R_data(RzBinEndianReader *R) {
	rz_return_val_if_fail(R, NULL);
	return R->data + R->offset;
}

static inline ut8 *R_end(RzBinEndianReader *R) {
	rz_return_val_if_fail(R, NULL);
	return R->data + R->length;
}

static inline ut64 R_size(RzBinEndianReader *R) {
	rz_return_val_if_fail(R, 0);
	return R->length;
}

static inline ut64 R_remain(RzBinEndianReader *R) {
	rz_return_val_if_fail(R, 0);
	if (R->length > R->offset) {
		return R->length - R->offset;
	}
	return 0;
}

static inline bool R_seek(RzBinEndianReader *R, st64 offset, int whence) {
	rz_return_val_if_fail(R, false);
	switch (whence) {
	case SEEK_CUR: R->offset += offset; break;
	case SEEK_SET:
		if (offset < 0) {
			return -1;
		}
		R->offset = offset;
		break;
	case SEEK_END:
		if (offset > 0) {
			return -1;
		}
		R->offset = R->length + offset;
		break;
	default: return false;
	}
	return true;
}

static inline ut64 R_tell(RzBinEndianReader *R) {
	rz_return_val_if_fail(R, 0);
	return R->offset;
}

static inline void R_free(RzBinEndianReader *R) {
	if (R == NULL) {
		return;
	}
	if (R->owned) {
		free(R->data);
		ht_up_free(R->relocations);
	}
	free(R);
}

static inline bool R_clone(const RzBinEndianReader *R, RzBinEndianReader *dst) {
	rz_return_val_if_fail(R && dst, false);
	memcpy(dst, R, sizeof(RzBinEndianReader));
	R_seek(dst, 0, SEEK_SET);
	return true;
}

#define READX_IMPL(T, F, B) \
	static inline bool R_read##B(RzBinEndianReader *R, T *x) { \
		rz_return_val_if_fail(R, false); \
		if (!(R->data && R->offset + (B / 8) <= R->length)) { \
			return false; \
		} \
		if (x) { \
			*x = F; \
		} \
		R->offset += (B / 8); \
		return true; \
	}

READX_IMPL(ut8, rz_read_at_ble8(R->data, R->offset), 8);
READX_IMPL(ut16, rz_read_at_ble16(R->data, R->offset, R->big_endian), 16);
READX_IMPL(ut32, rz_read_at_ble24(R->data, R->offset, R->big_endian), 24);
READX_IMPL(ut32, rz_read_at_ble32(R->data, R->offset, R->big_endian), 32);
READX_IMPL(ut64, rz_read_at_ble64(R->data, R->offset, R->big_endian), 64);
READX_IMPL(ut128, rz_read_at_ble128(R->data, R->offset, R->big_endian), 128);
#undef READX_IMPL

static inline bool R_read_ule128(RzBinEndianReader *R, ut64 *x) {
	rz_return_val_if_fail(R, false);
	if (!(R->data && R->offset + 1 <= R->length)) {
		return false;
	}
	ut64 len = read_u64_leb128(R_data(R), R_end(R), x);
	R->offset += len;
	return len > 0;
}

static inline bool R_read_sle128(RzBinEndianReader *R, st64 *x) {
	rz_return_val_if_fail(R, false);
	if (!(R->data && R->offset + 1 <= R->length)) {
		return false;
	}
	ut64 len = read_i64_leb128(R_data(R), R_end(R), x);
	R->offset += len;
	return len > 0;
}

static inline bool R_read_cstring(RzBinEndianReader *R, const char **x) {
	rz_return_val_if_fail(R && x, false);
	if (!(R->data && R->offset + 1 <= R->length)) {
		return false;
	}
	ut64 len = rz_str_nlen((char *)R_data(R), R_remain(R));
	*x = (const char *)R_data(R);
	R->offset += len + 1;
	return true;
}

static inline bool R_read(RzBinEndianReader *R, ut8 *x, ut64 length) {
	rz_return_val_if_fail(R && x && length, false);
	if (!(R->data && R->offset + length <= R->length)) {
		return false;
	}
	rz_mem_copy(x, length, R_data(R), R_remain(R));
	R->offset += length;
	return true;
}

static inline bool R_take(RzBinEndianReader *R, const ut8 **x, ut64 length) {
	rz_return_val_if_fail(R && length, false);
	if (!(R->data && R->offset + length <= R->length)) {
		return false;
	}
	if (x) {
		*x = R_data(R);
	}
	R->offset += length;
	return true;
}

static inline bool R_split(RzBinEndianReader *R, ut64 length, RzBinEndianReader *o) {
	rz_return_val_if_fail(R && o && length, false);
	if (!(R->data && R->offset + length <= R->length)) {
		return false;
	}
	memcpy(o, R, sizeof(RzBinEndianReader));
	o->data = R_data(R);
	o->offset = 0;
	o->length = length;
	o->owned = false;
	R->offset += length;
	return true;
}

static inline bool R_read_block(RzBinEndianReader *R, RzBinEndianReader *x) {
	rz_return_val_if_fail(R && x, false);
	if (!(R->data && R->offset + x->length <= R->length)) {
		return false;
	}
	x->data = R_data(R);
	x->offset = 0;
	x->owned = false;
	R->offset += x->length;
	return true;
}

/**
 * \brief Read an "initial length" value, as specified by dwarf.
 * This also determines whether it is 64bit or 32bit and reads 4 or 12 bytes respectively.
 */
static inline bool R_read_initial_length(RzBinEndianReader *R, RZ_OUT bool *is_64bit, ut64 *out) {
	rz_return_val_if_fail(R && is_64bit && out, false);
	static const ut64 DWARF32_UNIT_LENGTH_MAX = 0xfffffff0;
	static const ut64 DWARF64_UNIT_LENGTH_INI = 0xffffffff;
	ut32 x32;
	if (!R_read32(R, &x32)) {
		return false;
	}
	if (x32 <= DWARF32_UNIT_LENGTH_MAX) {
		*is_64bit = false;
		*out = x32;
	} else if (x32 == DWARF64_UNIT_LENGTH_INI) {
		ut64 x64;
		if (!R_read64(R, &x64)) {
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
static inline bool R_read_offset(RzBinEndianReader *R, ut64 *out, bool is_64bit) {
	rz_return_val_if_fail(R && out, false);
	ut64 offset = R_tell(R);
	if (is_64bit) {
		U_OR_RET_FALSE(64, *out);
	} else {
		U_OR_RET_FALSE(32, *out);
	}
	*out = R_relocate(R, offset, *out);
	return true;
}

static inline bool R_read_address(RzBinEndianReader *R, ut64 *out, ut8 address_size) {
	rz_return_val_if_fail(R && out, false);
	ut64 offset = R_tell(R);
	switch (address_size) {
	case 1: READ8_OR(ut8, *out, goto err); break;
	case 2: READ_UT_OR(16, *out, goto err); break;
	case 4: READ_UT_OR(32, *out, goto err); break;
	case 8: READ_UT_OR(64, *out, goto err); break;
	default: RZ_LOG_ERROR("DWARF: unexpected address size: %u\n", (unsigned)address_size); goto err;
	}
	*out = R_relocate(R, offset, *out);
	return true;
err:
	return false;
}

#endif // RZ_ENDIAN_READER_H
