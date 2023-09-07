// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin_dwarf.h>
#include "dwarf_private.h"

RZ_IPI void RzBinDwarfStrOffsets_free(RzBinDwarfStrOffsets *debug_str_offsets) {
	if (!debug_str_offsets) {
		return;
	}
	rz_vector_free(debug_str_offsets->str_offsets);
	rz_buf_free(debug_str_offsets->buffer);
	free(debug_str_offsets);
}

RZ_IPI RzBinDwarfStrOffsets *RzBinDwarfStrOffsets_from_buf(
	RZ_NONNULL RZ_OWN RzBuffer *buffer, bool big_endian) {
	rz_return_val_if_fail(buffer, NULL);
	RzBinDwarfStrOffsets *debug_str_offsets = RZ_NEW0(RzBinDwarfStrOffsets);
	RET_NULL_IF_FAIL(debug_str_offsets);
	debug_str_offsets->buffer = buffer;
	debug_str_offsets->str_offsets = rz_vector_new(sizeof(ut64), NULL, NULL);
	ERR_IF_FAIL(debug_str_offsets->str_offsets);

	debug_str_offsets->big_endian = big_endian;
	ERR_IF_FAIL(read_initial_length(
		buffer, &debug_str_offsets->encoding.is_64bit, &debug_str_offsets->unit_length, big_endian));
	U_OR_GOTO(16, debug_str_offsets->encoding.version, err);
	U_OR_GOTO(16, debug_str_offsets->padding, err);

	while (true) {
		ut64 offset;
		if (debug_str_offsets->encoding.is_64bit) {
			U_OR_GOTO(64, offset, ok);
		} else {
			U_OR_GOTO(32, offset, ok);
		}
		rz_vector_push(debug_str_offsets->str_offsets, &offset);
	}
ok:
	return debug_str_offsets;
err:
	RzBinDwarfStrOffsets_free(debug_str_offsets);
	return NULL;
}

RZ_IPI RzBinDwarfStrOffsets *RzBinDwarfStrOffsets_from_file(
	RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	RzBuffer *buffer = get_section_buf(bf, "debug_str_offsets");
	RET_NULL_IF_FAIL(buffer);
	return RzBinDwarfStrOffsets_from_buf(buffer, bf_bigendian(bf));
}

RZ_IPI char *RzBinDwarfStrOffsets_get(RzBinDwarfStr *debug_str, RzBinDwarfStrOffsets *debug_str_offsets, ut64 base, ut64 index) {
	rz_return_val_if_fail(debug_str && debug_str_offsets && index >= 0, NULL);
	if (index >= rz_vector_len(debug_str_offsets->str_offsets)) {
		return NULL;
	}
	ut64 offset = *(ut64 *)rz_vector_index_ptr(debug_str_offsets->str_offsets, index);
	return RzBinDwarfStr_get(debug_str, offset);
}

RZ_API RZ_OWN RzBinDwarfStrOffsets *rz_bin_dwarf_str_offsets_from_buf(
	RZ_NONNULL RZ_OWN RzBuffer *buffer, bool big_endian) {
	return RzBinDwarfStrOffsets_from_buf(buffer, big_endian);
}
RZ_API RZ_OWN RzBinDwarfStrOffsets *rz_bin_dwarf_str_offsets_from_file(
	RZ_NONNULL RZ_BORROW RzBinFile *bf) {
	return RzBinDwarfStrOffsets_from_file(bf);
}
RZ_API void rz_bin_dwarf_str_offsets_free(RzBinDwarfStrOffsets *str_offsets) {
	RzBinDwarfStrOffsets_free(str_offsets);
}
RZ_API RZ_BORROW const char *rz_bin_dwarf_str_offsets_get(
	RZ_NONNULL RZ_BORROW RzBinDwarfStr *debug_str,
	RZ_NONNULL RZ_BORROW RzBinDwarfStrOffsets *debug_str_offsets,
	ut64 base,
	ut64 index) {
	return RzBinDwarfStrOffsets_get(debug_str, debug_str_offsets, base, index);
}
