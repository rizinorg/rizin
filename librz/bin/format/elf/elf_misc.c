// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool buffer_read_32_signed(ELFOBJ *bin, ut64 *offset, st32 *result) {
	ut32 tmp;
	if (!rz_buf_read_ble32_at(bin->b, *offset, &tmp, bin->big_endian)) {
		return false;
	}

	*result = convert_to_two_complement_32(tmp);
	*offset += 4;

	return true;
}

static bool buffer_read_64_signed(ELFOBJ *bin, ut64 *offset, st64 *result) {
	ut64 tmp;

	if (!rz_buf_read_ble64_at(bin->b, *offset, &tmp, bin->big_endian)) {
		return false;
	}

	*result = convert_to_two_complement_64(tmp);
	*offset += 8;

	return true;
}

bool Elf_(rz_bin_elf_check_array)(RZ_NONNULL ELFOBJ *bin, Elf_(Off) offset, Elf_(Off) length, Elf_(Off) entry_size) {
	rz_return_val_if_fail(bin, false);

	Elf_(Off) array_size;
	if (!Elf_(rz_bin_elf_mul_off)(&array_size, length, entry_size)) {
		return false;
	}

	Elf_(Off) end_off;
	if (!Elf_(rz_bin_elf_add_off)(&end_off, offset, array_size)) {
		return false;
	}

	if (!array_size || end_off > bin->size) {
		return false;
	}

	return true;
}

bool Elf_(rz_bin_elf_read_char)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT ut8 *result) {
	rz_return_val_if_fail(bin && offset && result, false);
	return rz_buf_read8_offset(bin->b, offset, result);
}

bool Elf_(rz_bin_elf_read_half)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Half) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
	return rz_buf_read_ble16_offset(bin->b, offset, result, bin->big_endian);
}

bool Elf_(rz_bin_elf_read_word)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Word) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
	return rz_buf_read_ble32_offset(bin->b, offset, result, bin->big_endian);
}

bool Elf_(rz_bin_elf_read_sword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Sword) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
	return buffer_read_32_signed(bin, offset, result);
}

bool Elf_(rz_bin_elf_read_xword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Xword) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
	return rz_buf_read_ble64_offset(bin->b, offset, (ut64 *)result, bin->big_endian);
}

bool Elf_(rz_bin_elf_read_sxword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Sxword) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
	return buffer_read_64_signed(bin, offset, (st64 *)result);
}

bool Elf_(rz_bin_elf_read_addr)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Addr) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
#if RZ_BIN_ELF64
	return rz_buf_read_ble64_offset(bin->b, offset, (ut64 *)result, bin->big_endian);
#else
	return rz_buf_read_ble32_offset(bin->b, offset, (ut32 *)result, bin->big_endian);
#endif
}

bool Elf_(rz_bin_elf_read_off)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Off) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
#if RZ_BIN_ELF64
	return rz_buf_read_ble64_offset(bin->b, offset, (ut64 *)result, bin->big_endian);
#else
	return rz_buf_read_ble32_offset(bin->b, offset, (ut32 *)result, bin->big_endian);
#endif
}

bool Elf_(rz_bin_elf_read_section)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Section) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
	return rz_buf_read_ble16_offset(bin->b, offset, (ut16 *)result, bin->big_endian);
}

bool Elf_(rz_bin_elf_read_versym)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Versym) * result) {
	rz_return_val_if_fail(bin && offset && result, false);
	return Elf_(rz_bin_elf_read_half)(bin, offset, result);
}

#if RZ_BIN_ELF64
bool Elf_(rz_bin_elf_read_word_xword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Xword) * result) {
	rz_return_val_if_fail(bin && offset && result, false);

	return Elf_(rz_bin_elf_read_xword)(bin, offset, result);
}
#else
bool Elf_(rz_bin_elf_read_word_xword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Word) * result) {
	rz_return_val_if_fail(bin && offset && result, false);

	return Elf_(rz_bin_elf_read_word)(bin, offset, result);
}
#endif

#if RZ_BIN_ELF64
bool Elf_(rz_bin_elf_read_sword_sxword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Sxword) * result) {
	rz_return_val_if_fail(bin && offset && result, false);

	return Elf_(rz_bin_elf_read_sxword)(bin, offset, result);
}
#else
bool Elf_(rz_bin_elf_read_sword_sxword)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL RZ_INOUT ut64 *offset, RZ_NONNULL RZ_OUT Elf_(Sword) * result) {
	rz_return_val_if_fail(bin && offset && result, false);

	return Elf_(rz_bin_elf_read_sword)(bin, offset, result);
}
#endif

bool Elf_(rz_bin_elf_add_addr)(Elf_(Addr) * result, Elf_(Addr) addr, Elf_(Addr) value) {
#if RZ_BIN_ELF64
	return UT64_ADD((ut64 *)result, addr, value);
#else
	return UT32_ADD((ut32 *)result, addr, value);
#endif
}

bool Elf_(rz_bin_elf_add_off)(Elf_(Off) * result, Elf_(Off) addr, Elf_(Off) value) {
#if RZ_BIN_ELF64
	return UT64_ADD((ut64 *)result, addr, value);
#else
	return UT32_ADD((ut32 *)result, addr, value);
#endif
}

bool Elf_(rz_bin_elf_mul_addr)(Elf_(Addr) * result, Elf_(Addr) addr, Elf_(Addr) value) {
#if RZ_BIN_ELF64
	return UT64_MUL((ut64 *)result, addr, value);
#else
	return UT32_MUL((ut32 *)result, addr, value);
#endif
}

bool Elf_(rz_bin_elf_mul_off)(Elf_(Off) * result, Elf_(Off) addr, Elf_(Off) value) {
#if RZ_BIN_ELF64
	return UT64_MUL((ut64 *)result, addr, value);
#else
	return UT32_MUL((ut32 *)result, addr, value);
#endif
}
