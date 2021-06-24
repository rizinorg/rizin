// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf_strtab.h"
#include "elf.h"

RZ_OWN RzBinElfStrtab *Elf_(rz_bin_elf_new_strtab)(RZ_NONNULL ELFOBJ *bin, ut64 offset, ut64 size) {
	rz_return_val_if_fail(bin, NULL);

	if (!size || !Elf_(rz_bin_elf_check_array)(bin, offset, size, sizeof(ut8))) {
		RZ_LOG_WARN("Invalid strtab 0x%" PFMT64x, offset);
		return NULL;
	}

	RzBinElfStrtab *result = RZ_NEW(RzBinElfStrtab);
	if (!result) {
		return NULL;
	}

	result->size = size;
	result->data = RZ_NEWS(char, size);
	if (!result->data) {
		Elf_(rz_bin_elf_free_strtab)(result);
		return NULL;
	}

	if (rz_buf_read_at(bin->b, offset, (ut8 *)result->data, size) < 0) {
		Elf_(rz_bin_elf_free_strtab)(result);
		return NULL;
	}

	if (result->data[0] != '\0' || result->data[size - 1] != '\0') {
		RZ_LOG_WARN("String table 0x%" PFMT64x "should start and end by a NULL byte", offset);
		Elf_(rz_bin_elf_free_strtab)(result);
		return NULL;
	}

	return result;
}

RZ_OWN char *Elf_(rz_bin_elf_strtab_dup)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index) {
	rz_return_val_if_fail(strtab, NULL);

	if (Elf_(rz_bin_elf_strtab_has_index)(strtab, index)) {
		return NULL;
	}

	if (strnlen(strtab->data + index, ELF_STRING_LENGTH) == ELF_STRING_LENGTH) {
		return NULL;
	}

	return strndup(strtab->data + index, ELF_STRING_LENGTH);
}

bool Elf_(rz_bin_elf_strtab_has_index)(RZ_NONNULL RzBinElfStrtab *strtab, ut64 index) {
	rz_return_val_if_fail(strtab, false);

	return index < strtab->size;
}

bool Elf_(rz_bin_elf_strtab_cpy)(RZ_NONNULL RzBinElfStrtab *strtab, char *dst, ut64 index) {
	rz_return_val_if_fail(strtab, false);

	if (!Elf_(rz_bin_elf_strtab_has_index)(strtab, index)) {
		return false;
	}

	if (strnlen(strtab->data + index, ELF_STRING_LENGTH) == ELF_STRING_LENGTH) {
		return false;
	}

	strncpy(dst, strtab->data + index, ELF_STRING_LENGTH);
	return true;
}

void Elf_(rz_bin_elf_free_strtab)(RzBinElfStrtab *ptr) {
	if (!ptr) {
		return;
	}

	free(ptr->data);
	free(ptr);
}
