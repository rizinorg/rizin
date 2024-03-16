// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool start_a_sequence_of_instruction(RzBinSymbol *symbol) {
	return strlen(symbol->name) > 3 && rz_str_startswith(symbol->name, "$a.");
}

static bool start_a_sequence_of_thumb_instruction(RzBinSymbol *symbol) {
	return strlen(symbol->name) > 3 && rz_str_startswith(symbol->name, "$t.");
}

static bool start_a_sequence_of_data(RzBinSymbol *symbol) {
	return strlen(symbol->name) > 3 && rz_str_startswith(symbol->name, "$d.");
}

bool Elf_(rz_bin_elf_is_arm_binary_supporting_thumb)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->ehdr.e_machine == EM_ARM;
}

bool Elf_(rz_bin_elf_is_thumb_addr)(ut64 addr) {
	return addr != UT64_MAX && addr & 1;
}

void Elf_(rz_bin_elf_fix_arm_thumb_addr)(ut64 *addr) {
	rz_return_if_fail(Elf_(rz_bin_elf_is_thumb_addr(*addr)));
	*addr -= 1;
}

void Elf_(rz_bin_elf_fix_arm_thumb_object)(RZ_NONNULL ut64 *paddr, RZ_NONNULL ut64 *vaddr, RZ_NONNULL int *bits) {
	rz_return_if_fail(paddr && vaddr && bits);

	*bits = 32;

	if (Elf_(rz_bin_elf_is_thumb_addr)(*paddr)) {
		Elf_(rz_bin_elf_fix_arm_thumb_addr)(paddr);
		*bits = 16;
	}

	if (Elf_(rz_bin_elf_is_thumb_addr)(*vaddr)) {
		Elf_(rz_bin_elf_fix_arm_thumb_addr)(vaddr);
		*bits = 16;
	}
}

void Elf_(rz_bin_elf_fix_arm_thumb_symbol)(RZ_NONNULL RzBinSymbol *symbol) {
	rz_return_if_fail(symbol && symbol->name);

	if (start_a_sequence_of_instruction(symbol)) {
		symbol->bits = 32;
	} else if (start_a_sequence_of_thumb_instruction(symbol) || !start_a_sequence_of_data(symbol)) {
		rz_bin_elf_fix_arm_thumb_object_dispatch(symbol);
	}
}
