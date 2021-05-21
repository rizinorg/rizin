// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static void _set_arm_thumb_bits(struct Elf_(rz_bin_elf_obj_t) * bin, RzBinSymbol **sym) {
	int bin_bits = Elf_(rz_bin_elf_get_bits)(bin);
	RzBinSymbol *ptr = *sym;
	int len = strlen(ptr->name);
	if (ptr->name[0] == '$' && (len >= 2 && !ptr->name[2])) {
		switch (ptr->name[1]) {
		case 'a': //arm
			ptr->bits = 32;
			break;
		case 't': //thumb
			ptr->bits = 16;
			if (ptr->vaddr & 1) {
				ptr->vaddr--;
			}
			if (ptr->paddr & 1) {
				ptr->paddr--;
			}
			break;
		case 'd': //data
			break;
		default:
			goto arm_symbol;
		}
	} else {
	arm_symbol:
		ptr->bits = bin_bits;
		if (bin_bits != 64) {
			ptr->bits = 32;
			if (ptr->paddr != UT64_MAX) {
				if (ptr->vaddr & 1) {
					ptr->vaddr--;
					ptr->bits = 16;
				}
				if (ptr->paddr & 1) {
					ptr->paddr--;
					ptr->bits = 16;
				}
			}
		}
	}
}

RzBinSymbol *Elf_(rz_bin_elf_convert_symbol)(struct Elf_(rz_bin_elf_obj_t) * bin,
	struct rz_bin_elf_symbol_t *symbol,
	const char *namefmt) {
	ut64 paddr, vaddr;
	RzBinSymbol *ptr = NULL;
	if (symbol->is_vaddr) {
		paddr = UT64_MAX;
		vaddr = symbol->offset;
	} else {
		paddr = symbol->offset;
		vaddr = Elf_(rz_bin_elf_p2v_new)(bin, paddr);
	}

	if (!(ptr = RZ_NEW0(RzBinSymbol))) {
		return NULL;
	}
	ptr->name = symbol->name[0] ? rz_str_newf(namefmt, &symbol->name[0]) : strdup("");
	ptr->forwarder = "NONE";
	ptr->bind = symbol->bind;
	ptr->type = symbol->type;
	ptr->is_imported = symbol->is_imported;
	ptr->paddr = paddr;
	ptr->vaddr = vaddr;
	ptr->size = symbol->size;
	ptr->ordinal = symbol->ordinal;
	// detect thumb
	if (bin->ehdr.e_machine == EM_ARM && *ptr->name) {
		_set_arm_thumb_bits(bin, &ptr);
	}

	return ptr;
}
