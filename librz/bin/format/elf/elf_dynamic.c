// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf_dynamic.h"

static bool get_dt_info(RzBinElfDtDynamic *ptr, ut64 key, ut64 *info) {
	bool found = false;
	ut64 tmp = ht_uu_find(ptr->info, key, &found);

	if (!found) {
		return false;
	}

	if (info) {
		*info = tmp;
	}

	return true;
}

static bool get_dynamic_entry_aux(ELFOBJ *bin, ut64 offset, Elf_(Dyn) * entry) {
	return Elf_(rz_bin_elf_read_sword_sxword)(bin, &offset, &entry->d_tag) &&
		Elf_(rz_bin_elf_read_addr)(bin, &offset, &entry->d_un.d_ptr);
}

static bool get_dynamic_entry(ELFOBJ *bin, ut64 offset, Elf_(Dyn) * entry) {
	if (!get_dynamic_entry_aux(bin, offset, entry)) {
		RZ_LOG_WARN("Failed to read DT_DYNAMIC entry at 0x%" PFMT64x ".\n", offset);
		return false;
	}

	return true;
}

static bool add_dt_dynamic_entry(RzBinElfDtDynamic *ptr, ut64 key, ut64 info) {
	if (key == DT_NEEDED) {
		return !!rz_vector_push(&ptr->dt_needed, &info);
	} else {
		return ht_uu_insert(ptr->info, key, info);
	}
}

static bool fill_dt_dynamic(ELFOBJ *bin, RzBinElfDtDynamic *ptr, ut64 offset, ut64 size) {
	for (ut64 entry_offset = offset; entry_offset < offset + size; entry_offset += sizeof(Elf_(Dyn))) {
		Elf_(Dyn) entry;
		if (!get_dynamic_entry(bin, entry_offset, &entry)) {
			return false;
		}

		if (entry.d_tag == DT_NULL) {
			break;
		}

		if (get_dt_info(ptr, entry.d_tag, NULL)) {
			RZ_LOG_WARN("DT_DYNAMIC entry (0x%" PFMT64x ") at 0x%" PFMT64x " was already handled.\n", (ut64)entry.d_tag, offset);
		}

		if (!add_dt_dynamic_entry(ptr, entry.d_tag, entry.d_un.d_val)) {
			return false;
		}
	}

	return true;
}

static bool init_dt_dynamic(ELFOBJ *bin, RzBinElfDtDynamic *ptr) {
	RzBinElfSegment *segment = Elf_(rz_bin_elf_get_segment_with_type)(bin, PT_DYNAMIC);
	if (!segment) {
		RZ_LOG_WARN("No PT_DYNAMIC segment in the ELF binary.\n")
		return false;
	}

	if (!segment->is_valid) {
		RZ_LOG_WARN("The PT_DYNAMIC segment is invalid.\n");
		return false;
	}

	ut64 offset = Elf_(rz_bin_elf_v2p)(bin, segment->data.p_vaddr);
	if (offset == UT64_MAX) {
		RZ_LOG_INFO("Failed to convert PT_DYNAMIC segment p_vaddr to a physical offset.\n")
		return false;
	}

	return fill_dt_dynamic(bin, ptr, offset, segment->data.p_filesz);
}

RZ_BORROW RzVector /*<ut64>*/ *Elf_(rz_bin_elf_get_dt_needed)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return NULL;
	}

	return &bin->dt_dynamic->dt_needed;
}

RZ_OWN RzBinElfDtDynamic *Elf_(rz_bin_elf_dt_dynamic_new)(RZ_NONNULL ELFOBJ *bin) {
	RzBinElfDtDynamic *result = RZ_NEW0(RzBinElfDtDynamic);
	if (!result) {
		return NULL;
	}

	result->info = ht_uu_new();
	if (!result->info) {
		Elf_(rz_bin_elf_dt_dynamic_free)(result);
		return NULL;
	}

	rz_vector_init(&result->dt_needed, sizeof(ut64), NULL, NULL);

	if (!init_dt_dynamic(bin, result)) {
		Elf_(rz_bin_elf_dt_dynamic_free)(result);
		return NULL;
	}

	return result;
}

bool Elf_(rz_bin_elf_get_dt_info)(RZ_NONNULL ELFOBJ *bin, ut64 key, RZ_OUT ut64 *info) {
	rz_return_val_if_fail(bin, false);

	if (!Elf_(rz_bin_elf_has_dt_dynamic)(bin)) {
		return false;
	}

	return get_dt_info(bin->dt_dynamic, key, info);
}

bool Elf_(rz_bin_elf_has_dt_dynamic)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->dt_dynamic;
}

void Elf_(rz_bin_elf_dt_dynamic_free)(RzBinElfDtDynamic *ptr) {
	if (!ptr) {
		return;
	}

	ht_uu_free(ptr->info);
	rz_vector_fini(&ptr->dt_needed);
	free(ptr);
}
