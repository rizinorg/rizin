// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf_dynamic.h"

static bool get_dynamic_entry(ELFOBJ *bin, ut64 offset, Elf_(Dyn) * entry) {
	if (!Elf_(rz_bin_elf_read_sword_sxword)(bin, &offset, &entry->d_tag)) {
		return false;
	}

	if (!Elf_(rz_bin_elf_read_addr)(bin, &offset, &entry->d_un.d_ptr)) {
		return false;
	}

	return true;
}

static void fill_dt_dynamic(ELFOBJ *bin, RzBinElfDtDynamic *ptr, ut64 offset, ut64 size) {
	for (ut64 entry_offset = offset; entry_offset < offset + size; entry_offset += sizeof(Elf_(Dyn))) {
		Elf_(Dyn) entry;

		if (!get_dynamic_entry(bin, entry_offset, &entry)) {
			break;
		}

		if (entry.d_tag == DT_NULL) {
			break;
		}

		if (entry.d_tag == DT_NEEDED) {
			rz_vector_push(ptr->dt_needed, &entry.d_un.d_val);
		} else if (!ht_uu_insert(ptr->info, entry.d_tag, entry.d_un.d_val)) {
			RZ_LOG_WARN("Dynamic tag %" PFMT64d " already handled\n", (ut64)entry.d_tag);
		}
	}
}

static bool init_dt_dynamic(ELFOBJ *bin, RzBinElfDtDynamic *ptr) {
	RzBinElfSegment *segment = Elf_(rz_bin_elf_get_segment_with_type)(bin, PT_DYNAMIC);
	if (!segment) {
		return false;
	}

	ut64 size = segment->data.p_filesz;
	ut64 offset = Elf_(rz_bin_elf_v2p_new)(bin, segment->data.p_vaddr);
	if (offset == UT64_MAX || !size || offset + size > bin->size) {
		return false;
	}

	fill_dt_dynamic(bin, ptr, offset, size);

	return true;
}

RZ_BORROW RzVector *Elf_(rz_bin_elf_get_dt_needed)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin && bin->dt_dynamic && bin->dt_dynamic->dt_needed, NULL);

	return bin->dt_dynamic->dt_needed;
}

RZ_OWN RzBinElfDtDynamic *Elf_(rz_bin_elf_new_dt_dynamic)(RZ_NONNULL ELFOBJ *bin) {
	RzBinElfDtDynamic *result = RZ_NEW(RzBinElfDtDynamic);
	if (!result) {
		return NULL;
	}

	result->info = ht_uu_new0();
	if (!result->info) {
		free(result);
		return NULL;
	}

	result->dt_needed = rz_vector_new(sizeof(Elf_(Word)), NULL, NULL);
	if (!result->dt_needed) {
		ht_uu_free(result->info);
		free(result);
		return NULL;
	}

	if (!init_dt_dynamic(bin, result)) {
		ht_uu_free(result->info);
		rz_vector_free(result->dt_needed);
		free(result);
		return NULL;
	}

	return result;
}

bool Elf_(rz_bin_elf_get_dt_info)(RZ_NONNULL ELFOBJ *bin, ut64 key, RZ_OUT ut64 *info) {
	rz_return_val_if_fail(bin && bin->dt_dynamic && bin->dt_dynamic->info, false);

	bool found = false;
	ut64 tmp = ht_uu_find(bin->dt_dynamic->info, key, &found);

	if (!found) {
		return false;
	}

	if (info) {
		*info = tmp;
	}

	return true;
}

bool Elf_(rz_bin_elf_has_dt_dynamic)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->dt_dynamic && bin->dt_dynamic->info && bin->dt_dynamic->dt_needed;
}

void Elf_(rz_bin_elf_free_dt_dynamic)(RzBinElfDtDynamic *ptr) {
	if (!ptr) {
		return;
	}

	ht_uu_free(ptr->info);
	rz_vector_free(ptr->dt_needed);
	free(ptr);
}
