// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static bool get_phdr_entry(ELFOBJ *bin, Elf_(Phdr) * segment, ut64 offset) {
	if (!Elf_(rz_bin_elf_read_word)(bin, &offset, &segment->p_type) ||
#if RZ_BIN_ELF64
		!Elf_(rz_bin_elf_read_word)(bin, &offset, &segment->p_flags) ||
#endif
		!Elf_(rz_bin_elf_read_off)(bin, &offset, &segment->p_offset) ||
		!Elf_(rz_bin_elf_read_addr)(bin, &offset, &segment->p_vaddr) ||
		!Elf_(rz_bin_elf_read_addr)(bin, &offset, &segment->p_paddr) ||
		!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &segment->p_filesz) ||
		!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &segment->p_memsz) ||
#ifndef RZ_BIN_ELF64
		!Elf_(rz_bin_elf_read_word)(bin, &offset, &segment->p_flags) ||
#endif
		!Elf_(rz_bin_elf_read_word_xword)(bin, &offset, &segment->p_align)) {
		return false;
	}

	return true;
}

static bool verify_phdr_entry(ELFOBJ *bin, Elf_(Phdr) * entry) {
	if (!entry->p_offset && !entry->p_vaddr && !entry->p_paddr && !entry->p_filesz && !entry->p_memsz) {
		return true;
	}

	Elf_(Off) end_off;
	if (!Elf_(rz_bin_elf_add_off)(&end_off, entry->p_offset, entry->p_filesz) || end_off > bin->size) {
		return false;
	}

	if (!Elf_(rz_bin_elf_add_addr)(NULL, entry->p_vaddr, entry->p_memsz)) {
		return false;
	}

	if (entry->p_flags == PT_LOAD && (!entry->p_memsz || entry->p_filesz > entry->p_memsz)) {
		return false;
	}

	if (entry->p_align && entry->p_offset % entry->p_align != entry->p_vaddr % entry->p_align) {
		return false;
	}

	return true;
}

static bool get_elf_segment(ELFOBJ *bin, RzBinElfSegment *segment, ut64 offset, size_t pos) {
	if (!get_phdr_entry(bin, &segment->data, offset)) {
		return false;
	}

	segment->is_valid = verify_phdr_entry(bin, &segment->data);
	if (!segment->is_valid) {
		RZ_LOG_INFO("Invalid segment %zu at 0x%" PFMT64x "\n", pos, offset);
	}

	return true;
}

static RzVector *get_segments_from_phdr(ELFOBJ *bin) {
	RzVector *result = rz_vector_new(sizeof(RzBinElfSegment), NULL, NULL);
	if (!result) {
		return NULL;
	}

	ut64 offset = bin->ehdr.e_phoff;

	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		RzBinElfSegment *segment = rz_vector_push(result, NULL);
		if (!segment) {
			rz_vector_free(result);
			return NULL;
		}

		if (!get_elf_segment(bin, segment, offset, i)) {
			rz_vector_free(result);
			return NULL;
		}

		offset += sizeof(Elf_(Phdr));
	}

	return result;
}

static bool check_phdr_size(ELFOBJ *bin) {
	ut32 phdr_size;
	if (!UT32_MUL(&phdr_size, (ut32)bin->ehdr.e_phnum, sizeof(Elf_(Phdr)))) {
		return false;
	}

	Elf_(Off) end_off;
	if (!Elf_(rz_bin_elf_add_off)(&end_off, bin->ehdr.e_phoff, phdr_size)) {
		return false;
	}

	if (!phdr_size || end_off > bin->size) {
		return false;
	}

	return true;
}

RZ_BORROW RzBinElfSegment *Elf_(rz_bin_elf_get_segment_with_type)(RZ_NONNULL ELFOBJ *bin, Elf_(Word) type) {
	rz_return_val_if_fail(bin, NULL);
	if (!bin->segments) {
		return NULL;
	}

	RzBinElfSegment *iter;

	rz_bin_elf_foreach_segments(bin, iter) {
		if (iter->data.p_type == type) {
			return iter;
		}
	}

	return NULL;
}

RZ_OWN RzVector *Elf_(rz_bin_elf_new_segments)(RZ_NONNULL ELFOBJ *bin) {
	if (!check_phdr_size(bin)) {
		return NULL;
	}

	return get_segments_from_phdr(bin);
}

bool Elf_(rz_bin_elf_has_segments)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	return bin->segments && rz_vector_len(bin->segments);
}
