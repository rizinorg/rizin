// SPDX-FileCopyrightText: 2021 08A <dev@08a.re>
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

static bool verify_phdr_entry(ELFOBJ *bin, RzBinObjectLoadOptions *options, Elf_(Phdr) * entry) {
	if (!options->elf_checks_segments) {
		return true;
	}

	if (!entry->p_offset && !entry->p_vaddr && !entry->p_paddr && !entry->p_filesz && !entry->p_memsz) {
		return true;
	}

	Elf_(Off) end_off;
	if (!Elf_(rz_bin_elf_add_off)(&end_off, entry->p_offset, entry->p_filesz) || end_off > bin->size) {
		RZ_LOG_WARN("phdr entry: p_offset is invalid for p_filesz.\n");
		return false;
	}

	if (!Elf_(rz_bin_elf_add_addr)(NULL, entry->p_vaddr, entry->p_memsz)) {
		RZ_LOG_WARN("phdr entry: p_vaddr is invalid for p_memsz.\n");
		return false;
	}

	if (entry->p_flags == PT_LOAD && (!entry->p_memsz || entry->p_filesz > entry->p_memsz)) {
		RZ_LOG_WARN("phdr entry: p_memsz and/or p_filesz are invalid for a PT_LOAD segment.\n");
		return false;
	}

	if (entry->p_align && entry->p_offset % entry->p_align != entry->p_vaddr % entry->p_align) {
		RZ_LOG_WARN("phdr entry: p_offset and p_vaddr are not congruent for p_align.\n");
		return false;
	}

	return true;
}

static bool get_elf_segment(ELFOBJ *bin, RzBinObjectLoadOptions *options, RzBinElfSegment *segment, ut64 offset, size_t pos) {
	if (!get_phdr_entry(bin, &segment->data, offset)) {
		RZ_LOG_WARN("Failed to read segment entry at 0x%" PFMT64x ".\n", offset);
		return false;
	}

	segment->is_valid = verify_phdr_entry(bin, options, &segment->data);
	if (!segment->is_valid) {
		RZ_LOG_WARN("The segment %zu at 0x%" PFMT64x " seems to be invalid.\n", pos, offset);
	}

	return true;
}

static RzVector /*<RzBinElfSegment>*/ *get_segments_from_phdr(ELFOBJ *bin, size_t count, RzBinObjectLoadOptions *options) {
	RzVector *result = rz_vector_new(sizeof(RzBinElfSegment), NULL, NULL);
	if (!result) {
		return NULL;
	}

	ut64 offset = bin->ehdr.e_phoff;

	for (size_t i = 0; i < count; i++) {
		RzBinElfSegment *segment = rz_vector_push(result, NULL);
		if (!segment) {
			rz_vector_free(result);
			return NULL;
		}

		if (!get_elf_segment(bin, options, segment, offset, i)) {
			rz_vector_free(result);
			return NULL;
		}

		offset += sizeof(Elf_(Phdr));
	}

	if (!rz_vector_len(result)) {
		rz_vector_free(result);
		return NULL;
	}

	return result;
}

static size_t get_number_of_segments(ELFOBJ *bin, RzVector /*<Elf_(Shdr)>*/ *sections) {
	if (bin->ehdr.e_phnum != PN_XNUM) {
		return bin->ehdr.e_phnum;
	}

	if (!sections) {
		RZ_LOG_WARN("Failed to fetch the number of segments because there are no sections.\n");
		return 0;
	}

	Elf_(Shdr) *section = rz_vector_index_ptr(sections, 0);
	if (!section) {
		RZ_LOG_WARN("Failed to fetch the number of segments from the section 0.\n");
		return 0;
	}

	return section->sh_info;
}

RZ_BORROW RzBinElfSegment *Elf_(rz_bin_elf_get_segment_with_type)(RZ_NONNULL ELFOBJ *bin, Elf_(Word) type) {
	rz_return_val_if_fail(bin, NULL);

	RzBinElfSegment *iter;
	rz_bin_elf_foreach_segments(bin, iter) {
		if (iter->data.p_type == type) {
			return iter;
		}
	}

	return NULL;
}

RZ_OWN RzVector /*<RzBinElfSegment>*/ *Elf_(rz_bin_elf_segments_new)(RZ_NONNULL ELFOBJ *bin, RzVector /*<Elf_(Shdr)>*/ *sections, RZ_NONNULL RzBinObjectLoadOptions *options) {
	rz_return_val_if_fail(bin && options, NULL);

	size_t count = get_number_of_segments(bin, sections);
	if (!count) {
		return NULL;
	}

	if (!Elf_(rz_bin_elf_check_array)(bin, bin->ehdr.e_phoff, count, sizeof(Elf_(Phdr)))) {
		RZ_LOG_WARN("Invalid program header (check array failed).\n");
		return NULL;
	}

	return get_segments_from_phdr(bin, count, options);
}

bool Elf_(rz_bin_elf_has_segments)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->segments;
}
