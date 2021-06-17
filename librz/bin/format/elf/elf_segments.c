// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LPGL-3.0-only

#include "elf_segments.h"

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

static RzBinElfSegment convert_phdr_segment_to_elf_segment(Elf_(Phdr) segment) {
}

static bool read_phdr(ELFOBJ *bin, bool need_linux_kernel_hack) {
	bool phdr_found = false;

	ut64 offset = bin->ph_off;
	for (size_t i = 0; i < bin->ehdr.e_phnum; i++) {
		Elf_(Phdr) segment;

		if (!get_phdr_entry(bin, segment, offset)) {
			return false;
		}

		RzBinElfSegment tmp = convert_phdr_segment_to_elf_segment(bin, segment);

		if (need_linux_kernel_hack && bin->phdr[i].p_type == PT_PHDR) {
			phdr_found = true;
		}

		offset += sizeof(Elf_(Phdr));
	}

	if (need_linux_kernel_hack && phdr_found) {
		ut64 load_addr = Elf_(rz_bin_elf_get_baddr)(bin);
		bin->ehdr.e_phoff = Elf_(rz_bin_elf_v2p_new)(bin, load_addr + bin->ehdr.e_phoff);
		return read_phdr(bin, false);
	}

	return true;
}

/* Here is the where all the fun starts.
 * Linux kernel since 2005 calculates phdr offset wrongly
 * adding it to the load address (va of the LOAD0).
 * See `fs/binfmt_elf.c` file this line:
 *    NEW_AUX_ENT(AT_PHDR, load_addr + exec->e_phoff);
 * So after the first read, we fix the address and read it again
 */
static bool need_linux_kernel_hack(ELFOBJ *bin) {
	return bin->size > 128 * 1024 && (bin->ehdr.e_machine == EM_X86_64 || bin->ehdr.e_machine == EM_386);
}

static RzVector *get_segments_from_phdr(ELFOBJ *bin) {
	return read_phdr(bin, need_linux_kernel_hack(bin));
}

static bool check_phdr_size(ELFOBJ *bin) {
	ut32 phdr_size;

	if (!UT32_MUL(&phdr_size, (ut32)bin->ehdr.e_phnum, sizeof(Elf_(Phdr)))) {
		return false;
	}

	if (!phdr_size || bin->ehdr.e_phoff + phdr_size > bin->size) {
		return false;
	}

	return true;
}

RZ_OWN RzBinElfSegments *Elf_(rz_bin_elf_new_segments)(RZ_NONNULL ELFOBJ *bin) {
	if (!check_phdr_size(bin)) {
		return NULL;
	}

	RzBinElfSegments result = RZ_NEW(RzBinElfSegments);
	if (!result) {
		return NULL;
	}

	result->segments = get_segments_from_phdr(bin);
	if (!result->segments) {
		free(result);
		return NULL;
	}

	return result;
}

void Elf_(rz_bin_elf_free_segments)(RzBinElfSegments *ptr) {
	if (!ptr) {
		return;
	}

	rz_vector_free(ptr->segments);
	free(ptr);
}
