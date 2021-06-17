// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define X86      0
#define X86_64   1
#define ARM      2
#define AARCH64  3
#define ARCH_LEN 4

static RzBinElfPrStatusLayout prstatus_layouts[ARCH_LEN] = {
	[X86] = { 160, 0x48, 32, 0x3c },
	[X86_64] = { 216, 0x70, 64, 0x98 },
	[ARM] = { 72, 0x48, 32, 0x34 },
	[AARCH64] = { 272, 0x70, 64, 0xf8 }
};

RZ_BORROW RzBinElfPrStatusLayout *Elf_(rz_bin_elf_get_prstatus_layout)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

	switch (bin->ehdr.e_machine) {
	case EM_AARCH64:
		return prstatus_layouts + AARCH64;
	case EM_ARM:
		return prstatus_layouts + ARM;
	case EM_386:
		return prstatus_layouts + X86;
	case EM_X86_64:
		return prstatus_layouts + X86_64;
	}

	return NULL;
}

static RzBinElfNotePrStatus *get_nt_pr_status_from_note_segment(RzBinElfNoteSegment *segment) {
	for (size_t i = 0; i < segment->notes_count; i++) {
		RzBinElfNote *note = segment->notes + i;
		if (note->type == NT_PRSTATUS) {
			return &note->prstatus;
		}
	}

	return NULL;
}

// TODO: there can be multiple NT_PRSTATUS notes in the case of multiple threads.
static RZ_BORROW RzBinElfNotePrStatus *get_prstatus(RZ_NONNULL ELFOBJ *bin) {
	RzBinElfNoteSegment *segment;
	RzListIter *it;

	if (!bin->note_segments) {
		return NULL;
	}

	rz_list_foreach (bin->note_segments, it, segment) {
		RzBinElfNotePrStatus *tmp = get_nt_pr_status_from_note_segment(segment);
		if (tmp) {
			return tmp;
		}
	}

	return NULL;
}

/**
 * \brief Return register state
 * \param elf type
 * \return a borrowed array of ut8
 *
 * ...
 */
RZ_BORROW const ut8 *Elf_(rz_bin_elf_grab_regstate)(RZ_NONNULL ELFOBJ *bin, RZ_NONNULL size_t *size) {
	rz_return_val_if_fail(bin && size, NULL);

	RzBinElfNotePrStatus *pr_status = get_prstatus(bin);
	if (!pr_status) {
		return NULL;
	}

	*size = pr_status->regstate_size;
	return pr_status->regstate;
}

/**
 * \brief Get the stack pointer value
 * \param elf binary
 * \return allocated string
 *
 * Get the value of the stack pointer register in a core file from NT_PRSTATUS
 */
ut64 Elf_(rz_bin_elf_get_sp_val)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, UT64_MAX);

	RzBinElfPrStatusLayout *layout = Elf_(rz_bin_elf_get_prstatus_layout)(bin);
	RzBinElfNotePrStatus *prs = get_prstatus(bin);

	if (!layout || !prs) {
		return UT64_MAX;
	}

	if (layout->sp_offset + layout->sp_size / 8 > prs->regstate_size || !prs->regstate) {
		return UT64_MAX;
	}

	return rz_read_ble(prs->regstate + layout->sp_offset, bin->endian, layout->sp_size);
}
