// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

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
static RzBinElfNotePrStatus *get_prstatus(ELFOBJ *bin) {
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
