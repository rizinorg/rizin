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
RZ_IPI RZ_BORROW RzBinElfNotePrStatus *Elf_(rz_bin_elf_get_prstatus)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, NULL);

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
