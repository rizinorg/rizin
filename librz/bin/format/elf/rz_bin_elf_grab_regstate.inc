// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

static RzBinElfNotePrStatus *get_prstatus(ELFOBJ *bin) {
	// TODO: there can be multiple NT_PRSTATUS notes in the case of multiple threads.
	// Relevant citation from lldb source:
	// 5) If a core file contains multiple thread contexts then there is two data forms
	//    a) Each thread context(2 or more NOTE entries) contained in its own segment (PT_NOTE)
	//    b) All thread context is stored in a single segment(PT_NOTE).
	//        This case is little tricker since while parsing we have to find where the
	//        new thread starts. The current implementation marks beginning of
	//        new thread when it finds NT_PRSTATUS or NT_PRPSINFO NOTE entry.
	if (!bin->note_segments) {
		return NULL;
	}
	RzBinElfNoteSegment *seg;
	RzListIter *it;
	rz_list_foreach (bin->note_segments, it, seg) {
		for (size_t i = 0; i < seg->notes_count; i++) {
			RzBinElfNote *note = &seg->notes[i];
			if (note->type == NT_PRSTATUS) {
				return &note->prstatus;
			}
		}
	}
	return NULL;
}

const ut8 *Elf_(rz_bin_elf_grab_regstate)(ELFOBJ *bin, RZ_NONNULL size_t *size) {
	RzBinElfNotePrStatus *prs = get_prstatus(bin);
	if (!prs) {
		return NULL;
	}
	*size = prs->regstate_size;
	return prs->regstate;
}
