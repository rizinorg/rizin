// SPDX-FileCopyrightText: 2021 08A <08A@riseup.net>
// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define ROUND_UP_4(x) ((x) + (4 - 1)) / 4 * 4

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

static bool parse_note_prstatus(ELFOBJ *bin, RzVector *notes, Elf_(Nhdr) * note_segment_header, ut64 offset) {
	RzBinElfPrStatusLayout *layout = Elf_(rz_bin_elf_get_prstatus_layout)(bin);
	if (!layout) {
		RZ_LOG_WARN("Fetching registers from core file not supported for this architecture.\n");
		return false;
	}

	RzBinElfNote *note = rz_vector_push(notes, NULL);
	if (!note) {
		return false;
	}

	note->type = NT_PRSTATUS;

	note->prstatus.regstate_size = layout->regsize;
	note->prstatus.regstate = RZ_NEWS(ut8, layout->regsize);
	if (!note->prstatus.regstate) {
		return false;
	}

	if (rz_buf_read_at(bin->b, offset + layout->regdelta, note->prstatus.regstate, note->prstatus.regstate_size) != layout->regsize) {
		RZ_LOG_WARN("Failed to read register state from CORE file\n");
		return false;
	}

	return true;
}

static bool get_note_file_aux(ELFOBJ *bin, RzBinElfNoteFile *file, ut64 *offset) {
	return Elf_(rz_bin_elf_read_addr)(bin, offset, &file->start_vaddr) &&
		Elf_(rz_bin_elf_read_addr)(bin, offset, &file->end_vaddr) &&
		Elf_(rz_bin_elf_read_off)(bin, offset, &file->file_off);
}

static bool get_note_file(ELFOBJ *bin, RzBinElfNoteFile *file, ut64 *offset) {
	ut64 tmp = *offset;
	if (!get_note_file_aux(bin, file, offset)) {
		RZ_LOG_WARN("Failed to read NT_FILE at 0x%" PFMT64x ".\n", tmp);
	}

	return true;
}

static bool set_note_file(ELFOBJ *bin, RzBinElfNoteFile *file, ut64 *offset, char *name) {
	if (!get_note_file(bin, file, offset)) {
		return false;
	}

	file->file = name;
	return true;
}

static bool parse_note_file(ELFOBJ *bin, RzVector *notes, Elf_(Nhdr) * note_segment_header, ut64 offset) {
	Elf_(Addr) n_maps;
	if (!Elf_(rz_bin_elf_read_addr)(bin, &offset, &n_maps)) {
		return false;
	}

	offset += sizeof(Elf_(Addr)); // skip page size always 1

	Elf_(Addr) strings_offset; // offset after the addr-array
	if (!Elf_(rz_bin_elf_mul_addr)(&strings_offset, n_maps, sizeof(Elf_(Addr)) * 3)) {
		return false;
	}

	ut64 entry_offset = offset;
	for (Elf_(Addr) i = 0; i < n_maps; i++) {
		if (strings_offset >= note_segment_header->n_descsz) {
			return false;
		}

		char *name = rz_buf_get_nstring(bin->b, offset + strings_offset, note_segment_header->n_descsz);
		if (!name) {
			return false;
		}

		RzBinElfNote *note = rz_vector_push(notes, NULL);
		if (!note) {
			free(name);
			return false;
		}

		note->type = NT_FILE;

		if (!set_note_file(bin, &note->file, &entry_offset, name)) {
			return false;
		}

		strings_offset += strlen(name) + 1;
	}

	return true;
}

static bool set_note(ELFOBJ *bin, RzVector *notes, Elf_(Nhdr) * note_segment_header, ut64 offset) {
	switch (note_segment_header->n_type) {
	case NT_FILE:
		if (!parse_note_file(bin, notes, note_segment_header, offset)) {
			RZ_LOG_WARN("Failed to parse NT_FILE.\n");
			return false;
		}
		break;
	case NT_PRSTATUS:
		if (!parse_note_prstatus(bin, notes, note_segment_header, offset)) {
			RZ_LOG_WARN("Failed to parse NT_PRSTATUS.\n");
			return false;
		}
		break;
	}

	return true;
}

static bool read_note_segment_header(ELFOBJ *bin, ut64 *offset, Elf_(Nhdr) * note_segment_header) {
	if (!Elf_(rz_bin_elf_read_word)(bin, offset, &note_segment_header->n_namesz)) {
		return false;
	}

	if (!Elf_(rz_bin_elf_read_word)(bin, offset, &note_segment_header->n_descsz)) {
		return false;
	}

	if (!Elf_(rz_bin_elf_read_word)(bin, offset, &note_segment_header->n_type)) {
		return false;
	}

	return true;
}

static bool set_note_segment(ELFOBJ *bin, RzVector *notes, RzBinElfSegment *segment) {
	ut64 offset = segment->data.p_offset;

	while (offset < segment->data.p_filesz) {
		Elf_(Nhdr) note_segment_header;

		if (!read_note_segment_header(bin, &offset, &note_segment_header)) {
			return false;
		}

		offset += ROUND_UP_4(note_segment_header.n_namesz); // skip name

		if (!set_note(bin, notes, &note_segment_header, offset)) {
			return false;
		}

		offset += ROUND_UP_4(note_segment_header.n_descsz); // skip name
	}

	return true;
}

static void note_prstatus_free(RzBinElfNotePrStatus *ptr) {
	free(ptr->regstate);
}

static void note_file_free(RzBinElfNoteFile *ptr) {
	free(ptr->file);
}

static void note_free(void *e, RZ_UNUSED void *user) {
	RzBinElfNote *ptr = e;

	switch (ptr->type) {
	case NT_FILE:
		note_file_free(&ptr->file);
		break;
	case NT_PRSTATUS:
		note_prstatus_free(&ptr->prstatus);
		break;
	}
}

static void note_segment_free(void *e, RZ_UNUSED void *user) {
	RzVector *ptr = e;
	rz_vector_fini(ptr);
}

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

RZ_OWN RzVector *Elf_(rz_bin_elf_notes_new)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	RzVector *result = rz_vector_new(sizeof(RzVector), note_segment_free, NULL);
	if (!result) {
		return NULL;
	}

	RzBinElfSegment *segment;
	rz_bin_elf_foreach_segments(bin, segment) {
		if (!segment->is_valid || segment->data.p_type != PT_NOTE) {
			continue;
		}

		RzVector *notes = rz_vector_push(result, NULL);
		if (!notes) {
			rz_vector_free(result);
			return NULL;
		}

		rz_vector_init(notes, sizeof(RzBinElfNote), note_free, NULL);

		if (!set_note_segment(bin, notes, segment)) {
			rz_vector_fini(notes);
			rz_vector_free(result);
			return NULL;
		}
	}

	if (!rz_vector_len(result)) {
		rz_vector_free(result);
		return NULL;
	}

	return result;
}

bool Elf_(rz_bin_elf_has_notes)(RZ_NONNULL ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);
	return bin->notes;
}
