// SPDX-FileCopyrightText: 2008-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "elf.h"

#define round_up(a) ((((a) + (4) - (1)) / (4)) * (4))

/// Parse NT_PRSTATUS note
static void parse_note_prstatus(ELFOBJ *bin, RzBinElfNote *note, Elf_(Nhdr) * note_segment_header, ut64 offset) {
	RzBinElfPrStatusLayout *layout = Elf_(rz_bin_elf_get_prstatus_layout)(bin);

	if (!layout) {
		eprintf("Fetching registers from core file not supported for this architecture.\n");
		return;
	}

	ut8 *buf = malloc(layout->regsize);
	if (!buf) {
		return;
	}

	if (rz_buf_read_at(bin->b, offset + layout->regdelta, buf, layout->regsize) != layout->regsize) {
		free(buf);
		bprintf("Cannot read register state from CORE file\n");
		return;
	}

	note->prstatus.regstate_size = layout->regsize;
	note->prstatus.regstate = buf;
}

static void set_note_file(ELFOBJ *bin, RzBinElfNoteFile *file, ut64 *offset, const char *file_name) {
	file->start_vaddr = RZ_BIN_ELF_BREADWORD(bin->b, *offset);
	file->end_vaddr = RZ_BIN_ELF_BREADWORD(bin->b, *offset);
	file->file_off = RZ_BIN_ELF_BREADWORD(bin->b, *offset);
	file->file = strdup(file_name);
}

static void parse_note_file(RzBinElfNote *note, Elf_(Nhdr) * note_segment_header, ELFOBJ *bin, ut64 offset) {
	ut64 n_maps = RZ_BIN_ELF_BREADWORD(bin->b, offset);
	if (n_maps > (ut64)SIZE_MAX) {
		return;
	}

	RzVector files;
	rz_vector_init(&files, sizeof(RzBinElfNoteFile), NULL, NULL);
	rz_vector_reserve(&files, n_maps);

	offset += RZ_BIN_ELF_WORDSIZE; // skip page size

	ut64 offset_begin = offset;
	ut64 strings_begin = ((RZ_BIN_ELF_WORDSIZE * 3) * n_maps); // offset after the addr-array
	ut64 len_str = 0;

	while (n_maps-- && strings_begin + len_str < note_segment_header->n_descsz) {
		char tmp[512] = { 0 };

		int r = rz_buf_read_at(bin->b, offset_begin + strings_begin + len_str, (ut8 *)tmp, sizeof(tmp) - 1);
		if (r < 0) {
			break;
		}
		tmp[r] = 0;

		len_str += strlen(tmp) + 1;

		RzBinElfNoteFile *file = rz_vector_push(&files, NULL);
		if (file) {
			set_note_file(bin, file, &offset, tmp);
		}
	}

	note->file.files_count = rz_vector_len(&files);
	note->file.files = rz_vector_flush(&files);
	rz_vector_fini(&files);
}

static void set_note(ELFOBJ *bin, RzBinElfNote *note, Elf_(Nhdr) * note_segment_header, ut64 offset) {
	memset(note, 0, sizeof(*note));
	note->type = note_segment_header->n_type;

	// there are many more note types but for now we only need these:
	switch (note_segment_header->n_type) {
	case NT_FILE:
		parse_note_file(note, note_segment_header, bin, offset);
		break;
	case NT_PRSTATUS:
		parse_note_prstatus(bin, note, note_segment_header, offset);
		break;
	}
}

static void note_fini(RzBinElfNote *note) {
	switch (note->type) {
	case NT_FILE:
		for (size_t i = 0; i < note->file.files_count; i++) {
			free(note->file.files[i].file);
		}

		free(note->file.files);
		break;
	case NT_PRSTATUS:
		free(note->prstatus.regstate);
		break;
	}
}

static void note_segment_free(RzBinElfNoteSegment *segment) {
	if (!segment) {
		return;
	}

	if (segment->notes) {
		for (size_t i = 0; i < segment->notes_count; i++) {
			note_fini(segment->notes + i);
		}

		free(segment->notes);
	}

	free(segment);
}

static bool is_note_segment(ELFOBJ *bin, Elf_(Phdr) * segment) {
	return segment->p_type == PT_NOTE && segment->p_filesz >= 9;
}

static Elf_(Nhdr) read_note_segment_header(ELFOBJ *bin, ut64 *offset) {
	Elf_(Nhdr) note_segment_header;

	note_segment_header.n_namesz = BREAD32(bin->b, *offset);
	note_segment_header.n_descsz = BREAD32(bin->b, *offset);
	note_segment_header.n_type = BREAD32(bin->b, *offset);

	return note_segment_header;
}

static bool check_note_segment(Elf_(Phdr) * segment, Elf_(Nhdr) * note_segment_header, ut64 offset) {
	return segment->p_filesz >= offset - segment->p_offset + round_up(note_segment_header->n_namesz) + round_up(note_segment_header->n_descsz);
}

static void set_note_segment(ELFOBJ *bin, Elf_(Phdr) * segment, RzBinElfNoteSegment *note_segment) {
	RzVector notes;
	rz_vector_init(&notes, sizeof(RzBinElfNote), NULL, NULL);

	ut64 offset = segment->p_offset;

	while (offset + 9 < RZ_MIN(offset + segment->p_filesz, bin->size)) {
		Elf_(Nhdr) note_segment_header = read_note_segment_header(bin, &offset);

		if (!check_note_segment(segment, &note_segment_header, offset)) {
			break;
		}

		// skip name, not needed for us
		offset += round_up(note_segment_header.n_namesz);

		RzBinElfNote *note = rz_vector_push(&notes, NULL);
		set_note(bin, note, &note_segment_header, offset);

		offset += round_up(note_segment_header.n_descsz);
	}

	note_segment->notes_count = rz_vector_len(&notes);
	note_segment->notes = rz_vector_flush(&notes);
	rz_vector_fini(&notes);
}

RZ_IPI bool Elf_(rz_bin_elf_init_notes)(RZ_NONNULL RZ_INOUT ELFOBJ *bin) {
	rz_return_val_if_fail(bin, false);

	bin->note_segments = rz_list_newf((RzListFree)note_segment_free);
	if (!bin->note_segments) {
		return false;
	}

	for (size_t segment_index = 0; segment_index < bin->ehdr.e_phnum; segment_index++) {
		Elf_(Phdr) *segment = bin->phdr + segment_index;
		if (!is_note_segment(bin, segment)) {
			continue;
		}

		RzBinElfNoteSegment *note_segment = RZ_NEW0(RzBinElfNoteSegment);
		if (!note_segment) {
			return false;
		}

		set_note_segment(bin, segment, note_segment);

		rz_list_push(bin->note_segments, note_segment);
	}

	return true;
}
