// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

static void parse_image_header(PeImageSectionHeader *hdr, RzBuffer *buf) {
	char *name = rz_buf_get_nstring(buf, rz_buf_tell(buf), PDB_SIZEOF_SECTION_NAME);
	rz_str_cpy(hdr->name, name);
	RZ_FREE(name);
	rz_buf_seek(buf, rz_buf_tell(buf) + PDB_SIZEOF_SECTION_NAME, RZ_BUF_SET);
	hdr->misc.physical_address = rz_buf_read_le32(buf);
	hdr->virtual_address = rz_buf_read_le32(buf);
	hdr->size_of_raw_data = rz_buf_read_le32(buf);
	hdr->pointer_to_raw_data = rz_buf_read_le32(buf);
	hdr->pointer_to_relocations = rz_buf_read_le32(buf);
	hdr->pointer_to_line_numbers = rz_buf_read_le32(buf);
	hdr->number_of_relocations = rz_buf_read_le16(buf);
	hdr->number_of_line_numbers = rz_buf_read_le16(buf);
	hdr->charactestics = rz_buf_read_le32(buf);
}

RZ_IPI bool parse_pe_stream(RzPdb *pdb, MsfStream *stream) {
	rz_return_val_if_fail(pdb && stream, false);
	if (!pdb->s_pe) {
		pdb->s_pe = RZ_NEW0(PeStream);
	}
	RzBuffer *buf = stream->stream_data;
	PeStream *s = pdb->s_pe;
	if (!s->sections_hdrs) {
		s->sections_hdrs = rz_list_new();
	}
	ut32 size = rz_buf_size(buf);
	ut32 read_len = 0;
	while (read_len < size) {
		PeImageSectionHeader *hdr = RZ_NEW0(PeImageSectionHeader);
		if (!hdr) {
			rz_list_free(s->sections_hdrs);
			return false;
		}
		parse_image_header(hdr, buf);
		read_len += sizeof(PeImageSectionHeader);
		rz_list_append(s->sections_hdrs, hdr);
	}
	return true;
}
RZ_IPI void free_pe_stream(PeStream *stream) {
	RzListIter *it;
	PeImageSectionHeader *hdr;
	rz_list_foreach (stream->sections_hdrs, it, hdr) {
		RZ_FREE(hdr);
	}
	rz_list_free(stream->sections_hdrs);
};
