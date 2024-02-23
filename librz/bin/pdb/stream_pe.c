// SPDX-FileCopyrightText: 2015 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

static bool parse_image_header(PeImageSectionHeader *hdr, RzBuffer *buf) {
	rz_buf_read(buf, (ut8 *)hdr->name, PDB_SIZEOF_SECTION_NAME);
	return rz_buf_read_le32(buf, &hdr->misc.physical_address) &&
		rz_buf_read_le32(buf, &hdr->virtual_address) &&
		rz_buf_read_le32(buf, &hdr->size_of_raw_data) &&
		rz_buf_read_le32(buf, &hdr->pointer_to_raw_data) &&
		rz_buf_read_le32(buf, &hdr->pointer_to_relocations) &&
		rz_buf_read_le32(buf, &hdr->pointer_to_line_numbers) &&
		rz_buf_read_le16(buf, &hdr->number_of_relocations) &&
		rz_buf_read_le16(buf, &hdr->number_of_line_numbers) &&
		rz_buf_read_le32(buf, &hdr->charactestics);
}

RZ_IPI bool pe_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream) {
	rz_return_val_if_fail(pdb && stream, false);
	if (!pdb->s_pe) {
		pdb->s_pe = RZ_NEW0(RzPdbPeStream);
	}
	RzBuffer *buf = stream->stream_data;
	RzPdbPeStream *s = pdb->s_pe;
	if (!s) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		return false;
	}
	if (!s->sections_hdrs) {
		s->sections_hdrs = rz_list_newf(free);
	}
	ut32 size = rz_buf_size(buf);
	ut32 read_len = 0;
	while (read_len < size) {
		PeImageSectionHeader *hdr = RZ_NEW0(PeImageSectionHeader);
		if (!hdr) {
			rz_list_free(s->sections_hdrs);
			return false;
		}
		if (!parse_image_header(hdr, buf)) {
			rz_list_free(s->sections_hdrs);
			free(hdr);
			return false;
		}

		read_len += sizeof(PeImageSectionHeader);
		rz_list_append(s->sections_hdrs, hdr);
	}
	return true;
}
RZ_IPI void pe_stream_free(RzPdbPeStream *stream) {
	if (!stream) {
		return;
	}
	rz_list_free(stream->sections_hdrs);
	free(stream);
};
