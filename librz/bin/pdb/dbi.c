// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

RZ_IPI void free_dbi_stream(RzPdbDbiStream *stream) {
	if (!stream) {
		return;
	}
	RzPdbDbiStreamExHdr *ex_hdr;
	RzListIter *it;
	rz_list_foreach (stream->ex_hdrs, it, ex_hdr) {
		RZ_FREE(ex_hdr->ModuleName);
		RZ_FREE(ex_hdr->ObjFileName);
		RZ_FREE(ex_hdr);
	}
	rz_list_free(stream->ex_hdrs);
	free(stream);
}

static bool parse_dbi_stream_header(RzPdbDbiStream *s, RzBuffer *buf) {
	return rz_buf_read_le32(buf, (ut32 *)&s->hdr.version_signature) &&
		rz_buf_read_le32(buf, &s->hdr.version_header) &&
		rz_buf_read_le32(buf, &s->hdr.age) &&
		rz_buf_read_le16(buf, &s->hdr.global_stream_index) &&
		rz_buf_read_le16(buf, &s->hdr.build_number) &&
		rz_buf_read_le16(buf, &s->hdr.public_stream_index) &&
		rz_buf_read_le16(buf, &s->hdr.pdb_dll_version) &&
		rz_buf_read_le16(buf, &s->hdr.sym_record_stream) &&
		rz_buf_read_le16(buf, &s->hdr.pdb_dll_rbld) &&
		rz_buf_read_le32(buf, &s->hdr.mod_info_size) &&
		rz_buf_read_le32(buf, &s->hdr.section_contribution_size) &&
		rz_buf_read_le32(buf, &s->hdr.section_map_size) &&
		rz_buf_read_le32(buf, &s->hdr.source_info_size) &&
		rz_buf_read_le32(buf, &s->hdr.type_server_map_size) &&
		rz_buf_read_le32(buf, &s->hdr.mfc_type_server_index) &&
		rz_buf_read_le32(buf, &s->hdr.optional_dbg_header_size) &&
		rz_buf_read_le32(buf, &s->hdr.ec_substream_size) &&
		rz_buf_read_le16(buf, &s->hdr.flags) &&
		rz_buf_read_le16(buf, &s->hdr.machine) &&
		rz_buf_read_le32(buf, &s->hdr.padding);
}

static bool parse_dbi_stream_section_entry(RzPdbDbiStreamExHdr *hdr, RzBuffer *buf) {
	return rz_buf_read_le16(buf, &hdr->sec_con.Section) &&
		rz_buf_read_le16(buf, (ut16 *)&hdr->sec_con.Padding1) &&
		rz_buf_read_le32(buf, (ut32 *)&hdr->sec_con.Offset) &&
		rz_buf_read_le32(buf, (ut32 *)&hdr->sec_con.Size) &&
		rz_buf_read_le32(buf, &hdr->sec_con.Characteristics) &&
		rz_buf_read_le16(buf, &hdr->sec_con.ModuleIndex) &&
		rz_buf_read_le16(buf, (ut16 *)&hdr->sec_con.Padding2) &&
		rz_buf_read_le32(buf, &hdr->sec_con.DataCrc) &&
		rz_buf_read_le32(buf, &hdr->sec_con.RelocCrc);
}

static bool parse_dbi_stream_ex_header(RzPdbDbiStream *s, RzBuffer *buf) {
	s->ex_hdrs = rz_list_new();
	if (!s->ex_hdrs) {
		// free s-dbi
		return false;
	}
	ut32 ex_size = s->hdr.mod_info_size;
	ut32 read_len = 0;
	bool result = true;
	while (read_len < ex_size) {
		ut32 initial_seek = rz_buf_tell(buf);
		RzPdbDbiStreamExHdr *hdr = RZ_NEW0(RzPdbDbiStreamExHdr);
		if (!hdr) {
			result = false;
			goto err;
		}
		if (!rz_buf_read_le32(buf, &hdr->unknown)) {
			result = false;
			goto err;
		}
		if (!parse_dbi_stream_section_entry(hdr, buf)) {
			result = false;
			goto err;
		}
		if (!rz_buf_read_le16(buf, &hdr->Flags) ||
			!rz_buf_read_le16(buf, &hdr->ModuleSymStream)) {
			result = false;
			goto err;
		}
		if (!rz_buf_read_le32(buf, &hdr->SymByteSize) ||
			!rz_buf_read_le32(buf, &hdr->C11ByteSize) ||
			!rz_buf_read_le32(buf, &hdr->C13ByteSize)) {
			result = false;
			goto err;
		}
		if (!rz_buf_read_le16(buf, &hdr->SourceFileCount) ||
			!rz_buf_read_le16(buf, (ut16 *)&hdr->Padding)) {
			result = false;
			goto err;
		}
		if (!rz_buf_read_le32(buf, &hdr->Unused2) ||
			!rz_buf_read_le32(buf, &hdr->SourceFileNameIndex) ||
			!rz_buf_read_le32(buf, &hdr->PdbFilePathNameIndex)) {
			result = false;
			goto err;
		}

		hdr->ModuleName = rz_buf_get_string(buf, rz_buf_tell(buf));
		ut32 str_length = strlen(hdr->ModuleName) + 1;
		if (str_length) {
			rz_buf_seek(buf, str_length, RZ_BUF_CUR);
		}

		hdr->ObjFileName = rz_buf_get_string(buf, rz_buf_tell(buf));
		str_length = strlen(hdr->ObjFileName) + 1;
		if (str_length) {
			rz_buf_seek(buf, str_length, RZ_BUF_CUR);
		}
		read_len += rz_buf_tell(buf) - initial_seek;
		if ((read_len % 4)) {
			ut16 remain = 4 - (read_len % 4);
			rz_buf_seek(buf, remain, RZ_BUF_CUR);
			read_len += remain;
		}
		rz_list_append(s->ex_hdrs, hdr);
	err:
		if (!result) {
			free(hdr);
			return false;
		}
	}
	if (read_len != ex_size) {
		return false;
	}
	return true;
}

static bool parse_dbi_dbg_header(RzPdbDbiStream *s, RzBuffer *buf) {
	if (!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_fpo) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_exception) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_fixup) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_omap_to_src) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_omap_from_src) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_section_hdr) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_token_rid_map) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_xdata) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_pdata) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_new_fpo) ||
		!rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_section_hdr_orig)) {
		return false;
	}
	return true;
}

RZ_IPI bool parse_dbi_stream(RzPdb *pdb, RzPdbMsfStream *stream) {
	if (!pdb || !stream) {
		return false;
	}
	pdb->s_dbi = RZ_NEW0(RzPdbDbiStream);
	RzPdbDbiStream *s = pdb->s_dbi;
	if (!s) {
		RZ_LOG_ERROR("Error allocating memory.\n");
		return false;
	}
	RzBuffer *buf = stream->stream_data;
	// parse header
	if (!parse_dbi_stream_header(s, buf) || !parse_dbi_stream_ex_header(s, buf)) {
		return false;
	}

	// skip these streams
	ut64 seek = s->hdr.section_contribution_size + s->hdr.section_map_size +
		s->hdr.source_info_size + s->hdr.type_server_map_size +
		s->hdr.ec_substream_size;
	rz_buf_seek(buf, seek, RZ_BUF_CUR);
	if (!parse_dbi_dbg_header(s, buf)) {
		return false;
	}
	return true;
}
