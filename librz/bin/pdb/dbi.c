// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include "pdb.h"

RZ_IPI void dbi_stream_free(RzPdbDbiStream *stream) {
	if (!stream) {
		return;
	}
	void **it;
	rz_pvector_foreach (stream->modules, it) {
		PDB_DBIModule *m = *it;
		RZ_FREE(m->module_name);
		RZ_FREE(m->object_file_name);
		RZ_FREE(m);
	}
	rz_pvector_free(stream->modules);
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

static bool PDB_DBISectionContrbution_parse(RzBuffer *buf, PDB_DBISectionContrbution *section) {
	ut16 pad = 0;
	return rz_buf_read_le16(buf, &section->offset.section_index) &&
		rz_buf_read_le16(buf, &pad) &&
		rz_buf_read_le32(buf, &section->offset.offset) &&
		rz_buf_read_le32(buf, &section->size) &&
		rz_buf_read_le32(buf, &section->characteristics) &&
		rz_buf_read_le16(buf, &section->module) &&
		rz_buf_read_le16(buf, &section->pad) &&
		rz_buf_read_le32(buf, &section->data_crc) &&
		rz_buf_read_le32(buf, &section->reloc_crc);
}

static bool PDB_DBIModule_parse(RzBuffer *b, PDB_DBIModule *m) {
	return rz_buf_read_le32(b, &m->opened) &&
		PDB_DBISectionContrbution_parse(b, &m->section) &&
		rz_buf_read_le16(b, &m->flags) &&
		rz_buf_read_le16(b, &m->stream) &&
		rz_buf_read_le32(b, &m->symbols_size) &&
		rz_buf_read_le32(b, &m->line_size) &&
		rz_buf_read_le32(b, &m->c13_line_size) &&
		rz_buf_read_le16(b, &m->files) &&
		rz_buf_read_le16(b, &m->pad) &&
		rz_buf_read_le32(b, &m->filename_offsets) &&
		rz_buf_read_le32(b, &m->source) &&
		rz_buf_read_le32(b, &m->compiler) &&
		rz_buf_read_string(b, &m->module_name) > 0 &&
		rz_buf_read_string(b, &m->object_file_name) > 0;
}

static bool parse_dbi_dbg_header(RzPdbDbiStream *s, RzBuffer *buf) {
	return rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_fpo) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_exception) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_fixup) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_omap_to_src) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_omap_from_src) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_section_hdr) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_token_rid_map) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_xdata) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_pdata) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_new_fpo) &&
		rz_buf_read_le16(buf, (ut16 *)&s->dbg_hdr.sn_section_hdr_orig);
}

static bool modules_parse(RzPdbDbiStream *s, RzBuffer *stream_buffer) {
	s->modules = rz_pvector_new(NULL);
	if (!s->modules) {
		return false;
	}

	RzBuffer *b = rz_buf_new_slice(stream_buffer, s->hdr_size, s->hdr.mod_info_size);
	if (!b) {
		return false;
	}
	while (!buf_empty(b)) {
		PDB_DBIModule *m = RZ_NEW0(PDB_DBIModule);
		if (!(m && PDB_DBIModule_parse(b, m) &&
			    buf_align(b, 4))) {
			free(m);
			goto err;
		}
		rz_pvector_push(s->modules, m);
	}
	rz_buf_free(b);
	return true;
err:
	rz_buf_free(b);
	return false;
}

RZ_IPI bool dbi_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream) {
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
	if (!parse_dbi_stream_header(s, buf)) {
		return false;
	}
	s->hdr_size = rz_buf_tell(buf);
	if (!modules_parse(s, buf)) {
		return false;
	}

	// skip these streams
	ut64 pos = s->hdr_size + s->hdr.mod_info_size + s->hdr.section_contribution_size + s->hdr.section_map_size +
		s->hdr.source_info_size + s->hdr.type_server_map_size +
		s->hdr.ec_substream_size;
	rz_buf_seek(buf, pos, RZ_BUF_SET);
	if (!parse_dbi_dbg_header(s, buf)) {
		return false;
	}
	return true;
}
