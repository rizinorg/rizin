// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_type.h>
#include <string.h>
#include <rz_demangler.h>

#include "pdb.h"

static char *pdb_type_as_string_regular(const RzTypeDB *db, const RzPdb *pdb, const RzList *types) {
	rz_return_val_if_fail(pdb && db, NULL);
	if (!types) {
		eprintf("there is nothing to print!\n");
	}
	RzListIter *it;
	RzBaseType *type;
	RzStrBuf *buf = rz_strbuf_new(NULL);
	rz_list_foreach (types, it, type) {
		rz_strbuf_append(buf, rz_type_db_base_type_as_pretty_string(db, type, RZ_TYPE_PRINT_MULTILINE | RZ_TYPE_PRINT_END_NEWLINE, 1));
	}
	char *str = strdup(rz_strbuf_get(buf));
	rz_strbuf_free(buf);
	return str;
}

static char *pdb_type_as_string_json(const RzTypeDB *db, const RzPdb *pdb, const RzList *types, PJ *pj) {
	rz_return_val_if_fail(db && pdb && types && pj, NULL);
	RzListIter *it;
	RzBaseType *type;
	pj_o(pj);
	pj_ka(pj, "types");
	rz_list_foreach (types, it, type) {
		switch (type->kind) {
		case RZ_BASE_TYPE_KIND_STRUCT: {
			pj_o(pj);
			pj_ks(pj, "type", "structure");
			pj_ks(pj, "name", type->name);
			pj_kn(pj, "size", type->size);
			pj_ka(pj, "members");
			RzTypeStructMember *memb;
			rz_vector_foreach(&type->struct_data.members, memb) {
				pj_o(pj);
				char *typ = rz_type_as_string(db, memb->type);
				pj_ks(pj, "member_type", typ);
				RZ_FREE(typ);
				pj_ks(pj, "member_name", memb->name);
				pj_kN(pj, "offset", memb->offset);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
			break;
		}
		case RZ_BASE_TYPE_KIND_UNION: {
			pj_o(pj);
			pj_ks(pj, "type", "union");
			pj_ks(pj, "name", type->name);
			pj_kn(pj, "size", type->size);
			pj_ka(pj, "members");
			RzTypeUnionMember *memb;
			rz_vector_foreach(&type->union_data.members, memb) {
				pj_o(pj);
				char *typ = rz_type_as_string(db, memb->type);
				pj_ks(pj, "member_type", typ);
				RZ_FREE(typ);
				pj_ks(pj, "member_name", memb->name);
				pj_kN(pj, "offset", memb->offset);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
			break;
		}
		case RZ_BASE_TYPE_KIND_ENUM: {
			pj_o(pj);
			pj_ks(pj, "type", "enum");
			pj_ks(pj, "name", type->name);
			char *typ = rz_type_as_string(db, type->type);
			pj_ks(pj, "base_type", typ);
			RZ_FREE(typ);
			pj_ka(pj, "cases");
			RzTypeEnumCase *cas;
			rz_vector_foreach(&type->enum_data.cases, cas) {
				pj_o(pj);
				pj_ks(pj, "enum_name", cas->name);
				pj_kn(pj, "enum_val", cas->val);
				pj_end(pj);
			}
			pj_end(pj);
			pj_end(pj);
			break;
		}
		default:
			break;
		}
	}
	pj_end(pj);
	pj_end(pj);
	return NULL;
}

/**
 * \brief return the output text for types in PDB
 * \param db RzTypeDB
 * \param pdb PDB instance
 * \param state output state
 * \return string of pdb types
 */
RZ_API RZ_OWN char *rz_bin_pdb_types_as_string(RZ_NONNULL const RzTypeDB *db, RZ_NONNULL const RzPdb *pdb, const RzCmdStateOutput *state) {
	rz_return_val_if_fail(db && pdb && state, NULL);
	TpiStream *stream = pdb->s_tpi;
	if (!stream) {
		eprintf("There is no tpi stream in current pdb\n");
		return NULL;
	}
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD:
		return pdb_type_as_string_regular(db, pdb, stream->print_type);
	case RZ_OUTPUT_MODE_JSON:
		return pdb_type_as_string_json(db, pdb, stream->print_type, state->d.pj);
	default:
		return NULL;
	}
}

/**
 * \brief return the output text for global symbols in PDB
 * 
 * \param pdb PDB instance
 * \param img_base image base addr
 * \param state output state
 * \return string of pdb symbols
 */
RZ_API RZ_OWN char *rz_bin_pdb_gvars_as_string(RZ_NONNULL const RzPdb *pdb, const ut64 img_base, const RzCmdStateOutput *state) {
	rz_return_val_if_fail(pdb && state, NULL);
	PeImageSectionHeader *sctn_header = 0;
	GDataStream *gsym_data_stream = 0;
	PeStream *pe_stream = 0;
	OmapStream *omap_stream;
	GDataGlobal *gdata = 0;
	RzListIter *it = 0;
	PJ *pj = state->d.pj;
	char *name;
	RzStrBuf *buf = rz_strbuf_new(NULL);
	if (!buf) {
		return NULL;
	}
	RzStrBuf *cmd = rz_strbuf_new(NULL);
	if (!cmd) {
		rz_strbuf_free(buf);
		return NULL;
	}
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_o(pj);
		pj_ka(pj, "gvars");
	}
	gsym_data_stream = pdb->s_gdata;
	pe_stream = pdb->s_pe;
	omap_stream = pdb->s_omap;
	if (!pe_stream) {
		rz_strbuf_free(buf);
		return NULL;
	}
	rz_list_foreach (gsym_data_stream->global_list, it, gdata) {
		sctn_header = rz_list_get_n(pe_stream->sections_hdrs, (gdata->segment - 1));
		if (sctn_header) {
			name = rz_demangler_msvc(gdata->name);
			name = (name) ? name : strdup(gdata->name);
			switch (state->mode) {
			case RZ_OUTPUT_MODE_JSON: // JSON
				pj_o(pj);
				pj_kN(pj, "address", (img_base + omap_remap(omap_stream, gdata->offset + sctn_header->virtual_address)));
				pj_kN(pj, "symtype", gdata->symtype);
				pj_ks(pj, "section_name", sctn_header->name);
				pj_ks(pj, "gdata_name", name);
				pj_end(pj);
				break;
			case RZ_OUTPUT_MODE_STANDARD:
				rz_strbuf_appendf(buf, "0x%08" PFMT64x "  %d  %.*s  %s\n",
					(ut64)(img_base + omap_remap(omap_stream, gdata->offset + sctn_header->virtual_address)),
					gdata->symtype, PDB_SIZEOF_SECTION_NAME, sctn_header->name, name);
				break;
			default:
				break;
			}
			free(name);
		}
	}
	if (state->mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		pj_end(pj);
	}
	char *str = strdup(rz_strbuf_get(buf));
	rz_strbuf_free(buf);
	return str;
}

/**
 * \brief return the command text for global symbols in PDB
 * 
 * \param pdb PDB instance
 * \param img_base image base addr
 * \return command of pdb symbols
 */
RZ_API RZ_OWN char *rz_bin_pdb_gvars_as_cmd_string(RZ_NONNULL const RzPdb *pdb, const ut64 img_base) {
	rz_return_val_if_fail(pdb, NULL);
	PeImageSectionHeader *sctn_header = 0;
	GDataStream *gsym_data_stream = 0;
	PeStream *pe_stream = 0;
	OmapStream *omap_stream;
	GDataGlobal *gdata = 0;
	RzListIter *it = 0;
	char *name;
	char *filtered_name;
	RzStrBuf *cmd_buf = rz_strbuf_new(NULL);
	if (!cmd_buf) {
		return NULL;
	}
	gsym_data_stream = pdb->s_gdata;
	pe_stream = pdb->s_pe;
	omap_stream = pdb->s_omap;
	if (!pe_stream) {
		rz_strbuf_free(cmd_buf);
		return NULL;
	}
	rz_list_foreach (gsym_data_stream->global_list, it, gdata) {
		sctn_header = rz_list_get_n(pe_stream->sections_hdrs, (gdata->segment - 1));
		if (sctn_header) {
			name = rz_demangler_msvc(gdata->name);
			name = (name) ? name : strdup(gdata->name);
			filtered_name = rz_name_filter2(name, true);
			rz_strbuf_appendf(cmd_buf, "f pdb.%s = 0x%" PFMT64x " # %d %.*s\n",
				filtered_name,
				(ut64)(img_base + omap_remap(omap_stream, gdata->offset + sctn_header->virtual_address)),
				gdata->symtype, PDB_SIZEOF_SECTION_NAME, sctn_header->name);
			rz_strbuf_appendf(cmd_buf, "\"fN pdb.%s %s\"\n", filtered_name, name);
			free(filtered_name);
			free(name);
		}
	}
	char *str = strdup(rz_strbuf_get(cmd_buf));
	rz_strbuf_free(cmd_buf);
	return str;
}

static bool parse_pdb_stream(RzPdb *pdb, MsfStream *stream) {
	if (!pdb || !stream) {
		return false;
	}

	pdb->s_pdb = RZ_NEW0(PdbStream);
	PdbStream *s = pdb->s_pdb;
	RzBuffer *buf = stream->stream_data;
	if (!rz_buf_read_le32(buf, &s->hdr.version) ||
		!rz_buf_read_le32(buf, &s->hdr.signature) ||
		!rz_buf_read_le32(buf, &s->hdr.age) ||
		!rz_buf_read_le32(buf, &s->hdr.unique_id.data1) ||
		!rz_buf_read_le16(buf, &s->hdr.unique_id.data2) ||
		!rz_buf_read_le16(buf, &s->hdr.unique_id.data3) ||
		!rz_buf_read_le64(buf, (ut64 *)&s->hdr.unique_id.data4)) {
		return false;
	}

	if (s->hdr.version != VC70) {
		RZ_LOG_ERROR("Error Unsupported PDB version.\n");
		return false;
	}
	return true;
}

static bool parse_streams(RzPdb *pdb) {
	RzListIter *it;
	MsfStream *ms;
	rz_list_foreach (pdb->streams, it, ms) {
		switch (ms->stream_idx) {
		case PDB_STREAM_ROOT:
			break;
		case PDB_STREAM_PDB:
			if (!parse_pdb_stream(pdb, ms)) {
				RZ_LOG_ERROR("Parse pdb stream failed.");
				return false;
			}
			break;
		case PDB_STREAM_TPI:
			if (!parse_tpi_stream(pdb, ms)) {
				RZ_LOG_ERROR("Parse tpi stream failed.");
				return false;
			}
			break;
		case PDB_STREAM_DBI:
			if (!parse_dbi_stream(pdb, ms)) {
				RZ_LOG_ERROR("Parse dbi stream failed.");
				return false;
			}
			break;
		default: {
			if (!pdb->s_dbi) {
				break;
			}
			if (ms->stream_idx == pdb->s_dbi->hdr.sym_record_stream) {
				if (!parse_gdata_stream(pdb, ms)) {
					RZ_LOG_ERROR("Parse gdata stream failed.");
					return false;
				}
			} else if (ms->stream_idx == pdb->s_dbi->dbg_hdr.sn_section_hdr ||
				ms->stream_idx == pdb->s_dbi->dbg_hdr.sn_section_hdr_orig) {
				if (!parse_pe_stream(pdb, ms)) {
					RZ_LOG_ERROR("Parse pe stream failed.");
					return false;
				}
			} else if (ms->stream_idx == pdb->s_dbi->dbg_hdr.sn_omap_to_src ||
				ms->stream_idx == pdb->s_dbi->dbg_hdr.sn_omap_from_src) {
				if (!parse_omap_stream(pdb, ms)) {
					RZ_LOG_ERROR("Parse omap stream failed.");
					return false;
				}
			}
			break;
		}
		}
	}
	return true;
}

static void msf_stream_free(void *data) {
	MsfStream *msfstream = data;
	rz_buf_free(msfstream->stream_data);
	RZ_FREE(msfstream);
}

static void msf_stream_directory_free(void *data) {
	MsfStreamDirectory *msd = data;
	RZ_FREE(msd->StreamSizes);
	rz_buf_free(msd->sd);
	RZ_FREE(msd);
}

static ut64 count_blocks(ut64 length, ut64 block_size) {
	ut64 num_blocks = 0;
	if (block_size > 0) {
		num_blocks = length / block_size;
		if (length % block_size) {
			num_blocks++;
		}
	}
	return num_blocks;
}

static RzList *pdb7_extract_streams(RzPdb *pdb, MsfStreamDirectory *msd) {
	RzList *streams = rz_list_newf(msf_stream_free);
	if (!streams) {
		goto error_memory;
	}
	for (size_t i = 0; i < msd->NumStreams; i++) {
		MsfStream *stream = RZ_NEW0(MsfStream);
		if (!stream) {
			rz_list_free(streams);
			goto error_memory;
		}
		stream->stream_idx = i;
		stream->stream_size = msd->StreamSizes[i];
		stream->blocks_num = count_blocks(stream->stream_size, pdb->super_block->block_size);
		if (!stream->stream_size) {
			stream->stream_data = NULL;
			rz_list_append(streams, stream);
			continue;
		}
		ut8 *stream_data = (ut8 *)malloc((size_t)stream->blocks_num * pdb->super_block->block_size);
		if (!stream_data) {
			RZ_FREE(stream);
			rz_list_free(streams);
			RZ_LOG_ERROR("Error allocating memory.\n");
			return NULL;
		}
		for (size_t j = 0; j < stream->blocks_num; j++) {
			ut32 block_idx;
			if (!rz_buf_read_le32(msd->sd, &block_idx)) {
				rz_list_free(streams);
				return NULL;
			}
			rz_buf_seek(pdb->buf, (long long)block_idx * pdb->super_block->block_size, RZ_BUF_SET);
			rz_buf_read(pdb->buf, stream_data + j * pdb->super_block->block_size, pdb->super_block->block_size);
		}
		stream->stream_data = rz_buf_new_with_bytes(stream_data, stream->stream_size);
		if (!stream->stream_data) {
			RZ_FREE(stream_data);
			rz_list_free(streams);
			goto error_memory;
		}
		rz_list_append(streams, stream);
	}
	msf_stream_directory_free(msd);
	return streams;

error_memory:
	RZ_LOG_ERROR("Error memory allocation.\n");
	return NULL;
}

static MsfStreamDirectory *pdb7_extract_msf_stream_directory(RzPdb *pdb) {
	// Get block map
	ut32 block_num = count_blocks(pdb->super_block->num_directory_bytes, pdb->super_block->block_size);
	if (!block_num) {
		RZ_LOG_ERROR("Error block map size.\n");
		goto error;
	}
	rz_buf_seek(pdb->buf, (long long)pdb->super_block->block_size * pdb->super_block->block_map_addr, RZ_BUF_SET);
	ut32 *block_map = (ut32 *)malloc(sizeof(ut32) * block_num);
	if (!block_map) {
		goto error_memory;
	}
	for (size_t i = 0; i < block_num; i++) {
		ut32 block_idx;
		if (!rz_buf_read_le32(pdb->buf, &block_idx)) {
			goto error;
		}
		if (block_idx > pdb->super_block->num_blocks) {
			RZ_LOG_ERROR("Error block index.\n");
			goto error;
		}
		block_map[i] = block_idx;
	}

	ut32 stream_directory_len = block_num * pdb->super_block->block_size;
	ut8 *stream_directory = (ut8 *)malloc(stream_directory_len);
	if (!stream_directory) {
		RZ_FREE(block_map);
		goto error_memory;
	}
	for (size_t i = 0; i < block_num; i++) {
		rz_buf_seek(pdb->buf, (long long)block_map[i] * pdb->super_block->block_size, RZ_BUF_SET);
		rz_buf_read(pdb->buf, stream_directory + i * pdb->super_block->block_size, pdb->super_block->block_size);
	}
	RzBuffer *sd = rz_buf_new_with_bytes(stream_directory, stream_directory_len);
	if (!sd) {
		RZ_FREE(stream_directory);
		RZ_FREE(block_map);
		goto error_memory;
	}
	RZ_FREE(block_map);

	MsfStreamDirectory *msd = RZ_NEW0(MsfStreamDirectory);
	if (!msd) {
		goto error_memory;
	}
	if (!rz_buf_read_le32(sd, &msd->NumStreams)) {
		RZ_FREE(msd);
		goto error;
	}
	msd->StreamSizes = (ut32 *)malloc(msd->NumStreams * sizeof(ut32));
	msd->sd = sd;
	if (!msd->StreamSizes) {
		RZ_FREE(msd);
		goto error_memory;
	}
	ut32 total_blocks = 0;
	for (size_t i = 0; i < msd->NumStreams; i++) {
		ut32 stream_size;
		if (!rz_buf_read_le32(sd, &stream_size)) {
			RZ_FREE(msd);
			goto error;
		}
		msd->StreamSizes[i] = stream_size;
		ut32 blocks = count_blocks(stream_size, pdb->super_block->block_size);
		total_blocks += blocks;
	}
	//				NumStreams 						StreamsSizes 				StreamsBlockMap
	ut32 msd_size = sizeof(ut32) + msd->NumStreams * sizeof(ut32) + total_blocks * sizeof(ut32);
	if (msd_size != pdb->super_block->num_directory_bytes) {
		RZ_LOG_ERROR("Error stream directory size.\n");
		RZ_FREE(msd);
		goto error;
	}
	return msd;

error_memory:
	RZ_LOG_ERROR("Error memory allocation.\n");
error:
	return NULL;
}

static bool pdb7_parse(RzPdb *pdb) {
	MsfStreamDirectory *msd = pdb7_extract_msf_stream_directory(pdb);
	if (!msd) {
		RZ_LOG_ERROR("Error extracting stream directory.\n");
		goto error;
	}
	pdb->streams = pdb7_extract_streams(pdb, msd);
	if (!pdb->streams) {
		msf_stream_directory_free(msd);
		RZ_LOG_ERROR("Error extracting streams.\n");
		goto error;
	}
	return parse_streams(pdb);
error:
	return false;
}

/**
 * \brief Parse PDB file given the path
 * 
 * \param filename path of the PDB file
 * \return RzPdb *
 */
RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_file(RZ_NONNULL const char *filename) {
	rz_return_val_if_fail(filename, NULL);
	RzBuffer *buf = rz_buf_new_slurp(filename);
	if (!buf) {
		eprintf("%s: Error reading file \"%s\"\n", __FUNCTION__, filename);
		return false;
	}
	return rz_bin_pdb_parse_from_buf(buf);
}

/**
 * \brief Parse PDB from the buffer
 * 
 * \param buf mmap of the PDB file
 * \return RzPdb *
 */
RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_buf(RZ_NONNULL const RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	RzPdb *pdb = RZ_NEW0(RzPdb);
	if (!pdb) {
		goto error;
	}
	pdb->buf = (RzBuffer *)buf;
	pdb->super_block = RZ_NEW0(MsfSuperBlock);
	st64 len = rz_buf_read(pdb->buf, (ut8 *)pdb->super_block->file_magic, PDB_SIGNATURE_LEN);
	if (len != PDB_SIGNATURE_LEN) {
		RZ_LOG_ERROR("Wrong magic length!\n");
		goto error;
	}
	if (memcmp(pdb->super_block->file_magic, PDB_SIGNATURE, PDB_SIGNATURE_LEN)) {
		RZ_LOG_ERROR("PDB Signature Error!\n");
		goto error;
	}
	if (!rz_buf_read_le32(pdb->buf, &pdb->super_block->block_size) ||
		!rz_buf_read_le32(pdb->buf, &pdb->super_block->free_block_map_block) ||
		!rz_buf_read_le32(pdb->buf, &pdb->super_block->num_blocks) ||
		!rz_buf_read_le32(pdb->buf, &pdb->super_block->num_directory_bytes) ||
		!rz_buf_read_le32(pdb->buf, &pdb->super_block->unknown) ||
		!rz_buf_read_le32(pdb->buf, &pdb->super_block->block_map_addr)) {
		goto error;
	}
	ut64 bufsize = rz_buf_size((RzBuffer *)buf); // length of whole PDB file
	bool valid =
		pdb->super_block->num_blocks > 0 &&
		(ut64)pdb->super_block->num_blocks * pdb->super_block->block_size == bufsize &&
		pdb->super_block->free_block_map_block < pdb->super_block->num_blocks &&
		pdb->super_block->num_directory_bytes > 0;
	if (!valid) {
		RZ_LOG_ERROR("Invalid MSF superblock!\n");
		goto error;
	}
	if (!pdb7_parse(pdb)) {
		goto error;
	}
	return pdb;
error:

	return NULL;
}

/**
 * \brief Free PDB instance
 * 
 * \param pdb PDB instance
 * \return void 
 */
RZ_API void rz_bin_pdb_free(RzPdb *pdb) {
	rz_buf_free(pdb->buf);
	RZ_FREE(pdb->super_block);
	rz_list_free(pdb->streams);
	RZ_FREE(pdb->s_pdb);
	free_dbi_stream(pdb->s_dbi);
	RZ_FREE(pdb->s_dbi);
	free_gdata_stream(pdb->s_gdata);
	RZ_FREE(pdb->s_gdata);
	free_omap_stream(pdb->s_omap);
	RZ_FREE(pdb->s_omap);
	free_tpi_stream(pdb->s_tpi);
	RZ_FREE(pdb->s_tpi);
	RZ_FREE(pdb);
}
