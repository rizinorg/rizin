// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_type.h>
#include <string.h>

#include "pdb.h"

/**
 * \brief Prints out types in a default format "idpi" command
 * 
 * \param pdb pdb structure for printing function
 * \param types List of types
 */
static void print_types_regular(RzTypeDB *db, const RzPdb *pdb, const RzList *types) {
	rz_return_if_fail(pdb);
	if (!types) {
		eprintf("there is nothing to print!\n");
	}
	RzListIter *it;
	RzBaseType *type;
	rz_list_foreach (types, it, type) {
		RzStrBuf *buf = rz_strbuf_new(NULL);
		switch (type->kind) {
		case RZ_BASE_TYPE_KIND_STRUCT: {
			rz_strbuf_appendf(buf, "struct %s { \n", type->name);
			RzTypeStructMember *memb;
			rz_vector_foreach(&type->struct_data.members, memb) {
				char *declaration = rz_type_identifier_declaration_as_string(db, memb->type, memb->name);
				if (memb->type->kind == RZ_TYPE_KIND_CALLABLE) {
					rz_strbuf_appendf(buf, "\t%s \n", declaration);
				} else {
					rz_strbuf_appendf(buf, "\t%s %s; \n", declaration, memb->name);
				}
				free(declaration);
			}
			rz_strbuf_append(buf, " }\n");
			break;
		}
		case RZ_BASE_TYPE_KIND_ENUM: {
			rz_strbuf_appendf(buf, "enum %s { \n", type->name);
			RzTypeEnumCase *cas;
			rz_vector_foreach(&type->enum_data.cases, cas) {
				rz_strbuf_appendf(buf, "\t%s = 0x%" PFMT64x ", \n", cas->name, cas->val);
			}
			rz_strbuf_append(buf, " }\n");
			break;
		}
		case RZ_BASE_TYPE_KIND_UNION: {
			rz_strbuf_appendf(buf, "union %s { \n", type->name);
			RzTypeUnionMember *memb;
			rz_vector_foreach(&type->union_data.members, memb) {
				char *declaration = rz_type_identifier_declaration_as_string(db, memb->type, memb->name);
				rz_strbuf_appendf(buf, "\t%s %s; \n", declaration, memb->name);
				free(declaration);
			}
			rz_strbuf_append(buf, " }\n");
			break;
		}
		default:
			break;
		}
		rz_cons_printf("%s\n", rz_strbuf_get(buf));
		rz_strbuf_free(buf);
	}
}

/**
 * \brief Prints out types in a json format - "idpij" command
 * 
 * \param pdb pdb structure for printing function
 * \param types List of types
 */
static void print_types_json(RzTypeDB *db, const RzPdb *pdb, PJ *pj, const RzList *types) {
	rz_return_if_fail(pdb && types && pj);

	RzListIter *it;
	RzBaseType *type;
	rz_list_foreach (types, it, type) {
		pj_o(pj);
		switch (type->kind) {
		case RZ_BASE_TYPE_KIND_STRUCT: {
			pj_ks(pj, "type", "structure");
			pj_ks(pj, "name", type->name);
			pj_kn(pj, "size", type->size);
			pj_ka(pj, "members");
			RzTypeStructMember *memb;
			rz_vector_foreach(&type->struct_data.members, memb) {
				pj_ks(pj, "member_type", rz_type_as_string(db, memb->type));
				pj_ks(pj, "member_name", memb->name);
				pj_kN(pj, "offset", memb->offset);
				pj_end(pj);
			}
			pj_end(pj);
			break;
		}
		case RZ_BASE_TYPE_KIND_UNION: {
			pj_ks(pj, "type", "union");
			pj_ks(pj, "name", type->name);
			pj_kn(pj, "size", type->size);
			pj_ka(pj, "members");
			RzTypeUnionMember *memb;
			rz_vector_foreach(&type->union_data.members, memb) {
				pj_ks(pj, "member_type", rz_type_as_string(db, memb->type));
				pj_ks(pj, "member_name", memb->name);
				pj_kN(pj, "offset", memb->offset);
				pj_end(pj);
			}
			pj_end(pj);
			break;
		}
		case RZ_BASE_TYPE_KIND_ENUM: {
			pj_ks(pj, "type", "enum");
			pj_ks(pj, "name", type->name);
			pj_ks(pj, "base_type", rz_type_as_string(db, type->type));
			pj_ka(pj, "cases");
			RzTypeEnumCase *cas;
			rz_vector_foreach(&type->enum_data.cases, cas) {
				pj_ks(pj, "enum_name", cas->name);
				pj_kn(pj, "enum_val", cas->val);
				pj_end(pj);
			}
			pj_end(pj);
			break;
		}
		default:
			break;
		}
		pj_end(pj);
	}
}

/**
 * \brief Prints out all the type information in regular,json or pf format
 * 
 * \param pdb PDB information
 * \param mode printing mode
 */
RZ_API void rz_bin_pdb_print_types(RzTypeDB *db, const RzPdb *pdb, PJ *pj, const int mode) {
	TpiStream *stream = pdb->s_tpi;

	if (!stream) {
		eprintf("There is no tpi stream in current pdb\n");
		return;
	}
	switch (mode) {
	case 'd': print_types_regular(db, pdb, stream->print_type); return;
	case 'j': print_types_json(db, pdb, pj, stream->print_type); return;
	}
}

RZ_API void rz_bin_pdb_print_gvars(RzPdb *pdb, ut64 img_base, PJ *pj, int format) {
	PeImageSectionHeader *sctn_header = 0;
	GDataStream *gsym_data_stream = 0;
	PeStream *pe_stream = 0;
	OmapStream *omap_stream;
	GDataGlobal *gdata = 0;
	RzListIter *it = 0;
	char *name;

	if (format == 'j') {
		pj_ka(pj, "gvars");
	}
	gsym_data_stream = pdb->s_gdata;
	pe_stream = pdb->s_pe;
	omap_stream = pdb->s_omap;
	if (!pe_stream) {
		return;
	}
	rz_list_foreach (gsym_data_stream->global_list, it, gdata) {
		sctn_header = rz_list_get_n(pe_stream->sections_hdrs, (gdata->segment - 1));
		if (sctn_header) {
			name = rz_bin_demangle_msvc(gdata->name);
			name = (name) ? name : strdup(gdata->name);
			switch (format) {
			case 'j': // JSON
				pj_o(pj);
				pj_kN(pj, "address", (img_base + omap_remap(omap_stream, gdata->offset + sctn_header->virtual_address)));
				pj_kN(pj, "symtype", gdata->symtype);
				pj_ks(pj, "section_name", sctn_header->name);
				pj_ks(pj, "gdata_name", name);
				pj_end(pj);
				break;
			case 'd':
				rz_cons_printf("0x%08" PFMT64x "  %d  %.*s  %s\n",
					(ut64)(img_base + omap_remap(omap_stream, gdata->offset + sctn_header->virtual_address)),
					gdata->symtype, PDB_SIZEOF_SECTION_NAME, sctn_header->name, name);
				break;
			default:
				break;
			}
			free(name);
		}
	}
	if (format == 'j') {
		pj_end(pj);
	}
}

static bool parse_pdb_stream(RzPdb *pdb, MsfStream *stream) {
	if (!pdb || !stream) {
		return false;
	}

	pdb->s_pdb = RZ_NEW0(PdbStream);
	PdbStream *s = pdb->s_pdb;
	RzBuffer *buf = stream->stream_data;
	s->hdr.version = rz_buf_read_le32(buf);
	if (s->hdr.version != VC70) {
		RZ_LOG_ERROR("Error Unsupported PDB version.\n");
		return false;
	}
	s->hdr.signature = rz_buf_read_le32(buf);
	s->hdr.age = rz_buf_read_le32(buf);
	s->hdr.unique_id.data1 = rz_buf_read_le32(buf);
	s->hdr.unique_id.data2 = rz_buf_read_le16(buf);
	s->hdr.unique_id.data3 = rz_buf_read_le16(buf);
	*(ut64 *)s->hdr.unique_id.data4 = rz_buf_read_le64(buf);
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
			parse_pdb_stream(pdb, ms);
			break;
		case PDB_STREAM_TPI:
			parse_tpi_stream(pdb, ms);
			break;
		case PDB_STREAM_DBI:
			parse_dbi_stream(pdb, ms);
			break;
		default: {
			if (!pdb->s_dbi) {
				break;
			}
			if (ms->stream_idx == pdb->s_dbi->hdr.sym_record_stream) {
				parse_gdata_stream(pdb, ms);
			} else if (ms->stream_idx == pdb->s_dbi->dbg_hdr.sn_section_hdr ||
				ms->stream_idx == pdb->s_dbi->dbg_hdr.sn_section_hdr_orig) {
				parse_pe_stream(pdb, ms);
			} else if (ms->stream_idx == pdb->s_dbi->dbg_hdr.sn_omap_to_src ||
				ms->stream_idx == pdb->s_dbi->dbg_hdr.sn_omap_from_src) {
				parse_omap_stream(pdb, ms);
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
		ut8 *stream_data = (ut8 *)malloc(stream->blocks_num * pdb->super_block->block_size);
		for (size_t j = 0; j < stream->blocks_num; j++) {
			ut32 block_idx = rz_buf_read_le32(msd->sd);
			rz_buf_seek(pdb->buf, block_idx * pdb->super_block->block_size, RZ_BUF_SET);
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
	rz_buf_seek(pdb->buf, pdb->super_block->block_size * pdb->super_block->block_map_addr, RZ_BUF_SET);
	ut32 *block_map = (ut32 *)malloc(sizeof(ut32) * block_num);
	if (!block_map) {
		goto error_memory;
	}
	for (size_t i = 0; i < block_num; i++) {
		ut32 block_idx = rz_buf_read_le32(pdb->buf);
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
		rz_buf_seek(pdb->buf, block_map[i] * pdb->super_block->block_size, RZ_BUF_SET);
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
	msd->NumStreams = rz_buf_read_le32(sd);
	msd->StreamSizes = (ut32 *)malloc(msd->NumStreams * sizeof(ut32));
	msd->sd = sd;
	if (!msd->StreamSizes) {
		RZ_FREE(msd);
		goto error_memory;
	}
	ut32 total_blocks = 0;
	for (size_t i = 0; i < msd->NumStreams; i++) {
		ut32 stream_size = rz_buf_read_le32(sd);
		msd->StreamSizes[i] = stream_size;
		ut32 blocks = count_blocks(stream_size, pdb->super_block->block_size);
		total_blocks += blocks;
	}
	//				NumStreams						 StreamsSizes				   StreamsBlockMap
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

RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_file(RZ_NONNULL const char *filename) {
	RzBuffer *buf = rz_buf_new_slurp(filename);
	if (!buf) {
		eprintf("%s: Error reading file \"%s\"\n", __FUNCTION__, filename);
		return false;
	}
	return rz_bin_pdb_parse_from_buf(buf);
}

RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_buf(RZ_NONNULL RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);
	RzPdb *pdb = RZ_NEW0(RzPdb);
	if (!pdb) {
		goto error;
	}
	pdb->buf = buf;
	pdb->super_block = RZ_NEW0(MsfSuperBlock);
	rz_buf_read(pdb->buf, (ut8 *)pdb->super_block->file_magic, PDB_SIGNATURE_LEN);
	if (memcmp(pdb->super_block->file_magic, PDB_SIGNATURE, PDB_SIGNATURE_LEN)) {
		RZ_LOG_ERROR("PDB Signature Error!\n");
		goto error;
	}
	pdb->super_block->block_size = rz_buf_read_le32(pdb->buf);
	pdb->super_block->free_block_map_block = rz_buf_read_le32(pdb->buf);
	pdb->super_block->num_blocks = rz_buf_read_le32(pdb->buf);
	pdb->super_block->num_directory_bytes = rz_buf_read_le32(pdb->buf);
	pdb->super_block->unknown = rz_buf_read_le32(pdb->buf);
	pdb->super_block->block_map_addr = rz_buf_read_le32(pdb->buf);

	ut64 bufsize = buf->methods->get_size(buf); // length of whole PDB file
	bool valid =
		pdb->super_block->num_blocks > 0 &&
		pdb->super_block->num_blocks * pdb->super_block->block_size == bufsize &&
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
