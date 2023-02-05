// SPDX-FileCopyrightText: 2014-2020 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_type.h>
#include <string.h>
#include <rz_demangler.h>
#include <mspack.h>

#include "pdb.h"

static bool parse_pdb_stream(RzPdb *pdb, RzPdbMsfStream *stream) {
	if (!pdb || !stream) {
		return false;
	}

	pdb->s_pdb = RZ_NEW0(RzPdbStream);
	RzPdbStream *s = pdb->s_pdb;
	RzBuffer *buf = stream->stream_data;
	if (!rz_buf_read_le32(buf, &s->hdr.version) ||
		!rz_buf_read_le32(buf, &s->hdr.signature) ||
		!rz_buf_read_le32(buf, &s->hdr.age) ||
		!rz_buf_read_le32(buf, &s->hdr.unique_id.data1) ||
		!rz_buf_read_le16(buf, &s->hdr.unique_id.data2) ||
		!rz_buf_read_le16(buf, &s->hdr.unique_id.data3) ||
		rz_buf_read(buf, s->hdr.unique_id.data4, 8) != 8) {
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
	RzPdbMsfStream *ms;
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
	RzPdbMsfStream *msfstream = data;
	rz_buf_free(msfstream->stream_data);
	RZ_FREE(msfstream);
}

static void msf_stream_directory_free(void *data) {
	RzPdbMsfStreamDirectory *msd = data;
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

static RzList /*<RzPdbMsfStream *>*/ *pdb7_extract_streams(RzPdb *pdb, RzPdbMsfStreamDirectory *msd) {
	RzList *streams = rz_list_newf(msf_stream_free);
	if (!streams) {
		goto error_memory;
	}
	for (size_t i = 0; i < msd->NumStreams; i++) {
		RzPdbMsfStream *stream = RZ_NEW0(RzPdbMsfStream);
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
				RZ_FREE(stream);
				RZ_FREE(stream_data);
				rz_list_free(streams);
				return NULL;
			}
			rz_buf_seek(pdb->buf, (long long)block_idx * pdb->super_block->block_size, RZ_BUF_SET);
			rz_buf_read(pdb->buf, stream_data + j * pdb->super_block->block_size, pdb->super_block->block_size);
		}
		stream->stream_data = rz_buf_new_with_pointers(stream_data, stream->stream_size, true);
		if (!stream->stream_data) {
			RZ_FREE(stream);
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

static RzPdbMsfStreamDirectory *pdb7_extract_msf_stream_directory(RzPdb *pdb) {
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
			RZ_FREE(block_map);
			goto error;
		}
		if (block_idx > pdb->super_block->num_blocks) {
			RZ_LOG_ERROR("Error block index.\n");
			RZ_FREE(block_map);
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
	RzBuffer *sd = rz_buf_new_with_pointers(stream_directory, stream_directory_len, true);
	if (!sd) {
		RZ_FREE(stream_directory);
		RZ_FREE(block_map);
		goto error_memory;
	}
	RZ_FREE(block_map);

	RzPdbMsfStreamDirectory *msd = RZ_NEW0(RzPdbMsfStreamDirectory);
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
		if (stream_size == UT32_MAX) {
			msd->StreamSizes[i] = 0;
			continue;
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
	RzPdbMsfStreamDirectory *msd = pdb7_extract_msf_stream_directory(pdb);
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

bool is_compressed_pdb(RzBuffer *buf) {
	ut8 magic[4] = { 0 };
	// avoids to seek back, when using rz_buf_read_at
	if (rz_buf_read_at(buf, 0, magic, sizeof(magic)) != sizeof(magic)) {
		return false;
	} else if (memcmp(magic, CAB_SIGNATURE, sizeof(magic))) {
		return false;
	}
	return true;
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
		RZ_LOG_ERROR("%s: Error reading file \"%s\"\n", __FUNCTION__, filename);
		return false;
	}

	if (is_compressed_pdb(buf)) {
		rz_buf_free(buf);
		RZ_LOG_ERROR("The pdb file %s seems to be compressed, please use idpx command to extract the contents.\n", filename);
		return NULL;
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
	pdb->super_block = RZ_NEW0(RzPdbMsfSuperBlock);
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

	rz_bin_pdb_free(pdb);
	return NULL;
}

/**
 * \brief Free PDB instance
 *
 * \param pdb PDB instance
 * \return void
 */
RZ_API void rz_bin_pdb_free(RzPdb *pdb) {
	if (!pdb) {
		return;
	}
	rz_buf_free(pdb->buf);
	free(pdb->super_block);
	rz_list_free(pdb->streams);
	free(pdb->s_pdb);
	free_dbi_stream(pdb->s_dbi);
	free_gdata_stream(pdb->s_gdata);
	free_omap_stream(pdb->s_omap);
	free_tpi_stream(pdb->s_tpi);
	free_pe_stream(pdb->s_pe);
	free(pdb);
}
