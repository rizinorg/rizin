// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_H
#define PDB_H

#include <rz_util.h>
#include <rz_type.h>
#include "dbi.h"
#include "tpi.h"
#include "gdata.h"
#include "omap.h"
#include "stream_pe.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PDB_SIGNATURE     "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
#define PDB_SIGNATURE_LEN 32

typedef enum pdb_stream_index_t {
	PDB_STREAM_ROOT = 0, // PDB_ROOT_DIRECTORY
	PDB_STREAM_PDB, // PDB STREAM INFO
	PDB_STREAM_TPI, // TYPE INFO
	PDB_STREAM_DBI, // DEBUG INFO

	PDB_STREAM_GSYM,
	PDB_STREAM_SECT_HDR,
	PDB_STREAM_SECT__HDR_ORIG,
	PDB_STREAM_OMAP_TO_SRC,
	PDB_STREAM_OMAP_FROM_SRC,
	PDB_STREAM_FPO,
	PDB_STREAM_FPO_NEW,
	PDB_STREAM_XDATA,
	PDB_STREAM_PDATA,
	PDB_STREAM_TOKEN_RID_MAP,
	PDB_STREAM_MAX
} PDBStreamIndex;

enum pdb_stream_version {
	VC2 = 19941610,
	VC4 = 19950623,
	VC41 = 19950814,
	VC50 = 19960307,
	VC98 = 19970604,
	VC70Dep = 19990604,
	VC70 = 20000404,
	VC80 = 20030901,
	VC110 = 20091201,
	VC140 = 20140508,
};

typedef struct {
	ut32 data1;
	ut16 data2;
	ut16 data3;
	ut8 data4[8];
} pdb_guid;

typedef struct {
	ut32 version;
	ut32 signature;
	ut32 age;
	pdb_guid unique_id;
} pdb_stream_header;

typedef struct {
	pdb_stream_header hdr;
	/* Todo: parse named table */
} PdbStream;

/**
 * \brief MSF file format header https://llvm.org/docs/PDB/MsfFile.html#the-superblock
 */
typedef struct {
	char file_magic[PDB_SIGNATURE_LEN]; ///< Must be equal to "Microsoft C / C++ MSF 7.00\\r\\n" followed by the bytes 1A 44 53 00 00 00.
	ut32 block_size; ///< The block size of the internal file system.
	ut32 free_block_map_block; ///< The index of a block within the file, the data within that block is not used.
	ut32 num_blocks; ///< The total number of blocks in the file
	ut32 num_directory_bytes; ///< The size of the stream directory, in bytes.
	ut32 unknown;
	ut32 block_map_addr; ///< The index of a block within the MSF file.
} MsfSuperBlock;

typedef struct {
	ut32 stream_idx;
	ut32 stream_size;
	ut32 blocks_num;
	RzBuffer *stream_data;
} MsfStream;

typedef struct {
	ut32 NumStreams;
	ut32 *StreamSizes;
	RzBuffer *sd;
} MsfStreamDirectory;

typedef struct rz_pdb_t {
	RzBuffer *buf; // mmap of file
	MsfSuperBlock *super_block;
	RzList /* MsfStream */ *streams;
	PdbStream *s_pdb;
	DbiStream *s_dbi;
	TpiStream *s_tpi;
	GDataStream *s_gdata;
	OmapStream *s_omap;
	PeStream *s_pe;
} RzPdb;

RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_file(RZ_NONNULL const char *filename);
RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_buf(RZ_NONNULL RzBuffer *buf);
RZ_API void rz_bin_pdb_print_types(RzTypeDB *db, const RzPdb *pdb, PJ *pj, const int mode);
RZ_API void rz_bin_pdb_print_gvars(RzPdb *pdb, ut64 img_base, PJ *pj, int format);
RZ_API void rz_bin_pdb_free(RzPdb *pdb);

// OMAP
RZ_IPI bool parse_omap_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI void free_omap_stream(OmapStream *stream);
RZ_IPI int omap_remap(void *stream, int address);

// GDATA
RZ_IPI bool parse_gdata_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI void free_gdata_stream(GDataStream *stream);

// DBI
RZ_IPI bool parse_dbi_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI void free_dbi_stream(DbiStream *stream);

//PE
RZ_IPI bool parse_pe_stream(RzPdb *pdb, MsfStream *stream);
RZ_IPI void free_pe_stream(PeStream *stream);

//TPI
RZ_IPI bool parse_tpi_stream(RzPdb *pdb, MsfStream *stream);
// Get TpiType data by type_index
RZ_API TpiType *rz_bin_pdb_get_type_by_index(TpiStream *stream, ut32 index);
RZ_API char *rz_bin_pdb_calling_convention_as_string(TpiCallingConvention idx);
RZ_API bool rz_bin_pdb_type_is_fwdref(TpiType *t);
RZ_API RzList *rz_bin_pdb_get_type_members(TpiStream *stream, TpiType *t);
RZ_API char *rz_bin_pdb_get_type_name(TpiType *type);
RZ_API ut64 rz_bin_pdb_get_type_val(TpiType *type);
RZ_IPI TpiType *parse_simple_type(TpiStream *stream, ut32 idx);
RZ_IPI void free_tpi_stream(TpiStream *stream);

#ifdef __cplusplus
}
#endif

#endif