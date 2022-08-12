// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_PDB_H
#define RZ_PDB_H

#include <rz_util.h>
#include <rz_type.h>
#include <rz_cmd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CAB_SIGNATURE     "MSCF"
#define PDB_SIGNATURE     "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
#define PDB_SIGNATURE_LEN 32

#define GET_BF(value, start, len) (((value) >> (start)) & ((1 << len) - 1))

// DBI
typedef struct dbi_stream_header_t {
	st32 version_signature;
	ut32 version_header;
	ut32 age;
	ut16 global_stream_index;
	ut16 build_number;
	ut16 public_stream_index;
	ut16 pdb_dll_version;
	ut16 sym_record_stream;
	ut16 pdb_dll_rbld;
	ut32 mod_info_size;
	ut32 section_contribution_size;
	ut32 section_map_size;
	ut32 source_info_size;
	ut32 type_server_map_size;
	ut32 mfc_type_server_index;
	ut32 optional_dbg_header_size;
	ut32 ec_substream_size;
	ut16 flags;
	ut16 machine;
	ut32 padding;
} RzPdbRzPdbDbiStreamHdr;

typedef struct {
	st16 sn_fpo;
	st16 sn_exception;
	st16 sn_fixup;
	st16 sn_omap_to_src;
	st16 sn_omap_from_src;
	st16 sn_section_hdr;
	st16 sn_token_rid_map;
	st16 sn_xdata;
	st16 sn_pdata;
	st16 sn_new_fpo;
	st16 sn_section_hdr_orig;
} RzPdbRzPdbDbiStreamDbgHeader;

typedef struct dbi_stream_t {
	RzPdbRzPdbDbiStreamHdr hdr;
	RzList /*<RzPdbDbiStreamExHdr *>*/ *ex_hdrs;
	RzPdbRzPdbDbiStreamDbgHeader dbg_hdr;

} RzPdbDbiStream;

// GDATA
typedef struct {
	RzList /*<GDataGlobal *>*/ *global_list;
} RzPdbGDataStream;

// OMAP
typedef struct
{
	RzList /*<OmapEntry *>*/ *entries;
	ut32 *froms;
} RzPdbOmapStream;

// PE Stream
typedef struct {
	RzList /*<PeImageSectionHeader *>*/ *sections_hdrs;
} RzPdbPeStream;

// TPI
typedef enum {
	NEAR_C = 0x00000000,
	FAR_C = 0x00000001,
	NEAR_PASCAL = 0x00000002,
	FAR_PASCAL = 0x00000003,
	NEAR_FAST = 0x00000004,
	FAR_FAST = 0x00000005,
	SKIPPED = 0x00000006,
	NEAR_STD = 0x00000007,
	FAR_STD = 0x00000008,
	NEAR_SYS = 0x00000009,
	FAR_SYS = 0x0000000A,
	THISCALL = 0x0000000B,
	MIPSCALL = 0x0000000C,
	GENERIC = 0x0000000D,
	ALPHACALL = 0x0000000E,
	PPCCALL = 0x0000000F,
	SHCALL = 0x00000010,
	ARMCALL = 0x00000011,
	AM33CALL = 0x00000012,
	TRICALL = 0x00000013,
	SH5CALL = 0x00000014,
	M32RCALL = 0x00000015,
	CLRCALL = 0x00000016,
	INLINECALL = 0x00000017,
	NEAR_VEC = 0X00000018,
	RESERVED = 0x00000019,
	MAX_CV_CALL
} RzPdbTpiCallingConvention;

typedef enum {
	V40 = 19950410,
	V41 = 19951122,
	V50 = 19961031,
	V70 = 19990903,
	V80 = 20040203,
} RzPdbTpiStreamVersion;

typedef struct tpi_stream_header_t {
	RzPdbTpiStreamVersion Version;
	ut32 HeaderSize;
	ut32 TypeIndexBegin;
	ut32 TypeIndexEnd;
	ut32 TypeRecordBytes;

	ut16 HashStreamIndex;
	ut16 HashAuxStreamIndex;
	ut32 HashKeySize;
	ut32 NumHashBuckets;

	st32 HashValueBufferOffset;
	ut32 HashValueBufferLength;

	st32 IndexOffsetBufferOffset;
	ut32 IndexOffsetBufferLength;

	st32 HashAdjBufferOffset;
	ut32 HashAdjBufferLength;
} RzPdbTpiStreamHeader;

typedef struct tpi_types {
	RBNode rb;
	ut32 type_index;
	ut16 leaf_type;
	ut16 length;
	void *type_data;
	bool parsed;
} RzPdbTpiType;

typedef struct tpi_stream_t {
	RzPdbTpiStreamHeader header;
	RBTree types;
	ut64 type_index_base;
	RzList /*<RzBaseType *>*/ *print_type;
} RzPdbTpiStream;

// PDB
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
} RzRzPdbStreamIndex;

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

/**
 * Like GUID in windows.h/guiddef.h
 */
typedef struct {
	ut32 data1;
	ut16 data2;
	ut16 data3;
	ut8 data4[8];
} RzPdbGuid;

typedef struct {
	ut32 version;
	ut32 signature;
	ut32 age;
	RzPdbGuid unique_id;
} RzRzPdbStreamHeader;

typedef struct {
	RzRzPdbStreamHeader hdr;
	/* Todo: parse named table */
} RzPdbStream;

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
} RzPdbMsfSuperBlock;

typedef struct {
	ut32 stream_idx;
	ut32 stream_size;
	ut32 blocks_num;
	RzBuffer *stream_data;
} RzPdbMsfStream;

typedef struct {
	ut32 NumStreams;
	ut32 *StreamSizes;
	RzBuffer *sd;
} RzPdbMsfStreamDirectory;

typedef struct rz_pdb_t {
	RzBuffer *buf; // mmap of file
	RzPdbMsfSuperBlock *super_block;
	RzList /*<RzPdbMsfStream *>*/ *streams;
	RzPdbStream *s_pdb;
	RzPdbDbiStream *s_dbi;
	RzPdbTpiStream *s_tpi;
	RzPdbGDataStream *s_gdata;
	RzPdbOmapStream *s_omap;
	RzPdbPeStream *s_pe;
} RzPdb;

// PDB
RZ_API bool rz_bin_pdb_extract_in_folder(RZ_NONNULL const char *file_cab, RZ_NONNULL const char *output_dir);
RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_file(RZ_NONNULL const char *filename);
RZ_API RZ_OWN RzPdb *rz_bin_pdb_parse_from_buf(RZ_NONNULL const RzBuffer *buf);
RZ_API void rz_bin_pdb_free(RzPdb *pdb);

// TPI
RZ_API RZ_BORROW RzPdbTpiType *rz_bin_pdb_get_type_by_index(RZ_NONNULL RzPdbTpiStream *stream, ut32 index);
RZ_API RZ_OWN char *rz_bin_pdb_calling_convention_as_string(RZ_NONNULL RzPdbTpiCallingConvention idx);
RZ_API bool rz_bin_pdb_type_is_fwdref(RZ_NONNULL RzPdbTpiType *t);
RZ_API RZ_BORROW RzList /*<RzPdbTpiType *>*/ *rz_bin_pdb_get_type_members(RZ_NONNULL RzPdbTpiStream *stream, RzPdbTpiType *t);
RZ_API RZ_BORROW char *rz_bin_pdb_get_type_name(RZ_NONNULL RzPdbTpiType *type);
RZ_API ut64 rz_bin_pdb_get_type_val(RZ_NONNULL RzPdbTpiType *type);

// OMAP
RZ_API int rz_bin_pdb_omap_remap(RZ_NONNULL RzPdbOmapStream *omap_stream, int address);

#ifdef __cplusplus
}
#endif

#endif
