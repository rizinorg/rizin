// SPDX-FileCopyrightText: 2014 inisider <inisider@gmail.com>
// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DBI_H
#define DBI_H

enum dbi_stream_version {
	DSV_VC41 = 930803,
	DSV_V50 = 19960307,
	DSV_V60 = 19970606,
	DSV_V70 = 19990903,
	DSV_V110 = 20091201
};

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
} DbiStreamHdr;

typedef struct dbi_stream_ex_header_t {
	ut32 unknown;
	struct SectionContribEntry {
		ut16 Section;
		char Padding1[2];
		st32 Offset;
		st32 Size;
		ut32 Characteristics;
		ut16 ModuleIndex;
		char Padding2[2];
		ut32 DataCrc;
		ut32 RelocCrc;
	} SectionContr;
	ut16 Flags;
	ut16 ModuleSymStream;
	ut32 SymByteSize;
	ut32 C11ByteSize;
	ut32 C13ByteSize;
	ut16 SourceFileCount;
	char Padding[2];
	ut32 Unused2;
	ut32 SourceFileNameIndex;
	ut32 PdbFilePathNameIndex;
	char *ModuleName;
	char *ObjFileName;
} DbiStreamExHdr;

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
} DbiStreamDbgHeader;

typedef struct dbi_stream_t {
	DbiStreamHdr hdr;
	RzList /* DbiStreamExHdr */ *ex_hdrs;
	DbiStreamDbgHeader dbg_hdr;

} DbiStream;

#endif // DBI_H
