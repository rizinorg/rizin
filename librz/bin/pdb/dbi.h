// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_DBI_H
#define PDB_DBI_H

#include <rz_pdb.h>

RZ_IPI bool dbi_stream_parse(RzPdb *pdb, RzPdbMsfStream *stream);
RZ_IPI void dbi_stream_free(RzPdbDbiStream *stream);

enum dbi_stream_version {
	DSV_VC41 = 930803,
	DSV_V50 = 19960307,
	DSV_V60 = 19970606,
	DSV_V70 = 19990903,
	DSV_V110 = 20091201
};

typedef struct {
	PDBSectionOffset offset;
	ut32 size;
	ut32 characteristics;
	ut16 module;
	ut16 pad;
	ut32 data_crc;
	ut32 reloc_crc;
} PDB_DBISectionContrbution;

typedef struct {
	ut32 opened;
	PDB_DBISectionContrbution section;
	ut16 flags;
	ut16 stream;
	ut32 symbols_size;
	ut32 line_size;
	ut32 c13_line_size;
	ut16 files;
	ut16 pad;
	ut32 filename_offsets;
	ut32 source;
	ut32 compiler;
	char *module_name;
	char *object_file_name;
} PDB_DBIModule;

#endif