// SPDX-FileCopyrightText: 2021 Basstorm <basstorm@nyist.edu.cn>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PDB_DBI_H
#define PDB_DBI_H

#include <rz_util.h>

enum dbi_stream_version {
	DSV_VC41 = 930803,
	DSV_V50 = 19960307,
	DSV_V60 = 19970606,
	DSV_V70 = 19990903,
	DSV_V110 = 20091201
};

typedef struct SectionContribEntry {
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

typedef struct dbi_stream_ex_header_t {
	ut32 unknown;
	SectionContr sec_con;
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
} RzPdbDbiStreamExHdr;

#endif