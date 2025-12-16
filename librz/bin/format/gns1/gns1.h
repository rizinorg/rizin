// SPDX-FileCopyrightText: 2025 Zapper9982
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef GNS1_H
#define GNS1_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define GNS1_SEGMENT_ENTRY_SIZE 12
#define GNS1_MIN_FILE_SIZE      64
#define GNS1_CORE1_BASE         0x12000000
#define GNS1_CORE2_BASE         0x15000000
#define GNS1_INTERNAL_BASE      0x10000000

/**
 * \brief A GNS1 segment entry (12 bytes).
 *
 * Apple C4000 baseband firmware (GNS1.bin) format consists of a segment table
 * at the beginning of the file. Each entry describes a loadable segment.
 *
 * Reference: https://github.com/nlitsme/AppleC4000/blob/master/loadgns.py
 */
typedef struct gns1_segment_entry {
	ut32 size;
	ut32 paddr;
	ut32 offset;
} Gns1SegmentEntry;

//  parses the GNS1 file structure.
typedef struct gns1_obj {
	RzVector *segments;
	ut32 num_segments;
	RzBuffer *buf;
} Gns1Obj;

// functions
bool gns1_check_buffer(RzBuffer *b);
bool gns1_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb);
void gns1_destroy(RzBinFile *bf);
RzBinInfo *gns1_info(RzBinFile *bf);
ut64 gns1_baddr(RzBinFile *bf);
RzPVector *gns1_entries(RzBinFile *bf);
RzPVector *gns1_sections(RzBinFile *bf);
RzStructuredData *gns1_structure(RzBinFile *bf);

#endif
