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
	ut32 size; ///< Size of the segment in bytes
	ut32 paddr; ///< Physical address of the segment
	ut32 offset; ///< File offset of the segment data
} Gns1SegmentEntry;

//  parses the GNS1 file structure.
typedef struct gns1_obj {
	RzVector *segments; ///< Vector of Gns1SegmentEntry
	ut32 num_segments; ///< Number of segments in the file
	RzBuffer *buf; ///< Buffer containing the file data
} Gns1Obj;

// functions
RZ_API bool gns1_check_buffer(RzBuffer *b);
RZ_API bool gns1_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb);
RZ_API void gns1_destroy(RzBinFile *bf);
RZ_API RzBinInfo *gns1_info(RzBinFile *bf);
RZ_API ut64 gns1_baddr(RzBinFile *bf);
RZ_API RzPVector *gns1_entries(RzBinFile *bf);
RZ_API RzPVector *gns1_sections(RzBinFile *bf);
RZ_API RzStructuredData *gns1_structure(RzBinFile *bf);

#endif
