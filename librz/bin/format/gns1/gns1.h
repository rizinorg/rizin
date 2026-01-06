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
#define GNS1_REGION1_BASE       0x12000000 // region_a base
#define GNS1_REGION2_BASE       0x15000000 // region_b base
#define GNS1_INTERNAL_BASE      0x10000000
#define GNS1_ADDRMASK           0xFFFFFF

/**
 * \brief A GNS1 segment entry (12 bytes).
 *
 * Apple C4000 baseband firmware (GNS1.bin) format consists of a segment table
 * at the beginning of the file. Each entry describes a loadable segment.
 *
 * Reference: https://github.com/nlitsme/AppleC4000/blob/master/loadgns.py
 */
typedef enum {
	GNS1_SEG_TEXT,
	GNS1_SEG_DATA
} Gns1SegType;

typedef enum {
	GNS1_REGION_UNKNOWN,
	GNS1_REGION_A, // region_a (possibly core0)
	GNS1_REGION_B // region_b (possible core1)
} Gns1Region;

typedef struct gns1_segment_entry {
	ut32 size; ///< Size of the segment in bytes
	ut32 paddr; ///< Physical address of the segment
	ut32 offset; ///< File offset of the segment data
	Gns1SegType type; ///< Segment type (text/data)
	Gns1Region region; ///< Region (region_a/region_b)
} Gns1SegmentEntry;

/**
 * \brief A GNS1 object file.
 */
typedef struct gns1_obj {
	RzVector /*<Gns1SegmentEntry>*/ *segments; ///< Segments of the binary.
	ut32 num_segments; ///< Number of segments in the file
} Gns1Obj;

RZ_IPI bool gns1_check_buffer(RzBuffer *b);
RZ_IPI bool gns1_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb);
RZ_IPI void gns1_destroy(RzBinFile *bf);
RZ_IPI RzBinInfo *gns1_info(RzBinFile *bf);
RZ_IPI ut64 gns1_baddr(RzBinFile *bf);
RZ_IPI RzPVector /*<RzBinAddr *>*/ *gns1_entries(RzBinFile *bf);
RZ_IPI RzPVector /*<RzBinSection *>*/ *gns1_sections(RzBinFile *bf);
RZ_IPI RzStructuredData *gns1_structure(RzBinFile *bf);

#endif
