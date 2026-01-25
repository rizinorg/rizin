// SPDX-FileCopyrightText: 2025 Zapper9982
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Implementation of Apple C4000 baseband firmware (GNS1.bin) parser.
 *
 * Detection heuristic:
 * - Dword at offset 0xC (first chunk offset) must be >= 0x64
 * - Dword at offset 0x8 (should be 0, end of list marker in a valid table)
 *
 * Reference: https://github.com/nlitsme/AppleC4000/blob/master/loadgns.py
 */
#include "gns1.h"
#include <rz_util/rz_str.h>

static bool gns1_read_segment(RzBuffer *b, ut64 *offset, Gns1SegmentEntry *entry) {
	bool ok = rz_buf_read_le32_offset(b, offset, &entry->size) &&
		rz_buf_read_le32_offset(b, offset, &entry->paddr) &&
		rz_buf_read_le32_offset(b, offset, &entry->offset);
	if (!ok)
		return false;

	// Set type
	entry->type = (entry->paddr & GNS1_ADDRMASK) == 0 ? GNS1_SEG_TEXT : GNS1_SEG_DATA;

	// Set region (named region_a/region_b to avoid speculation about meaning)
	if (entry->paddr >= GNS1_REGION1_BASE && entry->paddr < GNS1_REGION2_BASE) {
		entry->region = GNS1_REGION_A;
	} else if (entry->paddr >= GNS1_REGION2_BASE) {
		entry->region = GNS1_REGION_B;
	} else {
		entry->region = GNS1_REGION_UNKNOWN;
	}
	return true;
}

static inline ut64 gns1_translate_vaddr(ut32 paddr) {
	ut32 core_base = paddr & 0xFF000000;
	if (core_base == GNS1_REGION1_BASE || core_base == GNS1_REGION2_BASE) {
		return GNS1_INTERNAL_BASE + (paddr & GNS1_ADDRMASK);
	}
	return paddr;
}

// heuristic: dword at 0xC >= 0x64 and dword at offset-4 == 0
RZ_IPI bool gns1_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);

	ut64 buf_size = rz_buf_size(b);
	// Check minimum file size for a valid GNS1 binary
	if (buf_size < GNS1_MIN_FILE_SIZE) {
		return false;
	}

	ut64 offset = 0;
	Gns1SegmentEntry first_entry;
	// Parse the first segment entry from the segment table
	if (!gns1_read_segment(b, &offset, &first_entry)) {
		return false;
	}

	// Validate segment size is nonzero and does not exceed file size
	if (first_entry.size == 0 || first_entry.size > buf_size) {
		return false;
	}
	// Validate segment offset is within file and at least 0x64 (per format spec)
	if (first_entry.offset < 0x64 || first_entry.offset >= buf_size) {
		return false;
	}
	// Validate segment does not overflow file bounds
	if (first_entry.offset + first_entry.size > buf_size) {
		return false;
	}

	// Check for required zero marker before segment data (end-of-table marker)
	ut32 marker = 0;
	if (!rz_buf_read_le32_at(b, first_entry.offset - 4, &marker) || marker != 0) {
		return false;
	}

	return true;
}

// load and parse GNS1 segment table from buffer.
RZ_IPI bool gns1_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && b, false);

	Gns1Obj *gns1 = RZ_NEW0(Gns1Obj);
	// Check allocation for GNS1 object
	if (!gns1) {
		return false;
	}

	gns1->segments = rz_vector_new(sizeof(Gns1SegmentEntry), NULL, NULL);
	if (!gns1->segments) {
		free(gns1);
		return false;
	}

	// Parse segment table entries from buffer
	ut64 offset = 0;
	Gns1SegmentEntry entry;
	ut64 file_size = rz_buf_size(b);
	int invalid_count = 0;

	while (gns1_read_segment(b, &offset, &entry)) {
		// End of segment table: size==0 marks end (per reference loader)
		if (entry.size == 0) {
			break;
		}

		// Validate segment offset and size are within file bounds
		if (entry.offset >= file_size || entry.offset + entry.size > file_size) {
			invalid_count++;
			// Allow at most 3 invalid segments in total
			if (invalid_count >= 3) {
				RZ_LOG_ERROR("GNS1: 3 invalid segments found, Stop parsing segments\n");
				break;
			}
			continue;
		}

		rz_vector_push(gns1->segments, &entry);
		gns1->num_segments++;

		// Safety limit: avoid excessive segment count (possible corruption)
		if (gns1->num_segments > 1000) {
			RZ_LOG_ERROR("GNS1: too many segments, file may be corrupted\n");
			break;
		}
	}

	// Fail if no valid segments were found
	if (gns1->num_segments == 0) {
		RZ_LOG_ERROR("GNS1: no valid segments found\n");
		rz_vector_free(gns1->segments);
		free(gns1);
		return false;
	}

	obj->bin_obj = gns1;
	return true;
}

// free GNS1 object resources
RZ_IPI void gns1_destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}

	Gns1Obj *gns1 = bf->o->bin_obj;
	rz_vector_free(gns1->segments);
	free(gns1);
}

// get base address for GNS1 binary.
RZ_IPI ut64 gns1_baddr(RzBinFile *bf) {
	return GNS1_INTERNAL_BASE;
}

// get entry points from GNS1 file
RZ_IPI RzPVector /*<RzBinAddr *>*/ *gns1_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Gns1Obj *gns1 = bf->o->bin_obj;
	if (gns1->num_segments == 0) {
		return rz_pvector_new(free);
	}

	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	Gns1SegmentEntry *region_a_text = NULL;
	Gns1SegmentEntry *region_b_text = NULL;

	Gns1SegmentEntry *entry;
	rz_vector_foreach (gns1->segments, entry) {
		if (entry->type != GNS1_SEG_TEXT) {
			continue;
		}
		if (entry->region == GNS1_REGION_A) {
			if (!region_a_text || entry->paddr < region_a_text->paddr) {
				region_a_text = entry;
			}
		} else if (entry->region == GNS1_REGION_B) {
			if (!region_b_text || entry->paddr < region_b_text->paddr) {
				region_b_text = entry;
			}
		}
	}

	if (region_a_text) {
		RzBinAddr *entry = RZ_NEW0(RzBinAddr);
		if (entry) {
			entry->paddr = region_a_text->offset;
			entry->vaddr = gns1_translate_vaddr(region_a_text->paddr);
			rz_pvector_push(ret, entry);
		}
	}
	if (region_b_text) {
		RzBinAddr *entry = RZ_NEW0(RzBinAddr);
		if (entry) {
			entry->paddr = region_b_text->offset;
			entry->vaddr = gns1_translate_vaddr(region_b_text->paddr);
			rz_pvector_push(ret, entry);
		}
	}

	return ret;
}

/**
 * \brief Create sections from GNS1 segments.
 *
 * Note: These are segments, not sections (in ELF terminology).
 * The GNS1 format does not provide information about actual sections,
 * so we expose the raw segments as RzBinSection objects for analysis.
 */
RZ_IPI RzPVector /*<RzBinSection *>*/ *gns1_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Gns1Obj *gns1 = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	Gns1SegmentEntry *entry;
	ut32 idx = 0;
	rz_vector_foreach (gns1->segments, entry) {
		RzBinSection *section = RZ_NEW0(RzBinSection);
		if (!section) {
			continue;
		}

		section->name = rz_str_newf("segment_%u", idx);
		section->paddr = entry->offset;
		section->size = entry->size;
		section->vsize = entry->size;

		// rebase to internal base
		section->vaddr = gns1_translate_vaddr(entry->paddr);

		if ((entry->paddr & 0xFFFFFF) == 0) {
			section->perm = RZ_PERM_RX;
		} else {
			section->perm = RZ_PERM_RW;
		}

		// use enum for type and region (region_a/region_b for user-facing names)
		const char *seg_type = entry->type == GNS1_SEG_TEXT ? "text" : "data";
		const char *region = entry->region == GNS1_REGION_A ? "region_a" : (entry->region == GNS1_REGION_B ? "region_b" : NULL);
		free(section->name);
		if (region) {
			section->name = rz_str_newf("%s_%s_%u", region, seg_type, idx);
		} else {
			section->name = rz_str_newf("%s_%u", seg_type, idx);
		}

		rz_pvector_push(ret, section);
		idx++;
	}

	return ret;
}

// get Binary Information
RZ_IPI RzBinInfo *gns1_info(RzBinFile *bf) {
	RzBinInfo *info = RZ_NEW0(RzBinInfo);
	if (!info) {
		return NULL;
	}

	info->file = bf->file ? rz_str_dup(bf->file) : NULL;
	info->type = rz_str_dup("GNS1");
	info->machine = rz_str_dup("Apple C4000 Baseband");
	info->arch = rz_str_dup("arc");
	info->rclass = rz_str_dup("firmware");
	info->subsystem = rz_str_dup("baseband");
	info->cpu = rz_str_dup("ARC700");
	info->has_va = true;
	info->bits = 16;
	info->big_endian = false;

	return info;
}

// structured data about the GNS1 segment table
RZ_IPI RzStructuredData *gns1_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Gns1Obj *gns1 = bf->o->bin_obj;
	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	// header information
	rz_structured_data_map_add_unsigned(info, "num_segments", gns1->num_segments, false);
	rz_structured_data_map_add_unsigned(info, "region_a_base", GNS1_REGION1_BASE, true);
	rz_structured_data_map_add_unsigned(info, "region_b_base", GNS1_REGION2_BASE, true);
	rz_structured_data_map_add_unsigned(info, "internal_base", GNS1_INTERNAL_BASE, true);

	//  segment table
	RzStructuredData *segments = rz_structured_data_map_add_array(info, "segments");
	if (!segments) {
		rz_structured_data_free(info);
		return NULL;
	}

	Gns1SegmentEntry *entry;
	rz_vector_foreach (gns1->segments, entry) {
		RzStructuredData *seg = rz_structured_data_array_add_map(segments);
		if (!seg) {
			continue;
		}

		rz_structured_data_map_add_unsigned(seg, "size", entry->size, true);
		rz_structured_data_map_add_unsigned(seg, "physical_addr", entry->paddr, true);
		rz_structured_data_map_add_unsigned(seg, "file_offset", entry->offset, true);

		// for region (user-facing: region_a/region_b)
		const char *region = NULL;
		switch (entry->region) {
		case GNS1_REGION_A:
			region = "region_a";
			break;
		case GNS1_REGION_B:
			region = "region_b";
			break;
		default:
			region = "unknown";
			break;
		}
		rz_structured_data_map_add_string(seg, "region", region);

		// for type
		const char *type = entry->type == GNS1_SEG_TEXT ? ".text" : ".data";
		rz_structured_data_map_add_string(seg, "type", type);

		// calc rebase virtual addr
		rz_structured_data_map_add_unsigned(seg, "virtual_addr", gns1_translate_vaddr(entry->paddr), true);
	}

	return info;
}
