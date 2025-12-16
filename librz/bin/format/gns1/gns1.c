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
	return rz_buf_read_le32_offset(b, offset, &entry->size) &&
		rz_buf_read_le32_offset(b, offset, &entry->paddr) &&
		rz_buf_read_le32_offset(b, offset, &entry->offset);
}

// heuristic: dword at 0xC >= 0x64 and dword at offset-4 == 0
RZ_IPI bool gns1_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);

	ut64 buf_size = rz_buf_size(b);
	if (buf_size < GNS1_MIN_FILE_SIZE) {
		return false;
	}

	ut64 offset = 0;
	Gns1SegmentEntry first_entry;
	if (!gns1_read_segment(b, &offset, &first_entry)) {
		return false;
	}
	// check 1
	if (first_entry.offset < 0x64) {
		return false;
	}
	// check 2
	ut32 marker = 0;
	if (!rz_buf_read_le32_at(b, first_entry.offset - 4, &marker) || marker != 0) {
		return false;
	}
	// sanity check
	if (first_entry.size == 0 || first_entry.size > buf_size) {
		return false;
	}

	if (first_entry.offset >= buf_size) {
		return false;
	}
	// overflow check
	if (first_entry.offset + first_entry.size > buf_size) {
		return false;
	}

	return true;
}

// load and parse GNS1 segment table from buffer.
RZ_IPI bool gns1_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && b, false);

	Gns1Obj *gns1 = RZ_NEW0(Gns1Obj);
	// base condition checks
	if (!gns1) {
		return false;
	}

	gns1->buf = b;
	gns1->segments = rz_vector_new(sizeof(Gns1SegmentEntry), NULL, NULL);
	if (!gns1->segments) {
		free(gns1);
		return false;
	}

	// parse segment table
	ut64 offset = 0;
	Gns1SegmentEntry entry;
	int consecutive_invalid = 0;
	ut64 file_size = rz_buf_size(b);

	while (gns1_read_segment(b, &offset, &entry)) {
		// end of segment table check
		if (entry.size == 0 && entry.paddr == 0 && entry.offset == 0) {
			break;
		}

		// skipping zero size segments
		if (entry.size == 0) {
			break;
		}

		// skip if too many invalid segments
		if (entry.offset >= file_size || entry.offset + entry.size > file_size) {
			consecutive_invalid++;
			if (consecutive_invalid >= 3) {
				break;
			}
			continue;
		}

		consecutive_invalid = 0;

		rz_vector_push(gns1->segments, &entry);
		gns1->num_segments++;

		// safety limit
		if (gns1->num_segments > 1000) {
			RZ_LOG_ERROR("GNS1: too many segments, file may be corrupted\n");
			break;
		}
	}

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
		return NULL;
	}

	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	// use first segment as entry point
	Gns1SegmentEntry *first = rz_vector_index_ptr(gns1->segments, 0);
	if (first) {
		RzBinAddr *entry = RZ_NEW0(RzBinAddr);
		if (entry) {
			entry->paddr = first->offset;
			// rebase address to INTERNAL_BASE like IDA does
			ut32 core_base = first->paddr & 0xFF000000;
			if (core_base == GNS1_CORE1_BASE || core_base == GNS1_CORE2_BASE) {
				entry->vaddr = GNS1_INTERNAL_BASE + (first->paddr & 0xFFFFFF);
			} else {
				entry->vaddr = first->paddr;
			}
			rz_pvector_push(ret, entry);
		}
	}

	return ret;
}

// create sections from GNS1 segments.
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
		ut32 core_base = entry->paddr & 0xFF000000;
		if (core_base == GNS1_CORE1_BASE || core_base == GNS1_CORE2_BASE) {
			// map both cores to internal base: core0 0x12xxxxxx -> 0x10xxxxxx, core1 0x15xxxxxx -> 0x10xxxxxx
			section->vaddr = GNS1_INTERNAL_BASE + (entry->paddr & 0xFFFFFF);
		} else {
			section->vaddr = entry->paddr;
		}

		if ((entry->paddr & 0xFFFFFF) == 0) {
			section->perm = RZ_PERM_RX;
		} else {
			section->perm = RZ_PERM_RW;
		}

		// determine core and type based on address range
		const char *seg_type = (entry->paddr & 0xFFFFFF) == 0 ? "text" : "data";
		if (entry->paddr >= GNS1_CORE1_BASE && entry->paddr < GNS1_CORE2_BASE) {
			free(section->name);
			section->name = rz_str_newf("core0_%s_%u", seg_type, idx);
		} else if (entry->paddr >= GNS1_CORE2_BASE) {
			free(section->name);
			section->name = rz_str_newf("core1_%s_%u", seg_type, idx);
		} else {
			free(section->name);
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
	info->os = rz_str_dup("firmware");
	info->arch = rz_str_dup("arc");
	info->rclass = rz_str_dup("firmware");
	info->subsystem = rz_str_dup("baseband");
	info->cpu = rz_str_dup("ARC700");
	info->has_va = true;
	info->bits = 32;
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
	rz_structured_data_map_add_unsigned(info, "core0_base", GNS1_CORE1_BASE, true);
	rz_structured_data_map_add_unsigned(info, "core1_base", GNS1_CORE2_BASE, true);
	rz_structured_data_map_add_unsigned(info, "internal_base", GNS1_INTERNAL_BASE, true);

	//  segment table
	RzStructuredData *segments = rz_structured_data_map_add_array(info, "segments");
	if (!segments) {
		rz_structured_data_free(info);
		return NULL;
	}

	Gns1SegmentEntry *entry;
	ut32 idx = 0;
	rz_vector_foreach (gns1->segments, entry) {
		RzStructuredData *seg = rz_structured_data_array_add_map(segments);
		if (!seg) {
			continue;
		}

		rz_structured_data_map_add_unsigned(seg, "index", idx, false);
		rz_structured_data_map_add_unsigned(seg, "size", entry->size, true);
		rz_structured_data_map_add_unsigned(seg, "physical_addr", entry->paddr, true);
		rz_structured_data_map_add_unsigned(seg, "file_offset", entry->offset, true);

		// for core
		const char *core = "unknown";
		if (entry->paddr >= GNS1_CORE1_BASE && entry->paddr < GNS1_CORE2_BASE) {
			core = "core0";
		} else if (entry->paddr >= GNS1_CORE2_BASE) {
			core = "core1";
		}
		rz_structured_data_map_add_string(seg, "core", core);

		// for type
		const char *type = (entry->paddr & 0xFFFFFF) == 0 ? "text" : "data";
		rz_structured_data_map_add_string(seg, "type", type);

		// calc rebase virtual addr
		ut32 core_base = entry->paddr & 0xFF000000;
		ut64 vaddr;
		if (core_base == GNS1_CORE1_BASE || core_base == GNS1_CORE2_BASE) {
			vaddr = GNS1_INTERNAL_BASE + (entry->paddr & 0xFFFFFF);
		} else {
			vaddr = entry->paddr;
		}
		rz_structured_data_map_add_unsigned(seg, "virtual_addr", vaddr, true);
		idx++;
	}

	return info;
}
