// SPDX-FileCopyrightText: 2025 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "mdt.h"
#include "../elf/elf.h"
#include "../elf/elf_parser.h"
#include "rz_bin.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_buf.h"
#include "rz_util/rz_file.h"
#include "rz_util/rz_itv.h"
#include "rz_util/rz_str.h"
#include <rz_vector.h>
#include <rz_util.h>
#include <rz_io.h>

static inline bool is_layout_bin(size_t p_flags) {
	return (p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_LAYOUT;
}

RZ_IPI RzBinMdtPart *rz_bin_mdt_part_new(const char *name, size_t p_flags) {
	RzBinMdtPart *part = RZ_NEW0(RzBinMdtPart);
	if (!part) {
		return NULL;
	}
	part->name = rz_str_dup(name);
	part->relocatable = p_flags & QCOM_MDT_RELOCATABLE;
	part->is_layout = is_layout_bin(p_flags);
	return part;
}

RZ_IPI void rz_bin_mdt_part_free(RZ_OWN RZ_NULLABLE RzBinMdtPart *part) {
	if (!part) {
		return;
	}
	rz_bin_virtual_file_free(part->vfile);
	switch (part->format) {
	default:
		break;
	case RZ_BIN_MDT_PART_ELF:
		Elf32_rz_bin_elf_free(part->obj.elf);
		break;
	case RZ_BIN_MDT_PART_MBN:
		mbn_destroy_obj(part->obj.mbn);
		break;
	}
	rz_bin_map_free(part->map);
	rz_pvector_free(part->relocs);
	rz_pvector_free(part->symbols);
	rz_pvector_free(part->sections);
	rz_pvector_free(part->sub_maps);
	free(part->patches_vfile_name);
	free(part->relocs_vfile_name);
	free(part->name);
	free(part);
}

RZ_IPI RzBinMdtObj *rz_bin_mdt_obj_new() {
	RzBinMdtObj *obj = RZ_NEW0(RzBinMdtObj);
	if (!obj) {
		return NULL;
	}
	obj->parts = rz_pvector_new((RzPVectorFree)rz_bin_mdt_part_free);
	return obj;
}

RZ_IPI void rz_bin_mdt_obj_free(RzBinMdtObj *obj) {
	if (!obj) {
		return;
	}
	Elf32_rz_bin_elf_free(obj->header);
	rz_pvector_free(obj->parts);
	free(obj->name);
	free(obj);
}

static inline bool is_elf32(RzBuffer *b) {
	return elf_check_buffer_aux(b) == ELFCLASS32;
}

RZ_IPI bool rz_bin_mdt_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);
	if (!is_elf32(b) || rz_buf_size(b) <= RZ_BIN_ELF_TINY_SIZE) {
		return false;
	}

	ELFOBJ *elf = NULL;
	RzBinObjectLoadOptions obj_opts = {
		.baseaddr = 0,
		.loadaddr = 0,
		.elf_load_sections = false,
	};

	elf = Elf32_rz_bin_elf_new_buf(b, &obj_opts);
	if (!elf || !elf->segments) {
		Elf32_rz_bin_elf_free(elf);
		return false;
	}
	RzBinElfSegment *sgmt = rz_vector_head(elf->segments);
	if (!sgmt) {
		Elf32_rz_bin_elf_free(elf);
		return false;
	}
	bool mdt_flags_set = is_layout_bin(sgmt->data.p_flags);
	Elf32_rz_bin_elf_free(elf);
	return mdt_flags_set;
}

static bool load_unidentified_obj_data(RZ_OUT RzBinMdtPart *part, RZ_OWN RzBinElfSegment *segment, RZ_OWN RzBinVirtualFile *vfile, RZ_OWN RzBinMap *map) {
	rz_return_val_if_fail(part && segment && vfile && map, false);
	return true;
}

static bool load_mbn_obj_data(RZ_OUT RzBinMdtPart *part, RZ_OWN RzBinElfSegment *segment, RZ_OWN RzBinVirtualFile *vfile, RZ_OWN RzBinMap *map) {
	rz_return_val_if_fail(part && segment && vfile && map, false);

	SblHeader *mbn = RZ_NEW0(SblHeader);
	ut64 offset = 0;
	if (!mbn || !mbn_read_sbl_header(vfile->buf, mbn, &offset)) {
		mbn_destroy_obj(mbn);
		mbn = NULL;
	}
	part->obj.mbn = mbn;
	return true;
}

static void prefix_name(char **to_prefix, const char *prefix) {
	rz_return_if_fail(to_prefix && prefix);
	const char *separator = *to_prefix[0] == '.' ? "" : ".";
	char *prefixed_name = rz_str_newf("%s%s%s", prefix, separator, RZ_STR_ISEMPTY(*to_prefix) ? "0x0" : *to_prefix);
	free(*to_prefix);
	*to_prefix = prefixed_name;
}

/**
 * \brief Couldn't figure out why, but the ELF module is inconsistent with the
 * virtual base addresses. Sometimes it updates the symbols and relocs with the
 * base address passed via the load options, sometimes it doesn't.
 * It seems to depend if the binary has relocations.
 * But since fixing it is too much trouble, this workaround has to do it.
 */
static void normalize_vaddr_of_elf(ELFOBJ *elf, ut64 base_vaddr) {
	elf->baddr = base_vaddr;
	RzBinElfSegment *segment;
	rz_bin_elf_foreach_segments(elf, segment) {
		segment->data.p_vaddr += base_vaddr;
	}

	RzBinElfSection *section;
	rz_bin_elf_foreach_sections(elf, section) {
		if (section->rva != UT64_MAX) {
			section->rva += base_vaddr;
		}
	}

	RzBinElfReloc *reloc;
	rz_bin_elf_foreach_relocs(elf, reloc) {
		reloc->vaddr += base_vaddr;
		reloc->target_vaddr += base_vaddr;
	}

	RzBinElfSymbol *symbol;
	rz_bin_elf_foreach_symbols(elf, symbol) {
		symbol->vaddr += base_vaddr;
	}
}

static bool load_elf_obj_data(RZ_OUT RzBinMdtPart *part, RZ_OWN RzBinElfSegment *segment, RZ_OWN RzBinVirtualFile *vfile, RZ_OWN RzBinMap *map, bool big_endian) {
	rz_return_val_if_fail(part && segment && vfile && map, false);

	ELFOBJ *elf = NULL;
	RzBinObjectLoadOptions obj_opts = {
		.force_elf_to_use_baddr = true,
		.baseaddr = 0,
		.loadaddr = 0,
		.elf_load_sections = segment->data.p_type == PT_LOAD,
		.patch_relocs = true,
		.big_endian = big_endian,
	};

	elf = Elf32_rz_bin_elf_new_buf(vfile->buf, &obj_opts);
	if (!elf) {
		RZ_LOG_ERROR("Failed to load segment '%s' as ELF.\n", part->name);
		rz_buf_free(vfile->buf);
		rz_bin_map_free(map);
		free(vfile);
		return false;
	}

	part->obj.elf = elf;
	part->patches_vfile_name = rz_str_newf("patches.%s", part->name);
	part->relocs_vfile_name = rz_str_newf("relocs.%s", part->name);

	normalize_vaddr_of_elf(part->obj.elf, part->map->vaddr);

	// Maps - Add the normal ELF maps and the patch maps.
	part->sub_maps = patched_maps_elf_only(part->obj.elf, part->map->psize, part->vfile->buf, part->map->vaddr, part->patches_vfile_name, part->relocs_vfile_name);
	if (!part->sub_maps) {
		rz_warn_if_reached();
		return false;
	}
	void **it;
	rz_pvector_foreach (part->sub_maps, it) {
		RzBinMap *patched_elf_map = *it;
		char *part_relative_name = rz_str_newf("%s.%s", part->map->name, patched_elf_map->name);
		free(patched_elf_map->name);
		if (!patched_elf_map->vfile_name) {
			// This map has no vfile set. This means the IO layer will attempt to
			// read from the "main" file (the initially opened .mdt file). Of course unsuccessfully.
			// So we set the virtual file of the part here.
			patched_elf_map->vfile_name = strdup(part->map->name);
		}
		patched_elf_map->paddr += part->map->paddr;
		patched_elf_map->name = part_relative_name;
	}

	// Symbols
	if (Elf_(rz_bin_elf_has_symbols)(part->obj.elf)) {
		RzPVector *elf_symbols = elf_symbols_obj(part->obj.elf);
		if (!elf_symbols) {
			rz_warn_if_reached();
			return false;
		}
		part->symbols = elf_symbols;
	}

	// sections
	if (Elf_(rz_bin_elf_has_sections)(part->obj.elf)) {
		RzPVector *elf_sections = elf_sections_obj(part->obj.elf, part->map->psize);
		if (!elf_sections) {
			rz_warn_if_reached();
			return false;
		}
		while (!rz_pvector_empty(elf_sections)) {
			RzBinSection *section = rz_pvector_pop(elf_sections);
			// Fix the name for those. So they can be uniquely identified to which part they belong.
			prefix_name(&section->name, part->name);
			rz_pvector_push(part->sections, section);
		}
		rz_pvector_free(elf_sections);
	}

	// relocs
	if (Elf_(rz_bin_elf_has_relocs)(part->obj.elf) && part->obj.elf->buf_patched) {
		RzPVector *elf_relocs = elf_relocs_obj(part->obj.elf, part->map->vaddr, part->obj.elf->buf_patched);
		if (!elf_relocs) {
			rz_warn_if_reached();
			return false;
		}
		part->relocs = elf_relocs;
	}

	return true;
}

RzBinSection *elf_to_bin_segment(RzBinElfSegment *esegment, const char *name) {
	RzBinSection *bseg = RZ_NEW0(RzBinSection);
	rz_return_val_if_fail(bseg, NULL);

	bseg->paddr = esegment->data.p_paddr;
	bseg->size = esegment->data.p_filesz;
	bseg->vsize = esegment->data.p_memsz;
	bseg->vaddr = esegment->data.p_vaddr;
	bseg->perm = esegment->data.p_flags;
	bseg->is_segment = true;
	bseg->is_data = !(esegment->data.p_flags & PF_X);
	bseg->align = esegment->data.p_align;
	bseg->flags = esegment->data.p_flags;
	bseg->name = rz_str_dup(name);
	return bseg;
}

static RzBinMdtPart *segment_to_mdt_part(RzBinElfSegment *segment, size_t part_num, const char *suffix_less_path, bool big_endian) {
	RzBuffer *vfile_buffer = NULL;
	char *segment_file_path = NULL;
	RzBinMdtPart *part = NULL;
	RzBinMap *map = NULL;
	RzBinVirtualFile *vfile = NULL;

	segment_file_path = rz_str_newf("%s.b%02" PFMTSZu, suffix_less_path, part_num);
	if (!segment_file_path) {
		rz_warn_if_reached();
		goto error;
	}
	const char *segment_name = rz_file_basename(segment_file_path);
	if (!segment_name) {
		segment_name = segment_file_path;
	}
	part = rz_bin_mdt_part_new(segment_name, segment->data.p_flags);

	bool segment_file_exists = rz_file_exists(segment_file_path);
	bool zero_segment = segment->data.p_filesz == 0;
	if (zero_segment && segment_file_exists) {
		RZ_LOG_WARN("The segment size for '%s' is 0. But the file exists. Skip loading.\n", segment_file_path);
		goto error;
	} else if (!zero_segment && !segment_file_exists) {
		RZ_LOG_WARN("The segment size for '%s' is 0x%" PFMT32x ". But the file doesn't exist. Skip loading.\n", segment_file_path, segment->data.p_filesz);
		goto error;
	}

	// Read <name>.bNN
	vfile_buffer = zero_segment ? rz_buf_new_empty(segment->data.p_memsz) : rz_buf_new_file(segment_file_path, O_RDONLY, 0);
	if (!vfile_buffer) {
		RZ_LOG_ERROR("Failed to read '%s'\n", segment_file_path);
		goto error;
	}

	vfile = RZ_NEW0(RzBinVirtualFile);
	if (!vfile) {
		goto error;
	}
	vfile->buf = vfile_buffer;
	vfile->buf_owned = true;
	vfile->name = strdup(part->name);

	map = RZ_NEW0(RzBinMap);
	if (!map) {
		rz_bin_virtual_file_free(vfile);
		goto error;
	}
	map->paddr = 0;
	map->psize = segment->data.p_filesz;
	map->vsize = segment->data.p_memsz;
	map->vaddr = segment->data.p_vaddr;
	map->perm = segment->data.p_flags & (PF_X | PF_W | PF_R);
	map->vfile_name = strdup(part->name);
	map->name = strdup(part->name);

	part->paddr = segment->data.p_paddr;
	part->pflags = segment->data.p_flags;
	part->map = map;
	part->vfile = vfile;
	part->sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	RzBinSection *bseg = elf_to_bin_segment(segment, part->name);
	if (!bseg) {
		goto error;
	}
	rz_pvector_push(part->sections, bseg);
	// Segments are also passed as Sections.
	if (is_elf32(vfile->buf)) {
		part->format = RZ_BIN_MDT_PART_ELF;
		if (!load_elf_obj_data(part, segment, vfile, map, big_endian)) {
			goto error;
		}
	} else if ((segment->data.p_flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_SIGNATURE) {
		part->format = RZ_BIN_MDT_PART_MBN;
		if (!load_mbn_obj_data(part, segment, vfile, map)) {
			// Not a critical error. Because it is irrelevant for the actual binary.
			RZ_LOG_WARN("Failed to load MBN signature segment. Header info won't be available.\n");
		}
	} else {
		part->format = RZ_BIN_MDT_PART_UNIDENTIFIED;
		if (!load_unidentified_obj_data(part, segment, vfile, map)) {
			goto error;
		}
	}
	free(segment_file_path);
	return part;

error:
	rz_bin_mdt_part_free(part);
	free(segment_file_path);
	return NULL;
}

RZ_IPI bool rz_bin_mdt_check_filename(const char *filename) {
	rz_return_val_if_fail(filename, NULL);
	return rz_str_endswith_icase(filename, ".mdt");
	;
}

static char *get_peripheral_name(const char *filename) {
	if (!rz_bin_mdt_check_filename(filename)) {
		return NULL;
	}
	char *peripheral = rz_str_dup(filename);
	char *dot = strrchr(peripheral, '.');
	if (!dot) {
		free(peripheral);
		return NULL;
	}
	*dot = '\0';
	return peripheral;
}

RZ_IPI bool rz_bin_mdt_load_buffer(RzBinFile *bf, RZ_OUT RzBinObject *obj, RzBuffer *buf, RZ_UNUSED Sdb *sdb) {
	rz_return_val_if_fail(obj && buf, false);
	if (!rz_bin_mdt_check_buffer(buf)) {
		RZ_LOG_ERROR("Unsupported binary.\n");
		return false;
	}
	RzBinMdtObj *mdt = rz_bin_mdt_obj_new();
	if (!mdt) {
		return false;
	}

	mdt->name = get_peripheral_name(bf->file);
	if (!mdt->name) {
		RZ_LOG_ERROR("Filename \"%s\" doesn't indicate it is an .mdt peripheral image.\n", bf->file);
		goto error;
	}

	RzBinObjectLoadOptions obj_opts = {
		.baseaddr = UT64_MAX,
		.loadaddr = 0,
		.elf_load_sections = false,
	};
	mdt->header = Elf32_rz_bin_elf_new_buf(buf, &obj_opts);
	if (!mdt->header) {
		RZ_LOG_ERROR("Failed to parse .mdt ELF header.\n");
		goto error;
	}

	size_t i;
	RzBinElfSegment *segment;
	rz_vector_enumerate (mdt->header->segments, segment, i) {
		RzBinMdtPart *part = segment_to_mdt_part(segment, i, mdt->name, mdt->header->big_endian);
		if (!part) {
			continue;
		}
		rz_pvector_push(mdt->parts, part);
	}

	obj->bin_obj = mdt;
	return true;

error:
	rz_bin_mdt_obj_free(mdt);
	return false;
}

RZ_IPI void rz_bin_mdt_destroy(RzBinFile *bf) {
	rz_return_if_fail(bf && bf->o && bf->o->bin_obj);
	rz_bin_mdt_obj_free(bf->o->bin_obj);
}

RZ_IPI RZ_OWN RzPVector /*<RzBinVirtualFile *>*/ *rz_bin_mdt_virtual_files(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	const RzBinMdtObj *mdt = bf->o->bin_obj;
	RzPVector *vfiles = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	void **it;
	rz_pvector_foreach (mdt->parts, it) {
		RzBinMdtPart *part = *it;
		RzBinVirtualFile *clone = rz_bin_virtual_file_clone(part->vfile);
		if (!clone) {
			continue;
		}
		rz_pvector_push(vfiles, clone);
		if (!part->relocs) {
			continue;
		}

		if (part->patches_vfile_name) {
			RzBinVirtualFile *patches = RZ_NEW0(RzBinVirtualFile);
			patches->buf = part->obj.elf->buf_patched;
			patches->buf_owned = false;
			patches->name = rz_str_dup(part->patches_vfile_name);
			rz_pvector_push(vfiles, patches);
		}
		if (part->relocs_vfile_name) {
			ut64 reloc_size = elf_reloc_targets_vfile_size(part->obj.elf);
			if (!reloc_size) {
				continue;
			}
			RzBuffer *buf = rz_buf_new_empty(reloc_size);
			RzBinVirtualFile *relocs = RZ_NEW0(RzBinVirtualFile);
			if (!relocs || !buf) {
				rz_buf_free(buf);
				free(relocs);
				continue;
			}
			relocs->buf = buf;
			relocs->buf_owned = true;
			relocs->name = rz_str_dup(part->relocs_vfile_name);
			rz_pvector_push(vfiles, relocs);
		}
	}
	return vfiles;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinMap *>*/ *rz_bin_mdt_get_maps(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	const RzBinMdtObj *mdt = bf->o->bin_obj;
	RzPVector *maps = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!maps) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (mdt->parts, it) {
		RzBinMdtPart *part = *it;
		if (!part->sub_maps || part->is_layout) {
			// The first ELF file is always the overall firmware layout.
			RzBinMap *clone = rz_bin_map_clone(part->map);
			if (!clone) {
				continue;
			}
			rz_pvector_push(maps, clone);
			continue;
		}

		// Add the patched ELF maps
		void **it;
		rz_pvector_foreach (part->sub_maps, it) {
			RzBinMap *clone = rz_bin_map_clone(*it);
			if (!clone) {
				continue;
			}
			rz_pvector_push(maps, clone);
		}
	}
	return maps;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinAddr *>*/ *rz_bin_mdt_get_entry_points(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	const RzBinMdtObj *mdt = bf->o->bin_obj;
	RzPVector *entries = rz_pvector_new((RzPVectorFree)free);
	if (!entries) {
		return NULL;
	}
	RzBinAddr *entry = elf_addr_new_from_paddr(mdt->header, mdt->header->ehdr.e_entry);
	if (!entry) {
		rz_pvector_free(entries);
		return NULL;
	}
	// For the firmware initialization the entry is at a physical address of course.
	// We search for the fitting segment and calculate the virtual address.
	// Because Rizin can't handle the MMU physical address space.
	RzBinElfSegment *seg;
	rz_bin_elf_foreach_segments(mdt->header, seg) {
		RzIntervalBoundedUt64 seg_phy_range;
		seg_phy_range.a = seg->data.p_paddr;
		seg_phy_range.b = seg->data.p_paddr + seg->data.p_memsz;
		seg_phy_range.bound = RZ_INTERVAL_BOUND_RIGHT_OPEN;

		if (rz_itv_bound_contains_ut64(&seg_phy_range, entry->paddr) == RZ_INTERVAL_IN) {
			entry->paddr = (entry->paddr - seg_phy_range.a);
			entry->vaddr = seg->data.p_vaddr + entry->paddr;
			entry->type = RZ_BIN_ENTRY_TYPE_INIT;
			entry->bits = mdt->header->bits;
			break;
		}
	}
	rz_pvector_push(entries, entry);
	return entries;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinSymbol *>*/ *rz_bin_mdt_symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	const RzBinMdtObj *mdt = bf->o->bin_obj;
	RzPVector *symbols = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!symbols) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (mdt->parts, it) {
		RzBinMdtPart *part = *it;
		while (part->symbols && !rz_pvector_empty(part->symbols)) {
			rz_pvector_push(symbols, rz_pvector_pop(part->symbols));
		}
	}
	return symbols;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_mdt_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	const RzBinMdtObj *mdt = bf->o->bin_obj;
	RzPVector *sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!sections) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (mdt->parts, it) {
		RzBinMdtPart *part = *it;
		while (part->sections && !rz_pvector_empty(part->sections)) {
			rz_pvector_push(sections, rz_pvector_pop(part->sections));
		}
	}
	return sections;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinReloc *>*/ *rz_bin_mdt_relocs(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	const RzBinMdtObj *mdt = bf->o->bin_obj;
	RzPVector *relocs = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free);
	if (!relocs) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (mdt->parts, it) {
		RzBinMdtPart *part = *it;
		while (part->relocs && !rz_pvector_empty(part->relocs)) {
			rz_pvector_push(relocs, rz_pvector_pop(part->relocs));
		}
	}
	return relocs;
}

RZ_IPI RzStructuredData *rz_bin_mdt_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	const RzBinMdtObj *mdt = bf->o->bin_obj;

	RzStructuredData *content = NULL;
	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *mdt_segments = rz_structured_data_map_add_array(info, "mdt_segments");
	if (!mdt_segments) {
		rz_structured_data_free(info);
		return NULL;
	}

	size_t i = 0;
	void **it = NULL;
	char bits[70] = { 0 };
	bits[0] = '0';
	bits[1] = 'b';
	rz_pvector_enumerate (mdt->parts, it, i) {
		RzBinMdtPart *part = *it;
		rz_str_bits64(&bits[2], qcom_p_flags(part->pflags));

		RzStructuredData *segment = rz_structured_data_array_add_map(mdt_segments);
		if (!segment) {
			rz_structured_data_free(info);
			return NULL;
		}
		rz_structured_data_map_add_string(segment, "priv_p_flags", bits);
		rz_structured_data_map_add_boolean(segment, "is_layout", part->is_layout);
		rz_structured_data_map_add_boolean(segment, "is_relocatable", part->relocatable);

		switch (part->format) {
		default:
			/* fall-thru */
		case RZ_BIN_MDT_PART_UNIDENTIFIED:
			rz_structured_data_map_add_string(segment, "format", "unidentified");
			break;
		case RZ_BIN_MDT_PART_ELF:
			rz_structured_data_map_add_string(segment, "format", "elf binary");
			content = elf_structure(part->obj.elf);
			rz_structured_data_map_add(segment, "content", content);
			break;
		case RZ_BIN_MDT_PART_MBN:
			rz_structured_data_map_add_string(segment, "format", "mbn signature");
			content = mbn_structure(part->obj.mbn);
			rz_structured_data_map_add(segment, "content", content);
			break;
		case RZ_BIN_MDT_PART_COMPRESSED_Q6ZIP:
			rz_structured_data_map_add_string(segment, "format", "Q6ZIP compressed");
			break;
		case RZ_BIN_MDT_PART_COMPRESSED_CLADE2:
			rz_structured_data_map_add_string(segment, "format", "CLADE2 compressed");
			break;
		case RZ_BIN_MDT_PART_COMPRESSED_ZLIB:
			rz_structured_data_map_add_string(segment, "format", "ZLIB compressed");
			break;
		}
	}

	return info;
}
