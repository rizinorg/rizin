// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ne.h"

#define NE_64K (64 * 1024)

static char *ne_get_target_os(ne_t *bin) {
	switch (bin->ne_header->targOS) {
	case 1:
		return "OS/2";
	case 2:
		return "Windows";
	case 3:
		return "European MS-DOS 4.x";
	case 4:
		return "Windows 386";
	case 5:
		return "BOSS (Borland Operating System Services)";
	default:
		return "Unknown";
	}
}

RZ_IPI RZ_OWN RzList /*<char *>*/ *ne_convert_section_flag_to_rzlist(ut64 flag) {
	RzList *list = rz_list_new();
	if (!list) {
		return NULL;
	}
	if (flag & SEGFLAGS_MOVABLE) {
		rz_list_append(list, "MOVABLE");
	}
	if (flag & SEGFLAGS_PRELOAD) {
		rz_list_append(list, "PRELOAD");
	}
	if (flag & SEGFLAGS_HAS_RELOCS) {
		rz_list_append(list, "HAS_RELOCS");
	}
	return list;
}

RZ_IPI RZ_OWN char *ne_convert_section_type_to_string(ut64 type) {
	switch (type) {
	case SEGFLAGS_TYPE_CODE:
		return rz_str_dup("CODE");
	case SEGFLAGS_TYPE_DATA:
		return rz_str_dup("DATA");
	default:
		return NULL;
	}
}

static char *ne_resolve_external_procedure(ne_t *bin, const char *module, ut32 ordinal_number) {
	if (!bin->path || RZ_STR_ISEMPTY(module)) {
		return NULL;
	}

	char n_ordinal[32] = { 0 };
	char *path = NULL;
	char *name = NULL;
	char *formats_dir = rz_path_system(bin->path, RZ_SDB_FORMAT);
	if (!formats_dir) {
		return NULL;
	}

	path = rz_str_newf(RZ_JOIN_3_PATHS("%s", "dll", "%s.sdb"), formats_dir, module);
	free(formats_dir);

	if (!rz_file_exists(path)) {
		RZ_LOG_INFO("ne: cannot resolve ordinal %u from %s (file not exists: %s)\n", ordinal_number, module, path);
		free(path);
		return NULL;
	}

	Sdb *sdb = sdb_new(NULL, path, 0);
	if (sdb) {
		rz_strf(n_ordinal, "%u", ordinal_number);
		name = sdb_get(sdb, n_ordinal);
		sdb_close(sdb);
		sdb_free(sdb);
	}
	free(path);
	return name;
}

static void ne_sanitize_name(char *name, ut16 count) {
	// expect to have names in ASCII format.
	for (ut16 i = 0; i < count && name[i]; ++i) {
		if (!IS_PRINTABLE(name[i])) {
			name[i] = '?';
		}
	}
}

static bool ne_parse_pascal_string(RzBuffer *buf, ut64 *offset, char **out) {
	char string[256] = { 0 };
	ut8 size = 0;
	bool ok = rz_buf_read8_offset(buf, offset, &size) &&
		rz_buf_read_offset(buf, offset, (ut8 *)string, size);
	if (!ok) {
		RZ_LOG_ERROR("ne: failed to parse string at 0x%" PFMT64x "\n", *offset);
		return false;
	}
	ne_sanitize_name(string, size);

	*out = NULL;
	if (size > 0) {
		*out = rz_str_ndup(string, size);
	}
	return true;
}

static ut64 ne_image_segment_entry_to_paddr(ne_t *bin, const NE_image_segment_entry *entry) {
	return entry->sector_base * bin->alignment;
}

static int ne_segment_flags_to_perms(const NE_image_segment_entry *se) {
	ut16 type = se->seg_flags & SEGFLAGS_TYPE_MASK;
	if (type == SEGFLAGS_TYPE_DATA) {
		return se->seg_flags & SEGFLAGS_PRELOAD ? RZ_PERM_R : RZ_PERM_RW;
	}

	return RZ_PERM_RWX;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinSection *>*/ *ne_get_sections(RZ_NONNULL ne_t *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!sections) {
		return NULL;
	}

	const NE_image_segment_entry *se = NULL;
	rz_vector_foreach (bin->image_segment_entries, se) {
		RzBinSection *bs = RZ_NEW0(RzBinSection);
		if (!bs) {
			break;
		}
		bs->size = se->seg_bytes ? se->seg_bytes : NE_64K;
		bs->vsize = se->min_alloc ? se->min_alloc : NE_64K;
		bs->bits = RZ_SYS_BITS_16;
		bs->type = se->seg_flags & SEGFLAGS_TYPE_MASK;
		bs->is_data = bs->type == SEGFLAGS_TYPE_DATA;
		bs->perm = ne_segment_flags_to_perms(se);
		bs->vaddr = bs->paddr = ne_image_segment_entry_to_paddr(bin, se);
		bs->align = bin->alignment;
		bs->name = rz_str_newf("%s_seg_%02u", bs->is_data ? "data" : "code", (ut32)se->sector_base);
		bs->is_segment = true;
		bs->flags = se->seg_flags & (~SEGFLAGS_TYPE_MASK);
		rz_pvector_push(sections, bs);
	}

	return sections;
}

static RzBinSymbol *ne_new_bin_symbol(RZ_OWN char *name, ut64 addr, const char *bind, const char *type, size_t ordinal) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (!sym) {
		free(name);
		return NULL;
	}
	sym->name = name;
	sym->vaddr = sym->paddr = addr;
	sym->bind = bind;
	sym->type = type;
	sym->ordinal = ordinal;
	return sym;
}

static void *ne_safe_vector_at(RzVector /*<None>*/ *vec, size_t index) {
	const size_t n_entries = rz_vector_len(vec);
	if (index >= n_entries) {
		return NULL;
	}
	return rz_vector_index_ptr(vec, index);
}

static void *ne_safe_pvector_at(RzPVector /*<void *>*/ *vec, size_t index) {
	const size_t n_entries = rz_pvector_len(vec);
	if (index >= n_entries) {
		return NULL;
	}
	return rz_pvector_at(vec, index);
}

static ut64 ne_resolve_entry_addr(ne_t *bin, const NE_segment_entry *seg_entry) {
	if (!seg_entry) {
		return UT64_MAX;
	}

	const NE_image_segment_entry *segment = NULL;
	switch (seg_entry->segment_indicator) {
	case ENTRY_SEGMENT_INDICATOR_UNUSED:
		return UT64_MAX;
	case ENTRY_SEGMENT_INDICATOR_MOVABLE:
		// Movable segment indicator
		segment = ne_safe_vector_at(bin->image_segment_entries, seg_entry->movable.segment_number - 1);
		if (!segment) {
			return UT64_MAX;
		}
		return ne_image_segment_entry_to_paddr(bin, segment) + seg_entry->movable.entry_point_offset;
	default:
		// Fixed segment indicator
		segment = ne_safe_vector_at(bin->image_segment_entries, seg_entry->segment_indicator - 1);
		if (!segment) {
			return UT64_MAX;
		}
		return ne_image_segment_entry_to_paddr(bin, segment) + seg_entry->fixed.entry_point_offset;
	}
}

static void ne_convert_resident_name_entries_to_symbols(ne_t *bin, RzVector /*<NE_resident_name_entry>*/ *entries, RzPVector /*<RzBinSymbol *>*/ *symbols) {
	bool resident = bin->resident_name_entries == entries;

	const NE_resident_name_entry *res = NULL;
	rz_vector_foreach (entries, res) {
		char *name = rz_str_dup(res->name);
		if (!name) {
			name = rz_str_newf("ne_%sresident_%u", resident ? "" : "non", (ut32)res->ordinal_number);
		}

		const char *type = resident ? "RESIDENT" : "NON-RESIDENT";
		const char *bind = RZ_BIN_BIND_UNKNOWN_STR;
		ut64 addr = UT64_MAX;
		const NE_segment_entry *seg_entry = ne_safe_vector_at(bin->segment_entries, res->ordinal_number - 1);
		if (seg_entry) {
			addr = ne_resolve_entry_addr(bin, seg_entry);
			if (seg_entry->fixed.entry_flags == ENTRY_FLAGS_EXPORTED) {
				bind = "EXPORT";
			} else if (seg_entry->fixed.entry_flags == ENTRY_FLAGS_GLOBALDATA) {
				bind = RZ_BIN_BIND_GLOBAL_STR;
			}
		}

		RzBinSymbol *sym = ne_new_bin_symbol(name, addr, bind, type, res->ordinal_number);
		if (!sym) {
			break;
		}
		rz_pvector_push(symbols, sym);
	}
}

RZ_IPI RZ_OWN RzPVector /*<RzBinSymbol *>*/ *ne_get_symbols(RZ_NONNULL ne_t *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *symbols = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!symbols) {
		return NULL;
	}

	ne_convert_resident_name_entries_to_symbols(bin, bin->resident_name_entries, symbols);
	ne_convert_resident_name_entries_to_symbols(bin, bin->nonresident_name_entries, symbols);

	return symbols;
}

static char *ne_resource_type_str(int type) {
	char *typeName;
	switch (type) {
	case 1:
		typeName = "CURSOR";
		break;
	case 2:
		typeName = "BITMAP";
		break;
	case 3:
		typeName = "ICON";
		break;
	case 4:
		typeName = "MENU";
		break;
	case 5:
		typeName = "DIALOG";
		break;
	case 6:
		typeName = "STRING";
		break;
	case 7:
		typeName = "FONTDIR";
		break;
	case 8:
		typeName = "FONT";
		break;
	case 9:
		typeName = "ACCELERATOR";
		break;
	case 10:
		typeName = "RCDATA";
		break;
	case 11:
		typeName = "MESSAGETABLE";
		break;
	case 12:
		typeName = "GROUP_CURSOR";
		break;
	case 14:
		typeName = "GROUP_ICON";
		break;
	case 15:
		typeName = "NAMETABLE";
		break;
	case 16:
		typeName = "VERSION";
		break;
	case 17:
		typeName = "DLGINCLUDE";
		break;
	case 19:
		typeName = "PLUGPLAY";
		break;
	case 20:
		typeName = "VXD";
		break;
	case 21:
		typeName = "ANICURSOR";
		break;
	case 22:
		typeName = "ANIICON";
		break;
	case 23:
		typeName = "HTML";
		break;
	case 24:
		typeName = "MANIFEST";
		break;
	default:
		return rz_str_newf("UNKNOWN (%d)", type);
	}
	return rz_str_dup(typeName);
}

static void ne_free_resource_entry(void *entry) {
	rz_ne_resource_entry *en = (rz_ne_resource_entry *)entry;
	free(en->name);
	free(en);
}

static void ne_free_resource(void *resource) {
	rz_ne_resource *res = (rz_ne_resource *)resource;
	free(res->name);
	rz_list_free(res->entry);
	free(res);
}

static bool ne_parse_image_typeinfo_entry(RzBuffer *buf, ut64 *offset, NE_image_typeinfo_entry *ti) {
	return rz_buf_read_le16_offset(buf, offset, &ti->rtTypeID) &&
		rz_buf_read_le16_offset(buf, offset, &ti->rtResourceCount) &&
		rz_buf_read_le32_offset(buf, offset, &ti->rtReserved);
}

static bool ne_parse_image_nameinfo_entry(RzBuffer *buf, ut64 *offset, NE_image_nameinfo_entry *ni) {
	return rz_buf_read_le16_offset(buf, offset, &ni->rnOffset) &&
		rz_buf_read_le16_offset(buf, offset, &ni->rnLength) &&
		rz_buf_read_le16_offset(buf, offset, &ni->rnFlags) &&
		rz_buf_read_le16_offset(buf, offset, &ni->rnID) &&
		rz_buf_read_le16_offset(buf, offset, &ni->rnHandle) &&
		rz_buf_read_le16_offset(buf, offset, &ni->rnUsage);
}

static bool ne_read_resources(RzBuffer *buf, ne_t *bin) {
	bin->resources = rz_list_newf(ne_free_resource);
	if (!bin->resources) {
		return false;
	}

	ut64 base_off = bin->ne_header->ResTableOffset + bin->header_offset;
	ut64 offset = base_off;
	ut16 alignment = 0;
	if (!rz_buf_read_le16_offset(buf, &offset, &alignment) || alignment > 31) {
		return false;
	}

	while (true) {
		NE_image_typeinfo_entry ti = { 0 };
		if (!ne_parse_image_typeinfo_entry(buf, &offset, &ti) ||
			!ti.rtTypeID) {
			break;
		}
		rz_ne_resource *res = RZ_NEW0(rz_ne_resource);
		if (!res) {
			break;
		}
		res->entry = rz_list_newf(ne_free_resource_entry);
		if (!res->entry) {
			free(res);
			break;
		}
		if (ti.rtTypeID & 0x8000) {
			res->name = ne_resource_type_str(ti.rtTypeID & ~0x8000);
		} else {
			// Offset to resident name table
			ut64 str_off = base_off + ti.rtTypeID;
			ne_parse_pascal_string(buf, &str_off, &res->name);
		}

		for (size_t i = 0; i < (size_t)ti.rtResourceCount; i++) {
			NE_image_nameinfo_entry ni = { 0 };
			if (!ne_parse_image_nameinfo_entry(buf, &offset, &ni)) {
				break;
			}
			rz_ne_resource_entry *ren = RZ_NEW0(rz_ne_resource_entry);
			if (!ren) {
				break;
			}
			ren->offset = ni.rnOffset << alignment;
			ren->size = ni.rnLength;
			ren->flags = ni.rnFlags;
			if (ni.rnID & 0x8000) {
				ren->name = rz_str_newf("%d", ni.rnID & ~0x8000);
			} else {
				// Offset to resident name table
				ut64 str_off = base_off + ni.rnID;
				ne_parse_pascal_string(buf, &str_off, &ren->name);
			}
			rz_list_append(res->entry, ren);
		}
		rz_list_append(bin->resources, res);
	}
	return true;
}

static RzBinImport *ne_new_bin_import(RZ_OWN char *name, const char *module, size_t ordinal) {
	RzBinImport *imp = RZ_NEW0(RzBinImport);
	if (!imp) {
		free(name);
		return NULL;
	}
	imp->name = name;
	imp->ordinal = ordinal;
	imp->libname = rz_str_dup(module);
	imp->bind = RZ_BIN_BIND_IMPORT_STR;
	return imp;
}

static RzBinImport *ne_convert_import_ordinal_to_bin_import(ne_t *bin, const NE_relocation_entry *entry) {
	// index always starts from 1.
	size_t index = entry->seg_reloc.import_ordinal.mod_ref_table_index - 1;
	ut32 ordinal = entry->seg_reloc.import_ordinal.ordinal_number;
	const char *module = ne_safe_pvector_at(bin->imported_modules, index);
	char *name = NULL;
	if (entry->procedure_name) {
		name = rz_str_dup(entry->procedure_name);
	} else {
		name = rz_str_newf("ordinal_%u", ordinal);
	}
	return ne_new_bin_import(name, module, ordinal);
}

static RzBinImport *ne_convert_import_name_to_bin_import(ne_t *bin, const NE_relocation_entry *entry) {
	// index always starts from 1.
	size_t index = entry->seg_reloc.import_name.mod_ref_table_index - 1;
	ut32 offset = entry->seg_reloc.import_name.proc_name_offset;
	const char *module = ne_safe_pvector_at(bin->imported_modules, index);
	char *name = NULL;
	if (entry->procedure_name) {
		name = rz_str_dup(entry->procedure_name);
	} else {
		name = rz_str_newf("offset_0x%08x", offset);
	}
	// we do not have an ordinal value here.
	return ne_new_bin_import(name, module, 0);
}

RZ_IPI RZ_OWN RzPVector /*<RzBinImport *>*/ *ne_get_imports(RZ_NONNULL ne_t *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *imports = rz_pvector_new((RzListFree)rz_bin_import_free);
	if (!imports) {
		return NULL;
	}

	HtSU *seen = ht_su_new(HT_STR_CONST);

	const NE_relocation_entry *entry = NULL;
	rz_vector_foreach (bin->relocation_entries, entry) {
		RzBinImport *imp = NULL;
		ut16 target = entry->seg_reloc.flags_and_target & RELOC_TARGET_MASK;
		if (target == RELOC_TARGET_IMPORT_ORDINAL) {
			imp = ne_convert_import_ordinal_to_bin_import(bin, entry);
		} else if (target == RELOC_TARGET_IMPORT_NAME) {
			imp = ne_convert_import_name_to_bin_import(bin, entry);
		} else {
			continue;
		}

		if (!imp) {
			break;
		}

		bool found = false;
		ht_su_find_kv(seen, imp->name, &found);
		if (found) {
			// we remove and duplicate.
			rz_bin_import_free(imp);
			continue;
		}

		imp->type = RZ_BIN_TYPE_FUNC_STR;
		rz_pvector_push(imports, imp);
		ht_su_insert(seen, imp->name, 1);
	}

	ht_su_free(seen);
	return imports;
}

static RzBinAddr *ne_new_bin_addr(ut64 addr, int type) {
	RzBinAddr *baddr = RZ_NEW0(RzBinAddr);
	if (!baddr) {
		return NULL;
	}

	baddr->type = RZ_BIN_ENTRY_TYPE_PROGRAM;
	baddr->vaddr = baddr->paddr = addr;
	baddr->bits = 16;

	return baddr;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinAddr *>*/ *ne_get_entrypoints(RZ_NONNULL ne_t *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *entries = rz_pvector_new(free);
	if (!entries) {
		return NULL;
	}

	// CS is index into segment table
	size_t segment_number = bin->ne_header->csEntryPoint;
	if (segment_number > 0) {
		const NE_image_segment_entry *segment = ne_safe_vector_at(bin->image_segment_entries, segment_number - 1);
		ut64 addr = ne_image_segment_entry_to_paddr(bin, segment) + bin->ne_header->ipEntryPoint;
		RzBinAddr *baddr = ne_new_bin_addr(addr, RZ_BIN_ENTRY_TYPE_PROGRAM);
		if (baddr) {
			rz_pvector_push(entries, baddr);
		}
	}

	size_t count = rz_vector_len(bin->segment_entries);
	for (size_t i = 0; i < count; ++i) {
		const NE_segment_entry *seg_entry = ne_safe_vector_at(bin->segment_entries, i);
		ut64 addr = ne_resolve_entry_addr(bin, seg_entry);
		RzBinAddr *baddr = ne_new_bin_addr(addr, RZ_BIN_ENTRY_TYPE_PROGRAM);
		if (!baddr) {
			break;
		}
		rz_pvector_push(entries, baddr);
	}
	return entries;
}

static void ne_resolve_reloc_internal_ref(ne_t *bin, const NE_relocation_entry *entry, RzBinReloc *reloc) {
	ut32 segment_index = entry->seg_reloc.internal_ref.segment_index;
	if (entry->seg_reloc.internal_ref.segment_number == 0xFF) {
		// movable segment, segment_index is ordinal number index into Entry Table
		const NE_segment_entry *seg_entry = ne_safe_vector_at(bin->segment_entries, segment_index);
		reloc->vaddr = reloc->paddr = ne_resolve_entry_addr(bin, seg_entry);
		return;
	}

	// fixed segment, segment_index is the offset into segment
	ut64 segment_paddr = ne_image_segment_entry_to_paddr(bin, entry->segment);
	reloc->vaddr = reloc->paddr = segment_paddr + segment_index;
}

static const char *ne_get_reloc_type_name(const NE_seg_relocation_entry *entry) {
#define CONCAT_RELOC_STR(a, b) a b
#define NE_RELOC_TARGET_TYPE(src, target) \
	switch (target) { \
	case RELOC_TARGET_INTERNAL_REF: \
		if (entry->internal_ref.segment_number == 0xFF) { \
			return CONCAT_RELOC_STR(src, " INTERNAL_REF MOVABLE"); \
		} \
		return CONCAT_RELOC_STR(src, " INTERNAL_REF FIXED"); \
	case RELOC_TARGET_IMPORT_ORDINAL: \
		return CONCAT_RELOC_STR(src, " IMPORTED_ORDINAL"); \
	case RELOC_TARGET_IMPORT_NAME: \
		return CONCAT_RELOC_STR(src, " IMPORTED_NAME"); \
	case RELOC_TARGET_OS_FIXUP: \
		switch (entry->os_fixup.os_fixup_type) { \
		case OS_FIXUP_TYPE_FIARQQ_FJARQQ: \
			return CONCAT_RELOC_STR(src, " OS_FIXUP FIARQQ_FJARQQ"); \
		case OS_FIXUP_TYPE_FISRQQ_FJSRQQ: \
			return CONCAT_RELOC_STR(src, " OS_FIXUP FISRQQ_FJSRQQ"); \
		case OS_FIXUP_TYPE_FICRQQ_FJCRQQ: \
			return CONCAT_RELOC_STR(src, " OS_FIXUP FICRQQ_FJCRQQ"); \
		case OS_FIXUP_TYPE_FIERQQ: \
			return CONCAT_RELOC_STR(src, " OS_FIXUP FIERQQ"); \
		case OS_FIXUP_TYPE_FIDRQQ: \
			return CONCAT_RELOC_STR(src, " OS_FIXUP FIDRQQ"); \
		case OS_FIXUP_TYPE_FIWRQQ: \
			return CONCAT_RELOC_STR(src, " OS_FIXUP FIWRQQ"); \
		default: \
			return CONCAT_RELOC_STR(src, " OS_FIXUP"); \
		} \
	default: \
		RZ_LOG_ERROR("Unknown NE relocation target flag %u\n", target); \
		return CONCAT_RELOC_STR(src, "_UNKNOWN"); \
	}

	ut16 target = entry->flags_and_target & RELOC_TARGET_MASK;
	switch (entry->source) {
	case RELOC_SOURCE_LOW_BYTE:
		NE_RELOC_TARGET_TYPE("LOW_BYTE", target);
	case RELOC_SOURCE_SEGMENT:
		NE_RELOC_TARGET_TYPE("SEGMENT", target);
	case RELOC_SOURCE_FAR_ADDR_32:
		NE_RELOC_TARGET_TYPE("FAR_ADDR_32", target);
	case RELOC_SOURCE_OFFSET_16:
		NE_RELOC_TARGET_TYPE("OFFSET_16", target);
	case RELOC_SOURCE_FAR_ADDR_48:
		NE_RELOC_TARGET_TYPE("FAR_ADDR_48", target);
	case RELOC_SOURCE_OFFSET_32:
		NE_RELOC_TARGET_TYPE("OFFSET_32", target);
	default:
		RZ_LOG_ERROR("Unknown NE relocation source type %d\n", entry->source);
		return NULL;
	}
#undef NE_RELOC_TARGET_TYPE
#undef CONCAT_RELOC_STR
}

static RzBinReloc *ne_convert_to_bin_reloc(ne_t *bin, const NE_relocation_entry *entry) {
	RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
	if (!reloc) {
		return NULL;
	}

	reloc->vaddr = reloc->paddr = UT64_MAX;

	switch (entry->seg_reloc.source) {
	case RELOC_SOURCE_LOW_BYTE:
		reloc->type = 8;
		break;
	case RELOC_SOURCE_SEGMENT:
		reloc->type = 16;
		break;
	case RELOC_SOURCE_OFFSET_16:
		reloc->type = 16;
		break;
	case RELOC_SOURCE_FAR_ADDR_32:
		reloc->type = 32;
		break;
	case RELOC_SOURCE_FAR_ADDR_48:
		reloc->type = 48;
		break;
	case RELOC_SOURCE_OFFSET_32:
		reloc->type = 32;
		break;
	default:
		RZ_LOG_ERROR("Unknown NE relocation source type %d\n", entry->seg_reloc.source);
		rz_bin_reloc_free(reloc);
		return NULL;
	}

	ut16 target = entry->seg_reloc.flags_and_target & RELOC_TARGET_MASK;
	switch (target) {
	case RELOC_TARGET_INTERNAL_REF:
		ne_resolve_reloc_internal_ref(bin, entry, reloc);
		break;
	case RELOC_TARGET_IMPORT_ORDINAL:
		reloc->import = ne_convert_import_ordinal_to_bin_import(bin, entry);
		break;
	case RELOC_TARGET_IMPORT_NAME:
		reloc->import = ne_convert_import_name_to_bin_import(bin, entry);
		break;
	case RELOC_TARGET_OS_FIXUP:
		break;
	default:
		RZ_LOG_ERROR("Unknown NE relocation target flag %u\n", target);
		rz_bin_reloc_free(reloc);
		return NULL;
	}

	if (reloc->paddr != UT64_MAX) {
		reloc->additive = entry->seg_reloc.flags_and_target & RELOC_FLAGS_ADDITIVE;
		if (reloc->additive) {
			reloc->addend = entry->seg_reloc.source_chain_offset;
		}
	}

	reloc->print_name = ne_get_reloc_type_name(&entry->seg_reloc);
	return reloc;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinReloc *>*/ *ne_get_relocs(RZ_NONNULL ne_t *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *relocs = rz_pvector_new((RzPVectorFree)rz_bin_reloc_free);
	if (!relocs) {
		return NULL;
	}

	const NE_relocation_entry *entry = NULL;
	rz_vector_foreach (bin->relocation_entries, entry) {
		RzBinReloc *reloc = ne_convert_to_bin_reloc(bin, entry);
		if (!reloc) {
			break;
		}
		rz_pvector_push(relocs, reloc);
	}
	return relocs;
}

static char *ne_resource_get_flags(const rz_ne_resource_entry *nen) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);

	if (nen->flags & RESOURCE_FLAGS_MOVEABLE) {
		rz_strbuf_append(&sb, "MOVABLE");
	}

	if (nen->flags & RESOURCE_FLAGS_PURE) {
		if (rz_strbuf_length(&sb) > 0) {
			rz_strbuf_append(&sb, ", ");
		}
		rz_strbuf_append(&sb, "PURE");
	}

	if (nen->flags & RESOURCE_FLAGS_PRELOAD) {
		if (rz_strbuf_length(&sb) > 0) {
			rz_strbuf_append(&sb, ", ");
		}
		rz_strbuf_append(&sb, "PRELOAD");
	}

	if (rz_strbuf_length(&sb) < 1) {
		if (nen->flags) {
			rz_strbuf_appendf(&sb, "FLAGS %u", nen->flags);
		} else {
			rz_strbuf_append(&sb, "NONE");
		}
	}

	return rz_strbuf_drain_nofree(&sb);
}

static RzBinResource *ne_convert_resource_to_bin_resource(const rz_ne_resource_entry *nen, const char *res_name) {
	RzBinResource *br = RZ_NEW0(RzBinResource);
	if (!br) {
		return NULL;
	}

	br->name = rz_str_newf("%s %s", res_name, nen->name);
	if (!br->name) {
		rz_bin_resource_free(br);
		return NULL;
	}
	br->time = rz_str_dup("-");
	br->language = rz_str_dup("-");
	br->vaddr = br->paddr = nen->offset;
	br->size = nen->size;
	br->type = ne_resource_get_flags(nen);
	return br;
}

RZ_IPI RZ_OWN RzPVector /*<char *>*/ *ne_get_libraries(RZ_NONNULL ne_t *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *libs = rz_pvector_new(free);
	if (!libs) {
		return NULL;
	}

	void **it;
	rz_pvector_foreach (bin->imported_modules, it) {
		const char *module = *it;
		char *name = rz_str_dup(module);
		if (!name) {
			break;
		}
		rz_pvector_push(libs, name);
	}

	return libs;
}

RZ_IPI RZ_OWN RzPVector /*<RzBinResource *>*/ *ne_get_resources(RZ_NONNULL ne_t *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *resources = rz_pvector_new((RzPVectorFree)rz_bin_resource_free);
	if (!resources) {
		return NULL;
	}

	rz_ne_resource *ne_res;
	RzListIter *it;
	RzListIter *it2;

	rz_list_foreach (bin->resources, it, ne_res) {
		rz_ne_resource_entry *nen;
		rz_list_foreach (ne_res->entry, it2, nen) {
			RzBinResource *res = ne_convert_resource_to_bin_resource(nen, ne_res->name);
			if (!res) {
				break;
			}
			rz_pvector_push(resources, res);
		}
	}
	return resources;
}

static bool read_ne_header(NE_image_header *ne, RzBuffer *buf, ut64 off) {
	ut64 offset = off;
	return (rz_buf_read_offset(buf, &offset, (ut8 *)ne->sig, sizeof(ne->sig)) &&
		rz_buf_read8_offset(buf, &offset, &ne->MajLinkerVersion) &&
		rz_buf_read8_offset(buf, &offset, &ne->MinLinkerVersion) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->EntryTableOffset) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->EntryTableLength) &&
		rz_buf_read_le32_offset(buf, &offset, &ne->FileLoadCRC) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->FlagWord) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->AutoDataSegIndex) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->InitHeapSize) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->InitStackSize) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->ipEntryPoint) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->csEntryPoint) &&
		rz_buf_read_le32_offset(buf, &offset, &ne->InitStack) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->SegCount) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->ModRefs) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->NoResNamesTabSiz) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->SegTableOffset) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->ResTableOffset) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->ResidNamTable) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->ModRefTable) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->ImportNameTable) &&
		rz_buf_read_le32_offset(buf, &offset, &ne->OffStartNonResTab) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->MovEntryCount) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->FileAlnSzShftCnt) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->nResTabEntries) &&
		rz_buf_read8_offset(buf, &offset, &ne->targOS) &&
		rz_buf_read8_offset(buf, &offset, &ne->OS2EXEFlags) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->retThunkOffset) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->segrefthunksoff) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->mincodeswap) &&
		rz_buf_read_offset(buf, &offset, (ut8 *)ne->expctwinver, sizeof(ne->expctwinver)));
}

static bool ne_parse_image_segment_entry(RzBuffer *buf, ut64 *offset, NE_image_segment_entry *entry) {
	return rz_buf_read_le16_offset(buf, offset, &entry->sector_base) &&
		rz_buf_read_le16_offset(buf, offset, &entry->seg_bytes) &&
		rz_buf_read_le16_offset(buf, offset, &entry->seg_flags) &&
		rz_buf_read_le16_offset(buf, offset, &entry->min_alloc);
}

static bool ne_parse_seg_relocation_entry(RzBuffer *buf, ut64 *offset, NE_seg_relocation_entry *entry) {
	bool ok = rz_buf_read8_offset(buf, offset, &entry->source) &&
		rz_buf_read8_offset(buf, offset, &entry->flags_and_target) &&
		rz_buf_read_le16_offset(buf, offset, &entry->source_chain_offset);
	if (!ok) {
		return false;
	}

	ut16 target = (entry->flags_and_target & RELOC_TARGET_MASK);
	if (target == RELOC_TARGET_INTERNAL_REF) {
		return rz_buf_read8_offset(buf, offset, &entry->internal_ref.segment_number) &&
			rz_buf_read8_offset(buf, offset, &entry->internal_ref.zero) &&
			rz_buf_read_le16_offset(buf, offset, &entry->internal_ref.segment_index);
	}

	// all the other fields of the unions are ut16.
	return rz_buf_read_le16_offset(buf, offset, &entry->import_name.mod_ref_table_index) &&
		rz_buf_read_le16_offset(buf, offset, &entry->import_name.proc_name_offset);
}

static bool ne_read_seg_relocation_entries(RzBuffer *buf, ne_t *bin, const NE_image_segment_entry *segment) {
	if (!(segment->seg_flags & SEGFLAGS_HAS_RELOCS)) {
		// this segment does not have relocations.
		return true;
	}

	// relocation is always located after the NE_image_segment_entry
	ut64 offset = ne_image_segment_entry_to_paddr(bin, segment) + segment->seg_bytes;
	ut64 import_table = bin->ne_header->ImportNameTable + bin->header_offset;

	ut16 reloc_entry_count = 0;
	if (!rz_buf_read_le16_offset(buf, &offset, &reloc_entry_count)) {
		RZ_LOG_ERROR("ne: failed to parse seg_relocation_entry count\n");
		return false;
	}

	if (reloc_entry_count < 1) {
		return true;
	}

	for (size_t i = 0; i < (size_t)reloc_entry_count; ++i) {
		NE_relocation_entry entry = { 0 };
		if (!ne_parse_seg_relocation_entry(buf, &offset, &entry.seg_reloc)) {
			RZ_LOG_ERROR("ne: failed to parse seg_relocation_entry\n");
			return false;
		}
		entry.segment = segment;

		ut16 target = entry.seg_reloc.flags_and_target & RELOC_TARGET_MASK;
		if (target == RELOC_TARGET_IMPORT_NAME) {
			ut64 proc_name_offset = entry.seg_reloc.import_name.proc_name_offset + import_table;
			if (!ne_parse_pascal_string(buf, &proc_name_offset, &entry.procedure_name)) {
				RZ_LOG_ERROR("ne: failed to parse seg_relocation_entry procedure name\n");
				return false;
			}
		} else if (target == RELOC_TARGET_IMPORT_ORDINAL) {
			size_t ordinal = entry.seg_reloc.import_ordinal.ordinal_number;
			// index always starts from 1.
			size_t index = entry.seg_reloc.import_ordinal.mod_ref_table_index - 1;
			const char *module = ne_safe_pvector_at(bin->imported_modules, index);
			entry.procedure_name = ne_resolve_external_procedure(bin, module, ordinal);
		}
		rz_vector_push(bin->relocation_entries, &entry);
	}

	return true;
}

static void ne_relocation_entry_fini(void *e, void *user) {
	(void)user;
	NE_relocation_entry *entry = e;
	free(entry->procedure_name);
}

static bool ne_read_image_segment_entries(RzBuffer *buf, ne_t *bin) {
	if (bin->ne_header->SegCount < 1) {
		RZ_LOG_ERROR("ne: image_segment_entries count is < 1\n");
		return false;
	}

	bin->image_segment_entries = rz_vector_new(sizeof(NE_image_segment_entry), NULL, NULL);
	if (!bin->image_segment_entries) {
		RZ_LOG_ERROR("ne: failed to allocate image_segment_entries\n");
		return false;
	}

	ut64 offset = bin->ne_header->SegTableOffset + bin->header_offset;
	for (size_t i = 0; i < (size_t)bin->ne_header->SegCount; i++) {
		NE_image_segment_entry segment = { 0 };
		if (!ne_parse_image_segment_entry(buf, &offset, &segment)) {
			RZ_LOG_ERROR("ne: failed to parse image_segment_entry[%" PFMTSZu "]\n", i);
			return false;
		}
		rz_vector_push(bin->image_segment_entries, &segment);
	}

	return true;
}

static bool ne_read_relocation_entries(RzBuffer *buf, ne_t *bin) {
	bin->relocation_entries = rz_vector_new(sizeof(NE_relocation_entry), ne_relocation_entry_fini, NULL);
	if (!bin->relocation_entries) {
		RZ_LOG_ERROR("ne: failed to allocate relocation_entries\n");
		return false;
	}
	// requires all the segments to be resolved first.
	const NE_image_segment_entry *segment = NULL;
	rz_vector_foreach (bin->image_segment_entries, segment) {
		if (!ne_read_seg_relocation_entries(buf, bin, segment)) {
			return false;
		}
	}
	return true;
}

static void ne_resident_name_entry_fini(void *e, void *user) {
	(void)user;
	NE_resident_name_entry *entry = e;
	free(entry->name);
}

static bool ne_parse_resident_name_entry(RzBuffer *buf, ut64 *offset, NE_resident_name_entry *entry) {
	return ne_parse_pascal_string(buf, offset, &entry->name) &&
		rz_buf_read_le16_offset(buf, offset, &entry->ordinal_number);
}

static bool ne_parse_resident_name_table(RzVector /*<NE_resident_name_entry>*/ *entries, RzBuffer *buf, ut64 offset) {
	if (!entries) {
		RZ_LOG_ERROR("ne: failed to allocate resident_name_entries\n");
		return false;
	} else if (offset < 1) {
		// if offset is 0, then we avoid parsing.
		return true;
	}

	while (1) {
		NE_resident_name_entry entry = { 0 };
		if (!ne_parse_resident_name_entry(buf, &offset, &entry)) {
			RZ_LOG_ERROR("ne: failed to parse NE_resident_name_entry\n");
			return false;
		} else if (!entry.name) {
			// the size was 0, so we ignore break.
			return true;
		}
		rz_vector_push(entries, &entry);
	}

	return true;
}

static bool ne_read_resident_name_table(RzBuffer *buf, ne_t *bin) {
	bin->resident_name_entries = rz_vector_new(sizeof(NE_resident_name_entry), ne_resident_name_entry_fini, NULL);
	bin->nonresident_name_entries = rz_vector_new(sizeof(NE_resident_name_entry), ne_resident_name_entry_fini, NULL);

	ut64 res_table = bin->ne_header->ResidNamTable + bin->header_offset;
	// always from the beginning of the executable file, unlike the rest which is from the header offset.
	ut64 non_res_tbl = bin->ne_header->OffStartNonResTab;

	return ne_parse_resident_name_table(bin->resident_name_entries, buf, res_table) &&
		ne_parse_resident_name_table(bin->nonresident_name_entries, buf, non_res_tbl);
}

static bool ne_parse_fixed_segment_entry(RzBuffer *buf, ut64 *offset, NE_fixed_segment_entry *entry) {
	return rz_buf_read8_offset(buf, offset, &entry->entry_flags) &&
		rz_buf_read_le16_offset(buf, offset, &entry->entry_point_offset);
}

static bool ne_parse_movable_segment_entry(RzBuffer *buf, ut64 *offset, NE_movable_segment_entry *entry) {
	return rz_buf_read8_offset(buf, offset, &entry->entry_flags) &&
		rz_buf_read_le16_offset(buf, offset, &entry->int3fh) &&
		rz_buf_read8_offset(buf, offset, &entry->segment_number) &&
		rz_buf_read_le16_offset(buf, offset, &entry->entry_point_offset);
}

static bool ne_read_segment_entries_by_count(RzBuffer *buf, ne_t *bin, ut64 *offset, size_t count, ut8 si) {
	for (size_t i = 0; i < count; ++i) {
		NE_segment_entry se = { 0 };
		se.segment_indicator = si;
		switch (si) {
		case ENTRY_SEGMENT_INDICATOR_UNUSED:
			// this is a bundle of unused entries.
			break;
		case ENTRY_SEGMENT_INDICATOR_MOVABLE:
			if (!ne_parse_movable_segment_entry(buf, offset, &se.movable)) {
				RZ_LOG_ERROR("ne: failed to parse NE_movable_segment_entry\n");
				return false;
			}
			break;
		default:
			if (!ne_parse_fixed_segment_entry(buf, offset, &se.fixed)) {
				RZ_LOG_ERROR("ne: failed to parse NE_fixed_segment_entry\n");
				return false;
			}
			break;
		}
		rz_vector_push(bin->segment_entries, &se);
	}

	return true;
}

static bool ne_read_segment_entries(RzBuffer *buf, ne_t *bin) {
	bin->segment_entries = rz_vector_new(sizeof(NE_segment_entry), NULL, NULL);
	if (!bin->segment_entries) {
		return false;
	} else if (bin->ne_header->EntryTableLength < 1) {
		return true;
	}

	ut64 offset = (ut64)bin->header_offset + bin->ne_header->EntryTableOffset;
	ut64 end = offset + bin->ne_header->EntryTableLength;

	while (offset < end) {
		ut8 entry_count = 0;
		ut8 segment_indicator = 0;
		if (!rz_buf_read8_offset(buf, &offset, &entry_count)) {
			RZ_LOG_ERROR("ne: failed to parse NE_segment_entry count\n");
			return false;
		} else if (!rz_buf_read8_offset(buf, &offset, &segment_indicator)) {
			RZ_LOG_ERROR("ne: failed to parse NE_segment_entry segment indicator\n");
			return false;
		}
		if (!ne_read_segment_entries_by_count(buf, bin, &offset, entry_count, segment_indicator)) {
			RZ_LOG_ERROR("ne: failed to parse NE_segment_entry segment indicator\n");
			return false;
		}
	}

	return true;
}

static bool ne_read_module_refs_and_imported_names(RzBuffer *buf, ne_t *bin) {
	bin->module_refs = rz_vector_new(sizeof(ut16), NULL, NULL);
	bin->imported_modules = rz_pvector_new(free);
	if (!bin->module_refs) {
		return false;
	} else if (bin->ne_header->ModRefs < 1) {
		return true;
	}

	ut64 import_table = bin->ne_header->ImportNameTable + bin->header_offset;
	ut64 offset = (ut64)bin->ne_header->ModRefTable + bin->header_offset;
	for (size_t i = 0; i < (size_t)bin->ne_header->ModRefs; ++i) {
		ut16 module_ref = 0;
		if (!rz_buf_read_le16_offset(buf, &offset, &module_ref)) {
			return false;
		}
		rz_vector_push(bin->module_refs, &module_ref);

		char *name = NULL;
		ut64 import_off = module_ref + import_table;
		if (!ne_parse_pascal_string(buf, &import_off, &name)) {
			return false;
		}

		rz_pvector_push(bin->imported_modules, name);
	}

	return true;
}

static bool ne_buf_init(RzBuffer *buf, ne_t *bin) {
	if (!rz_buf_read_le16_at(buf, 0x3c, &bin->header_offset)) {
		return false;
	}
	bin->path = rz_path_new();
	bin->ne_header = RZ_NEW0(NE_image_header);
	if (!bin->ne_header || !bin->path) {
		return false;
	}
	if (!read_ne_header(bin->ne_header, buf, bin->header_offset)) {
		RZ_FREE(bin->ne_header);
		return false;
	}
	if (bin->ne_header->FileAlnSzShftCnt > 31) {
		return false;
	}
	bin->alignment = 1 << bin->ne_header->FileAlnSzShftCnt;
	if (!bin->alignment) {
		bin->alignment = 1 << 9;
	}
	bin->os = ne_get_target_os(bin);

	if (!ne_read_module_refs_and_imported_names(buf, bin) ||
		!ne_read_image_segment_entries(buf, bin) ||
		!ne_read_segment_entries(buf, bin) ||
		!ne_read_resident_name_table(buf, bin) ||
		!ne_read_relocation_entries(buf, bin) ||
		!ne_read_resources(buf, bin)) {
		RZ_LOG_ERROR("ne: failed to parse bin\n");
		return false;
	}

	// ne_get_resources(buf, bin);
	return true;
}

RZ_IPI void ne_free(RZ_NULLABLE ne_t *bin) {
	if (!bin) {
		return;
	}
	free(bin->ne_header);
	rz_list_free(bin->resources);
	rz_vector_free(bin->resident_name_entries);
	rz_vector_free(bin->nonresident_name_entries);
	rz_vector_free(bin->image_segment_entries);
	rz_vector_free(bin->segment_entries);
	rz_vector_free(bin->relocation_entries);
	rz_vector_free(bin->module_refs);
	rz_pvector_free(bin->imported_modules);
	rz_path_free(bin->path);
	free(bin);
}

RZ_IPI RZ_OWN ne_t *ne_new_buf(RZ_NONNULL RzBuffer *buf) {
	rz_return_val_if_fail(buf, NULL);

	ne_t *bin = RZ_NEW0(ne_t);
	if (!bin || !ne_buf_init(buf, bin)) {
		ne_free(bin);
		return NULL;
	}
	return bin;
}
