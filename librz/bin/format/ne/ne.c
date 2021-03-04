// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "ne.h"

static char *__get_target_os(rz_bin_ne_obj_t *bin) {
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

static int __translate_perms(int flags) {
	int perms = 0;
	if (flags & IS_RX) {
		if (flags & IS_DATA) {
			perms = RZ_PERM_R;
		} else {
			perms = RZ_PERM_X;
		}
	}
	if (!perms) {
		perms = RZ_PERM_RWX;
	}
	return perms;
}

static char *__read_nonnull_str_at(RzBuffer *buf, ut64 offset) {
	ut8 sz = rz_buf_read8_at(buf, offset);
	if (!sz) {
		return NULL;
	}
	char *str = malloc((ut64)sz + 1);
	if (!str) {
		return NULL;
	}
	rz_buf_read_at(buf, offset + 1, (ut8 *)str, sz);
	str[sz] = '\0';
	return str;
}

static char *__func_name_from_ord(char *module, ut16 ordinal) {
	char *path = rz_str_newf(RZ_JOIN_4_PATHS("%s", RZ_SDB_FORMAT, "dll", "%s.sdb"), rz_sys_prefix(NULL), module);
	char *ord = rz_str_newf("%d", ordinal);
	char *name;
	if (rz_file_exists(path)) {
		Sdb *sdb = sdb_new(NULL, path, 0);
		name = sdb_get(sdb, ord, NULL);
		if (!name) {
			name = ord;
		} else {
			free(ord);
		}
		sdb_close(sdb);
		free(sdb);
	} else {
		name = ord;
	}
	return name;
}

RzList *rz_bin_ne_get_segments(rz_bin_ne_obj_t *bin) {
	int i;
	if (!bin) {
		return NULL;
	}
	RzList *segments = rz_list_newf(free);
	for (i = 0; i < bin->ne_header->SegCount; i++) {
		RzBinSection *bs = RZ_NEW0(RzBinSection);
		NE_image_segment_entry *se = &bin->segment_entries[i];
		if (!bs) {
			return segments;
		}
		bs->size = se->length;
		bs->vsize = se->minAllocSz ? se->minAllocSz : 64000;
		bs->bits = RZ_SYS_BITS_16;
		bs->is_data = se->flags & IS_DATA;
		bs->perm = __translate_perms(se->flags);
		bs->paddr = (ut64)se->offset * bin->alignment;
		bs->name = rz_str_newf("%s.%" PFMT64d, se->flags & IS_MOVEABLE ? "MOVEABLE" : "FIXED", bs->paddr);
		bs->is_segment = true;
		rz_list_append(segments, bs);
	}
	bin->segments = segments;
	return segments;
}

static int __find_symbol_by_paddr(const void *paddr, const void *sym) {
	return (int)!(*(ut64 *)paddr == ((RzBinSymbol *)sym)->paddr);
}

RzList *rz_bin_ne_get_symbols(rz_bin_ne_obj_t *bin) {
	RzBinSymbol *sym;
	ut16 off = bin->ne_header->ResidNamTable + bin->header_offset;
	RzList *symbols = rz_list_newf(free);
	if (!symbols) {
		return NULL;
	}
	RzList *entries = rz_bin_ne_get_entrypoints(bin);
	bool resident = true, first = true;
	while (true) {
		ut8 sz = rz_buf_read8_at(bin->buf, off);
		if (!sz) {
			first = true;
			if (resident) {
				resident = false;
				off = bin->ne_header->OffStartNonResTab;
				sz = rz_buf_read8_at(bin->buf, off);
				if (!sz) {
					break;
				}
			} else {
				break;
			}
		}
		char *name = malloc((ut64)sz + 1);
		if (!name) {
			break;
		}
		off++;
		rz_buf_read_at(bin->buf, off, (ut8 *)name, sz);
		name[sz] = '\0';
		off += sz;
		sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			break;
		}
		sym->name = name;
		if (!first) {
			sym->bind = RZ_BIN_BIND_GLOBAL_STR;
		}
		ut16 entry_off = rz_buf_read_le16_at(bin->buf, off);
		off += 2;
		RzBinAddr *entry = rz_list_get_n(entries, entry_off);
		if (entry) {
			sym->paddr = entry->paddr;
		} else {
			sym->paddr = -1;
		}
		sym->ordinal = entry_off;
		rz_list_append(symbols, sym);
		first = false;
	}
	RzListIter *it;
	RzBinAddr *en;
	int i = 1;
	rz_list_foreach (entries, it, en) {
		if (!rz_list_find(symbols, &en->paddr, __find_symbol_by_paddr)) {
			sym = RZ_NEW0(RzBinSymbol);
			if (!sym) {
				break;
			}
			sym->name = rz_str_newf("entry%d", i - 1);
			sym->paddr = en->paddr;
			sym->bind = RZ_BIN_BIND_GLOBAL_STR;
			sym->ordinal = i;
			rz_list_append(symbols, sym);
		}
		i++;
	}
	bin->symbols = symbols;
	return symbols;
}

static char *__resource_type_str(int type) {
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
	return strdup(typeName);
}

static void __free_resource_entry(void *entry) {
	rz_ne_resource_entry *en = (rz_ne_resource_entry *)entry;
	free(en->name);
	free(en);
}

static void __free_resource(void *resource) {
	rz_ne_resource *res = (rz_ne_resource *)resource;
	free(res->name);
	rz_list_free(res->entry);
	free(res);
}

static bool __ne_get_resources(rz_bin_ne_obj_t *bin) {
	if (!bin->resources) {
		bin->resources = rz_list_newf(__free_resource);
	}
	ut16 resoff = bin->ne_header->ResTableOffset + bin->header_offset;
	ut16 alignment = rz_buf_read_le16_at(bin->buf, resoff);
	ut32 off = resoff + 2;
	while (true) {
		NE_image_typeinfo_entry ti = { 0 };
		rz_ne_resource *res = RZ_NEW0(rz_ne_resource);
		if (!res) {
			break;
		}
		res->entry = rz_list_newf(__free_resource_entry);
		if (!res->entry) {
			break;
		}
		rz_buf_read_at(bin->buf, off, (ut8 *)&ti, sizeof(ti));
		if (!ti.rtTypeID) {
			break;
		} else if (ti.rtTypeID & 0x8000) {
			res->name = __resource_type_str(ti.rtTypeID & ~0x8000);
		} else {
			// Offset to resident name table
			res->name = __read_nonnull_str_at(bin->buf, (ut64)resoff + ti.rtTypeID);
		}
		off += sizeof(NE_image_typeinfo_entry);
		int i;
		for (i = 0; i < ti.rtResourceCount; i++) {
			NE_image_nameinfo_entry ni;
			rz_ne_resource_entry *ren = RZ_NEW0(rz_ne_resource_entry);
			if (!ren) {
				break;
			}
			rz_buf_read_at(bin->buf, off, (ut8 *)&ni, sizeof(NE_image_nameinfo_entry));
			ren->offset = ni.rnOffset << alignment;
			ren->size = ni.rnLength;
			if (ni.rnID & 0x8000) {
				ren->name = rz_str_newf("%d", ni.rnID & ~0x8000);
			} else {
				// Offset to resident name table
				ren->name = __read_nonnull_str_at(bin->buf, (ut64)resoff + ni.rnID);
			}
			rz_list_append(res->entry, ren);
			off += sizeof(NE_image_nameinfo_entry);
		}
		rz_list_append(bin->resources, res);
	}
	return true;
}

RzList *rz_bin_ne_get_imports(rz_bin_ne_obj_t *bin) {
	RzList *imports = rz_list_newf(free);
	if (!imports) {
		return NULL;
	}
	ut16 off = bin->ne_header->ImportNameTable + bin->header_offset + 1;
	int i;
	for (i = 0; i < bin->ne_header->ModRefs; i++) {
		RzBinImport *imp = RZ_NEW0(RzBinImport);
		if (!imp) {
			break;
		}
		ut8 sz = rz_buf_read8_at(bin->buf, off);
		if (!sz) {
			rz_bin_import_free(imp);
			break;
		}
		off++;
		char *name = malloc((ut64)sz + 1);
		if (!name) {
			break;
		}
		rz_buf_read_at(bin->buf, off, (ut8 *)name, sz);
		name[sz] = '\0';
		imp->name = name;
		imp->ordinal = i + 1;
		rz_list_append(imports, imp);
		off += sz;
	}
	bin->imports = imports;
	return imports;
}

RzList *rz_bin_ne_get_entrypoints(rz_bin_ne_obj_t *bin) {
	RzList *entries = rz_list_newf(free);
	if (!entries) {
		return NULL;
	}
	RzBinAddr *entry;
	RzList *segments = rz_bin_ne_get_segments(bin);
	if (!segments) {
		rz_list_free(entries);
		return NULL;
	}
	if (bin->ne_header->csEntryPoint) {
		entry = RZ_NEW0(RzBinAddr);
		if (!entry) {
			rz_list_free(entries);
			return NULL;
		}
		entry->bits = 16;
		RzBinSection *s = rz_list_get_n(segments, bin->ne_header->csEntryPoint - 1);
		entry->paddr = bin->ne_header->ipEntryPoint + (s ? s->paddr : 0);
		rz_list_append(entries, entry);
	}
	int off = 0;
	while (off < bin->ne_header->EntryTableLength) {
		ut8 bundle_length = *(ut8 *)(bin->entry_table + off);
		if (!bundle_length) {
			break;
		}
		off++;
		ut8 bundle_type = *(ut8 *)(bin->entry_table + off);
		off++;
		int i;
		for (i = 0; i < bundle_length; i++) {
			entry = RZ_NEW0(RzBinAddr);
			if (!entry) {
				rz_list_free(entries);
				return NULL;
			}
			off++;
			if (!bundle_type) { // Skip
				off--;
				free(entry);
				break;
			} else if (bundle_type == 0xFF) { // Moveable
				off += 2;
				ut8 segnum = *(bin->entry_table + off);
				off++;
				ut16 segoff = *(ut16 *)(bin->entry_table + off);
				entry->paddr = (ut64)bin->segment_entries[segnum - 1].offset * bin->alignment + segoff;
			} else { // Fixed
				entry->paddr = (ut64)bin->segment_entries[bundle_type - 1].offset * bin->alignment + *(ut16 *)(bin->entry_table + off);
			}
			off += 2;
			rz_list_append(entries, entry);
		}
	}
	rz_list_free(segments);
	bin->entries = entries;
	return entries;
}

RzList *rz_bin_ne_get_relocs(rz_bin_ne_obj_t *bin) {
	RzList *segments = bin->segments;
	if (!segments) {
		return NULL;
	}
	RzList *entries = bin->entries;
	if (!entries) {
		return NULL;
	}
	RzList *symbols = bin->symbols;
	if (!symbols) {
		return NULL;
	}

	ut16 *modref = malloc(bin->ne_header->ModRefs * sizeof(ut16));
	if (!modref) {
		return NULL;
	}
	rz_buf_read_at(bin->buf, (ut64)bin->ne_header->ModRefTable + bin->header_offset, (ut8 *)modref, bin->ne_header->ModRefs * sizeof(ut16));

	RzList *relocs = rz_list_newf(free);
	if (!relocs) {
		free(modref);
		return NULL;
	}

	RzListIter *it;
	RzBinSection *seg;
	int index = -1;
	rz_list_foreach (segments, it, seg) {
		index++;
		if (!(bin->segment_entries[index].flags & RELOCINFO)) {
			continue;
		}
		ut32 off, start = off = seg->paddr + seg->size;
		ut16 length = rz_buf_read_le16_at(bin->buf, off);
		if (!length) {
			continue;
		}
		off += 2;
		while (off < start + length * sizeof(NE_image_reloc_item)) {
			RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
			if (!reloc) {
				return NULL;
			}
			NE_image_reloc_item rel;
			rz_buf_read_at(bin->buf, off, (ut8 *)&rel, sizeof(rel));
			reloc->paddr = seg->paddr + rel.offset;
			switch (rel.type) {
			case LOBYTE:
				reloc->type = RZ_BIN_RELOC_8;
				break;
			case SEL_16:
			case OFF_16:
				reloc->type = RZ_BIN_RELOC_16;
				break;
			case POI_32:
			case OFF_32:
				reloc->type = RZ_BIN_RELOC_32;
				break;
			case POI_48:
				reloc->type = RZ_BIN_RELOC_64;
				break;
			}

			ut32 offset;
			if (rel.flags & (IMPORTED_ORD | IMPORTED_NAME)) {
				RzBinImport *imp = RZ_NEW0(RzBinImport);
				if (!imp) {
					free(reloc);
					break;
				}
				char *name;
				if (rel.index > bin->ne_header->ModRefs) {
					name = rz_str_newf("UnknownModule%d_%x", rel.index, off); // ????
				} else {
					offset = modref[rel.index - 1] + bin->header_offset + bin->ne_header->ImportNameTable;
					name = __read_nonnull_str_at(bin->buf, offset);
				}
				if (rel.flags & IMPORTED_ORD) {
					imp->ordinal = rel.func_ord;
					imp->name = rz_str_newf("%s.%s", name, __func_name_from_ord(name, rel.func_ord));
				} else {
					offset = bin->header_offset + bin->ne_header->ImportNameTable + rel.name_off;
					char *func = __read_nonnull_str_at(bin->buf, offset);
					imp->name = rz_str_newf("%s.%s", name, func);
					free(func);
				}
				free(name);
				reloc->import = imp;
			} else if (rel.flags & OSFIXUP) {
				// TODO
			} else {
				if (strstr(seg->name, "FIXED")) {
					RzBinSection *s = rz_list_get_n(segments, rel.segnum - 1);
					if (s) {
						offset = s->paddr + rel.segoff;
					} else {
						offset = -1;
					}
				} else {
					RzBinAddr *entry = rz_list_get_n(entries, rel.entry_ordinal - 1);
					if (entry) {
						offset = entry->paddr;
					} else {
						offset = -1;
					}
				}
				reloc->addend = offset;
				RzBinSymbol *sym = NULL;
				RzListIter *sit;
				rz_list_foreach (symbols, sit, sym) {
					if (sym->paddr == reloc->addend) {
						reloc->symbol = sym;
						break;
					}
				}
			}

			if (rel.flags & ADDITIVE) {
				reloc->additive = 1;
				rz_list_append(relocs, reloc);
			} else {
				do {
					rz_list_append(relocs, reloc);

					offset = rz_buf_read_le16_at(bin->buf, reloc->paddr);
					RzBinReloc *tmp = reloc;
					reloc = RZ_NEW0(RzBinReloc);
					if (!reloc) {
						break;
					}
					*reloc = *tmp;
					reloc->paddr = seg->paddr + offset;
				} while (offset != 0xFFFF);
				free(reloc);
			}

			off += sizeof(NE_image_reloc_item);
		}
	}
	free(modref);
	return relocs;
}

void __init(RzBuffer *buf, rz_bin_ne_obj_t *bin) {
	bin->header_offset = rz_buf_read_le16_at(buf, 0x3c);
	bin->ne_header = RZ_NEW0(NE_image_header);
	if (!bin->ne_header) {
		return;
	}
	bin->buf = buf;
	rz_buf_read_at(buf, bin->header_offset, (ut8 *)bin->ne_header, sizeof(NE_image_header));
	bin->alignment = 1 << bin->ne_header->FileAlnSzShftCnt;
	if (!bin->alignment) {
		bin->alignment = 1 << 9;
	}
	bin->os = __get_target_os(bin);

	ut16 offset = bin->ne_header->SegTableOffset + bin->header_offset;
	ut16 size = bin->ne_header->SegCount * sizeof(NE_image_segment_entry);
	bin->segment_entries = calloc(1, size);
	if (!bin->segment_entries) {
		return;
	}
	rz_buf_read_at(buf, offset, (ut8 *)bin->segment_entries, size);
	bin->entry_table = calloc(1, bin->ne_header->EntryTableLength);
	rz_buf_read_at(buf, (ut64)bin->header_offset + bin->ne_header->EntryTableOffset, bin->entry_table, bin->ne_header->EntryTableLength);
	bin->imports = rz_bin_ne_get_imports(bin);
	__ne_get_resources(bin);
}

void rz_bin_ne_free(rz_bin_ne_obj_t *bin) {
	// rz_list_free (bin->imports); // double free
	rz_list_free(bin->resources);
	free(bin->entry_table);
	free(bin->ne_header);
	free(bin->resident_name_table);
	free(bin->segment_entries);
}

rz_bin_ne_obj_t *rz_bin_ne_new_buf(RzBuffer *buf, bool verbose) {
	rz_bin_ne_obj_t *bin = RZ_NEW0(rz_bin_ne_obj_t);
	if (!bin) {
		return NULL;
	}
	__init(buf, bin);
	return bin;
}
