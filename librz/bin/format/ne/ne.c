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
	ut8 sz;
	if (!rz_buf_read8_at(buf, offset, &sz)) {
		return NULL;
	}
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
	char *formats_dir = rz_path_system(RZ_SDB_FORMAT);
	char *path = rz_str_newf(RZ_JOIN_3_PATHS("%s", "dll", "%s.sdb"), formats_dir, module);
	free(formats_dir);
	char *ord = rz_str_newf("%d", ordinal);
	char *name;
	if (rz_file_exists(path)) {
		Sdb *sdb = sdb_new(NULL, path, 0);
		name = sdb_get(sdb, ord);
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
	free(path);
	return name;
}

RzPVector /*<RzBinSection *>*/ *rz_bin_ne_get_segments(rz_bin_ne_obj_t *bin) {
	int i;
	if (!bin) {
		return NULL;
	}
	RzPVector *segments = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!segments) {
		return NULL;
	}
	for (i = 0; i < bin->ne_header->SegCount; i++) {
		RzBinSection *bs = RZ_NEW0(RzBinSection);
		NE_image_segment_entry *se = &bin->segment_entries[i];
		if (!bs || !se) {
			free(bs);
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
		rz_pvector_push(segments, bs);
	}
	bin->segments = segments;
	return segments;
}

static int __find_symbol_by_paddr(const void *paddr, const void *sym, void *user) {
	return (int)!(*(ut64 *)paddr == ((RzBinSymbol *)sym)->paddr);
}

static void ne_sanitize_name(char *name, ut16 count) {
	// expect to have names in ASCII format.
	for (ut16 i = 0; i < count && name[i]; ++i) {
		if (!IS_PRINTABLE(name[i])) {
			name[i] = '?';
		}
	}
}

RzPVector /*<RzBinSymbol *>*/ *rz_bin_ne_get_symbols(rz_bin_ne_obj_t *bin) {
	RzBinSymbol *sym;
	ut16 off = bin->ne_header->ResidNamTable + bin->header_offset;
	RzPVector *symbols = rz_pvector_new(free);
	if (!symbols) {
		return NULL;
	}
	RzPVector *entries = rz_bin_ne_get_entrypoints(bin);
	bool resident = true, first = true;
	while (true) {
		ut8 sz;
		if (!rz_buf_read8_at(bin->buf, off, &sz)) {
			break;
		}
		if (!sz) {
			first = true;
			if (resident) {
				resident = false;
				off = bin->ne_header->OffStartNonResTab;
				if (!rz_buf_read8_at(bin->buf, off, &sz)) {
					break;
				}
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
		ne_sanitize_name(name, sz);
		sym->name = name;
		if (!first) {
			sym->bind = RZ_BIN_BIND_GLOBAL_STR;
		}
		ut16 entry_off;
		if (!rz_buf_read_le16_at(bin->buf, off, &entry_off)) {
			rz_bin_symbol_free(sym);
			break;
		}
		off += 2;
		RzBinAddr *entry = (RzBinAddr *)rz_pvector_at(entries, entry_off);
		if (entry) {
			sym->paddr = entry->paddr;
		} else {
			sym->paddr = -1;
		}
		sym->ordinal = entry_off;
		rz_pvector_push(symbols, sym);
		first = false;
	}
	void **it;
	RzBinAddr *en;
	int i = 1;
	rz_pvector_foreach (entries, it) {
		en = *it;
		if (!rz_pvector_find(symbols, &en->paddr, __find_symbol_by_paddr, NULL)) {
			sym = RZ_NEW0(RzBinSymbol);
			if (!sym) {
				break;
			}
			sym->name = rz_str_newf("entry%d", i - 1);
			sym->paddr = en->paddr;
			sym->bind = RZ_BIN_BIND_GLOBAL_STR;
			sym->ordinal = i;
			rz_pvector_push(symbols, sym);
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

	ut16 alignment;
	if (!rz_buf_read_le16_at(bin->buf, resoff, &alignment) || alignment > 31) {
		return false;
	}

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
		ut64 offset = off;
		rz_buf_read_le16_offset(bin->buf, &offset, &ti.rtTypeID);
		rz_buf_read_le16_offset(bin->buf, &offset, &ti.rtResourceCount);
		rz_buf_read_le32_offset(bin->buf, &offset, &ti.rtReserved);
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
			rz_ne_resource_entry *ren = RZ_NEW0(rz_ne_resource_entry);
			if (!ren) {
				break;
			}
			offset = off;
			NE_image_nameinfo_entry ni = { 0 };
			rz_buf_read_le16_offset(bin->buf, &offset, &ni.rnOffset);
			rz_buf_read_le16_offset(bin->buf, &offset, &ni.rnLength);
			rz_buf_read_le16_offset(bin->buf, &offset, &ni.rnFlags);
			rz_buf_read_le16_offset(bin->buf, &offset, &ni.rnID);
			rz_buf_read_le16_offset(bin->buf, &offset, &ni.rnHandle);
			rz_buf_read_le16_offset(bin->buf, &offset, &ni.rnUsage);
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

RzPVector /*<RzBinImport *>*/ *rz_bin_ne_get_imports(rz_bin_ne_obj_t *bin) {
	RzPVector *imports = rz_pvector_new((RzListFree)rz_bin_import_free);
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
		ut8 sz;
		if (!rz_buf_read8_at(bin->buf, off, &sz)) {
			break;
		}
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
		rz_pvector_push(imports, imp);
		off += sz;
	}
	bin->imports = imports;
	return imports;
}

RzPVector /*<RzBinAddr *>*/ *rz_bin_ne_get_entrypoints(rz_bin_ne_obj_t *bin) {
	RzPVector *entries = rz_pvector_new(free);
	if (!entries) {
		return NULL;
	}
	RzBinAddr *entry;
	RzPVector *segments = rz_bin_ne_get_segments(bin);
	if (!segments) {
		rz_pvector_free(entries);
		return NULL;
	}
	if (bin->ne_header->csEntryPoint) {
		entry = RZ_NEW0(RzBinAddr);
		if (!entry) {
			rz_pvector_free(entries);
			rz_pvector_free(segments);
			return NULL;
		}
		entry->bits = 16;
		RzBinSection *s = (RzBinSection *)rz_pvector_at(segments, bin->ne_header->csEntryPoint - 1);
		entry->paddr = bin->ne_header->ipEntryPoint + (s ? s->paddr : 0);
		rz_pvector_push(entries, entry);
	}
	ut32 off = 0;
	while (off < bin->ne_header->EntryTableLength) {
		ut8 bundle_length = *(ut8 *)(bin->entry_table + off);
		if (!bundle_length) {
			break;
		}
		off++;
		if (off >= bin->ne_header->EntryTableLength) {
			break;
		}
		ut8 bundle_type = *(ut8 *)(bin->entry_table + off);
		off++;
		int i;
		for (i = 0; i < bundle_length; i++) {
			entry = RZ_NEW0(RzBinAddr);
			if (!entry) {
				rz_pvector_free(entries);
				rz_pvector_free(segments);
				return NULL;
			}
			off++;
			if (!bundle_type) { // Skip
				off--;
				free(entry);
				break;
			} else if (bundle_type == 0xFF) { // Moveable
				off += 2;
				if ((off + 1) >= bin->ne_header->EntryTableLength) {
					free(entry);
					goto end;
				}
				ut8 segnum = rz_read_le8(bin->entry_table + off);
				off++;
				if ((off + 2) >= bin->ne_header->EntryTableLength) {
					free(entry);
					goto end;
				}
				ut16 segoff = rz_read_le16(bin->entry_table + off);
				if (!segnum || segnum > bin->ne_header->SegCount) {
					free(entry);
					continue;
				}
				entry->paddr = (ut64)bin->segment_entries[segnum - 1].offset * bin->alignment + segoff;
			} else { // Fixed
				ut8 *p = bin->entry_table + off;
				if ((off + 2) >= bin->ne_header->EntryTableLength || bundle_type > bin->ne_header->SegCount) {
					free(entry);
					goto end;
				}
				entry->paddr = (ut64)bin->segment_entries[bundle_type - 1].offset * bin->alignment + rz_read_le16(p);
			}
			off += 2;
			rz_pvector_push(entries, entry);
		}
	}
end:
	rz_pvector_free(segments);
	bin->entries = entries;
	return entries;
}

RzPVector /*<RzBinReloc *>*/ *rz_bin_ne_get_relocs(rz_bin_ne_obj_t *bin) {
	RzPVector *segments = bin->segments;
	if (!segments) {
		return NULL;
	}
	RzPVector *entries = bin->entries;
	if (!entries) {
		return NULL;
	}
	RzPVector *symbols = bin->symbols;
	if (!symbols) {
		return NULL;
	}

	ut16 *modref = calloc(bin->ne_header->ModRefs, sizeof(ut16));
	if (!modref) {
		return NULL;
	}
	rz_buf_read_at(bin->buf, (ut64)bin->ne_header->ModRefTable + bin->header_offset, (ut8 *)modref, bin->ne_header->ModRefs * sizeof(ut16));

	RzPVector *relocs = rz_pvector_new(free);
	if (!relocs) {
		free(modref);
		return NULL;
	}

	ut64 bufsz = rz_buf_size(bin->buf);
	void **it;
	RzBinSection *seg;
	int index = -1;
	rz_pvector_foreach (segments, it) {
		seg = *it;
		index++;
		if (!(bin->segment_entries[index].flags & RELOCINFO)) {
			continue;
		}
		ut32 off, start = off = seg->paddr + seg->size;
		if ((ut64)off + 2 > bufsz) {
			continue;
		}
		ut16 length;
		if (!rz_buf_read_le16_at(bin->buf, off, &length)) {
			continue;
		}

		if (!length) {
			continue;
		}
		off += 2;
		while (off < start + length * sizeof(NE_image_reloc_item) && off + sizeof(NE_image_reloc_item) <= bufsz) {
			RzBinReloc *reloc = RZ_NEW0(RzBinReloc);
			if (!reloc) {
				return NULL;
			}
			NE_image_reloc_item rel;
			ut64 offset = off;
			rz_buf_read8_offset(bin->buf, &offset, &rel.type);
			rz_buf_read8_offset(bin->buf, &offset, &rel.flags);
			rz_buf_read_le16_offset(bin->buf, &offset, &rel.offset);
			rz_buf_read_le16_offset(bin->buf, &offset, &rel.align1);
			rz_buf_read_le16_offset(bin->buf, &offset, &rel.func_ord);
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

			if (rel.flags & (IMPORTED_ORD | IMPORTED_NAME)) {
				RzBinImport *imp = RZ_NEW0(RzBinImport);
				if (!imp) {
					free(reloc);
					break;
				}
				char *name = NULL;
				if (rel.index > bin->ne_header->ModRefs || !rel.index) {
					name = rz_str_newf("UnknownModule%d_%x", rel.index, off); // ????
				} else {
					ut16 modref_val = rz_read_le16(&modref[rel.index - 1]);
					offset = modref_val + bin->header_offset + bin->ne_header->ImportNameTable;
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
					RzBinSection *s = (RzBinSection *)rz_pvector_at(segments, rel.segnum - 1);
					if (s) {
						offset = s->paddr + rel.segoff;
					} else {
						offset = -1;
					}
				} else {
					RzBinAddr *entry = (RzBinAddr *)rz_pvector_at(entries, rel.entry_ordinal - 1);
					if (entry) {
						offset = entry->paddr;
					} else {
						offset = -1;
					}
				}
				reloc->addend = offset;
				RzBinSymbol *sym = NULL;
				void **sit;
				rz_pvector_foreach (symbols, sit) {
					sym = *sit;
					if (sym->paddr == reloc->addend) {
						reloc->symbol = sym;
						break;
					}
				}
			}

			if (rel.flags & ADDITIVE) {
				reloc->additive = 1;
				rz_pvector_push(relocs, reloc);
			} else {
				do {
					rz_pvector_push(relocs, reloc);
					ut16 tmp_offset;
					if (!rz_buf_read_le16_at(bin->buf, reloc->paddr, &tmp_offset)) {
						reloc = NULL;
						break;
					}

					offset = tmp_offset;

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

static bool read_ne_header(NE_image_header *ne, RzBuffer *buf, ut64 off) {
	ut64 offset = off;
	return (rz_buf_read8_offset(buf, &offset, (ut8 *)&ne->sig[0]) &&
		rz_buf_read8_offset(buf, &offset, (ut8 *)&ne->sig[1]) &&
		rz_buf_read8_offset(buf, &offset, &ne->MajLinkerVersion) &&
		rz_buf_read8_offset(buf, &offset, &ne->MinLinkerVersion) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->EntryTableOffset) &&
		rz_buf_read_le16_offset(buf, &offset, &ne->EntryTableLength) &&
		rz_buf_read_le32_offset(buf, &offset, &ne->FileLoadCRC) &&
		rz_buf_read8_offset(buf, &offset, &ne->ProgFlags) &&
		rz_buf_read8_offset(buf, &offset, &ne->ApplFlags) &&
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
		rz_buf_read8_offset(buf, &offset, (ut8 *)&ne->expctwinver[0]) &&
		rz_buf_read8_offset(buf, &offset, (ut8 *)&ne->expctwinver[1]));
}

bool rz_bin_ne_buf_init(RzBuffer *buf, rz_bin_ne_obj_t *bin) {
	if (!rz_buf_read_le16_at(buf, 0x3c, &bin->header_offset)) {
		return false;
	}

	bin->ne_header = RZ_NEW0(NE_image_header);
	if (!bin->ne_header) {
		return false;
	}
	bin->buf = buf;
	if (!read_ne_header(bin->ne_header, bin->buf, bin->header_offset)) {
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
	bin->os = __get_target_os(bin);

	if (!bin->ne_header->SegCount) {
		return false;
	}
	bin->segment_entries = calloc(bin->ne_header->SegCount, sizeof(NE_image_segment_entry));
	if (!bin->segment_entries) {
		return false;
	}

	ut64 offset = bin->ne_header->SegTableOffset + bin->header_offset;
	for (ut32 i = 0; i < bin->ne_header->SegCount; i++) {
		NE_image_segment_entry *ne_segment_entry = bin->segment_entries + i;
		rz_buf_read_le16_offset(buf, &offset, &ne_segment_entry->offset);
		rz_buf_read_le16_offset(buf, &offset, &ne_segment_entry->length);
		rz_buf_read_le16_offset(buf, &offset, &ne_segment_entry->flags);
		rz_buf_read_le16_offset(buf, &offset, &ne_segment_entry->minAllocSz);
	}
	if (!bin->ne_header->EntryTableLength) {
		return false;
	}
	bin->entry_table = calloc(1, bin->ne_header->EntryTableLength);
	if (!bin->entry_table) {
		return false;
	}
	rz_buf_read_at(buf, (ut64)bin->header_offset + bin->ne_header->EntryTableOffset, bin->entry_table, bin->ne_header->EntryTableLength);
	bin->imports = rz_bin_ne_get_imports(bin);
	__ne_get_resources(bin);
	return true;
}

void rz_bin_ne_free(rz_bin_ne_obj_t *bin) {
	if (!bin) {
		return;
	}
	// rz_list_free (bin->imports); // double free
	rz_list_free(bin->resources);
	free(bin->entry_table);
	free(bin->ne_header);
	free(bin->resident_name_table);
	free(bin->segment_entries);
	free(bin);
}

rz_bin_ne_obj_t *rz_bin_ne_new_buf(RzBuffer *buf, bool verbose) {
	rz_bin_ne_obj_t *bin = RZ_NEW0(rz_bin_ne_obj_t);
	if (!bin) {
		return NULL;
	}
	if (!rz_bin_ne_buf_init(buf, bin)) {
		rz_bin_ne_free(bin);
		return NULL;
	}
	return bin;
}
