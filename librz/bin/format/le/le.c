// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "le.h"
#include <rz_bin.h>

const char *le_get_module_type(rz_bin_le_obj_t *bin) {
	switch (bin->header->mflags & M_TYPE_MASK) {
	case M_TYPE_EXE: return "Program module (EXE)";
	case M_TYPE_DLL: return "Library module (DLL)";
	case M_TYPE_PDD: return "Physical Device Driver";
	case M_TYPE_VDD: return "Virtual Device Driver";
	default: return "Unknown";
	}
}

const char *le_get_os_type(rz_bin_le_obj_t *bin) {
	switch (bin->header->os) {
	case 1: return "OS/2";
	case 2: return "Windows";
	case 3: return "DOS 4.x";
	case 4: return "Windows 386";
	case 5: return "IBM Microkernel Personality Neutral";
	default: return "Unknown";
	}
}

const char *le_get_cpu_type(rz_bin_le_obj_t *bin) {
	switch (bin->header->cpu) {
	case 1: return "80286";
	case 2: return "80386";
	case 3: return "80486";
	case 0x20: return "N10";
	case 0x21: return "N11";
	case 0x40: return "R3000";
	case 0x41: return "R6000";
	case 0x42: return "R4000";
	default: return "Unknown";
	}
}

const char *le_get_arch(rz_bin_le_obj_t *bin) {
	switch (bin->header->cpu) {
	case 1:
	case 2:
	case 3:
		return "x86";
	case 0x20:
	case 0x21:
		return "i860";
	case 0x40:
	case 0x41:
	case 0x42:
		return "mips";
	default:
		return "Unknown";
	}
}

static char *le_read_nonnull_str_at(RzBuffer *buf, ut64 *offset) {
	ut8 size;
	if (!rz_buf_read8_at(buf, *offset, &size)) {
		return NULL;
	}

	size &= 0x7F; // Max is 127
	if (!size) {
		return NULL;
	}
	(*offset)++;
	char *str = calloc((ut64)size + 1, sizeof(char));
	rz_buf_read_at(buf, *offset, (ut8 *)str, size);
	*offset += size;
	return str;
}

static RzBinSymbol *le_get_symbol(rz_bin_le_obj_t *bin, ut64 *offset) {
	RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
	if (!sym) {
		return NULL;
	}
	char *name = le_read_nonnull_str_at(bin->buf, offset);
	if (!name) {
		rz_bin_symbol_free(sym);
		return NULL;
	}
	sym->name = name;
	ut16 entry_idx;
	if (!rz_buf_read_le16_offset(bin->buf, offset, &entry_idx)) {
		rz_bin_symbol_free(sym);
		return NULL;
	}
	sym->ordinal = entry_idx;
	return sym;
}

static bool read_le_entry_bundle_entry(RzBuffer *buf, ut64 addr, LE_entry_bundle_entry *e, LE_entry_bundle_type type) {
	ut64 offset = addr;
	switch (type) {
	case ENTRY16:
		return rz_buf_read8_offset(buf, &offset, &e->entry_16.flags) &&
			rz_buf_read_le16_offset(buf, &offset, &e->entry_16.offset);
	case CALLGATE:
		return rz_buf_read8_offset(buf, &offset, &e->callgate.flags) &&
			rz_buf_read_le16_offset(buf, &offset, &e->callgate.offset) &&
			rz_buf_read_le16_offset(buf, &offset, &e->callgate.callgate_sel);
	case ENTRY32:
		return rz_buf_read8_offset(buf, &offset, &e->entry_32.flags) &&
			rz_buf_read_le32_offset(buf, &offset, &e->entry_32.offset);
	case FORWARDER:
		return rz_buf_read8_offset(buf, &offset, &e->forwarder.flags) &&
			rz_buf_read_le16_offset(buf, &offset, &e->forwarder.import_ord) &&
			rz_buf_read_le32_offset(buf, &offset, &e->forwarder.offset);
	default:
		memset(e, 0, sizeof(LE_entry_bundle_entry));
		return false;
	}
}

RzList /*<char *>*/ *le_get_entries(rz_bin_le_obj_t *bin) {
	ut64 offset = (ut64)bin->header->enttab + bin->headerOff;
	RzList *l = rz_list_newf(free);
	if (!l) {
		return NULL;
	}
	while (true) {
		LE_entry_bundle_header header;
		LE_entry_bundle_entry e;
		ut64 off = offset;
		if (!(rz_buf_read8_offset(bin->buf, &off, &header.count) &&
			    rz_buf_read8_offset(bin->buf, &off, &header.type) &&
			    rz_buf_read_le16_offset(bin->buf, &off, &header.objnum))) {
			break;
		}
		if (!header.count) {
			break;
		}
		if ((header.type & ~ENTRY_PARAMETER_TYPING_PRESENT) == UNUSED_ENTRY) {
			offset += sizeof(header.type) + sizeof(header.count);
			while (header.count) {
				rz_list_append(l, strdup("")); // (ut64 *)-1);
				header.count--;
			}
			continue;
		}
		offset += sizeof(LE_entry_bundle_header);
		bool typeinfo = header.type & ENTRY_PARAMETER_TYPING_PRESENT;
		int i;
		for (i = 0; i < header.count; i++) {
			LE_entry_bundle_type bundle_type = header.type & ~ENTRY_PARAMETER_TYPING_PRESENT;
			ut64 entry = UT64_MAX;
			read_le_entry_bundle_entry(bin->buf, offset, &e, bundle_type);
			switch (bundle_type) {
			case ENTRY16:
				if ((header.objnum - 1) < bin->header->objcnt) {
					entry = (ut64)e.entry_16.offset + bin->objtbl[header.objnum - 1].reloc_base_addr;
				}
				offset += sizeof(e.entry_16);
				if (typeinfo) {
					offset += (ut64)(e.entry_16.flags & ENTRY_PARAM_COUNT_MASK) * 2;
				}
				break;
			case CALLGATE:
				if ((header.objnum - 1) < bin->header->objcnt) {
					entry = (ut64)e.callgate.offset + bin->objtbl[header.objnum - 1].reloc_base_addr;
				}
				offset += sizeof(e.callgate);
				if (typeinfo) {
					offset += (ut64)(e.callgate.flags & ENTRY_PARAM_COUNT_MASK) * 2;
				}
				break;
			case ENTRY32:
				if ((header.objnum - 1) < bin->header->objcnt) {
					entry = (ut64)e.entry_32.offset + bin->objtbl[header.objnum - 1].reloc_base_addr;
				}
				offset += sizeof(e.entry_32);
				if (typeinfo) {
					offset += (ut64)(e.entry_32.flags & ENTRY_PARAM_COUNT_MASK) * 2;
				}
				break;
			case FORWARDER:
				offset += sizeof(e.forwarder);
				break;
			default:
				break;
			}
			if (entry != UT64_MAX) {
				rz_list_append(l, rz_str_newf("0x%" PFMT64x, entry));
			}
		}
	}
	return l;
}

static void le_get_symbols_at(rz_bin_le_obj_t *bin, RzList /*<RzBinSymbol *>*/ *syml, RzList /*<char *>*/ *entl, ut64 offset, ut64 end) {
	while (offset < end) {
		RzBinSymbol *sym = le_get_symbol(bin, &offset);
		if (!sym) {
			break;
		}
		if (sym->ordinal) {
			const char *n = rz_list_get_n(entl, sym->ordinal - 1);
			if (n) {
				sym->vaddr = rz_num_get(NULL, n);
				sym->bind = RZ_BIN_BIND_GLOBAL_STR;
				sym->type = RZ_BIN_TYPE_FUNC_STR;
				rz_list_append(syml, sym);
			} else {
				rz_bin_symbol_free(sym);
			}
		} else {
			rz_bin_symbol_free(sym);
		}
	}
}

RzList /*<RzBinSymbol *>*/ *rz_bin_le_get_symbols(rz_bin_le_obj_t *bin) {
	RzList *l = rz_list_newf((RzListFree)rz_bin_symbol_free);
	RzList *entries = le_get_entries(bin);
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->restab + bin->headerOff;
	ut32 end = h->enttab + bin->headerOff;
	le_get_symbols_at(bin, l, entries, offset, end);
	offset = h->nrestab;
	end = h->nrestab + h->cbnrestab;
	le_get_symbols_at(bin, l, entries, offset, end);
	rz_list_free(entries);
	return l;
}

RzList /*<RzBinImport *>*/ *rz_bin_le_get_imports(rz_bin_le_obj_t *bin) {
	RzList *l = rz_list_newf((RzListFree)rz_bin_import_free);
	if (!l) {
		return NULL;
	}
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->impproc + bin->headerOff + 1; // First entry is a null string
	ut64 end = (ut64)h->fixupsize + h->fpagetab + bin->headerOff;
	while (offset < end) {
		RzBinImport *imp = RZ_NEW0(RzBinImport);
		if (!imp) {
			break;
		}
		imp->name = le_read_nonnull_str_at(bin->buf, &offset);
		if (!imp->name) {
			rz_bin_import_free(imp);
			break;
		}
		imp->type = RZ_BIN_TYPE_FUNC_STR;
		rz_list_append(l, imp);
	}
	return l;
}

RzList /*<RzBinAddr *>*/ *rz_bin_le_get_entrypoints(rz_bin_le_obj_t *bin) {
	RzList *l = rz_list_newf((RzListFree)free);
	if (!l) {
		return NULL;
	}
	RzBinAddr *entry = RZ_NEW0(RzBinAddr);
	if (entry) {
		if ((bin->header->startobj - 1) < bin->header->objcnt) {
			entry->vaddr = (ut64)bin->objtbl[bin->header->startobj - 1].reloc_base_addr + bin->header->eip;
		}
	}
	rz_list_append(l, entry);

	return l;
}

RzList /*<char *>*/ *rz_bin_le_get_libs(rz_bin_le_obj_t *bin) {
	RzList *l = rz_list_newf((RzListFree)free);
	if (!l) {
		return NULL;
	}
	LE_image_header *h = bin->header;
	ut64 offset = (ut64)h->impmod + bin->headerOff;
	ut64 end = offset + h->impproc - h->impmod;
	while (offset < end) {
		char *name = le_read_nonnull_str_at(bin->buf, &offset);
		if (!name) {
			break;
		}
		rz_list_append(l, name);
	}
	return l;
}

/*
 *	Creates & appends to l iter_n sections with the same paddr for each iter record.
 *	page->size is the total size of iter records that describe the page
 *	TODO: Don't do this
 */
static void __create_iter_sections(RzList /*<RzBinSection *>*/ *l, rz_bin_le_obj_t *bin, RzBinSection *sec, LE_object_page_entry *page, ut64 vaddr, int cur_page) {
	rz_return_if_fail(l && bin && sec && page);
	LE_image_header *h = bin->header;
	ut32 offset = (h->itermap + (page->offset << (bin->is_le ? 0 : h->pageshift)));

	// Gets the first iter record
	ut16 iter_n;
	if (!rz_buf_read_ble16_at(bin->buf, offset, &iter_n, h->worder)) {
		return;
	}

	offset += sizeof(ut16);
	ut16 data_size;
	if (!rz_buf_read_ble16_at(bin->buf, offset, &data_size, h->worder)) {
		return;
	}

	offset += sizeof(ut16);

	ut64 tot_size = 0;
	int iter_cnt = 0;
	ut64 bytes_left = page->size;
	while (iter_n && bytes_left > 0) {
		int i;
		for (i = 0; i < iter_n; i++) {
			RzBinSection *s = RZ_NEW0(RzBinSection);
			if (!s) {
				break;
			}
			s->name = rz_str_newf("%s.page.%d.iter.%d", sec->name, cur_page, iter_cnt);
			s->bits = sec->bits;
			s->perm = sec->perm;
			s->size = data_size;
			s->vsize = data_size;
			s->paddr = offset;
			s->vaddr = vaddr;
			vaddr += data_size;
			tot_size += data_size;
			rz_list_append(l, s);
			iter_cnt++;
		}
		bytes_left -= sizeof(ut16) * 2 + data_size;
		// Get the next iter record
		offset += data_size;

		if (!rz_buf_read_ble16_at(bin->buf, offset, &iter_n, h->worder)) {
			return;
		}
		offset += sizeof(ut16);

		if (!rz_buf_read_ble16_at(bin->buf, offset, &data_size, h->worder)) {
			return;
		}
		offset += sizeof(ut16);
	}
	if (tot_size < h->pagesize) {
		RzBinSection *s = RZ_NEW0(RzBinSection);
		if (!s) {
			return;
		}
		s->name = rz_str_newf("%s.page.%d.iter.zerofill", sec->name, cur_page);
		s->bits = sec->bits;
		s->perm = sec->perm;
		s->vsize = h->pagesize - tot_size;
		s->vaddr = vaddr;
		rz_list_append(l, s);
	}
}

// TODO: Compressed page
RzList /*<RzBinSection *>*/ *rz_bin_le_get_sections(rz_bin_le_obj_t *bin) {
	RzList *l = rz_list_newf((RzListFree)rz_bin_section_free);
	if (!l) {
		return NULL;
	}
	LE_image_header *h = bin->header;
	ut32 pages_start_off = h->datapage;
	int i;
	for (i = 0; i < h->objcnt; i++) {
		RzBinSection *sec = RZ_NEW0(RzBinSection);
		if (!sec) {
			return l;
		}
		LE_object_entry *entry = &bin->objtbl[i];
		sec->name = rz_str_newf("obj.%d", i + 1);
		sec->vsize = entry->virtual_size;
		sec->vaddr = entry->reloc_base_addr;
		if (entry->flags & O_READABLE) {
			sec->perm |= RZ_PERM_R;
		}
		if (entry->flags & O_WRITABLE) {
			sec->perm |= RZ_PERM_W;
		}
		if (entry->flags & O_EXECUTABLE) {
			sec->perm |= RZ_PERM_X;
		}
		if (entry->flags & O_BIG_BIT) {
			sec->bits = RZ_SYS_BITS_32;
		} else {
			sec->bits = RZ_SYS_BITS_16;
		}
		sec->is_data = entry->flags & O_RESOURCE || !(sec->perm & RZ_PERM_X);
		if (!entry->page_tbl_entries) {
			rz_list_append(l, sec);
		}
		int j;
		ut32 page_size_sum = 0;
		ut32 next_idx = i < h->objcnt - 1 ? bin->objtbl[i + 1].page_tbl_idx - 1 : UT32_MAX;
		ut32 objmaptbloff = h->objmap + bin->headerOff;
		ut64 objpageentrysz = bin->is_le ? sizeof(ut32) : sizeof(LE_object_page_entry);
		for (j = 0; j < entry->page_tbl_entries; j++) {
			LE_object_page_entry page;
			RzBinSection *s = RZ_NEW0(RzBinSection);
			if (!s) {
				rz_bin_section_free(sec);
				return l;
			}
			s->name = rz_str_newf("%s.page.%d", sec->name, j);
			s->is_data = sec->is_data;

			int cur_idx = entry->page_tbl_idx + j - 1;
			ut64 page_entry_off = objpageentrysz * cur_idx + objmaptbloff;
			ut64 offset = page_entry_off;
			if (!(rz_buf_read_le32_offset(bin->buf, &offset, &page.offset) &&
				    rz_buf_read_le16_offset(bin->buf, &offset, &page.size) &&
				    rz_buf_read_le16_offset(bin->buf, &offset, &page.flags))) {
				RZ_LOG_WARN("Cannot read out of bounds page table entry.\n");
				rz_bin_section_free(s);
				break;
			}
			if (cur_idx < next_idx) { // If not true rest of pages will be zeroes
				if (bin->is_le) {
					// Why is it big endian???
					ut32 tmp_offset;
					if (!rz_buf_read_be32_at(bin->buf, page_entry_off, &tmp_offset)) {
						rz_bin_section_free(s);
						break;
					}

					ut64 offset = tmp_offset >> 8;
					s->paddr = (offset - 1) * h->pagesize + pages_start_off;
					if (entry->page_tbl_idx + j == h->mpages) {
						page.size = h->pageshift;
					} else {
						page.size = h->pagesize;
					}
				} else if (page.flags == P_ITERATED) {
					ut64 vaddr = sec->vaddr + page_size_sum;
					__create_iter_sections(l, bin, sec, &page, vaddr, j);
					rz_bin_section_free(s);
					page_size_sum += h->pagesize;
					continue;
				} else if (page.flags == P_COMPRESSED) {
					// TODO
					RZ_LOG_WARN("Compressed page not handled: %s", s->name);
				} else if (page.flags != P_ZEROED) {
					s->paddr = ((ut64)page.offset << h->pageshift) + pages_start_off;
				}
			}
			s->vsize = h->pagesize;
			s->vaddr = sec->vaddr + page_size_sum;
			s->perm = sec->perm;
			s->size = page.size;
			s->bits = sec->bits;
			rz_list_append(l, s);
			page_size_sum += s->vsize;
		}
		if (entry->page_tbl_entries) {
			rz_bin_section_free(sec);
		}
	}
	return l;
}

char *le_get_modname_by_ord(rz_bin_le_obj_t *bin, ut32 ordinal) {
	char *modname = NULL;
	ut64 off = (ut64)bin->header->impmod + bin->headerOff;
	while (ordinal > 0) {
		free(modname);
		modname = le_read_nonnull_str_at(bin->buf, &off);
		ordinal--;
	}
	return modname;
}

RzList /*<RzBinReloc *>*/ *rz_bin_le_get_relocs(rz_bin_le_obj_t *bin) {
	RzList *l = rz_list_newf((RzListFree)free);
	if (!l) {
		return NULL;
	}
	RzList *entries = le_get_entries(bin);
	RzList *sections = rz_bin_le_get_sections(bin);
	LE_image_header *h = bin->header;
	ut64 cur_page = 0;
	const ut64 fix_rec_tbl_off = (ut64)h->frectab + bin->headerOff;
	ut32 tmp_offset;
	if (!rz_buf_read_ble32_at(bin->buf, (ut64)h->fpagetab + bin->headerOff + cur_page * sizeof(ut32), &tmp_offset, h->worder)) {
		rz_list_free(l);
		rz_list_free(entries);
		rz_list_free(sections);
		return NULL;
	}

	ut64 offset = tmp_offset + fix_rec_tbl_off;

	ut32 tmp_end;
	if (!rz_buf_read_ble32_at(bin->buf, (ut64)h->fpagetab + bin->headerOff + (cur_page + 1) * sizeof(ut32), &tmp_end, h->worder)) {
		rz_list_free(l);
		rz_list_free(entries);
		rz_list_free(sections);
		return NULL;
	}
	ut64 end = tmp_end + fix_rec_tbl_off;

	const RzBinSection *cur_section = (RzBinSection *)rz_list_get_n(sections, cur_page);
	ut64 cur_page_offset = cur_section ? cur_section->vaddr : 0;
	while (cur_page < h->mpages) {
		RzBinReloc *rel = RZ_NEW0(RzBinReloc);
		bool rel_appended = false; // whether rel has been appended to l and must not be freed
		if (!rel) {
			break;
		}
		LE_fixup_record_header header;
		if (!(rz_buf_read8_offset(bin->buf, &offset, &header.source) &&
			    rz_buf_read8_offset(bin->buf, &offset, &header.target))) {
			RZ_LOG_WARN("Cannot read out of bounds relocation.\n");
			free(rel);
			break;
		}
		switch (header.source & F_SOURCE_TYPE_MASK) {
		case BYTEFIXUP:
			rel->type = RZ_BIN_RELOC_8;
			break;
		case SELECTOR16:
		case OFFSET16:
			rel->type = RZ_BIN_RELOC_16;
			break;
		case OFFSET32:
		case POINTER32:
		case SELFOFFSET32:
			rel->type = RZ_BIN_RELOC_32;
			break;
		case POINTER48:
			rel->type = 48;
			break;
		}
		ut8 repeat = 0;
		ut16 source = 0;
		if (header.source & F_SOURCE_LIST) {
			if (!rz_buf_read8_at(bin->buf, offset, &repeat)) {
				rz_bin_reloc_free(rel);
				break;
			}
			offset += sizeof(ut8);
		} else {
			if (!rz_buf_read_ble16_at(bin->buf, offset, &source, h->worder)) {
				rz_bin_reloc_free(rel);
				break;
			}
			offset += sizeof(ut16);
		}
		ut32 ordinal;
		if (header.target & F_TARGET_ORD16) {
			ut16 tmp;
			if (!rz_buf_read_ble16_at(bin->buf, offset, &tmp, h->worder)) {
				rz_bin_reloc_free(rel);
				break;
			}
			ordinal = tmp;
			offset += sizeof(ut16);
		} else {
			ut8 tmp;
			if (!rz_buf_read8_at(bin->buf, offset, &tmp)) {
				rz_bin_reloc_free(rel);
				break;
			}
			ordinal = tmp;
			offset += sizeof(ut8);
		}
		switch (header.target & F_TARGET_TYPE_MASK) {
		case INTERNAL:
			if ((ordinal - 1) < bin->header->objcnt) {
				rel->addend = bin->objtbl[ordinal - 1].reloc_base_addr;
				if ((header.source & F_SOURCE_TYPE_MASK) != SELECTOR16) {
					if (header.target & F_TARGET_OFF32) {
						ut32 tmp;
						if (!rz_buf_read_ble32_offset(bin->buf, &offset, &tmp, h->worder)) {
							rz_bin_reloc_free(rel);
							continue;
						}
						rel->addend += tmp;
					} else {
						ut16 tmp;
						if (!rz_buf_read_ble16_offset(bin->buf, &offset, &tmp, h->worder)) {
							rz_bin_reloc_free(rel);
							continue;
						}
						rel->addend += tmp;
					}
				}
			}
			break;
		case IMPORTORD: {
			RzBinImport *imp = RZ_NEW0(RzBinImport);
			if (!imp) {
				break;
			}
			char *mod_name = le_get_modname_by_ord(bin, ordinal);
			if (!mod_name) {
				rz_bin_import_free(imp);
				break;
			}

			if (header.target & F_TARGET_ORD8) {
				ut8 tmp;
				if (!rz_buf_read8_at(bin->buf, offset, &tmp)) {
					rz_bin_import_free(imp);
					break;
				}
				ordinal = tmp;
				offset += sizeof(ut8);
			} else if (header.target & F_TARGET_OFF32) {
				if (!rz_buf_read_ble32_offset(bin->buf, &offset, &ordinal, h->worder)) {
					rz_bin_import_free(imp);
					break;
				}
			} else {
				ut16 tmp;
				if (!rz_buf_read_ble16_offset(bin->buf, &offset, &tmp, h->worder)) {
					rz_bin_import_free(imp);
					break;
				}
				ordinal = tmp;
			}
			imp->name = rz_str_newf("%s.%u", mod_name, ordinal);
			imp->ordinal = ordinal;
			rel->import = imp;
			free(mod_name);
			break;
		}
		case IMPORTNAME: {
			RzBinImport *imp = RZ_NEW0(RzBinImport);
			if (!imp) {
				break;
			}
			ut32 nameoff;
			if (header.target & F_TARGET_OFF32) {
				if (!rz_buf_read_ble32_offset(bin->buf, &offset, &nameoff, h->worder)) {
					rz_bin_import_free(imp);
					break;
				}
			} else {
				ut16 tmp;
				if (!rz_buf_read_ble16_offset(bin->buf, &offset, &tmp, h->worder)) {
					rz_bin_import_free(imp);
					break;
				}
				nameoff = tmp;
			}
			ut64 off = (ut64)h->impproc + nameoff + bin->headerOff;
			char *proc_name = le_read_nonnull_str_at(bin->buf, &off);
			char *mod_name = le_get_modname_by_ord(bin, ordinal);
			imp->name = rz_str_newf("%s.%s", mod_name ? mod_name : "", proc_name ? proc_name : "");
			rel->import = imp;
			break;
		}
		case INTERNALENTRY:
			rel->addend = (ut64)(size_t)rz_list_get_n(entries, ordinal - 1);
			break;
		}
		if (header.target & F_TARGET_ADDITIVE) {
			ut32 additive = 0;
			if (header.target & F_TARGET_ADD32) {
				if (!rz_buf_read_ble32_offset(bin->buf, &offset, &additive, h->worder)) {
					rz_bin_reloc_free(rel);
					break;
				}
			} else {
				ut16 tmp;
				if (!rz_buf_read_ble16_offset(bin->buf, &offset, &tmp, h->worder)) {
					rz_bin_reloc_free(rel);
					break;
				}
				additive = tmp;
			}
			rel->addend += additive;
		}
		if (!repeat) {
			rel->vaddr = cur_page_offset + source;
			rel->paddr = cur_section ? cur_section->paddr + source : 0;
			rz_list_append(l, rel);
			rel_appended = true;
		}

		if (header.target & F_TARGET_CHAIN) {
			ut32 fixupinfo;
			if (!rz_buf_read_ble32_at(bin->buf, cur_page_offset + source, &fixupinfo, h->worder)) {
				break;
			}

			ut64 base_target_address = rel->addend - (fixupinfo & 0xFFFFF);
			do {
				if (!rz_buf_read_ble32_at(bin->buf, cur_page_offset + source, &fixupinfo, h->worder)) {
					break;
				}
				RzBinReloc *new = RZ_NEW0(RzBinReloc);
				*new = *rel;
				new->addend = base_target_address + (fixupinfo & 0xFFFFF);
				rz_list_append(l, new);
				source = (fixupinfo >> 20) & 0xFFF;
			} while (source != 0xFFF);
		}

		while (repeat) {
			ut16 off;
			if (!rz_buf_read_ble16_offset(bin->buf, &offset, &off, h->worder)) {
				break;
			}
			rel->vaddr = cur_page_offset + off;
			rel->paddr = cur_section ? cur_section->paddr + off : 0;
			RzBinReloc *new = RZ_NEW0(RzBinReloc);
			*new = *rel;
			rz_list_append(l, new);
			repeat--;
		}
		while (offset >= end) {
			cur_page++;
			if (cur_page >= h->mpages) {
				break;
			}
			ut64 at = h->fpagetab + bin->headerOff;
			ut32 w0;
			if (!rz_buf_read_ble32_at(bin->buf, at + cur_page * sizeof(ut32), &w0, h->worder)) {
				break;
			}
			ut32 w1;
			if (!rz_buf_read_ble32_at(bin->buf, at + (cur_page + 1) * sizeof(ut32), &w1, h->worder)) {
				break;
			}
			offset = fix_rec_tbl_off + w0;
			end = fix_rec_tbl_off + w1;
			if (offset < end) {
				cur_section = (RzBinSection *)rz_list_get_n(sections, cur_page);
				cur_page_offset = cur_section ? cur_section->vaddr : 0;
			}
		}
		if (!rel_appended) {
			rz_bin_reloc_free(rel);
		}
	}
	rz_list_free(entries);
	rz_list_free(sections);
	return l;
}

static bool read_le_header_aux(rz_bin_le_obj_t *bin, RzBuffer *buf) {
	if (!rz_buf_read_at(buf, bin->headerOff, (ut8 *)bin->header, 4)) {
		return false;
	}
	ut64 offset = bin->headerOff + 4; /* skip magic, border, and worder */
	return rz_buf_read_le32_offset(buf, &offset, &bin->header->level) &&
		rz_buf_read_le16_offset(buf, &offset, &bin->header->cpu) &&
		rz_buf_read_le16_offset(buf, &offset, &bin->header->os) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->ver) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->mflags) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->mpages) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->startobj) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->eip) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->stackobj) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->esp) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->pagesize) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->pageshift) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->fixupsize) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->fixupsum) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->ldrsize) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->ldrsum) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->objtab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->objcnt) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->objmap) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->itermap) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->rsrctab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->rsrccnt) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->restab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->enttab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->dirtab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->dircnt) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->fpagetab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->frectab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->impmod) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->impmodcnt) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->impproc) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->pagesum) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->datapage) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->preload) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->nrestab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->cbnrestab) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->nressum) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->autodata) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->debuginfo) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->debuglen) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->instpreload) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->instdemand) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->heapsize) &&
		rz_buf_read_le32_offset(buf, &offset, &bin->header->stacksize);
}

static rz_bin_le_obj_t *le_init_header(RzBuffer *buf) {
	rz_bin_le_obj_t *bin = RZ_NEW0(rz_bin_le_obj_t);
	if (!bin) {
		return NULL;
	}
	ut8 magic[2];
	rz_buf_read_at(buf, 0, magic, sizeof(magic));
	if (!memcmp(&magic, "MZ", 2)) {
		ut16 tmp;
		if (!rz_buf_read_le16_at(buf, 0x3c, &tmp)) {
			rz_bin_le_free(bin);
			return NULL;
		}
		bin->headerOff = tmp;
	} else {
		bin->headerOff = 0;
	}
	bin->header = RZ_NEW0(LE_image_header);
	if (!bin->header) {
		RZ_LOG_ERROR("le: Failed to allocate memory\n");
		rz_bin_le_free(bin);
		return NULL;
	}

	if (!read_le_header_aux(bin, buf)) {
		RZ_LOG_ERROR("le: Failed to read LE header\n");
		rz_bin_le_free(bin);
		return NULL;
	}

	return bin;
}

void rz_bin_le_free(rz_bin_le_obj_t *bin) {
	rz_return_if_fail(bin);
	free(bin->header);
	free(bin->objtbl);
	free(bin->filename);
	free(bin);
}

rz_bin_le_obj_t *rz_bin_le_new_buf(RzBuffer *buf) {
	rz_bin_le_obj_t *bin = le_init_header(buf);
	if (!bin) {
		return NULL;
	}

	LE_image_header *h = bin->header;
	if (!memcmp("LE", h->magic, 2)) {
		bin->is_le = true;
	}

	if (UT32_MUL_OVFCHK(h->objcnt, sizeof(LE_object_entry))) {
		RZ_LOG_ERROR("le: overflow on objcnt\n");
		rz_bin_le_free(bin);
		return NULL;
	}

	bin->type = le_get_module_type(bin);
	bin->cpu = le_get_cpu_type(bin);
	bin->os = le_get_os_type(bin);
	bin->arch = le_get_arch(bin);
	bin->objtbl = calloc(h->objcnt, sizeof(LE_object_entry));
	if (!bin->objtbl) {
		rz_bin_le_free(bin);
		return NULL;
	}
	ut64 offset = (ut64)bin->headerOff + h->restab;
	bin->filename = le_read_nonnull_str_at(buf, &offset);
	offset = (ut64)bin->headerOff + h->objtab;
	for (ut32 i = 0; i < h->objcnt; i++) {
		LE_object_entry *le_obj_entry = bin->objtbl + i;
		if (!rz_buf_read_le32_offset(buf, &offset, &le_obj_entry->virtual_size) ||
			!rz_buf_read_le32_offset(buf, &offset, &le_obj_entry->reloc_base_addr) ||
			!rz_buf_read_le32_offset(buf, &offset, &le_obj_entry->flags) ||
			!rz_buf_read_le32_offset(buf, &offset, &le_obj_entry->page_tbl_idx) ||
			!rz_buf_read_le32_offset(buf, &offset, &le_obj_entry->page_tbl_entries) ||
			!rz_buf_read_le32_offset(buf, &offset, &le_obj_entry->reserved)) {
			rz_bin_le_free(bin);
			return NULL;
		}
	}
	bin->buf = buf;
	return bin;
}
