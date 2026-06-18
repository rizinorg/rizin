// SPDX-FileCopyrightText: 2025 godcodehunter
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Parser for MediaTek md1img container format.
 *
 * The md1img format is a simple section-based container used by MediaTek
 * to package modem firmware components: md1rom (GFH firmware image),
 * debug info (CATI format), DSP images, certificates, etc.
 *
 * Each section has a header with magic 0x58881688, a name, data size,
 * memory address, and other metadata, followed by the section data
 * and alignment padding.
 *
 * The md1rom section is parsed internally using the mtk GFH parser to
 * provide proper base address, entry points, and code/header sections.
 * Debug symbols are extracted from the CATI-format dbginfo section.
 *
 * References:
 * - https://github.com/nccgroup/mtk_bp/blob/main/mtk_structs/mtk_img.ksy (md1img)
 * - https://github.com/nccgroup/mtk_bp/blob/main/mtk_structs/mtk_dbg_info.ksy (CATI)
 */
#include "md1img.h"

// --- CATI debug info parsing ---

static void mtk_dbg_symbol_free(MtkDbgSymbol *sym) {
	if (sym) {
		free(sym->name);
		free(sym);
	}
}

/**
 * \brief Parse symbols from a single CATI debug entry.
 *
 * The debug entry format (after "CATI" magic + type):
 *   unk3(u32), unk_str1(strz), unk_str2(strz), unk_str3(strz), date_str(strz),
 *   symbols_start(u32), files_start(u32),
 *   symbol_entries: [strz name, u32 addr1, u32 addr2] ... until empty name
 */
static bool md1img_parse_cati_debug(RzBuffer *b, RzPVector /*<MtkDbgSymbol *>*/ *symbols) {
	// Skip unk3
	rz_buf_seek(b, 4, RZ_BUF_CUR);

	// Skip 4 strz fields (unk_str1, unk_str2, unk_str3, date_str)
	for (int i = 0; i < 4; i++) {
		ut64 len = rz_buf_read_string(b, NULL);
		if (len == 0) {
			return false;
		}
	}

	// Skip symbols_start and files_start
	rz_buf_seek(b, 8, RZ_BUF_CUR);

	// Parse symbol entries (limit guards against corrupted/missing terminator)
	int count = 0;
	while (count < 500000) {
		char *name = NULL;
		ut64 len = rz_buf_read_string(b, &name);
		if (len == 0 || !name) {
			free(name);
			break;
		}
		// Empty string = terminator
		if (name[0] == '\0') {
			free(name);
			break;
		}

		ut32 addr1 = 0, addr2 = 0;
		if (!rz_buf_read_le32(b, &addr1) || !rz_buf_read_le32(b, &addr2)) {
			free(name);
			break;
		}

		MtkDbgSymbol *sym = RZ_NEW0(MtkDbgSymbol);
		if (!sym) {
			free(name);
			break;
		}
		sym->name = name;
		sym->addr = addr1;
		// For corrupted entries
		sym->size = (addr2 > addr1) ? (addr2 - addr1) : 0;
		rz_pvector_push(symbols, sym);
		count++;
	}

	return count > 0;
}

/**
 * \brief Parse a CATI container wrapping one or more debug entries.
 */
static bool md1img_parse_cati_container(RzBuffer *b, RzPVector /*<MtkDbgSymbol *>*/ *symbols) {
	// unk1(u32), size(u32)
	ut32 unk1 = 0, container_size = 0;
	if (!rz_buf_read_le32(b, &unk1) || !rz_buf_read_le32(b, &container_size)) {
		return false;
	}

	// 0x10 = CATI header size (magic[4] + type[4] + unk1[4] + size[4])
	if (container_size < 0x10) {
		return false;
	}

	// The nested entries are within (container_size - 0x10) bytes
	ut64 entries_end = rz_buf_tell(b) + (container_size - 0x10);
	ut64 buf_size = rz_buf_size(b);
	// Clamp to actual buffer size in case container_size is corrupted
	if (entries_end > buf_size) {
		entries_end = buf_size;
	}

	// Parse nested CATI headers
	while (rz_buf_tell(b) + 8 <= entries_end) {
		ut8 magic[MTK_CATI_MAGIC_SIZE];
		if (rz_buf_read(b, magic, MTK_CATI_MAGIC_SIZE) != MTK_CATI_MAGIC_SIZE ||
			memcmp(magic, MTK_CATI_MAGIC, MTK_CATI_MAGIC_SIZE) != 0) {
			break;
		}

		ut32 cati_type = 0;
		if (!rz_buf_read_le32(b, &cati_type)) {
			break;
		}

		if (cati_type != MTK_CATI_TYPE_DEBUG && cati_type != MTK_CATI_TYPE_DEBUG_DSP) {
			break;
		}
		md1img_parse_cati_debug(b, symbols);
	}

	return rz_pvector_len(symbols) > 0;
}

/**
 * \brief Parse a CATI debug info buffer and extract symbols.
 */
static RzPVector /*<MtkDbgSymbol *>*/ *md1img_parse_dbginfo(RzBuffer *b) {
	rz_return_val_if_fail(b, NULL);

	ut8 magic[MTK_CATI_MAGIC_SIZE];
	if (rz_buf_read_at(b, 0, magic, MTK_CATI_MAGIC_SIZE) != MTK_CATI_MAGIC_SIZE) {
		return NULL;
	}
	if (memcmp(magic, MTK_CATI_MAGIC, MTK_CATI_MAGIC_SIZE) != 0) {
		return NULL;
	}

	rz_buf_seek(b, 0 + MTK_CATI_MAGIC_SIZE, RZ_BUF_SET);

	ut32 cati_type = 0;
	if (!rz_buf_read_le32(b, &cati_type)) {
		return NULL;
	}

	RzPVector *symbols = rz_pvector_new((RzPVectorFree)mtk_dbg_symbol_free);
	if (!symbols) {
		return NULL;
	}

	bool ok = false;
	if (cati_type == MTK_CATI_TYPE_CONTAINER) {
		ok = md1img_parse_cati_container(b, symbols);
	} else if (cati_type == MTK_CATI_TYPE_DEBUG || cati_type == MTK_CATI_TYPE_DEBUG_DSP) {
		ok = md1img_parse_cati_debug(b, symbols);
	}

	if (!ok || rz_pvector_len(symbols) == 0) {
		rz_pvector_free(symbols);
		return NULL;
	}

	return symbols;
}

// --- md1img container parsing ---

static bool md1img_read_section_hdr(RzBuffer *b, ut64 section_start, Md1imgSection *sec) {
	ut64 offset = section_start;

	// Check magic
	ut8 magic[MD1IMG_MAGIC_SIZE];
	if (!rz_buf_read_offset(b, &offset, magic, MD1IMG_MAGIC_SIZE)) {
		return false;
	}
	if (memcmp(magic, MD1IMG_MAGIC, MD1IMG_MAGIC_SIZE) != 0) {
		return false;
	}

	// Read dsize
	if (!rz_buf_read_le32_offset(b, &offset, &sec->dsize)) {
		return false;
	}

	// Read name (32 bytes, null-terminated)
	if (!rz_buf_read_offset(b, &offset, (ut8 *)sec->name, MD1IMG_NAME_SIZE)) {
		return false;
	}
	sec->name[MD1IMG_NAME_SIZE - 1] = '\0';

	// Read maddr and mode
	if (!rz_buf_read_le32_offset(b, &offset, &sec->maddr) ||
		!rz_buf_read_le32_offset(b, &offset, &sec->mode)) {
		return false;
	}

	// Verify ext_magic
	ut8 ext_magic[MD1IMG_EXT_MAGIC_SIZE];
	if (!rz_buf_read_offset(b, &offset, ext_magic, MD1IMG_EXT_MAGIC_SIZE)) {
		return false;
	}
	if (memcmp(ext_magic, MD1IMG_EXT_MAGIC, MD1IMG_EXT_MAGIC_SIZE) != 0) {
		return false;
	}

	// Read remaining header fields
	if (!rz_buf_read_le32_offset(b, &offset, &sec->hdr_size) ||
		!rz_buf_read_le32_offset(b, &offset, &sec->hdr_version) ||
		!rz_buf_read_le32_offset(b, &offset, &sec->img_type) ||
		!rz_buf_read_le32_offset(b, &offset, &sec->img_list_end) ||
		!rz_buf_read_le32_offset(b, &offset, &sec->align_size) ||
		!rz_buf_read_le32_offset(b, &offset, &sec->dsize_extend) ||
		!rz_buf_read_le32_offset(b, &offset, &sec->maddr_extend)) {
		return false;
	}

	if (sec->hdr_size < MD1IMG_MIN_HDR_SIZE) {
		return false;
	}

	sec->data_offset = section_start + sec->hdr_size;
	return true;
}

RZ_IPI bool md1img_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);

	if (rz_buf_size(b) < MD1IMG_MIN_HDR_SIZE) {
		return false;
	}

	ut8 magic[MD1IMG_MAGIC_SIZE];
	if (rz_buf_read_at(b, 0, magic, MD1IMG_MAGIC_SIZE) != MD1IMG_MAGIC_SIZE) {
		return false;
	}
	return memcmp(magic, MD1IMG_MAGIC, MD1IMG_MAGIC_SIZE) == 0;
}

RZ_IPI bool md1img_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *b, Sdb *sdb) {
	rz_return_val_if_fail(bf && obj && b, false);

	Md1imgObj *md1 = RZ_NEW0(Md1imgObj);
	if (!md1) {
		return false;
	}

	md1->sections = rz_vector_new(sizeof(Md1imgSection), NULL, NULL);
	md1->vfiles = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	md1->md1rom_idx = -1;

	if (!md1->sections || !md1->vfiles) {
		rz_vector_free(md1->sections);
		rz_pvector_free(md1->vfiles);
		free(md1);
		return false;
	}

	ut64 buf_size = rz_buf_size(b);
	ut64 offset = 0;
	int count = 0;

	// Limit iteration count as a safeguard against corrupted headers
	while (offset + MD1IMG_MIN_HDR_SIZE <= buf_size && count < 256) {
		Md1imgSection sec = { 0 };
		if (!md1img_read_section_hdr(b, offset, &sec)) {
			break;
		}

		// Validate that data fits in the buffer
		if (sec.data_offset + sec.dsize > buf_size) {
			RZ_LOG_WARN("md1img: section '%s' data exceeds file size, truncating\n", sec.name);
			sec.dsize = buf_size - sec.data_offset;
		}

		int sec_idx = rz_vector_len(md1->sections);
		rz_vector_push(md1->sections, &sec);

		// Create a virtual file for this section's data
		RzBuffer *vbuf = rz_buf_new_slice(b, sec.data_offset, sec.dsize);
		if (vbuf) {
			RzBinVirtualFile *vfile = RZ_NEW0(RzBinVirtualFile);
			if (vfile) {
				vfile->buf = vbuf;
				vfile->buf_owned = true;
				vfile->name = rz_str_dup(sec.name);
				rz_pvector_push(md1->vfiles, vfile);
			} else {
				rz_buf_free(vbuf);
			}

			// Parse md1rom section with mtk GFH parser
			if (rz_str_casestr(sec.name, "md1rom") && md1->md1rom_idx < 0) {
				md1->md1rom_idx = sec_idx;
				// Search for GFH magic within md1rom data (may not be at offset 0)
				ut64 gfh_off = 0;
				ut8 magic_buf[4];
				while (gfh_off + MTK_GFH_MIN_FILE_SIZE <= sec.dsize) {
					if (rz_buf_read_at(vbuf, gfh_off, magic_buf, 4) != 4) {
						break;
					}
					ut32 magic_val = rz_read_le32(magic_buf);
					if ((magic_val & MTK_GFH_MAGIC_MASK) == MTK_GFH_MAGIC) {
						break;
					}
					gfh_off += 4;
				}
				if (gfh_off + MTK_GFH_MIN_FILE_SIZE <= sec.dsize) {
					RzBuffer *gfh_buf = rz_buf_new_slice(vbuf, gfh_off, sec.dsize - gfh_off);
					if (gfh_buf) {
						md1->mtk = mtk_obj_new(gfh_buf);
						rz_buf_free(gfh_buf);
					}
					if (md1->mtk) {
						md1->gfh_offset = gfh_off;
						RZ_LOG_INFO("md1img: parsed GFH from '%s' at offset 0x%" PFMT64x " (load_addr=0x%x, entry=0x%x)\n",
							sec.name, gfh_off, md1->mtk->file_info.load_addr, md1->mtk->entry_vaddr);
					}
				}
			}

			// Parse CATI debug info from dbginfo sections
			if (rz_str_casestr(sec.name, "dbginfo") && sec.dsize > MTK_CATI_MAGIC_SIZE) {
				RzPVector *syms = md1img_parse_dbginfo(vbuf);
				// Try LZMA alone decompression if raw CATI parsing failed (dbginfo may be LZMA-compressed)
				if (!syms) {
					RzBuffer *decompressed = rz_buf_new_empty(0);
					if (decompressed && rz_lzma_alone_dec_buf(vbuf, decompressed, 4096)) {
						syms = md1img_parse_dbginfo(decompressed);
					}
					rz_buf_free(decompressed);
				}
				if (syms) {
					if (!md1->dbg_symbols) {
						md1->dbg_symbols = syms;
					} else {
						// Merge symbols from additional dbginfo sections
						void **it;
						rz_pvector_foreach (syms, it) {
							rz_pvector_push(md1->dbg_symbols, *it);
						}
						// Disown elements before freeing (ownership transferred)
						syms->v.free = NULL;
						rz_pvector_free(syms);
					}
					RZ_LOG_INFO("md1img: loaded debug symbols from '%s'\n", sec.name);
				}
			}
		}

		// Advance to next section: data_offset + dsize + alignment padding
		ut64 data_end = sec.data_offset + sec.dsize;
		ut64 remainder = sec.align_size > 0 ? sec.dsize % sec.align_size : 0;
		if (remainder > 0) {
			offset = data_end + (sec.align_size - remainder);
		} else {
			offset = data_end;
		}
		count++;
	}

	if (offset < buf_size) {
		RZ_LOG_WARN("md1img: %" PFMT64u " trailing bytes after last section header\n", buf_size - offset);
	}

	if (rz_vector_len(md1->sections) == 0) {
		rz_vector_free(md1->sections);
		rz_pvector_free(md1->vfiles);
		free(md1);
		return false;
	}

	obj->bin_obj = md1;
	return true;
}

RZ_IPI void md1img_destroy(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return;
	}
	Md1imgObj *md1 = bf->o->bin_obj;
	rz_vector_free(md1->sections);
	rz_pvector_free(md1->vfiles);
	rz_pvector_free(md1->dbg_symbols);
	mtk_obj_free(md1->mtk);
	free(md1);
}

RZ_IPI RzBinInfo *md1img_info(RzBinFile *bf) {
	RzBinInfo *info = RZ_NEW0(RzBinInfo);
	if (!info) {
		return NULL;
	}

	info->file = bf->file ? rz_str_dup(bf->file) : NULL;
	info->type = rz_str_dup("MediaTek md1img container");
	info->machine = rz_str_dup("MediaTek Modem");
	info->arch = rz_str_dup("mips");
	info->cpu = rz_str_dup("nanomips");
	info->rclass = rz_str_dup("firmware");
	info->subsystem = rz_str_dup("modem");
	info->has_va = true;
	info->bits = 32;
	info->big_endian = false;

	return info;
}

RZ_IPI ut64 md1img_baddr(RzBinFile *bf) {
	return MTK_MODEM_BADDR;
}

RZ_IPI RzPVector /*<RzBinAddr *>*/ *md1img_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Md1imgObj *md1 = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}

	if (md1->mtk) {
		RzBinAddr *entry = RZ_NEW0(RzBinAddr);
		if (entry) {
			entry->vaddr = md1img_baddr(bf) + (md1->mtk->file_info.jump_offset - md1->mtk->code_offset);
			entry->paddr = md1->gfh_offset + md1->mtk->file_info.jump_offset;
			rz_pvector_push(ret, entry);
		}
	}

	return ret;
}

RZ_IPI RzPVector /*<RzBinVirtualFile *>*/ *md1img_virtual_files(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Md1imgObj *md1 = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!ret) {
		return NULL;
	}

	void **it;
	rz_pvector_foreach (md1->vfiles, it) {
		RzBinVirtualFile *vf = *it;
		RzBinVirtualFile *clone = rz_bin_virtual_file_clone(vf);
		if (clone) {
			rz_pvector_push(ret, clone);
		}
	}

	return ret;
}

RZ_IPI RzPVector /*<RzBinMap *>*/ *md1img_maps(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Md1imgObj *md1 = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	// Only map the md1rom section into the virtual address space.
	// Other sections (md1dsp, md1drdi, certs, etc.) belong to different
	// processors or address spaces and would conflict with md1rom if mapped.
	// They remain accessible as virtual files for raw data viewing.
	if (md1->md1rom_idx >= 0) {
		Md1imgSection *sec = rz_vector_index_ptr(md1->sections, md1->md1rom_idx);
		if (md1->mtk) {
			ut64 paddr = md1->gfh_offset + md1->mtk->code_offset;
			mtk_append_maps(md1->mtk, paddr, sec->name, ret);
		} else {
			RzBinMap *map = RZ_NEW0(RzBinMap);
			if (map) {
				map->name = rz_str_dup(sec->name);
				map->vfile_name = rz_str_dup(sec->name);
				map->paddr = 0;
				map->psize = sec->dsize;
				map->vaddr = sec->maddr;
				map->vsize = sec->dsize;
				map->perm = RZ_PERM_RX;
				rz_pvector_push(ret, map);
			}
		}
	}

	return ret;
}

RZ_IPI RzPVector /*<RzBinSection *>*/ *md1img_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Md1imgObj *md1 = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	if (md1->mtk && md1->md1rom_idx >= 0 && md1->mtk->code_size > 0) {
		Md1imgSection *sec = rz_vector_index_ptr(md1->sections, md1->md1rom_idx);
		RzBinSection *code = RZ_NEW0(RzBinSection);
		if (code) {
			code->name = rz_str_newf("%s.code", sec->name);
			code->paddr = md1->gfh_offset + md1->mtk->code_offset;
			code->size = md1->mtk->code_size;
			code->vsize = md1->mtk->code_size;
			code->vaddr = md1img_baddr(bf);
			code->perm = RZ_PERM_RX;
			rz_pvector_push(ret, code);
		}
	}

	return ret;
}

RZ_IPI RzPVector /*<RzBinSymbol *>*/ *md1img_symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Md1imgObj *md1 = bf->o->bin_obj;
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	if (!md1->dbg_symbols) {
		return ret;
	}

	void **it;
	rz_pvector_foreach (md1->dbg_symbols, it) {
		MtkDbgSymbol *dbg = *it;
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			continue;
		}
		sym->name = rz_str_dup(dbg->name);
		sym->vaddr = dbg->addr;
		sym->size = dbg->size;
		sym->type = RZ_BIN_TYPE_FUNC_STR;

		// Compute paddr for symbols within mapped regions (kseg0 or kuseg).
		if (md1->mtk) {
			ut64 code_paddr = md1->gfh_offset + md1->mtk->code_offset;
			ut64 kseg0_end = md1img_baddr(bf) + md1->mtk->code_size;
			ut64 kuseg_base = md1->mtk->file_info.load_addr + md1->mtk->code_offset;
			ut64 kuseg_end = kuseg_base + md1->mtk->code_size;
			if (dbg->addr >= md1img_baddr(bf) && dbg->addr < kseg0_end) {
				sym->paddr = code_paddr + (dbg->addr - md1img_baddr(bf));
			} else if (dbg->addr >= kuseg_base && dbg->addr < kuseg_end) {
				sym->paddr = code_paddr + (dbg->addr - kuseg_base);
			}
		}

		rz_pvector_push(ret, sym);
	}

	return ret;
}

RZ_IPI RzPVector /*<RzBinString *>*/ *md1img_strings(RzBinFile *bf) {
	// Container format: suppress string scanning on the raw container buffer.
	// Strings from the firmware payload are accessible via the mapped vfiles.
	return rz_pvector_new(NULL);
}

RZ_IPI RzStructuredData *md1img_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	Md1imgObj *md1 = bf->o->bin_obj;
	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	rz_structured_data_map_add_unsigned(root, "num_sections", rz_vector_len(md1->sections), false);

	RzStructuredData *secs = rz_structured_data_map_add_array(root, "sections");
	if (secs) {
		Md1imgSection *sec;
		rz_vector_foreach (md1->sections, sec) {
			RzStructuredData *s = rz_structured_data_array_add_map(secs);
			if (!s) {
				continue;
			}
			rz_structured_data_map_add_string(s, "name", sec->name);
			rz_structured_data_map_add_unsigned(s, "data_size", sec->dsize, true);
			rz_structured_data_map_add_unsigned(s, "data_offset", sec->data_offset, true);
			rz_structured_data_map_add_unsigned(s, "maddr", sec->maddr, true);
			rz_structured_data_map_add_unsigned(s, "mode", sec->mode, true);
			rz_structured_data_map_add_unsigned(s, "hdr_size", sec->hdr_size, true);
			rz_structured_data_map_add_unsigned(s, "hdr_version", sec->hdr_version, true);
			rz_structured_data_map_add_unsigned(s, "img_type", sec->img_type, true);
			rz_structured_data_map_add_unsigned(s, "img_list_end", sec->img_list_end, true);
			rz_structured_data_map_add_unsigned(s, "align_size", sec->align_size, true);
		}
	}

	// GFH structure from md1rom section
	if (md1->mtk) {
		MtkObj *mtk = md1->mtk;
		RzStructuredData *gfh = rz_structured_data_map_add_map(root, "gfh_file_info");
		if (gfh) {
			rz_structured_data_map_add_unsigned(gfh, "magic_version", mtk->first_common.magic_version, true);
			rz_structured_data_map_add_unsigned(gfh, "header_block_size", mtk->first_common.size, false);
			rz_structured_data_map_add_string(gfh, "header_type", mtk_gfh_type_str(mtk->first_common.type));
			rz_structured_data_map_add_string(gfh, "name", mtk->file_info.name);
			rz_structured_data_map_add_unsigned(gfh, "file_type", mtk->file_info.file_type, true);
			rz_structured_data_map_add_unsigned(gfh, "flash_type", mtk->file_info.flash_type, true);
			rz_structured_data_map_add_unsigned(gfh, "sig_type", mtk->file_info.sig_type, true);
			rz_structured_data_map_add_unsigned(gfh, "load_addr", mtk->file_info.load_addr, true);
			rz_structured_data_map_add_unsigned(gfh, "total_size", mtk->file_info.total_size, true);
			rz_structured_data_map_add_unsigned(gfh, "max_size", mtk->file_info.max_size, true);
			rz_structured_data_map_add_unsigned(gfh, "hdr_size", mtk->file_info.hdr_size, true);
			rz_structured_data_map_add_unsigned(gfh, "sig_size", mtk->file_info.sig_size, true);
			rz_structured_data_map_add_unsigned(gfh, "jump_offset", mtk->file_info.jump_offset, true);
			rz_structured_data_map_add_unsigned(gfh, "entry_point", mtk->entry_vaddr, true);
		}

		if (rz_vector_len(mtk->extra_headers) > 0) {
			RzStructuredData *hdrs = rz_structured_data_map_add_array(root, "gfh_headers");
			if (hdrs) {
				MtkGfhHeader *extra;
				rz_vector_foreach (mtk->extra_headers, extra) {
					RzStructuredData *h = rz_structured_data_array_add_map(hdrs);
					if (!h) {
						continue;
					}
					rz_structured_data_map_add_unsigned(h, "file_offset", extra->file_offset, true);
					rz_structured_data_map_add_string(h, "type", mtk_gfh_type_str(extra->common.type));
					rz_structured_data_map_add_unsigned(h, "type_id", extra->common.type, true);
					rz_structured_data_map_add_unsigned(h, "size", extra->common.size, false);
				}
			}
		}
	}

	if (md1->dbg_symbols) {
		rz_structured_data_map_add_unsigned(root, "debug_symbols_count",
			rz_pvector_len(md1->dbg_symbols), false);
	}

	return root;
}
