// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 keegan
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_io.h>
#include "../format/mach0/dyldcache.h"
#include "objc/mach0_classes.h"

#define RZ_DYLDCACHE_VFILE_NAME_REBASED "rebased"

static ut64 bin_obj_va2pa(ut64 p, ut32 *offset, ut32 *left, RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return 0;
	}
	RzDyldCache *cache = (RzDyldCache *)((struct MACH0_(obj_t) *)bf->o->bin_obj)->user;
	if (!cache) {
		return 0;
	}
	return rz_dyldcache_va2pa(cache, p, offset, left);
}

static struct MACH0_(obj_t) * bin_to_mach0(RzBinFile *bf, RzDyldBinImage *bin) {
	if (!bin || !bf) {
		return NULL;
	}

	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	RzBuffer *buf = rz_buf_new_slice(cache->buf, bin->hdr_offset, rz_buf_size(cache->buf) - bin->hdr_offset);
	if (!buf) {
		return NULL;
	}

	struct MACH0_(opts_t) opts;
	MACH0_(opts_set_default)
	(&opts, bf);
	opts.header_at = bin->header_at - bin->hdr_offset;
	opts.symbols_off = bin->symbols_off;

	struct MACH0_(obj_t) *mach0 = MACH0_(new_buf)(buf, &opts);
	if (!mach0) {
		return NULL;
	}

	mach0->user = cache;
	mach0->va2pa = &bin_obj_va2pa;

	rz_buf_free(buf);

	return mach0;
}

static bool check_buffer(RzBuffer *buf) {
	if (rz_buf_size(buf) < 32) {
		return false;
	}

	char hdr[17] = { 0 };
	int rzhdr = rz_buf_read_at(buf, 0, (ut8 *)&hdr, sizeof(hdr) - 1);
	if (rzhdr != sizeof(hdr) - 1) {
		return false;
	}

	return rz_dyldcache_check_magic(hdr);
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	RzDyldCache *cache = rz_dyldcache_new_buf(buf);
	if (!cache) {
		return false;
	}
	obj->bin_obj = cache;
	return true;
}

static RzList /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	RzBinAddr *ptr = NULL;
	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		rz_list_append(ret, ptr);
	}
	return ret;
}

static RzBinInfo *info(RzBinFile *bf) {
	RzBinInfo *ret = NULL;

	if (!bf || !bf->o) {
		return NULL;
	}

	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	bool big_endian = 0;
	if (!(ret = RZ_NEW0(RzBinInfo))) {
		return NULL;
	}
	ret->file = strdup(bf->file);
	ret->bclass = strdup("dyldcache");
	ret->os = strdup("Darwin"); // TODO: actual OS info is available. See the platform member of struct dyld_cache_header in dyld source.
	if (strstr(cache->hdr->magic, "x86_64")) {
		ret->arch = strdup("x86");
		ret->bits = 64;
	} else {
		ret->arch = strdup("arm");
		ret->bits = strstr(cache->hdr->magic, "arm64") ? 64 : 32;
	}
	ret->machine = strdup(ret->arch);
	ret->subsystem = strdup("xnu");
	ret->type = strdup("library-cache");
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 baddr(RzBinFile *bf) {
	// XXX hardcoded
	return 0x180000000;
}

void symbols_from_bin(RzDyldCache *cache, RzList /*<RzBinSymbol *>*/ *ret, RzBinFile *bf, RzDyldBinImage *bin, SetU *hash) {
	struct MACH0_(obj_t) *mach0 = bin_to_mach0(bf, bin);
	if (!mach0) {
		return;
	}

	const struct symbol_t *symbols = MACH0_(get_symbols)(mach0);
	if (!symbols) {
		return;
	}
	int i;
	for (i = 0; !symbols[i].last; i++) {
		if (!symbols[i].name || !symbols[i].name[0] || symbols[i].addr < 100) {
			continue;
		}
		if (strstr(symbols[i].name, "<redacted>")) {
			continue;
		}
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			break;
		}
		sym->name = strdup(symbols[i].name);
		sym->vaddr = symbols[i].addr;
		sym->forwarder = "NONE";
		sym->bind = (symbols[i].type == RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL) ? RZ_BIN_BIND_LOCAL_STR : RZ_BIN_BIND_GLOBAL_STR;
		sym->type = RZ_BIN_TYPE_FUNC_STR;
		sym->paddr = symbols[i].offset + bf->o->boffset;
		sym->size = symbols[i].size;
		sym->ordinal = i;

		set_u_add(hash, sym->vaddr);
		rz_list_append(ret, sym);
	}
	MACH0_(mach0_free)
	(mach0);
}

static bool __is_data_section(const char *name) {
	if (strstr(name, "_cstring")) {
		return true;
	}
	if (strstr(name, "_os_log")) {
		return true;
	}
	if (strstr(name, "_objc_methname")) {
		return true;
	}
	if (strstr(name, "_objc_classname")) {
		return true;
	}
	if (strstr(name, "_objc_methtype")) {
		return true;
	}
	return false;
}

static void sections_from_bin(RzList /*<RzBinSection *>*/ *ret, RzBinFile *bf, RzDyldBinImage *bin) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return;
	}

	struct MACH0_(obj_t) *mach0 = bin_to_mach0(bf, bin);
	if (!mach0) {
		return;
	}

	struct section_t *sections = NULL;
	if (!(sections = MACH0_(get_sections)(mach0))) {
		return;
	}

	int i;
	for (i = 0; !sections[i].last; i++) {
		RzBinSection *ptr = RZ_NEW0(RzBinSection);
		if (!ptr) {
			break;
		}
		if (bin->file) {
			ptr->name = rz_str_newf("%s.%s", bin->file, (char *)sections[i].name);
		} else {
			ptr->name = rz_str_newf("%s", (char *)sections[i].name);
		}
		if (strstr(ptr->name, "la_symbol_ptr")) {
			int len = sections[i].size / 8;
			ptr->format = rz_str_newf("Cd %d %d", 8, len);
		}
		ptr->is_data = __is_data_section(ptr->name);
		ptr->size = sections[i].size;
		ptr->vsize = sections[i].vsize;
		ptr->vaddr = sections[i].addr;
		ptr->paddr = rz_dyldcache_va2pa(cache, sections[i].addr, NULL, NULL);
		if (!ptr->vaddr) {
			ptr->vaddr = ptr->paddr;
		}
		ptr->perm = sections[i].perm;
		rz_list_append(ret, ptr);
	}
	free(sections);
	MACH0_(mach0_free)
	(mach0);
}

static RzList /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzList *ret = rz_list_newf((RzListFree)rz_bin_virtual_file_free);
	if (!ret) {
		return NULL;
	}
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (rz_dyldcache_needs_rebasing(cache)) {
		RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
		if (!vf) {
			return ret;
		}
		vf->buf = rz_dyldcache_new_rebasing_buf(cache);
		vf->buf_owned = true;
		vf->name = strdup(RZ_DYLDCACHE_VFILE_NAME_REBASED);
		rz_list_push(ret, vf);
	}
	return ret;
}

static int prot2perm(int x) {
	int r = 0;
	if (x & 1) {
		r |= 4;
	}
	if (x & 2) {
		r |= 2;
	}
	if (x & 4) {
		r |= 1;
	}
	return r;
}

static RzList /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}
	RzList *ret = rz_list_newf((RzListFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}
	ut64 slide = rz_dyldcache_get_slide(cache);
	for (ut32 i = 0; i < cache->n_maps; i++) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			rz_list_free(ret);
			return NULL;
		}
		map->name = rz_str_newf("cache_map.%d", i);
		map->paddr = cache->maps[i].fileOffset;
		map->psize = cache->maps[i].size;
		map->vsize = map->psize;
		map->vaddr = cache->maps[i].address + slide;
		map->perm = prot2perm(cache->maps[i].initProt);
		if (rz_dyldcache_range_needs_rebasing(cache, map->paddr, map->psize)) {
			map->vfile_name = strdup(RZ_DYLDCACHE_VFILE_NAME_REBASED);
		}
		rz_list_append(ret, map);
	}
	return ret;
}

static RzList /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}
	RzList *ret = rz_list_newf((RzListFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}
	RzListIter *iter;
	RzDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		sections_from_bin(ret, bf, bin);
	}
	ut64 slide = rz_dyldcache_get_slide(cache);
	if (slide) {
		RzBinSection *section;
		rz_list_foreach (ret, iter, section) {
			section->vaddr += slide;
		}
	}
	return ret;
}

static RzList /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	RzList *ret = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	RzListIter *iter;
	RzDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		SetU *hash = set_u_new();
		if (!hash) {
			rz_list_free(ret);
			return NULL;
		}
		symbols_from_bin(cache, ret, bf, bin, hash);
		rz_dyldcache_symbols_from_locsym(cache, bin, ret, hash);
		set_u_free(hash);
	}

	ut64 slide = rz_dyldcache_get_slide(cache);
	if (slide) {
		RzBinSymbol *sym;
		rz_list_foreach (ret, iter, sym) {
			sym->vaddr += slide;
		}
	}

	return ret;
}

static void destroy(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	rz_dyldcache_free(cache);
}

static RzList /*<RzBinClass *>*/ *classes(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	RzList *ret = rz_list_newf(free);
	if (!ret) {
		return NULL;
	}

	if (!cache->objc_opt_info_loaded) {
		cache->oi = rz_dyldcache_get_objc_opt_info(bf, cache);
		cache->objc_opt_info_loaded = true;
	}

	RzListIter *iter;
	RzDyldBinImage *bin;

	RzBuffer *buf = bf->buf;
	RzBuffer *owned_buf = NULL;
	if (rz_dyldcache_needs_rebasing(cache)) {
		owned_buf = rz_dyldcache_new_rebasing_buf(cache);
		if (!owned_buf) {
			goto beach;
		}
		buf = owned_buf;
	}

	ut32 num_of_unnamed_class = 0;
	rz_list_foreach (cache->bins, iter, bin) {
		struct MACH0_(obj_t) *mach0 = bin_to_mach0(bf, bin);
		if (!mach0) {
			goto beach;
		}

		struct section_t *sections = NULL;
		if (!(sections = MACH0_(get_sections)(mach0))) {
			MACH0_(mach0_free)
			(mach0);
			goto beach;
		}

		int i;
		for (i = 0; !sections[i].last; i++) {
			if (sections[i].size == 0) {
				continue;
			}

			bool is_classlist = strstr(sections[i].name, "__objc_classlist");
			bool is_catlist = strstr(sections[i].name, "__objc_catlist");

			if (!is_classlist && !is_catlist) {
				continue;
			}

			ut8 *pointers = malloc(sections[i].size);
			if (!pointers) {
				continue;
			}

			ut64 offset = rz_dyldcache_va2pa(cache, sections[i].addr, NULL, NULL);
			if (rz_buf_read_at(buf, offset, pointers, sections[i].size) < sections[i].size) {
				RZ_FREE(pointers);
				continue;
			}
			ut8 *cursor = pointers;
			ut8 *pointers_end = pointers + sections[i].size;

			for (; cursor < pointers_end; cursor += 8) {
				if ((cursor + 8) > pointers_end) {
					MACH0_(mach0_free)
					(mach0);
					goto beach;
				}
				ut64 pointer_to_class = rz_read_le64(cursor);

				RzBinClass *klass;
				if (!(klass = RZ_NEW0(RzBinClass)) ||
					!(klass->methods = rz_list_new()) ||
					!(klass->fields = rz_list_new())) {
					RZ_FREE(klass);
					RZ_FREE(pointers);
					RZ_FREE(sections);
					MACH0_(mach0_free)
					(mach0);
					goto beach;
				}

				bf->o->bin_obj = mach0;
				if (is_classlist) {
					MACH0_(get_class_t)
					(pointer_to_class, bf, buf, klass, false, NULL, cache->oi);
				} else {
					MACH0_(get_category_t)
					(pointer_to_class, bf, buf, klass, NULL, cache->oi);
				}
				bf->o->bin_obj = cache;

				if (!klass->name) {
					RZ_LOG_ERROR("CLASS ERROR AT 0x%llx, is_classlist %d\n", pointer_to_class, is_classlist);
					klass->name = rz_str_newf("UnnamedClass%u", num_of_unnamed_class);
					if (!klass->name) {
						RZ_FREE(klass);
						RZ_FREE(pointers);
						RZ_FREE(sections);
						MACH0_(mach0_free)
						(mach0);
						goto beach;
					}
					num_of_unnamed_class++;
				}
				rz_list_append(ret, klass);
			}

			RZ_FREE(pointers);
		}

		RZ_FREE(sections);
		MACH0_(mach0_free)
		(mach0);
	}

	return ret;

beach:
	rz_list_free(ret);
	rz_buf_free(owned_buf);
	return NULL;
}

static void header(RzBinFile *bf) {
	if (!bf || !bf->o) {
		return;
	}

	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return;
	}

	RzBin *bin = bf->rbin;
	ut64 slide = rz_dyldcache_get_slide(cache);
	PrintfCallback p = bin->cb_printf;

	PJ *pj = pj_new();
	if (!pj) {
		return;
	}

	pj_o(pj);
	pj_k(pj, "header");
	pj_o(pj);
	pj_ks(pj, "magic", cache->hdr->magic);
	pj_kn(pj, "mappingOffset", cache->hdr->mappingOffset);
	pj_kn(pj, "mappingCount", cache->hdr->mappingCount);
	pj_kn(pj, "imagesOffset", cache->hdr->imagesOffset);
	pj_kn(pj, "imagesCount", cache->hdr->imagesCount);
	pj_kn(pj, "dyldBaseAddress", cache->hdr->dyldBaseAddress);
	pj_kn(pj, "codeSignatureOffset", cache->hdr->codeSignatureOffset);
	pj_kn(pj, "codeSignatureSize", cache->hdr->codeSignatureSize);
	pj_kn(pj, "slideInfoOffset", cache->hdr->slideInfoOffset);
	pj_kn(pj, "slideInfoSize", cache->hdr->slideInfoSize);
	pj_kn(pj, "localSymbolsOffset", cache->hdr->localSymbolsOffset);
	pj_kn(pj, "localSymbolsSize", cache->hdr->localSymbolsSize);
	char uuidstr[128];
	rz_hex_bin2str((ut8 *)cache->hdr->uuid, 16, uuidstr);
	pj_ks(pj, "uuid", uuidstr);
	pj_ks(pj, "cacheType", (cache->hdr->cacheType == 0) ? "development" : "production");
	pj_kn(pj, "branchPoolsOffset", cache->hdr->branchPoolsOffset);
	pj_kn(pj, "branchPoolsCount", cache->hdr->branchPoolsCount);
	pj_kn(pj, "accelerateInfoAddr", cache->hdr->accelerateInfoAddr + slide);
	pj_kn(pj, "accelerateInfoSize", cache->hdr->accelerateInfoSize);
	pj_kn(pj, "imagesTextOffset", cache->hdr->imagesTextOffset);
	pj_kn(pj, "imagesTextCount", cache->hdr->imagesTextCount);
	pj_end(pj);

	if (cache->accel) {
		pj_k(pj, "accelerator");
		pj_o(pj);
		pj_kn(pj, "version", cache->accel->version);
		pj_kn(pj, "imageExtrasCount", cache->accel->imageExtrasCount);
		pj_kn(pj, "imagesExtrasOffset", cache->accel->imagesExtrasOffset);
		pj_kn(pj, "bottomUpListOffset", cache->accel->bottomUpListOffset);
		pj_kn(pj, "dylibTrieOffset", cache->accel->dylibTrieOffset);
		pj_kn(pj, "dylibTrieSize", cache->accel->dylibTrieSize);
		pj_kn(pj, "initializersOffset", cache->accel->initializersOffset);
		pj_kn(pj, "initializersCount", cache->accel->initializersCount);
		pj_kn(pj, "dofSectionsOffset", cache->accel->dofSectionsOffset);
		pj_kn(pj, "dofSectionsCount", cache->accel->dofSectionsCount);
		pj_kn(pj, "reExportListOffset", cache->accel->reExportListOffset);
		pj_kn(pj, "reExportCount", cache->accel->reExportCount);
		pj_kn(pj, "depListOffset", cache->accel->depListOffset);
		pj_kn(pj, "depListCount", cache->accel->depListCount);
		pj_kn(pj, "rangeTableOffset", cache->accel->rangeTableOffset);
		pj_kn(pj, "rangeTableCount", cache->accel->rangeTableCount);
		pj_kn(pj, "dyldSectionAddr", cache->accel->dyldSectionAddr + slide);
		pj_end(pj);
	}

	if (cache->rebase_infos) {
		size_t i;
		pj_k(pj, "slideInfo");
		pj_a(pj);
		for (i = 0; i < cache->rebase_infos->length; i++) {
			RzDyldRebaseInfo *rebase_info = cache->rebase_infos->entries[i].info;
			pj_o(pj);
			pj_kn(pj, "start", cache->rebase_infos->entries[i].start);
			pj_kn(pj, "end", cache->rebase_infos->entries[i].end);
			if (rebase_info) {
				ut8 version = rebase_info->version;
				pj_kn(pj, "version", version);
				pj_kn(pj, "slide", slide);
				if (version == 3) {
					RzDyldRebaseInfo3 *info3 = (RzDyldRebaseInfo3 *)rebase_info;
					pj_kn(pj, "page_starts_count", info3->page_starts_count);
					pj_kn(pj, "page_size", info3->page_size);
					pj_kn(pj, "auth_value_add", info3->auth_value_add);
				} else if (version == 2 || version == 4) {
					RzDyldRebaseInfo2 *info2 = (RzDyldRebaseInfo2 *)rebase_info;
					pj_kn(pj, "page_starts_count", info2->page_starts_count);
					pj_kn(pj, "page_extras_count", info2->page_extras_count);
					pj_kn(pj, "delta_mask", info2->delta_mask);
					pj_kn(pj, "value_mask", info2->value_mask);
					pj_kn(pj, "value_add", info2->value_add);
					pj_kn(pj, "delta_shift", info2->delta_shift);
					pj_kn(pj, "page_size", info2->page_size);
				} else if (version == 1) {
					RzDyldRebaseInfo1 *info1 = (RzDyldRebaseInfo1 *)rebase_info;
					pj_kn(pj, "toc_count", info1->toc_count);
					pj_kn(pj, "entries_size", info1->entries_size);
					pj_kn(pj, "page_size", 4096);
				}
			}
			pj_end(pj);
		}
		pj_end(pj);
	}

	if (cache->hdr->imagesTextCount) {
		pj_k(pj, "images");
		pj_a(pj);
		ut64 total_size = cache->hdr->imagesTextCount * sizeof(cache_text_info_t);
		cache_text_info_t *text_infos = malloc(total_size);
		if (!text_infos) {
			goto beach;
		}
		if (rz_buf_fread_at(cache->buf, cache->hdr->imagesTextOffset, (ut8 *)text_infos, "16clii", cache->hdr->imagesTextCount) != total_size) {
			free(text_infos);
			goto beach;
		}
		size_t i;
		for (i = 0; i != cache->hdr->imagesTextCount; i++) {
			cache_text_info_t *text_info = &text_infos[i];
			rz_hex_bin2str((ut8 *)text_info->uuid, 16, uuidstr);
			pj_o(pj);
			pj_ks(pj, "uuid", uuidstr);
			pj_kn(pj, "address", text_info->loadAddress + slide);
			pj_kn(pj, "textSegmentSize", text_info->textSegmentSize);
			char file[256];
			if (rz_buf_read_at(cache->buf, text_info->pathOffset, (ut8 *)&file, sizeof(file)) == sizeof(file)) {
				file[255] = 0;
				pj_ks(pj, "path", file);
				char *last_slash = strrchr(file, '/');
				if (last_slash && *last_slash) {
					pj_ks(pj, "name", last_slash + 1);
				} else {
					pj_ks(pj, "name", file);
				}
			}
			pj_end(pj);
		}
		pj_end(pj);
		free(text_infos);
	}

	pj_end(pj);
	p("%s\n", pj_string(pj));

beach:
	pj_free(pj);
}

RzBinPlugin rz_bin_plugin_dyldcache = {
	.name = "dyldcache",
	.desc = "dyldcache bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.entries = &entries,
	.baddr = &baddr,
	.populate_symbols = &symbols,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.sections = &sections,
	.check_buffer = &check_buffer,
	.destroy = &destroy,
	.classes = &classes,
	.header = &header,
	.info = &info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dyldcache,
	.version = RZ_VERSION
};
#endif
