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
		rz_buf_free(buf);
		return NULL;
	}

	mach0->user = cache;
	mach0->va2pa = &bin_obj_va2pa;

	rz_buf_free(buf);

	return mach0;
}

static bool dyldcache_check_buffer(RzBuffer *buf) {
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

static bool dyldcache_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	RzDyldCache *cache = rz_dyldcache_new_buf(buf);
	if (!cache) {
		return false;
	}
	obj->bin_obj = cache;
	return true;
}

static RzPVector /*<RzBinAddr *>*/ *dyldcache_entries(RzBinFile *bf) {
	RzBinAddr *ptr = NULL;
	RzPVector *ret = rz_pvector_new(free);
	if (!ret) {
		return NULL;
	}
	if ((ptr = RZ_NEW0(RzBinAddr))) {
		rz_pvector_push(ret, ptr);
	}
	return ret;
}

static RzBinInfo *dyldcache_info(RzBinFile *bf) {
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
	ret->file = rz_str_dup(bf->file);
	ret->bclass = rz_str_dup("dyldcache");
	ret->os = rz_str_dup(rz_dyldcache_get_platform_str(cache));
	if (strstr(cache->hdr->magic, "x86_64")) {
		ret->arch = rz_str_dup("x86");
		ret->bits = 64;
	} else {
		ret->arch = rz_str_dup("arm");
		ret->bits = strstr(cache->hdr->magic, "arm64") ? 64 : 32;
	}
	ret->machine = rz_str_dup(ret->arch);
	ret->subsystem = rz_str_dup("xnu");
	ret->guid = rz_hex_bin2strdup((ut8 *)cache->hdr->uuid, sizeof(cache->hdr->uuid));
	ret->type = rz_str_dup(rz_dyldcache_get_type_str(cache));
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	return ret;
}

static ut64 dyldcache_baddr(RzBinFile *bf) {
	// XXX hardcoded
	return 0x180000000;
}

void symbols_from_bin(RzDyldCache *cache, RzPVector /*<RzBinSymbol *>*/ *ret, RzBinFile *bf, RzDyldBinImage *bin, RzSetU *hash) {
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
		sym->name = rz_str_dup(symbols[i].name);
		sym->vaddr = symbols[i].addr;
		sym->forwarder = "NONE";
		sym->bind = (symbols[i].type == RZ_BIN_MACH0_SYMBOL_TYPE_LOCAL) ? RZ_BIN_BIND_LOCAL_STR : RZ_BIN_BIND_GLOBAL_STR;
		sym->type = RZ_BIN_TYPE_FUNC_STR;
		sym->paddr = symbols[i].offset + bf->o->boffset;
		sym->size = symbols[i].size;
		sym->ordinal = i;

		rz_set_u_add(hash, sym->vaddr);
		rz_pvector_push(ret, sym);
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

static void sections_from_bin(RzPVector /*<RzBinSection *>*/ *ret, RzBinFile *bf, RzDyldBinImage *bin) {
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
			ptr->layout.type = RZ_META_TYPE_DATA;
			ptr->layout.element_size = 8;
			ptr->layout.count = len;
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
		rz_pvector_push(ret, ptr);
	}
	free(sections);
	MACH0_(mach0_free)
	(mach0);
}

static RzPVector /*<RzBinVirtualFile *>*/ *dyldcache_virtual_files(RzBinFile *bf) {
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
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
		vf->name = rz_str_dup(RZ_DYLDCACHE_VFILE_NAME_REBASED);
		rz_pvector_push(ret, vf);
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

static RzPVector /*<RzBinMap *>*/ *dyldcache_maps(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}
	ut64 slide = rz_dyldcache_get_slide(cache);
	for (ut32 i = 0; i < cache->n_maps; i++) {
		RzBinMap *map = RZ_NEW0(RzBinMap);
		if (!map) {
			rz_pvector_free(ret);
			return NULL;
		}
		map->name = rz_str_newf("cache_map.%d", i);
		map->paddr = cache->maps[i].fileOffset;
		map->psize = cache->maps[i].size;
		map->vsize = map->psize;
		map->vaddr = cache->maps[i].address + slide;
		map->perm = prot2perm(cache->maps[i].initProt);
		if (rz_dyldcache_range_needs_rebasing(cache, map->paddr, map->psize)) {
			map->vfile_name = rz_str_dup(RZ_DYLDCACHE_VFILE_NAME_REBASED);
		}
		rz_pvector_push(ret, map);
	}
	return ret;
}

static RzPVector /*<RzBinSection *>*/ *dyldcache_sections(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}
	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
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
		void **it;
		rz_pvector_foreach (ret, it) {
			section = *it;
			section->vaddr += slide;
		}
	}
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *dyldcache_symbols(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!ret) {
		return NULL;
	}

	RzListIter *iter;
	RzDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		RzSetU *hash = rz_set_u_new();
		if (!hash) {
			rz_pvector_free(ret);
			return NULL;
		}
		symbols_from_bin(cache, ret, bf, bin, hash);
		rz_dyldcache_symbols_from_locsym(cache, bin, ret, hash);
		rz_set_u_free(hash);
	}

	ut64 slide = rz_dyldcache_get_slide(cache);
	if (slide) {
		RzBinSymbol *sym;
		void **it;
		rz_pvector_foreach (ret, it) {
			sym = *it;
			sym->vaddr += slide;
		}
	}

	return ret;
}

static void dyldcache_destroy(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	rz_dyldcache_free(cache);
}

static RzPVector /*<RzBinClass *>*/ *dyldcache_classes(RzBinFile *bf) {
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	RzPVector *ret = rz_pvector_new(free);
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
				rz_pvector_push(ret, klass);
			}

			RZ_FREE(pointers);
		}

		RZ_FREE(sections);
		MACH0_(mach0_free)
		(mach0);
	}

	return ret;

beach:
	rz_pvector_free(ret);
	rz_buf_free(owned_buf);
	return NULL;
}

static RzStructuredData *dyldcache_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	char uuidstr[128] = { 0 };
	RzDyldCache *cache = (RzDyldCache *)bf->o->bin_obj;
	if (!cache) {
		return NULL;
	}

	ut64 slide = rz_dyldcache_get_slide(cache);

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *dyldcache = rz_structured_data_map_add_map(info, "dyldcache");
	if (!dyldcache) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzDyldCacheHeaderVersion ver = rz_dyldcache_header_version(cache->hdr);
	switch (ver) {
	case RZ_DYLD_CACHE_HEADER_BEFORE_940:
		rz_structured_data_map_add_string(dyldcache, "version", "<940");
		break;
	case RZ_DYLD_CACHE_HEADER_940_OR_AFTER:
		rz_structured_data_map_add_string(dyldcache, "version", "940");
		break;
	case RZ_DYLD_CACHE_HEADER_1042_1_OR_AFTER:
		rz_structured_data_map_add_string(dyldcache, "version", "1042.1");
		break;
	}

	RzStructuredData *header = rz_structured_data_map_add_map(dyldcache, "header");
	if (!header) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_string(header, "magic", cache->hdr->magic);
	rz_structured_data_map_add_unsigned(header, "mappingOffset", cache->hdr->mappingOffset, true);
	rz_structured_data_map_add_unsigned(header, "mappingCount", cache->hdr->mappingCount, false);
	rz_structured_data_map_add_unsigned(header, "imagesOffset", cache->hdr->imagesOffset, true);
	rz_structured_data_map_add_unsigned(header, "imagesCount", cache->hdr->imagesCount, false);
	rz_structured_data_map_add_unsigned(header, "dyldBaseAddress", cache->hdr->dyldBaseAddress, true);
	rz_structured_data_map_add_unsigned(header, "codeSignatureOffset", cache->hdr->codeSignatureOffset, true);
	rz_structured_data_map_add_unsigned(header, "codeSignatureSize", cache->hdr->codeSignatureSize, false);
	rz_structured_data_map_add_unsigned(header, "slideInfoOffset", cache->hdr->slideInfoOffset, true);
	rz_structured_data_map_add_unsigned(header, "slideInfoSize", cache->hdr->slideInfoSize, false);
	rz_structured_data_map_add_unsigned(header, "localSymbolsOffset", cache->hdr->localSymbolsOffset, true);
	rz_structured_data_map_add_unsigned(header, "localSymbolsSize", cache->hdr->localSymbolsSize, false);
	rz_hex_bin2str((ut8 *)cache->hdr->uuid, 16, uuidstr);
	rz_structured_data_map_add_string(header, "uuid", uuidstr);
	rz_structured_data_map_add_string(header, "cacheType", (cache->hdr->cacheType == 0) ? "development" : "production");
	rz_structured_data_map_add_unsigned(header, "branchPoolsOffset", cache->hdr->branchPoolsOffset, true);
	rz_structured_data_map_add_unsigned(header, "branchPoolsCount", cache->hdr->branchPoolsCount, false);
	if (rz_dyldcache_header_may_have_accel(cache->hdr)) {
		rz_structured_data_map_add_unsigned(header, "accelerateInfoAddr", cache->hdr->accelerateInfoAddr + slide, false);
		rz_structured_data_map_add_unsigned(header, "accelerateInfoSize", cache->hdr->accelerateInfoSize, false);
	} else {
		rz_structured_data_map_add_unsigned(header, "dyldInCacheMH", cache->hdr->dyldInCacheMH, true);
		rz_structured_data_map_add_unsigned(header, "dyldInCacheEntry", cache->hdr->dyldInCacheEntry, true);
	}
	rz_structured_data_map_add_unsigned(header, "imagesTextOffset", cache->hdr->imagesTextOffset, true);
	rz_structured_data_map_add_unsigned(header, "imagesTextCount", cache->hdr->imagesTextCount, false);
	rz_structured_data_map_add_unsigned(header, "patchInfoAddr", cache->hdr->patchInfoAddr, false);
	rz_structured_data_map_add_unsigned(header, "patchInfoSize", cache->hdr->patchInfoSize, false);
	rz_structured_data_map_add_unsigned(header, "otherImageGroupAddrUnused", cache->hdr->otherImageGroupAddrUnused, true);
	rz_structured_data_map_add_unsigned(header, "otherImageGroupSizeUnused", cache->hdr->otherImageGroupSizeUnused, false);
	rz_structured_data_map_add_unsigned(header, "progClosuresAddr", cache->hdr->progClosuresAddr, true);
	rz_structured_data_map_add_unsigned(header, "progClosuresSize", cache->hdr->progClosuresSize, false);
	rz_structured_data_map_add_unsigned(header, "progClosuresTrieAddr", cache->hdr->progClosuresTrieAddr, true);
	rz_structured_data_map_add_unsigned(header, "progClosuresTrieSize", cache->hdr->progClosuresTrieSize, false);
	rz_structured_data_map_add_unsigned(header, "platform", cache->hdr->platform, false);
	rz_structured_data_map_add_unsigned(header, "formatVersion", cache->hdr->formatVersion, false);
	rz_structured_data_map_add_unsigned(header, "dylibsExpectedOnDisk", cache->hdr->dylibsExpectedOnDisk, false);
	rz_structured_data_map_add_unsigned(header, "simulator", cache->hdr->simulator, false);
	rz_structured_data_map_add_unsigned(header, "locallyBuiltCache", cache->hdr->locallyBuiltCache, false);
	rz_structured_data_map_add_unsigned(header, "builtFromChainedFixups", cache->hdr->builtFromChainedFixups, false);
	rz_structured_data_map_add_unsigned(header, "padding", cache->hdr->padding, true);
	rz_structured_data_map_add_unsigned(header, "sharedRegionStart", cache->hdr->sharedRegionStart, false);
	rz_structured_data_map_add_unsigned(header, "sharedRegionSize", cache->hdr->sharedRegionSize, false);
	rz_structured_data_map_add_unsigned(header, "maxSlide", cache->hdr->maxSlide, false);
	rz_structured_data_map_add_unsigned(header, "dylibsImageArrayAddr", cache->hdr->dylibsImageArrayAddr, true);
	rz_structured_data_map_add_unsigned(header, "dylibsImageArraySize", cache->hdr->dylibsImageArraySize, false);
	rz_structured_data_map_add_unsigned(header, "dylibsTrieAddr", cache->hdr->dylibsTrieAddr, true);
	rz_structured_data_map_add_unsigned(header, "dylibsTrieSize", cache->hdr->dylibsTrieSize, false);
	rz_structured_data_map_add_unsigned(header, "otherImageArrayAddr", cache->hdr->otherImageArrayAddr, true);
	rz_structured_data_map_add_unsigned(header, "otherImageArraySize", cache->hdr->otherImageArraySize, false);
	rz_structured_data_map_add_unsigned(header, "otherTrieAddr", cache->hdr->otherTrieAddr, true);
	rz_structured_data_map_add_unsigned(header, "otherTrieSize", cache->hdr->otherTrieSize, false);
	rz_structured_data_map_add_unsigned(header, "mappingWithSlideOffset", cache->hdr->mappingWithSlideOffset, true);
	rz_structured_data_map_add_unsigned(header, "mappingWithSlideCount", cache->hdr->mappingWithSlideCount, false);
	if (ver >= RZ_DYLD_CACHE_HEADER_940_OR_AFTER) {
		rz_structured_data_map_add_unsigned(header, "dylibsPBLStateArrayAddrUnused", cache->hdr->dylibsPBLStateArrayAddrUnused, true);
		rz_structured_data_map_add_unsigned(header, "dylibsPBLSetAddr", cache->hdr->dylibsPBLSetAddr, true);
		rz_structured_data_map_add_unsigned(header, "programsPBLSetPoolAddr", cache->hdr->programsPBLSetPoolAddr, true);
		rz_structured_data_map_add_unsigned(header, "programsPBLSetPoolSize", cache->hdr->programsPBLSetPoolSize, false);
		rz_structured_data_map_add_unsigned(header, "programTrieAddr", cache->hdr->programTrieAddr, true);
		rz_structured_data_map_add_unsigned(header, "programTrieSize", cache->hdr->programTrieSize, false);
		rz_structured_data_map_add_unsigned(header, "osVersion", cache->hdr->osVersion, false);
		rz_structured_data_map_add_unsigned(header, "altPlatform", cache->hdr->altPlatform, false);
		rz_structured_data_map_add_unsigned(header, "altOsVersion", cache->hdr->altOsVersion, false);
		rz_structured_data_map_add_unsigned(header, "swiftOptsOffset", cache->hdr->swiftOptsOffset, true);
		rz_structured_data_map_add_unsigned(header, "swiftOptsSize", cache->hdr->swiftOptsSize, false);
		rz_structured_data_map_add_unsigned(header, "subCacheArrayOffset", cache->hdr->subCacheArrayOffset, true);
		rz_structured_data_map_add_unsigned(header, "subCacheArrayCount", cache->hdr->subCacheArrayCount, false);
		rz_hex_bin2str(cache->hdr->symbolFileUUID, sizeof(cache->hdr->symbolFileUUID), uuidstr);
		rz_structured_data_map_add_string(header, "symbolFileUUID", uuidstr);
		rz_structured_data_map_add_unsigned(header, "rosettaReadOnlyAddr", cache->hdr->rosettaReadOnlyAddr, true);
		rz_structured_data_map_add_unsigned(header, "rosettaReadOnlySize", cache->hdr->rosettaReadOnlySize, false);
		rz_structured_data_map_add_unsigned(header, "rosettaReadWriteAddr", cache->hdr->rosettaReadWriteAddr, true);
		rz_structured_data_map_add_unsigned(header, "rosettaReadWriteSize", cache->hdr->rosettaReadWriteSize, false);
	}
	if (ver >= RZ_DYLD_CACHE_HEADER_1042_1_OR_AFTER) {
		rz_structured_data_map_add_unsigned(header, "cacheSubType", cache->hdr->cacheSubType, false);
		rz_structured_data_map_add_unsigned(header, "objcOptsOffset", cache->hdr->objcOptsOffset, true);
		rz_structured_data_map_add_unsigned(header, "objcOptsSize", cache->hdr->objcOptsSize, false);
		rz_structured_data_map_add_unsigned(header, "cacheAtlasOffset", cache->hdr->cacheAtlasOffset, true);
		rz_structured_data_map_add_unsigned(header, "cacheAtlasSize", cache->hdr->cacheAtlasSize, false);
		rz_structured_data_map_add_unsigned(header, "dynamicDataOffset", cache->hdr->dynamicDataOffset, true);
		rz_structured_data_map_add_unsigned(header, "dynamicDataMaxSize", cache->hdr->dynamicDataMaxSize, false);
	}

	if (cache->accel) {
		RzStructuredData *acc = rz_structured_data_map_add_map(dyldcache, "accelerator");
		if (!acc) {
			rz_structured_data_free(info);
			return NULL;
		}
		rz_structured_data_map_add_unsigned(acc, "version", cache->accel->version, false);
		rz_structured_data_map_add_unsigned(acc, "imageExtrasCount", cache->accel->imageExtrasCount, false);
		rz_structured_data_map_add_unsigned(acc, "imagesExtrasOffset", cache->accel->imagesExtrasOffset, true);
		rz_structured_data_map_add_unsigned(acc, "bottomUpListOffset", cache->accel->bottomUpListOffset, true);
		rz_structured_data_map_add_unsigned(acc, "dylibTrieOffset", cache->accel->dylibTrieOffset, true);
		rz_structured_data_map_add_unsigned(acc, "dylibTrieSize", cache->accel->dylibTrieSize, false);
		rz_structured_data_map_add_unsigned(acc, "initializersOffset", cache->accel->initializersOffset, true);
		rz_structured_data_map_add_unsigned(acc, "initializersCount", cache->accel->initializersCount, false);
		rz_structured_data_map_add_unsigned(acc, "dofSectionsOffset", cache->accel->dofSectionsOffset, true);
		rz_structured_data_map_add_unsigned(acc, "dofSectionsCount", cache->accel->dofSectionsCount, false);
		rz_structured_data_map_add_unsigned(acc, "reExportListOffset", cache->accel->reExportListOffset, true);
		rz_structured_data_map_add_unsigned(acc, "reExportCount", cache->accel->reExportCount, false);
		rz_structured_data_map_add_unsigned(acc, "depListOffset", cache->accel->depListOffset, true);
		rz_structured_data_map_add_unsigned(acc, "depListCount", cache->accel->depListCount, false);
		rz_structured_data_map_add_unsigned(acc, "rangeTableOffset", cache->accel->rangeTableOffset, true);
		rz_structured_data_map_add_unsigned(acc, "rangeTableCount", cache->accel->rangeTableCount, false);
		rz_structured_data_map_add_unsigned(acc, "dyldSectionAddr", cache->accel->dyldSectionAddr + slide, true);
	}

	if (cache->rebase_infos) {
		RzStructuredData *slideInfo = rz_structured_data_map_add_array(dyldcache, "slideInfo");
		if (!slideInfo) {
			rz_structured_data_free(info);
			return NULL;
		}
		for (size_t i = 0; i < cache->rebase_infos->length; i++) {
			RzStructuredData *rbi = rz_structured_data_array_add_map(slideInfo);
			if (!rbi) {
				rz_structured_data_free(info);
				return NULL;
			}
			RzDyldRebaseInfo *rebase_info = cache->rebase_infos->entries[i].info;

			rz_structured_data_map_add_unsigned(rbi, "start", cache->rebase_infos->entries[i].start, true);
			rz_structured_data_map_add_unsigned(rbi, "end", cache->rebase_infos->entries[i].end, true);
			if (!rebase_info) {
				continue;
			}

			ut8 version = rebase_info->version;
			rz_structured_data_map_add_unsigned(rbi, "version", version, false);
			rz_structured_data_map_add_unsigned(rbi, "slide", slide, false);
			if (version == 3) {
				RzDyldRebaseInfo3 *info3 = (RzDyldRebaseInfo3 *)rebase_info;
				rz_structured_data_map_add_unsigned(rbi, "page_starts_count", info3->page_starts_count, false);
				rz_structured_data_map_add_unsigned(rbi, "page_size", info3->page_size, false);
				rz_structured_data_map_add_unsigned(rbi, "auth_value_add", info3->auth_value_add, false);
			} else if (version == 2 || version == 4) {
				RzDyldRebaseInfo2 *info2 = (RzDyldRebaseInfo2 *)rebase_info;
				rz_structured_data_map_add_unsigned(rbi, "page_starts_count", info2->page_starts_count, false);
				rz_structured_data_map_add_unsigned(rbi, "page_extras_count", info2->page_extras_count, false);
				rz_structured_data_map_add_unsigned(rbi, "delta_mask", info2->delta_mask, true);
				rz_structured_data_map_add_unsigned(rbi, "value_mask", info2->value_mask, true);
				rz_structured_data_map_add_unsigned(rbi, "value_add", info2->value_add, false);
				rz_structured_data_map_add_unsigned(rbi, "delta_shift", info2->delta_shift, false);
				rz_structured_data_map_add_unsigned(rbi, "page_size", info2->page_size, false);
			} else if (version == 1) {
				RzDyldRebaseInfo1 *info1 = (RzDyldRebaseInfo1 *)rebase_info;
				rz_structured_data_map_add_unsigned(rbi, "toc_count", info1->toc_count, false);
				rz_structured_data_map_add_unsigned(rbi, "entries_size", info1->entries_size, false);
				rz_structured_data_map_add_unsigned(rbi, "page_size", 4096, false);
			}
		}
	}

	if (cache->hdr->imagesTextCount) {
		char file[256] = { 0 };
		RzStructuredData *images = rz_structured_data_map_add_array(dyldcache, "images");
		if (!images) {
			rz_structured_data_free(info);
			return NULL;
		}

		ut64 total_size = cache->hdr->imagesTextCount * sizeof(cache_text_info_t);
		cache_text_info_t *text_infos = malloc(total_size);
		if (!text_infos) {
			RZ_LOG_ERROR("dyldcache: failed to allocate size: %" PFMT64u "\n", total_size);
			return info;
		}
		if (rz_buf_fread_at(cache->buf, cache->hdr->imagesTextOffset, (ut8 *)text_infos, "16clii", cache->hdr->imagesTextCount) != total_size) {
			free(text_infos);
			RZ_LOG_ERROR("dyldcache: failed to read size: %" PFMT64u "\n", total_size);
			return info;
		}

		for (size_t i = 0; i != cache->hdr->imagesTextCount; i++) {
			RzStructuredData *ti = rz_structured_data_array_add_map(images);
			if (!ti) {
				rz_structured_data_free(info);
				return NULL;
			}

			cache_text_info_t *text_info = &text_infos[i];
			rz_hex_bin2str((ut8 *)text_info->uuid, 16, uuidstr);
			rz_structured_data_map_add_string(ti, "uuid", uuidstr);
			rz_structured_data_map_add_unsigned(ti, "address", text_info->loadAddress + slide, true);
			rz_structured_data_map_add_unsigned(ti, "textSegmentSize", text_info->textSegmentSize, false);

			if (rz_buf_read_at(cache->buf, text_info->pathOffset, (ut8 *)&file, sizeof(file)) == sizeof(file)) {
				file[255] = 0;
				rz_structured_data_map_add_string(ti, "path", file);
				char *last_slash = strrchr(file, '/');
				if (RZ_STR_ISNOTEMPTY(last_slash)) {
					rz_structured_data_map_add_string(ti, "name", last_slash + 1);
				} else {
					rz_structured_data_map_add_string(ti, "name", file);
				}
			}
		}
		free(text_infos);
	}

	return info;
}

RzBinPlugin rz_bin_plugin_dyldcache = {
	.name = "dyldcache",
	.desc = "Apple DYLD Cache",
	.license = "LGPL3",
	.author = "pancake",
	.load_buffer = &dyldcache_load_buffer,
	.entries = &dyldcache_entries,
	.baddr = &dyldcache_baddr,
	.symbols = &dyldcache_symbols,
	.virtual_files = &dyldcache_virtual_files,
	.maps = &dyldcache_maps,
	.sections = &dyldcache_sections,
	.check_buffer = &dyldcache_check_buffer,
	.destroy = &dyldcache_destroy,
	.classes = &dyldcache_classes,
	.bin_structure = &dyldcache_structure,
	.info = &dyldcache_info,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dyldcache,
	.version = RZ_VERSION
};
#endif
