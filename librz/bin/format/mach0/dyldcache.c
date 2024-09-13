// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 keegan
// SPDX-FileCopyrightText: 2020-2021 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dyldcache.h"

#include <rz_util/ht_pu.h>

#define MAX_N_HDR 16

static RzDyldLocSym *rz_dyld_locsym_new(RzDyldCache *cache);

/**
 * \param magic zero-terminated string from the beginning of some file
 */
RZ_API bool rz_dyldcache_check_magic(const char *magic) {
	return !strncmp(magic, "dyld_v1   arm64", 16) ||
		!strncmp(magic, "dyld_v1  arm64e", 16) ||
		!strncmp(magic, "dyld_v1  x86_64", 16) ||
		!strncmp(magic, "dyld_v1 x86_64h", 16);
}

static ut64 va2pa(uint64_t addr, ut32 n_maps, cache_map_t *maps, RzBuffer *cache_buf, ut64 slide, ut32 *offset, ut32 *left) {
	ut64 res = UT64_MAX;
	ut32 i;

	addr -= slide;

	for (i = 0; i < n_maps; i++) {
		if (addr >= maps[i].address && addr < maps[i].address + maps[i].size) {
			res = maps[i].fileOffset + addr - maps[i].address;
			if (offset) {
				*offset = addr - maps[i].address;
			}
			if (left) {
				*left = maps[i].size - (addr - maps[i].address);
			}
			break;
		}
	}

	return res;
}

static void free_bin(RzDyldBinImage *bin) {
	if (!bin) {
		return;
	}
	free(bin->file);
	free(bin);
}

static RzDyldCacheHeader *read_cache_header(RzBuffer *cache_buf, ut64 offset) {
	if (!cache_buf) {
		return NULL;
	}

	RzDyldCacheHeader *hdr = RZ_NEW0(RzDyldCacheHeader);
	if (!hdr) {
		return NULL;
	}

	ut64 cur = offset;
	if (!rz_buf_read_offset(cache_buf, &cur, (ut8 *)hdr->magic, sizeof(hdr->magic)) ||
		!rz_dyldcache_check_magic(hdr->magic) ||
		!rz_buf_read_le32_offset(cache_buf, &cur, &hdr->mappingOffset) ||
		!rz_buf_read_le32_offset(cache_buf, &cur, &hdr->mappingCount) ||
		!rz_buf_read_le32_offset(cache_buf, &cur, &hdr->imagesOffset) ||
		!rz_buf_read_le32_offset(cache_buf, &cur, &hdr->imagesCount) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->dyldBaseAddress) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->codeSignatureOffset) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->codeSignatureSize) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->slideInfoOffset) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->slideInfoSize) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->localSymbolsOffset) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->localSymbolsSize) ||
		!rz_buf_read_offset(cache_buf, &cur, hdr->uuid, sizeof(hdr->uuid)) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->cacheType) ||
		!rz_buf_read_le32_offset(cache_buf, &cur, &hdr->branchPoolsOffset) ||
		!rz_buf_read_le32_offset(cache_buf, &cur, &hdr->branchPoolsCount) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->accelerateInfoAddr) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->accelerateInfoSize) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->imagesTextOffset) ||
		!rz_buf_read_le64_offset(cache_buf, &cur, &hdr->imagesTextCount)) {
		goto fail;
	}

	// Size of the header was continuously expanded during versions as newer fields got added.
	// There is no dedicated header size stored in the file, but in practice the mappingOffset is
	// directly after the header, so we use this as an indicator on how far we may read.
	ut64 hdr_end_offset = offset + hdr->mappingOffset;
#define READ_OR_FINISH(bits, dst) \
	do { \
		if (cur + bits / 8 > hdr_end_offset || !rz_buf_read_le##bits##_offset(cache_buf, &cur, dst)) { \
			goto finish; \
		} \
	} while (0)
	READ_OR_FINISH(64, &hdr->patchInfoAddr);
	READ_OR_FINISH(64, &hdr->patchInfoSize);
	READ_OR_FINISH(64, &hdr->otherImageGroupAddrUnused);
	READ_OR_FINISH(64, &hdr->otherImageGroupSizeUnused);
	READ_OR_FINISH(64, &hdr->progClosuresAddr);
	READ_OR_FINISH(64, &hdr->progClosuresSize);
	READ_OR_FINISH(64, &hdr->progClosuresTrieAddr);
	READ_OR_FINISH(64, &hdr->progClosuresTrieSize);
	READ_OR_FINISH(32, &hdr->platform);

	ut32 flags;
	READ_OR_FINISH(32, &flags);
	hdr->formatVersion = flags & rz_num_bitmask(8);
	flags >>= 8;
	hdr->dylibsExpectedOnDisk = flags & 1;
	flags >>= 1;
	hdr->simulator = flags & 1;
	flags >>= 1;
	hdr->locallyBuiltCache = flags & 1;
	flags >>= 1;
	hdr->builtFromChainedFixups = flags & 1;
	flags >>= 1;
	hdr->padding = flags;

	READ_OR_FINISH(64, &hdr->sharedRegionStart);
	READ_OR_FINISH(64, &hdr->sharedRegionSize);
	READ_OR_FINISH(64, &hdr->maxSlide);
	READ_OR_FINISH(64, &hdr->dylibsImageArrayAddr);
	READ_OR_FINISH(64, &hdr->dylibsImageArraySize);
	READ_OR_FINISH(64, &hdr->dylibsTrieAddr);
	READ_OR_FINISH(64, &hdr->dylibsTrieSize);
	READ_OR_FINISH(64, &hdr->otherImageArrayAddr);
	READ_OR_FINISH(64, &hdr->otherImageArraySize);
	READ_OR_FINISH(64, &hdr->otherTrieAddr);
	READ_OR_FINISH(64, &hdr->otherTrieSize);
	READ_OR_FINISH(32, &hdr->mappingWithSlideOffset);
	READ_OR_FINISH(32, &hdr->mappingWithSlideCount);

	READ_OR_FINISH(64, &hdr->dylibsPBLStateArrayAddrUnused);
	READ_OR_FINISH(64, &hdr->dylibsPBLSetAddr);
	READ_OR_FINISH(64, &hdr->programsPBLSetPoolAddr);
	READ_OR_FINISH(64, &hdr->programsPBLSetPoolSize);
	READ_OR_FINISH(64, &hdr->programTrieAddr);
	READ_OR_FINISH(32, &hdr->programTrieSize);
	READ_OR_FINISH(32, &hdr->osVersion);
	READ_OR_FINISH(32, &hdr->altPlatform);
	READ_OR_FINISH(32, &hdr->altOsVersion);
	READ_OR_FINISH(64, &hdr->swiftOptsOffset);
	READ_OR_FINISH(64, &hdr->swiftOptsSize);
	READ_OR_FINISH(32, &hdr->subCacheArrayOffset);
	READ_OR_FINISH(32, &hdr->subCacheArrayCount);

	if (cur + sizeof(hdr->symbolFileUUID) > hdr_end_offset ||
		!rz_buf_read_offset(cache_buf, &cur, hdr->symbolFileUUID, sizeof(hdr->symbolFileUUID))) {
		goto finish;
	}

	READ_OR_FINISH(64, &hdr->rosettaReadOnlyAddr);
	READ_OR_FINISH(64, &hdr->rosettaReadOnlySize);
	READ_OR_FINISH(64, &hdr->rosettaReadWriteAddr);
	READ_OR_FINISH(64, &hdr->rosettaReadWriteSize);

	// This intentionally overrides the imagesOffset/imagesCount above as these
	// two fields were moved down here in dyld-940:
	READ_OR_FINISH(32, &hdr->imagesOffset);
	READ_OR_FINISH(32, &hdr->imagesCount);

	READ_OR_FINISH(32, &hdr->cacheSubType);
	cur += 4; // 8-alignment/padding
	READ_OR_FINISH(64, &hdr->objcOptsOffset);
	READ_OR_FINISH(64, &hdr->objcOptsSize);
	READ_OR_FINISH(64, &hdr->cacheAtlasOffset);
	READ_OR_FINISH(64, &hdr->cacheAtlasSize);
	READ_OR_FINISH(64, &hdr->dynamicDataOffset);
	READ_OR_FINISH(64, &hdr->dynamicDataMaxSize);

#undef READ_OR_FINISH
finish:
	return hdr;
fail:
	free(hdr);
	return NULL;
}

RZ_API RZ_NONNULL const char *rz_dyldcache_get_platform_str(RzDyldCache *cache) {
	switch (cache->hdr->platform) {
	case 1:
		return "macOS";
	case 2:
		return "iOS";
	case 3:
		return "tvOS";
	case 4:
		return "watchOS";
	case 5:
		return "bridgeOS";
	case 6:
		return "iOSMac";
	case 7:
		return "iOS_simulator";
	case 8:
		return "tvOS_simulator";
	case 9:
		return "watchOS_simulator";
	case 10:
		return "driverKit";
	default:
		return "darwin"; // unknown
	}
}

RZ_API RZ_NONNULL const char *rz_dyldcache_get_type_str(RzDyldCache *cache) {
	switch (cache->hdr->cacheType) {
	case 0:
		return "development";
	case 1:
		return "production";
	case 2:
		return "multi-cache";
	default:
		return "unknown";
	}
}

#define SHIFT_MAYBE(x) \
	if (x) { \
		x += offset; \
	}

static void populate_cache_headers(RzDyldCache *cache) {
	cache->n_hdr = 0;
	RzList *hdrs = rz_list_newf(NULL);
	if (!hdrs) {
		return;
	}

	RzDyldCacheHeader *h;
	ut64 offsets[MAX_N_HDR];
	ut64 offset = 0;
	do {
		offsets[cache->n_hdr] = offset;
		h = read_cache_header(cache->buf, offset);
		if (!h) {
			break;
		}
		rz_list_append(hdrs, h);

		ut64 size = h->codeSignatureOffset + h->codeSignatureSize;

		SHIFT_MAYBE(h->mappingOffset);
		SHIFT_MAYBE(h->imagesOffset);
		SHIFT_MAYBE(h->codeSignatureOffset);
		SHIFT_MAYBE(h->slideInfoOffset);
		SHIFT_MAYBE(h->localSymbolsOffset);
		SHIFT_MAYBE(h->branchPoolsOffset);
		SHIFT_MAYBE(h->imagesTextOffset);

		offset += size;
		cache->n_hdr++;
	} while (cache->n_hdr < MAX_N_HDR);

	if (!cache->n_hdr) {
		goto beach;
	}

	cache->hdr = RZ_NEWS0(RzDyldCacheHeader, cache->n_hdr);
	if (!cache->hdr) {
		cache->n_hdr = 0;
		goto beach;
	}

	cache->hdr_offset = RZ_NEWS0(ut64, cache->n_hdr);
	if (!cache->hdr_offset) {
		cache->n_hdr = 0;
		RZ_FREE(cache->hdr);
		goto beach;
	}

	memcpy(cache->hdr_offset, offsets, cache->n_hdr * sizeof(ut64));

	ut32 i = 0;
	RzListIter *iter;
	RzDyldCacheHeader *item;
	rz_list_foreach (hdrs, iter, item) {
		if (i >= cache->n_hdr) {
			break;
		}
		memcpy(&cache->hdr[i++], item, sizeof(RzDyldCacheHeader));
	}

beach:
	rz_list_free(hdrs);
}

#undef SHIFT_MAYBE

static void populate_cache_maps(RzDyldCache *cache) {
	rz_return_if_fail(cache && cache->buf);

	ut32 i;
	ut32 n_maps = 0;
	ut64 max_count = 0;
	for (i = 0; i < cache->n_hdr; i++) {
		RzDyldCacheHeader *hdr = &cache->hdr[i];
		if (!hdr->mappingCount || !hdr->mappingOffset) {
			continue;
		}
		max_count = RZ_MAX(hdr->mappingCount, max_count);
		n_maps += hdr->mappingCount;
	}

	if (n_maps < 1 || n_maps < max_count /* overflow */) {
		cache->maps = NULL;
		cache->n_maps = 0;
		return;
	}

	cache->maps_index = RZ_NEWS0(ut32, cache->n_hdr);
	if (!cache->maps_index) {
		return;
	}
	cache_map_t *maps = RZ_NEWS0(cache_map_t, n_maps);
	if (!maps) {
		return;
	}

	ut32 next_map = 0;
	ut32 last_idx = UT32_MAX;
	ut64 max_address = 0;
	for (i = 0; i < cache->n_hdr; i++) {
		RzDyldCacheHeader *hdr = &cache->hdr[i];
		cache->maps_index[i] = next_map;

		if (!hdr->mappingCount || !hdr->mappingOffset) {
			continue;
		}
		ut64 size = sizeof(cache_map_t) * hdr->mappingCount;
		if (rz_buf_fread_at(cache->buf, hdr->mappingOffset, (ut8 *)&maps[next_map], "3l2i", hdr->mappingCount) != size) {
			continue;
		}
		ut32 j;
		ut64 hdr_offset = cache->hdr_offset[i];
		for (j = 0; j < hdr->mappingCount; j++) {
			cache_map_t *map = &maps[next_map + j];
			map->fileOffset += hdr_offset;
			if (map->address > max_address) {
				last_idx = i;
				max_address = map->address;
			}
		}
		next_map += hdr->mappingCount;
	}

	cache->maps = maps;
	cache->n_maps = next_map;
	if (last_idx == UT32_MAX) {
		cache->symbols_off_base = 0;
	} else {
		cache->symbols_off_base = cache->hdr_offset[last_idx];
	}
}

static cache_accel_t *read_cache_accel(RzBuffer *cache_buf, RzDyldCacheHeader *hdr, cache_map_t *maps, size_t n_maps) {
	if (!cache_buf || !hdr || !rz_dyldcache_header_may_have_accel(hdr) || !hdr->accelerateInfoSize || !hdr->accelerateInfoAddr) {
		return NULL;
	}

	size_t map_count = RZ_MIN(hdr->mappingCount, n_maps);
	ut64 offset = va2pa(hdr->accelerateInfoAddr, map_count, maps, cache_buf, 0, NULL, NULL);
	if (!offset) {
		return NULL;
	}

	ut64 size = sizeof(cache_accel_t);
	cache_accel_t *accel = RZ_NEW0(cache_accel_t);
	if (!accel) {
		return NULL;
	}

	if (rz_buf_fread_at(cache_buf, offset, (ut8 *)accel, "16il", 1) != size) {
		RZ_FREE(accel);
		return NULL;
	}

	accel->imagesExtrasOffset += offset;
	accel->bottomUpListOffset += offset;
	accel->dylibTrieOffset += offset;
	accel->initializersOffset += offset;
	accel->dofSectionsOffset += offset;
	accel->reExportListOffset += offset;
	accel->depListOffset += offset;
	accel->rangeTableOffset += offset;

	return accel;
}

RZ_API objc_cache_opt_info *rz_dyldcache_get_objc_opt_info(RzBinFile *bf, RzDyldCache *cache) {
	objc_cache_opt_info *result = NULL;
	RzListIter *iter;
	RzDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		if (!bin->file || strcmp(bin->file, "lib/libobjc.A.dylib")) {
			continue;
		}

		struct MACH0_(opts_t) opts = { 0 };
		opts.verbose = bf->rbin->verbose;
		opts.header_at = bin->header_at;

		struct MACH0_(obj_t) *mach0 = MACH0_(new_buf)(cache->buf, &opts);
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
		ut64 scoffs_offset = 0;
		ut64 scoffs_size = 0;
		ut64 slide = rz_dyldcache_get_slide(cache);
		for (i = 0; !sections[i].last; i++) {
			if (sections[i].size == 0) {
				continue;
			}
			if (strstr(sections[i].name, "__objc_scoffs")) {
				scoffs_offset = va2pa(sections[i].addr, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);
				scoffs_size = sections[i].size;
				break;
			}
		}

		MACH0_(mach0_free)
		(mach0);
		RZ_FREE(sections);

		if (!scoffs_offset || scoffs_size < 40) {
			break;
		}
		ut64 check;
		if (!rz_buf_read_le64_at(cache->buf, scoffs_offset, &check) || check != 2) {
			break;
		}
		ut64 sel_string_base;
		if (!rz_buf_read_le64_at(cache->buf, scoffs_offset + 8, &sel_string_base)) {
			break;
		}
		ut64 sel_string_end;
		if (!rz_buf_read_le64_at(cache->buf, scoffs_offset + 16, &sel_string_end) || sel_string_end == sel_string_base) {
			break;
		}
		result = RZ_NEW0(objc_cache_opt_info);
		if (!result) {
			break;
		}
		result->sel_string_base = sel_string_base;
	}
beach:
	return result;
}

static cache_img_t *read_cache_images(RzBuffer *cache_buf, RzDyldCacheHeader *hdr, ut64 hdr_offset) {
	if (!cache_buf || !hdr) {
		return NULL;
	}
	if (!hdr->imagesCount || !hdr->imagesOffset || hdr->imagesOffset == UT32_MAX || hdr->imagesCount == UT32_MAX) {
		return NULL;
	}

	ut64 size = sizeof(cache_img_t) * hdr->imagesCount;
	cache_img_t *images = RZ_NEWS0(cache_img_t, hdr->imagesCount);
	if (!images) {
		return NULL;
	}

	if (rz_buf_fread_at(cache_buf, hdr->imagesOffset, (ut8 *)images, "3l2i", hdr->imagesCount) != size) {
		RZ_FREE(images);
		return NULL;
	}

	if (hdr_offset) {
		ut32 i;
		for (i = 0; i < hdr->imagesCount; i++) {
			cache_img_t *img = &images[i];
			img->pathFileOffset += hdr_offset;
		}
	}

	return images;
}

static void match_bin_entries(RzDyldCache *cache, void *entries) {
	rz_return_if_fail(cache && cache->bins && entries);

	cache_img_t *imgs = read_cache_images(cache->buf, cache->hdr, 0);
	if (!imgs) {
		return;
	}

	RzDyldBinImage *bin = NULL;
	RzListIter *it = rz_list_iterator(cache->bins);

	bool has_large_entries = cache->n_hdr > 1;

	ut32 i;
	for (i = 0; i < cache->hdr->imagesCount; i++) {
		cache_img_t *img = &imgs[i];
		if (!it) {
			break;
		}
		bin = rz_list_iter_get_data(it);
		if (!bin) {
			break;
		}
		if (bin && bin->va == img->address) {
			if (has_large_entries) {
				cache_locsym_entry_large_t *e = &((cache_locsym_entry_large_t *)entries)[i];
				bin->nlist_start_index = e->nlistStartIndex;
				bin->nlist_count = e->nlistCount;
			} else {
				cache_locsym_entry_t *e = &((cache_locsym_entry_t *)entries)[i];
				bin->nlist_start_index = e->nlistStartIndex;
				bin->nlist_count = e->nlistCount;
			}

			it = rz_list_iter_get_next(it);
		}
	}

	RZ_FREE(imgs);
}

static cache_imgxtr_t *read_cache_imgextra(RzBuffer *cache_buf, RzDyldCacheHeader *hdr, cache_accel_t *accel) {
	if (!cache_buf || !hdr || !hdr->imagesCount || !accel || !accel->imageExtrasCount || !accel->imagesExtrasOffset) {
		return NULL;
	}

	ut64 size = sizeof(cache_imgxtr_t) * accel->imageExtrasCount;
	cache_imgxtr_t *images = RZ_NEWS0(cache_imgxtr_t, accel->imageExtrasCount);
	if (!images) {
		return NULL;
	}

	if (rz_buf_fread_at(cache_buf, accel->imagesExtrasOffset, (ut8 *)images, "ll4i", accel->imageExtrasCount) != size) {
		RZ_FREE(images);
		return NULL;
	}

	return images;
}

static char *get_lib_name(RzBuffer *cache_buf, cache_img_t *img) {
	char file[256];
	char *lib_name = file;
	if (rz_buf_read_at(cache_buf, img->pathFileOffset, (ut8 *)file, sizeof(file)) == sizeof(file)) {
		file[255] = 0;
		return strdup(lib_name);
	}
	return strdup("FAIL");
}

static int string_contains(const void *a, const void *b, void *user) {
	return !strstr((const char *)a, (const char *)b);
}

static HtSU *create_path_to_index(RzBuffer *cache_buf, cache_img_t *img, RzDyldCacheHeader *hdr) {
	HtSU *path_to_idx = ht_su_new(HT_STR_DUP);
	if (!path_to_idx) {
		return NULL;
	}
	for (size_t i = 0; i != hdr->imagesCount; i++) {
		char file[256];
		if (rz_buf_read_at(cache_buf, img[i].pathFileOffset, (ut8 *)file, sizeof(file)) != sizeof(file)) {
			continue;
		}
		file[255] = 0;
		ht_su_insert(path_to_idx, file, (ut64)i);
	}

	return path_to_idx;
}

static void carve_deps_at_address(RzDyldCache *cache, cache_img_t *img, HtSU *path_to_idx, ut64 address, int *deps, bool printing) {
	ut64 pa = va2pa(address, cache->n_maps, cache->maps, cache->buf, 0, NULL, NULL);
	if (pa == UT64_MAX) {
		return;
	}
	struct MACH0_(mach_header) mh;
	if (rz_buf_fread_at(cache->buf, pa, (ut8 *)&mh, "8i", 1) != sizeof(struct MACH0_(mach_header))) {
		return;
	}
	if (mh.magic != MH_MAGIC_64 || mh.sizeofcmds == 0) {
		return;
	}
	ut64 cmds_at = pa + sizeof(struct MACH0_(mach_header));
	ut8 *cmds = malloc(mh.sizeofcmds + 1);
	if (!cmds || rz_buf_read_at(cache->buf, cmds_at, cmds, mh.sizeofcmds) != mh.sizeofcmds) {
		goto beach;
	}
	cmds[mh.sizeofcmds] = 0;
	ut8 *cursor = cmds;
	ut8 *end = cmds + mh.sizeofcmds;
	while (cursor < end) {
		ut32 cmd = rz_read_le32(cursor);
		ut32 cmdsize = rz_read_le32(cursor + sizeof(ut32));
		if (cmd == LC_LOAD_DYLIB ||
			cmd == LC_LOAD_WEAK_DYLIB ||
			cmd == LC_REEXPORT_DYLIB ||
			cmd == LC_LOAD_UPWARD_DYLIB) {
			bool found;
			if (cursor + 24 >= end) {
				break;
			}
			const char *key = (const char *)cursor + 24;
			size_t dep_index = (size_t)ht_su_find(path_to_idx, key, &found);
			if (!found || dep_index >= cache->hdr->imagesCount) {
				RZ_LOG_WARN("alien dep '%s'\n", key);
				continue;
			}
			deps[dep_index]++;
			if (printing) {
				RZ_LOG_INFO("-> %s\n", key);
			}
		}
		cursor += cmdsize;
	}

beach:
	free(cmds);
}

static RzList /*<RzDyldBinImage *>*/ *create_cache_bins(RzDyldCache *cache) {
	RzList *bins = rz_list_newf((RzListFree)free_bin);
	if (!bins) {
		return NULL;
	}

	ut16 *dep_array = NULL;
	cache_imgxtr_t *extras = NULL;
	char *target_libs = NULL;
	RzList *target_lib_names = NULL;
	int *deps = NULL;
	target_libs = rz_sys_getenv("RZ_DYLDCACHE_FILTER");
	if (target_libs) {
		target_lib_names = rz_str_split_list(target_libs, ":", 0);
		if (!target_lib_names) {
			rz_list_free(bins);
			return NULL;
		}
		deps = RZ_NEWS0(int, cache->hdr->imagesCount);
		if (!deps) {
			rz_list_free(bins);
			rz_list_free(target_lib_names);
			return NULL;
		}
	}

	ut32 i;
	for (i = 0; i < cache->n_hdr; i++) {
		RzDyldCacheHeader *hdr = &cache->hdr[i];
		ut64 hdr_offset = cache->hdr_offset[i];
		ut64 symbols_off = cache->symbols_off_base - hdr_offset;
		ut32 maps_index = cache->maps_index[i];
		cache_img_t *img = read_cache_images(cache->buf, hdr, hdr_offset);
		if (!img) {
			goto next;
		}

		if (target_libs) {
			HtSU *path_to_idx = NULL;
			size_t dep_array_count = 0;
			if (cache->accel) {
				dep_array_count = cache->accel->depListCount;
				dep_array = RZ_NEWS0(ut16, dep_array_count);
				if (!dep_array) {
					goto next;
				}

				if (rz_buf_fread_at(cache->buf, cache->accel->depListOffset, (ut8 *)dep_array, "s", dep_array_count) != dep_array_count * 2) {
					goto next;
				}

				extras = read_cache_imgextra(cache->buf, hdr, cache->accel);
				if (!extras) {
					goto next;
				}
			} else {
				path_to_idx = create_path_to_index(cache->buf, img, hdr);
			}

			for (ut32 j = 0; j < hdr->imagesCount; j++) {
				bool printing = !deps[j];
				char *lib_name = get_lib_name(cache->buf, &img[j]);
				if (!lib_name) {
					break;
				}
				if (strstr(lib_name, "libobjc.A.dylib")) {
					deps[j]++;
				}
				if (!rz_list_find(target_lib_names, lib_name, string_contains, NULL)) {
					RZ_FREE(lib_name);
					continue;
				}
				if (printing) {
					RZ_LOG_INFO("FILTER: %s\n", lib_name);
				}
				RZ_FREE(lib_name);
				deps[j]++;

				if (extras && dep_array) {
					for (ut32 k = extras[j].dependentsStartArrayIndex;; k++) {
						if (k >= dep_array_count) {
							RZ_LOG_ERROR("dyldcache: depList overflow\n");
							break;
						}
						if (dep_array[k] == 0xffff) {
							break;
						}
						ut16 dep_index = dep_array[k] & 0x7fff;
						if (dep_index >= cache->hdr->imagesCount) {
							RZ_LOG_ERROR("dyldcache: depList contents overflow\n");
							break;
						}
						deps[dep_index]++;

						char *dep_name = get_lib_name(cache->buf, &img[dep_index]);
						if (!dep_name) {
							break;
						}
						if (printing) {
							RZ_LOG_INFO("-> %s\n", dep_name);
						}
						free(dep_name);
					}
				} else if (path_to_idx) {
					carve_deps_at_address(cache, img, path_to_idx, img[j].address, deps, printing);
				}
			}

			ht_su_free(path_to_idx);
			RZ_FREE(dep_array);
			RZ_FREE(extras);
		}

		for (ut32 j = 0; j < hdr->imagesCount; j++) {
			if (deps && !deps[j]) {
				continue;
			}
			ut64 pa = va2pa(img[j].address, hdr->mappingCount, &cache->maps[maps_index], cache->buf, 0, NULL, NULL);
			if (pa == UT64_MAX) {
				continue;
			}
			ut8 magicbytes[4];
			rz_buf_read_at(cache->buf, pa, magicbytes, 4);
			int magic = rz_read_le32(magicbytes);
			switch (magic) {
			case MH_MAGIC_64: {
				char file[256];
				RzDyldBinImage *bin = RZ_NEW0(RzDyldBinImage);
				if (!bin) {
					goto next;
				}
				bin->header_at = pa;
				bin->hdr_offset = hdr_offset;
				bin->symbols_off = symbols_off;
				bin->va = img[j].address;
				if (rz_buf_read_at(cache->buf, img[j].pathFileOffset, (ut8 *)&file, sizeof(file)) == sizeof(file)) {
					file[255] = 0;
					char *last_slash = strrchr(file, '/');
					if (last_slash && *last_slash) {
						if (last_slash > file) {
							char *scan = last_slash - 1;
							while (scan > file && *scan != '/') {
								scan--;
							}
							if (*scan == '/') {
								bin->file = strdup(scan + 1);
							} else {
								bin->file = strdup(last_slash + 1);
							}
						} else {
							bin->file = strdup(last_slash + 1);
						}
					} else {
						bin->file = strdup(file);
					}
				} else {
					bin->file = rz_str_newf("unknown_image_%08" PFMT64x, symbols_off);
				}
				rz_list_append(bins, bin);
				break;
			}
			default:
				RZ_LOG_WARN("Unknown sub-bin\n");
				break;
			}
		}
	next:
		RZ_FREE(dep_array);
		RZ_FREE(extras);
		RZ_FREE(img);
	}
	if (rz_list_empty(bins)) {
		rz_list_free(bins);
		bins = NULL;
	}
	RZ_FREE(deps);
	RZ_FREE(target_libs);
	rz_list_free(target_lib_names);
	return bins;
}

static ut32 dumb_ctzll(ut64 x) {
	ut64 result = 0;
	int i, j;
	for (i = 0; i < 64; i += 8) {
		ut8 byte = (x >> i) & 0xff;
		if (!byte) {
			result += 8;
		} else {
			for (j = 0; j < 8; j++) {
				if (!((byte >> j) & 1)) {
					result++;
				} else {
					break;
				}
			}
			break;
		}
	}
	return result;
}

static ut64 estimate_slide(RzDyldCache *cache, ut64 value_mask, ut64 value_add) {
	ut64 slide = 0;
	if (cache->n_hdr > 1) {
		return slide;
	}
	ut64 *classlist = malloc(64);
	if (!classlist) {
		goto beach;
	}

	RzListIter *iter;
	RzDyldBinImage *bin;
	rz_list_foreach (cache->bins, iter, bin) {
		bool found_sample = false;

		struct MACH0_(opts_t) opts = { 0 };
		opts.header_at = bin->header_at;

		struct MACH0_(obj_t) *mach0 = MACH0_(new_buf)(cache->buf, &opts);
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
		int incomplete = 2;
		int classlist_idx = 0, data_idx = 0;
		for (i = 0; !sections[i].last && incomplete; i++) {
			if (sections[i].size == 0) {
				continue;
			}
			if (strstr(sections[i].name, "__objc_classlist")) {
				incomplete--;
				classlist_idx = i;
				continue;
			}
			if (strstr(sections[i].name, "__objc_data")) {
				incomplete--;
				data_idx = i;
				continue;
			}
		}

		if (incomplete) {
			goto next_bin;
		}

		int classlist_sample_size = RZ_MIN(64, sections[classlist_idx].size);
		int n_classes = classlist_sample_size / 8;
		ut64 sect_offset = sections[classlist_idx].offset + bin->hdr_offset;

		if (rz_buf_fread_at(cache->buf, sect_offset, (ut8 *)classlist, "l", n_classes) < classlist_sample_size) {
			goto next_bin;
		}

		ut64 data_addr = sections[data_idx].addr;
		ut64 data_tail = data_addr & 0xfff;
		ut64 data_tail_end = (data_addr + sections[data_idx].size) & 0xfff;
		for (i = 0; i < n_classes; i++) {
			ut64 cl_addr = (classlist[i] & value_mask) + value_add;
			ut64 cl_tail = cl_addr & 0xfff;
			if (cl_tail >= data_tail && cl_tail < data_tail_end) {
				ut64 off = cl_tail - data_tail;
				slide = ((cl_addr - off) & value_mask) - (data_addr & value_mask);
				found_sample = true;
				break;
			}
		}

	next_bin:
		MACH0_(mach0_free)
		(mach0);
		free(sections);

		if (found_sample) {
			break;
		}
	}

beach:
	free(classlist);
	return slide;
}

static RzDyldRebaseInfo *get_rebase_info(RzDyldCache *cache, ut64 slideInfoOffset, ut64 slideInfoSize, ut64 start_of_data, ut64 slide) {
	ut8 *tmp_buf_1 = NULL;
	ut8 *tmp_buf_2 = NULL;
	ut8 *one_page_buf = NULL;
	RzBuffer *cache_buf = cache->buf;

	ut64 offset = slideInfoOffset;
	ut32 slide_info_version = 0;
	if (!rz_buf_read_le32_at(cache_buf, offset, &slide_info_version)) {
		return NULL;
	}

	if (slide_info_version == 3) {
		cache_slide3_t slide_info;
		ut64 size = sizeof(cache_slide3_t);
		if (rz_buf_fread_at(cache_buf, offset, (ut8 *)&slide_info, "4i1l", 1) < 20) {
			return NULL;
		}

		if (UT32_MUL_OVFCHK(slide_info.page_starts_count, 2) || UT64_ADD_OVFCHK(offset, size)) {
			return NULL;
		}

		ut64 page_starts_offset = offset + size;
		ut64 page_starts_size = slide_info.page_starts_count * 2;

		if (page_starts_size + size > slideInfoSize) {
			return NULL;
		}

		if (page_starts_size > 0) {
			tmp_buf_1 = malloc(page_starts_size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (rz_buf_fread_at(cache_buf, page_starts_offset, tmp_buf_1, "s", slide_info.page_starts_count) != page_starts_size) {
				goto beach;
			}
		}

		if (slide_info.page_size > 0) {
			one_page_buf = malloc(slide_info.page_size);
			if (!one_page_buf) {
				goto beach;
			}
		}

		RzDyldRebaseInfo3 *rebase_info = RZ_NEW0(RzDyldRebaseInfo3);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 3;
		rebase_info->delta_mask = 0x3ff8000000000000ULL;
		rebase_info->delta_shift = 51;
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16 *)tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->auth_value_add = slide_info.auth_value_add;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide(cache, 0x7ffffffffffffULL, 0);
			if (rebase_info->slide) {
				RZ_LOG_INFO("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RzDyldRebaseInfo *)rebase_info;
	} else if (slide_info_version == 2 || slide_info_version == 4) {
		cache_slide2_t slide_info;
		ut64 size = sizeof(cache_slide2_t);
		if (rz_buf_fread_at(cache_buf, offset, (ut8 *)&slide_info, "6i2l", 1) != size) {
			return NULL;
		}

		if (slide_info.page_starts_offset == 0 ||
			slide_info.page_starts_offset > slideInfoSize ||
			slide_info.page_starts_offset + slide_info.page_starts_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.page_extras_offset == 0 ||
			slide_info.page_extras_offset > slideInfoSize ||
			slide_info.page_extras_offset + slide_info.page_extras_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.page_starts_count > 0) {
			ut64 size = slide_info.page_starts_count * 2;
			ut64 at = slideInfoOffset + slide_info.page_starts_offset;
			tmp_buf_1 = malloc(size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (rz_buf_fread_at(cache_buf, at, tmp_buf_1, "s", slide_info.page_starts_count) != size) {
				goto beach;
			}
		}

		if (slide_info.page_extras_count > 0) {
			ut64 size = slide_info.page_extras_count * 2;
			ut64 at = slideInfoOffset + slide_info.page_extras_offset;
			tmp_buf_2 = malloc(size);
			if (!tmp_buf_2) {
				goto beach;
			}
			if (rz_buf_fread_at(cache_buf, at, tmp_buf_2, "s", slide_info.page_extras_count) != size) {
				goto beach;
			}
		}

		if (slide_info.page_size > 0) {
			one_page_buf = malloc(slide_info.page_size);
			if (!one_page_buf) {
				goto beach;
			}
		}

		RzDyldRebaseInfo2 *rebase_info = RZ_NEW0(RzDyldRebaseInfo2);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = slide_info_version;
		rebase_info->start_of_data = start_of_data;
		rebase_info->page_starts = (ut16 *)tmp_buf_1;
		rebase_info->page_starts_count = slide_info.page_starts_count;
		rebase_info->page_extras = (ut16 *)tmp_buf_2;
		rebase_info->page_extras_count = slide_info.page_extras_count;
		rebase_info->value_add = slide_info.value_add;
		rebase_info->delta_mask = slide_info.delta_mask;
		rebase_info->value_mask = ~rebase_info->delta_mask;
		rebase_info->delta_shift = dumb_ctzll(rebase_info->delta_mask) - 2;
		rebase_info->page_size = slide_info.page_size;
		rebase_info->one_page_buf = one_page_buf;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide(cache, rebase_info->value_mask, rebase_info->value_add);
			if (rebase_info->slide) {
				RZ_LOG_INFO("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RzDyldRebaseInfo *)rebase_info;
	} else if (slide_info_version == 1) {
		cache_slide1_t slide_info;
		ut64 size = sizeof(cache_slide1_t);
		if (rz_buf_fread_at(cache_buf, offset, (ut8 *)&slide_info, "6i", 1) != size) {
			return NULL;
		}

		if (slide_info.toc_offset == 0 ||
			slide_info.toc_offset > slideInfoSize ||
			slide_info.toc_offset + slide_info.toc_count * 2 > slideInfoSize) {
			return NULL;
		}

		if (slide_info.entries_offset == 0 ||
			slide_info.entries_offset > slideInfoSize ||
			slide_info.entries_offset + slide_info.entries_count * slide_info.entries_size > slideInfoSize) {
			return NULL;
		}

		if (slide_info.toc_count > 0) {
			ut64 size = slide_info.toc_count * 2;
			ut64 at = slideInfoOffset + slide_info.toc_offset;
			tmp_buf_1 = malloc(size);
			if (!tmp_buf_1) {
				goto beach;
			}
			if (rz_buf_fread_at(cache_buf, at, tmp_buf_1, "s", slide_info.toc_count) != size) {
				goto beach;
			}
		}

		if (slide_info.entries_count > 0) {
			ut64 size = (ut64)slide_info.entries_count * (ut64)slide_info.entries_size;
			ut64 at = slideInfoOffset + slide_info.entries_offset;
			tmp_buf_2 = malloc(size);
			if (!tmp_buf_2) {
				goto beach;
			}
			if (rz_buf_read_at(cache_buf, at, tmp_buf_2, size) != size) {
				goto beach;
			}
		}

		one_page_buf = malloc(4096);
		if (!one_page_buf) {
			goto beach;
		}

		RzDyldRebaseInfo1 *rebase_info = RZ_NEW0(RzDyldRebaseInfo1);
		if (!rebase_info) {
			goto beach;
		}

		rebase_info->version = 1;
		rebase_info->start_of_data = start_of_data;
		rebase_info->one_page_buf = one_page_buf;
		rebase_info->page_size = 4096;
		rebase_info->toc = (ut16 *)tmp_buf_1;
		rebase_info->toc_count = slide_info.toc_count;
		rebase_info->entries = tmp_buf_2;
		rebase_info->entries_size = slide_info.entries_size;
		if (slide == UT64_MAX) {
			rebase_info->slide = estimate_slide(cache, UT64_MAX, 0);
			if (rebase_info->slide) {
				RZ_LOG_INFO("dyldcache is slid: 0x%" PFMT64x "\n", rebase_info->slide);
			}
		} else {
			rebase_info->slide = slide;
		}

		return (RzDyldRebaseInfo *)rebase_info;
	} else {
		RZ_LOG_ERROR("Unsupported slide info version %d\n", slide_info_version);
		return NULL;
	}

beach:
	free(tmp_buf_1);
	free(tmp_buf_2);
	free(one_page_buf);
	return NULL;
}

static RzDyldRebaseInfos *get_rebase_infos(RzDyldCache *cache) {
	RzDyldRebaseInfos *result = RZ_NEW0(RzDyldRebaseInfos);
	if (!result) {
		return NULL;
	}

	if (!cache->hdr->slideInfoOffset || !cache->hdr->slideInfoSize) {
		size_t total_slide_infos = 0;
		ut32 n_slide_infos[MAX_N_HDR];

		ut32 i;
		for (i = 0; i < cache->n_hdr && i < MAX_N_HDR; i++) {
			ut64 hdr_offset = cache->hdr_offset[i];
			if (!rz_buf_read_le32_at(cache->buf, 0x13c + hdr_offset, &n_slide_infos[i])) {
				goto beach;
			}
			ut32 total = total_slide_infos + n_slide_infos[i];
			if (total < total_slide_infos) {
				// overflow
				goto beach;
			}
			total_slide_infos = total;
		}

		if (!total_slide_infos) {
			goto beach;
		}

		RzDyldRebaseInfosEntry *infos = RZ_NEWS0(RzDyldRebaseInfosEntry, total_slide_infos);
		if (!infos) {
			goto beach;
		}

		ut32 k = 0;
		for (i = 0; i < cache->n_hdr && i < MAX_N_HDR; i++) {
			ut64 hdr_offset = cache->hdr_offset[i];
			if (!n_slide_infos[i]) {
				continue;
			}
			ut32 sio;
			if (!rz_buf_read_le32_at(cache->buf, 0x138 + hdr_offset, &sio)) {
				continue;
			}
			ut64 slide_infos_offset = sio;
			if (!slide_infos_offset) {
				continue;
			}
			slide_infos_offset += hdr_offset;

			ut32 j;
			RzDyldRebaseInfo *prev_info = NULL;
			for (j = 0; j < n_slide_infos[i]; j++) {
				ut64 offset = slide_infos_offset + j * sizeof(cache_mapping_slide);
				cache_mapping_slide entry;
				if (rz_buf_fread_at(cache->buf, offset, (ut8 *)&entry, "6lii", 1) != sizeof(cache_mapping_slide)) {
					break;
				}

				if (entry.slideInfoOffset && entry.slideInfoSize) {
					infos[k].start = entry.fileOffset + hdr_offset;
					infos[k].end = infos[k].start + entry.size;
					ut64 slide = prev_info ? prev_info->slide : UT64_MAX;
					infos[k].info = get_rebase_info(cache, entry.slideInfoOffset + hdr_offset, entry.slideInfoSize, entry.fileOffset + hdr_offset, slide);
					prev_info = infos[k].info;
					k++;
				}
			}
		}

		if (!k) {
			free(infos);
			goto beach;
		}

		if (k < total_slide_infos) {
			RzDyldRebaseInfosEntry *pruned_infos = RZ_NEWS0(RzDyldRebaseInfosEntry, k);
			if (!pruned_infos) {
				free(infos);
				goto beach;
			}

			memcpy(pruned_infos, infos, sizeof(RzDyldRebaseInfosEntry) * k);
			free(infos);
			infos = pruned_infos;
		}

		result->entries = infos;
		result->length = k;
		return result;
	}

	if (cache->hdr->mappingCount > 1) {
		RzDyldRebaseInfosEntry *infos = RZ_NEWS0(RzDyldRebaseInfosEntry, 1);
		if (!infos) {
			goto beach;
		}

		infos[0].start = cache->maps[1].fileOffset;
		infos[0].end = infos[0].start + cache->maps[1].size;
		infos[0].info = get_rebase_info(cache, cache->hdr->slideInfoOffset, cache->hdr->slideInfoSize, infos[0].start, UT64_MAX);

		result->entries = infos;
		result->length = 1;
		return result;
	}

beach:
	free(result);
	return NULL;
}

RZ_API ut64 rz_dyldcache_get_slide(RzDyldCache *cache) {
	rz_return_val_if_fail(cache, 0);
	if (!cache->rebase_infos || !cache->rebase_infos->length) {
		return 0;
	}

	size_t i;
	for (i = 0; i < cache->rebase_infos->length; i++) {
		if (cache->rebase_infos->entries[i].info) {
			return cache->rebase_infos->entries[i].info->slide;
		}
	}

	return 0;
}

RZ_API void rz_dyldcache_symbols_from_locsym(RzDyldCache *cache, RzDyldBinImage *bin, RzPVector /*<RzBinSymbol *>*/ *symbols, RzSetU *hash) {
	RzDyldLocSym *locsym = cache->locsym;
	if (!locsym) {
		return;
	}

	if (bin->nlist_start_index >= locsym->nlists_count ||
		bin->nlist_start_index + bin->nlist_count > locsym->nlists_count) {
		RZ_LOG_ERROR("dyldcache: malformed local symbol entry\n");
		return;
	}

	ut64 nlists_size = sizeof(struct MACH0_(nlist)) * bin->nlist_count;
	struct MACH0_(nlist) *nlists = RZ_NEWS0(struct MACH0_(nlist), bin->nlist_count);
	if (!nlists) {
		return;
	}
	ut64 nlists_offset = locsym->local_symbols_offset + locsym->nlists_offset +
		bin->nlist_start_index * sizeof(struct MACH0_(nlist));
	if (rz_buf_fread_at(cache->buf, nlists_offset, (ut8 *)nlists, "iccsl", bin->nlist_count) != nlists_size) {
		free(nlists);
		return;
	}

	ut32 j;
	for (j = 0; j != bin->nlist_count; j++) {
		struct MACH0_(nlist) *nlist = &nlists[j];
		if (rz_set_u_contains(hash, (ut64)nlist->n_value)) {
			continue;
		}
		rz_set_u_add(hash, (ut64)nlist->n_value);
		if (nlist->n_strx >= locsym->strings_size) {
			continue;
		}
		RzBinSymbol *sym = RZ_NEW0(RzBinSymbol);
		if (!sym) {
			break;
		}
		sym->type = "LOCAL";
		sym->vaddr = nlist->n_value;
		ut64 slide = rz_dyldcache_get_slide(cache);
		sym->paddr = va2pa(nlist->n_value, cache->n_maps, cache->maps, cache->buf, slide, NULL, NULL);

		char *symstr = rz_buf_get_string(cache->buf, locsym->local_symbols_offset + locsym->strings_offset + nlist->n_strx);
		if (symstr) {
			sym->name = symstr;
		} else {
			sym->name = rz_str_newf("unk_local%" PFMT32u, cache->unk_local_n);
			cache->unk_local_n++;
		}

		rz_pvector_push(symbols, sym);
	}

	free(nlists);
}

RZ_API RzDyldCache *rz_dyldcache_new_buf(RzBuffer *buf) {
	RzDyldCache *cache = RZ_NEW0(RzDyldCache);
	if (!cache) {
		return NULL;
	}
	memcpy(cache->magic, "dyldcac", 7);
	cache->buf = rz_buf_ref(buf);
	populate_cache_headers(cache);
	if (!cache->hdr) {
		goto cupertino;
	}
	populate_cache_maps(cache);
	if (!cache->maps) {
		goto cupertino;
	}
	cache->accel = read_cache_accel(cache->buf, cache->hdr, cache->maps, cache->n_maps);
	cache->bins = create_cache_bins(cache);
	if (!cache->bins) {
		goto cupertino;
	}
	cache->locsym = rz_dyld_locsym_new(cache);
	cache->rebase_infos = get_rebase_infos(cache);
	cache->unk_local_n = 0;
	return cache;
cupertino:
	rz_dyldcache_free(cache);
	return NULL;
}

static void rebase_info3_free(RzDyldRebaseInfo3 *rebase_info) {
	if (!rebase_info) {
		return;
	}
	free(rebase_info->page_starts);
	free(rebase_info);
}

static void rebase_info2_free(RzDyldRebaseInfo2 *rebase_info) {
	if (!rebase_info) {
		return;
	}
	free(rebase_info->page_starts);
	free(rebase_info->page_extras);
	free(rebase_info);
}

static void rebase_info1_free(RzDyldRebaseInfo1 *rebase_info) {
	if (!rebase_info) {
		return;
	}
	free(rebase_info->toc);
	free(rebase_info->entries);
	free(rebase_info);
}

static void rebase_info_free(RzDyldRebaseInfo *rebase_info) {
	if (!rebase_info) {
		return;
	}

	RZ_FREE(rebase_info->one_page_buf);

	ut8 version = rebase_info->version;

	if (version == 1) {
		rebase_info1_free((RzDyldRebaseInfo1 *)rebase_info);
	} else if (version == 2 || version == 4) {
		rebase_info2_free((RzDyldRebaseInfo2 *)rebase_info);
	} else if (version == 3) {
		rebase_info3_free((RzDyldRebaseInfo3 *)rebase_info);
	} else {
		free(rebase_info);
	}
}

static RzDyldLocSym *rz_dyld_locsym_new(RzDyldCache *cache) {
	rz_return_val_if_fail(cache && cache->buf, NULL);

	ut32 i;
	for (i = 0; i < cache->n_hdr; i++) {
		RzDyldCacheHeader *hdr = &cache->hdr[i];
		if (!hdr || !hdr->localSymbolsSize || !hdr->localSymbolsOffset) {
			continue;
		}

		cache_locsym_info_t *info = NULL;
		void *entries = NULL;

		ut64 info_size = sizeof(cache_locsym_info_t);
		info = RZ_NEW0(cache_locsym_info_t);
		if (!info) {
			goto beach;
		}
		if (rz_buf_fread_at(cache->buf, hdr->localSymbolsOffset, (ut8 *)info, "6i", 1) != info_size) {
			RZ_LOG_ERROR("Cannot read cache_locsym_info_t from header\n");
			goto beach;
		}
		if (info->entriesCount != cache->hdr->imagesCount) {
			RZ_LOG_ERROR("The number of entries count differs from cache header image count\n");
			goto beach;
		}

		bool has_large_entries = cache->n_hdr > 1;
		if (has_large_entries) {
			ut64 entries_size = sizeof(cache_locsym_entry_large_t) * info->entriesCount;
			cache_locsym_entry_large_t *large_entries = RZ_NEWS0(cache_locsym_entry_large_t, info->entriesCount);
			if (!large_entries) {
				goto beach;
			}
			if (rz_buf_fread_at(cache->buf, hdr->localSymbolsOffset + info->entriesOffset, (ut8 *)large_entries, "lii",
				    info->entriesCount) != entries_size) {
				RZ_LOG_ERROR("Cannot read cache_locsym_entry_large_t\n");
				goto beach;
			}
			entries = large_entries;
		} else {
			ut64 entries_size = sizeof(cache_locsym_entry_t) * info->entriesCount;
			cache_locsym_entry_t *regular_entries = RZ_NEWS0(cache_locsym_entry_t, info->entriesCount);
			if (!regular_entries) {
				goto beach;
			}
			if (rz_buf_fread_at(cache->buf, hdr->localSymbolsOffset + info->entriesOffset, (ut8 *)regular_entries, "iii",
				    info->entriesCount) != entries_size) {
				RZ_LOG_ERROR("Cannot read cache_locsym_entry_t\n");
				goto beach;
			}
			entries = regular_entries;
		}
		RzDyldLocSym *locsym = RZ_NEW0(RzDyldLocSym);
		if (!locsym) {
			goto beach;
		}

		match_bin_entries(cache, entries);

		locsym->local_symbols_offset = hdr->localSymbolsOffset;
		locsym->nlists_offset = info->nlistOffset;
		locsym->nlists_count = info->nlistCount;
		locsym->strings_offset = info->stringsOffset;
		locsym->strings_size = info->stringsSize;

		free(info);
		free(entries);

		return locsym;

	beach:
		free(info);
		free(entries);

		RZ_LOG_ERROR("dyldcache: malformed local symbols metadata\n");
		break;
	}
	return NULL;
}

RZ_API void rz_dyldcache_free(RzDyldCache *cache) {
	if (!cache) {
		return;
	}

	rz_list_free(cache->bins);
	cache->bins = NULL;
	rz_buf_free(cache->buf);
	cache->buf = NULL;
	if (cache->rebase_infos) {
		int i;
		for (i = 0; i < cache->rebase_infos->length; i++) {
			rebase_info_free(cache->rebase_infos->entries[i].info);
			cache->rebase_infos->entries[i].info = NULL;
		}
		RZ_FREE(cache->rebase_infos->entries);
		RZ_FREE(cache->rebase_infos);
	}
	free(cache->hdr);
	free(cache->maps);
	free(cache->maps_index);
	free(cache->hdr_offset);
	free(cache->accel);
	free(cache->locsym);
	free(cache->oi);
	free(cache);
}

RZ_API ut64 rz_dyldcache_va2pa(RzDyldCache *cache, uint64_t vaddr, ut32 *offset, ut32 *left) {
	rz_return_val_if_fail(cache, UT64_MAX);
	ut64 slide = rz_dyldcache_get_slide(cache);
	ut64 res = va2pa(vaddr, cache->n_maps, cache->maps, cache->buf, slide, offset, left);
	if (res == UT64_MAX) {
		res = 0;
	}
	return res;
}
