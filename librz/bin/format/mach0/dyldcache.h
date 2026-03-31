// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_FORMAT_DYLDCACHE_H
#define RZ_BIN_FORMAT_DYLDCACHE_H

#include <rz_util.h>
#include <rz_util/rz_set.h>

#define RZ_BIN_MACH064 1

#include "mach0.h"

typedef struct rz_dyld_cache_header_t {
	char magic[16];
	ut32 mappingOffset;
	ut32 mappingCount;
	ut32 imagesOffset;
	ut32 imagesCount;
	ut64 dyldBaseAddress;
	ut64 codeSignatureOffset;
	ut64 codeSignatureSize;
	ut64 slideInfoOffset;
	ut64 slideInfoSize;
	ut64 localSymbolsOffset;
	ut64 localSymbolsSize;
	ut8 uuid[16];
	ut64 cacheType;
	ut32 branchPoolsOffset;
	ut32 branchPoolsCount;
	union {
		struct {
			ut64 accelerateInfoAddr;
			ut64 accelerateInfoSize;
		}; ///< used if rz_dyldcache_header_may_have_accel() == true
		struct {
			ut64 dyldInCacheMH;
			ut64 dyldInCacheEntry;
		}; ///< used if rz_dyldcache_header_may_have_accel() == false
	};
	ut64 imagesTextOffset;
	ut64 imagesTextCount;
	ut64 patchInfoAddr;
	ut64 patchInfoSize;
	ut64 otherImageGroupAddrUnused;
	ut64 otherImageGroupSizeUnused;
	ut64 progClosuresAddr;
	ut64 progClosuresSize;
	ut64 progClosuresTrieAddr;
	ut64 progClosuresTrieSize;
	ut32 platform;
	ut32 formatVersion : 8,
		dylibsExpectedOnDisk : 1,
		simulator : 1,
		locallyBuiltCache : 1,
		builtFromChainedFixups : 1,
		padding : 20;
	ut64 sharedRegionStart;
	ut64 sharedRegionSize;
	ut64 maxSlide;
	ut64 dylibsImageArrayAddr;
	ut64 dylibsImageArraySize;
	ut64 dylibsTrieAddr;
	ut64 dylibsTrieSize;
	ut64 otherImageArrayAddr;
	ut64 otherImageArraySize;
	ut64 otherTrieAddr;
	ut64 otherTrieSize;
	ut32 mappingWithSlideOffset;
	ut32 mappingWithSlideCount;

	// offset = 0x140

	// below added in dyld-940
	ut64 dylibsPBLStateArrayAddrUnused;
	ut64 dylibsPBLSetAddr;
	ut64 programsPBLSetPoolAddr;
	ut64 programsPBLSetPoolSize;
	ut64 programTrieAddr;
	ut32 programTrieSize;
	ut32 osVersion;
	ut32 altPlatform;
	ut32 altOsVersion;
	ut64 swiftOptsOffset;
	ut64 swiftOptsSize;
	ut32 subCacheArrayOffset;
	ut32 subCacheArrayCount;
	ut8 symbolFileUUID[16];
	ut64 rosettaReadOnlyAddr;
	ut64 rosettaReadOnlySize;
	ut64 rosettaReadWriteAddr;
	ut64 rosettaReadWriteSize;
	// ut32 imagesOffset; (consolidated with imageOffset above)
	// ut32 imagesCount; (consolidated with imagesCount above)

	// offset = 0x1c8

	// below added in dyld-1042.1
	ut32 cacheSubType;
	ut64 objcOptsOffset;
	ut64 objcOptsSize;
	ut64 cacheAtlasOffset;
	ut64 cacheAtlasSize;
	ut64 dynamicDataOffset;
	ut64 dynamicDataMaxSize;
	// offset = 0x200
} RzDyldCacheHeader;

typedef enum rz_dyld_cache_header_version {
	RZ_DYLD_CACHE_HEADER_BEFORE_940,
	RZ_DYLD_CACHE_HEADER_940_OR_AFTER,
	RZ_DYLD_CACHE_HEADER_1042_1_OR_AFTER
} RzDyldCacheHeaderVersion;

/**
 * Guess the dyld version that \p hdr was created from
 */
static inline RzDyldCacheHeaderVersion rz_dyldcache_header_version(RzDyldCacheHeader *hdr) {
	// Fields were added during different dyld versions, so we can use the size of the header to guess
	// the version. Even though there is no explicit header size field, mappingOffset is usually directly
	// after the header, so we use this to measure size.
	if (hdr->mappingOffset < 0x1c8) {
		return RZ_DYLD_CACHE_HEADER_BEFORE_940;
	} else if (hdr->mappingOffset < 0x200) {
		return RZ_DYLD_CACHE_HEADER_940_OR_AFTER;
	} else {
		return RZ_DYLD_CACHE_HEADER_1042_1_OR_AFTER;
	}
}

/**
 * Determine if the accelerateInfoAddr/accelerateInfoSize fields are available in the header,
 * as opposed to dyldInCacheMH/dyldInCacheEntry
 */
static inline bool rz_dyldcache_header_may_have_accel(RzDyldCacheHeader *hdr) {
	return rz_dyldcache_header_version(hdr) < RZ_DYLD_CACHE_HEADER_1042_1_OR_AFTER;
}

typedef struct rz_dyld_rebase_info_t {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
} RzDyldRebaseInfo;

typedef struct rz_dyld_rebase_infos_entry_t {
	ut64 start;
	ut64 end;
	RzDyldRebaseInfo *info;
} RzDyldRebaseInfosEntry;

typedef struct rz_dyld_rebase_infos_t {
	RzDyldRebaseInfosEntry *entries;
	size_t length;
} RzDyldRebaseInfos;

typedef struct rz_dyld_rebase_info_3_t {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut64 delta_mask;
	ut32 delta_shift;
	ut64 auth_value_add;
} RzDyldRebaseInfo3;

typedef struct rz_dyld_rebase_info_2_t {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *page_starts;
	ut32 page_starts_count;
	ut16 *page_extras;
	ut32 page_extras_count;
	ut64 delta_mask;
	ut64 value_mask;
	ut32 delta_shift;
	ut64 value_add;
} RzDyldRebaseInfo2;

typedef struct rz_dyld_rebase_info_1_t {
	ut8 version;
	ut64 slide;
	ut8 *one_page_buf;
	ut32 page_size;
	ut64 start_of_data;
	ut16 *toc;
	ut32 toc_count;
	ut8 *entries;
	ut32 entries_size;
} RzDyldRebaseInfo1;

typedef struct rz_dyld_loc_sym_t {
	ut64 local_symbols_offset;
	ut64 nlists_offset;
	ut64 nlists_count;
	ut64 strings_offset;
	ut64 strings_size;
} RzDyldLocSym;

typedef struct rz_bin_dyld_image_t {
	char *file;
	ut64 header_at;
	ut64 hdr_offset;
	ut64 symbols_off;
	ut64 va;
	ut32 nlist_start_index;
	ut32 nlist_count;
} RzDyldBinImage;

typedef struct rz_dyldcache_t {
	ut8 magic[8];

	RzDyldCacheHeader *hdr;
	ut64 *hdr_offset;
	ut64 symbols_off_base;
	ut32 *maps_index;
	ut32 n_hdr;
	cache_map_t *maps;
	ut32 n_maps;

	RzList /*<RzDyldBinImage *>*/ *bins;
	RzBuffer *buf;
	RzDyldRebaseInfos *rebase_infos;
	cache_accel_t *accel;
	RzDyldLocSym *locsym;
	objc_cache_opt_info *oi;
	bool objc_opt_info_loaded;
	ut32 unk_local_n;
} RzDyldCache;

RZ_API bool rz_dyldcache_check_magic(const char *magic);
RZ_API RzDyldCache *rz_dyldcache_new_buf(RzBuffer *buf);
RZ_API void rz_dyldcache_free(RzDyldCache *cache);
RZ_API RZ_NONNULL const char *rz_dyldcache_get_platform_str(RzDyldCache *cache);
RZ_API RZ_NONNULL const char *rz_dyldcache_get_type_str(RzDyldCache *cache);
RZ_API ut64 rz_dyldcache_va2pa(RzDyldCache *cache, uint64_t vaddr, ut32 *offset, ut32 *left);
RZ_API ut64 rz_dyldcache_get_slide(RzDyldCache *cache);
RZ_API objc_cache_opt_info *rz_dyldcache_get_objc_opt_info(RzBinFile *bf, RzDyldCache *cache);
RZ_API void rz_dyldcache_symbols_from_locsym(RzDyldCache *cache, RzDyldBinImage *bin, RzPVector /*<RzBinSymbol *>*/ *symbols, RzSetU *hash);

RZ_API RzBuffer *rz_dyldcache_new_rebasing_buf(RzDyldCache *cache);
RZ_API bool rz_dyldcache_needs_rebasing(RzDyldCache *cache);
RZ_API bool rz_dyldcache_range_needs_rebasing(RzDyldCache *cache, ut64 paddr, ut64 size);

#endif
