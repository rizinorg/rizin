// SPDX-FileCopyrightText: 2009-2010 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include "mach0_specs.h"

#ifndef _INCLUDE_R_BIN_DYLDCACHE_H_
#define _INCLUDE_R_BIN_DYLDCACHE_H_

struct rz_bin_dyldcache_obj_t {
	const char *file;
	int size;
	int nlibs;
	struct cache_header hdr;
	RzBuffer *b;
};

struct rz_bin_dyldcache_lib_t {
	char path[1024];
	int size;
	ut64 offset;
	RzBuffer *b;
	int last;
};

struct dyld_cache_mapping_info {
	ut64 address;
	ut64 size;
	ut64 fileOffset;
	ut32 maxProt;
	ut32 initProt;
};

struct dyld_cache_image_info {
	ut64 address;
	ut64 modTime;
	ut64 inode;
	ut32 pathFileOffset;
	ut32 pad;
};

struct dyld_cache_slide_info {
	ut32 version;
	ut32 toc_offset;
	ut32 toc_count;
	ut32 entries_offset;
	ut32 entries_count;
	ut32 entries_size;
};

typedef struct _dyld_cache_local_symbols_info {
	ut32 nlistOffset;
	ut32 nlistCount;
	ut32 stringsOffset;
	ut32 stringsSize;
	ut32 entriesOffset;
	ut32 entriesCount;
} dyld_cache_local_symbols_info;

typedef struct _dyld_cache_local_symbols_entry {
	ut32 dylibOffset;
	ut32 nlistStartIndex;
	ut32 nlistCount;
} dyld_cache_local_symbols_entry;

struct rz_bin_dyldcache_lib_t *rz_bin_dyldcache_extract(struct rz_bin_dyldcache_obj_t *bin, int idx, int *nlib);
void *rz_bin_dyldcache_free(struct rz_bin_dyldcache_obj_t *bin);
struct rz_bin_dyldcache_obj_t *rz_bin_dyldcache_new(const char *file);
struct rz_bin_dyldcache_obj_t *rz_bin_dyldcache_from_bytes_new(const ut8 *bytes, ut64 size);
void rz_bin_dydlcache_get_libname(struct rz_bin_dyldcache_lib_t *lib, char **libname);

#endif
