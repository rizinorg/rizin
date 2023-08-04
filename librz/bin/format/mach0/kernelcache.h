// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_FORMAT_KERNELCACHE_H
#define RZ_BIN_FORMAT_KERNELCACHE_H

#define RZ_BIN_MACH064 1

#include "mach0.h"

#include "../xnu/rz_cf_dict.h"

typedef struct rz_xnu_kernelcache_file_range_t {
	ut64 offset;
	ut64 size;
} RzXNUKernelCacheFileRange;

typedef struct rz_xnu_kernelcache_rebase_info_t {
	RzXNUKernelCacheFileRange *ranges;
	ut64 n_ranges;
	ut64 multiplier;
	ut64 kernel_base;
} RzXNUKernelCacheRebaseInfo;

typedef struct rz_xnu_kernelcache_parsed_pointer_t {
	ut64 address;
} RzXNUKernelCacheParsedPointer;

typedef struct rz_xnu_kernelcache_obj_t {
	RzBuffer *cache_buf;
	RzBuffer *patched_buf;
	RzCFValueDict *prelink_info;
	ut64 pa2va_exec;
	ut64 pa2va_data;
	struct _RKextIndex *kexts;
	struct MACH0_(obj_t) * mach0;
	RzXNUKernelCacheRebaseInfo *rebase_info;
	int (*original_io_read)(RzIO *io, RzIODesc *fd, ut8 *buf, int count);
	bool rebase_info_populated;
	bool kexts_initialized;
} RzXNUKernelCacheObj;

RZ_API bool rz_xnu_kernelcache_buf_is_kernelcache(RzBuffer *b);
RZ_API RzBuffer *rz_xnu_kernelcache_new_patched_buf(RzXNUKernelCacheObj *obj);
RZ_API bool rz_xnu_kernelcache_needs_rebasing(RzXNUKernelCacheObj *obj);
RZ_API bool rz_xnu_kernelcache_parse_pointer(RzXNUKernelCacheParsedPointer *ptr, ut64 decorated_addr, RzXNUKernelCacheObj *obj);

#endif
