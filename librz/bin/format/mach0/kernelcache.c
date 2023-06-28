// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019-2020 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "kernelcache.h"

typedef bool (*OnRebaseFunc)(ut64 offset, ut64 decorated_addr, void *user_data);
static ut64 rebase_offset_to_paddr(RzXNUKernelCacheObj *obj, struct section_t *sections, ut64 offset);
static ut64 iterate_rebase_list(RzBuffer *cache_buf, ut64 multiplier, ut64 start_offset, OnRebaseFunc func, void *user_data);
static bool on_rebase_pointer(ut64 offset, ut64 decorated_addr, void *user);

RZ_API bool rz_xnu_kernelcache_buf_is_kernelcache(RzBuffer *b) {
	ut64 length = rz_buf_size(b);
	if (length < sizeof(struct MACH0_(mach_header))) {
		return false;
	}
	ut32 cputype;
	if (!rz_buf_read_le32_at(b, 4, &cputype)) {
		return false;
	}
	if (cputype != CPU_TYPE_ARM64) {
		return false;
	}
	ut32 filetype;
	if (!rz_buf_read_le32_at(b, 12, &filetype)) {
		return false;
	}
	if (filetype == MH_FILESET) {
		return true;
	}
	ut32 flags;
	if (!rz_buf_read_le32_at(b, 24, &flags)) {
		return false;
	}
	if (!(flags & MH_PIE)) {
		return false;
	}
	ut32 ncmds;
	if (!rz_buf_read_le32_at(b, 16, &ncmds)) {
		return false;
	}
	bool has_unixthread = false;
	bool has_negative_vaddr = false;
	bool has_kext = false;

	ut32 cursor = sizeof(struct MACH0_(mach_header));
	for (size_t i = 0; i < ncmds && cursor < length; i++) {

		ut32 cmdtype;
		if (!rz_buf_read_le32_at(b, cursor, &cmdtype)) {
			return false;
		}

		ut32 cmdsize;
		if (!rz_buf_read_le32_at(b, cursor + 4, &cmdsize)) {
			return false;
		}

		switch (cmdtype) {
		case LC_KEXT:
			has_kext = true;
			break;
		case LC_UNIXTHREAD:
			has_unixthread = true;
			break;
		case LC_LOAD_DYLIB:
		case LC_LOAD_WEAK_DYLIB:
		case LC_LAZY_LOAD_DYLIB:
			return false;
		case LC_SEGMENT_64: {
			if (has_negative_vaddr) {
				break;
			}
			ut64 tmp;
			if (!rz_buf_read_le64_at(b, cursor + 24, &tmp)) {
				return false;
			}

			st64 vmaddr = convert_to_two_complement_64(tmp);
			if (vmaddr < 0) {
				has_negative_vaddr = true;
			}
		} break;
		}

		cursor += cmdsize;
	}

	return has_kext || (has_unixthread && has_negative_vaddr);
}

static ut64 iterate_rebase_list(RzBuffer *cache_buf, ut64 multiplier, ut64 start_offset, OnRebaseFunc func, void *user_data) {
	ut8 bytes[8];
	ut64 cursor = start_offset;

	while (true) {
		if (rz_buf_read_at(cache_buf, cursor, bytes, 8) < 8) {
			return UT64_MAX;
		}

		ut64 decorated_addr = rz_read_le64(bytes);

		if (func) {
			bool carry_on = func(cursor, decorated_addr, user_data);
			if (!carry_on) {
				break;
			}
		}

		ut64 delta = ((decorated_addr >> 51) & 0x7ff) * multiplier;
		if (delta == 0) {
			break;
		}
		cursor += delta;
	}

	return cursor;
}

static void rebase_info_populate(RzXNUKernelCacheRebaseInfo *info, RzXNUKernelCacheObj *obj) {
	struct section_t *sections = NULL;
	int i = 0;

	if (obj->rebase_info_populated) {
		return;
	}
	obj->rebase_info_populated = true;

	for (; i < info->n_ranges; i++) {
		if (info->ranges[i].size != UT64_MAX) {
			goto cleanup;
		} else if (sections == NULL) {
			if (!(sections = MACH0_(get_sections)(obj->mach0))) {
				return;
			}
		}
		info->ranges[i].offset = rebase_offset_to_paddr(obj, sections, info->ranges[i].offset);
		ut64 end = iterate_rebase_list(obj->cache_buf, info->multiplier, info->ranges[i].offset, NULL, NULL);
		if (end != UT64_MAX) {
			info->ranges[i].size = end - info->ranges[i].offset + 8;
		} else {
			info->ranges[i].size = 0;
		}
	}

cleanup:
	RZ_FREE(sections);
}

static ut64 rebase_offset_to_paddr(RzXNUKernelCacheObj *obj, struct section_t *sections, ut64 offset) {
	ut64 vaddr = obj->rebase_info->kernel_base + offset;
	int i = 0;
	for (; !sections[i].last; i++) {
		if (sections[i].addr <= vaddr && vaddr < (sections[i].addr + sections[i].vsize)) {
			return sections[i].offset + (vaddr - sections[i].addr);
		}
	}
	return offset;
}

typedef struct {
	ut64 eob;
	RzBuffer *dst;
	RzXNUKernelCacheObj *obj;
} RebaseCtx;

static void rebase_buffer(RzXNUKernelCacheObj *obj, RzBuffer *dst) {
	rebase_info_populate(obj->rebase_info, obj);

	ut64 eob = rz_buf_size(obj->cache_buf);
	int i = 0;
	RebaseCtx ctx;
	ctx.eob = eob;
	ctx.dst = dst;
	ctx.obj = obj;

	for (; i < obj->rebase_info->n_ranges; i++) {
		ut64 start = obj->rebase_info->ranges[i].offset;
		if (start < eob) {
			iterate_rebase_list(obj->cache_buf, obj->rebase_info->multiplier, start, on_rebase_pointer, &ctx);
		}
	}
}

static bool on_rebase_pointer(ut64 offset, ut64 decorated_addr, void *user) {
	RebaseCtx *ctx = user;
	if (offset >= ctx->eob) {
		return false;
	}
	RzXNUKernelCacheParsedPointer ptr;
	rz_xnu_kernelcache_parse_pointer(&ptr, decorated_addr, ctx->obj);
	rz_buf_write_le64_at(ctx->dst, offset, ptr.address);
	return true;
}

RZ_API bool rz_xnu_kernelcache_parse_pointer(RzXNUKernelCacheParsedPointer *ptr, ut64 decorated_addr, RzXNUKernelCacheObj *obj) {
	/*
	 * Logic taken from:
	 * https://github.com/Synacktiv/kernelcache-laundering/blob/master/ios12_kernel_cache_helper.py
	 */

	if ((decorated_addr & 0x4000000000000000LL) == 0 && obj->rebase_info) {
		if (decorated_addr & 0x8000000000000000LL) {
			ptr->address = obj->rebase_info->kernel_base + (decorated_addr & 0xFFFFFFFFLL);
		} else {
			ptr->address = ((decorated_addr << 13) & 0xFF00000000000000LL) | (decorated_addr & 0x7ffffffffffLL);
			if (decorated_addr & 0x40000000000LL) {
				ptr->address |= 0xfffc0000000000LL;
			}
		}
	} else {
		ptr->address = decorated_addr;
	}

	return true;
}

RZ_API RzBuffer *rz_xnu_kernelcache_new_patched_buf(RzXNUKernelCacheObj *obj) {
	RzBuffer *r = rz_buf_new_sparse_overlay(obj->cache_buf, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!r) {
		return NULL;
	}

	if (MACH0_(has_chained_fixups)(obj->mach0)) {
		// clang-format off
		MACH0_(patch_chained_fixups)(obj->mach0, r);
		// clang-format on
	} else if (obj->rebase_info) {
		rebase_buffer(obj, r);
	}

	// from now on, all writes should propagate through to the actual file
	rz_buf_sparse_set_write_mode(r, RZ_BUF_SPARSE_WRITE_MODE_THROUGH);
	return r;
}

RZ_API bool rz_xnu_kernelcache_needs_rebasing(RzXNUKernelCacheObj *obj) {
	return obj->rebase_info || obj->mach0->chained_fixups.starts;
}
