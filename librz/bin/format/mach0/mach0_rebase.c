// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Modified read proxy of Mach-O binaries for use as part of a virtual file.
 *
 * This is used in Mach-O binaries that either contain LC_DYLD_CHANGED_FIXUPS/LC_DYLD_EXPORTS_TRIE
 * load commands or BIND_OPCODE_THREADED in their dyld info. This is currently only known
 * to exist on binaries with the "arm64e" architecture, as Apple calls it, which is essentially
 * arm64 with pointer authentication.
 * In particular, we strip away additional info stored inside of pointers in the binary so we get
 * the raw pointers out for convenient analysis.
 *
 * see also mach0_relocs.c for additional modification of the data that might happen.
 */

#include "mach0.h"

#define IS_PTR_AUTH(x) ((x & (1ULL << 63)) != 0)
#define IS_PTR_BIND(x) ((x & (1ULL << 62)) != 0)

static void rebase_buffer(struct MACH0_(obj_t) * obj, ut64 off, ut8 *buf, int count) {
	rz_return_if_fail(obj && buf);
	ut64 eob = off + count;
	for (int i = 0; i < obj->nsegs; i++) {
		if (!obj->chained_starts[i]) {
			continue;
		}
		ut64 page_size = obj->chained_starts[i]->page_size;
		ut64 start = obj->segs[i].fileoff;
		ut64 end = start + obj->segs[i].filesize;
		if (end < off || start > eob) {
			continue;
		}
		ut64 page_idx = (RZ_MAX(start, off) - start) / page_size;
		ut64 page_end_idx = (RZ_MIN(eob, end) - start) / page_size;
		for (; page_idx <= page_end_idx; page_idx++) {
			if (page_idx >= obj->chained_starts[i]->page_count) {
				break;
			}
			ut16 page_start = obj->chained_starts[i]->page_start[page_idx];
			if (page_start == DYLD_CHAINED_PTR_START_NONE) {
				continue;
			}
			ut64 cursor = start + page_idx * page_size + page_start;
			while (cursor < eob && cursor < end) {
				ut8 tmp[8];
				if (rz_buf_read_at(obj->b, cursor, tmp, 8) != 8) {
					break;
				}
				ut64 raw_ptr = rz_read_le64(tmp);
				bool is_auth = IS_PTR_AUTH(raw_ptr);
				bool is_bind = IS_PTR_BIND(raw_ptr);
				ut64 ptr_value = raw_ptr;
				ut64 delta;
				if (is_auth && is_bind) {
					struct dyld_chained_ptr_arm64e_auth_bind *p =
						(struct dyld_chained_ptr_arm64e_auth_bind *)&raw_ptr;
					delta = p->next;
				} else if (!is_auth && is_bind) {
					struct dyld_chained_ptr_arm64e_bind *p =
						(struct dyld_chained_ptr_arm64e_bind *)&raw_ptr;
					delta = p->next;
				} else if (is_auth && !is_bind) {
					struct dyld_chained_ptr_arm64e_auth_rebase *p =
						(struct dyld_chained_ptr_arm64e_auth_rebase *)&raw_ptr;
					delta = p->next;
					ptr_value = p->target + obj->baddr;
				} else {
					struct dyld_chained_ptr_arm64e_rebase *p =
						(struct dyld_chained_ptr_arm64e_rebase *)&raw_ptr;
					delta = p->next;
					ptr_value = ((ut64)p->high8 << 56) | p->target;
				}
				ut64 in_buf = cursor - off;
				if (cursor >= off && cursor <= eob - 8) {
					rz_write_le64(&buf[in_buf], ptr_value);
				}
				cursor += delta * 8;
				if (!delta) {
					break;
				}
			}
		}
	}
}

typedef struct {
	struct MACH0_(obj_t) * obj;
	ut64 off;
} BufCtx;

static bool buf_init(RzBuffer *b, const void *user) {
	BufCtx *ctx = RZ_NEW0(BufCtx);
	if (!ctx) {
		return false;
	}
	ctx->obj = (void *)user;
	b->priv = ctx;
	return true;
}

static bool buf_fini(RzBuffer *b) {
	BufCtx *ctx = b->priv;
	free(ctx);
	return true;
}

static bool buf_resize(RzBuffer *b, ut64 newsize) {
	BufCtx *ctx = b->priv;
	return rz_buf_resize(ctx->obj->b, newsize);
}

static st64 buf_read(RzBuffer *b, ut8 *buf, ut64 len) {
	BufCtx *ctx = b->priv;
	st64 r = rz_buf_read_at(ctx->obj->b, ctx->off, buf, len);
	if (r <= 0 || !len) {
		return r;
	}
	rebase_buffer(ctx->obj, ctx->off, buf, RZ_MIN(r, len));
	return r;
}

static st64 buf_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	BufCtx *ctx = b->priv;
	return rz_buf_write_at(ctx->obj->b, ctx->off, buf, len);
}

static ut64 buf_get_size(RzBuffer *b) {
	BufCtx *ctx = b->priv;
	return rz_buf_size(ctx->obj->b);
}

static st64 buf_seek(RzBuffer *b, st64 addr, int whence) {
	BufCtx *ctx = b->priv;
	return ctx->off = rz_seek_offset(ctx->off, rz_buf_size(b), addr, whence);
}

static ut8 *buf_get_whole_buf(RzBuffer *b, ut64 *sz) {
	BufCtx *ctx = b->priv;
	return (ut8 *)rz_buf_data(ctx->obj->b, sz);
}

static const RzBufferMethods buf_methods = {
	.init = buf_init,
	.fini = buf_fini,
	.read = buf_read,
	.write = buf_write,
	.get_size = buf_get_size,
	.resize = buf_resize,
	.seek = buf_seek,
	.get_whole_buf = buf_get_whole_buf
};

RZ_API RzBuffer *MACH0_(new_rebasing_and_stripping_buf)(struct MACH0_(obj_t) * obj) {
	return rz_buf_new_with_methods(&buf_methods, obj);
}

RZ_API bool MACH0_(needs_rebasing_and_stripping)(struct MACH0_(obj_t) * obj) {
	return !!obj->chained_starts;
}

RZ_API bool MACH0_(segment_needs_rebasing_and_stripping)(struct MACH0_(obj_t) * obj, size_t seg_index) {
	if (seg_index >= obj->nsegs) {
		return false;
	}
	return obj->chained_starts && obj->chained_starts[seg_index];
}
