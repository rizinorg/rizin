// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2020 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dyldcache.h"

static void rebase_bytes_v1(RzDyldRebaseInfo1 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;
		ut64 entry_index = page_offset / 32;
		ut64 offset_in_entry = (page_offset % 32) / 4;

		if (entry_index >= rebase_info->entries_size) {
			in_buf += to_next_page;
			offset += to_next_page;
			continue;
		}

		if (page_index >= rebase_info->toc_count) {
			break;
		}

		ut8 *entry = &rebase_info->entries[rebase_info->toc[page_index] * rebase_info->entries_size];
		ut8 b = entry[entry_index];

		if (b & (1 << offset_in_entry)) {
			ut64 value = rz_read_le64(buf + in_buf);
			value += rebase_info->slide;
			rz_write_le64(buf + in_buf, value);
			in_buf += 8;
			offset += 8;
		} else {
			in_buf += 4;
			offset += 4;
		}
	}
}

static void rebase_bytes_v2(RzDyldRebaseInfo2 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut16 page_flag = rebase_info->page_starts[page_index];

		if (page_flag == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		if (!(page_flag & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA)) {
			ut64 first_rebase_off = rebase_info->page_starts[page_index] * 4;
			if (first_rebase_off >= page_offset && first_rebase_off < page_offset + count) {
				ut32 delta = 1;
				while (delta) {
					ut64 position = in_buf + first_rebase_off - page_offset;
					if (position >= count) {
						break;
					}
					ut64 raw_value = rz_read_le64(buf + position);
					delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift);
					if (position >= start_of_write) {
						ut64 new_value = raw_value & rebase_info->value_mask;
						if (new_value != 0) {
							new_value += rebase_info->value_add;
							new_value += rebase_info->slide;
						}
						rz_write_le64(buf + position, new_value);
					}
					first_rebase_off += delta;
				}
			}
		}
	next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

#define RZ_IS_PTR_AUTHENTICATED(x) B_IS_SET(x, 63)

static void rebase_bytes_v3(RzDyldRebaseInfo3 *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	int in_buf = 0;
	while (in_buf < count) {
		ut64 offset_in_data = offset - rebase_info->start_of_data;
		ut64 page_index = offset_in_data / rebase_info->page_size;
		ut64 page_offset = offset_in_data % rebase_info->page_size;
		ut64 to_next_page = rebase_info->page_size - page_offset;

		if (page_index >= rebase_info->page_starts_count) {
			goto next_page;
		}
		ut64 delta = rebase_info->page_starts[page_index];

		if (delta == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE) {
			goto next_page;
		}

		ut64 first_rebase_off = delta;
		if (first_rebase_off >= page_offset && first_rebase_off < page_offset + count) {
			do {
				ut64 position = in_buf + first_rebase_off - page_offset;
				if (position >= count) {
					break;
				}
				ut64 raw_value = rz_read_le64(buf + position);
				delta = ((raw_value & rebase_info->delta_mask) >> rebase_info->delta_shift) * 8;
				if (position >= start_of_write) {
					ut64 new_value = 0;
					if (RZ_IS_PTR_AUTHENTICATED(raw_value)) {
						new_value = (raw_value & 0xFFFFFFFFULL) + rebase_info->auth_value_add;
						// TODO: don't throw auth info away
					} else {
						new_value = ((raw_value << 13) & 0xFF00000000000000ULL) | (raw_value & 0x7ffffffffffULL);
						new_value &= 0x00FFFFFFFFFFFFFFULL;
					}
					if (new_value != 0) {
						new_value += rebase_info->slide;
					}
					rz_write_le64(buf + position, new_value);
				}
				first_rebase_off += delta;
			} while (delta);
		}
	next_page:
		in_buf += to_next_page;
		offset += to_next_page;
	}
}

static RzDyldRebaseInfo *rebase_info_by_range(RzDyldRebaseInfos *infos, ut64 offset, ut64 count) {
	int imid;
	int imin = 0;
	int imax = infos->length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		RzDyldRebaseInfosEntry *entry = &infos->entries[imid];
		if ((entry->end) <= offset) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	RzDyldRebaseInfosEntry *minEntry = &infos->entries[imin];
	if ((imax == imin) && (minEntry->start <= offset + count) && (minEntry->end >= offset)) {
		return minEntry->info;
	}
	return NULL;
}

static void rebase_bytes(RzDyldRebaseInfo *rebase_info, ut8 *buf, ut64 offset, int count, ut64 start_of_write) {
	if (!rebase_info || !buf) {
		return;
	}

	if (rebase_info->version == 3) {
		rebase_bytes_v3((RzDyldRebaseInfo3 *)rebase_info, buf, offset, count, start_of_write);
	} else if (rebase_info->version == 2 || rebase_info->version == 4) {
		rebase_bytes_v2((RzDyldRebaseInfo2 *)rebase_info, buf, offset, count, start_of_write);
	} else if (rebase_info->version == 1) {
		rebase_bytes_v1((RzDyldRebaseInfo1 *)rebase_info, buf, offset, count, start_of_write);
	}
}

typedef struct {
	RzDyldCache *cache;
	ut64 off;
} BufCtx;

static bool buf_init(RzBuffer *b, const void *user) {
	BufCtx *ctx = RZ_NEW0(BufCtx);
	if (!ctx) {
		return false;
	}
	ctx->cache = (void *)user;
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
	return rz_buf_resize(ctx->cache->buf, newsize);
}

static st64 buf_read(RzBuffer *b, ut8 *buf, ut64 len) {
	BufCtx *ctx = b->priv;
	st64 r = rz_buf_read_at(ctx->cache->buf, ctx->off, buf, len);
	if (r <= 0 || !len) {
		return r;
	}

	RzDyldCache *cache = ctx->cache;
	RzDyldRebaseInfo *rebase_info = rebase_info_by_range(cache->rebase_infos, ctx->off, len);

	if (!rebase_info) {
		return rz_buf_read_at(cache->buf, ctx->off, buf, len);
	} else if (rebase_info->page_size < 1) {
		return -1;
	}

	st64 result = 0;
	ut64 offset_in_data = ctx->off - rebase_info->start_of_data;
	ut64 page_offset = offset_in_data % rebase_info->page_size;

	ut64 internal_offset = ctx->off & ~(rebase_info->page_size - 1);
	ut64 internal_end = ctx->off + len;
	int rounded_count = internal_end - internal_offset;

	ut8 *internal_buf = rebase_info->one_page_buf;
	if (rounded_count > rebase_info->page_size) {
		internal_buf = malloc(rounded_count);
		if (!internal_buf) {
			RZ_LOG_ERROR("dyldcache: Cannot allocate memory for 'internal_buf'\n");
			return -1;
		}
	}

	st64 internal_result = rz_buf_read_at(cache->buf, internal_offset, internal_buf, rounded_count);
	if (internal_result >= page_offset + len) {
		rebase_bytes(rebase_info, internal_buf, internal_offset, internal_result, page_offset);
		result = RZ_MIN(len, internal_result);
		memcpy(buf, internal_buf + page_offset, result);
	} else {
		RZ_LOG_ERROR("dyldcache: Cannot rebase address\n");
		result = rz_buf_read_at(cache->buf, ctx->off, buf, len);
	}

	if (internal_buf != rebase_info->one_page_buf) {
		RZ_FREE(internal_buf);
	}
	return result;
}

static st64 buf_write(RzBuffer *b, const ut8 *buf, ut64 len) {
	BufCtx *ctx = b->priv;
	return rz_buf_write_at(ctx->cache->buf, ctx->off, buf, len);
}

static ut64 buf_get_size(RzBuffer *b) {
	BufCtx *ctx = b->priv;
	return rz_buf_size(ctx->cache->buf);
}

static st64 buf_seek(RzBuffer *b, st64 addr, int whence) {
	BufCtx *ctx = b->priv;
	st64 val = rz_seek_offset(ctx->off, rz_buf_size(b), addr, whence);
	if (val == -1) {
		return -1;
	}
	return ctx->off = (ut64)val;
}

static ut8 *buf_get_whole_buf(RzBuffer *b, ut64 *sz) {
	BufCtx *ctx = b->priv;
	return (ut8 *)rz_buf_data(ctx->cache->buf, sz);
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

RZ_API RzBuffer *rz_dyldcache_new_rebasing_buf(RzDyldCache *cache) {
	rz_return_val_if_fail(cache, NULL);
	return rz_buf_new_with_methods(&buf_methods, cache, RZ_BUFFER_CUSTOM);
}

RZ_API bool rz_dyldcache_needs_rebasing(RzDyldCache *cache) {
	rz_return_val_if_fail(cache, false);
	if (cache->rebase_infos) {
		if (!rz_dyldcache_get_slide(cache)) {
			return true;
		}
	}
	return false;
}

RZ_API bool rz_dyldcache_range_needs_rebasing(RzDyldCache *cache, ut64 paddr, ut64 size) {
	rz_return_val_if_fail(cache, false);
	if (!rz_dyldcache_needs_rebasing(cache)) {
		return false;
	}
	return !!rebase_info_by_range(cache->rebase_infos, paddr, size);
}
