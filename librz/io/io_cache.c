// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_skyline.h>

static void cache_item_free(RzIOCache *cache) {
	if (!cache) {
		return;
	}
	free(cache->data);
	free(cache->odata);
	free(cache);
}

RZ_API bool rz_io_cache_at(RzIO *io, ut64 addr) {
	rz_return_val_if_fail(io, false);
	return rz_skyline_contains(&io->cache_skyline, addr);
}

RZ_API void rz_io_cache_init(RzIO *io) {
	rz_return_if_fail(io);
	rz_pvector_init(&io->cache, (RzPVectorFree)cache_item_free);
	rz_skyline_init(&io->cache_skyline);
	io->cached = 0;
}

RZ_API void rz_io_cache_fini(RzIO *io) {
	rz_return_if_fail(io);
	rz_pvector_fini(&io->cache);
	rz_skyline_fini(&io->cache_skyline);
	io->cached = 0;
}

RZ_API void rz_io_cache_commit(RzIO *io, ut64 from, ut64 to) {
	void **iter;
	RzIOCache *c;
	RzInterval range = (RzInterval){ from, to - from };
	rz_return_if_fail(io);
	rz_pvector_foreach (&io->cache, iter) {
		// if (from <= c->to - 1 && c->from <= to - 1) {
		c = *iter;
		if (rz_itv_overlap(c->itv, range)) {
			int cached = io->cached;
			io->cached = 0;
			if (rz_io_write_at(io, rz_itv_begin(c->itv), c->data, rz_itv_size(c->itv))) {
				c->written = true;
			} else {
				eprintf("Error writing change at 0x%08" PFMT64x "\n", rz_itv_begin(c->itv));
			}
			io->cached = cached;
			// break; // XXX old behavior, revisit this
		}
	}
}

RZ_API void rz_io_cache_reset(RzIO *io, int set) {
	rz_return_if_fail(io);
	io->cached = set;
	rz_pvector_clear(&io->cache);
	rz_skyline_clear(&io->cache_skyline);
}

RZ_API int rz_io_cache_invalidate(RzIO *io, ut64 from, ut64 to) {
	rz_return_val_if_fail(io, 0);
	int invalidated = 0;
	void **iter;
	RzIOCache *c;
	RzInterval range = (RzInterval){ from, to - from };
	rz_pvector_foreach_prev(&io->cache, iter) {
		c = *iter;
		if (rz_itv_overlap(c->itv, range)) {
			int cached = io->cached;
			io->cached = 0;
			rz_io_write_at(io, rz_itv_begin(c->itv), c->odata, rz_itv_size(c->itv));
			io->cached = cached;
			c->written = false;
			rz_pvector_remove_data(&io->cache, c);
			free(c->data);
			free(c->odata);
			free(c);
			invalidated++;
		}
	}
	rz_skyline_clear(&io->cache_skyline);
	rz_pvector_foreach (&io->cache, iter) {
		c = *iter;
		rz_skyline_add(&io->cache_skyline, c->itv, c);
	}
	return invalidated;
}

RZ_API bool rz_io_cache_write(RzIO *io, ut64 addr, const ut8 *buf, int len) {
	rz_return_val_if_fail(io && buf, false);
	RzIOCache *ch = RZ_NEW0(RzIOCache);
	if (!ch) {
		return false;
	}
	if (UT64_ADD_OVFCHK(addr, len)) {
		const ut64 first_len = UT64_MAX - addr;
		rz_io_cache_write(io, 0, buf + first_len, len - first_len);
		len = first_len;
	}
	ch->itv = (RzInterval){ addr, len };
	ch->odata = (ut8 *)calloc(1, len + 1);
	if (!ch->odata) {
		free(ch);
		return false;
	}
	ch->data = (ut8 *)calloc(1, len + 1);
	if (!ch->data) {
		free(ch->odata);
		free(ch);
		return false;
	}
	ch->written = false;
	{
		const bool cm = io->cachemode;
		io->cachemode = false;
		rz_io_read_at(io, addr, ch->odata, len);
		io->cachemode = cm;
	}
	memcpy(ch->data, buf, len);
	rz_pvector_push(&io->cache, ch);
	rz_skyline_add(&io->cache_skyline, ch->itv, ch);
	RzEventIOWrite iow = { addr, buf, len };
	rz_event_send(io->event, RZ_EVENT_IO_WRITE, &iow);
	return true;
}

RZ_API bool rz_io_cache_read(RzIO *io, ut64 addr, ut8 *buf, int len) {
	rz_return_val_if_fail(io && buf, false);
	RzSkyline *skyline = &io->cache_skyline;
	if (!len) {
		return true;
	}
	if (UT64_ADD_OVFCHK(addr, len)) {
		const ut64 first_len = UT64_MAX - addr;
		rz_io_cache_read(io, 0, buf + first_len, len - first_len);
		len = first_len;
	}
	const RzSkylineItem *iter = rz_skyline_get_item_intersect(skyline, addr, len);
	if (!iter) {
		return false;
	}
	const RzSkylineItem *last = (RzSkylineItem *)skyline->v.a + skyline->v.len;
	bool covered = false;
	while (iter != last) {
		const ut64 begin = rz_itv_begin(iter->itv);
		const st64 addr_offset = begin - addr;
		const ut64 buf_offset = addr_offset > 0 ? addr_offset : 0;
		const ut64 cur_addr = addr + buf_offset;
		const ut64 left = len - buf_offset;
		if (begin > cur_addr + left) {
			break;
		}
		RzIOCache *cache = iter->user;
		const ut64 cache_shift = addr_offset < 0 ? -addr_offset : 0;
		const ut64 cache_offset = begin - rz_itv_begin(cache->itv) + cache_shift;
		const ut64 read = RZ_MIN(left, rz_itv_size(iter->itv) - cache_shift);
		memcpy(buf + buf_offset, cache->data + cache_offset, read);
		covered = true;
		if (left - read <= 0) {
			break;
		}
		iter++;
	}
	return covered;
}
