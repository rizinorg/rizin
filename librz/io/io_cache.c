// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_skyline.h>

static void cache_item_free(RzIOCache *cache) {
	if (!cache) {
		return;
	}
	free (cache->data);
	free (cache->odata);
	free (cache);
}

RZ_API bool rz_io_cache_at(RzIO *io, ut64 addr) {
	rz_return_val_if_fail (io, false);
	return rz_skyline_contains (&io->cache_skyline, addr);
}

RZ_API void rz_io_cache_init(RzIO *io) {
	rz_return_if_fail (io);
	rz_pvector_init (&io->cache, (RzPVectorFree)cache_item_free);
	rz_skyline_init (&io->cache_skyline);
	io->buffer = rz_cache_new ();
	io->cached = 0;
}

RZ_API void rz_io_cache_fini(RzIO *io) {
	rz_return_if_fail (io);
	rz_pvector_fini (&io->cache);
	rz_skyline_fini (&io->cache_skyline);
	rz_cache_free (io->buffer);
	io->buffer = NULL;
	io->cached = 0;
}

RZ_API void rz_io_cache_commit(RzIO *io, ut64 from, ut64 to) {
	void **iter;
	RzIOCache *c;
	RzInterval range = (RzInterval){from, to - from};
	rz_return_if_fail (io);
	rz_pvector_foreach (&io->cache, iter) {
		// if (from <= c->to - 1 && c->from <= to - 1) {
		c = *iter;
		if (rz_itv_overlap (c->itv, range)) {
			int cached = io->cached;
			io->cached = 0;
			if (rz_io_write_at (io, rz_itv_begin (c->itv), c->data, rz_itv_size (c->itv))) {
				c->written = true;
			} else {
				eprintf ("Error writing change at 0x%08"PFMT64x"\n", rz_itv_begin (c->itv));
			}
			io->cached = cached;
			// break; // XXX old behavior, revisit this
		}
	}
}

RZ_API void rz_io_cache_reset(RzIO *io, int set) {
	rz_return_if_fail (io);
	io->cached = set;
	rz_pvector_clear (&io->cache);
	rz_skyline_clear (&io->cache_skyline);
}

RZ_API int rz_io_cache_invalidate(RzIO *io, ut64 from, ut64 to) {
	rz_return_val_if_fail (io, 0);
	int invalidated = 0;
	void **iter;
	RzIOCache *c;
	RzInterval range = (RzInterval){from, to - from};
	rz_pvector_foreach_prev (&io->cache, iter) {
		c = *iter;
		if (rz_itv_overlap (c->itv, range)) {
			int cached = io->cached;
			io->cached = 0;
			rz_io_write_at (io, rz_itv_begin (c->itv), c->odata, rz_itv_size (c->itv));
			io->cached = cached;
			c->written = false;
			rz_pvector_remove_data (&io->cache, c);
			invalidated++;
		}
	}
	rz_skyline_clear (&io->cache_skyline);
	rz_pvector_foreach (&io->cache, iter) {
		c = *iter;
		rz_skyline_add (&io->cache_skyline, c->itv, c);
	}
	return invalidated;
}

RZ_API bool rz_io_cache_list(RzIO *io, int rad) {
	rz_return_val_if_fail (io, false);
	size_t i, j = 0;
	void **iter;
	RzIOCache *c;
	PJ *pj = NULL;
	if (rad == 2) {
		pj = pj_new ();
		pj_a (pj);
	}
	rz_pvector_foreach (&io->cache, iter) {
		c = *iter;
		const ut64 dataSize = rz_itv_size (c->itv);
		if (rad == 1) {
			io->cb_printf ("wx ");
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", (ut8)(c->data[i] & 0xff));
			}
			io->cb_printf (" @ 0x%08"PFMT64x, rz_itv_begin (c->itv));
			io->cb_printf (" # replaces: ");
		  	for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", (ut8)(c->odata[i] & 0xff));
			}
			io->cb_printf ("\n");
		} else if (rad == 2) {
			pj_o (pj);
			pj_kn (pj, "idx", j);
			pj_kn (pj, "addr", rz_itv_begin (c->itv));
			pj_kn (pj, "size", dataSize);
			char *hex = rz_hex_bin2strdup (c->odata, dataSize);
			pj_ks (pj, "before", hex);
			free (hex);
			hex = rz_hex_bin2strdup (c->data, dataSize);
			pj_ks (pj, "after", hex);
			free (hex);
			pj_kb (pj, "written", c->written);
			pj_end (pj);
		} else if (rad == 0) {
			io->cb_printf ("idx=%"PFMTSZu" addr=0x%08"PFMT64x" size=%"PFMT64u" ", j, rz_itv_begin (c->itv), dataSize);
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", c->odata[i]);
			}
			io->cb_printf (" -> ");
			for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", c->data[i]);
			}
			io->cb_printf (" %s\n", c->written? "(written)": "(not written)");
		}
		j++;
	}
	if (rad == 2) {
		pj_end (pj);
		char *json = pj_drain (pj);
		io->cb_printf ("%s", json);
		free (json);
	}
	return false;
}

RZ_API bool rz_io_cache_write(RzIO *io, ut64 addr, const ut8 *buf, int len) {
	rz_return_val_if_fail (io && buf, false);
	RzIOCache *ch = RZ_NEW0 (RzIOCache);
	if (!ch) {
		return false;
	}
	ch->itv = (RzInterval){addr, len};
	ch->odata = (ut8*)calloc (1, len + 1);
	if (!ch->odata) {
		free (ch);
		return false;
	}
	ch->data = (ut8*)calloc (1, len + 1);
	if (!ch->data) {
		free (ch->odata);
		free (ch);
		return false;
	}
	ch->written = false;
	{
		const bool cm = io->cachemode;
		io->cachemode = false;
		rz_io_read_at (io, addr, ch->odata, len);
		io->cachemode = cm;
	}
	memcpy (ch->data, buf, len);
	rz_pvector_push (&io->cache, ch);
	rz_skyline_add (&io->cache_skyline, ch->itv, ch);
	RzEventIOWrite iow = { addr, buf, len };
	rz_event_send (io->event, RZ_EVENT_IO_WRITE, &iow);
	return true;
}

RZ_API bool rz_io_cache_read(RzIO *io, ut64 addr, ut8 *buf, int len) {
	rz_return_val_if_fail (io && buf, false);
	RzSkyline *skyline = &io->cache_skyline;
	const RzSkylineItem *iter = rz_skyline_get_item_intersect (skyline, addr, len);
	if (!iter) {
		return false;
	}
	const RzSkylineItem *last = (RzSkylineItem *)skyline->v.a + skyline->v.len;
	bool covered = false;
	while (iter != last) {
		const ut64 begin = rz_itv_begin (iter->itv);
		const st64 addr_offset = begin - addr;
		const ut64 buf_offset = addr_offset > 0 ? addr_offset : 0;
		const ut64 cur_addr = addr + buf_offset;
		const ut64 left = len - buf_offset;
		if (begin > cur_addr + left) {
			break;
		}
		RzIOCache *cache = iter->user;
		const ut64 cache_shift = addr_offset < 0 ? -addr_offset : 0;
		const ut64 cache_offset = begin - rz_itv_begin (cache->itv) + cache_shift;
		const ut64 read = RZ_MIN (left, rz_itv_size (iter->itv) - cache_shift);
		memcpy (buf + buf_offset, cache->data + cache_offset, read);
		covered = true;
		if (left - read <= 0) {
			break;
		}
		iter++;
	}
	return covered;
}
