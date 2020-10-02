/* radare - LGPL - Copyright 2008-2018 - pancake */

// TODO: implement a more intelligent way to store cached memory

#include "rz_io.h"

#if 0
#define CACHE_CONTAINER(x) container_of ((RBNode*)x, RCache, rb)

static void _fcn_tree_calc_max_addr(RBNode *node) {
	RzIOCache *c = CACHE_CONTAINER (node);
}
#endif // 0

static void cache_item_free(RzIOCache *cache) {
	if (!cache) {
		return;
	}
	free (cache->data);
	free (cache->odata);
	free (cache);
}

RZ_API bool rz_io_cache_at(RzIO *io, ut64 addr) {
	RzIOCache *c;
	RzListIter *iter;
	rz_list_foreach (io->cache, iter, c) {
		if (rz_itv_contain (c->itv, addr)) {
			return true;
		}
	}
	return false;
}

RZ_API void rz_io_cache_init(RzIO *io) {
	io->cache = rz_list_newf ((RzListFree)cache_item_free);
	io->buffer = rz_cache_new ();
	io->cached = 0;
}

RZ_API void rz_io_cache_fini (RzIO *io) {
	rz_list_free (io->cache);
	rz_cache_free (io->buffer);
	io->cache = NULL;
	io->buffer = NULL;
	io->cached = 0;
}

RZ_API void rz_io_cache_commit(RzIO *io, ut64 from, ut64 to) {
	RzListIter *iter;
	RzIOCache *c;
	RInterval range = (RInterval){from, to - from};
	rz_list_foreach (io->cache, iter, c) {
		// if (from <= c->to - 1 && c->from <= to - 1) {
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
	io->cached = set;
	rz_list_purge (io->cache);
}

RZ_API int rz_io_cache_invalidate(RzIO *io, ut64 from, ut64 to) {
	int invalidated = 0;
	RzListIter *iter, *tmp;
	RzIOCache *c;
	RInterval range = (RInterval){from, to - from};
	rz_list_foreach_prev_safe (io->cache, iter, tmp, c) {
		if (rz_itv_overlap (c->itv, range)) {
			int cached = io->cached;
			io->cached = 0;
			rz_io_write_at (io, rz_itv_begin (c->itv), c->odata, rz_itv_size (c->itv));
			io->cached = cached;
			c->written = false;
			rz_list_delete (io->cache, iter);
			invalidated++;
		}
	}
	return invalidated;
}

RZ_API int rz_io_cache_list(RzIO *io, int rad) {
	int i, j = 0;
	RzListIter *iter;
	RzIOCache *c;
	if (rad == 2) {
		io->cb_printf ("[");
	}
	rz_list_foreach (io->cache, iter, c) {
		const int dataSize = rz_itv_size (c->itv);
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
			io->cb_printf ("{\"idx\":%"PFMT64d",\"addr\":%"PFMT64d",\"size\":%d,",
				j, rz_itv_begin (c->itv), dataSize);
			io->cb_printf ("\"before\":\"");
		  	for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", c->odata[i]);
			}
			io->cb_printf ("\",\"after\":\"");
		  	for (i = 0; i < dataSize; i++) {
				io->cb_printf ("%02x", c->data[i]);
			}
			io->cb_printf ("\",\"written\":%s}%s", c->written
				? "true": "false", iter->n? ",": "");
		} else if (rad == 0) {
			io->cb_printf ("idx=%d addr=0x%08"PFMT64x" size=%d ", j, rz_itv_begin (c->itv), dataSize);
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
		io->cb_printf ("]\n");
	}
	return false;
}

RZ_API bool rz_io_cache_write(RzIO *io, ut64 addr, const ut8 *buf, int len) {
	RzIOCache *ch;
	ch = RZ_NEW0 (RzIOCache);
	if (!ch) {
		return false;
	}
	ch->itv = (RInterval){addr, len};
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
		bool cm = io->cachemode;
		io->cachemode = false;
		rz_io_read_at (io, addr, ch->odata, len);
		io->cachemode = cm;
	}
	memcpy (ch->data, buf, len);
	rz_list_append (io->cache, ch);
	return true;
}

RZ_API bool rz_io_cache_read(RzIO *io, ut64 addr, ut8 *buf, int len) {
	bool covered = false;
	RzListIter *iter;
	RzIOCache *c;
	RInterval range = (RInterval){ addr, len };
	rz_list_foreach (io->cache, iter, c) {
		if (rz_itv_overlap (c->itv, range)) {
			const ut64 begin = rz_itv_begin (c->itv);
			if (addr < begin) {
				int l = RZ_MIN (addr + len - begin, rz_itv_size (c->itv));
				memcpy (buf + begin - addr, c->data, l);
			} else {
				int l = RZ_MIN (rz_itv_end (c->itv) - addr, len);
				memcpy (buf, c->data + addr - begin, l);
			}
			covered = true;
		}
	}
	return covered;
}
