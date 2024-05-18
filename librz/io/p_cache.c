// SPDX-FileCopyrightText: 2017-2018 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2017-2018 alvaro <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <rz_types.h>
#include <string.h>

const ut64 cleanup_masks[] = {
	0x0000000000000001,
	0x0000000000000003,
	0x0000000000000007,
	0x000000000000000f,
	0x000000000000001f,
	0x000000000000003f,
	0x000000000000007f,
	0x00000000000000ff,
	0x00000000000001ff,
	0x00000000000003ff,
	0x00000000000007ff,
	0x0000000000000fff,
	0x0000000000001fff,
	0x0000000000003fff,
	0x0000000000007fff,
	0x000000000000ffff,
	0x000000000001ffff,
	0x000000000003ffff,
	0x000000000007ffff,
	0x00000000000fffff,
	0x00000000001fffff,
	0x00000000003fffff,
	0x00000000007fffff,
	0x0000000000ffffff,
	0x0000000001ffffff,
	0x0000000003ffffff,
	0x0000000007ffffff,
	0x000000000fffffff,
	0x000000001fffffff,
	0x000000003fffffff,
	0x000000007fffffff,
	0x00000000ffffffff,
	0x00000001ffffffff,
	0x00000003ffffffff,
	0x00000007ffffffff,
	0x0000000fffffffff,
	0x0000001fffffffff,
	0x0000003fffffffff,
	0x0000007fffffffff,
	0x000000ffffffffff,
	0x000001ffffffffff,
	0x000003ffffffffff,
	0x000007ffffffffff,
	0x00000fffffffffff,
	0x00001fffffffffff,
	0x00003fffffffffff,
	0x00007fffffffffff,
	0x0000ffffffffffff,
	0x0001ffffffffffff,
	0x0003ffffffffffff,
	0x0007ffffffffffff,
	0x000fffffffffffff,
	0x001fffffffffffff,
	0x003fffffffffffff,
	0x007fffffffffffff,
	0x00ffffffffffffff,
	0x01ffffffffffffff,
	0x03ffffffffffffff,
	0x07ffffffffffffff,
	0x0fffffffffffffff,
	0x1fffffffffffffff,
	0x3fffffffffffffff,
	0x7fffffffffffffff
};

RZ_API bool rz_io_desc_cache_init(RzIODesc *desc) {
	if (!desc || desc->cache) {
		return false;
	}
	return (desc->cache = ht_up_new(NULL, free)) ? true : false;
}

RZ_API int rz_io_desc_cache_write(RzIODesc *desc, ut64 paddr, const ut8 *buf, size_t len) {
	RzIODescCache *cache;
	ut64 caddr, desc_sz = rz_io_desc_size(desc);
	int cbaddr, written = 0;
	if ((len < 1) || !desc || (desc_sz <= paddr) ||
		!desc->io || (!desc->cache && !rz_io_desc_cache_init(desc))) {
		return 0;
	}
	if (len > desc_sz) {
		len = (int)desc_sz;
	}
	if (paddr > (desc_sz - len)) {
		len = (int)(desc_sz - paddr);
	}
	caddr = paddr / RZ_IO_DESC_CACHE_SIZE;
	cbaddr = paddr % RZ_IO_DESC_CACHE_SIZE;
	while (written < len) {
		// get an existing desc-cache, if it exists
		if (!(cache = (RzIODescCache *)ht_up_find(desc->cache, caddr, NULL))) {
			// create new desc-cache
			cache = RZ_NEW0(RzIODescCache);
			if (!cache) {
				return 0;
			}
			// feed ht with the new desc-cache
			ht_up_insert(desc->cache, caddr, cache);
		}
		// check if the remaining data fits into the cache
		if ((len - written) > (RZ_IO_DESC_CACHE_SIZE - cbaddr)) {
			written += (RZ_IO_DESC_CACHE_SIZE - cbaddr);
			// this can be optimized
			for (; cbaddr < RZ_IO_DESC_CACHE_SIZE; cbaddr++) {
				// write to cache
				cache->cdata[cbaddr] = *buf;
				// save, that its cached
				cache->cached |= (0x1ULL << cbaddr);
				buf++;
			}
		} else {
			// XXX this looks like very suspicious
			do {
				cache->cdata[cbaddr] = *buf;
				cache->cached |= (0x1ULL << cbaddr);
				buf++;
				written++;
				cbaddr++;
			} while (len > written);
		}
		caddr++;
		cbaddr = 0;
	}
	RzEventIOWrite iow = { paddr, buf, len };
	rz_event_send(desc->io->event, RZ_EVENT_IO_WRITE, &iow);
	return written;
}

RZ_API int rz_io_desc_cache_read(RzIODesc *desc, ut64 paddr, ut8 *buf, size_t len) {
	RzIODescCache *cache;
	ut8 *ptr = buf;
	ut64 caddr, desc_sz = rz_io_desc_size(desc);
	int cbaddr, amount = 0;
	if ((len < 1) || !desc || (desc_sz <= paddr) || !desc->io || !desc->cache) {
		return 0;
	}
	if (len > desc_sz) {
		len = (int)desc_sz;
	}
	if (paddr > (desc_sz - len)) {
		len = (int)(desc_sz - paddr);
	}
	caddr = paddr / RZ_IO_DESC_CACHE_SIZE;
	cbaddr = paddr % RZ_IO_DESC_CACHE_SIZE;
	while (amount < len) {
		// get an existing desc-cache, if it exists
		if (!(cache = (RzIODescCache *)ht_up_find(desc->cache, caddr, NULL))) {
			amount += (RZ_IO_DESC_CACHE_SIZE - cbaddr);
			ptr += (RZ_IO_DESC_CACHE_SIZE - cbaddr);
			goto beach;
		}
		if ((len - amount) > (RZ_IO_DESC_CACHE_SIZE - cbaddr)) {
			amount += (RZ_IO_DESC_CACHE_SIZE - cbaddr);
			for (; cbaddr < RZ_IO_DESC_CACHE_SIZE; cbaddr++) {
				if (cache->cached & (0x1ULL << cbaddr)) {
					*ptr = cache->cdata[cbaddr];
				}
				ptr++;
			}
		} else {
			do {
				if (cache->cached & (0x1ULL << cbaddr)) {
					*ptr = cache->cdata[cbaddr];
				}
				ptr++;
				amount++;
				cbaddr++;
			} while (len > amount);
		}
	beach:
		caddr++;
		cbaddr = 0;
	}
	return amount;
}

static void __riocache_free(void *user) {
	RzIOCache *cache = (RzIOCache *)user;
	if (cache) {
		free(cache->data);
		free(cache->odata);
	}
	free(cache);
}

static bool __desc_cache_list_cb(void *user, const ut64 k, const void *v) {
	RzList *writes = (RzList *)user;
	RzIOCache *cache = NULL;
	ut64 blockaddr;
	int byteaddr, i;
	if (!writes) {
		return false;
	}
	const RzIODescCache *dcache = v;
	blockaddr = k * RZ_IO_DESC_CACHE_SIZE;
	for (i = byteaddr = 0; byteaddr < RZ_IO_DESC_CACHE_SIZE; byteaddr++) {
		if (dcache->cached & (0x1LL << byteaddr)) {
			if (!cache) {
				cache = RZ_NEW0(RzIOCache);
				if (!cache) {
					return false;
				}
				cache->data = malloc(RZ_IO_DESC_CACHE_SIZE - byteaddr);
				if (!cache->data) {
					free(cache);
					return false;
				}
				cache->itv.addr = blockaddr + byteaddr;
			}
			cache->data[i] = dcache->cdata[byteaddr];
			i++;
		} else if (cache) {
			ut8 *data = realloc(cache->data, i);
			if (!data) {
				__riocache_free((void *)cache);
				return false;
			}
			cache->data = data;
			cache->itv.size = i;
			i = 0;
			rz_list_push(writes, cache);
			cache = NULL;
		}
	}
	if (cache) {
#if 0
		cache->size = i;
		cache->to = blockaddr + RZ_IO_DESC_CACHE_SIZE;
#endif
		cache->itv.size = i;
		rz_list_push(writes, cache);
	}
	return true;
}

RZ_API RzList /*<RzIOCache *>*/ *rz_io_desc_cache_list(RzIODesc *desc) {
	if (!desc || !desc->io || !desc->io->desc || !desc->io->p_cache || !desc->cache) {
		return NULL;
	}
	RzList *writes = rz_list_newf((RzListFree)__riocache_free);
	if (!writes) {
		return NULL;
	}
	ht_up_foreach_cb(desc->cache, __desc_cache_list_cb, writes);
	RzIODesc *current = desc->io->desc;
	desc->io->desc = desc;
	desc->io->p_cache = false;

	RzIOCache *c;
	RzListIter *iter;
	rz_list_foreach (writes, iter, c) {
		const ut64 itvSize = rz_itv_size(c->itv);
		c->odata = calloc(1, itvSize);
		if (!c->odata) {
			rz_list_free(writes);
			return NULL;
		}
		rz_io_pread_at(desc->io, rz_itv_begin(c->itv), c->odata, itvSize);
	}
	desc->io->p_cache = true;
	desc->io->desc = current;
	return writes;
}

static bool __desc_cache_commit_cb(void *user, const ut64 k, const void *v) {
	RzIODesc *desc = (RzIODesc *)user;
	int byteaddr, i;
	ut8 buf[RZ_IO_DESC_CACHE_SIZE] = { 0 };
	if (!desc || !desc->io) {
		return false;
	}
	const RzIODescCache *dcache = v;
	ut64 blockaddr = RZ_IO_DESC_CACHE_SIZE * k;
	for (i = byteaddr = 0; byteaddr < RZ_IO_DESC_CACHE_SIZE; byteaddr++) {
		if (dcache->cached & (0x1LL << byteaddr)) {
			buf[i] = dcache->cdata[byteaddr];
			i++;
		} else if (i > 0) {
			rz_io_pwrite_at(desc->io, blockaddr + byteaddr - i, buf, i);
			i = 0;
		}
	}
	if (i > 0) {
		rz_io_pwrite_at(desc->io, blockaddr + RZ_IO_DESC_CACHE_SIZE - i, buf, i);
	}
	return true;
}

RZ_API bool rz_io_desc_cache_commit(RzIODesc *desc) {
	RzIODesc *current;
	if (!desc || !(desc->perm & RZ_PERM_W) || !desc->io || !desc->io->files || !desc->io->p_cache) {
		return false;
	}
	if (!desc->cache) {
		return true;
	}
	current = desc->io->desc;
	desc->io->desc = desc;
	desc->io->p_cache = false;
	ht_up_foreach_cb(desc->cache, __desc_cache_commit_cb, desc);
	ht_up_free(desc->cache);
	desc->cache = NULL;
	desc->io->p_cache = true;
	desc->io->desc = current;
	return true;
}

static bool __desc_cache_cleanup_cb(void *user, const ut64 k, const void *v) {
	RzIODesc *desc = (RzIODesc *)user;
	ut64 size, blockaddr;
	int byteaddr;
	if (!desc || !desc->cache) {
		return false;
	}
	RzIODescCache *cache = (RzIODescCache *)v;
	blockaddr = RZ_IO_DESC_CACHE_SIZE * k;
	size = rz_io_desc_size(desc);
	if (size <= blockaddr) {
		ht_up_delete(desc->cache, k);
		return true;
	}
	if (size <= (blockaddr + RZ_IO_DESC_CACHE_SIZE - 1)) {
		// this looks scary, but it isn't
		byteaddr = (int)(size - blockaddr) - 1;
		cache->cached &= cleanup_masks[byteaddr];
	}
	return true;
}

RZ_API void rz_io_desc_cache_cleanup(RzIODesc *desc) {
	if (desc && desc->cache) {
		ht_up_foreach_cb(desc->cache, __desc_cache_cleanup_cb, desc);
	}
}

static bool __desc_fini_cb(void *user, void *data, ut32 id) {
	RzIODesc *desc = (RzIODesc *)data;
	if (desc->cache) {
		ht_up_free(desc->cache);
		desc->cache = NULL;
	}
	return true;
}

RZ_API void rz_io_desc_cache_fini(RzIODesc *desc) {
	__desc_fini_cb(NULL, (void *)desc, 0);
}

RZ_API void rz_io_desc_cache_fini_all(RzIO *io) {
	if (io && io->files) {
		rz_id_storage_foreach(io->files, __desc_fini_cb, NULL);
	}
}
