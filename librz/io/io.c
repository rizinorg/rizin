// SPDX-FileCopyrightText: 2008-2019 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2008-2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2019 alvaro_fe <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include <sdb.h>
#include "io_private.h"

#if __WINDOWS__
#include <rz_windows.h>
#include <w32dbg_wrap.h>
#endif

RZ_LIB_VERSION(rz_io);

static int fd_read_at_wrap(RzIO *io, int fd, ut64 addr, ut8 *buf, size_t len, RzIOMap *map, void *user) {
	return rz_io_fd_read_at(io, fd, addr, buf, len);
}

static int fd_write_at_wrap(RzIO *io, int fd, ut64 addr, ut8 *buf, size_t len, RzIOMap *map, void *user) {
	return rz_io_fd_write_at(io, fd, addr, buf, len);
}

typedef int (*cbOnIterMap)(RzIO *io, int fd, ut64 addr, ut8 *buf, size_t len, RzIOMap *map, void *user);

// If prefix_mode is true, returns the number of bytes of operated prefix; returns < 0 on error.
// If prefix_mode is false, operates in non-stop mode and returns true iff all IO operations on overlapped maps are complete.
static st64 on_map_skyline(RzIO *io, ut64 vaddr, ut8 *buf, size_t len, int match_flg, cbOnIterMap op, bool prefix_mode) {
	RzVector *skyline = &io->map_skyline.v;
	ut64 addr = vaddr;
	size_t i;
	bool ret = false, wrap = !prefix_mode && vaddr + len < vaddr;
#define CMP(addr, part) ((addr) < rz_itv_end(((RzSkylineItem *)(part))->itv) - 1 ? -1 : (addr) > rz_itv_end(((RzSkylineItem *)(part))->itv) - 1 ? 1 \
																		: 0)
	// Let i be the first skyline part whose right endpoint > addr
	if (!len) {
		i = rz_vector_len(skyline);
	} else {
		rz_vector_lower_bound(skyline, addr, i, CMP);
		if (i == rz_vector_len(skyline) && wrap) {
			wrap = false;
			i = 0;
			addr = 0;
		}
	}
#undef CMP
	while (i < rz_vector_len(skyline)) {
		const RzSkylineItem *part = rz_vector_index_ptr(skyline, i);
		// Right endpoint <= addr
		if (rz_itv_end(part->itv) == 0 || rz_itv_end(part->itv) - 1 < addr) {
			i++;
			if (wrap && i == rz_vector_len(skyline)) {
				wrap = false;
				i = 0;
				addr = 0;
			}
			continue;
		}
		if (addr < part->itv.addr) {
			// [addr, part->itv.addr) is a gap
			if (prefix_mode || len <= part->itv.addr - vaddr) {
				break;
			}
			addr = part->itv.addr;
		}
		// Now left endpoint <= addr < right endpoint
		ut64 len1 = RZ_MIN(vaddr + len - addr, rz_itv_end(part->itv) - addr);
		if (len1 < 1) {
			break;
		}
		RzIOMap *map = part->user;
		// The map satisfies the permission requirement or p_cache is enabled
		if (((map->perm & match_flg) == match_flg || io->p_cache)) {
			st64 result = op(io, map->fd, map->delta + addr - map->itv.addr,
				buf + (addr - vaddr), len1, map, NULL);
			if (prefix_mode) {
				if (result < 0) {
					return result;
				}
				addr += result;
				if (result != len1) {
					break;
				}
			} else {
				ret = result == len1;
				addr += len1;
			}
		} else if (prefix_mode) {
			break;
		} else {
			addr += len1;
			ret = false;
		}
		// Reaches the end
		if (addr == vaddr + len) {
			break;
		}
		// Wrap to the beginning of skyline if address wraps
		if (!addr) {
			i = 0;
		}
	}
	return prefix_mode ? addr - vaddr : ret;
}

RZ_API RzIO *rz_io_new(void) {
	return rz_io_init(RZ_NEW0(RzIO));
}

RZ_API RzIO *rz_io_init(RzIO *io) {
	rz_return_val_if_fail(io, NULL);
	io->addrbytes = 1;
	rz_io_desc_init(io);
	rz_skyline_init(&io->map_skyline);
	rz_io_map_init(io);
	rz_io_cache_init(io);
	rz_io_plugin_init(io);
	io->event = rz_event_new(io);
	return io;
}

RZ_API void rz_io_free(RzIO *io) {
	if (io) {
		rz_io_fini(io);
		free(io);
	}
}

RZ_API RzIODesc *rz_io_open_buffer(RzIO *io, RzBuffer *b, int perm, int mode) {
	ut64 bufSize = rz_buf_size(b);
	char *uri = rz_str_newf("malloc://%" PFMT64d, bufSize);
	RzIODesc *desc = rz_io_open_nomap(io, uri, perm, mode);
	if (desc) {
		const ut8 *tmp = rz_buf_data(b, &bufSize);
		rz_io_desc_write(desc, tmp, bufSize);
	}
	free(uri);
	return desc;
}

RZ_API RzIODesc *rz_io_open_nomap(RzIO *io, const char *uri, int perm, int mode) {
	rz_return_val_if_fail(io && uri, NULL);
	RzIODesc *desc = rz_io_desc_open(io, uri, perm, mode);
	if ((io->autofd || !io->desc) && desc) {
		io->desc = desc;
	}
	// set desc as current if autofd or io->desc==NULL
	return desc;
}

/* opens a file and maps it to 0x0 */
RZ_API RzIODesc *rz_io_open(RzIO *io, const char *uri, int perm, int mode) {
	rz_return_val_if_fail(io, NULL);
	RzIODesc *desc = rz_io_open_nomap(io, uri, perm, mode);
	if (!desc) {
		return NULL;
	}
	rz_io_map_new(io, desc->fd, desc->perm, 0LL, 0LL, rz_io_desc_size(desc));
	return desc;
}

/**
 * \brief Open a file and directly map it at the given offset
 *
 * This executes both rz_io_open_nomap() and rz_io_map_new() and returns their
 * results without updating the skyline.
 *
 * \param uri file uri to open
 * \param at where to map the file
 * \param map optionally returns the created RzIOMap
 * \return the opened RzIODesc of the file
 * */
RZ_API RzIODesc *rz_io_open_at(RzIO *io, const char *uri, int perm, int mode, ut64 at, RZ_NULLABLE RZ_OUT RzIOMap **map) {
	rz_return_val_if_fail(io && uri, NULL);

	RzIODesc *desc = rz_io_open_nomap(io, uri, perm, mode);
	if (!desc) {
		return NULL;
	}
	ut64 size = rz_io_desc_size(desc);
	// second map
	if (size && ((UT64_MAX - size + 1) < at)) {
		// split map into 2 maps if only 1 big map results into interger overflow
		io_map_new(io, desc->fd, desc->perm, UT64_MAX - at + 1, 0LL, size - (UT64_MAX - at) - 1);
		// someone pls take a look at this confusing stuff
		size = UT64_MAX - at + 1;
	}
	// skyline not updated
	RzIOMap *m = rz_io_map_new(io, desc->fd, desc->perm, 0LL, at, size);
	if (map) {
		*map = m;
	}
	return desc;
}

/* opens many files, without mapping them. This should be discussed */
RZ_API RzList /*<RzIODesc *>*/ *rz_io_open_many(RzIO *io, const char *uri, int perm, int mode) {
	RzList *desc_list;
	RzListIter *iter;
	RzIODesc *desc;
	rz_return_val_if_fail(io && io->files && uri, NULL);
	RzIOPlugin *plugin = rz_io_plugin_resolve(io, uri, 1);
	if (!plugin || !plugin->open_many || !plugin->close) {
		return NULL;
	}
	if (!(desc_list = plugin->open_many(io, uri, perm, mode))) {
		return NULL;
	}
	rz_list_foreach (desc_list, iter, desc) {
		if (desc) {
			if (!desc->plugin) {
				desc->plugin = plugin;
			}
			if (!desc->uri) {
				desc->uri = rz_str_dup(uri);
			}
			// should autofd be honored here?
			rz_io_desc_add(io, desc);
			if (!io->desc) {
				io->desc = desc;
			}
		}
	}
	return desc_list;
}

RZ_API bool rz_io_reopen(RzIO *io, int fd, int perm, int mode) {
	RzIODesc *old, *new;
	char *uri;
	if (!(old = rz_io_desc_get(io, fd))) {
		return false;
	}
	// does this really work, or do we have to handler debuggers ugly
	uri = old->referer ? old->referer : old->uri;
#if __WINDOWS__ // TODO: workaround, see https://github.com/rizinorg/rizin/issues/8840
	if (old->plugin->close && old->plugin->close(old)) {
		return false; // TODO: this is an unrecoverable scenario
	}
	if (!(new = rz_io_open_nomap(io, uri, perm, mode))) {
		return false;
	}
	rz_io_desc_exchange(io, old->fd, new->fd);
	rz_io_desc_del(io, old->fd);
	return true;
#else
	if (!(new = rz_io_open_nomap(io, uri, perm, mode))) {
		return false;
	}
	rz_io_desc_exchange(io, old->fd, new->fd);
	return rz_io_desc_close(old); // magic
#endif // __WINDOWS__
}

RZ_API int rz_io_close_all(RzIO *io) { // what about undo?
	if (!io) {
		return false;
	}
	rz_io_desc_fini(io);
	rz_io_map_reset(io);
	rz_io_desc_init(io);
	rz_io_cache_fini(io);
	return true;
}

RZ_API int rz_io_pread_at(RzIO *io, ut64 paddr, ut8 *buf, size_t len) {
	rz_return_val_if_fail(io && buf && len >= 0, -1);
	if (io->ff) {
		memset(buf, io->Oxff, len);
	}
	return rz_io_desc_read_at(io->desc, paddr, buf, len);
}

RZ_API int rz_io_pwrite_at(RzIO *io, ut64 paddr, const ut8 *buf, size_t len) {
	rz_return_val_if_fail(io && buf && len > 0, -1);
	return rz_io_desc_write_at(io->desc, paddr, buf, len);
}

// Returns true iff all reads on mapped regions are successful and complete.
RZ_API bool rz_io_vread_at_mapped(RzIO *io, ut64 vaddr, ut8 *buf, size_t len) {
	rz_return_val_if_fail(io && buf && len > 0, false);
	if (io->ff) {
		memset(buf, io->Oxff, len);
	}
	return on_map_skyline(io, vaddr, buf, len, RZ_PERM_R, fd_read_at_wrap, false);
}

static bool rz_io_vwrite_at(RzIO *io, ut64 vaddr, const ut8 *buf, size_t len) {
	return on_map_skyline(io, vaddr, (ut8 *)buf, len, RZ_PERM_W, fd_write_at_wrap, false);
}

// Deprecated, use either rz_io_read_at_mapped or rz_io_nread_at instead.
// For virtual mode, returns true if all reads on mapped regions are successful
// and complete.
// For physical mode, the interface is broken because the actual read bytes are
// not available. This requires fixes in all call sites.
RZ_API bool rz_io_read_at(RzIO *io, ut64 addr, ut8 *buf, size_t len) {
	// NOTE:
	// Greetings! If you reached this code with your debugger, because
	// "something is not read from memory", step no further!
	// First try to replace the call with `rz_io_nread_at()`,
	// it maybe fixes it already.
	// If not, you can still venture downwards of course.
	// Good luck!
	rz_return_val_if_fail(io && buf && len >= 0, false);
	if (len == 0) {
		return false;
	}
	bool ret = (io->va)
		? rz_io_vread_at_mapped(io, addr, buf, len)
		: rz_io_pread_at(io, addr, buf, len) > 0;
	if (io->cached & RZ_PERM_R) {
		ret |= rz_io_cache_read(io, addr, buf, len);
	}
	return ret;
}

// Returns true iff all reads on mapped regions are successful and complete.
// Unmapped regions are filled with io->Oxff in both physical and virtual modes.
// Use this function if you want to ignore gaps or do not care about the number
// of read bytes.
RZ_API bool rz_io_read_at_mapped(RzIO *io, ut64 addr, ut8 *buf, size_t len) {
	bool ret;
	rz_return_val_if_fail(io && buf, false);
	if (io->ff) {
		memset(buf, io->Oxff, len);
	}
	if (io->va) {
		ret = on_map_skyline(io, addr, buf, len, RZ_PERM_R, fd_read_at_wrap, false);
	} else {
		ret = rz_io_pread_at(io, addr, buf, len) > 0;
	}
	if (io->cached & RZ_PERM_R) {
		ret |= rz_io_cache_read(io, addr, buf, len);
	}
	return ret;
}

// For both virtual and physical mode, returns the number of bytes of read
// prefix.
// Returns -1 on error.
RZ_API int rz_io_nread_at(RzIO *io, ut64 addr, ut8 *buf, size_t len) {
	int ret;
	rz_return_val_if_fail(io && buf && len >= 0, -1);
	if (len == 0) {
		return 0;
	}
	if (io->va) {
		if (io->ff) {
			memset(buf, io->Oxff, len);
		}
		ret = on_map_skyline(io, addr, buf, len, RZ_PERM_R, fd_read_at_wrap, true);
	} else {
		ret = rz_io_pread_at(io, addr, buf, len);
	}
	if (ret > 0 && io->cached & RZ_PERM_R) {
		(void)rz_io_cache_read(io, addr, buf, len);
	}
	return ret;
}

/**
 * \brief Writes \p len bytes of data from \p buf to \p addr into the given \p io.
 *
 * \param io The IO object to write to.
 * \param addr The address the data is written.
 * \param buf The buffer to read the data for writing.
 * \param len The number of bytes to write.
 * \return true The write was successful.
 * \return false The write as unsucessful or \p len was less then 1.
 */
RZ_API bool rz_io_write_at(RzIO *io, ut64 addr, const ut8 *buf, size_t len) {
	int i;
	bool ret = false;
	ut8 *mybuf = (ut8 *)buf;
	rz_return_val_if_fail(io && buf && len > 0, false);
	if (io->write_mask) {
		mybuf = rz_mem_dup((void *)buf, len);
		for (i = 0; i < len; i++) {
			// TODO: this needs some love because it is not optimal.
			mybuf[i] &= io->write_mask[i % io->write_mask_len];
		}
	}
	if (io->cached & RZ_PERM_W) {
		ret = rz_io_cache_write(io, addr, mybuf, len);
	} else if (io->va) {
		ret = rz_io_vwrite_at(io, addr, mybuf, len);
	} else {
		ret = rz_io_pwrite_at(io, addr, mybuf, len) > 0;
	}
	if (buf != mybuf) {
		free(mybuf);
	}
	return ret;
}

RZ_API bool rz_io_read(RzIO *io, ut8 *buf, size_t len) {
	if (io && rz_io_read_at(io, io->off, buf, len)) {
		io->off += len;
		return true;
	}
	return false;
}

RZ_API bool rz_io_write(RzIO *io, const ut8 *buf, size_t len) {
	if (io && buf && len > 0 && rz_io_write_at(io, io->off, buf, len)) {
		io->off += len;
		return true;
	}
	return false;
}

RZ_API ut64 rz_io_size(RzIO *io) {
	// TODO: rethink this, maybe not needed
	return io ? rz_io_desc_size(io->desc) : 0LL;
}

RZ_API bool rz_io_is_listener(RzIO *io) {
	if (io && io->desc && io->desc->plugin && io->desc->plugin->listener) {
		return io->desc->plugin->listener(io->desc);
	}
	return false;
}

RZ_API char *rz_io_system(RzIO *io, const char *cmd) {
	if (io && io->desc && io->desc->plugin && io->desc->plugin->system && RZ_STR_ISNOTEMPTY(cmd)) {
		return io->desc->plugin->system(io, io->desc, cmd);
	}
	return NULL;
}

RZ_API bool rz_io_resize(RZ_NONNULL RzIO *io, ut64 newsize) {
	rz_return_val_if_fail(io && io->desc, false);

	RzList *maps = rz_io_map_get_for_fd(io, io->desc->fd);
	ut64 fd_size = rz_io_fd_size(io, io->desc->fd);
	if (!rz_io_desc_resize(io->desc, newsize)) {
		rz_list_free(maps);
		return false;
	}
	RzListIter *iter;
	RzIOMap *current_map;
	rz_list_foreach (maps, iter, current_map) {
		// we just resize map of the same size of its fd
		if (current_map->itv.size == fd_size) {
			rz_io_map_resize(io, current_map->id, newsize);
		}
	}
	rz_list_free(maps);
	return true;
}

RZ_API bool rz_io_close(RzIO *io) {
	return io ? rz_io_desc_close(io->desc) : false;
}

/**
 * \brief Extend the RzIODesc at \p addr by inserting \p size 0 bytes
 *
 * \param io Reference to RzIO instance
 * \param addr Address where to insert new 0 bytes
 * \param size Number of 0 bytes to insert
 * \return true if extend operation was successful, false otherwise
 */
RZ_API bool rz_io_extend_at(RzIO *io, ut64 addr, ut64 size) {
#define IO_EXTEND_BLOCK_SZ 256
	rz_return_val_if_fail(io, false);

	if (!io->desc || !io->desc->plugin) {
		return false;
	}
	if (size == 0) {
		return true;
	}

	if ((io->desc->perm & RZ_PERM_RW) != RZ_PERM_RW) {
		return false;
	}
	ut64 cur_size = rz_io_desc_size(io->desc);
	if (addr > cur_size) {
		return false;
	}

	// Extend the file to include the additional <size> bytes
	if (UT64_ADD_OVFCHK(cur_size, size)) {
		return false;
	}
	if (!rz_io_resize(io, cur_size + size)) {
		return false;
	}

	// Shift old data to make space for the zero bytes
	ut64 tmp = cur_size >= IO_EXTEND_BLOCK_SZ ? RZ_MAX(cur_size - IO_EXTEND_BLOCK_SZ, addr) : addr;
	ut64 remaining = cur_size - addr;

	ut8 *buffer = RZ_NEWS(ut8, IO_EXTEND_BLOCK_SZ);
	if (!buffer) {
		return false;
	}
	while (remaining) {
		int sz = rz_io_pread_at(io, tmp, buffer, IO_EXTEND_BLOCK_SZ);
		rz_io_pwrite_at(io, tmp + size, buffer, sz);

		tmp = tmp - IO_EXTEND_BLOCK_SZ > addr ? tmp - IO_EXTEND_BLOCK_SZ : addr;
		remaining = remaining > sz ? remaining - sz : 0;
	}
	free(buffer);

	// Put the zero bytes at the right place
	ut8 *empty = RZ_NEWS0(ut8, size);
	if (!empty) {
		return false;
	}
	rz_io_pwrite_at(io, addr, empty, size);
	free(empty);

	return true;
#undef IO_EXTEND_BLOCK_SZ
}

/**
 * \brief Set a mask that is used on all following write operations
 *
 * \param io Reference to RzIo instance
 * \param mask Mask to apply
 * \param len Number of bytes in the mask
 * \return true if the mask was correctly set, false otherwise
 */
RZ_API bool rz_io_set_write_mask(RzIO *io, const ut8 *mask, size_t len) {
	rz_return_val_if_fail(io, false);
	rz_return_val_if_fail(mask || len == 0, false);

	free(io->write_mask);
	if (!mask) {
		io->write_mask = NULL;
		io->write_mask_len = 0;
		return true;
	}
	io->write_mask = (ut8 *)malloc(len);
	memcpy(io->write_mask, mask, len);
	io->write_mask_len = len;
	return true;
}

RZ_API ut64 rz_io_p2v(RzIO *io, ut64 pa) {
	RzIOMap *map = rz_io_map_get_paddr(io, pa);
	if (map) {
		return pa - map->delta + map->itv.addr;
	}
	return UT64_MAX;
}

RZ_API ut64 rz_io_v2p(RzIO *io, ut64 va) {
	RzIOMap *map = rz_io_map_get(io, va);
	if (map) {
		st64 delta = va - map->itv.addr;
		return map->delta + delta;
	}
	return UT64_MAX;
}

RZ_API void rz_io_bind(RzIO *io, RzIOBind *bnd) {
	rz_return_if_fail(io && bnd);

	bnd->io = io;
	bnd->init = true;
	bnd->fd_get_current = rz_io_fd_get_current;
	bnd->desc_use = rz_io_use_fd;
	bnd->desc_get = rz_io_desc_get;
	bnd->desc_size = rz_io_desc_size;
	bnd->p2v = rz_io_p2v;
	bnd->v2p = rz_io_v2p;
	bnd->open = rz_io_open_nomap;
	bnd->open_at = rz_io_open_at;
	bnd->close = rz_io_fd_close;
	bnd->read_at = rz_io_read_at;
	bnd->write_at = rz_io_write_at;
	bnd->system = rz_io_system;
	bnd->fd_open = rz_io_fd_open;
	bnd->fd_close = rz_io_fd_close;
	bnd->fd_seek = rz_io_fd_seek;
	bnd->fd_size = rz_io_fd_size;
	bnd->fd_resize = rz_io_fd_resize;
	bnd->fd_read = rz_io_fd_read;
	bnd->fd_write = rz_io_fd_write;
	bnd->fd_read_at = rz_io_fd_read_at;
	bnd->fd_write_at = rz_io_fd_write_at;
	bnd->fd_is_dbg = rz_io_fd_is_dbg;
	bnd->fd_get_name = rz_io_fd_get_name;
	bnd->fd_get_map = rz_io_map_get_for_fd;
	bnd->fd_remap = rz_io_map_remap_fd;
	bnd->fd_getbuf = rz_io_fd_get_buf;
	bnd->is_valid_offset = rz_io_is_valid_offset;
	bnd->map_get = rz_io_map_get;
	bnd->map_get_paddr = rz_io_map_get_paddr;
	bnd->addr_is_mapped = rz_io_addr_is_mapped;
	bnd->map_add = rz_io_map_add;
#if HAVE_PTRACE
	bnd->ptrace = rz_io_ptrace;
	bnd->ptrace_func = rz_io_ptrace_func;
#endif
#if __WINDOWS__
	bnd->get_w32dbg_wrap = rz_io_get_w32dbg_wrap;
#endif
}

/* moves bytes up (+) or down (-) within the specified range */
RZ_API bool rz_io_shift(RzIO *io, ut64 start, ut64 end, st64 move) {
	ut8 *buf;
	ut64 chunksize = 0x10000;
	ut64 saved_off = io->off;
	ut64 src, shiftsize = rz_num_abs(move);
	if (!shiftsize || (end - start) <= shiftsize) {
		return false;
	}
	ut64 rest = (end - start) - shiftsize;
	if (!(buf = calloc(1, chunksize + 1))) {
		return false;
	}
	if (move > 0) {
		src = end - shiftsize;
	} else {
		src = start + shiftsize;
	}
	while (rest > 0) {
		if (chunksize > rest) {
			chunksize = rest;
		}
		if (move > 0) {
			src -= chunksize;
		}
		rz_io_read_at(io, src, buf, chunksize);
		rz_io_write_at(io, src + move, buf, chunksize);
		if (move < 0) {
			src += chunksize;
		}
		rest -= chunksize;
	}
	free(buf);
	io->off = rz_io_desc_seek(io->desc, saved_off, RZ_IO_SEEK_SET);
	return true;
}

RZ_API ut64 rz_io_seek(RzIO *io, ut64 offset, int whence) {
	if (!io) {
		return 0LL;
	}
	switch (whence) {
	case RZ_IO_SEEK_SET:
		io->off = offset;
		break;
	case RZ_IO_SEEK_CUR:
		io->off += offset;
		break;
	case RZ_IO_SEEK_END:
	default:
		io->off = rz_io_desc_seek(io->desc, offset, whence);
		break;
	}
	return io->off;
}

#if HAVE_PTRACE

#if USE_PTRACE_WRAP
#include <ptrace_wrap.h>
#include <errno.h>

static ptrace_wrap_instance *io_ptrace_wrap_instance(RzIO *io) {
	if (!io->ptrace_wrap) {
		io->ptrace_wrap = RZ_NEW(ptrace_wrap_instance);
		if (!io->ptrace_wrap) {
			return NULL;
		}
		if (ptrace_wrap_instance_start(io->ptrace_wrap) < 0) {
			RZ_FREE(io->ptrace_wrap);
			return NULL;
		}
	}
	return io->ptrace_wrap;
}
#endif

RZ_API long rz_io_ptrace(RzIO *io, rz_ptrace_request_t request, pid_t pid, void *addr, rz_ptrace_data_t data) {
#if USE_PTRACE_WRAP
	ptrace_wrap_instance *wrap = io_ptrace_wrap_instance(io);
	if (!wrap) {
		errno = 0;
		return -1;
	}
	return ptrace_wrap(wrap, request, pid, addr, data);
#else
	return ptrace(request, pid, addr, data);
#endif
}

RZ_API pid_t rz_io_ptrace_fork(RzIO *io, void (*child_callback)(void *), void *child_callback_user) {
#if USE_PTRACE_WRAP
	ptrace_wrap_instance *wrap = io_ptrace_wrap_instance(io);
	if (!wrap) {
		errno = 0;
		return -1;
	}
	return ptrace_wrap_fork(wrap, child_callback, child_callback_user);
#else
	pid_t r = rz_sys_fork();
	if (r == 0) {
		child_callback(child_callback_user);
	}
	return r;
#endif
}

RZ_API void *rz_io_ptrace_func(RzIO *io, void *(*func)(void *), void *user) {
#if USE_PTRACE_WRAP
	ptrace_wrap_instance *wrap = io_ptrace_wrap_instance(io);
	if (wrap) {
		return ptrace_wrap_func(wrap, func, user);
	}
#endif
	return func(user);
}
#endif

#if __WINDOWS__
/// Lazily initializing getter for the w32dbg_wrap instance. Only use this and don't access io->w32dbg_wrap directly.
RZ_API struct w32dbg_wrap_instance_t *rz_io_get_w32dbg_wrap(RzIO *io) {
	if (!io->priv_w32dbg_wrap) {
		io->priv_w32dbg_wrap = (struct w32dbg_wrap_instance_t *)w32dbg_wrap_new();
	}
	return io->priv_w32dbg_wrap;
}
#endif

// remove all descs and maps
RZ_API int rz_io_fini(RzIO *io) {
	if (!io) {
		return false;
	}
	rz_io_desc_cache_fini_all(io);
	rz_io_desc_fini(io);
	rz_io_map_fini(io);
	ht_sp_free(io->plugins);
	rz_io_cache_fini(io);
	if (io->runprofile) {
		RZ_FREE(io->runprofile);
	}
	rz_event_free(io->event);
	free(io->envprofile);
#if RZ_IO_USE_PTRACE_WRAP
	if (io->ptrace_wrap) {
		ptrace_wrap_instance_stop(io->ptrace_wrap);
		free(io->ptrace_wrap);
	}
#endif
#if __WINDOWS__
	w32dbg_wrap_free((W32DbgWInst *)io->priv_w32dbg_wrap);
#endif
	return true;
}
