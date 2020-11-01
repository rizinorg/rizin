/* rizin - LGPL - Copyright 2017-2020 - condret, pancake, alvaro */

#include <rz_io.h>
#include <sdb.h>
#include <string.h>

// shall be used by plugins for creating descs
RZ_API RzIODesc* rz_io_desc_new(RzIO* io, RzIOPlugin* plugin, const char* uri, int perm, int mode, void* data) {
	ut32 fd32 = 0;
	// this is required for emscripten builds to work, but should assert
	if (!io || !plugin || !uri) {
		return NULL;
	}
	if (io->files) {
		if (!rz_id_pool_grab_id (io->files->pool, &fd32)) {
			return NULL;
		}
	}
	RzIODesc* desc = RZ_NEW0 (RzIODesc);
	if (desc) {
		desc->fd = fd32;
		desc->io = io;
		desc->plugin = plugin;
		desc->data = data;
		desc->perm = perm;
		//because the uri-arg may live on the stack
		desc->uri = strdup (uri);
	}
	return desc;
}

RZ_API void rz_io_desc_free(RzIODesc* desc) {
	if (desc) {
		free (desc->uri);
		free (desc->referer);
		free (desc->name);
		rz_io_desc_cache_fini (desc);
		if (desc->io && desc->io->files) {
			rz_id_storage_delete (desc->io->files, desc->fd);
		}
//		free (desc->plugin);
	}
	free (desc);
}

RZ_API bool rz_io_desc_add(RzIO* io, RzIODesc* desc) {
	rz_return_val_if_fail (io && desc && desc->io, false);
	if (!rz_id_storage_set (io->files, desc, desc->fd)) {
		// TODO: use assert here
		eprintf ("You are using this API incorrectly\n");
		eprintf ("fd %d was probably not generated by this RzIO-instance\n", desc->fd);
		rz_sys_backtrace ();
		return false;
	}
	return true;
}

RZ_API bool rz_io_desc_del(RzIO* io, int fd) {		//can we pass this a riodesc and check if it belongs to the desc->io ?
	rz_return_val_if_fail (io && io->files, false);
	RzIODesc* desc = rz_id_storage_get (io->files, fd);
	rz_io_desc_free (desc);
	if (desc == io->desc) {
		io->desc = NULL;
	}
	// remove all dead maps
	rz_io_map_cleanup (io);
	return true;
}

RZ_API RzIODesc* rz_io_desc_get(RzIO* io, int fd) {
	rz_return_val_if_fail (io && io->files, NULL);
	return (RzIODesc*) rz_id_storage_get (io->files, fd);
}

RZ_API RzIODesc *rz_io_desc_get_next(RzIO *io, RzIODesc *desc) {
	rz_return_val_if_fail (desc && io && io->files, NULL);
	const int next_fd = rz_io_fd_get_next (io, desc->fd);
	if (next_fd == -1) {
		return NULL;
	}
	return (RzIODesc*) rz_id_storage_get (io->files, next_fd);
}

RZ_API RzIODesc *rz_io_desc_get_prev(RzIO *io, RzIODesc *desc) {
	rz_return_val_if_fail (desc && io && io->files, NULL);
	const int prev_fd = rz_io_fd_get_prev (io, desc->fd);
	if (prev_fd == -1) {
		return NULL;
	}
	return (RzIODesc*) rz_id_storage_get (io->files, prev_fd);
}

RZ_API RzIODesc *rz_io_desc_get_highest(RzIO *io) {
	int fd = rz_io_fd_get_highest (io);
	if (fd == -1) {
		return NULL;
	}
	return rz_io_desc_get (io, fd);
}

RZ_API RzIODesc *rz_io_desc_get_lowest(RzIO *io) {
	int fd = rz_io_fd_get_lowest (io);
	if (fd == -1) {
		return NULL;
	}
	return rz_io_desc_get (io, fd);
}

RZ_API RzIODesc *rz_io_desc_open(RzIO *io, const char *uri, int perm, int mode) {
	rz_return_val_if_fail (io && uri, NULL);
	RzIOPlugin *plugin = rz_io_plugin_resolve (io, uri, 0);
	if (!plugin || !plugin->open) {
		return NULL;
	}
	RzIODesc *desc = plugin->open (io, uri, perm, mode);
	if (!desc) {
		return NULL;
	}
	// for none static callbacks, those that cannot use rz_io_desc_new
	if (!desc->name) {
		desc->name = strdup (uri);
	}
	if (!desc->uri) {
		desc->uri = strdup (uri);
	}
	if (!desc->plugin) {
		desc->plugin = plugin;
	}
	if (!rz_io_desc_add (io, desc)) {
		rz_io_desc_free (desc);
		return NULL;
	}
	return desc;
}

RZ_API RzIODesc *rz_io_desc_open_plugin(RzIO *io, RzIOPlugin *plugin, const char *uri, int perm, int mode) {
	rz_return_val_if_fail (io && io->files && uri, NULL);
	if (!plugin || !plugin->open || !plugin->check || !plugin->check (io, uri, false)) {
		return NULL;
	}
	RzIODesc *desc = plugin->open (io, uri, perm, mode);
	if (!desc) {
		return NULL;
	}
	// for none static callbacks, those that cannot use rz_io_desc_new
	if (!desc->plugin) {
		desc->plugin = plugin;
	}
	if (!desc->uri) {
		desc->uri = strdup (uri);
	}
	if (!desc->name) {
		desc->name = strdup (uri);
	}
	if (!rz_io_desc_add (io, desc)) {
		rz_io_desc_free (desc);
		return NULL;
	}
	return desc;
}


RZ_API bool rz_io_desc_close(RzIODesc *desc) {
	RzIO *io;
	if (!desc || !desc->io || !desc->plugin) {
		return false;
	}
	if (desc->plugin->close && desc->plugin->close (desc)) {
		return false;
	}
	io = desc->io;
	// remove entry from idstorage and free the desc-struct
	rz_io_desc_del (io, desc->fd);
	// remove all dead maps
	rz_io_map_cleanup (io);
	return true;
}

//returns length of written bytes
RZ_API int rz_io_desc_write(RzIODesc *desc, const ut8* buf, int len) {
	rz_return_val_if_fail (desc && buf, -1);
	if (len < 0) {
		return -1;
	}
	//check pointers and pcache
	if (desc->io && (desc->io->p_cache & 2)) {
		return rz_io_desc_cache_write (desc,
				rz_io_desc_seek (desc, 0LL, RZ_IO_SEEK_CUR), buf, len);
	}
	return rz_io_plugin_write (desc, buf, len);
}

// returns length of read bytes
RZ_API int rz_io_desc_read(RzIODesc *desc, ut8 *buf, int len) {
	// check pointers and permissions
	if (!buf || !desc || !desc->plugin || !(desc->perm & RZ_PERM_R)) {
		return -1;
	}
	ut64 seek = rz_io_desc_seek (desc, 0LL, RZ_IO_SEEK_CUR);
	if (desc->io->cachemode) {
		if (seek != UT64_MAX && rz_io_cache_at (desc->io, seek)) {
			return rz_io_cache_read (desc->io, seek, buf, len);
		}
	}
	int ret = rz_io_plugin_read (desc, buf, len);
	if (ret > 0 && desc->io->cachemode) {
		rz_io_cache_write (desc->io, seek, buf, len);
	} else if ((ret > 0) && desc->io && (desc->io->p_cache & 1)) {
		ret = rz_io_desc_cache_read (desc, seek, buf, ret);
	}
	return ret;
}

RZ_API ut64 rz_io_desc_seek(RzIODesc* desc, ut64 offset, int whence) {
	if (!desc || !desc->plugin || !desc->plugin->lseek) {
		return (ut64) -1;
	}
	return desc->plugin->lseek (desc->io, desc, offset, whence);
}

RZ_API ut64 rz_io_desc_size(RzIODesc* desc) {
	if (!desc || !desc->plugin || !desc->plugin->lseek) {
		return 0LL;
	}
	ut64 off = rz_io_desc_seek (desc, 0LL, RZ_IO_SEEK_CUR);
	ut64 ret = rz_io_desc_seek (desc, 0LL, RZ_IO_SEEK_END);
	// what to do if that seek fails?
	rz_io_desc_seek (desc, off, RZ_IO_SEEK_SET);
	return ret;
}

RZ_API bool rz_io_desc_resize(RzIODesc *desc, ut64 newsize) {
	if (desc && desc->plugin && desc->plugin->resize) {
		bool ret = desc->plugin->resize (desc->io, desc, newsize);
		if (desc->io && desc->io->p_cache) {
			rz_io_desc_cache_cleanup (desc);
		}
		return ret;
	}
	return false;
}

RZ_API bool rz_io_desc_is_blockdevice(RzIODesc *desc) {
	if (!desc || !desc->plugin || !desc->plugin->is_blockdevice) {
		return false;
	}
	return desc->plugin->is_blockdevice (desc);
}

RZ_API bool rz_io_desc_is_chardevice(RzIODesc *desc) {
	if (!desc || !desc->plugin || !desc->plugin->is_chardevice) {
		return false;
	}
	return desc->plugin->is_chardevice (desc);
}

RZ_API bool rz_io_desc_exchange(RzIO* io, int fd, int fdx) {
	RzIODesc* desc, * descx;
	if (!(desc = rz_io_desc_get (io, fd)) || !(descx = rz_io_desc_get (io, fdx))) {
		return false;
	}
	desc->fd = fdx;
	descx->fd = fd;
	rz_id_storage_set (io->files, desc,  fdx);
	rz_id_storage_set (io->files, descx, fd);
	if (io->p_cache) {
		HtUP* cache = desc->cache;
		desc->cache = descx->cache;
		descx->cache = cache;
		rz_io_desc_cache_cleanup (desc);
		rz_io_desc_cache_cleanup (descx);
	}
	void **it;
	rz_pvector_foreach (&io->maps, it) {
		RzIOMap *map = *it;
		if (map->fd == fdx) {
			map->perm &= (desc->perm | RZ_PERM_X);
		} else if (map->fd == fd) {
			map->perm &= (descx->perm | RZ_PERM_X);
		}
	}
	return true;
}

RZ_API bool rz_io_desc_is_dbg(RzIODesc *desc) {
	if (desc && desc->plugin) {
		return desc->plugin->isdbg;
	}
	return false;
}

RZ_API int rz_io_desc_get_pid(RzIODesc *desc) {
	//-1 and -2 are reserved
	if (!desc) {
		return -3;
	}
	if (!desc->plugin) {
		return -4;
	}
	if (!desc->plugin->isdbg) {
		return -5;
	}
	if (!desc->plugin->getpid) {
		return -6;
	}
	return desc->plugin->getpid (desc);
}

RZ_API int rz_io_desc_get_tid(RzIODesc *desc) {
	//-1 and -2 are reserved
	if (!desc) {
		return -3;
	}
	if (!desc->plugin) {
		return -4;
	}
	if (!desc->plugin->isdbg) {
		return -5;
	}
	if (!desc->plugin->gettid) {
		return -6;
	}
	return desc->plugin->gettid (desc);
}

RZ_API bool rz_io_desc_get_base (RzIODesc *desc, ut64 *base) {
	if (!base || !desc || !desc->plugin || !desc->plugin->isdbg || !desc->plugin->getbase) {
		return false;
	}
	return desc->plugin->getbase (desc, base);
}

RZ_API int rz_io_desc_read_at(RzIODesc *desc, ut64 addr, ut8 *buf, int len) {
	if (desc && buf && (rz_io_desc_seek (desc, addr, RZ_IO_SEEK_SET) == addr)) {
		return rz_io_desc_read (desc, buf, len);
	}
	return 0;
}

RZ_API int rz_io_desc_write_at(RzIODesc *desc, ut64 addr, const ut8 *buf, int len) {
	if (desc && buf && (rz_io_desc_seek (desc, addr, RZ_IO_SEEK_SET) == addr)) {
		return rz_io_desc_write (desc, buf, len);
	}
	return 0;
}

RZ_API int rz_io_desc_extend(RzIODesc *desc, ut64 size) {
	if (desc && desc->plugin && desc->plugin->extend) {
		return desc->plugin->extend (desc->io, desc, size);
	}
	return 0;
}

/* lifecycle */

// TODO: move into io.c : rz_io_init
RZ_IPI bool rz_io_desc_init(RzIO* io) {
	rz_return_val_if_fail (io, false);
	rz_io_desc_fini (io);
	// TODO: it leaks if called twice
	//fd is signed
	io->files = rz_id_storage_new (3, 0x80000000);
	if (!io->files) {
		return false;
	}
	return true;
}

static bool desc_fini_cb(void* user, void* data, ut32 id) {
	RzIODesc* desc = (RzIODesc*) data;
	if (desc->plugin && desc->plugin->close) {
		desc->plugin->close (desc);
	}
	rz_io_desc_free (desc);
	return true;
}

//closes all descs and frees all descs and io->files
RZ_IPI bool rz_io_desc_fini(RzIO* io) {
	rz_return_val_if_fail (io, NULL);
	if (io->files) {
		rz_id_storage_foreach (io->files, desc_fini_cb, io);
		rz_id_storage_free (io->files);
		io->files = NULL;
	}
	//no map-cleanup here, to keep it modular useable
	io->desc = NULL;
	return true;
}
