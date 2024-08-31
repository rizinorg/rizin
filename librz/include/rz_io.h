// SPDX-FileCopyrightText: 2017-2020 condret <condr3t@protonmail.com>
// SPDX-FileCopyrightText: 2017-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2017-2020 alvaro <alvaro.felipe91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IO_H
#define RZ_IO_H

#include "rz_list.h"
#include <rz_util.h>
#include <rz_bind.h>
#include "rz_vector.h"
#include "rz_skyline.h"
#include <rz_util/rz_ptrace.h>

#define RZ_IO_SEEK_SET 0
#define RZ_IO_SEEK_CUR 1
#define RZ_IO_SEEK_END 2

#define rz_io_map_get_from(map) map->itv.addr
#define rz_io_map_get_to(map)   (rz_itv_size(map->itv) ? rz_itv_end(map->itv) - 1 : 0)

#if __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_io);

typedef struct rz_io_t {
	struct rz_io_desc_t *desc; // XXX deprecate... we should use only the fd integer, not hold a weak pointer
	ut64 off;
	int bits;
	int va; // all of this config stuff must be in 1 int
	int ff;
	int Oxff;
	size_t addrbytes;
	int aslr;
	int autofd;
	int cached;
	bool cachemode; // write in cache all the read operations (EXPERIMENTAL)
	int p_cache;
	RzIDPool *map_ids;
	RzPVector /*<RzIOMap *>*/ maps; // from tail backwards maps with higher priority are found
	RzSkyline map_skyline; // map parts that are not covered by others
	RzIDStorage *files;
	RzPVector /*<RzIOCache *>*/ cache;
	RzSkyline cache_skyline;
	ut8 *write_mask;
	int write_mask_len;
	RzList /*<RzIOPlugin *>*/ *plugins;
	char *runprofile;
	char *envprofile;
#if USE_PTRACE_WRAP
	struct ptrace_wrap_instance_t *ptrace_wrap;
#endif
#if __WINDOWS__
	struct w32dbg_wrap_instance_t *priv_w32dbg_wrap; ///< Do not access this directly, use rz_io_get_w32dbg_wrap() instead!
#endif
	char *args;
	RzEvent *event;
	PrintfCallback cb_printf;
	RzCoreBind corebind;
} RzIO;

typedef struct rz_io_desc_t {
	int fd;
	int perm;
	char *uri;
	char *name;
	char *referer;
	HtUP /*<ut64, RzIODescCache *>*/ *cache;
	void *data;
	struct rz_io_plugin_t *plugin;
	RzIO *io;
} RzIODesc;

typedef struct {
	ut64 magic;
	int pid;
	int tid;
	void *data;
} RzIODescData;

typedef struct rz_io_plugin_t {
	const char *name;
	const char *desc;
	const char *version;
	const char *author;
	const char *license;
	void *widget;
	const char *uris;
	int (*listener)(RzIODesc *io);
	int (*init)(void);
	bool isdbg;
	// int (*is_file_opened)(RzIO *io, RzIODesc *fd, const char *);
	char *(*system)(RzIO *io, RzIODesc *fd, const char *);
	RzIODesc *(*open)(RzIO *io, const char *, int perm, int mode);
	RzList /*<RzIODesc *>*/ *(*open_many)(RzIO *io, const char *, int perm, int mode);
	int (*read)(RzIO *io, RzIODesc *fd, ut8 *buf, size_t len);
	ut64 (*lseek)(RzIO *io, RzIODesc *fd, ut64 offset, int whence);
	int (*write)(RzIO *io, RzIODesc *fd, const ut8 *buf, size_t len);
	int (*close)(RzIODesc *desc);
	bool (*is_blockdevice)(RzIODesc *desc);
	bool (*is_chardevice)(RzIODesc *desc);
	int (*getpid)(RzIODesc *desc);
	int (*gettid)(RzIODesc *desc);
	bool (*getbase)(RzIODesc *desc, ut64 *base);
	bool (*resize)(RzIO *io, RzIODesc *fd, ut64 size);
	bool (*accept)(RzIO *io, RzIODesc *desc, int fd);
	int (*create)(RzIO *io, const char *file, int mode, int type);
	bool (*check)(RzIO *io, const char *, bool many);
	ut8 *(*get_buf)(RzIODesc *desc, ut64 *size);
} RzIOPlugin;

typedef struct rz_io_map_t {
	int fd;
	int perm;
	ut32 id;
	RzInterval itv;
	ut64 delta; // paddr = itv.addr + delta
	RZ_NULLABLE char *name;

	/**
	 * @brief Uninterpreted data to be injected from outside
	 *
	 * RZ_EVENT_IO_MAP_DEL may be listened to if any freeing is necessary.
	 * (Hint when part of RzCore: RzCoreIOMapInfo is stored here)
	 */
	void *user;
} RzIOMap;

typedef struct rz_io_cache_t {
	RzInterval itv;
	ut8 *data;
	ut8 *odata;
	int written;
} RzIOCache;

#define RZ_IO_DESC_CACHE_SIZE (sizeof(ut64) * 8)
typedef struct rz_io_desc_cache_t {
	ut64 cached;
	ut8 cdata[RZ_IO_DESC_CACHE_SIZE];
} RzIODescCache;

typedef struct rz_event_io_write_t {
	ut64 addr;
	const ut8 *buf;
	size_t len;
} RzEventIOWrite;

typedef struct rz_event_io_desc_close_t {
	RzIODesc *desc;
} RzEventIODescClose;

typedef struct rz_event_io_map_del_t {
	RzIOMap *map;
} RzEventIOMapDel;

struct rz_io_bind_t;

typedef int (*RzIOGetCurrentFd)(RzIO *io);
typedef bool (*RzIODescUse)(RzIO *io, int fd);
typedef RzIODesc *(*RzIODescGet)(RzIO *io, int fd);
typedef ut64 (*RzIODescSize)(RzIODesc *desc);
typedef RzIODesc *(*RzIOOpen)(RzIO *io, const char *uri, int flags, int mode);
typedef RzIODesc *(*RzIOOpenAt)(RzIO *io, const char *uri, int flags, int mode, ut64 at, RZ_NULLABLE RZ_OUT RzIOMap **map);
typedef bool (*RzIOClose)(RzIO *io, int fd);
typedef bool (*RzIOReadAt)(RzIO *io, ut64 addr, ut8 *buf, size_t len);
typedef bool (*RzIOWriteAt)(RzIO *io, ut64 addr, const ut8 *buf, size_t len);
typedef char *(*RzIOSystem)(RzIO *io, const char *cmd);
typedef int (*RzIOFdOpen)(RzIO *io, const char *uri, int flags, int mode);
typedef bool (*RzIOFdClose)(RzIO *io, int fd);
typedef ut64 (*RzIOFdSeek)(RzIO *io, int fd, ut64 addr, int whence);
typedef ut64 (*RzIOFdSize)(RzIO *io, int fd);
typedef bool (*RzIOFdResize)(RzIO *io, int fd, ut64 newsize);
typedef ut64 (*RzIOP2V)(RzIO *io, ut64 pa);
typedef ut64 (*RzIOV2P)(RzIO *io, ut64 va);
typedef int (*RzIOFdRead)(RzIO *io, int fd, ut8 *buf, size_t len);
typedef int (*RzIOFdWrite)(RzIO *io, int fd, const ut8 *buf, size_t len);
typedef int (*RzIOFdReadAt)(RzIO *io, int fd, ut64 addr, ut8 *buf, size_t len);
typedef int (*RzIOFdWriteAt)(RzIO *io, int fd, ut64 addr, const ut8 *buf, size_t len);
typedef bool (*RzIOFdIsDbg)(RzIO *io, int fd);
typedef const char *(*RzIOFdGetName)(RzIO *io, int fd);
typedef RzList *(*RzIOFdGetMap)(RzIO *io, int fd);
typedef bool (*RzIOFdRemap)(RzIO *io, int fd, ut64 addr);
typedef ut8 *(*RzIOFdGetBuf)(RzIO *io, int fd, ut64 *size);
typedef bool (*RzIOIsValidOff)(RzIO *io, ut64 addr, int hasperm);
typedef RzIOMap *(*RzIOMapGet)(RzIO *io, ut64 addr);
typedef RzIOMap *(*RzIOMapGetPaddr)(RzIO *io, ut64 paddr);
typedef bool (*RzIOAddrIsMapped)(RzIO *io, ut64 addr);
typedef RzIOMap *(*RzIOMapAdd)(RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
#if HAVE_PTRACE
typedef long (*RzIOPtraceFn)(RzIO *io, rz_ptrace_request_t request, pid_t pid, void *addr, rz_ptrace_data_t data);
typedef void *(*RzIOPtraceFuncFn)(RzIO *io, void *(*func)(void *), void *user);
#endif
#if __WINDOWS__
typedef struct w32dbg_wrap_instance_t *(*RzIOGetW32DbgWrap)(RzIO *io);
#endif

typedef struct rz_io_bind_t {
	int init;
	RzIO *io;
	RzIOGetCurrentFd fd_get_current;
	RzIODescUse desc_use;
	RzIODescGet desc_get;
	RzIODescSize desc_size;
	RzIOOpen open;
	RzIOOpenAt open_at;
	RzIOClose close;
	RzIOReadAt read_at;
	RzIOWriteAt write_at;
	RzIOSystem system;
	RzIOFdOpen fd_open;
	RzIOFdClose fd_close;
	RzIOFdSeek fd_seek; // needed for esil
	RzIOFdSize fd_size;
	RzIOFdResize fd_resize;
	RzIOFdRead fd_read; // needed for esil
	RzIOFdWrite fd_write; // needed for esil
	RzIOFdReadAt fd_read_at;
	RzIOFdWriteAt fd_write_at;
	RzIOFdIsDbg fd_is_dbg;
	RzIOFdGetName fd_get_name;
	RzIOFdGetMap fd_get_map;
	RzIOFdRemap fd_remap;
	RzIOFdGetBuf fd_getbuf;
	RzIOIsValidOff is_valid_offset;
	RzIOAddrIsMapped addr_is_mapped;
	RzIOMapGet map_get;
	RzIOMapGetPaddr map_get_paddr;
	RzIOMapAdd map_add;
	RzIOV2P v2p;
	RzIOP2V p2v;
#if HAVE_PTRACE
	RzIOPtraceFn ptrace;
	RzIOPtraceFuncFn ptrace_func;
#endif
#if __WINDOWS__
	RzIOGetW32DbgWrap get_w32dbg_wrap;
#endif
} RzIOBind;

// map.c
RZ_API RzIOMap *rz_io_map_new(RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
RZ_API void rz_io_map_init(RzIO *io);
RZ_API bool rz_io_map_remap(RzIO *io, ut32 id, ut64 addr);
RZ_API bool rz_io_map_remap_fd(RzIO *io, int fd, ut64 addr);
RZ_API ut64 rz_io_map_location(RzIO *io, ut64 size);
RZ_API bool rz_io_map_exists(RzIO *io, RzIOMap *map);
RZ_API bool rz_io_map_exists_for_id(RzIO *io, ut32 id);
RZ_API RzIOMap *rz_io_map_resolve(RzIO *io, ut32 id);
RZ_API RzIOMap *rz_io_map_add(RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
// same as rz_io_map_add but used when many maps need to be added. Call rz_io_update when all maps have been added.
RZ_API RzIOMap *rz_io_map_add_batch(RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
RZ_API RzIOMap *rz_io_map_get(RzIO *io, ut64 addr); // returns the map at vaddr with the highest priority
// update the internal state of RzIO after a series of _batch operations
RZ_API void rz_io_update(RzIO *io);
RZ_API bool rz_io_map_is_mapped(RzIO *io, ut64 addr);
RZ_API RzIOMap *rz_io_map_get_paddr(RzIO *io, ut64 paddr); // returns the map at paddr with the highest priority
RZ_API void rz_io_map_reset(RzIO *io);
RZ_API bool rz_io_map_del(RzIO *io, ut32 id);
RZ_API bool rz_io_map_del_for_fd(RzIO *io, int fd);
RZ_API bool rz_io_map_depriorize(RzIO *io, ut32 id);
RZ_API bool rz_io_map_priorize(RzIO *io, ut32 id);
RZ_API bool rz_io_map_priorize_for_fd(RzIO *io, int fd);
RZ_API void rz_io_map_cleanup(RzIO *io);
RZ_API void rz_io_map_fini(RzIO *io);
RZ_API void rz_io_map_set_name(RzIOMap *map, const char *name);
RZ_API void rz_io_map_del_name(RzIOMap *map);
RZ_API RzList /*<RzIOMap *>*/ *rz_io_map_get_for_fd(RzIO *io, int fd);
RZ_API bool rz_io_map_resize(RzIO *io, ut32 id, ut64 newsize);
RZ_API RZ_BORROW RzPVector /*<RzIOMap *>*/ *rz_io_maps(RzIO *io);

// next free address to place a map.. maybe just unify
RZ_API ut64 rz_io_map_next_available(RzIO *io, ut64 addr, ut64 size, ut64 load_align);
RZ_API ut64 rz_io_map_next_address(RzIO *io, ut64 addr);

// p2v/v2p

RZ_API ut64 rz_io_p2v(RzIO *io, ut64 pa);
RZ_API ut64 rz_io_v2p(RzIO *io, ut64 va);

// io.c
RZ_API RzIO *rz_io_new(void);
RZ_API RzIO *rz_io_init(RzIO *io);
RZ_API RzIODesc *rz_io_open_nomap(RzIO *io, const char *uri, int flags, int mode); // should return int
RZ_API RzIODesc *rz_io_open(RzIO *io, const char *uri, int flags, int mode);
RZ_API RzIODesc *rz_io_open_at(RzIO *io, const char *uri, int flags, int mode, ut64 at, RZ_NULLABLE RZ_OUT RzIOMap **map);
RZ_API RzList /*<RzIODesc *>*/ *rz_io_open_many(RzIO *io, const char *uri, int flags, int mode);
RZ_API RzIODesc *rz_io_open_buffer(RzIO *io, RzBuffer *b, int flags, int mode);
RZ_API bool rz_io_close(RzIO *io);
RZ_API bool rz_io_reopen(RzIO *io, int fd, int flags, int mode);
RZ_API int rz_io_close_all(RzIO *io);
RZ_API int rz_io_pread_at(RzIO *io, ut64 paddr, ut8 *buf, size_t len);
RZ_API int rz_io_pwrite_at(RzIO *io, ut64 paddr, const ut8 *buf, size_t len);
RZ_API bool rz_io_vread_at_mapped(RzIO *io, ut64 vaddr, ut8 *buf, size_t len);
RZ_API bool rz_io_read_at(RzIO *io, ut64 addr, ut8 *buf, size_t len);
RZ_API bool rz_io_read_at_mapped(RzIO *io, ut64 addr, ut8 *buf, size_t len);
RZ_API int rz_io_nread_at(RzIO *io, ut64 addr, ut8 *buf, size_t len);
RZ_API bool rz_io_write_at(RzIO *io, ut64 addr, const ut8 *buf, size_t len);
RZ_API bool rz_io_read(RzIO *io, ut8 *buf, size_t len);
RZ_API bool rz_io_write(RzIO *io, const ut8 *buf, size_t len);
RZ_API ut64 rz_io_size(RzIO *io);
RZ_API bool rz_io_is_listener(RzIO *io);
RZ_API char *rz_io_system(RzIO *io, const char *cmd);
RZ_API bool rz_io_resize(RZ_NONNULL RzIO *io, ut64 newsize);
RZ_API bool rz_io_extend_at(RzIO *io, ut64 addr, ut64 size);
RZ_API bool rz_io_set_write_mask(RzIO *io, const ut8 *mask, size_t len);
RZ_API void rz_io_bind(RzIO *io, RzIOBind *bnd);
RZ_API bool rz_io_shift(RzIO *io, ut64 start, ut64 end, st64 move);
RZ_API ut64 rz_io_seek(RzIO *io, ut64 offset, int whence);
RZ_API int rz_io_fini(RzIO *io);
RZ_API void rz_io_free(RzIO *io);
#define rz_io_bind_init(x) memset(&x, 0, sizeof(x))

RZ_API bool rz_io_plugin_init(RzIO *io);
RZ_API bool rz_io_plugin_add(RzIO *io, RZ_NONNULL RZ_BORROW RzIOPlugin *plugin);
RZ_API bool rz_io_plugin_del(RzIO *io, RZ_NONNULL RZ_BORROW RzIOPlugin *plugin);
RZ_API int rz_io_plugin_read(RzIODesc *desc, ut8 *buf, size_t len);
RZ_API int rz_io_plugin_write(RzIODesc *desc, const ut8 *buf, size_t len);
RZ_API int rz_io_plugin_read_at(RzIODesc *desc, ut64 addr, ut8 *buf, size_t len);
RZ_API int rz_io_plugin_write_at(RzIODesc *desc, ut64 addr, const ut8 *buf, size_t len);
RZ_API RzIOPlugin *rz_io_plugin_resolve(RzIO *io, const char *filename, bool many);
RZ_API RzIOPlugin *rz_io_plugin_get_default(RzIO *io, const char *filename, bool many);

// desc.c
RZ_API RzIODesc *rz_io_desc_new(RzIO *io, RzIOPlugin *plugin, const char *uri, int flags, int mode, void *data);
RZ_API RzIODesc *rz_io_desc_open(RzIO *io, const char *uri, int flags, int mode);
RZ_API RzIODesc *rz_io_desc_open_plugin(RzIO *io, RzIOPlugin *plugin, const char *uri, int flags, int mode);
RZ_API bool rz_io_desc_close(RzIODesc *desc);
RZ_API int rz_io_desc_read(RzIODesc *desc, ut8 *buf, size_t len);
RZ_API int rz_io_desc_write(RzIODesc *desc, const ut8 *buf, size_t len);
RZ_API void rz_io_desc_free(RzIODesc *desc);
RZ_API bool rz_io_desc_add(RzIO *io, RzIODesc *desc);
RZ_API bool rz_io_desc_del(RzIO *io, int fd);
RZ_API RzIODesc *rz_io_desc_get(RzIO *io, int fd);
RZ_API ut64 rz_io_desc_seek(RzIODesc *desc, ut64 offset, int whence);
RZ_API bool rz_io_desc_resize(RzIODesc *desc, ut64 newsize);
RZ_API ut64 rz_io_desc_size(RzIODesc *desc);
RZ_API ut8 *rz_io_desc_get_buf(RzIODesc *desc, RZ_OUT RZ_NONNULL ut64 *size);
RZ_API bool rz_io_desc_is_blockdevice(RzIODesc *desc);
RZ_API bool rz_io_desc_is_chardevice(RzIODesc *desc);
RZ_API bool rz_io_desc_exchange(RzIO *io, int fd, int fdx); // this should get 2 descs
RZ_API bool rz_io_desc_is_dbg(RzIODesc *desc);
RZ_API int rz_io_desc_get_pid(RzIODesc *desc);
RZ_API int rz_io_desc_get_tid(RzIODesc *desc);
RZ_API bool rz_io_desc_get_base(RzIODesc *desc, ut64 *base);
RZ_API int rz_io_desc_read_at(RzIODesc *desc, ut64 addr, ut8 *buf, size_t len);
RZ_API int rz_io_desc_write_at(RzIODesc *desc, ut64 addr, const ut8 *buf, size_t len);

/* lifecycle */
RZ_IPI bool rz_io_desc_init(RzIO *io);
RZ_IPI bool rz_io_desc_fini(RzIO *io);

/* io/cache.c */
RZ_API int rz_io_cache_invalidate(RzIO *io, ut64 from, ut64 to);
RZ_API bool rz_io_cache_at(RzIO *io, ut64 addr);
RZ_API void rz_io_cache_commit(RzIO *io, ut64 from, ut64 to);
RZ_API void rz_io_cache_init(RzIO *io);
RZ_API void rz_io_cache_fini(RzIO *io);
RZ_API void rz_io_cache_reset(RzIO *io, int set);
RZ_API bool rz_io_cache_write(RzIO *io, ut64 addr, const ut8 *buf, size_t len);
RZ_API bool rz_io_cache_read(RzIO *io, ut64 addr, ut8 *buf, size_t len);

/* io/p_cache.c */
RZ_API bool rz_io_desc_cache_init(RzIODesc *desc);
RZ_API int rz_io_desc_cache_write(RzIODesc *desc, ut64 paddr, const ut8 *buf, size_t len);
RZ_API int rz_io_desc_cache_read(RzIODesc *desc, ut64 paddr, ut8 *buf, size_t len);
RZ_API bool rz_io_desc_cache_commit(RzIODesc *desc);
RZ_API void rz_io_desc_cache_cleanup(RzIODesc *desc);
RZ_API void rz_io_desc_cache_fini(RzIODesc *desc);
RZ_API void rz_io_desc_cache_fini_all(RzIO *io);
RZ_API RzList /*<RzIOCache *>*/ *rz_io_desc_cache_list(RzIODesc *desc);

/* io/fd.c */
RZ_API int rz_io_fd_open(RzIO *io, const char *uri, int flags, int mode);
RZ_API bool rz_io_fd_close(RzIO *io, int fd);
RZ_API int rz_io_fd_read(RzIO *io, int fd, ut8 *buf, size_t len);
RZ_API int rz_io_fd_write(RzIO *io, int fd, const ut8 *buf, size_t len);
RZ_API ut64 rz_io_fd_seek(RzIO *io, int fd, ut64 addr, int whence);
RZ_API ut64 rz_io_fd_size(RzIO *io, int fd);
RZ_API ut8 *rz_io_fd_get_buf(RzIO *io, int fd, RZ_OUT RZ_NONNULL ut64 *size);
RZ_API bool rz_io_fd_resize(RzIO *io, int fd, ut64 newsize);
RZ_API bool rz_io_fd_is_blockdevice(RzIO *io, int fd);
RZ_API bool rz_io_fd_is_chardevice(RzIO *io, int fd);
RZ_API int rz_io_fd_read_at(RzIO *io, int fd, ut64 addr, ut8 *buf, size_t len);
RZ_API int rz_io_fd_write_at(RzIO *io, int fd, ut64 addr, const ut8 *buf, size_t len);
RZ_API bool rz_io_fd_is_dbg(RzIO *io, int fd);
RZ_API int rz_io_fd_get_pid(RzIO *io, int fd);
RZ_API int rz_io_fd_get_tid(RzIO *io, int fd);
RZ_API bool rz_io_fd_get_base(RzIO *io, int fd, ut64 *base);
RZ_API const char *rz_io_fd_get_name(RzIO *io, int fd);
RZ_API int rz_io_fd_get_current(RzIO *io);
RZ_API int rz_io_fd_get_next(RzIO *io, int fd);
RZ_API int rz_io_fd_get_prev(RzIO *io, int fd);
RZ_API int rz_io_fd_get_highest(RzIO *io);
RZ_API int rz_io_fd_get_lowest(RzIO *io);
RZ_API bool rz_io_use_fd(RzIO *io, int fd);

#define rz_io_range_new()   RZ_NEW0(RzIORange)
#define rz_io_range_free(x) free(x)

/* io/ioutils.c */
RZ_API bool rz_io_is_valid_offset(RzIO *io, ut64 offset, int hasperm);
RZ_API bool rz_io_addr_is_mapped(RzIO *io, ut64 vaddr);
RZ_API bool rz_io_read_i(RzIO *io, ut64 addr, ut64 *val, int size, bool endian);
RZ_API bool rz_io_write_i(RzIO *io, ut64 addr, ut64 *val, int size, bool endian);

#if HAVE_PTRACE
RZ_API long rz_io_ptrace(RzIO *io, rz_ptrace_request_t request, pid_t pid, void *addr, rz_ptrace_data_t data);
RZ_API pid_t rz_io_ptrace_fork(RzIO *io, void (*child_callback)(void *), void *child_callback_user);
RZ_API void *rz_io_ptrace_func(RzIO *io, void *(*func)(void *), void *user);
#endif

#if __WINDOWS__
RZ_API struct w32dbg_wrap_instance_t *rz_io_get_w32dbg_wrap(RzIO *io);
#endif

#if __cplusplus
}
#endif

#endif
