/* rizin - LGPL - Copyright 2017-2020 - condret, pancake, alvaro */

#ifndef RZ_IO_H
#define RZ_IO_H

#include "rz_list.h"
#include <rz_util.h>
#include "rz_socket.h"
#include "rz_vector.h"
#include "rz_skyline.h"

#define RZ_IO_SEEK_SET	0
#define RZ_IO_SEEK_CUR	1
#define RZ_IO_SEEK_END	2

#define RZ_IO_UNDOS 64

#define rz_io_map_get_from(map) map->itv.addr
#define rz_io_map_get_to(map) ( rz_itv_end (map->itv) - 1 )

#if HAVE_PTRACE

#if __sun
#include <sys/types.h>
#else
#if DEBUGGER && HAVE_PTRACE
#include <sys/ptrace.h>
#endif
#endif

#if (defined(__GLIBC__) && defined(__linux__))
typedef enum __ptrace_request rz_ptrace_request_t;
typedef void * rz_ptrace_data_t;
#define RZ_PTRACE_NODATA NULL
#else
#if __ANDROID__
typedef int rz_ptrace_request_t;
typedef void * rz_ptrace_data_t;
#define RZ_PTRACE_NODATA NULL
#else
typedef int rz_ptrace_request_t;
typedef int rz_ptrace_data_t;
#define RZ_PTRACE_NODATA 0
#endif
#endif
#endif

#if __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_io);

typedef struct rz_io_undos_t {
	ut64 off;
	int cursor;
} RzIOUndos;

typedef struct rz_io_undo_t {
	int s_enable;
	int w_enable;
	/* write stuff */
	RzList *w_list;
	int w_init;
	/* seek stuff */
	int idx;
	int undos; /* available undos */
	int redos; /* available redos */
	RzIOUndos seek[RZ_IO_UNDOS];
	/*int fd[RZ_IO_UNDOS]; // XXX: Must be RzIODesc* */
} RzIOUndo;

typedef struct rz_io_undo_w_t {
	int set;
	ut64 off;
	ut8 *o;   /* old data */
	ut8 *n;   /* new data */
	int len;  /* length */
} RzIOUndoWrite;

typedef struct rz_io_t {
	struct rz_io_desc_t *desc; // XXX deprecate... we should use only the fd integer, not hold a weak pointer
	ut64 off;
	int bits;
	int va;		//all of this config stuff must be in 1 int
	int ff;
	int Oxff;
	size_t addrbytes;
	int aslr;
	int autofd;
	int cached;
	bool cachemode; // write in cache all the read operations (EXPERIMENTAL)
	int p_cache;
	RzIDPool *map_ids;
	RzPVector maps; //from tail backwards maps with higher priority are found
	RzSkyline map_skyline; // map parts that are not covered by others
	RzIDStorage *files;
	RzCache *buffer;
	RzPVector cache;
	RzSkyline cache_skyline;
	ut8 *write_mask;
	int write_mask_len;
	RzIOUndo undo;
	SdbList *plugins;
	char *runprofile;
	char *envprofile;
#if USE_PTRACE_WRAP
	struct ptrace_wrap_instance_t *ptrace_wrap;
#endif
#if __WINDOWS__
	struct w32dbg_wrap_instance_t *w32dbg_wrap;
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
	HtUP/*<ut64, RzIODescCache *>*/ *cache;
	void *data;
	struct rz_io_plugin_t *plugin;
	RzIO *io;
} RzIODesc;

typedef struct {
	ut32 magic;
	int pid;
	int tid;
	void *data;
} RzIODescData;

// Move somewhere else?
typedef struct {
	RzSocket *fd;
	RzSocket *client;
	bool listener;
} RzIORap;

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
	RzIOUndo undo;
	bool isdbg;
	// int (*is_file_opened)(RzIO *io, RzIODesc *fd, const char *);
	char *(*system)(RzIO *io, RzIODesc *fd, const char *);
	RzIODesc* (*open)(RzIO *io, const char *, int perm, int mode);
	RzList* /*RzIODesc* */ (*open_many)(RzIO *io, const char *, int perm, int mode);
	int (*read)(RzIO *io, RzIODesc *fd, ut8 *buf, int count);
	ut64 (*lseek)(RzIO *io, RzIODesc *fd, ut64 offset, int whence);
	int (*write)(RzIO *io, RzIODesc *fd, const ut8 *buf, int count);
	int (*close)(RzIODesc *desc);
	bool (*is_blockdevice)(RzIODesc *desc);
	bool (*is_chardevice)(RzIODesc *desc);
	int (*getpid)(RzIODesc *desc);
	int (*gettid)(RzIODesc *desc);
	bool (*getbase)(RzIODesc *desc, ut64 *base);
	bool (*resize)(RzIO *io, RzIODesc *fd, ut64 size);
	int (*extend)(RzIO *io, RzIODesc *fd, ut64 size);
	bool (*accept)(RzIO *io, RzIODesc *desc, int fd);
	int (*create)(RzIO *io, const char *file, int mode, int type);
	bool (*check)(RzIO *io, const char *, bool many);
} RzIOPlugin;

typedef struct rz_io_map_t {
	int fd;
	int perm;
	ut32 id;
	RzInterval itv;
	ut64 delta; // paddr = itv.addr + delta
	char *name;
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

struct rz_io_bind_t;

typedef bool (*RzIODescUse) (RzIO *io, int fd);
typedef RzIODesc *(*RzIODescGet) (RzIO *io, int fd);
typedef ut64 (*RzIODescSize) (RzIODesc *desc);
typedef RzIODesc *(*RzIOOpen) (RzIO *io, const char *uri, int flags, int mode);
typedef RzIODesc *(*RzIOOpenAt) (RzIO *io, const  char *uri, int flags, int mode, ut64 at);
typedef bool (*RzIOClose) (RzIO *io, int fd);
typedef bool (*RzIOReadAt) (RzIO *io, ut64 addr, ut8 *buf, int len);
typedef bool (*RzIOWriteAt) (RzIO *io, ut64 addr, const ut8 *buf, int len);
typedef char *(*RzIOSystem) (RzIO *io, const char* cmd);
typedef int (*RzIOFdOpen) (RzIO *io, const char *uri, int flags, int mode);
typedef bool (*RzIOFdClose) (RzIO *io, int fd);
typedef ut64 (*RzIOFdSeek) (RzIO *io, int fd, ut64 addr, int whence);
typedef ut64 (*RzIOFdSize) (RzIO *io, int fd);
typedef bool (*RzIOFdResize) (RzIO *io, int fd, ut64 newsize);
typedef ut64 (*RzIOP2V) (RzIO *io, ut64 pa);
typedef ut64 (*RzIOV2P) (RzIO *io, ut64 va);
typedef int (*RzIOFdRead) (RzIO *io, int fd, ut8 *buf, int len);
typedef int (*RzIOFdWrite) (RzIO *io, int fd, const ut8 *buf, int len);
typedef int (*RzIOFdReadAt) (RzIO *io, int fd, ut64 addr, ut8 *buf, int len);
typedef int (*RzIOFdWriteAt) (RzIO *io, int fd, ut64 addr, const ut8 *buf, int len);
typedef bool (*RzIOFdIsDbg) (RzIO *io, int fd);
typedef const char *(*RzIOFdGetName) (RzIO *io, int fd);
typedef RzList *(*RzIOFdGetMap) (RzIO *io, int fd);
typedef bool (*RzIOFdRemap) (RzIO *io, int fd, ut64 addr);
typedef bool (*RzIOIsValidOff) (RzIO *io, ut64 addr, int hasperm);
typedef RzIOMap *(*RzIOMapGet) (RzIO *io, ut64 addr);
typedef RzIOMap *(*RzIOMapGetPaddr) (RzIO *io, ut64 paddr);
typedef bool (*RzIOAddrIsMapped) (RzIO *io, ut64 addr);
typedef RzIOMap *(*RzIOMapAdd) (RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
#if HAVE_PTRACE
typedef long (*RzIOPtraceFn) (RzIO *io, rz_ptrace_request_t request, pid_t pid, void *addr, rz_ptrace_data_t data);
typedef void *(*RzIOPtraceFuncFn) (RzIO *io, void *(*func)(void *), void *user);
#endif

typedef struct rz_io_bind_t {
	int init;
	RzIO *io;
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
	RzIOFdSeek fd_seek;	//needed for esil
	RzIOFdSize fd_size;
	RzIOFdResize fd_resize;
	RzIOFdRead fd_read;	//needed for esil
	RzIOFdWrite fd_write;	//needed for esil
	RzIOFdReadAt fd_read_at;
	RzIOFdWriteAt fd_write_at;
	RzIOFdIsDbg fd_is_dbg;
	RzIOFdGetName fd_get_name;
	RzIOFdGetMap fd_get_map;
	RzIOFdRemap fd_remap;
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
} RzIOBind;

//map.c
RZ_API RzIOMap *rz_io_map_new(RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
RZ_API void rz_io_map_init (RzIO *io);
RZ_API bool rz_io_map_remap (RzIO *io, ut32 id, ut64 addr);
RZ_API bool rz_io_map_remap_fd (RzIO *io, int fd, ut64 addr);
RZ_API ut64 rz_io_map_location(RzIO *io, ut64 size);
RZ_API bool rz_io_map_exists (RzIO *io, RzIOMap *map);
RZ_API bool rz_io_map_exists_for_id (RzIO *io, ut32 id);
RZ_API RzIOMap *rz_io_map_resolve (RzIO *io, ut32 id);
RZ_API RzIOMap *rz_io_map_add(RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
// same as rz_io_map_add but used when many maps need to be added. Call rz_io_update when all maps have been added.
RZ_API RzIOMap *rz_io_map_add_batch(RzIO *io, int fd, int flags, ut64 delta, ut64 addr, ut64 size);
RZ_API RzIOMap *rz_io_map_get(RzIO *io, ut64 addr);		//returns the map at vaddr with the highest priority
// update the internal state of RzIO after a series of _batch operations
RZ_API void rz_io_update(RzIO *io);
RZ_API bool rz_io_map_is_mapped(RzIO* io, ut64 addr);
RZ_API RzIOMap *rz_io_map_get_paddr(RzIO *io, ut64 paddr);		//returns the map at paddr with the highest priority
RZ_API void rz_io_map_reset(RzIO* io);
RZ_API bool rz_io_map_del(RzIO *io, ut32 id);
RZ_API bool rz_io_map_del_for_fd(RzIO *io, int fd);
RZ_API bool rz_io_map_depriorize(RzIO* io, ut32 id);
RZ_API bool rz_io_map_priorize (RzIO *io, ut32 id);
RZ_API bool rz_io_map_priorize_for_fd (RzIO *io, int fd);
RZ_API void rz_io_map_cleanup (RzIO *io);
RZ_API void rz_io_map_fini (RzIO *io);
RZ_API bool rz_io_map_is_in_range (RzIOMap *map, ut64 from, ut64 to);
RZ_API void rz_io_map_set_name (RzIOMap *map, const char *name);
RZ_API void rz_io_map_del_name (RzIOMap *map);
RZ_API RzList* rz_io_map_get_for_fd(RzIO *io, int fd);
RZ_API bool rz_io_map_resize(RzIO *io, ut32 id, ut64 newsize);

// next free address to place a map.. maybe just unify
RZ_API ut64 rz_io_map_next_available(RzIO* io, ut64 addr, ut64 size, ut64 load_align);
RZ_API ut64 rz_io_map_next_address(RzIO* io, ut64 addr);

// p2v/v2p

RZ_API ut64 rz_io_p2v(RzIO *io, ut64 pa);
RZ_API ut64 rz_io_v2p(RzIO *io, ut64 va);

//io.c
RZ_API RzIO *rz_io_new (void);
RZ_API RzIO *rz_io_init (RzIO *io);
RZ_API RzIODesc *rz_io_open_nomap (RzIO *io, const char *uri, int flags, int mode);		//should return int
RZ_API RzIODesc *rz_io_open (RzIO *io, const char *uri, int flags, int mode);
RZ_API RzIODesc *rz_io_open_at (RzIO *io, const char *uri, int flags, int mode, ut64 at);
RZ_API RzList *rz_io_open_many (RzIO *io, const char *uri, int flags, int mode);
RZ_API RzIODesc* rz_io_open_buffer (RzIO *io, RzBuffer *b, int flags, int mode);
RZ_API bool rz_io_close (RzIO *io);
RZ_API bool rz_io_reopen (RzIO *io, int fd, int flags, int mode);
RZ_API int rz_io_close_all (RzIO *io);
RZ_API int rz_io_pread_at (RzIO *io, ut64 paddr, ut8 *buf, int len);
RZ_API int rz_io_pwrite_at (RzIO *io, ut64 paddr, const ut8 *buf, int len);
RZ_API bool rz_io_vread_at_mapped(RzIO* io, ut64 vaddr, ut8* buf, int len);
RZ_API bool rz_io_read_at (RzIO *io, ut64 addr, ut8 *buf, int len);
RZ_API bool rz_io_read_at_mapped(RzIO *io, ut64 addr, ut8 *buf, int len);
RZ_API int rz_io_nread_at (RzIO *io, ut64 addr, ut8 *buf, int len);
RZ_API void rz_io_alprint(RzList *ls);
RZ_API bool rz_io_write_at (RzIO *io, ut64 addr, const ut8 *buf, int len);
RZ_API bool rz_io_read (RzIO *io, ut8 *buf, int len);
RZ_API bool rz_io_write (RzIO *io, ut8 *buf, int len);
RZ_API ut64 rz_io_size (RzIO *io);
RZ_API bool rz_io_is_listener (RzIO *io);
RZ_API char *rz_io_system (RzIO *io, const char* cmd);
RZ_API bool rz_io_resize (RzIO *io, ut64 newsize);
RZ_API int rz_io_extend_at (RzIO *io, ut64 addr, ut64 size);
RZ_API bool rz_io_set_write_mask (RzIO *io, const ut8 *mask, int len);
RZ_API void rz_io_bind(RzIO *io, RzIOBind *bnd);
RZ_API bool rz_io_shift (RzIO *io, ut64 start, ut64 end, st64 move);
RZ_API ut64 rz_io_seek (RzIO *io, ut64 offset, int whence);
RZ_API int rz_io_fini (RzIO *io);
RZ_API void rz_io_free (RzIO *io);
#define rz_io_bind_init(x) memset(&x,0,sizeof(x))

RZ_API bool rz_io_plugin_init(RzIO *io);
RZ_API int rz_io_plugin_open(RzIO *io, int fd, RzIOPlugin *plugin);
RZ_API int rz_io_plugin_close(RzIO *io, int fd, RzIOPlugin *plugin);
RZ_API int rz_io_plugin_generate(RzIO *io);
RZ_API bool rz_io_plugin_add(RzIO *io, RzIOPlugin *plugin);
RZ_API int rz_io_plugin_list(RzIO *io);
RZ_API int rz_io_plugin_list_json(RzIO *io);
RZ_API int rz_io_plugin_read(RzIODesc *desc, ut8 *buf, int len);
RZ_API int rz_io_plugin_write(RzIODesc *desc, const ut8 *buf, int len);
RZ_API int rz_io_plugin_read_at(RzIODesc *desc, ut64 addr, ut8 *buf, int len);
RZ_API int rz_io_plugin_write_at(RzIODesc *desc, ut64 addr, const ut8 *buf, int len);
RZ_API RzIOPlugin *rz_io_plugin_resolve(RzIO *io, const char *filename, bool many);
RZ_API RzIOPlugin *rz_io_plugin_resolve_fd(RzIO *io, int fd);
RZ_API RzIOPlugin *rz_io_plugin_get_default(RzIO *io, const char *filename, bool many);

/* undo api */
// track seeks and writes
// TODO: needs cleanup..kinda big?
RZ_API int rz_io_undo_init(RzIO *io);
RZ_API void rz_io_undo_enable(RzIO *io, int seek, int write);
/* seek undo */
RZ_API RzIOUndos *rz_io_sundo(RzIO *io, ut64 offset);
RZ_API RzIOUndos *rz_io_sundo_redo(RzIO *io);
RZ_API void rz_io_sundo_push(RzIO *io, ut64 off, int cursor);
RZ_API void rz_io_sundo_reset(RzIO *io);
RZ_API RzList *rz_io_sundo_list(RzIO *io, int mode);
/* write undo */
RZ_API void rz_io_wundo_new(RzIO *io, ut64 off, const ut8 *data, int len);
RZ_API void rz_io_wundo_apply_all(RzIO *io, int set);
RZ_API int rz_io_wundo_apply(RzIO *io, struct rz_io_undo_w_t *u, int set);
RZ_API void rz_io_wundo_clear(RzIO *io);
RZ_API int rz_io_wundo_size(RzIO *io);
RZ_API void rz_io_wundo_list(RzIO *io);
RZ_API int rz_io_wundo_set_t(RzIO *io, RzIOUndoWrite *u, int set) ;
RZ_API void rz_io_wundo_set_all(RzIO *io, int set);
RZ_API int rz_io_wundo_set(RzIO *io, int n, int set);

//desc.c
RZ_API RzIODesc *rz_io_desc_new (RzIO *io, RzIOPlugin *plugin, const char *uri, int flags, int mode, void *data);
RZ_API RzIODesc *rz_io_desc_open (RzIO *io, const char *uri, int flags, int mode);
RZ_API RzIODesc *rz_io_desc_open_plugin (RzIO *io, RzIOPlugin *plugin, const char *uri, int flags, int mode);
RZ_API bool rz_io_desc_close (RzIODesc *desc);
RZ_API int rz_io_desc_read (RzIODesc *desc, ut8 *buf, int count);
RZ_API int rz_io_desc_write (RzIODesc *desc, const ut8 *buf, int count);
RZ_API void rz_io_desc_free (RzIODesc *desc);
RZ_API bool rz_io_desc_add (RzIO *io, RzIODesc *desc);
RZ_API bool rz_io_desc_del (RzIO *io, int fd);
RZ_API RzIODesc *rz_io_desc_get (RzIO *io, int fd);
RZ_API ut64 rz_io_desc_seek (RzIODesc *desc, ut64 offset, int whence);
RZ_API bool rz_io_desc_resize (RzIODesc *desc, ut64 newsize);
RZ_API ut64 rz_io_desc_size (RzIODesc *desc);
RZ_API bool rz_io_desc_is_blockdevice (RzIODesc *desc);
RZ_API bool rz_io_desc_is_chardevice (RzIODesc *desc);
RZ_API bool rz_io_desc_exchange (RzIO *io, int fd, int fdx);	//this should get 2 descs
RZ_API bool rz_io_desc_is_dbg (RzIODesc *desc);
RZ_API int rz_io_desc_get_pid (RzIODesc *desc);
RZ_API int rz_io_desc_get_tid (RzIODesc *desc);
RZ_API bool rz_io_desc_get_base (RzIODesc *desc, ut64 *base);
RZ_API int rz_io_desc_read_at (RzIODesc *desc, ut64 addr, ut8 *buf, int len);
RZ_API int rz_io_desc_write_at (RzIODesc *desc, ut64 addr, const ut8 *buf, int len);

/* lifecycle */
RZ_IPI bool rz_io_desc_init (RzIO *io);
RZ_IPI bool rz_io_desc_fini (RzIO *io);

/* io/cache.c */
RZ_API int rz_io_cache_invalidate(RzIO *io, ut64 from, ut64 to);
RZ_API bool rz_io_cache_at(RzIO *io, ut64 addr);
RZ_API void rz_io_cache_commit(RzIO *io, ut64 from, ut64 to);
RZ_API void rz_io_cache_init(RzIO *io);
RZ_API void rz_io_cache_fini (RzIO *io);
RZ_API bool rz_io_cache_list(RzIO *io, int rad);
RZ_API void rz_io_cache_reset(RzIO *io, int set);
RZ_API bool rz_io_cache_write(RzIO *io, ut64 addr, const ut8 *buf, int len);
RZ_API bool rz_io_cache_read(RzIO *io, ut64 addr, ut8 *buf, int len);

/* io/p_cache.c */
RZ_API bool rz_io_desc_cache_init(RzIODesc *desc);
RZ_API int rz_io_desc_cache_write(RzIODesc *desc, ut64 paddr, const ut8 *buf, int len);
RZ_API int rz_io_desc_cache_read(RzIODesc *desc, ut64 paddr, ut8 *buf, int len);
RZ_API bool rz_io_desc_cache_commit(RzIODesc *desc);
RZ_API void rz_io_desc_cache_cleanup(RzIODesc *desc);
RZ_API void rz_io_desc_cache_fini(RzIODesc *desc);
RZ_API void rz_io_desc_cache_fini_all(RzIO *io);
RZ_API RzList *rz_io_desc_cache_list(RzIODesc *desc);
RZ_API int rz_io_desc_extend(RzIODesc *desc, ut64 size);

/* io/buffer.c */
RZ_API int rz_io_buffer_read (RzIO* io, ut64 addr, ut8* buf, int len);
RZ_API int rz_io_buffer_load (RzIO* io, ut64 addr, int len);
RZ_API void rz_io_buffer_close (RzIO* io);

/* io/fd.c */
RZ_API int rz_io_fd_open (RzIO *io, const char *uri, int flags, int mode);
RZ_API bool rz_io_fd_close (RzIO *io, int fd);
RZ_API int rz_io_fd_read (RzIO *io, int fd, ut8 *buf, int len);
RZ_API int rz_io_fd_write (RzIO *io, int fd, const ut8 *buf, int len);
RZ_API ut64 rz_io_fd_seek (RzIO *io, int fd, ut64 addr, int whence);
RZ_API ut64 rz_io_fd_size (RzIO *io, int fd);
RZ_API bool rz_io_fd_resize (RzIO *io, int fd, ut64 newsize);
RZ_API bool rz_io_fd_is_blockdevice (RzIO *io, int fd);
RZ_API bool rz_io_fd_is_chardevice (RzIO *io, int fd);
RZ_API int rz_io_fd_read_at (RzIO *io, int fd, ut64 addr, ut8 *buf, int len);
RZ_API int rz_io_fd_write_at (RzIO *io, int fd, ut64 addr, const ut8 *buf, int len);
RZ_API bool rz_io_fd_is_dbg (RzIO *io, int fd);
RZ_API int rz_io_fd_get_pid (RzIO *io, int fd);
RZ_API int rz_io_fd_get_tid (RzIO *io, int fd);
RZ_API bool rz_io_fd_get_base (RzIO *io, int fd, ut64 *base);
RZ_API const char *rz_io_fd_get_name (RzIO *io, int fd);
RZ_API int rz_io_fd_get_current(RzIO *io);
RZ_API int rz_io_fd_get_next(RzIO *io, int fd);
RZ_API int rz_io_fd_get_prev(RzIO *io, int fd);
RZ_API int rz_io_fd_get_highest(RzIO *io);
RZ_API int rz_io_fd_get_lowest(RzIO *io);
RZ_API bool rz_io_use_fd (RzIO *io, int fd);


#define rz_io_range_new()	RZ_NEW0(RzIORange)
#define rz_io_range_free(x)	free(x)

/* io/ioutils.c */
RZ_API bool rz_io_is_valid_offset (RzIO *io, ut64 offset, int hasperm);
RZ_API bool rz_io_addr_is_mapped(RzIO *io, ut64 vaddr);
RZ_API bool rz_io_read_i (RzIO* io, ut64 addr, ut64 *val, int size, bool endian);
RZ_API bool rz_io_write_i (RzIO* io, ut64 addr, ut64 *val, int size, bool endian);

#if HAVE_PTRACE
RZ_API long rz_io_ptrace(RzIO *io, rz_ptrace_request_t request, pid_t pid, void *addr, rz_ptrace_data_t data);
RZ_API pid_t rz_io_ptrace_fork(RzIO *io, void (*child_callback)(void *), void *child_callback_user);
RZ_API void *rz_io_ptrace_func(RzIO *io, void *(*func)(void *), void *user);
#endif

extern RzIOPlugin rz_io_plugin_procpid;
extern RzIOPlugin rz_io_plugin_malloc;
extern RzIOPlugin rz_io_plugin_sparse;
extern RzIOPlugin rz_io_plugin_ptrace;
extern RzIOPlugin rz_io_plugin_w32dbg;
extern RzIOPlugin rz_io_plugin_windbg;
extern RzIOPlugin rz_io_plugin_mach;
extern RzIOPlugin rz_io_plugin_debug;
extern RzIOPlugin rz_io_plugin_shm;
extern RzIOPlugin rz_io_plugin_gdb;
extern RzIOPlugin rz_io_plugin_rap;
extern RzIOPlugin rz_io_plugin_http;
extern RzIOPlugin rz_io_plugin_bfdbg;
extern RzIOPlugin rz_io_plugin_w32;
extern RzIOPlugin rz_io_plugin_zip;
extern RzIOPlugin rz_io_plugin_mmap;
extern RzIOPlugin rz_io_plugin_default;
extern RzIOPlugin rz_io_plugin_ihex;
extern RzIOPlugin rz_io_plugin_self;
extern RzIOPlugin rz_io_plugin_gzip;
extern RzIOPlugin rz_io_plugin_winkd;
extern RzIOPlugin rz_io_plugin_rzpipe;
extern RzIOPlugin rz_io_plugin_rzweb;
extern RzIOPlugin rz_io_plugin_qnx;
extern RzIOPlugin rz_io_plugin_rzk;
extern RzIOPlugin rz_io_plugin_tcp;
extern RzIOPlugin rz_io_plugin_bochs;
extern RzIOPlugin rz_io_plugin_null;
extern RzIOPlugin rz_io_plugin_ar;
extern RzIOPlugin rz_io_plugin_rbuf;
extern RzIOPlugin rz_io_plugin_winedbg;
extern RzIOPlugin rz_io_plugin_gprobe;
extern RzIOPlugin rz_io_plugin_fd;

#if __cplusplus
}
#endif

#endif
