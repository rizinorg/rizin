// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef SDB_H
#define SDB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_types.h>
#include <rz_vector.h>
#include <rz_list.h>
#include "sdbht.h"
#include "cdb.h"
#include "cdb_make.h"

/* Key value sizes */
#define SDB_CDB_MIN_VALUE 1
#define SDB_CDB_MAX_VALUE CDB_MAX_VALUE
#define SDB_CDB_MIN_KEY   2
#define SDB_CDB_MAX_KEY   CDB_MAX_KEY

#if __WINDOWS__ && !__CYGWIN__
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#define ftruncate _chsize
#ifndef _MSC_VER
extern __attribute__((dllimport)) void *__cdecl _aligned_malloc(size_t, size_t);
extern __attribute__((dllimport)) void __cdecl _aligned_free(void *memblock);
extern char *strdup(const char *);
#else
#include <process.h>
#include <malloc.h> // for _aligned_malloc
#endif

// #define SDB_MODE 0
#define SDB_MODE _S_IWRITE | _S_IREAD
#else
#define SDB_MODE 0644
// #define SDB_MODE 0600
#endif

// #define SDB_RS '\x1e'
#define SDB_RS        ','
#define SDB_SS        ","
#define SDB_MAX_PATH  256
#define SDB_NUM_BASE  16
#define SDB_NUM_BUFSZ 64

#define SDB_OPTION_NONE    0
#define SDB_OPTION_ALL     0xff
#define SDB_OPTION_SYNC    (1 << 0)
#define SDB_OPTION_NOSTAMP (1 << 1)
#define SDB_OPTION_FS      (1 << 2)

#define SDB_LIST_UNSORTED 0
#define SDB_LIST_SORTED   1

typedef bool (*VALUE_EQ_F)(const char *, const char *);

typedef struct sdb_t {
	char *dir; // path+name
	char *path;
	char *name;
	int fd;
	int refs; // reference counter
	int lock;
	struct cdb db;
	struct cdb_make m;
	HtSS *ht;
	ut32 eod;
	ut32 pos;
	ut32 dump_end_pos; ///< Used in sdb_dump_next()
	int fdump;
	char *ndump;
	int options;
	int ns_lock; // TODO: merge into options?
	RzList /*<SdbNs *>*/ *ns;
	ut32 depth;
} Sdb;

typedef struct sdb_ns_t {
	char *name;
	ut32 hash;
	Sdb *sdb;
} SdbNs;

RZ_API Sdb *sdb_new0(void);
RZ_API Sdb *sdb_new(const char *path, const char *file, int lock);

RZ_API int sdb_open(Sdb *s, const char *file);
RZ_API void sdb_close(Sdb *s);

RZ_API void sdb_config(Sdb *s, int options);
RZ_API bool sdb_free(Sdb *s);
RZ_API void sdb_file(Sdb *s, const char *dir);
RZ_API bool sdb_merge(Sdb *d, Sdb *s);
RZ_API int sdb_count(Sdb *s);
RZ_API void sdb_reset(Sdb *s);
RZ_API void sdb_setup(Sdb *s, int options);
RZ_API void sdb_drain(Sdb *, Sdb *);

// Copy everything, including namespaces, from src to dst
RZ_API void sdb_copy(Sdb *src, Sdb *dst);

RZ_API bool sdb_stats(Sdb *s, ut32 *disk, ut32 *mem);

typedef bool (*SdbForeachCallback)(void *user, const SdbKv *kv);
RZ_API bool sdb_foreach(RZ_NONNULL Sdb *s, RZ_NONNULL SdbForeachCallback cb, RZ_NULLABLE void *user);
RZ_API RZ_OWN RzPVector /*<SdbKv *>*/ *sdb_get_items(RZ_NONNULL Sdb *s, bool sorted);
RZ_API RZ_OWN RzPVector /*<SdbKv *>*/ *sdb_get_items_filter(RZ_NONNULL Sdb *s, RZ_NONNULL SdbForeachCallback filter, RZ_NULLABLE void *user, bool sorted);
RZ_API RZ_OWN RzPVector /*<SdbKv *>*/ *sdb_get_items_match(RZ_NONNULL Sdb *s, RZ_NONNULL const char *expr, bool sorted);

RZ_API int sdb_query(Sdb *s, const char *cmd);
RZ_API int sdb_queryf(Sdb *s, const char *fmt, ...);
RZ_API int sdb_query_lines(Sdb *s, const char *cmd);
RZ_API char *sdb_querys(Sdb *s, char *buf, size_t len, const char *cmd);
RZ_API char *sdb_querysf(Sdb *s, char *buf, size_t buflen, const char *fmt, ...);
RZ_API int sdb_query_file(Sdb *s, const char *file);
RZ_API bool sdb_exists(Sdb *, const char *key);
RZ_API bool sdb_remove(Sdb *, const char *key);
RZ_API int sdb_unset(Sdb *, const char *key);
RZ_API int sdb_unset_like(Sdb *s, const char *k);

// diffing
typedef struct sdb_diff_t {
	const RzList /*<char *>*/ *path;
	const char *k;
	const char *v; // if null, k is a namespace
	bool add;
} SdbDiff;

// Format diff in a readable form into str. str, size and return are like in snprintf.
RZ_API int sdb_diff_format(char *str, int size, const SdbDiff *diff);

typedef void (*SdbDiffCallback)(const SdbDiff *diff, void *user);

// Returns true iff the contents of a and b are equal including contained namespaces
// If cb is non-null, it will be called subsequently with differences.
RZ_API bool sdb_diff(Sdb *a, Sdb *b, SdbDiffCallback cb, void *cb_user);

RZ_API bool sdb_diff_eq(Sdb *a, Sdb *b, VALUE_EQ_F eq, SdbDiffCallback cb, void *cb_user);

// Gets a pointer to the value associated with `key`.
RZ_API char *sdb_get(Sdb *, const char *key);

// Gets a pointer to the value associated with `key` and returns in `vlen` the
// length of the value string.
RZ_API char *sdb_get_len(Sdb *, const char *key, int *vlen);

// Gets a const pointer to the value associated with `key`
RZ_API const char *sdb_const_get(Sdb *, const char *key);

// Gets a const pointer to the value associated with `key` and returns in
// `vlen` the length of the value string.
RZ_API const char *sdb_const_get_len(Sdb *s, const char *key, int *vlen);
RZ_API bool sdb_set(Sdb *, const char *key, const char *data);
RZ_API bool sdb_set_owned(Sdb *s, const char *key, char *val);
RZ_API bool sdb_concat(Sdb *s, const char *key, const char *value);
RZ_API bool sdb_uncat(Sdb *s, const char *key, const char *value);
RZ_API bool sdb_add(Sdb *s, const char *key, const char *val);
RZ_API bool sdb_sync(Sdb *);
RZ_API void sdbkv_free(RZ_NULLABLE SdbKv *kv);

/* num.c */
RZ_API bool sdb_num_exists(Sdb *, const char *key);
RZ_API int sdb_num_base(const char *s);
RZ_API ut64 sdb_num_get(Sdb *s, const char *key);
RZ_API bool sdb_num_set(Sdb *s, const char *key, ut64 v);
RZ_API bool sdb_num_add(Sdb *s, const char *key, ut64 v);
RZ_API ut64 sdb_num_inc(Sdb *s, const char *key, ut64 n);
RZ_API ut64 sdb_num_dec(Sdb *s, const char *key, ut64 n);
RZ_API int sdb_num_min(Sdb *s, const char *key, ut64 v);
RZ_API int sdb_num_max(Sdb *s, const char *key, ut64 v);

/* create db */
RZ_API bool sdb_disk_create(Sdb *s);
RZ_API bool sdb_disk_insert(Sdb *s, const char *key, const char *val);
RZ_API bool sdb_disk_finish(Sdb *s);
RZ_API bool sdb_disk_unlink(Sdb *s);

/* plaintext sdb files */
RZ_API bool sdb_text_save_fd(Sdb *s, int fd, bool sort);
RZ_API bool sdb_text_save(Sdb *s, const char *file, bool sort);
RZ_API bool sdb_text_load_buf(Sdb *s, char *buf, size_t sz);
RZ_API bool sdb_text_load(Sdb *s, const char *file);

/* iterate */
RZ_API void sdb_dump_begin(RZ_NONNULL Sdb *s);
RZ_API bool sdb_dump_next(RZ_NONNULL Sdb *s, RZ_OUT RZ_NONNULL SdbKv *kv);

/* numeric */
RZ_API char *sdb_itoa(ut64 n, char *s, int base);
RZ_API ut64 sdb_atoi(const char *s);
RZ_API const char *sdb_itoca(ut64 n);

/* locking */
RZ_API bool sdb_lock(const char *s);
RZ_API const char *sdb_lock_file(const char *f);
RZ_API void sdb_unlock(const char *s);
RZ_API bool sdb_unlink(Sdb *s);
RZ_API int sdb_lock_wait(RZ_UNUSED const char *s);

/* expiration */
RZ_API ut64 sdb_now(void);
RZ_API ut64 sdb_unow(void);
RZ_API ut32 sdb_hash(const char *key);
RZ_API ut32 sdb_hash_len(const char *key, ut32 *len);
RZ_API ut8 sdb_hash_byte(const char *s);

// namespace
RZ_API Sdb *sdb_ns(Sdb *s, const char *name, int create);
RZ_API Sdb *sdb_ns_path(Sdb *s, const char *path, int create);
RZ_API void sdb_ns_init(Sdb *s);
RZ_API void sdb_ns_free_all(Sdb *s);
RZ_API void sdb_ns_lock(Sdb *s, int lock, int depth);
RZ_API void sdb_ns_sync(Sdb *s);
RZ_API int sdb_ns_set(Sdb *s, const char *name, Sdb *r);
RZ_API bool sdb_ns_unset(Sdb *s, const char *name, Sdb *r);

// array
RZ_API bool sdb_array_contains(Sdb *s, const char *key, const char *val);
RZ_API bool sdb_array_contains_num(Sdb *s, const char *key, ut64 val);
RZ_API int sdb_array_indexof(Sdb *s, const char *key, const char *val);
RZ_API bool sdb_array_set(Sdb *s, const char *key, int idx, const char *val);
RZ_API bool sdb_array_set_num(Sdb *s, const char *key, int idx, ut64 val);
RZ_API bool sdb_array_append(Sdb *s, const char *key, const char *val);
RZ_API bool sdb_array_append_num(Sdb *s, const char *key, ut64 val);
RZ_API bool sdb_array_prepend(Sdb *s, const char *key, const char *val);
RZ_API bool sdb_array_prepend_num(Sdb *s, const char *key, ut64 val);
RZ_API char *sdb_array_get(Sdb *s, const char *key, int idx);
RZ_API ut64 sdb_array_get_num(Sdb *s, const char *key, int idx);
RZ_API int sdb_array_get_idx(Sdb *s, const char *key, const char *val); // agetv
RZ_API bool sdb_array_insert(Sdb *s, const char *key, int idx, const char *val);
RZ_API int sdb_array_insert_num(Sdb *s, const char *key, int idx, ut64 val);
RZ_API int sdb_array_unset(Sdb *s, const char *key, int n); // leaves empty bucket
RZ_API int sdb_array_delete(Sdb *s, const char *key, int n);
RZ_API void sdb_array_sort(Sdb *s, const char *key);
RZ_API void sdb_array_sort_num(Sdb *s, const char *key);
// set

// Adds string `val` at the end of array `key`.
RZ_API bool sdb_array_add(Sdb *s, const char *key, const char *val);

// Adds number `val` at the end of array `key`.
RZ_API bool sdb_array_add_num(Sdb *s, const char *key, ut64 val);

// Adds string `val` in the sorted array `key`.
RZ_API int sdb_array_add_sorted(Sdb *s, const char *key, const char *val);

// Adds number `val` in the sorted array `key`.
RZ_API bool sdb_array_add_sorted_num(Sdb *s, const char *key, ut64 val);

// Removes the string `val` from the array `key`.
RZ_API int sdb_array_remove(Sdb *s, const char *key, const char *val);

// Removes the number `val` from the array `key`.
RZ_API int sdb_array_remove_num(Sdb *s, const char *key, ut64 val);

// helpers
RZ_API char *sdb_anext(char *str, char **next);
RZ_API const char *sdb_const_anext(const char *str);
RZ_API int sdb_alen(const char *str);
RZ_API int sdb_alen_ignore_empty(const char *str);
RZ_API int sdb_array_size(Sdb *s, const char *key);
RZ_API int sdb_array_length(Sdb *s, const char *key);

int sdb_array_list(Sdb *s, const char *key);

// Adds the string `val` to the start of array `key`.
RZ_API bool sdb_array_push(Sdb *s, const char *key, const char *val);

// Returns the string at the start of array `key` or
// NULL if there are no elements.
RZ_API char *sdb_array_pop(Sdb *s, const char *key);

// Adds the number `val` to the start of array `key`.
RZ_API int sdb_array_push_num(Sdb *s, const char *key, ut64 num);

// Returns the number at the start of array `key`.
RZ_API ut64 sdb_array_pop_num(Sdb *s, const char *key);

RZ_API char *sdb_array_pop_head(Sdb *s, const char *key);
RZ_API char *sdb_array_pop_tail(Sdb *s, const char *key);

/* Util.c */
RZ_API int sdb_isnum(const char *s);
RZ_API bool sdb_isempty(Sdb *s);

RZ_API const char *sdb_type(const char *k);
RZ_API bool sdb_match(const char *str, const char *glob);
RZ_API bool sdb_bool_set(Sdb *db, const char *str, bool v);
RZ_API bool sdb_bool_get(Sdb *db, const char *str);

// base64
RZ_API ut8 *sdb_decode(const char *in, int *len);
RZ_API char *sdb_encode(const ut8 *bin, int len);
RZ_API void sdb_encode_raw(char *bout, const ut8 *bin, int len);
RZ_API int sdb_decode_raw(ut8 *bout, const char *bin, int len);

// binfmt
RZ_API char *sdb_fmt(const char *fmt, ...) RZ_PRINTF_CHECK(1, 2);
RZ_API int sdb_fmt_init(void *p, const char *fmt);
RZ_API void sdb_fmt_free(void *p, const char *fmt);
RZ_API int sdb_fmt_tobin(const char *_str, const char *fmt, void *stru);
RZ_API char *sdb_fmt_tostr(void *stru, const char *fmt);
RZ_API char **sdb_fmt_array(const char *list);
RZ_API ut64 *sdb_fmt_array_num(const char *list);

// raw array helpers
RZ_API char *sdb_array_compact(char *p);
RZ_API char *sdb_aslice(char *out, int from, int to);
#define sdb_aforeach(x, y) \
	{ \
		char *next; \
		if (y) \
			for (x = y;;) { \
				x = sdb_anext(x, &next);
#define sdb_aforeach_next(x) \
	if (!next) \
		break; \
	*(next - 1) = ','; \
	x = next; \
	} \
	}

#ifdef __cplusplus
}
#endif

#endif
