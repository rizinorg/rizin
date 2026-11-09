// SPDX-FileCopyrightText: 2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: MIT

#include "sdb.h"

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#if HAVE_HEADER_SYS_MMAN_H
#include <sys/mman.h>
#endif
#include "sdb_private.h"

/**
 * ********************
 * Plaintext SDB Format
 * ********************
 *
 * Files are UTF-8 and use '\n' line endings. Always.
 *
 * Lines starting with '/' denote the path of the namespace for the following data:
 *
 *   /some/namespace
 *
 * The default path is root, just a slash also means root.
 * These paths are always absolute from the root. Characters that must be escaped in a path are: '/', '\\', '\n', '\r':
 *
 *   /s\/ome/name\nspa\\ce
 *
 * SDB entries are written each as a single k=v line:
 *
 *   somekey=somevalue
 *
 * To distinguish these from path lines, if there is a leading '/' in the key, it must be escaped
 * (slashes later in the line don't have to be escaped):
 *
 *   \/slashedkey=somevalue
 *
 * Other than that, at any postion, '\\', '\n' and '\r' must be escaped:
 *
 *   some\\key=some\nvalue
 *
 * In the key, '=' must also be escaped (not necessary in the value):
 *
 *   some\=key=some=value
 *
 * --------
 * Example:
 *
 *   /
 *   key=intheroot
 *   \/slashedkey=somevalue
 *   some\\key=some\nvalue
 *   some\=key=some=value
 *
 *   /subns
 *   some=stuff in the sub-namespace
 *
 *   /subns/deeper
 *   this=is in /subns/deeper
 *
 */

static int cmp_ns(const void *a, const void *b, void *user) {
	const SdbNs *nsa = a;
	const SdbNs *cia = b;
	return strcmp(nsa->name, cia->name);
}

typedef struct {
	int fd;
	size_t len;
	bool ok;
	char buf[65536];
} SdbTextBuf;

static void text_buf_raw_write(SdbTextBuf *tb, const char *data, size_t sz) {
	if (!tb->ok) {
		return;
	}
	ssize_t written = write(tb->fd, data, sz);
	if (written < 0 || (size_t)written != sz) {
		SDB_V_NOT(-1, -1);
		tb->ok = false;
	}
}

static void text_buf_flush(SdbTextBuf *tb) {
	if (tb->len > 0) {
		text_buf_raw_write(tb, tb->buf, tb->len);
		tb->len = 0;
	}
}

static void text_buf_write(SdbTextBuf *tb, const char *data, size_t sz) {
	if (!tb->ok) {
		return;
	}
	if (sz >= sizeof(tb->buf)) {
		text_buf_flush(tb);
		text_buf_raw_write(tb, data, sz);
		return;
	}
	if (tb->len + sz > sizeof(tb->buf)) {
		text_buf_flush(tb);
	}
	memcpy(tb->buf + tb->len, data, sz);
	tb->len += sz;
}

// n = position we are currently looking at
// p = position until we have already written everything
// flush a block of text that doesn't have to be escaped
#define FLUSH \
	do { \
		if (p != n) { \
			text_buf_write(tb, p, n - p); \
			p = n; \
		} \
	} while (0)
// write and escape a string from str to tb
#define ESCAPE_LOOP(tb, str, escapes) \
	do { \
		const char *p = str; \
		const char *n = p; \
		while (*n) { \
			switch (*n) { escapes } \
			n++; \
		} \
		FLUSH; \
	} while (0)
#define ESCAPE(c, repl, replsz) \
	case c: \
		FLUSH; \
		p++; \
		text_buf_write(tb, "\\" repl, replsz + 1); \
		break;

static void write_path(SdbTextBuf *tb, RzList /*<char *>*/ *path) {
	text_buf_write(tb, "/", 1); // always print a /, even if path is empty
	RzListIter *it;
	const char *path_token;
	bool first = true;
	rz_list_foreach (path, it, path_token) {
		if (first) {
			first = false;
		} else {
			text_buf_write(tb, "/", 1);
		}
		ESCAPE_LOOP(tb, path_token,
			ESCAPE('\\', "\\", 1);
			ESCAPE('/', "/", 1);
			ESCAPE('\n', "n", 1);
			ESCAPE('\r', "r", 1););
	}
}

static void write_key(SdbTextBuf *tb, const char *k) {
	// escape leading '/'
	if (*k == '/') {
		text_buf_write(tb, "\\", 1);
	}
	ESCAPE_LOOP(tb, k,
		ESCAPE('\\', "\\", 1);
		ESCAPE('=', "=", 1);
		ESCAPE('\n', "n", 1);
		ESCAPE('\r', "r", 1););
}

static void write_value(SdbTextBuf *tb, const char *v) {
	ESCAPE_LOOP(tb, v,
		ESCAPE('\\', "\\", 1);
		ESCAPE('\n', "n", 1);
		ESCAPE('\r', "r", 1););
}
#undef FLUSH
#undef ESCAPE_LOOP
#undef ESCAPE

static bool save_kv_cb(void *user, const SdbKv *kv) {
	SdbTextBuf *tb = (SdbTextBuf *)user;
	write_key(tb, sdbkv_key(kv));
	text_buf_write(tb, "=", 1);
	write_value(tb, sdbkv_value(kv));
	text_buf_write(tb, "\n", 1);
	return true;
}

static bool text_save(Sdb *s, SdbTextBuf *tb, bool sort, RzList /*<char *>*/ *path) {
	// path
	write_path(tb, path);
	text_buf_write(tb, "\n", 1);

	// k=v entries
	if (sort) {
		RzPVector *items = sdb_get_items(s, true);
		void **it;
		rz_pvector_foreach (items, it) {
			SdbKv *kv = *it;
			save_kv_cb(tb, kv);
		}
		rz_pvector_free(items);
	} else {
		// This is faster when sorting is not needed.
		sdb_foreach(s, save_kv_cb, tb);
	}

	// sub-namespaces
	RzList *l = s->ns;
	if (sort) {
		l = rz_list_clone(l);
		rz_list_sort(l, cmp_ns, NULL);
	}
	SdbNs *ns;
	RzListIter *it;
	rz_list_foreach (l, it, ns) {
		text_buf_write(tb, "\n", 1);
		rz_list_append(path, ns->name);
		text_save(ns->sdb, tb, sort, path);
		rz_list_pop(path);
	}
	if (l != s->ns) {
		rz_list_free(l);
	}

	return true;
}
#undef write_

/**
 * \brief Save an Sdb database in plaintext format to a file descriptor using buffered writes.
 * \param s Sdb instance to serialize
 * \param fd Destination file descriptor
 * \param sort Whether to sort keys and sub-namespaces lexicographically
 * \return true on success, false on allocation failure
 */
RZ_API bool sdb_text_save_fd(Sdb *s, int fd, bool sort) {
	if (!s || fd < 0) {
		return false;
	}
	RzList *path = rz_list_new();
	if (!path) {
		return false;
	}
	SdbTextBuf *tb = malloc(sizeof(SdbTextBuf));
	if (!tb) {
		rz_list_free(path);
		return false;
	}
	tb->fd = fd;
	tb->len = 0;
	tb->ok = true;
	bool r = text_save(s, tb, sort, path);
	text_buf_flush(tb);
	bool ok = r && tb->ok;
	free(tb);
	rz_list_free(path);
	return ok;
}

RZ_API bool sdb_text_save(Sdb *s, const char *file, bool sort) {
	int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644);
	if (fd < 0) {
		return false;
	}
	bool r = sdb_text_save_fd(s, fd, sort);
	close(fd);
	return r;
}

typedef enum {
	STATE_NEWLINE,
	STATE_PATH,
	STATE_KEY,
	STATE_VALUE
} LoadState;

typedef struct {
	bool eof;
	char *buf;
	size_t bufsz;
	Sdb *root_db;
	Sdb *cur_db; // current namespace, changes when encountering a path line
	size_t pos; // current processing position in the buffer
	size_t line_begin;
	size_t token_begin; // beginning of the currently processed token in the buffer
	size_t shift; // amount to shift chars to the left (from unescaping)
	RzList /*<void *>*/ *path;
	LoadState state;
	bool unescape; // whether the prev char was a backslash, i.e. the current one is escaped
} LoadCtx;

// to be called at the end of a line.
// save all the data processed from the line into the database.
// assumes that the ctx->buf is allocated until ctx->buf[ctx->pos] inclusive!
static void load_process_line(LoadCtx *ctx) {
	ctx->unescape = false;
	// finish up the line
	ctx->buf[ctx->pos - ctx->shift] = '\0';
	switch (ctx->state) {
	case STATE_PATH: {
		rz_list_append(ctx->path, (void *)ctx->token_begin);
		RzListIter *it;
		void *token_off_tmp;
		ctx->cur_db = ctx->root_db;
		rz_list_foreach (ctx->path, it, token_off_tmp) {
			size_t token_off = (size_t)token_off_tmp;
			if (!ctx->buf[token_off]) {
				continue;
			}
			ctx->cur_db = sdb_ns(ctx->cur_db, ctx->buf + token_off, 1);
			if (!ctx->cur_db) {
				ctx->cur_db = ctx->root_db;
				break;
			}
		}
		rz_list_purge(ctx->path);
		break;
	}
	case STATE_VALUE: {
		const char *k = ctx->buf + ctx->line_begin;
		const char *v = ctx->buf + ctx->token_begin;
		if (!*k || !*v) {
			break;
		}
		sdb_set(ctx->cur_db, k, v);
		break;
	}
	default:
		break;
	}
	// prepare for next line
	ctx->shift = 0;
	ctx->state = STATE_NEWLINE;
}

static inline char unescape_raw_char(char c) {
	switch (c) {
	case 'n':
		return '\n';
	case 'r':
		return '\r';
	case 't':
		return '\t';
	default:
		return c;
	}
}

static void load_process_single_char(LoadCtx *ctx) {
	char c = ctx->buf[ctx->pos];
	if (c == '\n' || c == '\r') {
		load_process_line(ctx);
		ctx->pos++;
		return;
	}

	if (ctx->state == STATE_NEWLINE) {
		ctx->line_begin = ctx->pos;
		// at the start of a line, decide whether it's a path or a k=v
		// by whether there is a leading slash.
		if (c == '/') {
			ctx->state = STATE_PATH;
			ctx->token_begin = ctx->pos + 1;
			ctx->pos++;
			c = ctx->buf[ctx->pos];
			return;
		}
		ctx->state = STATE_KEY;
	}

	if (ctx->unescape) {
		ctx->buf[ctx->pos - ctx->shift] = unescape_raw_char(c);
		ctx->unescape = false;
	} else if (c == '\\') {
		// got a backslash, the next char, unescape in the next iteration or die!
		ctx->shift++;
		ctx->unescape = true;
	} else if (ctx->state == STATE_PATH && c == '/') {
		// new path token
		ctx->buf[ctx->pos - ctx->shift] = '\0';
		rz_list_append(ctx->path, (void *)ctx->token_begin);
		ctx->token_begin = ctx->pos + 1;
		ctx->shift = 0;
	} else if (ctx->state == STATE_KEY && c == '=') {
		// switch from key to value mode
		ctx->buf[ctx->pos - ctx->shift] = '\0';
		ctx->token_begin = ctx->pos + 1;
		ctx->shift = 0;
		ctx->state = STATE_VALUE;
	} else if (ctx->shift) {
		// just some char, shift it back if necessary
		ctx->buf[ctx->pos - ctx->shift] = c;
	}
	ctx->pos++;
}

static bool load_process_final_line(LoadCtx *ctx) {
	// load_process_line needs ctx.buf[ctx.pos] to be allocated!
	// so we need room for one additional byte after the buffer.
	size_t linesz = ctx->bufsz - ctx->line_begin;
	char *linebuf = malloc(linesz + 1);
	if (!linebuf) {
		return false;
	}
	memcpy(linebuf, ctx->buf + ctx->line_begin, linesz);
	ctx->buf = linebuf;
	// shift everything by the size we skipped
	ctx->bufsz -= ctx->line_begin;
	ctx->pos = linesz;
	ctx->token_begin -= ctx->line_begin;
	RzListIter *it;
	void *token_off_tmp;
	rz_list_foreach (ctx->path, it, token_off_tmp) {
		it->val = (void *)((size_t)token_off_tmp - ctx->line_begin);
	}
	ctx->line_begin = 0;
	load_process_line(ctx);
	free(linebuf);
	ctx->buf = NULL;
	return true;
}

static void load_ctx_fini(LoadCtx *ctx) {
	rz_list_free(ctx->path);
}

static bool load_ctx_init(LoadCtx *ctx, Sdb *s, char *buf, size_t sz) {
	ctx->eof = false;
	ctx->buf = buf;
	ctx->bufsz = sz;
	ctx->root_db = s;
	ctx->cur_db = s;
	ctx->pos = 0;
	ctx->line_begin = 0;
	ctx->token_begin = 0;
	ctx->shift = 0;
	ctx->path = rz_list_new();
	ctx->state = STATE_NEWLINE;
	ctx->unescape = false;
	if (!ctx->buf || !ctx->path) {
		load_ctx_fini(ctx);
		return false;
	}
	return true;
}

RZ_API bool sdb_text_load_buf(Sdb *s, char *buf, size_t sz) {
	if (!sz) {
		return true;
	}
	LoadCtx ctx;
	if (!load_ctx_init(&ctx, s, buf, sz)) {
		return false;
	}
	bool ret = true;
	while (ctx.pos < ctx.bufsz) {
		load_process_single_char(&ctx);
	}
	if (ctx.line_begin < ctx.bufsz && ctx.state != STATE_NEWLINE) {
		load_process_final_line(&ctx);
	}
	load_ctx_fini(&ctx);
	return ret;
}

RZ_API bool sdb_text_load(Sdb *s, const char *file) {
	int fd = open(file, O_RDONLY | O_BINARY);
	if (fd < 0) {
		return false;
	}
	bool r = false;
	struct stat st;
	if (fstat(fd, &st) || !st.st_size) {
		goto beach;
	}
#if HAVE_HEADER_SYS_MMAN_H
	char *x = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (x == MAP_FAILED) {
		goto beach;
	}
#else
	char *x = calloc(1, st.st_size);
	if (!x) {
		goto beach;
	}
	if (read(fd, x, st.st_size) != st.st_size) {
		free(x);
		goto beach;
	}
#endif
	r = sdb_text_load_buf(s, x, st.st_size);
#if HAVE_HEADER_SYS_MMAN_H
	munmap(x, st.st_size);
#else
	free(x);
#endif
beach:
	close(fd);
	return r;
}
