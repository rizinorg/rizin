// SPDX-FileCopyrightText: 2011-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
/* $OpenBSD: magic.c,v 1.8 2009/10/27 23:59:37 deraadt Exp $ */

#include <rz_userconf.h>
#include <rz_magic.h>

RZ_LIB_VERSION(rz_magic);

#ifdef _MSC_VER
#include <io.h>
#include <sys\stat.h>
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_IFIFO     (-1)
#define S_ISFIFO(m) (((m) & S_IFIFO) == S_IFIFO)
#define MAXPATHLEN  255
#endif

#if USE_LIB_MAGIC

// we keep this code just to make debian happy, but we should use
// our own magic implementation for consistency reasons
#include <magic.h>
#undef RZ_API
#define RZ_API

RZ_API RzMagic *rz_magic_new(int flags) {
	return magic_open(flags);
}
RZ_API void rz_magic_free(RzMagic *m) {
	if (m) {
		magic_close(m);
	}
}
RZ_API const char *rz_magic_file(RzMagic *m, const char *f) {
	return magic_file(m, f);
}
RZ_API const char *rz_magic_descriptor(RzMagic *m, int fd) {
	return magic_descriptor(m, fd);
}
RZ_API const char *rz_magic_buffer(RzMagic *m, const void *b, size_t s) {
	return magic_buffer(m, b, s);
}
RZ_API const char *rz_magic_error(RzMagic *m) {
	return magic_error(m);
}
RZ_API void rz_magic_setflags(RzMagic *m, int f) {
	magic_setflags(m, f);
}
RZ_API bool rz_magic_load_buffer(RzMagic *m, const char *f) {
	if (*f == '#') {
		return magic_load(m, f) != -1;
	} else {
		eprintf("Magic buffers should start with #\n");
	}
	return false;
}
RZ_API bool rz_magic_load(RzMagic *m, const char *f) {
	return magic_load(m, f) != -1;
}
RZ_API bool rz_magic_compile(RzMagic *m, const char *x) {
	return magic_compile(m, x) != -1;
}
RZ_API bool rz_magic_check(RzMagic *m, const char *x) {
	return magic_check(m, x) != -1;
}
RZ_API int rz_magic_errno(RzMagic *m) {
	return magic_errno(m);
}

#else

/* use embedded magic library */

#include "file.h"

#ifndef PIPE_BUF
/* Get the PIPE_BUF from pathconf */
#ifdef _PC_PIPE_BUF
#define PIPE_BUF pathconf(".", _PC_PIPE_BUF)
#else
#define PIPE_BUF 512
#endif
#endif

static void free_mlist(struct mlist *mlist) {
	struct mlist *ml;
	if (!mlist) {
		return;
	}
	for (ml = mlist->next; ml != mlist;) {
		struct mlist *next = ml->next;
		struct rz_magic *mg = ml->magic;
		file_delmagic(mg, ml->mapped, ml->nmagic);
		free(ml);
		ml = next;
	}
	free(ml);
}

static int info_from_stat(RzMagic *ms, unsigned short md) {
	/* We cannot open it, but we were able to stat it. */
	if (md & 0222) {
		if (file_printf(ms, "writable, ") == -1) {
			return -1;
		}
	}
	if (md & 0111) {
		if (file_printf(ms, "executable, ") == -1) {
			return -1;
		}
	}
	if (S_ISREG(md)) {
		if (file_printf(ms, "regular file, ") == -1) {
			return -1;
		}
	}
	if (file_printf(ms, "no read permission") == -1) {
		return -1;
	}
	return 0;
}

static void close_and_restore(const RzMagic *ms, const char *name, int fd, const struct stat *sb) {
	if (fd >= 0) {
		close(fd);
	}
}

static const char *file_or_fd(RzMagic *ms, const char *inname, int fd) {
	bool ispipe = false;
	int rv = -1;
	unsigned char *buf;
	struct stat sb;
	int nbytes = 0; /* number of bytes read from a datafile */

	/*
	 * one extra for terminating '\0', and
	 * some overlapping space for matches near EOF
	 */
#define SLOP (1 + sizeof(union VALUETYPE))
	if (!(buf = malloc(HOWMANY + SLOP))) {
		return NULL;
	}

	if (file_reset(ms) == -1) {
		goto done;
	}

	switch (file_fsmagic(ms, inname, &sb)) {
	case -1: goto done; /* error */
	case 0: break; /* nothing found */
	default: rv = 0; goto done; /* matched it and printed type */
	}

	if (!inname) {
		if (fstat(fd, &sb) == 0 && S_ISFIFO(sb.st_mode)) {
			ispipe = true;
		}
	} else {
		int flags = O_RDONLY | O_BINARY;

		if (stat(inname, &sb) == 0 && S_ISFIFO(sb.st_mode)) {
#if O_NONBLOCK
			flags |= O_NONBLOCK;
#endif
			ispipe = true;
		}
		errno = 0;
		if ((fd = open(inname, flags)) < 0) {
			eprintf("couldn't open file\n");
			if (info_from_stat(ms, sb.st_mode) == -1) {
				goto done;
			}
			rv = 0;
			goto done;
		}
#ifdef O_NONBLOCK
		if ((flags = fcntl(fd, F_GETFL)) != -1) {
			flags &= ~O_NONBLOCK;
			(void)fcntl(fd, F_SETFL, flags);
		}
#endif
	}

	/*
	 * try looking at the first HOWMANY bytes
	 */
#ifdef O_NONBLOCK
	if (ispipe) {
		ssize_t r = 0;

		// while ((r = sread(fd, (void *)&buf[nbytes],
		while ((r = read(fd, (void *)&buf[nbytes],
				(size_t)(HOWMANY - nbytes))) > 0) {
			nbytes += r;
			if (r < PIPE_BUF) {
				break;
			}
		}

		if (nbytes == 0) {
			/* We can not read it, but we were able to stat it. */
			if (info_from_stat(ms, sb.st_mode) == -1) {
				goto done;
			}
			rv = 0;
			goto done;
		}
	} else {
#endif
		if ((nbytes = read(fd, (char *)buf, HOWMANY)) == -1) {
			file_error(ms, errno, "cannot read `%s'", inname);
			goto done;
		}
#ifdef O_NONBLOCK
	}
#endif

	(void)memset(buf + nbytes, 0, SLOP); /* NUL terminate */
	if (file_buffer(ms, fd, inname, buf, (size_t)nbytes) == -1) {
		goto done;
	}
	rv = 0;
done:
	free(buf);
	close_and_restore(ms, inname, fd, &sb);
	return rv == 0 ? file_getbuffer(ms) : NULL;
}

/* API */

// TODO: reinitialize all the time
RZ_API RzMagic *rz_magic_new(int flags) {
	RzMagic *ms = RZ_NEW0(RzMagic);
	if (!ms) {
		return NULL;
	}
	rz_magic_setflags(ms, flags);
	ms->o.buf = ms->o.pbuf = NULL;
	ms->c.li = malloc((ms->c.len = 10) * sizeof(*ms->c.li));
	if (!ms->c.li) {
		free(ms);
		return NULL;
	}
	file_reset(ms);
	ms->mlist = NULL;
	ms->file = "unknown";
	ms->line = 0;
	return ms;
}

RZ_API void rz_magic_free(RzMagic *ms) {
	if (ms) {
		free_mlist(ms->mlist);
		free(ms->o.pbuf);
		free(ms->o.buf);
		free(ms->c.li);
		free(ms);
	}
}

RZ_API bool rz_magic_load_buffer(RzMagic *ms, const char *magicdata) {
	if (*magicdata == '#') {
		struct mlist *ml = file_apprentice(ms, magicdata, FILE_LOAD);
		if (ml) {
			free_mlist(ms->mlist);
			ms->mlist = ml;
			return true;
		}
	} else {
		eprintf("Magic buffers should start with #\n");
	}
	return false;
}

RZ_API bool rz_magic_load(RzMagic *ms, const char *magicfile) {
	struct mlist *ml = file_apprentice(ms, magicfile, FILE_LOAD);
	if (ml) {
		free_mlist(ms->mlist);
		ms->mlist = ml;
		return true;
	}
	return false;
}

RZ_API bool rz_magic_compile(RzMagic *ms, const char *magicfile) {
	struct mlist *ml = file_apprentice(ms, magicfile, FILE_COMPILE);
	free_mlist(ml);
	return ml != NULL;
}

RZ_API bool rz_magic_check(RzMagic *ms, const char *magicfile) {
	struct mlist *ml = file_apprentice(ms, magicfile, FILE_CHECK);
	free_mlist(ml);
	return ml != NULL;
}

RZ_API const char *rz_magic_descriptor(RzMagic *ms, int fd) {
	return file_or_fd(ms, NULL, fd);
}

RZ_API const char *rz_magic_file(RzMagic *ms, const char *inname) {
	return file_or_fd(ms, inname, 0); // 0 = stdin
}

RZ_API const char *rz_magic_buffer(RzMagic *ms, const void *buf, size_t nb) {
	if (file_reset(ms) == -1) {
		return NULL;
	}
	if (file_buffer(ms, -1, NULL, buf, nb) == -1) {
		return NULL;
	}
	return file_getbuffer(ms);
}

RZ_API const char *rz_magic_error(RzMagic *ms) {
	if (ms && ms->haderr) {
		return ms->o.buf;
	}
	return NULL;
}

RZ_API int rz_magic_errno(RzMagic *ms) {
	if (ms && ms->haderr) {
		return ms->error;
	}
	return 0;
}

RZ_API void rz_magic_setflags(RzMagic *ms, int flags) {
	if (ms) {
		ms->flags = flags;
	}
}
#endif
