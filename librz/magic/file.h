/*	$OpenBSD: file.h,v 1.22 2009/10/27 23:59:37 deraadt Exp $ */
/*
 * Copyright (c) Ian F. Darwin 1986-1995.
 * Software written by Ian F. Darwin and others;
 * maintained 1995-present by Christos Zoulas and others.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * file.h - definitions for file(1) program
 * @(#)$Id: file.h,v 1.22 2009/10/27 23:59:37 deraadt Exp $
 */

#ifndef __file_h__
#define __file_h__

#include "mconfig.h"
#include <rz_magic.h>

#include <stdio.h> /* Include that here, to make sure __P gets defined */
#include <errno.h>
#include <fcntl.h> /* For open and flags */
#include <inttypes.h> // TODO: use utX
#include <rz_util/rz_regex.h>
#include <sys/types.h>
/* Do this here and now, because struct stat gets re-defined on solaris */
#include <sys/stat.h>
#include <stdarg.h>

/* Type for Unicode characters */
typedef unsigned long unichar;

struct stat;
const char *file_fmttime(unsigned int, int, char *);
int file_buffer(struct rz_magic_set *, int, const char *, const void *, size_t);
int file_fsmagic(struct rz_magic_set *, const char *, struct stat *);
int file_pipe2file(struct rz_magic_set *, int, const void *, size_t);
int file_printf(struct rz_magic_set *, const char *, ...);
int file_reset(struct rz_magic_set *);
int file_tryelf(struct rz_magic_set *, int, const unsigned char *, size_t);
int file_zmagic(struct rz_magic_set *, int, const char *, const ut8 *, size_t);
int file_ascmagic(struct rz_magic_set *, const unsigned char *, size_t);
int file_is_tar(struct rz_magic_set *, const unsigned char *, size_t);
int file_softmagic(struct rz_magic_set *, const unsigned char *, size_t, int);
struct mlist *file_apprentice(struct rz_magic_set *, const char *, int);
ut64 file_signextend(RzMagic *, struct rz_magic *, ut64);
void file_delmagic(struct rz_magic *, int type, size_t entries);
void file_badread(struct rz_magic_set *);
void file_badseek(struct rz_magic_set *);
void file_oomem(struct rz_magic_set *, size_t);
void file_error(struct rz_magic_set *, int, const char *, ...);
void file_magerror(struct rz_magic_set *, const char *, ...);
void file_magwarn(struct rz_magic_set *, const char *, ...);
void file_mdump(struct rz_magic *);
void file_showstr(FILE *, const char *, size_t);
size_t file_mbswidth(const char *);
const char *file_getbuffer(struct rz_magic_set *);
ssize_t sread(int, void *, size_t, int);
int file_check_mem(struct rz_magic_set *, unsigned int);
int file_looks_utf8(const unsigned char *, size_t, unichar *, size_t *);

#ifndef HAVE_VASPRINTF
int vasprintf(char **ptr, const char *format_string, va_list vargs);
#endif
#ifndef HAVE_ASPRINTF
int asprintf(char **ptr, const char *format_string, ...);
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#endif /* __file_h__ */
