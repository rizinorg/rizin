/* $OpenBSD: magic-common.c,v 1.3 2015/08/11 22:29:25 nicm Exp $ */

/*
 * Copyright (c) 2015 Nicholas Marriott <nicm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "magic.h"

RZ_BORROW char *magic_strtoull(RZ_NONNULL const char *s, RZ_NONNULL ut64 *u) {
	rz_return_val_if_fail(s && u, NULL);

	char *endptr;

	if (*s == '-' || *s == '\0')
		return (NULL);

	errno = 0;
	*u = strtoull(s, &endptr, 0);
	if (endptr == s)
		*u = strtoull(s, &endptr, 16);
	if (errno == ERANGE && *u == ULLONG_MAX)
		return (NULL);
	if (*endptr == 'L')
		endptr++;
	return (endptr);
}

RZ_BORROW char *magic_strtoll(RZ_NONNULL const char *s, RZ_NONNULL int64_t *i) {
	rz_return_val_if_fail(s && i, NULL);

	char *endptr;

	if (*s == '\0')
		return (NULL);

	errno = 0;
	*i = strtoll(s, &endptr, 0);
	if (endptr == s)
		*i = strtoll(s, &endptr, 16);
	if (errno == ERANGE && *i == LLONG_MAX)
		return (NULL);
	if (*endptr == 'L')
		endptr++;
	return (endptr);
}