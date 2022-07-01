// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef _INCLUDE_RANGSTR_H_
#define _INCLUDE_RANGSTR_H_

#include <sys/types.h>
#include <rz_types.h>

#define RangstrType unsigned int

typedef struct {
	int type;
	int next;
	size_t f, t;
	const char *p;
} Rangstr;

#if 0
RZ_IPI void rangstr_print (Rangstr *s);
RZ_IPI Rangstr rangstr_new (const char *s);
RZ_IPI Rangstr rangstr_null(void);
RZ_IPI int rangstr_int (Rangstr *s);
RZ_IPI char *rangstr_dup (Rangstr *rs);
RZ_IPI Rangstr rangstr_news (const char *s, RangstrType *res, int i);
RZ_IPI int rangstr_cmp (Rangstr *a, Rangstr *b);
RZ_IPI const char *rangstr_str (Rangstr* rs);
RZ_IPI int rangstr_length (Rangstr* rs);
RZ_IPI int rangstr_find (Rangstr* rs, char ch);
#endif

#endif
