// SPDX-FileCopyrightText: unknown
// SPDX-License-Identifier: CC-PDDC

#ifndef BUFFER_H
#define BUFFER_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*BufferOp)(int, const char *, int);

typedef struct buffer {
	char *x;
	unsigned int p;
	unsigned int n;
	int fd;
	BufferOp op;
} buffer;

extern void buffer_init(buffer *, BufferOp, int, char *, unsigned int);
extern int buffer_flush(buffer *);
extern int buffer_putalign(buffer *, const char *, unsigned int);
extern int buffer_putflush(buffer *, const char *, unsigned int);

#ifdef __cplusplus
}
#endif

#endif
