// SPDX-FileCopyrightText: unknown
// SPDX-License-Identifier: CC-PDDC

#ifndef BUFFER_H
#define BUFFER_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief The callback which writes to the file descriptor.
 *
 * Takes the parameters \c fd, \c buf, \c len in this order, and
 * returns the number of bytes successfully written.
 */
typedef int (*BufferOp)(int, const char *, int);

typedef struct buffer {
	char *x; ///< The underlying memory buffer.
	unsigned int p; ///< Anything between 0 and p is buffered; not yet written out.
	unsigned int n; ///< The total size of the memory buffer.
	int fd; ///< The file descriptor to write to when the buffer is full.
	BufferOp op; ///< The callback which writes to the file descriptor.
} buffer;

extern void buffer_init(buffer *, BufferOp, int, char *, unsigned int);
extern int buffer_flush(buffer *);
extern int buffer_putalign(buffer *, const char *, unsigned int);
extern int buffer_putflush(buffer *, const char *, unsigned int);

#ifdef __cplusplus
}
#endif

#endif
