// SPDX-FileCopyrightText: unknown
// SPDX-License-Identifier: CC-PDDC

/** \file
 * \brief Operations on buffers.
 *
 * Provide simple buffered write functionality: functions to write to
 * memory buffer until filled out and then write to file descriptor
 * via provided callback, or to flush buffer.
 */

#include "buffer.h"

/**
 * \brief Initialize a buffer.
 * \param[out] s The buffer to initialize.
 * \param[in] op The writing operation of the buffer.
 * \param fd The file descriptor to write to.
 * \param buf The underlying buffer associated with \p s.
 * \param len The size in bytes of the underlying buffer.
 * \attention This function owns \p buf for as long as \p s is used.
 */
void buffer_init(buffer *s, BufferOp op, int fd, char *buf, ut32 len) {
	s->x = buf;
	s->fd = fd;
	s->op = op;
	s->p = 0;
	s->n = len;
}

/** \internal
 * \brief Unbuffered write of a message.
 * \param op The writing operation.
 * \param fd The file descriptor to write to.
 * \param buf The message to write.
 * \param len The size in bytes of the message to write.
 * \return \c 1 for success, \c 0 for failure.
 */
static int allwrite(BufferOp op, int fd, const char *buf, ut32 len) {
	ut32 w;
	while (len > 0) {
		w = op(fd, buf, len);
		if (w != len) {
			return 0;
		}
		buf += w;
		len -= w;
	}
	return 1;
}

/**
 * \brief Flush (write out) buffered data.
 * \param s The buffer containing buffered data.
 * \return \c 1 for success, \c 0 for failure.
 */
int buffer_flush(buffer *s) {
	int p = s->p;
	if (!p) {
		return 1;
	}
	s->p = 0;
	return allwrite(s->op, s->fd, s->x, p);
}

/**
 * \brief Buffered write of message.
 * \param s The buffer to operate on.
 * \param buf The message to write.
 * \param len The length of the message in bytes.
 */
int buffer_putalign(buffer *s, const char *buf, ut32 len) {
	ut32 n;
	if (!s || !s->x || !buf) {
		return 0;
	}
	while (len > (n = s->n - s->p)) {
		memcpy(s->x + s->p, buf, n);
		s->p += n;
		buf += n;
		len -= n;
		if (!buffer_flush(s)) {
			return 0;
		}
	}
	/* now len <= s->n - s->p */
	memcpy(s->x + s->p, buf, len);
	s->p += len;
	return 1;
}

/**
 * \brief Flush buffer and then flush message.
 * \param s The buffer to operate on.
 * \param buf The message to write.
 * \param len The length of the message in bytes.
 * \return \c 1 for success, \c 0 for failure.
 *
 * Whatever buffered data is in \p s is flushed and then an unbuffered
 * write of the contents of \p buf is performed.
 */
int buffer_putflush(buffer *s, const char *buf, ut32 len) {
	if (!buffer_flush(s)) {
		return 0;
	}
	return allwrite(s->op, s->fd, buf, len);
}
