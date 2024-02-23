// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

/**
 * \internal
 * \file
 * \brief Some helpful macros and static functions.
 */

#ifndef SDB_PRIVATE_H_
#define SDB_PRIVATE_H_

#if __WINDOWS__
#include <io.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_HEADER_SYS_MMAN_H
#define HAVE_HEADER_SYS_MMAN_H HAVE_MMAN
#endif

#define SDB_V_NOT(op, fail_ret) \
	if ((op) == (fail_ret)) \
	eprintf(#op " at %s:%d failed: %s\n", __FILE__, __LINE__, strerror(errno))
#define write_(fd, buf, count) SDB_V_NOT(write(fd, buf, count), -1)
#define read_(fd, buf, count)  SDB_V_NOT(read(fd, buf, count), -1)

/**
 * \brief Reposition file offset.
 * \param fd The file whose offset is to be repositioned
 * \param pos The offset to reposition the file to.
 * \return 1 if successful, 0 otherwise.
 */
static inline int seek_set(int fd, off_t pos) {
	return ((fd == -1) || (lseek(fd, (off_t)pos, SEEK_SET) == -1)) ? 0 : 1;
}

#ifdef __cplusplus
}
#endif

#endif
