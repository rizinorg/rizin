// SPDX-FileCopyrightText: D. J. Bernstein
// SPDX-FileCopyrightText: 2014-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: CC-PDDC

/**
 * \internal
 * \file
 * \brief Reading and operating on a \ref cdb structure.
 * \attention This API is not reentrant.
 *
 * The \ref cdb structure is an associative array mapping strings to
 * strings. Originally written by D. J. Bernstein, see
 * <https://cr.yp.to/cdb.html> for a description of the binary format.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rz_endian.h>
#include "cdb.h"
#if HAVE_HEADER_SYS_MMAN_H
#include <sys/mman.h>
#endif
#include "sdb_private.h"

/**
 * \brief Read the key and value lengths at a given offset.
 * \param c The \def cdb structure.
 * \param[out] klen The 8-bit key length read.
 * \param[out] vlen The 24-bit value length read.
 * \param pos The offset in the \ref cdb structure to read from.
 * \return True if successfully read.
 *
 * The 8-bit and 24-bit integer are read in sequence. The 24-bit
 * integer is expected to be stored in low endian order.
 *
 * Thus in total, four bytes are read, and ahead these four bytes,
 * there is expected to be a key-value pair (which is not read). The
 * first 8-bit integer read is the length of the key, and the 24-bit
 * integer read after is the length of the value that follows the key.
 */
bool cdb_getkvlen(struct cdb *c, ut32 *klen, ut32 *vlen, ut32 pos) {
	ut8 buf[4] = { 0 };
	*klen = *vlen = 0;
	if (!cdb_read(c, (char *)buf, sizeof(buf), pos)) {
		return false;
	}
	*klen = (ut32)buf[0];
	*vlen = (ut32)(buf[1] | ((ut32)buf[2] << 8) | ((ut32)buf[3] << 16));
	if (*vlen > CDB_MAX_VALUE) {
		*vlen = CDB_MAX_VALUE; // untaint value for coverity
		return false;
	}
	return true;
}

/**
 * \brief Deallocate a \ref cdb structure.
 * \param c The \ref cdb structure to deallocate.
 *
 * Deallocates the memory used by the structure. This function may be
 * called on any \ref cdb structure that has been previously
 * initialized with a call to \ref cdb_init.
 *
 * \attention Any initialized \cdb structure should eventually be
 * freed according to this function in order to release its memory.
 *
 * # Example
 *
 * \code{.c}
 * // fd is a file descriptor from some open file.
 * struct cdb c;
 * c.fd = -1;
 * if(cdb_init(&c, fd)) {
 *   // ... use c as desired
 *   cdb_free(&c);
 * }
 * \endcode
 */
void cdb_free(struct cdb *c) {
	if (!c->map) {
		return;
	}
#if HAVE_HEADER_SYS_MMAN_H
	(void)munmap(c->map, c->size);
#else
	free(c->map);
#endif
	c->map = NULL;
}

/**
 * \brief Reset the search state of the \ref cdb structure to its beginning.
 * \param c The \ref cdb structure operated upon.
 */
void cdb_findstart(struct cdb *c) {
	c->loop = 0;
#if !HAVE_HEADER_SYS_MMAN_H
	if (c->fd != -1) {
		lseek(c->fd, 0, SEEK_SET);
	}
#endif
}

/**
 * \brief Initialize a \ref cdb structure.
 * \param c A pointer to the \ref cdb structure to allocate.
 * \param fd The file descriptor containing the database.
 * \return \c true if initialization succeeded, \c false otherwise.
 *
 * This is the first operation on a \ref cdb structure. It should be
 * called on a \ref cdb structure where \ref cdb.fd is set to \c -1.
 *
 * This function may be called more than once on the same
 * structure. It will close the associated file descriptor and
 * deallocate memory before associating with the new file descriptor
 * and allocating new memory.
 *
 * \attention The \p fd parameter should be kept open at least until
 * the \ref cdb structure is disassociated with it.
 * \attention The function \ref cdb_free should be called once the
 * \cdb structure is no longer needed.
 *
 * # Example
 * \code{.c}
 * int fd;
 * struct cdb c;
 * c.fd = -1; // This is important in order to call cdb_init.
 * fd = open("cdb_file", O_RDONLY);
 * if(cdb_init(&c, fd)) {
 *   // The cdb structure is ready to use.
 *   // ...
 * } else {
 *   // report error
 * }
 * close(fd);
 * // From this point below, ensure that the cdb structure is either
 * // reinitialized with cdb_init or deallocated with cdb_dealloc.
 * // Do not call other operations once the file descriptor is closed!
 * \endcode
 */
bool cdb_init(struct cdb *c, int fd) {
	struct stat st;
	if (fd != c->fd && c->fd != -1) {
		close(c->fd);
	}
	c->fd = fd;
	cdb_findstart(c);
	if (fd != -1 && !fstat(fd, &st) && st.st_size > 4 && st.st_size != (off_t)UT64_MAX) {
#if HAVE_HEADER_SYS_MMAN_H
		char *x = mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (x == MAP_FAILED) {
			eprintf("Cannot mmap %d\n", (int)st.st_size);
			return false;
		}
		if (c->map) {
			munmap(c->map, c->size);
		}
#else
		char *x = calloc(1, st.st_size);
		if (!x) {
			eprintf("Cannot malloc %d\n", (int)st.st_size);
			return false;
		}
		/* TODO: read by chunks instead of a big huge syscall */
		if (read(fd, x, st.st_size) != st.st_size) {
			/* handle read error */
		}
		free(c->map);
#endif
		c->map = x;
		c->size = st.st_size;
		return true;
	}
	c->map = NULL;
	c->size = 0;
	return false;
}

/**
 * \brief Read bytes from the \ref cdb structure.
 * \param c The \def cdb structure.
 * \param[out] buf The buffer to write to.
 * \param len Number of bytes to write to \p buf.
 * \param pos The offset in the \ref cdb structure to read from.
 * \return \c true if \p bytes were successfully read, \c false
 *  otherwise.
 *
 * The function writes \p len bytes to \p buf from the offset \p in
 * the \ref cdb structure.
 */
bool cdb_read(struct cdb *c, char *buf, ut32 len, ut32 pos) {
	if (c->map) {
		if ((pos > c->size) || (c->size - pos < len)) {
			return false;
		}
		if (!buf) {
			return false;
		}
		memcpy(buf, c->map + pos, len);
		return true;
	}
	if (c->fd == -1 || !seek_set(c->fd, pos)) {
		return false;
	}
	while (len > 0) {
		int r = (int)read(c->fd, buf, len);
		if (r < 1 || (ut32)r != len) {
			return false;
		}
		buf += r;
		len -= r;
	}
	return true;
}

/**
 * \brief The match function to compare keys.
 * \return The value \c 1 is returned if the keys match byte-for-byte.
 * \return The value \c 0 is returned if the keys do not match.
 * \return The value \c -1 is returned if there was an error.
 */
static int match(struct cdb *c, const char *key, ut32 len, ut32 pos) {
	char buf[32];
	const size_t szb = sizeof buf;
	while (len > 0) {
		int n = (szb > len) ? len : szb;
		if (!cdb_read(c, buf, n, pos)) {
			return -1;
		}
		if (memcmp(buf, key, n)) {
			return 0;
		}
		pos += n;
		key += n;
		len -= n;
	}
	return 1;
}

/**
 * \brief Find the next occurence of \p key in the \ref cdb structure.
 * \param u The hash of the \p key to search for.
 * \param key The key, a NUL-terminated string.
 * \param len The string length of \p key.
 * \return The function returns 1 when the key is matched, 0 when not
 * found and -1 on error.
 *
 * This function may be used repeatedly until no more matches are
 * produced. The state of the search is saved within the \ref cdb
 * structure, and may be reset with \ref cdb_findstart.
 *
 * # Example
 * \code{.c}
 * const char *key = "MYKEY";
 * ut32 len = (ut32)strlen(key);
 * ut32 hash = my_hash_func(key);
 * int r;
 * cdb_findstart(&c);
 * while((r = cdb_findnext(&c, hash, key, len)) == 1) {
 *   // process match; details in c->dpos, c->dlen
 * }
 * if(r == -1) {
 *   // process error
 * }
 * cdb_findstart(&c); // reset the search state if necessary
 * \endcode
 */
int cdb_findnext(struct cdb *c, ut32 u, const char *key, ut32 len) {
	char buf[8];
	ut32 pos;
	int m;
	len++; // To include the \0 byte.
	if (c->fd == -1) {
		return -1;
	}
	c->hslots = 0;
	if (!c->loop) {
		/* Read the hash table position. */
		const int bufsz = ((u + 1) & 0xFF) ? sizeof(buf) : sizeof(buf) / 2;
		if (!cdb_read(c, buf, bufsz, (u << 2) & 1023)) {
			return -1;
		}
		/* hslots = (hpos_next - hpos) / 8 */
		c->hpos = rz_read_le32(buf);
		if (bufsz == sizeof(buf)) {
			pos = rz_read_at_le32(buf, 4);
		} else {
			pos = c->size;
		}
		if (pos < c->hpos) {
			return -1;
		}
		c->hslots = (pos - c->hpos) / (2 * sizeof(ut32));
		if (!c->hslots) {
			return 0;
		}
		c->khash = u;
		u = ((u >> 8) % c->hslots) << 3;
		c->kpos = c->hpos + u;
	}
	while (c->loop < c->hslots) {
		/* Loop through the hash table slots. */
		if (!cdb_read(c, buf, sizeof(buf), c->kpos)) {
			return 0;
		}
		pos = rz_read_at_le32(buf, 4);
		if (!pos) {
			return 0;
		}
		c->loop++;
		c->kpos += sizeof(buf);
		if (c->kpos == c->hpos + (c->hslots << 3)) {
			c->kpos = c->hpos;
		}
		u = rz_read_le32(buf);
		if (u == c->khash) {
			/* The hashes match, compare the strings. */
			if (!cdb_getkvlen(c, &u, &c->dlen, pos) || !u) {
				return -1;
			}
			if (u == len) {
				if ((m = match(c, key, len, pos + KVLSZ)) == -1) {
					return 0;
				}
				if (m == 1) {
					c->dpos = pos + KVLSZ + len;
					return 1;
				}
			}
		}
	}
	return 0;
}
