// SPDX-FileCopyrightText: D. J. Bernstein <djb@cr.yp.to>
// SPDX-License-Identifier: CC-PDDC

/**
 * \internal
 * \file
 * \brief Reading and operating on a \ref cdb structure.
 *
 * The \ref cdb structure is an associative array mapping strings to
 * strings. Originally written by D. J. Bernstein, see
 * <https://cr.yp.to/cdb.html> for a description of the binary format.
 */

#ifndef CDB_H
#define CDB_H

#include <string.h>
#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \def KVLSZ
 * \brief The size in bytes of the key-value lengths combined.
 */

#define KVLSZ         4
#define CDB_MAX_KEY   0xff
#define CDB_MAX_VALUE 0xffffff

#define CDB_HASHSTART 5381

/** \internal
 * \brief The \ref cdb structure.
 *
 * An associative array of strings to strings based on cdb by
 * D. J. Bernstein, see <https://cr.yp.to/cdb.html>.
 */
struct cdb {
	char *map; ///< Maps the file in memory. NULL if no map is available.
	int fd; ///< The file descriptor from which the cdb structure is read.
	ut32 size; ///< Initialized if map is nonzero.
	ut32 loop; ///< The search state, number of hash slots searched in a given key.
	ut32 khash; ///< Hash of key. Initialized if loop is nonzero.
	ut32 kpos; ///< Key position. Initialized if loop is nonzero.
	ut32 hpos; ///< Current hash table position. Initialized if loop is nonzero.
	ut32 hslots; ///< Number of slots of current hash table. Initialized if loop is nonzero.
	ut32 dpos; ///< Data position. Initialized if cdb_findnext() returns 1.
	ut32 dlen; ///< Data length. Initialized if cdb_findnext() returns 1.
};

/* TODO Remove this! */
bool cdb_getkvlen(struct cdb *db, ut32 *klen, ut32 *vlen, ut32 pos);
void cdb_free(struct cdb *);
bool cdb_init(struct cdb *, int fd);
void cdb_findstart(struct cdb *);
bool cdb_read(struct cdb *, char *, unsigned int, ut32);
int cdb_findnext(struct cdb *, ut32 u, const char *, ut32);

#define cdb_datapos(c) ((c)->dpos)
#define cdb_datalen(c) ((c)->dlen)

#ifdef __cplusplus
}
#endif

#endif
