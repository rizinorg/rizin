// SPDX-FileCopyrightText: 1999 Alan DeKok <aland@ox.org>
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef RZ_HASH_MD5_H
#define RZ_HASH_MD5_H

#include <rz_types.h>

#define RZ_HASH_MD5_DIGEST_SIZE  0x10
#define RZ_HASH_MD5_BLOCK_LENGTH 0x40

#include <string.h>

/*  The below was retrieved from
 *  http://www.openbsd.org/cgi-bin/cvsweb/~checkout~/src/sys/crypto/md5.h?rev=1.1
 *  With the following changes: uint64_t => ut32[2]
 *  Commented out #include <sys/cdefs.h>
 *  Commented out the __BEGIN and __END _DECLS, and the __attributes.
 */

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

#define MD5_BLOCK_LENGTH  64
#define MD5_DIGEST_LENGTH 16

typedef struct MD5Context {
	ut32 state[4]; /* state */
	ut32 count[2]; /* number of bits, mod 2^64 */
	ut8 buffer[MD5_BLOCK_LENGTH]; /* input buffer */
} rz_MD5_CTX;

RZ_IPI void rz_MD5Init(rz_MD5_CTX *);
RZ_IPI void rz_MD5Update(rz_MD5_CTX *, const ut8 *, size_t);
RZ_IPI void rz_MD5Final(ut8[MD5_DIGEST_LENGTH], rz_MD5_CTX *);

#endif /* RZ_HASH_MD5_H */
