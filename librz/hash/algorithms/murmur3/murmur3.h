// SPDX-FileCopyrightText: 2015. Andrey Jivsov <crypto@brainhub.org>
// SPDX-License-Identifier: MIT

// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

#ifndef _MURMURHASH3_H_
#define _MURMURHASH3_H_

#include <rz_types.h>

#define MURMUR3_32_DIGEST_LENGTH  4
#define MURMUR3_128_DIGEST_LENGTH 16

void MurmurHash3_x86_32(const void *key, int len, size_t seed, void *out);
void MurmurHash3_x86_128(const void *key, int len, size_t seed, void *out);
void MurmurHash3_x64_128(const void *key, int len, size_t seed, void *out);

#endif // _MURMURHASH3_H_
