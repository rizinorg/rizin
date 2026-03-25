// SPDX-FileCopyrightText: 2015 Andrey Jivsov <crypto@brainhub.org>
// SPDX-License-Identifier: MIT

/**
 * \file MurmurHash3.cpp
 * High performance non cryptographic hashing algorithm.
 * Implementation of the MurmurHash3 algorithm.
 * 3 variants of this algo are provided to hash 32,64 and 128 bit data
 * MurmurHash3 was written by Austin Appleby, and is placed in the public domain.
 * is engineered for speed and high-quality distribution,
 * passing the full SMHasher test suite. This makes it a go-to choice for
 * hash tables, bloom filters, and large-scale data de-duplication where
 * performance is the primary constraint.
 *
 * Note - The x86 and x64 versions do _not_ produce the same results, as the
 * algorithms are optimized for their respective platforms. You can still
 * compile and run any of them on any platform, but your performance with the
 * non-native version will be less than optimal.
 *
 */

#include "murmur3.h"
#include "rz_types.h"
#include "rz_types_base.h"
#include <string.h>

static RZ_INLINE ut32 rotl32(ut32 x, int8_t r) {
	return (x << r) | (x >> (32 - r));
}

static RZ_INLINE ut64 rotl64(ut64 x, int8_t r) {
	return (x << r) | (x >> (64 - r));
}

/**
 * \brief Block read - if your platform needs to do endian-swapping or can only
 * handle aligned reads, do the conversion here
 */
#define getblock(p, i) \
	(sizeof(*(p)) == 8 ? rz_read_le64(p + i) : rz_read_le32(p + i))

/*
 * \brief Finalization mix - force all bits of a hash block to avalanche
 */
static RZ_INLINE ut32 fmix32(ut32 h) {
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

static RZ_INLINE ut64 fmix64(ut64 k) {
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xff51afd7ed558ccd);
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
	k ^= k >> 33;

	return k;
}

RZ_IPI void MurmurHash3_x86_32(const void *key, RzRef len, size_t seed, void *out) {
	const ut8 *data = (const ut8 *)key;
	const RzRef nblocks = len / 4;
	RzRef i;

	ut32 h1 = seed;

	ut32 c1 = 0xcc9e2d51;
	ut32 c2 = 0x1b873593;
	const ut32 *blocks = (const ut32 *)(data + nblocks * 4);

	for (i = -nblocks; i; i++) {
		ut32 k1 = getblock(blocks, i);

		k1 *= c1;
		k1 = ROTL32_Murmur3(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = ROTL32_Murmur3(h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}

	const ut8 *tail = (const ut8 *)(data + nblocks * 4);

	ut32 k1 = 0;

	switch (len & 3) {
	case 3:
		k1 ^= tail[2] << 16;
		/* fall through */
	case 2:
		k1 ^= tail[1] << 8;
		/* fall through */
	case 1:
		k1 ^= tail[0];
		k1 *= c1;
		k1 = ROTL32_Murmur3(k1, 15);
		k1 *= c2;
		h1 ^= k1;
	};

	// finalization
	h1 ^= len;
	h1 = fmix32(h1);
	*(ut32 *)out = h1;
}

RZ_IPI void MurmurHash3_x86_128(const void *key, const RzRef len, size_t seed, void *out) {
	const ut8 *data = (const ut8 *)key;
	const RzRef nblocks = len / 16;
	RzRef i;

	size_t h1 = seed;
	size_t h2 = seed;
	size_t h3 = seed;
	size_t h4 = seed;

	const size_t c1 = 0x239b961b;
	const size_t c2 = 0xab0e9789;
	const size_t c3 = 0x38b34ae5;
	const size_t c4 = 0xa1e38b93;

	const ut32 *blocks = (const ut32 *)(data + nblocks * 16);

	for (i = -nblocks; i; i++) {
		ut32 k1 = getblock(blocks, i * 4 + 0);
		ut32 k2 = getblock(blocks, i * 4 + 1);
		ut32 k3 = getblock(blocks, i * 4 + 2);
		ut32 k4 = getblock(blocks, i * 4 + 3);

		k1 *= c1;
		k1 = ROTL32_Murmur3(k1, 15);
		k1 *= c2;
		h1 ^= k1;

		h1 = ROTL32_Murmur3(h1, 19);
		h1 += h2;
		h1 = h1 * 5 + 0x561ccd1b;

		k2 *= c2;
		k2 = ROTL32_Murmur3(k2, 16);
		k2 *= c3;
		h2 ^= k2;

		h2 = ROTL32_Murmur3(h2, 17);
		h2 += h3;
		h2 = h2 * 5 + 0x0bcaa747;

		k3 *= c3;
		k3 = ROTL32_Murmur3(k3, 17);
		k3 *= c4;
		h3 ^= k3;

		h3 = ROTL32_Murmur3(h3, 15);
		h3 += h4;
		h3 = h3 * 5 + 0x96cd1c35;

		k4 *= c4;
		k4 = ROTL32_Murmur3(k4, 18);
		k4 *= c1;
		h4 ^= k4;

		h4 = ROTL32_Murmur3(h4, 13);
		h4 += h1;
		h4 = h4 * 5 + 0x32ac3b17;
	}

	const ut8 *tail = (const ut8 *)(data + nblocks * 16);

	ut32 k1 = 0;
	ut32 k2 = 0;
	ut32 k3 = 0;
	ut32 k4 = 0;

	switch (len & 15) {
	case 15:
		k4 ^= tail[14] << 16;
		/* fall through */
	case 14:
		k4 ^= tail[13] << 8;
		/* fall through */
	case 13:
		k4 ^= tail[12] << 0;
		k4 *= c4;
		k4 = ROTL32_Murmur3(k4, 18);
		k4 *= c1;
		h4 ^= k4;
		/* fall through */

	case 12:
		k3 ^= tail[11] << 24;
		/* fall through */
	case 11:
		k3 ^= tail[10] << 16;
		/* fall through */
	case 10:
		k3 ^= tail[9] << 8;
		/* fall through */
	case 9:
		k3 ^= tail[8] << 0;
		k3 *= c3;
		k3 = ROTL32_Murmur3(k3, 17);
		k3 *= c4;
		h3 ^= k3;
		/* fall through */

	case 8:
		k2 ^= tail[7] << 24;
		/* fall through */
	case 7:
		k2 ^= tail[6] << 16;
		/* fall through */
	case 6:
		k2 ^= tail[5] << 8;
		/* fall through */
	case 5:
		k2 ^= tail[4] << 0;
		k2 *= c2;
		k2 = ROTL32_Murmur3(k2, 16);
		k2 *= c3;
		h2 ^= k2;
		/* fall through */

	case 4:
		k1 ^= tail[3] << 24;
		/* fall through */
	case 3:
		k1 ^= tail[2] << 16;
		/* fall through */
	case 2:
		k1 ^= tail[1] << 8;
		/* fall through */
	case 1:
		k1 ^= tail[0] << 0;
		k1 *= c1;
		k1 = ROTL32_Murmur3(k1, 15);
		k1 *= c2;
		h1 ^= k1;
	};

	h1 ^= len;
	h2 ^= len;
	h3 ^= len;
	h4 ^= len;

	h1 += h2;
	h1 += h3;
	h1 += h4;
	h2 += h1;
	h3 += h1;
	h4 += h1;

	h1 = fmix32(h1);
	h2 = fmix32(h2);
	h3 = fmix32(h3);
	h4 = fmix32(h4);

	h1 += h2;
	h1 += h3;
	h1 += h4;
	h2 += h1;
	h3 += h1;
	h4 += h1;

	((ut32 *)out)[0] = h1;
	((ut32 *)out)[1] = h2;
	((ut32 *)out)[2] = h3;
	((ut32 *)out)[3] = h4;
}

RZ_IPI void MurmurHash3_x64_128(const void *key, const RzRef len, const ut64 seed, void *out) {
	const ut8 *data = (const ut8 *)key;
	const RzRef nblocks = len / 16;
	RzRef i;

	ut64 h1 = seed;
	ut64 h2 = seed;

	const ut64 c1 = BIG_CONSTANT(0x87c37b91114253d5);
	const ut64 c2 = BIG_CONSTANT(0x4cf5ad432745937f);

	const ut64 *blocks = (const ut64 *)(data);

	for (i = 0; i < nblocks; i++) {
		ut64 k1 = getblock(blocks, i * 2 + 0);
		ut64 k2 = getblock(blocks, i * 2 + 1);

		k1 *= c1;
		k1 = ROTL64_Murmur3(k1, 31);
		k1 *= c2;
		h1 ^= k1;

		h1 = ROTL64_Murmur3(h1, 27);
		h1 += h2;
		h1 = h1 * 5 + 0x52dce729;

		k2 *= c2;
		k2 = ROTL64_Murmur3(k2, 33);
		k2 *= c1;
		h2 ^= k2;

		h2 = ROTL64_Murmur3(h2, 31);
		h2 += h1;
		h2 = h2 * 5 + 0x38495ab5;
	}

	const ut8 *tail = (const ut8 *)(data + nblocks * 16);

	ut64 k1 = 0;
	ut64 k2 = 0;

	switch (len & 15) {
	case 15:
		k2 ^= (ut64)(tail[14]) << 48;
		/* fall through */
	case 14:
		k2 ^= (ut64)(tail[13]) << 40;
		/* fall through */
	case 13:
		k2 ^= (ut64)(tail[12]) << 32;
		/* fall through */
	case 12:
		k2 ^= (ut64)(tail[11]) << 24;
		/* fall through */
	case 11:
		k2 ^= (ut64)(tail[10]) << 16;
		/* fall through */
	case 10:
		k2 ^= (ut64)(tail[9]) << 8;
		/* fall through */
	case 9:
		k2 ^= (ut64)(tail[8]) << 0;
		k2 *= c2;
		k2 = ROTL64_Murmur3(k2, 33);
		k2 *= c1;
		h2 ^= k2;
	/* fall through */
	case 8:
		k1 ^= (ut64)(tail[7]) << 56;
		/* fall through */
	case 7:
		k1 ^= (ut64)(tail[6]) << 48;
		/* fall through */
	case 6:
		k1 ^= (ut64)(tail[5]) << 40;
		/* fall through */
	case 5:
		k1 ^= (ut64)(tail[4]) << 32;
		/* fall through */
	case 4:
		k1 ^= (ut64)(tail[3]) << 24;
		/* fall through */
	case 3:
		k1 ^= (ut64)(tail[2]) << 16;
		/* fall through */
	case 2:
		k1 ^= (ut64)(tail[1]) << 8;
		/* fall through */
	case 1:
		k1 ^= (ut64)(tail[0]) << 0;
		k1 *= c1;
		k1 = ROTL64_Murmur3(k1, 31);
		k1 *= c2;
		h1 ^= k1;
	};

	h1 ^= len;
	h2 ^= len;

	h1 += h2;
	h2 += h1;

	h1 = fmix64(h1);
	h2 = fmix64(h2);

	h1 += h2;
	h2 += h1;

	((ut64 *)out)[0] = h1;
	((ut64 *)out)[1] = h2;
}
