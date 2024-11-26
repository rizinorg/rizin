// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2008 Nadia Heninger and J. Alex Halderman
// SPDX-FileCopyrightText: 2008 J. Alex Halderman
// SPDX-License-Identifier: BSD-3-Clause

// Originally from RSAKeyFinder 1.0 (2008-07-18) By Nadia Heninger and J. Alex Halderman
// Improved by santitox, jvoisin and spelissier

#include <rz_search.h>
#include <rz_util.h>

#include "search_internal.h"

/* The minimal length to perform a search is the sizes of
the sequence tag, the minimal length of the sequence,
the version marker and the minimal key length. */
#define PRIVKEY_SEARCH_MIN_LENGTH (1 + 1 + 4 + 1)
#define KEY_MAX_LEN               26000

typedef struct pkey_marker {
	const char *metadata;
	ut8 marker[4];
} PKeyMarker;

static PKeyMarker rsa_version = {
	"rsa",
	/// RFC 3447 for RSA ASN1-bytes representing version field
	{ 0x02, 0x01, 0x00, 0x02 },
};

static PKeyMarker ecc_version = {
	"ecc",
	/// RFC 5915 for elliptic curves ASN1-bytes representing version field
	{ 0x02, 0x01, 0x01, 0x04 },
};

static PKeyMarker safecurves_version = {
	"safecurves",
	/// RFC 8410 for Edwards-curve ASN1-bytes representing version field
	{ 0x02, 0x01, 0x00, 0x30 },
};

/*Baby BER parser, just good enough for private keys.

This is not robust to errors in the memory image, but if we added
some entropy testing and intelligent guessing, it could be made to be.

Parses a single field of the key, beginning at start.  Each field
consists of a type, a length, and a value.  Puts the type of field
into type, the number of bytes into len, and returns a pointer to
the beginning of the value. */
static const ut8 *parse_next_field(const ut8 *start, size_t *len) {
	*len = 0;
	if (!(start[1] & 0x80)) {
		*len = (size_t)start[1];
		return start + 2;
	}

	const size_t lensize = start[1] & 0x7f;
	for (size_t i = 0; i < lensize; i++) {
		*len = (*len << 8) | start[2 + i];
	}
	return start + 2 + lensize;
}

/* Check if `start` points to an ensemble of BER fields
with the format as a private key syntax. We check only the first
three fields of the key */
static int check_fields(const ut8 *start) {
	size_t field_len = 0;
	// Sequence field
	const ut8 *ptr = parse_next_field(start, &field_len);
	if (!field_len || field_len > KEY_MAX_LEN) {
		return false;
	}

	// Version field
	ptr = parse_next_field(ptr, &field_len);
	if (field_len != 1) {
		return false;
	}
	ptr = ptr + field_len;
	parse_next_field(ptr, &field_len);

	if (!field_len || field_len > KEY_MAX_LEN) {
		return false;
	}

	return true;
}

// Finds and return index of a private key based on the asn1 bytes
static bool pkeys_find(void *user, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits) {
	const char *metadata = NULL;
	// always skip the first 2 bytes since they are the sequence identifier + size
	for (size_t offset = 2; offset < (size - PRIVKEY_SEARCH_MIN_LENGTH); offset++) {
		if (!memcmp(buffer + offset, rsa_version.marker, sizeof(rsa_version.marker))) {
			metadata = rsa_version.metadata;
		} else if (!memcmp(buffer + offset, ecc_version.marker, sizeof(ecc_version.marker))) {
			metadata = ecc_version.metadata;
		} else if (!memcmp(buffer + offset, safecurves_version.marker, sizeof(safecurves_version.marker))) {
			metadata = safecurves_version.metadata;
		} else {
			continue;
		}

		size_t key_len = 0;
		size_t max = 5;
		ssize_t index = -1;
		// Going backward maximum up to 5 characters.
		if (offset < 5) {
			max = offset;
		}
		for (size_t k = offset - 2; k >= offset - max; k--) {
			if (buffer[k] == 0x30) { // The asn1 sequence identifier is 0x30
				index = k;
				break;
			}
		}

		if (index == -1) {
			continue;
		}

		if (check_fields(buffer + index)) {
			parse_next_field(buffer + index, &key_len);

			RzSearchHit *hit = rz_search_hit_new(metadata, address + index, key_len);
			if (!hit || !rz_th_queue_push(hits, hit, true)) {
				rz_search_hit_free(hit);
				return false;
			}
		}
	}
	return true;
}

static bool pkeys_is_empty(void *user) {
	// we always return false.
	return false;
}

/**
 * \brief      Allocates and initialize a pkey RzSearchCollection
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzSearchCollection *rz_search_collection_private_keys() {
	return rz_search_collection_new(pkeys_find, pkeys_is_empty, NULL, NULL);
}
