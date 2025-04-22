// SPDX-FileCopyrightText: 2024-2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cryptographic_search_pki.c
 * Searches for DER/BER encoded sequences in a buffer which are used for storing ASN.1 to public keys.
 **/

#define PKI_SEARCH_MIN_LENGTH 8

/// RFC 3447 for RSA ASN1-bytes representing version field
static ut8 rsa_version[4] = { 0x02, 0x01, 0x00, 0x02 };

/// RFC 5915 for elliptic curves ASN1-bytes representing version field
static ut8 ecc_version[4] = { 0x02, 0x01, 0x01, 0x04 };

/// RFC 8410 for Edwards-curve ASN1-bytes representing version field
static ut8 safecurves_version[4] = { 0x02, 0x01, 0x00, 0x30 };

static RzSearchHit *pki_find(const ut8 *marker, size_t marker_size, const char *metadata, ut64 address, const ut8 *buffer, size_t buffer_size) {
	bool marker_found = false;
	if (buffer_size < PKI_SEARCH_MIN_LENGTH) {
		return NULL;
	}

	// The asn1 sequence identifier is 0x30
	if (buffer[0] != 0x30) {
		return NULL;
	}

	for (size_t i = 1; i < (buffer_size - marker_size) && i < PKI_SEARCH_MIN_LENGTH; ++i) {
		if (!memcmp(buffer + i, marker, marker_size)) {
			marker_found = true;
			break;
		}
	}

	if (!marker_found) {
		// the marker was not found
		return NULL;
	}

	RzASN1Object *asn1 = rz_asn1_object_parse_header(buffer, buffer_size);
	if (!asn1) {
		return NULL;
	}

	size_t length = asn1->total_size;
	rz_asn1_object_free(asn1);
	return rz_search_hit_new(metadata, address, length, NULL);
}

static RzSearchHit *rsa_find(ut64 address, const ut8 *bytes, size_t n_bytes) {
	return pki_find(rsa_version, sizeof(rsa_version), "rsa", address, bytes, n_bytes);
}

static RzSearchHit *ecc_find(ut64 address, const ut8 *bytes, size_t n_bytes) {
	return pki_find(ecc_version, sizeof(ecc_version), "ecc", address, bytes, n_bytes);
}

static RzSearchHit *safecurves_find(ut64 address, const ut8 *bytes, size_t n_bytes) {
	return pki_find(safecurves_version, sizeof(safecurves_version), "safecurves", address, bytes, n_bytes);
}
