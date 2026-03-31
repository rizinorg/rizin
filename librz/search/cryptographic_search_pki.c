// SPDX-FileCopyrightText: 2024-2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024-2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cryptographic_search_pki.c
 * Searches for DER/BER encoded sequences in a buffer which are used for storing ASN.1 to public keys.
 **/

#define PKI_SEARCH_MIN_LENGTH 16

/// RFC 3447 for RSA ASN1-bytes representing version field
static ut8 rsa_version[4] = { 0x02, 0x01, 0x00, 0x02 };

/// RFC 5915 for elliptic curves ASN1-bytes representing version field
static ut8 ecc_version[4] = { 0x02, 0x01, 0x01, 0x04 };

/// RFC 5958 ASN1-bytes representing pkcs8 version field used to define PrivateKeyInfo/OneAsymmetricKey structures
static ut8 pkcs8_pkey_version[4] = { 0x02, 0x01, 0x00, 0x30 };

static bool pki_has_marker(const ut8 *marker, size_t marker_size, const ut8 *buffer, size_t buffer_size) {
	if (buffer_size < PKI_SEARCH_MIN_LENGTH) {
		return false;
	}

	// The asn1 sequence identifier is 0x30
	if (buffer[0] != 0x30) {
		return false;
	}

	for (size_t i = 1; i < (buffer_size - marker_size) && i < PKI_SEARCH_MIN_LENGTH; ++i) {
		if (!memcmp(buffer + i, marker, marker_size)) {
			return true;
		}
	}

	return false;
}

static RzSearchHit *rsa_find(ut64 address, const ut8 *bytes, size_t n_bytes) {
	if (!pki_has_marker(rsa_version, sizeof(rsa_version), bytes, n_bytes)) {
		// the marker was not found
		return NULL;
	}

	RzASN1Object *asn1 = rz_asn1_object_parse_header(bytes, n_bytes);
	if (!asn1) {
		return NULL;
	}

	size_t length = asn1->total_size;
	rz_asn1_object_free(asn1);
	return rz_search_hit_new("rsa", address, length, NULL);
}

static RzSearchHit *ecc_find(ut64 address, const ut8 *bytes, size_t n_bytes) {
	if (!pki_has_marker(ecc_version, sizeof(ecc_version), bytes, n_bytes)) {
		// the marker was not found
		return NULL;
	}

	RzASN1Object *asn1 = rz_asn1_object_parse_header(bytes, n_bytes);
	if (!asn1) {
		return NULL;
	}

	size_t length = asn1->total_size;
	rz_asn1_object_free(asn1);
	return rz_search_hit_new("ecc", address, length, NULL);
}

static RzSearchHit *pkcs8_privkey_find(ut64 address, const ut8 *bytes, size_t n_bytes) {
	if (!pki_has_marker(pkcs8_pkey_version, sizeof(pkcs8_pkey_version), bytes, n_bytes)) {
		// the marker was not found
		return NULL;
	}

	RzSearchHitDetail *detail = NULL;
	char *algo_name = NULL;
	RzPrivateKeyInfo *pki = rz_pkcs8_private_key_info_parse(bytes, n_bytes);
	RzASN1Object *asn1 = rz_asn1_object_parse_header(bytes, n_bytes);
	if (!pki || !asn1) {
		rz_pkcs8_private_key_info_free(pki);
		rz_asn1_object_free(asn1);
		return NULL;
	}

	algo_name = rz_pkcs8_private_key_algorithm(pki);
	if (algo_name) {
		detail = rz_search_hit_detail_string_new(algo_name);
		free(algo_name);
	}

	RzSearchHit *hit = rz_search_hit_new("pkcs8_pkey", address, asn1->total_size, detail);
	rz_asn1_object_free(asn1);
	rz_pkcs8_private_key_info_free(pki);
	return hit;
}
