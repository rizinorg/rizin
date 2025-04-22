// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file cryptographic_search_x509.c
 * Searches for DER/BER encoded sequences in a buffer which are used for storing x509 certificates.
 **/

#define X509_SEARCH_MIN_LENGTH 9

// marker A0 0302 01
#define X509_ASN1_VERSION(b, o) (b[o] == 0xa0 && b[o + 1] == 3 && b[o + 2] == 2 && b[o + 3] == 1)

static bool x509_has_version_or_serial(const ut8 *buffer, size_t buffer_size) {
	if (buffer[5] == 0x82 && buffer[8] == 0x02) {
		// 0x3082....3082....02
		return true;
	} else if (buffer_size >= 11 && buffer[5] == 0x81 && X509_ASN1_VERSION(buffer, 7)) {
		// 0x3082....3081..A0030201
		return true;
	} else if (buffer_size >= 12 && buffer[5] == 0x82 && X509_ASN1_VERSION(buffer, 8)) {
		// 0x3082....3082....A0030201
		return true;
	}
	return false;
}

static RzSearchHit *x509_find(ut64 address, const ut8 *buffer, size_t buffer_size) {
	if (buffer_size < X509_SEARCH_MIN_LENGTH) {
		return NULL;
	}

	// The asn1 sequence identifier is 0x3082....30
	if (!(buffer[0] == 0x30 && buffer[1] == 0x82 &&
		    buffer[4] == 0x30 && x509_has_version_or_serial(buffer, buffer_size))) {
		return NULL;
	}

	RzASN1Object *asn1 = rz_asn1_object_parse_header(buffer, buffer_size);
	if (!asn1) {
		return NULL;
	}

	size_t length = asn1->total_size;
	rz_asn1_object_free(asn1);
	return rz_search_hit_new("x509", address, length, NULL);
}
