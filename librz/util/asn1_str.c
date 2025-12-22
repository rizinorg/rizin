// SPDX-FileCopyrightText: 2017-2018 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2017-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "asn1_oids.h"

static const char *_hex = "0123456789abcdef";

/**
 * \brief      Allocates and initializes an RzASN1String structure
 *
 * \param[in]  string     The string to hold
 * \param[in]  allocated  Indicates if the pointer is owned by the structure or not
 * \param[in]  length     The length of the string
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_string_parse(RZ_NULLABLE const char *string, bool allocated, ut32 length) {
	if (!string || !length) {
		return NULL;
	}
	RzASN1String *s = RZ_NEW0(RzASN1String);
	if (s) {
		s->allocated = allocated;
		s->length = length;
		s->string = string;
	}
	return s;
}

static RzASN1String *newstr_const(const char *string) {
	return rz_asn1_string_parse(string, false, strlen(string) + 1);
}

static RzASN1String *newstr_strbuf_drain(RzStrBuf *sb) {
	size_t length = rz_strbuf_length(sb) + 1;
	char *string = rz_strbuf_drain_nofree(sb);
	return rz_asn1_string_parse(string, true, length);
}

/**
 * \brief      Allocates and initializes an RzASN1String structure from a raw buffer
 *
 * \param[in]  buffer     The buffer to read from
 * \param[in]  length     The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_string(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	if (!buffer || !length) {
		return NULL;
	}
	char *str = rz_str_ndup((const char *)buffer, length);
	if (!str) {
		return NULL;
	}
	rz_str_filter(str);
	return rz_asn1_string_parse(str, true, strlen(str));
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing an utc timestamp
 *
 * \param[in]  buffer     The buffer to read from
 * \param[in]  length     The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_utctime(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	if (!buffer || length != 13 || buffer[12] != 'Z') {
		return NULL;
	}
	const int str_sz = 24;
	char *str = malloc(str_sz);
	if (!str) {
		return NULL;
	}
	str[0] = buffer[4];
	str[1] = buffer[5];
	str[2] = '/';
	str[3] = buffer[2];
	str[4] = buffer[3];
	str[5] = '/';
	str[6] = buffer[0] < '5' ? '2' : '1';
	str[7] = buffer[0] < '5' ? '0' : '9';
	str[8] = buffer[0];
	str[9] = buffer[1];
	str[10] = ' ';
	str[11] = buffer[6];
	str[12] = buffer[7];
	str[13] = ':';
	str[14] = buffer[8];
	str[15] = buffer[9];
	str[16] = ':';
	str[17] = buffer[10];
	str[18] = buffer[11];
	str[19] = ' ';
	str[20] = 'G';
	str[21] = 'M';
	str[22] = 'T';
	str[23] = '\0';

	RzASN1String *asn1str = rz_asn1_string_parse(str, true, str_sz);
	if (!asn1str) {
		free(str);
	}
	return asn1str;
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing a timestamp
 *
 * \param[in]  buffer     The buffer to read from
 * \param[in]  length     The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_time(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	if (!buffer || length != 15 || buffer[14] != 'Z') {
		return NULL;
	}
	const int str_sz = 24;
	char *str = malloc(str_sz);
	if (!str) {
		return NULL;
	}

	str[0] = buffer[6];
	str[1] = buffer[7];
	str[2] = '/';
	str[3] = buffer[4];
	str[4] = buffer[5];
	str[5] = '/';
	str[6] = buffer[0];
	str[7] = buffer[1];
	str[8] = buffer[2];
	str[9] = buffer[3];
	str[10] = ' ';
	str[11] = buffer[8];
	str[12] = buffer[9];
	str[13] = ':';
	str[14] = buffer[10];
	str[15] = buffer[11];
	str[16] = ':';
	str[17] = buffer[12];
	str[18] = buffer[13];
	str[19] = ' ';
	str[20] = 'G';
	str[21] = 'M';
	str[22] = 'T';
	str[23] = '\0';

	RzASN1String *asn1str = rz_asn1_string_parse(str, true, str_sz);
	if (!asn1str) {
		free(str);
	}
	return asn1str;
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing a bit array
 *
 * \param[in]  buffer     The buffer to read from
 * \param[in]  length     The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_bits(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	if (!buffer || length < 1 || buffer[0] > length) {
		return NULL;
	}
	ut64 size = 1 + ((length - 1) * 8) - buffer[0];
	char *str = (char *)malloc(size);
	if (!str) {
		return NULL;
	}
	for (ut32 i = 1, j = 0; i < length && j < size; i++) {
		ut8 c = buffer[i];
		for (ut32 k = 0; k < 8 && j < size; k++, j++) {
			str[size - j - 1] = c & 0x80 ? '1' : '0';
			c <<= 1;
		}
	}
	str[size - 1] = '\0';
	RzASN1String *asn1str = rz_asn1_string_parse(str, true, size);
	if (!asn1str) {
		free(str);
	}
	return asn1str;
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing a boolean value
 *
 * \param[in]  buffer     The buffer to read from
 * \param[in]  length     The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_boolean(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	if (!buffer || length != 1 || (buffer[0] != 0 && buffer[0] != 0xFF)) {
		return NULL;
	}
	return newstr_const(rz_str_bool(buffer[0]));
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing an integer
 *
 * \param[in]  buffer     The buffer to read from
 * \param[in]  length     The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_integer(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	ut32 i, j;
	ut64 size;
	ut8 c;
	char *str;
	if (!buffer || !length) {
		return NULL;
	}
	size = 3 * length;
	str = (char *)malloc(size);
	if (!str) {
		return NULL;
	}
	memset(str, 0, size);
	for (i = 0, j = 0; i < length && j < size; i++, j += 3) {
		c = buffer[i];
		str[j + 0] = _hex[c >> 4];
		str[j + 1] = _hex[c & 15];
		str[j + 2] = ':';
	}
	str[size - 1] = '\0';
	RzASN1String *asn1str = rz_asn1_string_parse(str, true, size);
	if (!asn1str) {
		free(str);
	}
	return asn1str;
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing hexadecimal bytes
 *
 * \param[in]  buffer     The buffer to read from
 * \param[in]  length     The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_bytes(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	ut32 i, j, k;
	ut64 size;
	ut8 c;
	char *str;
	if (!buffer || !length) {
		return NULL;
	}
	size = (4 * length);
	size += (64 - (size % 64));
	str = (char *)malloc(size);
	if (!str) {
		return NULL;
	}
	memset(str, 0x20, size);

	for (i = 0, j = 0, k = 48; i < length && j < size && k < size; i++, j += 3, k++) {
		c = buffer[i];
		str[j + 0] = _hex[c >> 4];
		str[j + 1] = _hex[c & 15];
		str[j + 2] = ' ';
		str[k] = (c >= ' ' && c <= '~') ? c : '.';
		if (i % 16 == 15) {
			str[j + 19] = '\n';
			j += 17;
			k += 49;
		}
	}
	str[size - 1] = '\0';
	str = rz_str_trim_tail(str);

	RzASN1String *asn1str = rz_asn1_string_parse(str, true, size);
	if (!asn1str) {
		free(str);
	}
	return asn1str;
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing a OID
 *
 * \param[in]  buffer     The buffer to read from
 * \param[in]  length     The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_oid(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	const ut8 *start = NULL, *end = NULL;
	const char *oid_decoded = NULL;
	const ASN1OidListEntry *oid_match = NULL;
	size_t slen = 0;
	ut32 bits = 0;
	ut64 oid = 0;
	RzStrBuf sb = { 0 };
	if (!buffer || !length) {
		return NULL;
	}

	rz_strbuf_init(&sb);

	end = buffer + length;
	for (start = buffer; start < end && slen < RZ_ASN1_OID_LEN; start++) {
		ut8 c = *start;
		oid <<= 7;
		oid |= (c & 0x7F);
		bits += 7;
		if (!(c & 0x80)) {
			if (!slen) {
				ut32 m = oid / 40;
				ut32 n = oid % 40;
				rz_strbuf_appendf(&sb, "%01u.%01u", m, n);
				slen = rz_strbuf_length(&sb);
			} else {
				rz_strbuf_appendf(&sb, ".%01u", (ut32)oid);
				slen = rz_strbuf_length(&sb);
			}
			oid = 0;
			bits = 0;
		}
	}

	// incomplete oid.
	// bad structure.
	if (bits > 0) {
		rz_strbuf_fini(&sb);
		return NULL;
	}

	slen = rz_strbuf_length(&sb);
	oid_decoded = rz_strbuf_get(&sb);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(known_oid_list); ++i) {
		if (slen < known_oid_list[i].length ||
			(oid_match && oid_match->length > known_oid_list[i].length)) {
			continue;
		}

		size_t oid_len = RZ_MIN(slen, known_oid_list[i].length);
		if (strncmp(known_oid_list[i].oid, oid_decoded, oid_len)) {
			continue;
		}

		oid_match = &known_oid_list[i];
		if (known_oid_list[i].length == slen) {
			// perfect match
			break;
		}
	}

	RzASN1String *asn1str = NULL;
	if (!oid_match) {
		// no match, not even partial, so we return the actual oid.
		asn1str = newstr_strbuf_drain(&sb);
		return asn1str;
	}

	// we have a perfect or partial match, so we return the name + part of the unknown oid.
	RzStrBuf match = { 0 };
	rz_strbuf_init(&match);
	rz_strbuf_set(&match, oid_match->name);

	if (oid_match->length != slen) {
		// partial match, so we return the partial name and the remaining ids.
		rz_strbuf_append(&match, oid_decoded + oid_match->length);
		const char *partial_str = rz_strbuf_get(&match);
		rz_str_replace_ch((char *)partial_str + oid_match->length, '.', '/', 1);
	}

	rz_strbuf_appendf(&match, " (%s)", oid_decoded);

	asn1str = newstr_strbuf_drain(&match);
	rz_strbuf_fini(&sb);
	return asn1str;
}

/**
 * \brief      Frees a RzASN1String structure
 *
 * \param[in]  str  The pointer to be freed
 */
RZ_API void rz_asn1_string_free(RZ_NULLABLE RzASN1String *str) {
	if (!str) {
		return;
	}
	if (str->allocated) {
		free((char *)str->string);
	}
	free(str);
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing the ASN1 tag type
 *
 * \param[in]  object     The RzASN1Object to stringify
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RzASN1String *asn1_stringify_tag(RzASN1Object *object) {
	if (!object) {
		return NULL;
	}
	const char *s = "Unknown tag";
	// TODO: use array of strings
	switch (object->tag) {
	case RZ_ASN1_TAG_EOC: s = "EOC"; break;
	case RZ_ASN1_TAG_BOOLEAN: s = "BOOLEAN"; break;
	case RZ_ASN1_TAG_INTEGER: s = "INTEGER"; break;
	case RZ_ASN1_TAG_BITSTRING: s = "BIT STRING"; break;
	case RZ_ASN1_TAG_OCTETSTRING: s = "OCTET STRING"; break;
	case RZ_ASN1_TAG_NULL: s = "NULL"; break;
	case RZ_ASN1_TAG_OID: s = "OBJECT IDENTIFIER"; break;
	case RZ_ASN1_TAG_OBJDESCRIPTOR: s = "ObjectDescriptor"; break;
	case RZ_ASN1_TAG_EXTERNAL: s = "EXTERNAL"; break;
	case RZ_ASN1_TAG_REAL: s = "REAL"; break;
	case RZ_ASN1_TAG_ENUMERATED: s = "ENUMERATED"; break;
	case RZ_ASN1_TAG_EMBEDDED_PDV: s = "EMBEDDED PDV"; break;
	case RZ_ASN1_TAG_UTF8STRING: s = "UTF8String"; break;
	case RZ_ASN1_TAG_SEQUENCE: s = "SEQUENCE"; break;
	case RZ_ASN1_TAG_SET: s = "SET"; break;
	case RZ_ASN1_TAG_NUMERICSTRING: s = "NumericString"; break;
	case RZ_ASN1_TAG_PRINTABLESTRING: s = "PrintableString"; break;
	case RZ_ASN1_TAG_T61STRING: s = "TeletexString"; break;
	case RZ_ASN1_TAG_VIDEOTEXSTRING: s = "VideotexString"; break;
	case RZ_ASN1_TAG_IA5STRING: s = "IA5String"; break;
	case RZ_ASN1_TAG_UTCTIME: s = "UTCTime"; break;
	case RZ_ASN1_TAG_GENERALIZEDTIME: s = "GeneralizedTime"; break;
	case RZ_ASN1_TAG_GRAPHICSTRING: s = "GraphicString"; break;
	case RZ_ASN1_TAG_VISIBLESTRING: s = "VisibleString"; break;
	case RZ_ASN1_TAG_GENERALSTRING: s = "GeneralString"; break;
	case RZ_ASN1_TAG_UNIVERSALSTRING: s = "UniversalString"; break;
	case RZ_ASN1_TAG_BMPSTRING: s = "BMPString"; break;
	}
	return newstr_const(s);
}

/**
 * \brief      Allocates and initializes an RzASN1String structure containing the hold ASN1 object
 *
 * \param[in]  object     The RzASN1Object to stringify
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RzASN1String *asn1_stringify_sector(RzASN1Object *object) {
	if (!object) {
		return NULL;
	}
	switch (object->tag) {
	case RZ_ASN1_TAG_EOC:
		return NULL;
	case RZ_ASN1_TAG_BOOLEAN:
		return newstr_const(rz_str_bool(object->sector[0]));
	case RZ_ASN1_TAG_REAL:
	case RZ_ASN1_TAG_INTEGER:
		if (object->length < 16) {
			return rz_asn1_stringify_integer(object->sector, object->length);
		} else {
			return rz_asn1_stringify_bytes(object->sector, object->length);
		}
	case RZ_ASN1_TAG_BITSTRING:
		if (object->length > 0 && object->length < 20) {
			return rz_asn1_stringify_bits(object->sector, object->length);
		} else {
			return rz_asn1_stringify_bytes(object->sector, object->length);
		}
	case RZ_ASN1_TAG_OCTETSTRING:
		return rz_asn1_stringify_bytes(object->sector, object->length);
	case RZ_ASN1_TAG_NULL:
		return NULL;
	case RZ_ASN1_TAG_OID:
		return rz_asn1_stringify_oid(object->sector, object->length);
		//    case RZ_ASN1_TAG_OBJDESCRIPTOR:
		//    case RZ_ASN1_TAG_EXTERNAL:
		//    case RZ_ASN1_TAG_ENUMERATED:
		//    case RZ_ASN1_TAG_EMBEDDED_PDV:
	case RZ_ASN1_TAG_UTF8STRING:
		//    case RZ_ASN1_TAG_SEQUENCE:
		//    case RZ_ASN1_TAG_SET:
	case RZ_ASN1_TAG_NUMERICSTRING:
	case RZ_ASN1_TAG_PRINTABLESTRING:
		//    case RZ_ASN1_TAG_T61STRING:
		//    case RZ_ASN1_TAG_VIDEOTEXSTRING:
	case RZ_ASN1_TAG_IA5STRING:
	case RZ_ASN1_TAG_VISIBLESTRING:
		return rz_asn1_stringify_string(object->sector, object->length);
	case RZ_ASN1_TAG_UTCTIME:
		return rz_asn1_stringify_utctime(object->sector, object->length);
	case RZ_ASN1_TAG_GENERALIZEDTIME:
		return rz_asn1_stringify_time(object->sector, object->length);
		//    case RZ_ASN1_TAG_GRAPHICSTRING:
		//    case RZ_ASN1_TAG_GENERALSTRING:
		//    case RZ_ASN1_TAG_UNIVERSALSTRING:
		//    case RZ_ASN1_TAG_BMPSTRING:
	}
	return NULL;
}
