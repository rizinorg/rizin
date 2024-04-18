// SPDX-FileCopyrightText: 2017-2018 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_cons.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static ut64 asn1_ber_indefinite(const ut8 *buffer, ut64 length) {
	if (!buffer || length < 3) {
		return 0;
	}
	const ut8 *next = buffer + 2;
	const ut8 *end = buffer + (length - 3);
	while (next < end) {
		if (!next[0] && !next[1]) {
			break;
		}
		if (next[0] == 0x80 && (next[-1] & RZ_ASN1_FORM) == RZ_ASN1_FORM_CONSTRUCTED) {
			next--;
			st64 sz = (st64)asn1_ber_indefinite(next, end - next);
			if (sz < (st64)1) {
				break;
			}
			next += sz;
		}
		next++;
	}
	return (next - buffer) + 2;
}

static RzASN1Object *asn1_parse_header(const ut8 *buffer, ut64 length, const ut8 *start_pointer) {
	ut8 head, length8, byte;
	ut64 length64, remaining;
	if (!buffer || length < 2) {
		return NULL;
	}

	RzASN1Object *object = RZ_NEW0(RzASN1Object);
	if (!object) {
		return NULL;
	}
	head = buffer[0];
	object->offset = buffer - start_pointer;
	object->klass = head & RZ_ASN1_CLASS;
	object->form = head & RZ_ASN1_FORM;
	object->tag = head & RZ_ASN1_TAG;
	length8 = buffer[1];
	remaining = length - 2;
	if (length8 & RZ_ASN1_LENLONG) {
		length64 = 0;
		length8 &= RZ_ASN1_LENSHORT;
		object->sector = buffer + 2;
		if (length8 && length8 < remaining) {
			remaining -= length8;
			// can overflow.
			for (ut8 i8 = 0; i8 < length8; i8++) {
				byte = buffer[2 + i8];
				length64 <<= 8;
				length64 |= byte;
				if (length64 > remaining) {
					// Malformed object - overflow from data ptr
					goto out_error;
				}
			}
			object->sector += length8;
		} else {
			length64 = asn1_ber_indefinite(object->sector, remaining);
			if (length64 > remaining) {
				// Malformed object - overflow from data ptr
				goto out_error;
			}
		}
		object->length = (ut32)length64;
	} else {
		if (length8 > remaining) {
			// Malformed object - overflow from data ptr
			goto out_error;
		}
		object->length = (ut32)length8;
		object->sector = buffer + 2;
	}
	if (object->sector >= (buffer + length)) {
		// Malformed object - overflow from data ptr
		goto out_error;
	}

	if (object->tag == RZ_ASN1_TAG_BITSTRING && !object->sector[0] && object->length > 0) {
		object->sector++; // real sector starts + 1
		object->length--;
	}
	return object;
out_error:
	free(object);
	return NULL;
}

static ut32 asn1_count_objects(RzASN1Object *object) {
	if (!object) {
		return 0;
	}
	const ut8 *buffer = object->sector;
	ut64 length = object->length;
	ut32 counter = 0;
	RzASN1Object *tmp = NULL;
	const ut8 *next = buffer;
	const ut8 *end = buffer + length;
	while (next >= buffer && next < end) {
		// i do not care about the offset now.
		tmp = asn1_parse_header(next, end - next, buffer);
		if (!tmp || next == tmp->sector) {
			RZ_FREE(tmp);
			break;
		}
		next = tmp->sector + tmp->length;
		counter++;
		RZ_FREE(tmp);
	}
	RZ_FREE(tmp);
	return counter;
}

static RzASN1Object *asn1_create_object(const ut8 *buffer, ut64 length, const ut8 *start_pointer) {
	RzASN1Object *object = asn1_parse_header(buffer, length, start_pointer);
	if (object && (object->form == RZ_ASN1_FORM_CONSTRUCTED || object->tag == RZ_ASN1_TAG_BITSTRING || object->tag == RZ_ASN1_TAG_OCTETSTRING)) {
		const ut8 *next = object->sector;
		const ut8 *end = next + object->length;
		if (end > buffer + length) {
			free(object);
			return NULL;
		}
		ut64 count = asn1_count_objects(object);
		if (count > 0) {
			object->list.length = count;
			object->list.objects = RZ_NEWS0(RzASN1Object *, count);
			if (!object->list.objects) {
				rz_asn1_object_free(object);
				return NULL;
			}
			for (ut32 i = 0; next >= buffer && next < end && i < count; i++) {
				RzASN1Object *inner = asn1_create_object(next, end - next, start_pointer);
				if (!inner || next == inner->sector) {
					rz_asn1_object_free(inner);
					break;
				}
				next = inner->sector + inner->length;
				object->list.objects[i] = inner;
			}
		}
	}
	return object;
}

/**
 * \brief      Parse the ASN1 DER encoded buffer
 *
 * \param[in]  buffer  The buffer to decode
 * \param[in]  length  The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1Object *rz_asn1_object_parse(RZ_NONNULL const ut8 *buffer, ut32 length) {
	rz_return_val_if_fail(buffer && length > 0, NULL);
	return asn1_create_object(buffer, length, buffer);
}

/**
 * \brief      Allocates and initializes an RzASN1String structure
 *
 * \param[in]  buffer  The buffer to copy
 * \param[in]  length  The length of the buffer
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzASN1Binary *rz_asn1_binary_parse(RZ_NULLABLE const ut8 *buffer, ut32 length) {
	if (!buffer || !length) {
		return NULL;
	}
	ut8 *buf = (ut8 *)calloc(sizeof(*buf), length);
	if (!buf) {
		return NULL;
	}
	RzASN1Binary *bin = RZ_NEW0(RzASN1Binary);
	if (!bin) {
		free(buf);
		return NULL;
	}
	memcpy(buf, buffer, length);
	bin->binary = buf;
	bin->length = length;
	return bin;
}

static void asn1_print_hex(RzASN1Object *object, char *buffer, ut32 size, ut32 depth, bool structured) {
	if (!object || !object->sector) {
		return;
	}
	char *p = buffer;
	char *end = buffer + size;
	if (depth > 0 && !structured) {
		char *pad = rz_str_pad(' ', (depth * 2) - 2);
		snprintf(p, end - p, "%s", pad);
		p += strlen(pad);
		free(pad);
	}
	for (ut32 i = 0; i < object->length && p < end; i++) {
		snprintf(p, end - p, "%02x", object->sector[i]);
		p += 2;
	}
	if (p >= end) {
		p -= 4;
		snprintf(p, end - p, "...");
	}
}

static void asn1_print_padded(RzStrBuf *sb, RzASN1Object *object, int depth, const char *k, const char *v) {
	if (object->form && !*v) {
		return;
	}
	switch (object->tag) {
	case RZ_ASN1_TAG_NULL:
	case RZ_ASN1_TAG_EOC:
		break;
	case RZ_ASN1_TAG_INTEGER:
	case RZ_ASN1_TAG_REAL:
		if (*rz_str_trim_head_ro(v)) {
			char *pad = rz_str_pad(' ', (depth * 2) - 2);
			rz_strbuf_appendf(sb, "%s%s\n%s%s\n", pad, k, pad, v);
			free(pad);
		}
		break;
	case RZ_ASN1_TAG_BITSTRING:
	default:
		if (*rz_str_trim_head_ro(v)) {
			char *pad = rz_str_pad(' ', (depth * 2) - 2);
			rz_strbuf_appendf(sb, "%s%s\n", pad, v);
			free(pad);
		}
		break;
	}
}

static RzASN1String *asn1_print_hexdump_padded(RzASN1Object *object, ut32 depth, bool structured) {
	const char *pad = NULL;
	char *allocated = NULL;
	ut32 i, j;
	char readable[20] = { 0 };
	if (!object || !object->sector || object->length < 1) {
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new("");
	if (structured) {
		pad = "                                        : ";
	} else {
		pad = allocated = rz_str_pad(' ', depth * 2);
		rz_strbuf_appendf(sb, "  ");
	}

	for (i = 0, j = 0; i < object->length; i++, j++) {
		ut8 c = object->sector[i];
		if (i > 0 && (i % 16) == 0) {
			rz_strbuf_appendf(sb, "|%-16s|\n%s", readable, pad);
			memset(readable, 0, sizeof(readable));
			j = 0;
		}
		rz_strbuf_appendf(sb, "%02x ", c);
		readable[j] = IS_PRINTABLE(c) ? c : '.';
	}
	free(allocated);

	while ((i % 16) != 0) {
		rz_strbuf_appendf(sb, "   ");
		i++;
	}
	rz_strbuf_appendf(sb, "|%-16s|", readable);
	char *text = rz_strbuf_drain(sb);
	RzASN1String *asn1str = rz_asn1_string_parse(text, true, strlen(text) + 1);
	if (!asn1str) {
		/* no memory left.. */
		free(text);
	}
	return asn1str;
}

/**
 * \brief      Converts an the ASN1 structure to a human readable string
 *
 * \param      object      The ASN1 object
 * \param[in]  depth       The padding depth
 * \param[in]  structured  Indicates if to print its structures or not
 * \param      sb          The RzStrBuf to write to
 */
RZ_API void rz_asn1_to_strbuf(RZ_NULLABLE RzASN1Object *object, ut32 depth, bool structured, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(sb);
	if (!object) {
		return;
	}
	// this shall not be freed. it's a pointer into the buffer.
	RzASN1String *asn1str = NULL;
	char temp_name[4096] = { 0 };
	const char *name = "";
	const char *string = "";

	switch (object->klass) {
	case RZ_ASN1_CLASS_UNIVERSAL: // universal
		switch (object->tag) {
		case RZ_ASN1_TAG_EOC:
			name = "EOC";
			break;
		case RZ_ASN1_TAG_BOOLEAN:
			name = "BOOLEAN";
			if (object->sector) {
				string = (object->sector[0] != 0) ? "true" : "false";
			}
			break;
		case RZ_ASN1_TAG_INTEGER:
			name = "INTEGER";
			if (object->length < 16) {
				asn1_print_hex(object, temp_name, sizeof(temp_name), depth, structured);
				string = temp_name;
			} else {
				asn1str = asn1_print_hexdump_padded(object, depth, structured);
			}
			break;
		case RZ_ASN1_TAG_BITSTRING:
			name = "BIT_STRING";
			if (!object->list.objects) {
				if (object->length < 16) {
					asn1_print_hex(object, temp_name, sizeof(temp_name), depth, structured);
					string = temp_name;
				} else {
					asn1str = asn1_print_hexdump_padded(object, depth, structured);
				}
			}
			break;
		case RZ_ASN1_TAG_OCTETSTRING:
			name = "OCTET_STRING";
			if (rz_str_is_printable_limited((const char *)object->sector, object->length)) {
				asn1str = rz_asn1_stringify_string(object->sector, object->length);
			} else if (!object->list.objects) {
				if (object->length < 16) {
					asn1_print_hex(object, temp_name, sizeof(temp_name), depth, structured);
					string = temp_name;
				} else {
					asn1str = asn1_print_hexdump_padded(object, depth, structured);
				}
			}
			break;
		case RZ_ASN1_TAG_NULL:
			name = "NULL";
			break;
		case RZ_ASN1_TAG_OID:
			name = "OBJECT_IDENTIFIER";
			asn1str = rz_asn1_stringify_oid(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_OBJDESCRIPTOR:
			name = "OBJECT_DESCRIPTOR";
			break;
		case RZ_ASN1_TAG_EXTERNAL:
			name = "EXTERNAL";
			break;
		case RZ_ASN1_TAG_REAL:
			name = "REAL";
			asn1str = asn1_print_hexdump_padded(object, depth, structured);
			break;
		case RZ_ASN1_TAG_ENUMERATED:
			name = "ENUMERATED";
			break;
		case RZ_ASN1_TAG_EMBEDDED_PDV:
			name = "EMBEDDED_PDV";
			break;
		case RZ_ASN1_TAG_UTF8STRING:
			name = "UTF8String";
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_SEQUENCE:
			name = "SEQUENCE";
			break;
		case RZ_ASN1_TAG_SET:
			name = "SET";
			break;
		case RZ_ASN1_TAG_NUMERICSTRING:
			name = "NumericString";
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_PRINTABLESTRING:
			name = "PrintableString"; // ASCII subset
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_T61STRING:
			name = "TeletexString"; // aka T61String
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_VIDEOTEXSTRING:
			name = "VideotexString";
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_IA5STRING:
			name = "IA5String"; // ASCII
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_UTCTIME:
			name = "UTCTime";
			asn1str = rz_asn1_stringify_utctime(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_GENERALIZEDTIME:
			name = "GeneralizedTime";
			asn1str = rz_asn1_stringify_time(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_GRAPHICSTRING:
			name = "GraphicString";
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_VISIBLESTRING:
			name = "VisibleString"; // ASCII subset
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_GENERALSTRING:
			name = "GeneralString";
			break;
		case RZ_ASN1_TAG_UNIVERSALSTRING:
			name = "UniversalString";
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		case RZ_ASN1_TAG_BMPSTRING:
			name = "BMPString";
			asn1str = rz_asn1_stringify_string(object->sector, object->length);
			break;
		default:
			snprintf(temp_name, sizeof(temp_name), "Universal_%u", object->tag);
			name = temp_name;
			break;
		}
		break;
	case RZ_ASN1_CLASS_APPLICATION:
		snprintf(temp_name, sizeof(temp_name), "Application_%u", object->tag);
		name = temp_name;
		break;
	case RZ_ASN1_CLASS_CONTEXT:
		snprintf(temp_name, sizeof(temp_name), "Context [%u]", object->tag); // Context
		name = temp_name;
		break;
	case RZ_ASN1_CLASS_PRIVATE:
		snprintf(temp_name, sizeof(temp_name), "Private_%u", object->tag);
		name = temp_name;
		break;
	}
	if (asn1str) {
		string = asn1str->string;
	}
	if (structured) {
		rz_strbuf_appendf(sb, "%4" PFMT64d "  ", object->offset);
		rz_strbuf_appendf(sb, "%4u:%2d: %s %-20s: %s\n", object->length,
			depth, object->form ? "cons" : "prim", name, string);
		rz_asn1_string_free(asn1str);
		if (object->list.objects) {
			for (ut32 i = 0; i < object->list.length; i++) {
				rz_asn1_to_strbuf(object->list.objects[i], depth + 1, structured, sb);
			}
		}
	} else {
		asn1_print_padded(sb, object, depth, name, string);
		rz_asn1_string_free(asn1str);
		if (object->list.objects) {
			for (ut32 i = 0; i < object->list.length; i++) {
				RzASN1Object *obj = object->list.objects[i];
				rz_asn1_to_strbuf(obj, depth + 1, structured, sb);
			}
		}
	}
}

/**
 * \brief      Converts an the ASN1 structure to a human readable string
 *
 * \param      object      The ASN1 object
 * \param[in]  depth       The padding depth
 * \param[in]  structured  Indicates if to print its structures or not
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN char *rz_asn1_to_string(RZ_NULLABLE RzASN1Object *object, ut32 depth, bool structured) {
	if (!object) {
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}
	rz_asn1_to_strbuf(object, depth, structured, sb);
	return rz_strbuf_drain(sb);
}

/**
 * \brief      Frees an RzASN1Object structure
 *
 * \param      object  The ASN1 object to be freed
 */
RZ_API void rz_asn1_object_free(RZ_NULLABLE RzASN1Object *object) {
	if (!object) {
		return;
	}
	// This shall not be freed. it's a pointer into the buffer.
	object->sector = NULL;
	if (object->list.objects) {
		for (ut32 i = 0; i < object->list.length; i++) {
			rz_asn1_object_free(object->list.objects[i]);
		}
		RZ_FREE(object->list.objects);
	}
	object->list.objects = NULL;
	object->list.length = 0;
	free(object);
}

/**
 * \brief      Frees an RzASN1Binary structure
 *
 * \param      bin  The ASN1 binary to be freed
 */
RZ_API void rz_asn1_binary_free(RZ_NULLABLE RzASN1Binary *bin) {
	if (!bin) {
		return;
	}
	free(bin->binary);
	free(bin);
}
