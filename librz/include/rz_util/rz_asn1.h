#ifndef RZ_ASN1_H
#define RZ_ASN1_H

#include <rz_types.h>
#include <stdint.h>
#include <rz_util/rz_strbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_ASN1_JSON_NULL  "null"
#define RZ_ASN1_JSON_EMPTY "{}"

#define RZ_ASN1_OID_LEN 64

/* Masks */
#define RZ_ASN1_CLASS    0xC0 /* Bits 8 and 7 */
#define RZ_ASN1_FORM     0x20 /* Bit 6 */
#define RZ_ASN1_TAG      0x1F /* Bits 5 - 1 */
#define RZ_ASN1_LENLONG  0x80 /* long form */
#define RZ_ASN1_LENSHORT 0x7F /* Bits 7 - 1 */

/* Classes */
#define RZ_ASN1_CLASS_UNIVERSAL   0x00 /* 0 = Universal (defined by ITU X.680) */
#define RZ_ASN1_CLASS_APPLICATION 0x40 /* 1 = Application */
#define RZ_ASN1_CLASS_CONTEXT     0x80 /* 2 = Context-specific */
#define RZ_ASN1_CLASS_PRIVATE     0xC0 /* 3 = Private */

/* Forms */
#define RZ_ASN1_FORM_PRIMITIVE   0x00 /* 0 = primitive */
#define RZ_ASN1_FORM_CONSTRUCTED 0x20 /* 1 = constructed */

/* Tags */
#define RZ_ASN1_TAG_EOC             0x00 /*  0: End-of-contents octets */
#define RZ_ASN1_TAG_BOOLEAN         0x01 /*  1: Boolean */
#define RZ_ASN1_TAG_INTEGER         0x02 /*  2: Integer */
#define RZ_ASN1_TAG_BITSTRING       0x03 /*  2: Bit string */
#define RZ_ASN1_TAG_OCTETSTRING     0x04 /*  4: Byte string */
#define RZ_ASN1_TAG_NULL            0x05 /*  5: NULL */
#define RZ_ASN1_TAG_OID             0x06 /*  6: Object Identifier */
#define RZ_ASN1_TAG_OBJDESCRIPTOR   0x07 /*  7: Object Descriptor */
#define RZ_ASN1_TAG_EXTERNAL        0x08 /*  8: External */
#define RZ_ASN1_TAG_REAL            0x09 /*  9: Real */
#define RZ_ASN1_TAG_ENUMERATED      0x0A /* 10: Enumerated */
#define RZ_ASN1_TAG_EMBEDDED_PDV    0x0B /* 11: Embedded Presentation Data Value */
#define RZ_ASN1_TAG_UTF8STRING      0x0C /* 12: UTF8 string */
#define RZ_ASN1_TAG_SEQUENCE        0x10 /* 16: Sequence/sequence of */
#define RZ_ASN1_TAG_SET             0x11 /* 17: Set/set of */
#define RZ_ASN1_TAG_NUMERICSTRING   0x12 /* 18: Numeric string */
#define RZ_ASN1_TAG_PRINTABLESTRING 0x13 /* 19: Printable string (ASCII subset) */
#define RZ_ASN1_TAG_T61STRING       0x14 /* 20: T61/Teletex string */
#define RZ_ASN1_TAG_VIDEOTEXSTRING  0x15 /* 21: Videotex string */
#define RZ_ASN1_TAG_IA5STRING       0x16 /* 22: IA5/ASCII string */
#define RZ_ASN1_TAG_UTCTIME         0x17 /* 23: UTC time */
#define RZ_ASN1_TAG_GENERALIZEDTIME 0x18 /* 24: Generalized time */
#define RZ_ASN1_TAG_GRAPHICSTRING   0x19 /* 25: Graphic string */
#define RZ_ASN1_TAG_VISIBLESTRING   0x1A /* 26: Visible string (ASCII subset) */
#define RZ_ASN1_TAG_GENERALSTRING   0x1B /* 27: General string */
#define RZ_ASN1_TAG_UNIVERSALSTRING 0x1C /* 28: Universal string */
#define RZ_ASN1_TAG_BMPSTRING       0x1E /* 30: Basic Multilingual Plane/Unicode string */

typedef struct rz_asn1_string_t {
	ut32 length;
	const char *string;
	bool allocated;
} RzASN1String;

typedef struct rz_asn1_list_t {
	ut32 length;
	struct rz_asn1_object_t **objects;
} RzASN1List;

typedef struct rz_asn1_bin_t {
	ut32 length;
	ut8 *binary;
} RzASN1Binary;

typedef struct rz_asn1_object_t {
	ut8 klass; /* class type */
	ut8 form; /* defines if contains data or objects */
	ut8 tag; /* tag type */
	const ut8 *sector; /* Sector containing data */
	ut32 length; /* Sector Length */
	ut64 offset; /* Object offset */
	RzASN1List list; /* List of objects contained in the sector */
} RzASN1Object;

RZ_API RZ_OWN RzASN1Object *rz_asn1_object_parse(RZ_NONNULL const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1Binary *rz_asn1_binary_parse(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_string_parse(RZ_NULLABLE const char *string, bool allocated, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_bits(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_utctime(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_time(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_integer(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_string(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_bytes(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_boolean(RZ_NULLABLE const ut8 *buffer, ut32 length);
RZ_API RZ_OWN RzASN1String *rz_asn1_stringify_oid(RZ_NULLABLE const ut8 *buffer, ut32 length);

RZ_API void rz_asn1_object_free(RZ_NULLABLE RzASN1Object *object);
RZ_API void rz_asn1_to_strbuf(RZ_NULLABLE RzASN1Object *object, ut32 depth, bool structured, RZ_NONNULL RzStrBuf *sb);
RZ_API RZ_OWN char *rz_asn1_to_string(RZ_NULLABLE RzASN1Object *object, ut32 depth, bool structured);
RZ_API void rz_asn1_string_free(RZ_NULLABLE RzASN1String *string);
RZ_API void rz_asn1_binary_free(RZ_NULLABLE RzASN1Binary *string);

#ifdef __cplusplus
}
#endif

#endif /* RZ_ASN1_H */
