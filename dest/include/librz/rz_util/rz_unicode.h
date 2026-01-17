#ifndef RZ_UNICODE_H
#define RZ_UNICODE_H

#include <rz_types.h>
#include "rz_str.h"

#define RZ_UNICODE_NUL                    0
#define RZ_UNICODE_MAX_BYTES_PER_CHAR     4
#define RZ_UNICODE_VERSION_MAJOR          16
#define RZ_UNICODE_VERSION_MINOR          0
#define RZ_UNICODE_VERSION_PATCH          0
#define RZ_UNICODE_LAST_ASCII             0x7F
#define RZ_UNICODE_FIRST_1BYTE_CODE_POINT 0x0
#define RZ_UNICODE_FIRST_2BYTE_CODE_POINT 0x80
#define RZ_UNICODE_FIRST_3BYTE_CODE_POINT 0x0800
#define RZ_UNICODE_FIRST_4BYTE_CODE_POINT 0x010000
#define RZ_UNICODE_LAST_CODE_POINT        0x10ffff
/**
 * \brief String width of "\U00hhhhhh"
 */
#define RZ_UNICODE_ESCAPED_STR_WIDTH 10

struct rz_unicode_range_name_entry_t {
	ut32 from;
	ut32 to;
	const char *name;
};

typedef struct rz_unicode_range_name_entry_t RzUnicodeRangeNameTable[];

struct rz_unicode_range_entry_t {
	ut32 from;
	ut32 to;
};

typedef struct rz_unicode_range_entry_t RzUnicodeRangeTable[];

/**
 * \brief An Unicode code point.
 *
 * NOTE: Be careful when assigning char values to it. On some platforms
 * they might get sign extended and the code point is an invalid value.
 */
typedef ut32 RzCodePoint;

RZ_API bool rz_unicode_code_point_is_printable(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_defined(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_legal_decode(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_control(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_surrogate(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_private(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_format(const RzCodePoint c);
RZ_API RzStrEnc rz_unicode_bom_encoding(const ut8 *ptr, size_t ptrlen);
RZ_API void rz_unicode_code_point_escape(RzCodePoint code_point, RZ_NONNULL RZ_OUT char **dst, RZ_NONNULL const RzStrEscOptions *opt);
RZ_API void rz_unicode_byte_escape(char ch, RZ_NONNULL RZ_OUT char **dst, RZ_NONNULL const RzStrEscOptions *opt);

#endif // RZ_UNICODE_H
