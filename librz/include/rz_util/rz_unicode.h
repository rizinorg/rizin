#ifndef RZ_UNICODE_H
#define RZ_UNICODE_H

#include <rz_types.h>
#include "rz_str.h"

#define UNICODE_VERSION_MAJOR   16
#define UNICODE_VERSION_MINOR   0
#define UNICODE_VERSION_PATCH   0
#define UNICODE_LAST_CODE_POINT 0x10ffff

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

typedef ut32 RzCodePoint;

RZ_API bool rz_unicode_code_point_is_printable(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_defined(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_control(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_surrogate(const RzCodePoint c);
RZ_API bool rz_unicode_code_point_is_private(const RzCodePoint c);
RZ_API RzStrEnc rz_unicode_bom_encoding(const ut8 *ptr, size_t ptrlen);

#endif // RZ_UNICODE_H
