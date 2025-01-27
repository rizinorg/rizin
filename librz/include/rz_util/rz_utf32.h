#ifndef RZ_UTF32_H
#define RZ_UTF32_H

/* For RzRune definition */
#include "rz_utf8.h"

RZ_API int rz_utf32_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch, bool bigendian);
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch);
RZ_API int rz_utf32be_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch);
RZ_API bool rz_utf32_valid_cp(const ut8 *buf, size_t buf_len, bool big_endian);

#endif //  RZ_UTF32_H
