#ifndef RZ_UTF16_H
#define RZ_UTF16_H

/* For RzRune definition */
#include "rz_utf8.h"

RZ_API size_t rz_utf16_decode(const ut8 *ptr, int ptrlen, RZ_NONNULL RZ_OUT RzCodePoint *ch, bool bigendian);
RZ_API size_t rz_utf16le_decode(const ut8 *ptr, int ptrlen, RZ_NONNULL RZ_OUT RzCodePoint *ch);
RZ_API size_t rz_utf16be_decode(const ut8 *ptr, int ptrlen, RZ_NONNULL RZ_OUT RzCodePoint *ch);
RZ_API size_t rz_utf16le_encode(RZ_NONNULL RZ_OUT ut8 *ptr, RzCodePoint ch);

#endif //  RZ_UTF16_H
