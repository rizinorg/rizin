#ifndef RZ_UTF16_H
#define RZ_UTF16_H

/* For RzRune definition */
#include "rz_utf8.h"

RZ_API int rz_utf16_decode(const ut8 *ptr, int ptrlen, RzRune *ch, bool bigendian);
RZ_API int rz_utf16le_decode(const ut8 *ptr, int ptrlen, RzRune *ch);
RZ_API int rz_utf16be_decode(const ut8 *ptr, int ptrlen, RzRune *ch);
RZ_API int rz_utf16le_encode(ut8 *ptr, RzRune ch);

#endif //  RZ_UTF16_H
