#ifndef RZ_UTF16_H
#define RZ_UTF16_H

/* For RRune definition */
#include "rz_utf8.h"

RZ_API int rz_utf16_decode(const ut8 *ptr, int ptrlen, RRune *ch, bool bigendian);
RZ_API int rz_utf16le_decode(const ut8 *ptr, int ptrlen, RRune *ch);
RZ_API int rz_utf16be_decode(const ut8 *ptr, int ptrlen, RRune *ch);
RZ_API int rz_utf16le_encode(ut8 *ptr, RRune ch);

#endif //  RZ_UTF16_H
