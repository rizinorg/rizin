#ifndef RZ_UTF32_H
#define RZ_UTF32_H

/* For RzRune definition */
#include "rz_utf8.h"

RZ_API int rz_utf32_decode(const ut8 *ptr, int ptrlen, RzRune *ch, bool bigendian);
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RzRune *ch);
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RzRune *ch);

#endif //  RZ_UTF32_H
