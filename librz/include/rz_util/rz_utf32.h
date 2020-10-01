#ifndef R_UTF32_H
#define R_UTF32_H

/* For RRune definition */
#include "rz_utf8.h"

RZ_API int rz_utf32_decode(const ut8 *ptr, int ptrlen, RRune *ch, bool bigendian);
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RRune *ch);
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RRune *ch);

#endif //  R_UTF32_H
