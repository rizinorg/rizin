#ifndef RZ_EBCDIC_H
#define RZ_EBCDIC_H

#include "rz_utf8.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: ASCII<->EBCDIC conversion

// Unicode <-> EBCDIC conversion
RZ_API static int ibm037_to_unicode(const ut8 *ptr, int ptrlen, RzRune *c);
// EBCDIC strings autodetection
RZ_API RZ_API bool rz_is_ebcdic(const ut8 *str);

#ifdef __cplusplus
}
#endif
#endif