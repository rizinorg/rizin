#ifndef RZ_EBCDIC_H
#define RZ_EBCDIC_H

#include "rz_utf8.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: ASCII<->EBCDIC conversion
RZ_API static int ibm037_to_ascii(const ut8 src, ut8 *dst);
RZ_API static int ibm037_from_ascii(ut8 *dst, const ut8 src);

RZ_API static int ibm290_to_ascii(const ut8 src, ut8 *dst);
RZ_API static int ibm290_from_ascii(ut8 *dst, const ut8 src);

RZ_API static int ebcdic_uk_to_ascii(const ut8 src, ut8 *dst);
RZ_API static int ebcdic_uk_from_ascii(ut8 *dst, const ut8 src);

RZ_API static int ebcdic_us_to_ascii(const ut8 src, ut8 *dst);
RZ_API static int ebcdic_us_from_ascii(ut8 *dst, const ut8 src);

RZ_API static int ebcdic_es_to_ascii(const ut8 src, ut8 *dst);
RZ_API static int ebcdic_es_from_ascii(ut8 *dst, const ut8 src);

// Unicode <-> EBCDIC conversion
RZ_API static int ibm037_to_unicode(const ut8 src, RzRune *dst);
RZ_API static int ibm037_from_unicode(ut8 *dst, const RzRune src);

RZ_API static int ibm290_to_unicode(const ut8 src, RzRune *dst);
RZ_API static int ibm290_from_unicode(ut8 *dst, const RzRune src);

RZ_API static int ebcdic_uk_to_unicode(const ut8 src, RzRune *dst);
RZ_API static int ebcdic_uk_from_unicode(ut8 *dst, const RzRune src);

RZ_API static int ebcdic_us_to_unicode(const ut8 src, RzRune *dst);
RZ_API static int ebcdic_us_from_unicode(ut8 *dst, const RzRune src);

RZ_API static int ebcdic_es_to_unicode(const ut8 src, RzRune *dst);
RZ_API static int ebcdic_es_from_unicode(ut8 *dst, const RzRune src);

// EBCDIC strings autodetection
RZ_API static bool rz_is_ebcdic(const ut8 *str);

#ifdef __cplusplus
}
#endif
#endif