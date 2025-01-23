// SPDX-FileCopyrightText: 2021 Billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_EBCDIC_H
#define RZ_EBCDIC_H

#include "rz_utf8.h"

#ifdef __cplusplus
extern "C" {
#endif

// ASCII<->EBCDIC conversion
RZ_API int rz_str_ibm037_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst);
RZ_API int rz_str_ibm037_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src);

RZ_API int rz_str_ibm290_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst);
RZ_API int rz_str_ibm290_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src);

RZ_API int rz_str_ebcdic_uk_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst);
RZ_API int rz_str_ebcdic_uk_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src);

RZ_API int rz_str_ebcdic_us_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst);
RZ_API int rz_str_ebcdic_us_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src);

RZ_API int rz_str_ebcdic_es_to_ascii(const ut8 src, RZ_NONNULL RZ_OUT ut8 *dst);
RZ_API int rz_str_ebcdic_es_from_ascii(RZ_NONNULL RZ_OUT ut8 *dst, const ut8 src);

// Unicode <-> EBCDIC conversion
RZ_API int rz_str_ibm037_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzCodePoint *dst);
RZ_API int rz_str_ibm037_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzCodePoint src);

RZ_API int rz_str_ibm290_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzCodePoint *dst);
RZ_API int rz_str_ibm290_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzCodePoint src);

RZ_API int rz_str_ebcdic_uk_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzCodePoint *dst);
RZ_API int rz_str_ebcdic_uk_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzCodePoint src);

RZ_API int rz_str_ebcdic_us_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzCodePoint *dst);
RZ_API int rz_str_ebcdic_us_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzCodePoint src);

RZ_API int rz_str_ebcdic_es_to_unicode(const ut8 src, RZ_NONNULL RZ_OUT RzCodePoint *dst);
RZ_API int rz_str_ebcdic_es_from_unicode(RZ_NONNULL RZ_OUT ut8 *dst, const RzCodePoint src);

#ifdef __cplusplus
}
#endif
#endif
