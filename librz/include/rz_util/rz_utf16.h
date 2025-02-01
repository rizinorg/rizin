#ifndef RZ_UTF16_H
#define RZ_UTF16_H

/* For RzCodePoint definition */
#include "rz_utf8.h"

/**
 * \brief Unicode byte order markings (BOM)
 * according to https://www.unicode.org/faq/utf_bom.html#BOM
 */
#define RZ_UTF16_UNICODE_BOM_LE 0xFFFE
#define RZ_UTF16_UNICODE_BOM_BE 0xFEFF

RZ_API size_t rz_utf16_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NONNULL RZ_OUT RzCodePoint *ch, bool bigendian);
RZ_API size_t rz_utf16le_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NONNULL RZ_OUT RzCodePoint *ch);
RZ_API size_t rz_utf16be_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NONNULL RZ_OUT RzCodePoint *ch);
RZ_API size_t rz_utf16le_encode(RZ_NONNULL RZ_OUT ut8 *buf, RzCodePoint ch);
RZ_API bool rz_utf16_is_printable_cp(const ut8 *buf, size_t buf_len, bool big_endian, size_t lookahead);

#endif //  RZ_UTF16_H
