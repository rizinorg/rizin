#ifndef RZ_UTF32_H
#define RZ_UTF32_H

/* For RzCodePoint definition */
#include "rz_utf8.h"

/**
 * \brief Unicode byte order markings (BOM)
 * according to https://www.unicode.org/faq/utf_bom.html#BOM
 */
#define RZ_UTF32_UNICODE_BOM_LE 0xFFFE0000
#define RZ_UTF32_UNICODE_BOM_BE 0x0000FFFE

/**
 * \brief Width of an UTF32 character in bytes.
 */
#define RZ_UTF32_WIDTH_CHAR       4
#define RZ_UTF32_CODE_POINT_WIDTH 4

RZ_API size_t rz_utf32_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_is_def, bool big_endian);
RZ_API int rz_utf32le_decode(const ut8 *ptr, int ptrlen, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_validity);
RZ_API int rz_utf32be_decode(const ut8 *ptr, int ptrlen, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_validity);
RZ_API size_t rz_utf32_encode(RZ_NONNULL RZ_OUT ut8 *buf, RzCodePoint ch, bool big_endian);
RZ_API bool rz_utf32_valid_code_point(RZ_NONNULL const ut8 *buf, size_t buf_len, bool big_endian, size_t lookahead);
RZ_API RZ_OWN ut8 *rz_str_utf32_to_utf8(RZ_NONNULL const ut8 *src, size_t len_src, bool little_endian);

#endif //  RZ_UTF32_H
