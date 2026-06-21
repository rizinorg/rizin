#ifndef RZ_UTF16_H
#define RZ_UTF16_H

/* For RzCodePoint definition */
#include "rz_utf8.h"

/**
 * \brief First Unicode code point which needs 4 bytes to be encoded.
 */
#define RZ_UTF16_FIRST_4BYTES_CODE_POINT 0x10000
/**
 * \brief Width of an UTF16 character in bytes.
 */
#define RZ_UTF16_CODE_POINT_WIDTH 2

RZ_API size_t rz_utf16_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_is_def, bool bigendian);
RZ_API size_t rz_utf16le_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_is_def);
RZ_API size_t rz_utf16be_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *ch, bool check_is_def);
RZ_API size_t rz_utf16_encode(RZ_NONNULL RZ_OUT ut8 *buf, RzCodePoint ch, bool big_endian);
RZ_API bool rz_utf16_is_printable_code_point(RZ_NONNULL const ut8 *buf, size_t buf_len, bool big_endian, size_t lookahead);
RZ_API RZ_OWN ut8 *rz_str_utf16_to_utf8(RZ_NONNULL const ut8 *src, size_t len_src, bool little_endian);

#endif //  RZ_UTF16_H
