#ifndef RZ_UTF8_H
#define RZ_UTF8_H

/* For RzStrEnc definition */
#include "rz_unicode.h"

/**
 * \brief Width of an UTF32 character in bytes.
 */
#define RZ_UTF8_CODE_POINT_WIDTH 1

/**
 * \brief An Unicode code point.
 */
RZ_API size_t rz_utf8_encode(RZ_OUT RZ_NONNULL ut8 *ptr, const RzCodePoint ch);
RZ_API size_t rz_utf8_decode(RZ_NONNULL const ut8 *buf, size_t buf_len, RZ_NULLABLE RZ_OUT RzCodePoint *cp, bool check_is_def);
RZ_API int rz_mutf8_decode(const ut8 *ptr, int ptrlen, RzCodePoint *ch);
RZ_API int rz_utf8_encode_str(const RzCodePoint *str, ut8 *dst, const int dst_length);
RZ_API int rz_utf8_size(const ut8 *ptr);
RZ_API size_t rz_utf8_strlen(const ut8 *str);
RZ_API const char *rz_utf_block_name(int idx);
RZ_API int rz_utf_block_idx(RzCodePoint ch);
RZ_API int *rz_utf_block_list(const ut8 *str, int len, int **freq_list);
#if __WINDOWS__
#define rz_utf16_to_utf8(wc)      rz_utf16_to_utf8_l((wchar_t *)wc, -1)
#define rz_utf8_to_utf16(cstring) rz_utf8_to_utf16_l((char *)cstring, -1)
RZ_API char *rz_utf16_to_utf8_l(const wchar_t *wc, int len);
RZ_API wchar_t *rz_utf8_to_utf16_l(const char *cstring, int len);
RZ_API char *rz_acp_to_utf8_l(const char *str, int len);
RZ_API char *rz_utf8_to_acp_l(const char *str, int len);
#define rz_acp_to_utf8(str)     rz_acp_to_utf8_l((char *)str, -1)
#define rz_utf8_to_acp(cstring) rz_utf8_to_acp_l((char *)cstring, -1)
#endif // __WINDOWS__

#endif //  RZ_UTF8_H
