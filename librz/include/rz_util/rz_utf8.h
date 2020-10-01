#ifndef R_UTF8_H
#define R_UTF8_H

/* For RStrEnc definition */
#include "rz_str.h"

typedef struct { ut32 from, to; const char *name; } RUtfBlock;
// extern const RUtfBlock rz_utf_blocks[];

typedef ut32 RRune;
RZ_API int rz_utf8_encode(ut8 *ptr, const RRune ch);
RZ_API int rz_utf8_decode(const ut8 *ptr, int ptrlen, RRune *ch);
RZ_API int rz_utf8_encode_str(const RRune *str, ut8 *dst, const int dst_length);
RZ_API int rz_utf8_size(const ut8 *ptr);
RZ_API int rz_utf8_strlen(const ut8 *str);
RZ_API int rz_isprint(const RRune c);
RZ_API char *rz_utf16_to_utf8_l(const wchar_t *wc, int len);
RZ_API const char *rz_utf_block_name(int idx);
RZ_API wchar_t *rz_utf8_to_utf16_l(const char *cstring, int len);
RZ_API int rz_utf_block_idx (RRune ch);
RZ_API int *rz_utf_block_list (const ut8 *str, int len, int **freq_list);
RZ_API RStrEnc rz_utf_bom_encoding(const ut8 *ptr, int ptrlen);
#define rz_utf16_to_utf8(wc) rz_utf16_to_utf8_l ((wchar_t *)wc, -1)
#define rz_utf8_to_utf16(cstring) rz_utf8_to_utf16_l ((char *)cstring, -1)
#if __WINDOWS__
RZ_API char *rz_acp_to_utf8_l(const char *str, int len);
RZ_API char *rz_utf8_to_acp_l(const char *str, int len);
#define rz_acp_to_utf8(str) rz_acp_to_utf8_l ((char *)str, -1)
#define rz_utf8_to_acp(cstring) rz_utf8_to_acp_l ((char *)cstring, -1)
#endif // __WINDOWS__

#endif //  R_UTF8_H
