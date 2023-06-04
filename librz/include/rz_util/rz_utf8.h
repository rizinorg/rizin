// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2020-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2020 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2019 GustavoLCR <gugulcr@gmail.com>
// SPDX-FileCopyrightText: 2018 a1ext <a13x4nd3r.t@gmail.com>
// SPDX-FileCopyrightText: 2017 Khairul Azhar Kasmiran <kazarmy@gmail.com>
// SPDX-FileCopyrightText: 2016 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_UTF8_H
#define RZ_UTF8_H

/* For RzStrEnc definition */
#include "rz_str.h"

typedef struct {
	ut32 from, to;
	const char *name;
} RUtfBlock;

typedef ut32 RzRune;
RZ_API int rz_utf8_encode(ut8 *ptr, const RzRune ch);
RZ_API int rz_utf8_decode(const ut8 *ptr, int ptrlen, RzRune *ch);
RZ_API int rz_mutf8_decode(const ut8 *ptr, int ptrlen, RzRune *ch);
RZ_API int rz_utf8_encode_str(const RzRune *str, ut8 *dst, const int dst_length);
RZ_API int rz_utf8_size(const ut8 *ptr);
RZ_API int rz_utf8_strlen(const ut8 *str);
RZ_API bool rz_rune_is_printable(const RzRune c);
RZ_API const char *rz_utf_block_name(int idx);
RZ_API int rz_utf_block_idx(RzRune ch);
RZ_API int *rz_utf_block_list(const ut8 *str, int len, int **freq_list);
RZ_API RzStrEnc rz_utf_bom_encoding(const ut8 *ptr, int ptrlen);
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
