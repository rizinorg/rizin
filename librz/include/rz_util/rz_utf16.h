// SPDX-FileCopyrightText: 2020 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2020 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-FileCopyrightText: 2017 Khairul Azhar Kasmiran <kazarmy@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_UTF16_H
#define RZ_UTF16_H

/* For RzRune definition */
#include "rz_utf8.h"

RZ_API int rz_utf16_decode(const ut8 *ptr, int ptrlen, RzRune *ch, bool bigendian);
RZ_API int rz_utf16le_decode(const ut8 *ptr, int ptrlen, RzRune *ch);
RZ_API int rz_utf16be_decode(const ut8 *ptr, int ptrlen, RzRune *ch);
RZ_API int rz_utf16le_encode(ut8 *ptr, RzRune ch);

#endif //  RZ_UTF16_H
