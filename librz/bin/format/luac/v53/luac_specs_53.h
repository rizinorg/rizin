// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#ifndef BUILD_LUAC_SPECS_53_H
#define BUILD_LUAC_SPECS_53_H

#include "librz/bin/format/luac/luac_common.h"

typedef double LUA_NUMBER;
typedef ut64 LUA_INTEGER;
typedef ut32 LUA_INT;

#define cast(t, exp) ((t)(exp))
#define cast_num(i)  cast(LUA_NUMBER, (i))

#define LUAC_54_FORMAT            0
#define LUAC_54_DATA              "\x19\x93\r\n\x1a\n"
#define LUAC_53_INT_VALIDATION    0x5678
#define LUAC_53_NUMBER_VALIDATION cast_num(370.5)

/* Header Part */
#define LUAC_53_FORMAT_OFFSET           0x05
#define LUAC_53_LUAC_DATA_OFFSET        0x06
#define LUAC_53_INT_SIZE_OFFSET         0x0C
#define LUAC_53_SIZET_SIZE_OFFSET       0x0D
#define LUAC_53_INSTRUCTION_SIZE_OFFSET 0x0E
#define LUAC_53_INTEGER_SIZE_OFFSET     0x0F
#define LUAC_53_NUMBER_SIZE_OFFSET      0x10
#define LUAC_53_INTEGER_VALID_OFFSET    0x11 /* from 0x11 - 0x18 : 8 bytes */
#define LUAC_53_NUMBER_VALID_OFFSET     0x19 /* from 0x19 - 0x20 : 8 bytes */
#define LUAC_53_UPVALUES_NUMBER_OFFSET  0x21

#define LUAC_53_HDRSIZE 0x22

/* Body */
#define LUAC_FILENAME_OFFSET 0x22

/* Macros of tag */
// conflict with 5.4
#define LUA_TNUMFLT (3 | (0 << 4)) /* float numbers */
#define LUA_TNUMINT (3 | (1 << 4)) /* integer numbers */

#endif // BUILD_LUAC_SPECS_53_H
