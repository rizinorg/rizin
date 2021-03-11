// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

// put common definition of luac

#ifndef BUILD_LUAC_COMMON_H
#define BUILD_LUAC_COMMON_H

#include <rz_bin.h>
#include <rz_lib.h>

/* Macros/Typedefs used in luac */
typedef double LUA_NUMBER;
typedef uint32_t LUA_INSTRUCTION;
typedef uint64_t LUA_INTEGER;

/* Macro Functions */
/* type casts (a macro highlights casts in the code) */
#define luac_cast(t, exp) ((t)(exp))
#define luac_cast_num(i)  luac_cast(LUA_NUMBER, (i))
#define luac_cast_int(i)  luac_cast(int, (i))

/* Macros About Luac Format */
#define LUAC_MAGIC_OFFSET   0x00
#define LUAC_MAGIC_SIZE     4
#define LUAC_VERSION_OFFSET 0x04
#define LUAC_VERSION_SIZE   1

#define LUAC_MAGIC "\x1b\x4c\x75\x61"

/* Export version specified Api to bin_luac.c */
RzBinInfo *info_54(RzBinFile *bf, st32 major, st32 minor);


#endif //BUILD_LUAC_COMMON_H
