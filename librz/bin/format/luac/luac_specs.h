// SPDX-License-Identifier: LGPL-3.0-only
.
// put common definition of luac

#ifndef BUILD_LUAC_SPECS_H
#define BUILD_LUAC_SPECS_H

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
#define LUAC_MAGIC             "\x1b\x4c\x75\x61"
#define LUAC_FORMAT            0 /* this is the official format */
#define LUAC_DATA              "\x19\x93\r\n\x1a\n"
#define LUAC_INT_VALIDATION    0x5678
#define LUAC_NUMBER_VALIDATION luac_cast_num(370.5)

/* Lua Functions */
void luaLoadBlock(void *src, void *dest, size_t size);
#define luaLoadVector(src, buf, n) luaLoadBlock(src, buf, (n) * sizeof((buf)[0]))
#define luaLoadVar(raw_data, var)  luaLoadVector(raw_data, &(var), 1)

LUA_INTEGER luaLoadInteger(void *src);
LUA_NUMBER luaLoadNumber(void *src);
size_t luaLoadUnsigned(void *src, size_t limit);
size_t luaLoadSize(void *src);
char *luaLoadString(void *src);

#endif //BUILD_LUAC_SPECS_H
