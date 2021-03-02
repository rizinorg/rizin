//
// Created by heersin on 2/28/21.
// Implement Functions declared in luac_specs.h
//

#include "luac_specs.h"

void luaLoadBlock(void *src, void *dest, size_t size)
{
    memcpy(dest, src, size);
}

LUA_INTEGER luaLoadInteger(void *src)
{
    LUA_INTEGER x;
    luaLoadVar(src, x);
    return x;
}

LUA_NUMBER luaLoadNumber(void *src)
{
    LUA_NUMBER x;
    luaLoadVar(src, x);
    return x;
}

/* Luac load method , defined in lua source code lundump.c */
size_t luaLoadUnsigned(void *src, size_t limit)
{
    size_t x = 0;
    int b;
    int i = 0;
    limit >>= 7;
    do {
        b = ((unsigned char *)src)[i];
        if (x >= limit) {
            eprintf("integer overflow\n");
            return 0;
        }
        x = (x << 7) | (b & 0x7f);
    } while ((b & 0x80) == 0);
    return x;
}

size_t luaLoadSize(void *src)
{
    return luaLoadUnsigned(src, ~(size_t)0);
}

/* load a null-terminated string, return a malloced string */
char *luaLoadString(void *src)
{
    /* size is the buffer's size */
    size_t size = luaLoadSize(src);

    /* no string */
    if (size == 0){
        return NULL;
    }

    /* skip size byte */
    void *string_start = src + 1;
    char *ret = (char *)malloc(size * sizeof(char));
    memcpy(ret, string_start, size - 1);
    ret[size] = '\0';

    return ret;
}

