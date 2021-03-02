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