//
// Created by heersin on 3/1/21.
//

#ifndef BUILD_LUAC_54_H
#define BUILD_LUAC_54_H

#include "luac_specs.h"


/* Macros for bin_luac.c */
#define LUAC_HDR_SIZE_54 sizeof(luacHdr54)

/* luac 5.4 spec */
RZ_PACKED(
        typedef struct {
            ut8 signature[4]; /* == '.Lua' */
            ut8 version;      /* version of luac */
            ut8 format;       /* 1 if it's modified luac */

            ut8 luac_data[6];               /* luac data for error detection */
            ut8 instruction_size;
            ut8 integer_size;
            ut8 number_size;

            ut8 integer_valid_data[8];        /* test integer data loading */
            ut8 number_valid_data[8];         /* test number data loading */

            ut8 upvalues_number;            /* number of upvalue arrays */
        }) luacHdr54;


/* Exported Api to bin_luac.c */
RzBinInfo *info_54(RzBinFile *bf, int major, int minor);

#endif //BUILD_LUAC_54_H
