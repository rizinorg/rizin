//
// Created by heersin on 2/28/21.
//

#ifndef BUILD_LUAC_SPECS_H
#define BUILD_LUAC_SPECS_H

#define LUAC_MAGIC "\x1b\x4c\x75\x61"

/* Valid for luac5.4 and previous versions */
typedef struct {
    ut8 signature[4]; /* == '.Lua' */
    ut8 version;      /* version of luac */
    ut8 format;       /* 1 if it's modified luac */
} LUAC_common_header;

/* luac 5.4 spec */
typedef struct {
    LUAC_common_header common_hdr;
    ut8 luac_data[6];               /* luac data for error detection */
    ut8 instruction_size;
    ut8 integer_size;
    ut8 number_size;

    ut64 integer_valid_data;        /* test integer data loading */
    ut64 number_valid_data;         /* test number data loading */

    ut8 upvalues_number;            /* number of upvalue arrays */
};

#endif //BUILD_LUAC_SPECS_H
