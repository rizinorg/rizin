//
// Created by heersin on 2/28/21.
//

#ifndef BUILD_LUAC_SPECS_H
#define BUILD_LUAC_SPECS_H

/* Macros/Typedefs used in luac */
typedef	double LUA_NUMBER;


/* Macro Functions */
/* type casts (a macro highlights casts in the code) */
#define cast(t, exp)	((t)(exp))
#define cast_num(i)	cast(LUA_NUMBER, (i))


/* Macros About Luac Format */
#define LUAC_MAGIC "\x1b\x4c\x75\x61"
#define LUAC_FORMAT 0           /* this is the official format */
#define LUAC_DATA "\x19\x93\r\n\x1a\n"
#define LUAC_INT_VALIDATION 0x5678
#define LUAC_NUMBER_VALIDATION cast_num(370.5)


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

            ut64 integer_valid_data;        /* test integer data loading */
            ut64 number_valid_data;         /* test number data loading */

            ut8 upvalues_number;            /* number of upvalue arrays */
        }) luac_hdr;



#endif //BUILD_LUAC_SPECS_H
