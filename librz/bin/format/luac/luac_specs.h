//
// Created by heersin on 2/28/21.
// put common definition of luac
//

#ifndef BUILD_LUAC_SPECS_H
#define BUILD_LUAC_SPECS_H

#include <rz_bin.h>
#include <rz_lib.h>

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






#endif //BUILD_LUAC_SPECS_H
