#ifndef C55PLUS_H
#define C55PLUS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>

#include "../tms320_p.h"
#include "../tms320_dasm.h"

extern int c55x_plus_disassemble(tms320_dasm_t *dasm, const ut8 *buf, int len);

#endif
