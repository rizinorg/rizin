#ifndef BINUTILS_AS_H
#define BINUTILS_AS_H

#include <rz_types.h>
#include <rz_asm.h>

int binutils_assemble(RzAsm *a, RzAsmOp *op, const char *buf, const char *as, const char *env, const char *header, const char *cmd_opt);

#endif
