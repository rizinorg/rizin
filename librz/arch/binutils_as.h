// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef BINUTILS_AS_H
#define BINUTILS_AS_H

#include <rz_types.h>
#include <rz_asm.h>

int binutils_assemble(RzAsm *a, RzAsmOp *op, const char *buf, const char *as, const char *env, const char *header, const char *cmd_opt);

#endif
