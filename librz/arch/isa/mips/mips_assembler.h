// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef ASSEMBLE_MIPS_H
#define ASSEMBLE_MIPS_H

#include <rz_asm.h>

RZ_IPI int mips_assemble_opcode(const char *str, ut64 pc, ut8 *out);

#endif /* ASSEMBLE_MIPS_H */
