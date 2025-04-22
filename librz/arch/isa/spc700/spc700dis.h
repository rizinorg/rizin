// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DISASSEMBLE_SPC700_H
#define DISASSEMBLE_SPC700_H

#include <rz_asm.h>

size_t spc700_disas(RzStrBuf *out, ut64 pc, const ut8 *buf, size_t bufsz);

#endif /* DISASSEMBLE_SPC700_H */
