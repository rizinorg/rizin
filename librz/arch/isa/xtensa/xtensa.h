// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RIZIN_XTENSA_H
#define RIZIN_XTENSA_H

#include <capstone/capstone.h>
#include <rz_asm.h>

typedef struct xtensa_context_t {
	csh handle;
	cs_insn *insn;
	size_t count;
} XtensaContext;

bool xtensa_init(void **user);
bool xtensa_fini(void *user);
bool xtensa_open(XtensaContext *ctx, const char *cpu, bool big_endian);
bool xtensa_disassemble(XtensaContext *self, const ut8 *buf, int len, ut64 addr);
void xtensa_disassemble_fini(XtensaContext *self);

#endif // RIZIN_XTENSA_H
