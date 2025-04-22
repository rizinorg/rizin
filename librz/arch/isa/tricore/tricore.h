// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <capstone.h>

#ifndef RZ_TRICORE_H
#define RZ_TRICORE_H

typedef struct {
	csh h;
	cs_mode mode;
	cs_insn *insn;
	ut32 count;
	ut32 word;
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns;
} RzAsmTriCoreContext;

#endif // RZ_TRICORE_H
