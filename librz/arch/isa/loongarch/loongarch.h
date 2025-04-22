// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <capstone.h>

#ifndef RZ_LOONGARCH_H
#define RZ_LOONGARCH_H

#include <capstone/capstone.h>
#include <capstone/loongarch.h>

typedef struct {
	csh h;
	cs_mode mode;
	cs_insn *insn;
	ut32 count;
	ut32 word;
	RzPVector /*<RzAsmTokenPattern *>*/ *token_patterns;
} RzAsmLoongArchContext;

#endif // RZ_LOONGARCH_H
