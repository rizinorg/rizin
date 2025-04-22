// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_JAVA_ASSEMBLER_H
#define RZ_ASM_JAVA_ASSEMBLER_H
#include <rz_types.h>
#include <rz_util.h>
#include "bytecode.h"

bool java_assembler(const char *input, st32 input_size, ut8 *output, st32 output_size, ut64 pc, st32 *written);

#endif /* RZ_ASM_JAVA_ASSEMBLER_H */
