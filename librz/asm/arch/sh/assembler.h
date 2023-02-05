// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SH_ASSEMBLER_H
#define RZ_SH_ASSEMBLER_H

#include "common.h"
#include "disassembler.h"

RZ_IPI ut16 sh_assembler(RZ_NONNULL const char *buffer, ut64 pc, RZ_NULLABLE bool *success);

#endif // RZ_SH_ASSEMBLER_H
