// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _C166_DISAS_H
#define _C166_DISAS_H

#include <rz_types.h>
#include <rz_lib.h>

/**
 * Disassemble C166 instruction
 *
 * @param pc Program counter address
 * @param buf Buffer containing instruction bytes
 * @param len Length of buffer
 * @param olen Output parameter for instruction length
 * @return Disassembled instruction string or NULL on error
 */
RZ_API char *rz_c166_disas(ut64 pc, const ut8 *buf, int len, int *olen);

#endif /* _C166_DISAS_H */