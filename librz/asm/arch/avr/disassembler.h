// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_AVR_DISASSEMBLER_H
#define RZ_ASM_AVR_DISASSEMBLER_H
#include <rz_types.h>
#include <rz_util.h>

ut32 avr_disassembler(const ut8 *buffer, const ut32 size, ut64 pc, bool be, RzStrBuf *sb);

#endif /* RZ_ASM_AVR_DISASSEMBLER_H */
