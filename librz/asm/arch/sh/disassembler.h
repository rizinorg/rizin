// SPDX-FileCopyrightText: 2022 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_SH_DISASSEMBLER_H
#define RZ_ASM_SH_DISASSEMBLER_H
#include <rz_types.h>
#include <rz_util.h>

typedef enum {
	SH_OP_INVALID = 0,
	SH_OP_MOV,
    /* end */
    SH_OP_SIZE
} SHOpMnem;


typedef struct sh_opcode_t {
	SHOpMnem mnemonic;
	ut16 mask;
	ut16 param[4];
	ut16 cycles;
	ut16 size;
} SHOp;

ut32 sh_disassembler(const ut8 *buffer, const ut32 size, ut64 pc, bool be, SHOp* aop, RzStrBuf *sb);

#endif /* RZ_ASM_AVR_DISASSEMBLER_H */
