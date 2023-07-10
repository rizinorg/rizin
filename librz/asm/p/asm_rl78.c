// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "../arch/rl78/rl78.h"

static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
        return 0x69;
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
        ut8 instr_bytes[2];

        /* for (int opcode = 0; opcode <= 0xff; opcode++) { */
                instr_bytes[0] = 0x71;
                instr_bytes[1] = 0xd7;

                RL78Instr instr;
                RzStrBuf instr_strbuf;
                size_t bytes_read;

                rl78_dis(&instr, &bytes_read, instr_bytes, sizeof(instr_bytes));
                rl78_instr_to_string(&instr_strbuf, &instr);

                printf("%s\n", instr_strbuf.buf);
        /* } */

        return 0;
}

RzAsmPlugin rz_asm_plugin_rl78 = {
        .name = "rl78",
        .arch = "rl78",
        .desc = "Renesas RL78 disassembler",
        .author = "Bastian Engel",
        .license = "LGPL3",
        .bits = 32,
        .endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
        .assemble = &assemble,
        .disassemble = &disassemble
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
        .type = RZ_LIB_TYPE_ASM,
        .data = &rz_asm_plugin_rl78,
        .version = RZ_VERSION
};
#endif
