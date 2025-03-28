// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (C) 2025 Rizin

#include <rz_types.h>
#include <rz_util.h>
#include "vax.h"

static const char *reg_names[] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "ap", "fp", "sp", "pc"
};

int vax_disassemble(RzStrBuf *sb, const ut8 *buf, int len, ut64 addr) {
    if (len < 1) return -1;

    // Handle 1-byte opcodes for now
    unsigned int opcode = buf[0];
    int opcode_len = 1;

    // Find the opcode in the table
    const vax_instruction *insn = vax_instructions;
    while (insn->name) {
        if (insn->opcode == opcode) break;
        insn++;
    }

    if (!insn->name) {
        rz_strbuf_set(sb, "invalid");
        return opcode_len;
    }

    // Print the instruction name
    rz_strbuf_setf(sb, "%s", insn->name);

    // Process operands based on args
    if (insn->args[0]) {
        const ut8 *p = buf + opcode_len;
        int arg_idx = 0;
        while (insn->args[arg_idx]) {
            if (arg_idx > 0) rz_strbuf_append(sb, ", ");
            char mode = p[0];
            p++;
            ut8 reg = mode & 0xF;

            if (strcmp(insn->name, "brb") == 0) {
                // BRB: 1-byte displacement
                ut8 disp = p[0];
                p++;
                rz_strbuf_appendf(sb, "0x%llx", addr + 2 + (st8)disp);
            } else {
                // Register mode (e.g., 0x50 for R0)
                if ((mode & 0xF0) == 0x50) {
                    rz_strbuf_appendf(sb, "%s", reg_names[reg]);
                } else {
                    rz_strbuf_append(sb, "???");
                }
            }
            arg_idx++;
        }
        opcode_len = p - buf;
    }

    return opcode_len;
}
