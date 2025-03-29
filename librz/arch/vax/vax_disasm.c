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

    VaxOpcode opcode = (VaxOpcode)buf[0];
    int opcode_len = 1;

    const VaxInstruction *insn = vax_instructions;
    while (insn->opcode != VAX_OP_INVALID) {
        if (insn->opcode == opcode) break;
        insn++;
    }

    if (insn->opcode == VAX_OP_INVALID) {
        rz_strbuf_set(sb, "invalid");
        return opcode_len;
    }

    rz_strbuf_setf(sb, "%s", insn->name);

    if (!insn->args[0]) {
        return opcode_len;
    }

    const ut8 *operand_ptr = buf + opcode_len;
    int arg_idx = 0;
    while (insn->args[arg_idx]) {
        if (arg_idx > 0) rz_strbuf_append(sb, ", ");
        char arg_type = insn->args[arg_idx];
        char mode = operand_ptr[0];
        operand_ptr++;
        ut8 reg = mode & 0xF;

        switch (arg_type) {
        case 'b': // Byte displacement (e.g., brb)
            if (len - opcode_len < 1) return -1; // Check buffer bounds
            {
                ut8 disp = operand_ptr[0];
                operand_ptr++;
                rz_strbuf_appendf(sb, "0x%llx", addr + opcode_len + (st8)disp);
            }
            break;
        case 'r': // Register read
        case 'w': // Register write (treating same for now)
            if (len - opcode_len < 1) return -1; // Check buffer bounds
            if ((mode & 0xF0) == 0x50) { // Register mode
                rz_strbuf_appendf(sb, "%s", reg_names[reg]);
            } else {
                rz_strbuf_append(sb, "???");
            }
            break;
        case 'l': // Long (placeholder, not fully implemented)
            rz_strbuf_append(sb, "???"); // TODO: Implement long operand
            break;
        default:
            rz_strbuf_append(sb, "???");
            break;
        }
        arg_idx++;
        opcode_len = operand_ptr - buf; // Update length inside loop
    }

    return opcode_len;
}