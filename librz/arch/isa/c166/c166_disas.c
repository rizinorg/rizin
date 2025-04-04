// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file c166_disas.c
 * \brief C166 disassembler implementation
 *
 * Core disassembler implementation for the C166 microcontroller architecture.
 * Converts machine code bytes into human-readable assembly language strings.
 */

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <string.h>

#include "c166_ops.h"

// C166 register names for display in disassembly
static const char *c166_reg_names[] = {
    "R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
    "RL0", "RH0", "RL1", "RH1", "RL2", "RH2", "RL3", "RH3", 
    "RL4", "RH4", "RL5", "RH5", "RL6", "RH6", "RL7", "RH7",
    "IP", "SP", "PSW", "CSP", "MDL", "MDH", "MDC", 
    "STKOV", "STKUN", "CPUCON1", "CPUCON2", "VECSEG", "SPSEG", "CP"
};

// C166 condition code names
static const char *c166_cc_names[] = {
    "cc_UC", "cc_Z", "cc_NZ", "cc_V", "cc_NV", "cc_N", "cc_NN", "cc_C",
    "cc_NC", "cc_EQ", "cc_NE", "cc_ULT", "cc_ULE", "cc_UGE", "cc_UGT",
    "cc_SLT", "cc_SLE", "cc_SGE", "cc_SGT", "cc_NET"
};

/**
 * \brief Find opcode info from opcode value
 * \param opcode Opcode byte from instruction
 * \return Pointer to C166OpInfo structure or NULL if not found
 *
 * Searches the opcode tables to find matching instruction information
 * for the given opcode byte.
 */
static const C166OpInfo *get_opcode_info(ut8 opcode) {
    int i = 0;
    while (c166_opcodes[i].mnemonic) {
        if ((opcode & ~c166_opcodes[i].mask) == (c166_opcodes[i].opcode & ~c166_opcodes[i].mask)) {
            return &c166_opcodes[i];
        }
        i++;
    }
    return NULL;
}


/**
 * \brief Disassemble address mode for an operand
 * \param str Output buffer to store the result
 * \param str_size Size of the output buffer
 * \param mode Address mode to disassemble
 * \param buf Buffer containing instruction bytes
 * \param pos Position in buffer to read from
 * \param pc Program counter address
 *
 * Formats an operand according to the specified addressing mode.
 * Handles different C166 addressing modes like register, immediate,
 * direct, indirect, and relative addressing.
 */
static void disassemble_addr_mode(char *str, size_t str_size, C166AddrMode mode, 
                                 const ut8 *buf, int pos, ut64 pc) {
    switch (mode) {
        case C166_ADDR_REG:
            snprintf(str, str_size, "%s", c166_reg_names[buf[pos] & 0x0F]);
            break;
        case C166_ADDR_IMM:
            // Immediate value
            if (buf[0] < 0x08) {
                snprintf(str, str_size, "#0x%04x", (buf[pos] << 8) | buf[pos+1]);
            } else {
                snprintf(str, str_size, "#0x%02x", buf[pos]);
            }
            break;
        case C166_ADDR_DIR:
            // Direct memory addressing
            snprintf(str, str_size, "0x%02x", buf[pos]);
            break;
        case C166_ADDR_INDIRECT:
            // @Rn notation
            snprintf(str, str_size, "@%s", c166_reg_names[buf[pos] & 0x0F]);
            break;
        case C166_ADDR_POSTINC:
            // [Rn+] notation
            snprintf(str, str_size, "[%s+]", c166_reg_names[buf[pos] & 0x0F]);
            break;
        case C166_ADDR_PREDEC:
            // [-Rn] notation
            snprintf(str, str_size, "[-R%d]", buf[pos] & 0x0F);
            break;
        case C166_ADDR_OFFSET:
            // [Rn + #data16] notation
            snprintf(str, str_size, "[%s+#0x%04x]", 
                     c166_reg_names[buf[pos] & 0x0F], 
                     (buf[pos+1] << 8) | buf[pos+2]);
            break;
        case C166_ADDR_RELATIVE:
            // Relative address for jumps
            {
                ut64 target = c166_addr_relative(pc + 2, buf[pos]);
                snprintf(str, str_size, "0x%04" PFMT64x, target);
            }
            break;
        case C166_ADDR_BITADDR:
            // Bit addressing mode
            snprintf(str, str_size, "0x%02x.%d", buf[pos], buf[pos] & 0x07);
            break;
        case C166_ADDR_BITOFF:
            // Bit offset addressing
            snprintf(str, str_size, "0x%02x.%d", buf[pos], buf[0] & 0x0F);
            break;
        case C166_ADDR_SEG:
            // Segment address
            snprintf(str, str_size, "0x%02x", buf[pos]);
            break;
        case C166_ADDR_CADDR:
            // Code address
            snprintf(str, str_size, "0x%04x", (buf[pos] << 8) | buf[pos+1]);
            break;
        case C166_ADDR_NONE:
        default:
            str[0] = '\0';
            break;
    }
}

/**
 * \brief Disassemble C166 instruction to a human-readable string
 * \param pc Program counter address of the instruction
 * \param buf Buffer containing instruction bytes
 * \param len Length of the buffer
 * \param olen Pointer to store the size of the disassembled instruction
 * \return Allocated string containing disassembled instruction or NULL on failure
 *
 * Core disassembly function for C166 instructions. Parses opcode bytes,
 * identifies instruction type and addressing modes, and formats them into
 * a human-readable assembly representation. The caller is responsible for
 * freeing the returned string with free().
 */
RZ_API char *rz_c166_disas(ut64 pc, const ut8 *buf, int len, int *olen) {
    if (!buf || len < 1) {
        if (olen) {
            *olen = 0;
        }
        return NULL;
    }
    
    // Find opcode info
    const C166OpInfo *op_info = get_opcode_info(buf[0]);
    if (!op_info || !op_info->mnemonic) {
        if (olen) {
            *olen = 0;
        }
        return NULL;
    }
    
    // Check if we have enough bytes for this instruction
    if (len < op_info->size) {
        if (olen) {
            *olen = -1; // Not enough data
        }
        return rz_str_dup("truncated");
    }
    
    // Set output length
    if (olen) {
        *olen = op_info->size;
    }
    
    // Handle special cases for each instruction type
    char disasm[64] = {0};
    char op1[32] = {0};
    char op2[32] = {0};
    char op3[32] = {0};
    
    // Disassemble operands if they exist
    if (op_info->addr_mode1 != C166_ADDR_NONE) {
        disassemble_addr_mode(op1, sizeof(op1), op_info->addr_mode1, buf, 1, pc);
    }
    
    if (op_info->addr_mode2 != C166_ADDR_NONE) {
        disassemble_addr_mode(op2, sizeof(op2), op_info->addr_mode2, buf, 
                             op_info->addr_mode1 != C166_ADDR_NONE ? 2 : 1, pc);
    }
    
    if (op_info->addr_mode3 != C166_ADDR_NONE) {
        disassemble_addr_mode(op3, sizeof(op3), op_info->addr_mode3, buf, 
                             (op_info->addr_mode1 != C166_ADDR_NONE ? 1 : 0) + 
                             (op_info->addr_mode2 != C166_ADDR_NONE ? 1 : 0) + 1, pc);
    }
    
    // Special case for JMPR with condition codes
    if (op_info->type == C166_OP_JMPR) {
        // Calculate index into condition code table
        int cc_idx = (buf[0] - 0x0D) / 16;
        if (cc_idx >= 0 && cc_idx < sizeof(c166_cc_jmpr_map)/sizeof(C166CondCode)) {
            C166CondCode cc = c166_cc_jmpr_map[cc_idx];
            snprintf(disasm, sizeof(disasm), "%s %s, %s", op_info->mnemonic, 
                    c166_cc_names[cc], op1);
        } else {
            snprintf(disasm, sizeof(disasm), "%s %s", op_info->mnemonic, op1);
        }
    } else {
        // Regular instruction formatting
        if (op_info->addr_mode1 == C166_ADDR_NONE) {
            // No operands
            snprintf(disasm, sizeof(disasm), "%s", op_info->mnemonic);
        } else if (op_info->addr_mode2 == C166_ADDR_NONE) {
            // One operand
            snprintf(disasm, sizeof(disasm), "%s %s", op_info->mnemonic, op1);
        } else if (op_info->addr_mode3 == C166_ADDR_NONE) {
            // Two operands
            snprintf(disasm, sizeof(disasm), "%s %s, %s", op_info->mnemonic, op1, op2);
        } else {
            // Three operands
            snprintf(disasm, sizeof(disasm), "%s %s, %s, %s", op_info->mnemonic, op1, op2, op3);
        }
    }
    
    return rz_str_dup(disasm);
}
