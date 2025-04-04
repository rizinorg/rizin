// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

#include "librz/arch/isa/c166/c166_ops.h"
#include "librz/arch/isa/c166/c166_disas.h"

/**
 * \file analysis_c166.c
 * \brief C166 architecture analysis plugin implementation
 *
 * Provides analysis capabilities for the Infineon C166 microcontroller architecture,
 * including operation type identification, control flow analysis, and register profiles.
 */

/**
 * C166 plugin context structure for storing architecture-specific data
 */

typedef struct {
    const char *cpu_model;
} c166_plugin_context;


/**
 * \brief C166 analysis operation function
 * \param analysis Pointer to RzAnalysis structure
 * \param op Pointer to RzAnalysisOp structure to be filled with analysis data
 * \param addr Current address being analyzed
 * \param buf Buffer containing bytes to be analyzed
 * \param len Length of the buffer
 * \param mask Analysis operation mask
 * \return Size of the analyzed opcode or 0 on failure
 *
 * Analyzes a C166 instruction at the given address. This function determines
 * the instruction type, operands, and control flow information such as jump
 * targets or call destinations. It populates the provided RzAnalysisOp structure
 * with this information for use by Rizin's analysis engine.
 */

static int c166_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
    if (!buf || len < 1) {
        return 0;
    }
    
    memset(op, 0, sizeof(RzAnalysisOp));
    
    // Find opcode info
    const C166OpInfo *op_info = NULL;
    int i = 0;
    while (c166_opcodes[i].mnemonic) {
        if ((buf[0] & ~c166_opcodes[i].mask) == (c166_opcodes[i].opcode & ~c166_opcodes[i].mask)) {
            op_info = &c166_opcodes[i];
            break;
        }
        i++;
    }
    
    if (!op_info || !op_info->mnemonic) {
        return 0;
    }
    
    // Check if we have enough bytes for this instruction
    if (len < op_info->size) {
        return 0;
    }
    
    op->size = op_info->size;
    op->addr = addr;
    op->type = RZ_ANALYSIS_OP_TYPE_UNK;  
    op->id = buf[0];
    
    // Set basic op type based on instruction type
    switch (op_info->type) {
        // Arithmetic operations
        case C166_OP_ADD:
        case C166_OP_ADDB:
        case C166_OP_ADDC:
        case C166_OP_ADDCB:
            op->type = RZ_ANALYSIS_OP_TYPE_ADD;
            break;
        case C166_OP_SUB:
        case C166_OP_SUBB:
        case C166_OP_SUBC:
        case C166_OP_SUBCB:
        case C166_OP_NEG:
        case C166_OP_NEGB:
            op->type = RZ_ANALYSIS_OP_TYPE_SUB;
            break;
        case C166_OP_MUL:
        case C166_OP_MULU:
            op->type = RZ_ANALYSIS_OP_TYPE_MUL;
            break;
        case C166_OP_DIV:
        case C166_OP_DIVL:
        case C166_OP_DIVLU:
        case C166_OP_DIVU:
            op->type = RZ_ANALYSIS_OP_TYPE_DIV;
            break;
            
        // Logical operations
        case C166_OP_AND:
        case C166_OP_ANDB:
            op->type = RZ_ANALYSIS_OP_TYPE_AND;
            break;
        case C166_OP_OR:
        case C166_OP_ORB:
            op->type = RZ_ANALYSIS_OP_TYPE_OR;
            break;
        case C166_OP_XOR:
        case C166_OP_XORB:
            op->type = RZ_ANALYSIS_OP_TYPE_XOR;
            break;
        case C166_OP_CPL:
        case C166_OP_CPLB:
            op->type = RZ_ANALYSIS_OP_TYPE_NOT;
            break;
            
        // Comparison operations
        case C166_OP_CMP:
        case C166_OP_CMPB:
        case C166_OP_CMPD1:
        case C166_OP_CMPD2:
        case C166_OP_CMPI1:
        case C166_OP_CMPI2:
            op->type = RZ_ANALYSIS_OP_TYPE_CMP;
            break;
            
        // Bit operations
        case C166_OP_BCLR:
        case C166_OP_BSET:
        case C166_OP_BMOV:
        case C166_OP_BMOVN:
        case C166_OP_BAND:
        case C166_OP_BOR:
        case C166_OP_BXOR:
        case C166_OP_BCMP:
        case C166_OP_BFLDH:
        case C166_OP_BFLDL:
            op->type = RZ_ANALYSIS_OP_TYPE_MOD;
            break;
            
        // Shift operations
        case C166_OP_SHL:
            op->type = RZ_ANALYSIS_OP_TYPE_SHL;
            break;
        case C166_OP_SHR:
        case C166_OP_ASHR:
            op->type = RZ_ANALYSIS_OP_TYPE_SHR;
            break;
        case C166_OP_ROL:
            op->type = RZ_ANALYSIS_OP_TYPE_ROL;
            break;
        case C166_OP_ROR:
            op->type = RZ_ANALYSIS_OP_TYPE_ROR;
            break;
            
        // Data movement operations
        case C166_OP_MOV:
        case C166_OP_MOVB:
        case C166_OP_MOVBS:
        case C166_OP_MOVBZ:
            op->type = RZ_ANALYSIS_OP_TYPE_MOV;
            break;
        case C166_OP_PUSH:
            op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
            break;
        case C166_OP_POP:
            op->type = RZ_ANALYSIS_OP_TYPE_POP;
            break;
        case C166_OP_SCXT:
            op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
            break;
            
        // Jump operations
        case C166_OP_JMP:
        case C166_OP_JMPA:
        case C166_OP_JMPI:
        case C166_OP_JMPR:
        case C166_OP_JMPS:
            op->type = RZ_ANALYSIS_OP_TYPE_JMP;
            // Handle jump targets
            if (op_info->addr_mode1 == C166_ADDR_RELATIVE) {
                // Relative jump
                st8 offset = (st8)buf[1];
                op->jump = addr + op->size + offset;
                op->fail = addr + op->size;
            } else if (op_info->addr_mode1 == C166_ADDR_CADDR) {
                // Absolute jump
                op->jump = (buf[1] << 8) | buf[2];
                op->fail = addr + op->size;
            }
            break;
            
        case C166_OP_JB:
        case C166_OP_JBC:
        case C166_OP_JNB:
        case C166_OP_JNBS:
            op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
            if (len >= 4) {
                // Last byte is relative offset
                st8 offset = (st8)buf[3];
                op->jump = addr + op->size + offset;
                op->fail = addr + op->size;
            }
            break;
            
        // Call operations
        case C166_OP_CALL:
        case C166_OP_CALLA:
        case C166_OP_CALLI:
        case C166_OP_CALLR:
        case C166_OP_CALLS:
        case C166_OP_PCALL:
            op->type = RZ_ANALYSIS_OP_TYPE_CALL;
            if (op_info->addr_mode1 == C166_ADDR_RELATIVE) {
                // Relative call
                st8 offset = (st8)buf[1];
                op->jump = addr + op->size + offset;
                op->fail = addr + op->size;
            } else if (op_info->addr_mode1 == C166_ADDR_CADDR) {
                // Absolute call
                op->jump = (buf[1] << 8) | buf[2];
                op->fail = addr + op->size;
            }
            break;
            
        // Return operations
        case C166_OP_RET:
        case C166_OP_RETS:
        case C166_OP_RETP:
            op->type = RZ_ANALYSIS_OP_TYPE_RET;
            break;
        case C166_OP_RETI:
            op->type = RZ_ANALYSIS_OP_TYPE_RET | RZ_ANALYSIS_OP_TYPE_TRAP;
            break;
            
        // System operations
        case C166_OP_TRAP:
            op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
            break;
        case C166_OP_NOP:
            op->type = RZ_ANALYSIS_OP_TYPE_NOP;
            break;
        case C166_OP_SRST:
            op->type = RZ_ANALYSIS_OP_TYPE_SWI;
            break;
            
        default:
            op->type = RZ_ANALYSIS_OP_TYPE_UNK;
            break;
    }
    
    // Get disassembly if requested
    if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
        int olen = 0;
        op->mnemonic = rz_c166_disas(addr, buf, len, &olen);
        if (olen != op->size) {
            op->size = olen > 0 ? olen : 0;
        }
    }
    
    return op->size;
}

/**
 * \brief Get register profile for C166
 * \param analysis Pointer to RzAnalysis structure
 * \return String containing register profile definition for C166
 *
 * Returns a string describing the CPU registers of the C166 architecture.
 * This includes general purpose registers, segment registers, and flags.
 * The format follows Rizin's register profile specification.
 */

static char *get_reg_profile(RzAnalysis *analysis) {
    const char *p =
        "=PC    ip\n"
        "=SP    sp\n"
        "=BP    cp\n"
        "=A0    r0\n"
        "=A1    r1\n"
        "=A2    r2\n"
        "=A3    r3\n"
        "gpr    r0      .16 0   0\n"
        "gpr    r1      .16 2   0\n"
        "gpr    r2      .16 4   0\n"
        "gpr    r3      .16 6   0\n"
        "gpr    r4      .16 8   0\n"
        "gpr    r5      .16 10  0\n"
        "gpr    r6      .16 12  0\n"
        "gpr    r7      .16 14  0\n"
        "gpr    r8      .16 16  0\n"
        "gpr    r9      .16 18  0\n"
        "gpr    r10     .16 20  0\n"
        "gpr    r11     .16 22  0\n"
        "gpr    r12     .16 24  0\n"
        "gpr    r13     .16 26  0\n"
        "gpr    r14     .16 28  0\n"
        "gpr    r15     .16 30  0\n"
        "gpr    rl0     .8  0   0\n"
        "gpr    rh0     .8  1   0\n"
        "gpr    rl1     .8  2   0\n"
        "gpr    rh1     .8  3   0\n"
        "gpr    rl2     .8  4   0\n"
        "gpr    rh2     .8  5   0\n"
        "gpr    rl3     .8  6   0\n"
        "gpr    rh3     .8  7   0\n"
        "gpr    rl4     .8  8   0\n"
        "gpr    rh4     .8  9   0\n"
        "gpr    rl5     .8  10  0\n"
        "gpr    rh5     .8  11  0\n"
        "gpr    rl6     .8  12  0\n"
        "gpr    rh6     .8  13  0\n"
        "gpr    rl7     .8  14  0\n"
        "gpr    rh7     .8  15  0\n"
        "gpr    ip      .16 32  0\n"
        "gpr    sp      .16 34  0\n"
        "gpr    psw     .16 36  0\n"
        "flg    cy      .1  36.0  0\n"
        "flg    ac      .1  36.1  0\n"
        "flg    v       .1  36.2  0\n"
        "flg    z       .1  36.3  0\n"
        "flg    n       .1  36.4  0\n"
        "flg    e       .1  36.5  0\n"
        "flg    usr0    .1  36.6  0\n"
        "flg    usr1    .1  36.7  0\n"
        "flg    ien     .1  36.8  0\n"
        "flg    bank    .2  36.12 0\n"
        "gpr    csp     .8  38   0\n"
        "gpr    mdl     .16 40   0\n"
        "gpr    mdh     .16 42   0\n"
        "gpr    mdc     .16 44   0\n"
        "gpr    stkov   .16 46   0\n"
        "gpr    stkun   .16 48   0\n"
        "gpr    cpucon1 .16 50   0\n"
        "gpr    cpucon2 .16 52   0\n"
        "gpr    vecseg  .8  54   0\n"
        "gpr    spseg   .8  55   0\n"
        "gpr    cp      .16 56   0\n";
    return rz_str_dup(p);
}

/**
 * \brief Initialize plugin context for C166 architecture
 * \param user Pointer to store the allocated context
 * \return true on successful initialization, false on failure
 *
 * Allocates and initializes a new context for the C166 plugin.
 * Sets default CPU model and other architecture-specific configuration.
 */

static bool c166_init(void **user) {
    c166_plugin_context *ctx = RZ_NEW0(c166_plugin_context);
    if (!ctx) {
        return false;
    }
    ctx->cpu_model = "c166-generic";
    *user = ctx;
    return true;
}

/**
 * \brief Free plugin context for C166 architecture
 * \param user Pointer to the plugin context
 * \return true on successful cleanup, false on failure
 *
 * Frees resources allocated by the C166 plugin context.
 */
static bool c166_fini(void *user) {
    c166_plugin_context *ctx = (c166_plugin_context *)user;
    if (ctx) {
        // Free any allocated resources in context
        free(ctx);
    }
    return true;
}

RzAnalysisPlugin rz_analysis_plugin_c166 = {
    .name = "c166",
    .desc = "Infineon C166 microcontroller analysis plugin",
    .license = "LGPL3",
    .arch = "c166",
    .bits = 16,
    .op = &c166_op,
    .get_reg_profile = &get_reg_profile,
    .init = &c166_init,
    .fini = &c166_fini,
};
