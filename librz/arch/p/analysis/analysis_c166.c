// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>

// C166 Instruction Analysis
typedef struct {
    ut16 opcode;
    ut16 mask;
    _RzAnalysisOpType type;
    bool jump;
    bool call;
    bool branch;
    int cycles;
} C166OpcodeAnalysis;


static const C166OpcodeAnalysis c166_opcode_analysis[] = {
    {0x00, 0xF0, RZ_ANALYSIS_OP_TYPE_ADD, false, false, false, 1},  // ADD
    {0x10, 0xF0, RZ_ANALYSIS_OP_TYPE_ADD, false, false, false, 1},  // ADDC
    {0x20, 0xF0, RZ_ANALYSIS_OP_TYPE_SUB, false, false, false, 1},  // SUB
    {0x30, 0xF0, RZ_ANALYSIS_OP_TYPE_SUB, false, false, false, 1},  // SUBC
    {0x40, 0xF0, RZ_ANALYSIS_OP_TYPE_CMP, false, false, false, 1},  // CMP
    {0x50, 0xF0, RZ_ANALYSIS_OP_TYPE_XOR, false, false, false, 1},  // XOR
    {0x60, 0xF0, RZ_ANALYSIS_OP_TYPE_AND, false, false, false, 1},  // AND
    {0x70, 0xF0, RZ_ANALYSIS_OP_TYPE_OR, false, false, false, 1},   // OR
    {0xE0, 0xF0, RZ_ANALYSIS_OP_TYPE_MOV, false, false, false, 1},  // MOV Rw, #data4
    {0xF0, 0xF0, RZ_ANALYSIS_OP_TYPE_MOV, false, false, false, 1},  // MOV Rw, Rw
    {0x0D, 0xFF, RZ_ANALYSIS_OP_TYPE_JMP, true, false, false, 2},   // JMPR cc_UC, rel
    {0xEA, 0xFF, RZ_ANALYSIS_OP_TYPE_JMP, true, false, false, 2},   // JMPA cc_UC, caddr
    {0x8D, 0xFF, RZ_ANALYSIS_OP_TYPE_CJMP, true, false, true, 2},   // JMPR.C cc_C, rel
    {0xCA, 0xFF, RZ_ANALYSIS_OP_TYPE_CALL, true, true, false, 5},   // CALLA cc_UC, caddr
    {0xBB, 0xFF, RZ_ANALYSIS_OP_TYPE_CALL, true, true, false, 4},   // CALLR rel
    {0xCB, 0xFF, RZ_ANALYSIS_OP_TYPE_RET, false, false, false, 4},  // RET
    {0xFB, 0xFF, RZ_ANALYSIS_OP_TYPE_RET, false, false, false, 6},  // RETI
    {0x0E, 0xFF, RZ_ANALYSIS_OP_TYPE_AND, false, false, false, 2},  // BCLR
    {0x0F, 0xFF, RZ_ANALYSIS_OP_TYPE_OR, false, false, false, 2},   // BSET
    {0, 0, 0, false, false, false, 0}
};

static ut64 calc_rel_jump(ut64 addr, int len, int8_t offset) {
    return addr + len + offset;
}

static int c166_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
    if (len < 2) {
        return 0;
    }
    
    memset(op, 0, sizeof(RzAnalysisOp));
    op->addr = addr;
    op->type = RZ_ANALYSIS_OP_TYPE_UNK;
    op->size = 2; // Default size
    
    ut16 insn = rz_read_le16(buf);
    
    for (int i = 0; c166_opcode_analysis[i].mask != 0; i++) {
        if ((insn & c166_opcode_analysis[i].mask) == c166_opcode_analysis[i].opcode) {
            op->type = c166_opcode_analysis[i].type;
            op->cycles = c166_opcode_analysis[i].cycles;
            
            // For 4-byte instructions
            if (c166_opcode_analysis[i].opcode == 0xEA || c166_opcode_analysis[i].opcode == 0xCA) { 
                if (len >= 4) {
                    op->size = 4;
                    ut16 target_addr = rz_read_le16(buf + 2);
                    op->jump = target_addr;
                    
                    if (c166_opcode_analysis[i].type == RZ_ANALYSIS_OP_TYPE_CJMP) {
                        op->fail = addr + 4;
                    }
                }
            }
            // For relative jumps/calls
            else if (c166_opcode_analysis[i].opcode == 0x0D || c166_opcode_analysis[i].opcode == 0x8D || c166_opcode_analysis[i].opcode == 0xBB) {
                int8_t offset = (int8_t)(insn & 0xFF);
                op->jump = calc_rel_jump(addr, 2, offset);
                
                if (c166_opcode_analysis[i].type == RZ_ANALYSIS_OP_TYPE_CJMP) {
                    op->fail = addr + 2;
                }
            }
            
            // For stack operations
            if (c166_opcode_analysis[i].opcode == 0xBB || c166_opcode_analysis[i].opcode == 0xCA) {
                op->stackop = RZ_ANALYSIS_STACK_INC;
                op->stackptr = 4; 
            } else if (c166_opcode_analysis[i].opcode == 0xCB || c166_opcode_analysis[i].opcode == 0xFB) {
                op->stackop = RZ_ANALYSIS_STACK_INC;
                op->stackptr = -4; 
            }
            
            return op->size;
        }
    }
    
    return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
    const char *p = 
        "=PC    pc\n"
        "=SP    sp\n"
        "=BP    r0\n"
        "=A0    r4\n"  
        "=A1    r5\n"   
        "=A2    r6\n"   
        "=A3    r7\n"   
        "=SN    r3\n"   
        "=R0    r4\n"   
        "=R1    r5\n"  

        "gpr    r0      .16     0       0\n"
        "gpr    r1      .16     2       0\n"
        "gpr    r2      .16     4       0\n"
        "gpr    r3      .16     6       0\n"
        "gpr    r4      .16     8       0\n"
        "gpr    r5      .16     10      0\n"
        "gpr    r6      .16     12      0\n"
        "gpr    r7      .16     14      0\n"
        "gpr    r8      .16     16      0\n"
        "gpr    r9      .16     18      0\n"
        "gpr    r10     .16     20      0\n"
        "gpr    r11     .16     22      0\n"
        "gpr    r12     .16     24      0\n"
        "gpr    r13     .16     26      0\n"
        "gpr    r14     .16     28      0\n"
        "gpr    r15     .16     30      0\n"
        
        "gpr    pc      .16     32      0\n"  // Program Counter
        "gpr    sp      .16     34      0\n"  // Stack Pointer
        "gpr    psw     .16     36      0\n"  // Program Status Word
        
        "flg    c       .1      .288    0\n"  // Carry Flag
        "flg    z       .1      .289    0\n"  // Zero Flag
        "flg    v       .1      .290    0\n"  // Overflow Flag
        "flg    n       .1      .291    0\n"  // Negative Flag
        ;
    return rz_str_dup(p);
}

RzAnalysisPlugin rz_analysis_plugin_c166 = {
    .name = "c166",
    .arch = "c166",
    .license = "LGPL3",
    .desc = "Infineon C166 CPU code analysis plugin",
    .bits = 16,
    .op = &c166_op,
    .get_reg_profile = &get_reg_profile,
};