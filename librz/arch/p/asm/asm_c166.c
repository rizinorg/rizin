// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>

typedef struct {
    ut16 opcode;
    ut16 mask;
    const char *mnemonic;
    int length;    // Instruction length in bytes
    const char *format;
} C166Opcode;

static const C166Opcode c166_opcodes[] = {
    {0x00, 0xF0, "add", 2, "Rw, Rw"},
    {0x10, 0xF0, "addc", 2, "Rw, Rw"},
    {0x20, 0xF0, "sub", 2, "Rw, Rw"},
    {0x30, 0xF0, "subc", 2, "Rw, Rw"},
    {0x40, 0xF0, "cmp", 2, "Rw, Rw"},
    {0x50, 0xF0, "xor", 2, "Rw, Rw"},
    {0x60, 0xF0, "and", 2, "Rw, Rw"},
    {0x70, 0xF0, "or", 2, "Rw, Rw"},
    {0xE0, 0xF0, "mov", 2, "Rw, #data4"},
    {0xF0, 0xF0, "mov", 2, "Rw, Rw"},
    {0x0D, 0xFF, "jmpr", 2, "rel"},
    {0xEA, 0xFF, "jmpa", 4, "caddr"},
    {0x8D, 0xFF, "jmpr.c", 2, "rel"},
    {0xCA, 0xFF, "calla", 4, "caddr"},
    {0xBB, 0xFF, "callr", 2, "rel"},
    {0xCB, 0xFF, "ret", 2, ""},
    {0xFB, 0xFF, "reti", 2, ""},
    {0x0E, 0xFF, "bclr", 2, "bitoff"},
    {0x0F, 0xFF, "bset", 2, "bitoff"},
    {0xA0, 0xF0, "push", 2, "Rw"},
    {0xB0, 0xF0, "pop", 2, "Rw"},
    {0xC4, 0xFC, "rol", 2, "Rw, #N"},
    {0xC0, 0xFC, "ror", 2, "Rw, #N"},
    {0, 0, NULL, 0, NULL}
};

static const char* get_register_name(int reg) {
    static char reg_name[8];
    snprintf(reg_name, sizeof(reg_name), "r%d", reg);
    return reg_name;
}

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
    if (len < 2) {
        return 0;
    }
    
    ut16 insn = rz_read_le16(buf);
    
    for (int i = 0; c166_opcodes[i].mnemonic != NULL; i++) {
        if ((insn & c166_opcodes[i].mask) == c166_opcodes[i].opcode) {
            char disasm[64];
            
            if (c166_opcodes[i].length == 2) {
                if (strcmp(c166_opcodes[i].format, "Rw, Rw") == 0) {
                    int reg1 = insn & 0xF;
                    int reg2 = (insn >> 4) & 0xF;
                    snprintf(disasm, sizeof(disasm), "%s %s, %s", 
                            c166_opcodes[i].mnemonic,
                            get_register_name(reg1),
                            get_register_name(reg2));
                } else if (strcmp(c166_opcodes[i].format, "Rw, #data4") == 0) {
                    int reg = insn & 0xF;
                    int imm = (insn >> 4) & 0xF;
                    snprintf(disasm, sizeof(disasm), "%s %s, #0x%x", 
                            c166_opcodes[i].mnemonic,
                            get_register_name(reg),
                            imm);
                } else if (strcmp(c166_opcodes[i].format, "rel") == 0) {
                    int8_t offset = (int8_t)(insn >> 8); 
                    snprintf(disasm, sizeof(disasm), "%s %+d", 
                            c166_opcodes[i].mnemonic,
                            offset);
                } else if (strcmp(c166_opcodes[i].format, "bitoff") == 0) {
                    int bit_pos = insn & 0xF;
                    snprintf(disasm, sizeof(disasm), "%s bitoff.%d", 
                            c166_opcodes[i].mnemonic,
                            bit_pos);
                } else if (strcmp(c166_opcodes[i].format, "Rw") == 0) {
                    int reg = insn & 0xF;
                    snprintf(disasm, sizeof(disasm), "%s %s", 
                            c166_opcodes[i].mnemonic,
                            get_register_name(reg));
                } else if (strcmp(c166_opcodes[i].format, "Rw, #N") == 0) {
                    int reg = insn & 0xF;
                    int count = ((insn >> 4) & 0x3) + 1;  
                    snprintf(disasm, sizeof(disasm), "%s %s, #%d", 
                            c166_opcodes[i].mnemonic,
                            get_register_name(reg),
                            count);
                } else if (strcmp(c166_opcodes[i].format, "") == 0) {
                    snprintf(disasm, sizeof(disasm), "%s", c166_opcodes[i].mnemonic);
                } else {
                    snprintf(disasm, sizeof(disasm), "%s %s", 
                            c166_opcodes[i].mnemonic,
                            c166_opcodes[i].format);
                }
            } else if (c166_opcodes[i].length == 4 && len >= 4) {
                if (strcmp(c166_opcodes[i].format, "caddr") == 0) {
                    ut16 addr = rz_read_le16(buf + 2);
                    snprintf(disasm, sizeof(disasm), "%s 0x%04x", 
                            c166_opcodes[i].mnemonic,
                            addr);
                } else {
                    snprintf(disasm, sizeof(disasm), "%s %s", 
                            c166_opcodes[i].mnemonic,
                            c166_opcodes[i].format);
                }
            } else {
                snprintf(disasm, sizeof(disasm), "%s", c166_opcodes[i].mnemonic);
            }
            
            rz_strbuf_set(&op->buf_asm, disasm);
            op->size = c166_opcodes[i].length;
            return op->size;
        }
    }
    
    // Unknown instruction
    rz_strbuf_set(&op->buf_asm, "undefined");
    op->size = 2;
    return op->size;
}


// Assembler function not implemented yet
static int assemble(RzAsm *a, RzAsmOp *op, const char *str) {
    return 0;
}

RzAsmPlugin rz_asm_plugin_c166 = {
    .name = "c166",
    .arch = "c166",
    .bits = 16,
    .endian = RZ_SYS_ENDIAN_LITTLE,
    .desc = "Infineon C166 disassembler",
    .disassemble = &disassemble,
    .assemble = &assemble,
    .license = "LGPL3",
    .cpus = "c166-generic"
};