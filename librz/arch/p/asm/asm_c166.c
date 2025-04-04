// SPDX-FileCopyrightText: 2025 Alexandru Aioanei <alex03aioanei@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file asm_c166.c
 * \brief Assembly and disassembly plugin for C166 architecture
 *
 * Provides functionality for disassembling C166 machine code into assembly language
 * representation and assembling C166 assembly code into machine code.
 */

#include <stdio.h>
#include <string.h>
#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>

#include "librz/arch/isa/c166/c166_ops.h"
#include "librz/arch/isa/c166/c166_disas.h"

/**
 * \brief C166 disassembly function
 * \param a Pointer to RzAsm structure
 * \param op Pointer to RzAsmOp structure to be filled with disassembly data
 * \param buf Buffer containing instruction bytes
 * \param len Length of the buffer
 * \return Length of the disassembled instruction or 0 on failure
 *
 * Disassembles a single C166 instruction and populates the op->buf_asm with
 * human-readable assembly representation. Uses the rz_c166_disas helper function
 * to perform the actual disassembly.
 */
static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
    int dlen = 0;
    char *s = rz_c166_disas(a->pc, buf, len, &dlen);
    if (dlen < 0) {
        dlen = 0;
    }
    if (s) {
        rz_strbuf_set(&op->buf_asm, s);
        free(s);
    }
    op->size = dlen;
    return dlen;
}


/**
 * \brief C166 assembly function
 * \param a Pointer to RzAsm structure
 * \param op Pointer to RzAsmOp structure to be filled with assembled data
 * \param buf Assembly instruction text to be converted to machine code
 * \return Size of the assembled instruction or 0 on failure
 *
 * Converts C166 assembly language text into machine code.
 * Currently a placeholder for future implementation.
 */
static int assemble(RzAsm *a, RzAsmOp *op, const char *buf) {
    // Not implemented
    return 0;
}

RzAsmPlugin rz_asm_plugin_c166 = {
    .name = "c166",
    .arch = "c166",
    .bits = 16,
    .endian = RZ_SYS_ENDIAN_LITTLE,
    .desc = "Infineon C166 microcontroller",
    .license = "LGPL3",
    .disassemble = &disassemble,
    .assemble = &assemble,
    .cpus = "c166-generic"  
};