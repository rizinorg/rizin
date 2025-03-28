// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (C) 2025 Rizin

#ifndef RZ_VAX_H
#define RZ_VAX_H

typedef struct {
    const char *name;  // e.g., "movl"
    unsigned int opcode;  // e.g., 0xD0
    const char *args;  // e.g., "rlwl"
} vax_instruction;

static const vax_instruction vax_instructions[] = {
    {"halt", 0x04, ""},        // HALT: no operands (for NetBSD binary)
    {"nop",  0x01, ""},        // NOP: no operands
    {"brb",  0x11, "bb"},      // BRB: 1-byte displacement
    {"movl", 0xD0, "rlwl"},    // MOVL: read long, write long
    {NULL,   0,    NULL}       // End of table
};

#endif // RZ_VAX_H
