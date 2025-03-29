// SPDX-License-Identifier: LGPL-3.0-only
// Copyright (C) 2025 Rizin

#ifndef RZ_VAX_H
#define RZ_VAX_H

typedef enum {
    VAX_OP_HALT = 0x04,
    VAX_OP_NOP = 0x01,
    VAX_OP_BRB = 0x11,
    VAX_OP_MOVL = 0xD0,
    VAX_OP_INVALID = 0 // Sentinel value for end of table
} VaxOpcode;

typedef struct {
    const char *name;
    VaxOpcode opcode;
    const char *args;
} VaxInstruction;

static const VaxInstruction vax_instructions[] = {
    {"halt", VAX_OP_HALT, ""},
    {"nop",  VAX_OP_NOP,  ""},
    {"brb",  VAX_OP_BRB,  "bb"},
    {"movl", VAX_OP_MOVL, "rlwl"},
    {NULL,   VAX_OP_INVALID, NULL}
};

#endif // RZ_VAX_H