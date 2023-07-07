#include "maps.h"

#define ENTRY(dv0, dv1, dtype, sv0, sv1, stype, optype) \
{ \
        .dst = { .v0 = dv0; .v1 = dv1; .type = dtype; }, \
        .src = { .v0 = sv0, .v1 = sv1, .type = stype }, \
        .type = optype \
}

struct rl78_instr rl78_instr_maps[4 * 256] = {
        [0] = { .operation = RL78_OPERATION_NOP },
        [1] = { .dst = { .v0 = RL78_GPR_AX, .type = RL78_OPERAND_TYPE_SYMBOL },
                .src = { .v0 = RL78_GPR_AX, .type = RL78_OPERAND_TYPE_SYMBOL },
                .operation = RL78_OPERATION_ADDW },
        [2] = { .dst = { .v0 = RL78_GPR_AX, .type = RL78_OPERAND_TYPE_SYMBOL },
                .src = { .type = RL78_OPERAND_TYPE_ABSOLUTE_ADDR_16 },
                .operation = RL78_OPERATION_ADDW },
        [3] = { .dst = { .v0 = RL78_GPR_AX, .type = RL78_OPERAND_TYPE_SYMBOL },
                .src = { .v0 = RL78_GPR_BC, .type = RL78_OPERAND_TYPE_SYMBOL },
                .operation = RL78_OPERATION_ADDW },
        [4] = { .dst = { .v0 = RL78_GPR_AX, .type = RL78_OPERAND_TYPE_SYMBOL },
                .src = { .type = RL78_OPERAND_TYPE_IMMEDIATE },
                .operation = RL78_OPERATION_ADDW },
        [5] = { .dst = { .v0 = RL78_GPR_AX, .type = RL78_OPERAND_TYPE_SYMBOL },
                .src = { .v0 = RL78_GPR_DE, .type = RL78_OPERAND_TYPE_SYMBOL },
                .operation = RL78_OPERATION_ADDW },
        [6] = { .dst = { .v0 = RL78_GPR_AX, .type = RL78_OPERAND_TYPE_SYMBOL },
                .src = { .type = RL78_OPERAND_TYPE_SYMBOL },
                .operation = RL78_OPERATION_ADDW },
        [7] = { .dst = { .v0 = RL78_GPR_AX, .type = RL78_OPERAND_TYPE_SYMBOL },
                .src = { .v0 = RL78_GPR_HL, .type = RL78_OPERAND_TYPE_SYMBOL },
                .operation = RL78_OPERATION_ADDW },
};
