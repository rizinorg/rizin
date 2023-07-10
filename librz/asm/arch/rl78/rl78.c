// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rl78.h"
#include "rl78_maps.h"

static bool parse_operand(RL78Operand RZ_INOUT *operand, size_t RZ_INOUT *next_byte_p,
                          const ut8 RZ_BORROW *buf, size_t buf_len);

static inline bool optype_es_applies(RL78OperandType type);

bool rl78_dis(RL78Instr RZ_OUT *instr, size_t RZ_OUT *bytes_read,
              const ut8 *buf, size_t buf_len)
{
        if (buf_len == 0) {
                *bytes_read = 0;
                return false;
        }

        size_t next_byte_p = 0;
        int byte = buf[next_byte_p++];

        bool extension_addressing = false;
        if (byte == 0x11) {
                extension_addressing = true;
                if (next_byte_p >= buf_len) {
                        *bytes_read = next_byte_p;
                        return false;
                }

                byte = buf[next_byte_p++];
        }

        int map;
        switch (byte) {
                case 0x31:
                        // 4th map
                        map = 3;
                        next_byte_p++;
                        break;
                case 0x61:
                        // 2nd map
                        map = 1;
                        next_byte_p++;
                        break;
                case 0x71:
                        // 3rd map
                        map = 2;
                        next_byte_p++;
                        break;

                default:
                        // default (first) map
                        map = 0;

        }

        *instr = rl78_instr_maps[map * 256 + byte];

        // an empty slot was indexed
        if (instr->operation == RL78_OPERATION_NONE) {
                *bytes_read = next_byte_p;
                return false;
        }

        if (!parse_operand(&instr->op0, &next_byte_p, buf, buf_len) ||
            !parse_operand(&instr->op1, &next_byte_p, buf, buf_len)) {
                *bytes_read = next_byte_p;
                return false;
        }

        if (extension_addressing) {
                if (optype_es_applies(instr->op0.type)) {
                        instr->op0.extension_addressing = true;
                } else if (optype_es_applies(instr->op1.type)) {
                        instr->op1.extension_addressing = true;
                }
        }

        *bytes_read = next_byte_p;
        return true;
}

static bool parse_operand(RL78Operand RZ_INOUT *operand, size_t RZ_INOUT *next_byte_p,
                          const ut8 RZ_BORROW *buf, size_t buf_len)
{
        // already has value
        if (operand->v0 != 0) {
                return true;
        }

        switch (operand->type) {
                // byte-sized operands
                case RL78_OPERAND_TYPE_IMMEDIATE_8:
                case RL78_OPERAND_TYPE_RELATIVE_ADDR_8:
                case RL78_OPERAND_TYPE_SYMBOL: // TODO put short direct addressing into own type
                        if (*next_byte_p == buf_len) {
                                return false;
                        }

                        operand->v0 = buf[(*next_byte_p)++];
                        break;

                // write to v1 since v0 already has base register
                case RL78_OPERAND_TYPE_BASED_ADDR:
                        if (*next_byte_p == buf_len) {
                                return false;
                        }

                        operand->v1 = buf[(*next_byte_p)++];
                        break;

                // word-sized operands
                case RL78_OPERAND_TYPE_IMMEDIATE_16:
                case RL78_OPERAND_TYPE_ABSOLUTE_ADDR_16:
                case RL78_OPERAND_TYPE_ABSOLUTE_ADDR_20:
                case RL78_OPERAND_TYPE_RELATIVE_ADDR_16:
                        if (*next_byte_p == buf_len) {
                                return false;
                        }

                        int byte_l = buf[*next_byte_p];
                        (*next_byte_p)++;

                        if (*next_byte_p == buf_len) {
                                return false;
                        }

                        int byte_h = buf[*next_byte_p];
                        (*next_byte_p)++;
                        operand->v0 = byte_l | (byte_h << 8);
                        break;

                case RL78_OPERAND_TYPE_NONE:
                default:
                        // do nothing
                        break;
        }

        return true;
}

static inline bool optype_es_applies(RL78OperandType type)
{
        return type == RL78_OPERAND_TYPE_ABSOLUTE_ADDR_16 ||
                type == RL78_OPERAND_TYPE_INDIRECT_ADDR ||
                type == RL78_OPERAND_TYPE_BASED_ADDR ||
                type == RL78_OPERAND_TYPE_BASED_INDEX_ADDR;
}
