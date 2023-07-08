// SPDX-FileCopyrightText: 2023 Bastian Engel <bastian.engel00@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rl78.h"

#include "maps.h"

static bool parse_operand(struct rl78_operand *operand, size_t *p,
                          const ut8 *buf, size_t buf_len);

static bool optype_es_applies(enum rl78_operand_type type);

bool rl78_dis(struct rl78_instr RZ_OUT *instr, size_t RZ_OUT *bytes_read,
              const ut8 *buf, size_t buf_len)
{
        if (buf_len == 0) {
                *bytes_read = 0;
                return false;
        }

        // points to the next byte to be processed
        size_t p = 0;
        int byte = buf[p++];

        bool extension_addressing = false;
        if (byte == 0x11) {
                extension_addressing = true;
                if (p >= buf_len) {
                        *bytes_read = p;
                        return false;
                }

                byte = buf[p++];
        }

        switch (byte) {
                case 0x31:
                        // 4th map
                        *instr = rl78_instr_maps[3 * 256 + byte];
                        break;
                case 0x61:
                        // 2nd map
                        *instr = rl78_instr_maps[1 * 256 + byte];
                        break;
                case 0x71:
                        // 3rd map
                        *instr = rl78_instr_maps[2 * 256 + byte];
                        break;

                default:
                        *instr = rl78_instr_maps[0 * 256 + byte];

        }

        // an empty slot was indexed
        if (instr->operation == RL78_OPERATION_NONE) {
                *bytes_read = p;
                return false;
        }

        if (!parse_operand(&instr->op0, &p, buf, buf_len) ||
            !parse_operand(&instr->op1, &p, buf, buf_len)) {
                *bytes_read = p;
                return false;
        }

        if (extension_addressing) {
                if (optype_es_applies(instr->op0.type)) {
                        instr->op0.extension_addressing = true;
                } else if (optype_es_applies(instr->op1.type)) {
                        instr->op1.extension_addressing = true;
                }
        }

        *bytes_read = p;
        return true;
}

static bool parse_operand(struct rl78_operand *operand, size_t *p,
                          const ut8 *buf, size_t buf_len)
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
                        if (*p == buf_len) {
                                return false;
                        }

                        operand->v0 = buf[(*p)++];
                        break;

                // write to v1 since v0 already has base register
                case RL78_OPERAND_TYPE_BASED_ADDR:
                        if (*p == buf_len) {
                                return false;
                        }

                        operand->v1 = buf[(*p)++];
                        break;

                // word-sized operands
                case RL78_OPERAND_TYPE_IMMEDIATE_16:
                case RL78_OPERAND_TYPE_ABSOLUTE_ADDR_16:
                case RL78_OPERAND_TYPE_ABSOLUTE_ADDR_20:
                case RL78_OPERAND_TYPE_RELATIVE_ADDR_16:
                        if (*p == buf_len) {
                                return false;
                        }

                        int byte_l = buf[(*p)++];

                        if (*p == buf_len) {
                                return false;
                        }

                        int byte_h = buf[(*p)++];
                        operand->v0 = byte_l | (byte_h << 8);
                        break;

                case RL78_OPERAND_TYPE_NONE:
                default:
                        // do nothing
                        break;
        }

        return true;
}

static bool optype_es_applies(enum rl78_operand_type type)
{
        return type == RL78_OPERAND_TYPE_ABSOLUTE_ADDR_16 ||
                type == RL78_OPERAND_TYPE_INDIRECT_ADDR ||
                type == RL78_OPERAND_TYPE_BASED_ADDR ||
                type == RL78_OPERAND_TYPE_BASED_INDEX_ADDR;
}
