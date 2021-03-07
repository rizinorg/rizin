// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#ifndef BUILD_LUAC_54_H
#define BUILD_LUAC_54_H

#include "luac_specs.h"

/* Macros for bin_luac.c */

/* luac 5.4 spec */
/* Header Information */
#define LUAC_54_FORMAT_OFFSET           0x05
#define LUAC_54_LUAC_DATA_OFFSET        0x06
#define LUAC_54_INSTRUCTION_SIZE_OFFSET 0x0C
#define LUAC_54_INTEGER_SIZE_OFFSET     0x0D
#define LUAC_54_NUMBER_SIZE_OFFSET      0x0E
#define LUAC_54_INTEGER_VALID_OFFSET    0x0F
#define LUAC_54_NUMBER_VALID_OFFSET     0x17
#define LUAC_54_UPVALUES_NUMBER_OFFSET  0x1F

#define LUAC_54_SIGNATURE_SIZE        4
#define LUAC_54_VERSION_SIZE          1
#define LUAC_54_FORMAT_SIZE           1
#define LUAC_54_LUAC_DATA_SIZE        6
#define LUAC_54_INSTRUCTION_SIZE_SIZE 1
#define LUAC_54_INTEGER_SIZE_SIZE     1
#define LUAC_54_NUMBER_SIZE_SIZE      1
#define LUAC_54_INTEGER_VALID_SIZE    8
#define LUAC_54_NUMBER_VALID_SIZE     8
#define LUAC_54_UPVALUES_NUMBER_SIZE  1

#define LUAC_54_FORMAT            0 /* this is the official format */
#define LUAC_54_DATA              "\x19\x93\r\n\x1a\n"
#define LUAC_54_INT_VALIDATION    0x5678
#define LUAC_54_NUMBER_VALIDATION luac_cast_num(370.5)

#define LUAC_54_HDRSIZE 0x20

/* Body */
#define LUAC_FILENAME_OFFSET 0x20

/* Exported Api to bin_luac.c */
RzBinInfo *info_54(RzBinFile *bf, st32 major, st32 minor);

#endif //BUILD_LUAC_54_H
