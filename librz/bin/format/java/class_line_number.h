// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_LINE_NUMBER_TABLE_H
#define RZ_BIN_JAVA_CLASS_LINE_NUMBER_TABLE_H
#include <rz_types.h>

typedef struct java_line_number_table_t {
	ut16 start_pc;
	ut16 line_number;
} LineNumberTable;

#endif /* RZ_BIN_JAVA_CLASS_LINE_NUMBER_TABLE_H */
