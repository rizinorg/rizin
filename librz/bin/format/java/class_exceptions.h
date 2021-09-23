// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_EXCEPTIONS_H
#define RZ_BIN_JAVA_CLASS_EXCEPTIONS_H
#include <rz_types.h>

typedef struct java_exception_table_t {
	ut16 start_pc;
	ut16 end_pc;
	ut16 handler_pc;
	ut16 catch_type;
} ExceptionTable;

#endif /* RZ_BIN_JAVA_CLASS_EXCEPTIONS_H */
