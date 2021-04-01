// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_LOCAL_VARIABLE_TABLE_H
#define RZ_BIN_JAVA_CLASS_LOCAL_VARIABLE_TABLE_H
#include <rz_types.h>

typedef struct java_local_variable_table_t {
	ut16 start_pc;
	ut16 length;
	ut16 name_index;
	ut16 descriptor_index;
	ut16 index;
} LocalVariableTable;

typedef struct java_local_variable_type_table_t {
	ut16 start_pc;
	ut16 length;
	ut16 name_index;
	ut16 signature_index;
	ut16 index;
} LocalVariableTypeTable;

#endif /* RZ_BIN_JAVA_CLASS_LOCAL_VARIABLE_TABLE_H */
