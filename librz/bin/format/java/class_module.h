// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_MODULE_H
#define RZ_BIN_JAVA_CLASS_MODULE_H
#include <rz_types.h>

typedef struct java_module_provide_t {
	ut16 index;
	ut16 with_count;
	ut16 *with_indices;
} ModuleProvide;

typedef struct java_module_open_t {
	ut16 index;
	ut16 flags;
	ut16 to_count;
	ut16 *to_indices;
} ModuleOpen;

typedef struct java_module_export_t {
	ut16 index;
	ut16 flags;
	ut16 to_count;
	ut16 *to_indices;
} ModuleExport;

typedef struct java_module_require_t {
	ut16 index;
	ut16 flags;
	ut16 version_index;
} ModuleRequire;

#endif /* RZ_BIN_JAVA_CLASS_MODULE_H */
