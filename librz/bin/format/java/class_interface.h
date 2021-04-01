// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_INTERFACE_H
#define RZ_BIN_JAVA_CLASS_INTERFACE_H
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>

typedef struct java_interface_t {
	ut64 offset;
	ut16 index;
} Interface;

Interface *java_interface_new(RzBuffer *buf, ut64 offset);
#define java_interface_free(x) free(x)

#endif /* RZ_BIN_JAVA_CLASS_INTERFACE_H */
