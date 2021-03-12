// SPDX-FileCopyrightText: 2012 pancake
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef _INCLUDE_R_JAVA_H_
#define _INCLUDE_R_JAVA_H_

#include <rz_types.h>
#include "../../bin/format/java/class.h"

typedef struct java_op {
	const char *name;
	unsigned char byte;
	int size;
	ut64 op_type;
} JavaOp;

#define JAVA_OPS_COUNT 297
extern struct java_op JAVA_OPS[JAVA_OPS_COUNT];
RZ_API int java_print_opcode(RzBinJavaObj *obj, ut64 addr, int idx, const ut8 *bytes, int len, char *output, int outlen);
RZ_API int rz_java_disasm(RzBinJavaObj *obj, ut64 addr, const ut8 *bytes, int len, char *output, int outlen);
RZ_API int rz_java_assemble(ut64 addr, ut8 *bytes, const char *string);
RZ_API void rz_java_new_method(void);

#endif
