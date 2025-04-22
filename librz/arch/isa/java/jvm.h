// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ASM_JAVA_JVM_H
#define RZ_ASM_JAVA_JVM_H
#include <rz_types.h>
#include <rz_util.h>
#include "bytecode.h"

typedef struct jvm_t {
	const ut8 *buffer;
	ut32 size;
	ut32 current;
	ut64 pc;
	ut64 section;
} JavaVM;

void bytecode_snprint(RzStrBuf *sb, Bytecode *bytecode);
void bytecode_clean(Bytecode *bytecode);
bool jvm_init(JavaVM *jvm, const ut8 *buffer, const ut32 size, ut64 pc, ut64 section);
bool jvm_fetch(JavaVM *jvm, Bytecode *bytecode);

#endif /* RZ_ASM_JAVA_JVM_H */
