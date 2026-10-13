// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef C166_RAW_H
#define C166_RAW_H

#include <rz_types.h>
#include <rz_util.h>

typedef enum {
	CPU_C166,
	CPU_C167,
	CPU_ST10
} C16xCpuType;

typedef struct bin_c166_int_table {
	ut8 index;
	ut64 address;
	const char *name;
} BinC166IntTable;

typedef struct {
	ut8 bits;
	ut64 base_addr;
	C16xCpuType cpu;
	RzVector /*<ut64>*/ *interrupts;
} rz_bin_c166_obj;

const BinC166IntTable *get_isr_table(void);
char *cpu_name(C16xCpuType cpu);
bool create_isr_sym(RzPVector /*<RzBinSymbol *>*/ *isr_table, char *sym_name, ut64 addr);
bool populate_isr_table(RzVector /*<ut64>*/ *interrupts, RzPVector /*<RzBinSymbol *>*/ *isr_table, ut64 base_addr);
#endif // C166_RAW_H
