// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef BUILD_MEM_H
#define BUILD_MEM_H
#include "bitvector.h"

struct mem_t {
	HtPP *kv_map;
	int min_unit_size; // minimal unit size in bit (len of value bv)
};
typedef struct mem_t *Mem;

Mem rz_il_new_mem(int min_unit_size);
void rz_il_free_mem(Mem mem);
Mem rz_il_mem_store(Mem mem, BitVector key, BitVector value);
BitVector rz_il_mem_load(Mem mem, BitVector key);

#endif //BUILD_MEM_H
