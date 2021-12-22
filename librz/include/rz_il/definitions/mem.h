// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_MEM_H
#define RZ_IL_MEM_H

#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rzil_mem_t {
	HtPP *kv_map;
	ut32 min_unit_size; // minimal unit size in bit (len of value bv)
};
typedef struct rzil_mem_t RzILMem;

RZ_API RzILMem *rz_il_mem_new(ut32 min_unit_size);
RZ_API void rz_il_mem_free(RzILMem *mem);
RZ_API RzILMem *rz_il_mem_store(RzILMem *mem, RzBitVector *key, RzBitVector *value);
RZ_API RzBitVector *rz_il_mem_load(RzILMem *mem, RzBitVector *key);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_MEM_H
