// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_MEM_H
#define RZ_IL_MEM_H

#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef ut32 RzILMemIndex;

/**
 * \brief A single memory as part of the RzIL VM.
 *
 * This can be seen as an array of bitvectors, indexed by bitvector keys, covering a
 * certain address space. It corresponds to `('a, 'b) mem` in bap where 'a and 'b
 * statically determine the size of all keys and values, respectively.
 * Because currently our memory can only bind to an RzBuffer, the key size is limited to
 * a maximum of 64bits and the value size is always 8, but this can be extended in
 * the future if necessary.
 */
typedef struct rz_il_mem_t {
	RzBuffer *buf;
	ut32 key_len;
} RzILMem;

RZ_API RzILMem *rz_il_mem_new(RzBuffer *buf, ut32 key_len);
RZ_API void rz_il_mem_free(RzILMem *mem);
RZ_API ut32 rz_il_mem_key_len(RzILMem *mem);
RZ_API ut32 rz_il_mem_value_len(RzILMem *mem);
RZ_API RzBitVector *rz_il_mem_load(RzILMem *mem, RzBitVector *key);
RZ_API bool rz_il_mem_store(RzILMem *mem, RzBitVector *key, RzBitVector *value);
RZ_API RzBitVector *rz_il_mem_loadw(RzILMem *mem, RzBitVector *key, ut32 n_bits, bool big_endian);
RZ_API bool rz_il_mem_storew(RzILMem *mem, RzBitVector *key, RzBitVector *value, bool big_endian);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_MEM_H
