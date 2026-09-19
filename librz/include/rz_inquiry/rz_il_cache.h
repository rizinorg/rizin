// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_INQUIRY_IL_CACHE_H
#define RZ_INQUIRY_IL_CACHE_H

#include <rz_analysis.h>

typedef struct rz_il_cache_t RzILCache;

typedef struct {
	RzILOpEffect *effect; ///< Vector with the IL ops of an instruction packets.
	size_t insn_pkt_size; ///< The size of the instruction packet. Used to increment the PC if no JMP occurred.
} RzILCacheInsnPkt;

/**
 * \brief A sequence of instructions of which the last instruction is always
 * a branch or a terminating instruction.
 */
typedef struct {
	RzPVector /*<RzILCacheInsnPkt *>*/ *il_ops; ///< The sequence of IL operations of this block.
	size_t size; ///< The number of bytes the instructions of the block cover in memory.
	ut64 addr; ///< The address where the block starts.
} RzILCacheBlock;

typedef enum {
	RZ_IL_CACHE_CONFIG_DEFAULT = 0,
	RZ_IL_CACHE_CONFIG_NOP_UNLIFTED = 1 << 0, ///< replace un-lifted instructions with a NOP
	RZ_IL_CACHE_CONFIG_TRACE = 1 << 1 ///< Log lifted blocks for debugging
} RzILCacheConfig;

RZ_API RZ_OWN char *rz_il_cache_block_str(RZ_NONNULL const RzILCacheBlock *block);

RZ_API RZ_OWN RzILCache *rz_il_cache_new(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_BORROW RZ_NONNULL RzIO *io, RzILCacheConfig config);
RZ_API void rz_il_cache_free(RZ_OWN RZ_NULLABLE RzILCache *cache);

RZ_API const RzILCacheBlock *rz_il_cache_lift_il_block(RzILCache *cache, ut64 addr);

#endif // RZ_INQUIRY_IL_CACHE_H
