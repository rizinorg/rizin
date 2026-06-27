// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_INQUIRY_IL_CACHE_H
#define RZ_INQUIRY_IL_CACHE_H

#include "rz_th.h"
#include "rz_types.h"
#include <rz_type.h>
#include <rz_analysis.h>

/**
 * \brief This value is pushed over the IL ops queue if the requested
 * IL op failed to be lifted.
 */
#define RZ_IL_CACHE_FAILED_LIFTING_PTR ((void *)(utptr)UT64_MAX)

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
	/**
	 * \brief The IL cache will replace un-lifted instructions
	 * with a NOP.
	 */
	RZ_IL_CACHE_CONFIG_NOP_UNLIFTED = 1 << 0,
	/**
	 * \brief The IL cache will lift instructions only on request.
	 * If unset, it will lift all instructions in all executable maps
	 * on initialization.
	 */
	RZ_IL_CACHE_CONFIG_LIFT_ON_REQUEST = 1 << 1,

	// TODO: Sleep times are not really a useful setting.
	// They are just here for experiments.

	/**
	 * \brief If set, the cache doesn't sleep in its serve loop.
	 * It continuously checks for requests.
	 */
	RZ_IL_CACHE_CONFIG_NO_SLEEP = 1 << 2,
	/**
	 * \brief If set, the cache sleeps a short time between checks for requests.
	 */
	RZ_IL_CACHE_CONFIG_SLEEP_SHORT = 1 << 3,
	/**
	 * \brief If set, the cache sleeps a relatively long time between checks for requests.
	 */
	RZ_IL_CACHE_CONFIG_SLEEP_LONG = RZ_IL_CACHE_CONFIG_NO_SLEEP | RZ_IL_CACHE_CONFIG_SLEEP_SHORT,
} RzILCacheConfig;

RZ_API RZ_OWN char *rz_il_cache_block_str(RZ_NONNULL const RzILCacheBlock *block);

RZ_API RZ_OWN RzILCache *rz_il_cache_new(
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_BORROW RZ_NONNULL RzIO *io,
	RZ_OWN RzPVector /*<RzBinSection *>*/ *bin_sections,
	RzILCacheConfig config);
RZ_API void rz_il_cache_free(RZ_OWN RZ_NULLABLE RzILCache *cache);
RZ_API void rz_il_cache_close(RZ_BORROW RZ_NONNULL RzILCache *cache);
RZ_API void rz_il_cache_stop_serving(RZ_BORROW RZ_NONNULL RzILCache *cache);
RZ_API const RzVector /*<RzAnalysisXRef>*/ *rz_il_cache_get_static_xrefs(const RzILCache *cache);
RZ_API RzIterator /*<const RzILCacheBlock *>*/ *rz_il_cache_get_blocks(const RzILCache *cache);

typedef struct rz_il_cache_client_t {
	RzThreadRingBuf *req_rbuf;
	RzThreadQueue *il_queue;
} RzILCacheClient;

RZ_API RZ_BORROW RzILCacheClient *rz_il_cache_new_client(RZ_NONNULL RZ_BORROW RzILCache *cache);
RZ_API RZ_NULLABLE RZ_BORROW const RzILCacheBlock *rz_il_cache_client_lift_il_block(RZ_NONNULL RZ_BORROW RzILCacheClient *client, ut64 addr);

RZ_API bool rz_il_cache_was_requested(
	RZ_BORROW RzILCache *cache,
	ut64 addr);
RZ_API bool rz_il_cache_serve(RZ_NONNULL RzILCache *cache);
RZ_API RZ_OWN RzILCacheBlock *rz_il_cache_lift_il_block(const RzILCache *cache, ut64 addr);

#endif // RZ_INQUIRY_IL_CACHE_H
