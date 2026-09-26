// SPDX-FileCopyrightText: 2026 vk3089790-arch <vk3089790@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MUTUAL_INFO_H
#define RZ_MUTUAL_INFO_H

#include <rz_types.h>

/**
 * \brief Context for computing mutual information between two byte streams.
 *
 * Tracks the joint frequency of byte value pairs seen across successive
 * calls to rz_mutual_info_update(), used to compute the final mutual
 * information value.
 */
typedef struct rz_mutual_info_t {
	ut64 joint_count[256][256]; ///< Frequency of each (byte_a, byte_b) pair observed.
	ut64 size; ///< Total number of byte pairs processed so far.
} RzMutualInfo;

/**
 * \brief Initialize a mutual information context.
 *
 * Must be called before any calls to rz_mutual_info_update() or
 * rz_mutual_info_final().
 *
 * \param ctx Pointer to the context to initialize.
 * \return true on success, false if ctx is NULL.
 */
RZ_API bool rz_mutual_info_init(RzMutualInfo *ctx);

/**
 * \brief Accumulate joint frequency counts from two byte buffers.
 *
 * Can be called multiple times to process data incrementally; counts
 * accumulate across calls.
 *
 * \param ctx Pointer to an initialized context.
 * \param data_a Pointer to the first byte buffer.
 * \param data_b Pointer to the second byte buffer, same length as data_a.
 * \param len Number of bytes to process from each buffer.
 * \return true on success, false if ctx, data_a, or data_b is NULL.
 */
RZ_API bool rz_mutual_info_update(RzMutualInfo *ctx, const ut8 *data_a, const ut8 *data_b, size_t len);

/**
 * \brief Compute the final mutual information value from accumulated counts.
 *
 * Uses the formula I(X;Y) = sum p(x,y) * log2(p(x,y) / (p(x) * p(y)))
 * over all non-zero joint probabilities.
 *
 * \param ctx Pointer to a context that has been updated with data.
 * \return The mutual information value in bits, or 0.0 if ctx is NULL.
 */
RZ_API double rz_mutual_info_final(RzMutualInfo *ctx);

#endif