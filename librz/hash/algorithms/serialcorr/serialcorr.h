// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SERIALCORR_H
#define RZ_SERIALCORR_H

#include <rz_types.h>

#define RZ_HASH_SERIALCORR_DIGEST_SIZE  sizeof(double)
#define RZ_HASH_SERIALCORR_BLOCK_LENGTH 0

typedef struct serialcorr_t {
	ut64 size;
	double sum; ///< Sum of byte values.
	double sum_sq; ///< Sum of squared byte values.
	double sum_cross; ///< Sum of products of consecutive byte values.
	ut8 first; ///< First byte (for the wrap-around term).
	ut8 last; ///< Most recent byte (bridges streaming updates).
	bool started; ///< Whether at least one byte was consumed.
} RzSerialCorr;

bool rz_serialcorr_init(RzSerialCorr *ctx);
bool rz_serialcorr_update(RzSerialCorr *ctx, const ut8 *data, size_t len);
bool rz_serialcorr_final(ut8 *digest, RzSerialCorr *ctx);

#endif /* RZ_SERIALCORR_H */
